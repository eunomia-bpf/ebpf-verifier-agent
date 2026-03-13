"""Formal proof analysis engine over parsed verifier traces."""

from __future__ import annotations

import re
from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .abstract_domain import (
    eval_atom_abstract,
    scalar_bounds_from_register_state,
    pointer_state_from_register_state,
)
from .obligation_catalog_formal import match_error_message as _catalog_match_error_message
from .shared_utils import (
    decode_regs_mask as _shared_decode_regs_mask,
    extract_registers as _shared_extract_registers,
    is_map_value_type_name,
    is_packet_pointer_type,
    is_pointer_type_name,
    normalize_register as _shared_normalize_register,
    register_index as _shared_register_index,
)
from .trace_parser import BacktrackChain, ParsedTrace, RegisterState, TracedInstruction
from .value_lineage import ValueLineage, build_value_lineage


REGISTER_RE = re.compile(r"\b([RrWw]\d+)\b")
ERROR_REGISTER_RE = re.compile(r"\b([Rr]\d+)(?:\b|\()")
LOAD_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*=\s*\*\((?P<width>[us]\d+)\s*\*\)\("
    r"(?P<base>[rw]\d+)\s*(?P<sign>[+-])\s*(?P<offset>[-+]?(?:0x[0-9a-fA-F]+|\d+))\)$",
    re.IGNORECASE,
)
STORE_RE = re.compile(
    r"^\*\((?P<width>[us]\d+)\s*\*\)\("
    r"(?P<base>[rw]\d+)\s*(?P<sign>[+-])\s*(?P<offset>[-+]?(?:0x[0-9a-fA-F]+|\d+))\)\s*=\s*"
    r"(?P<src>.+)$",
    re.IGNORECASE,
)
BRANCH_RE = re.compile(
    r"^if\s+(?P<lhs>[rw]\d+)\s*(?P<cmp>s?[<>]=?|==|!=|&)\s*(?P<rhs>.+?)\s+goto\s+pc(?P<delta>[+-]\d+)$",
    re.IGNORECASE,
)
JUMP_RE = re.compile(r"^(?:goto|ja)\s+pc(?P<delta>[+-]\d+)$", re.IGNORECASE)
CALL_RE = re.compile(r"^call\s+(?P<target>.+)$", re.IGNORECASE)
AUG_ASSIGN_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*(?P<op>s>>=|s<<=|<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=)\s*(?P<src>.+)$",
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(r"^(?P<dst>[rw]\d+)\s*=\s*(?P<rhs>.+)$", re.IGNORECASE)
HELPER_EXPECTED_RE = re.compile(r"expected=(?P<expected>[^,]+(?:,\s*[^,]+)*)", re.IGNORECASE)
HELPER_ARG_CLUE_RE = re.compile(r"\b(?:type=|expected=|arg\s*#?\d+)\b", re.IGNORECASE)
ERROR_ARG_RE = re.compile(
    r"\b(?:helper|trusted)\s+arg(?P<plain>\d+)\b|\barg\s*#(?P<spaced>\d+)\b|\barg#(?P<compact>\d+)\b",
    re.IGNORECASE,
)
ARG_PAIR_RE = re.compile(
    r"\barg#(?P<base>\d+)\s+arg#(?P<index>\d+)\s+memory,\s*len pair leads to invalid memory access",
    re.IGNORECASE,
)
VALUE_SIZE_RE = re.compile(r"\bvalue_size=(?P<value_size>-?(?:0x[0-9a-fA-F]+|\d+))\b")
MEM_SIZE_RE = re.compile(r"\bmem_size=(?P<mem_size>-?(?:0x[0-9a-fA-F]+|\d+))\b")
OFF_RE = re.compile(r"\boff=(?P<off>-?(?:0x[0-9a-fA-F]+|\d+))\b")
SIZE_RE = re.compile(r"\bsize=(?P<size>-?(?:0x[0-9a-fA-F]+|\d+))\b")
STACK_SLOT_RE = re.compile(r"^fp(?P<off>-?(?:0x[0-9a-fA-F]+|\d+))$")

PHASE_ORDER = {"pre": 0, "post": 1}
RESULT_ORDER = {"violated": 0, "unknown": 1, "satisfied": 2}
STACK_FRAME_BYTES = 512
HELPER_ARG_EXPECTATIONS: dict[int, dict[str, tuple[str, ...]]] = {
    1: {
        "R1": ("map_ptr",),
        "R2": ("fp", "map_key", "ptr"),
    },
    2: {
        "R1": ("map_ptr",),
        "R2": ("fp", "map_key", "ptr"),
        "R3": ("fp", "map_value", "ptr"),
        "R4": ("inv", "scalar"),
    },
}
OBLIGATION_FAMILIES: dict[str, dict[str, object]] = {
    "packet_access": {
        "summary": "Packet dereferences stay within the verifier-proven packet range.",
        "atom_ids": ("base_is_pkt", "range_at_least"),
    },
    "packet_ptr_add": {
        "summary": "Packet pointer arithmetic uses a non-negative, bounded scalar offset.",
        "atom_ids": ("base_is_pkt", "offset_non_negative", "offset_bounded"),
    },
    "map_value_access": {
        "summary": "Map-value accesses stay within the map value size.",
        "atom_ids": ("type_matches", "range_at_least"),
    },
    "memory_access": {
        "summary": "Generic memory accesses stay within the accessible memory window.",
        "atom_ids": ("type_matches", "range_at_least"),
    },
    "stack_access": {
        "summary": "Stack accesses remain within the current stack frame.",
        "atom_ids": ("type_matches", "range_at_least"),
    },
    "null_check": {
        "summary": "Nullable pointers are proven non-null before use.",
        "atom_ids": ("non_null",),
    },
    "scalar_deref": {
        "summary": "Dereferenced values retain pointer-compatible type information.",
        "atom_ids": ("type_is_pointer",),
    },
    "helper_arg": {
        "summary": "Helper arguments satisfy the helper's expected type contract.",
        "atom_ids": ("type_matches",),
    },
    "trusted_null_check": {
        "summary": "Trusted or referenced arguments satisfy the helper's trust/null contract.",
        "atom_ids": ("non_null", "type_matches"),
    },
    "dynptr_protocol": {
        "summary": "Dynptr values are initialized, aligned, and not invalidated before use.",
        "atom_ids": ("type_matches",),
    },
    "iterator_protocol": {
        "summary": "Iterator references are initialized and remain live until release.",
        "atom_ids": ("type_matches",),
    },
    "unreleased_reference": {
        "summary": "Acquired references are released on every exit path.",
        "atom_ids": (),
    },
    "btf_reference_type": {
        "summary": "BTF reference types resolve to a valid, sized referenced type.",
        "atom_ids": (),
    },
    "exception_callback_context": {
        "summary": "Exception callbacks are only called from verifier-allowed contexts.",
        "atom_ids": (),
    },
    "execution_context": {
        "summary": "Program actions stay within the current execution-context rules.",
        "atom_ids": (),
    },
    "buffer_length_pair": {
        "summary": "Memory and length argument pairs describe an accessible buffer.",
        "atom_ids": (),
    },
    "exit_return_type": {
        "summary": "R0 has a known verifier-approved return value at program exit.",
        "atom_ids": ("scalar_bounds_known",),
    },
    "verifier_limits": {
        "summary": "Program structure stays within verifier-enforced resource limits.",
        "atom_ids": (),
    },
    "safety_violation": {
        "summary": "The verifier rejected a concrete safety rule, but the specific proof family could not be recovered.",
        "atom_ids": (),
    },
}


@dataclass(slots=True)
class InstructionNode:
    insn_idx: int
    bytecode: str
    source_line: str | None
    pre_state: dict[str, RegisterState]
    post_state: dict[str, RegisterState]
    defs: list[str]
    uses: list[str]
    preds: list[int]
    succs: list[int]
    trace_pos: int = -1
    visit_index: int = 0
    pred_positions: list[int] = field(default_factory=list)
    succ_positions: list[int] = field(default_factory=list)


@dataclass(slots=True)
class TraceIR:
    instructions: list[InstructionNode]
    cfg_edges: list[tuple[int, int]]
    reg_versions: dict[tuple[int, str, str], RegisterState]
    backtrack_chains: list[BacktrackChain]
    point_versions: dict[tuple[int, str, str], int] = field(default_factory=dict)
    value_versions: dict[int, "ValueVersion"] = field(default_factory=dict)
    point_order: dict[tuple[int, str], int] = field(default_factory=dict)
    trace_edges: list[tuple[int, int]] = field(default_factory=list)
    positions_by_insn: dict[int, list[int]] = field(default_factory=dict)
    # Value lineage graph — built once at TraceIR construction time and used for
    # alias resolution in predicate evaluation and backward slicing.
    value_lineage: ValueLineage | None = field(default=None)


@dataclass(slots=True)
class ValueVersion:
    version_id: int
    register: str
    defined_at: int | None
    op_kind: str
    parent_versions: tuple[int, ...]
    proof_root: int


@dataclass(slots=True)
class PredicateAtom:
    atom_id: str
    registers: tuple[str, ...]
    expression: str


@dataclass(slots=True)
class ObligationSpec:
    kind: str
    failing_insn: int
    base_reg: str | None
    index_reg: str | None
    const_off: int
    access_size: int
    atoms: list[PredicateAtom]
    failing_trace_pos: int | None = None


Obligation = ObligationSpec


@dataclass(slots=True)
class CompositeObligation:
    sub_obligations: list[Obligation]


@dataclass(slots=True)
class PredicateEval:
    insn_idx: int
    phase: str
    atom_id: str
    result: str
    witness: str
    carrier_register: str | None = None
    trace_pos: int | None = None


@dataclass(slots=True)
class TransitionWitness:
    atom_id: str
    insn_idx: int
    before_result: str
    after_result: str
    witness: str
    carrier_register: str | None = None
    trace_pos: int | None = None


@dataclass(slots=True)
class SliceEdge:
    src: tuple[int, str]
    dst: tuple[int, str]
    kind: str
    reason: str


@dataclass
class ProofAnalysisResult:
    obligation: ObligationSpec | None
    predicate_evals: list[PredicateEval]
    transition: TransitionWitness | None
    slice_edges: list[SliceEdge]
    proof_status: str
    establish_site: int | None
    loss_site: int | None
    reject_site: int | None
    status_reason: str | None = None
    causal_chain: list[tuple[int, str]] = field(default_factory=list)


@dataclass(slots=True)
class _ParsedOperation:
    kind: str
    defs: list[str]
    uses: list[str]
    dst_reg: str | None = None
    src_reg: str | None = None
    base_reg: str | None = None
    offset: int = 0
    size: int = 0
    target: int | None = None
    helper_id: int | None = None
    immediate: int | None = None


@dataclass(slots=True)
class _OverallPoint:
    insn_idx: int
    phase: str
    result: str
    trace_pos: int | None = None


@dataclass(slots=True)
class _AtomTarget:
    version_id: int | None
    proof_root: int | None
    register: str | None
    state: RegisterState | None


def build_trace_ir(parsed_trace: ParsedTrace) -> TraceIR:
    """Build a lightweight SSA-like IR over the parsed instruction trace."""

    traced_instructions = list(parsed_trace.instructions)
    parsed_ops = {
        position: _parse_bytecode(instruction.insn_idx, instruction.bytecode)
        for position, instruction in enumerate(traced_instructions)
    }
    positions_by_insn: dict[int, list[int]] = defaultdict(list)
    for position, instruction in enumerate(traced_instructions):
        positions_by_insn[instruction.insn_idx].append(position)

    sorted_indices = sorted({instruction.insn_idx for instruction in traced_instructions})
    next_by_idx = {
        insn_idx: sorted_indices[position + 1]
        for position, insn_idx in enumerate(sorted_indices[:-1])
    }

    cfg_edges: set[tuple[int, int]] = set()
    trace_edges: set[tuple[int, int]] = set()
    nodes: list[InstructionNode] = []
    reg_versions: dict[tuple[int, str, str], RegisterState] = {}
    visit_counts: dict[int, int] = defaultdict(int)

    for trace_pos, instruction in enumerate(traced_instructions):
        op = parsed_ops[trace_pos]
        succs = _compute_successors(op, instruction.insn_idx, next_by_idx.get(instruction.insn_idx))
        for succ in succs:
            cfg_edges.add((instruction.insn_idx, succ))
            successor_pos = _next_occurrence_position(positions_by_insn.get(succ, []), trace_pos)
            if successor_pos is not None:
                trace_edges.add((trace_pos, successor_pos))

        nodes.append(
            InstructionNode(
                insn_idx=instruction.insn_idx,
                bytecode=instruction.bytecode,
                source_line=instruction.source_line,
                pre_state=dict(instruction.pre_state),
                post_state=dict(instruction.post_state),
                defs=list(op.defs),
                uses=list(op.uses),
                preds=[],
                succs=sorted(succs),
                trace_pos=trace_pos,
                visit_index=visit_counts[instruction.insn_idx],
                succ_positions=sorted(
                    successor_pos
                    for successor_pos in (
                        _next_occurrence_position(positions_by_insn.get(succ, []), trace_pos)
                        for succ in succs
                    )
                    if successor_pos is not None
                ),
            )
        )
        visit_counts[instruction.insn_idx] += 1

        for register, state in instruction.pre_state.items():
            reg_versions[(trace_pos, register, "pre")] = state
        for register, state in instruction.post_state.items():
            reg_versions[(trace_pos, register, "post")] = state

    for src_pos, dst_pos in trace_edges:
        src_node = nodes[src_pos]
        dst_node = nodes[dst_pos]
        dst_node.preds.append(src_node.insn_idx)
        dst_node.pred_positions.append(src_pos)

    for node in nodes:
        node.preds = sorted(set(node.preds))
        node.succs = sorted(set(node.succs))
        node.pred_positions = sorted(set(node.pred_positions))
        node.succ_positions = sorted(set(node.succ_positions))

    point_versions, value_versions = _build_value_versions(traced_instructions, parsed_ops)
    point_order = _build_point_order(traced_instructions)

    # Build the value lineage graph once here so that predicate evaluation and
    # backward slicing can use it for alias resolution across spills/fills.
    try:
        lineage = build_value_lineage(traced_instructions)
    except Exception:
        lineage = None

    return TraceIR(
        instructions=nodes,
        cfg_edges=sorted(cfg_edges),
        reg_versions=reg_versions,
        backtrack_chains=list(parsed_trace.backtrack_chains),
        point_versions=point_versions,
        value_versions=value_versions,
        point_order=point_order,
        trace_edges=sorted(trace_edges),
        positions_by_insn={insn_idx: list(positions) for insn_idx, positions in positions_by_insn.items()},
        value_lineage=lineage,
    )


def _build_point_order(instructions: list[TracedInstruction]) -> dict[tuple[int, str], int]:
    order: dict[tuple[int, str], int] = {}
    for trace_pos, _instruction in enumerate(instructions):
        order[(trace_pos, "pre")] = trace_pos * 2
        order[(trace_pos, "post")] = trace_pos * 2 + 1
    return order


def _build_value_versions(
    instructions: list[TracedInstruction],
    parsed_ops: dict[int, _ParsedOperation],
) -> tuple[dict[tuple[int, str, str], int], dict[int, ValueVersion]]:
    point_versions: dict[tuple[int, str, str], int] = {}
    value_versions: dict[int, ValueVersion] = {}
    current_versions: dict[str, int] = {}
    next_version_id = 1

    def new_version(
        register: str,
        *,
        defined_at: int | None,
        op_kind: str,
        parent_versions: tuple[int, ...] = (),
        proof_root: int | None = None,
    ) -> int:
        nonlocal next_version_id
        version_id = next_version_id
        next_version_id += 1
        value_versions[version_id] = ValueVersion(
            version_id=version_id,
            register=register,
            defined_at=defined_at,
            op_kind=op_kind,
            parent_versions=parent_versions,
            proof_root=proof_root if proof_root is not None else version_id,
        )
        return version_id

    for trace_pos, instruction in enumerate(instructions):
        insn_idx = instruction.insn_idx
        op = parsed_ops[trace_pos]

        for register in instruction.pre_state:
            current_versions.setdefault(
                register,
                new_version(register, defined_at=None, op_kind="entry"),
            )
            point_versions[(trace_pos, register, "pre")] = current_versions[register]

        for register in op.defs:
            parent_versions: tuple[int, ...] = ()
            proof_root = None
            if op.kind == "mov" and op.src_reg is not None and op.src_reg in current_versions:
                parent_versions = (current_versions[op.src_reg],)
                proof_root = value_versions[current_versions[op.src_reg]].proof_root
            elif op.kind in {"alu", "ptr_add"} and op.dst_reg is not None and op.dst_reg in current_versions:
                parent_versions = (current_versions[op.dst_reg],)
            current_versions[register] = new_version(
                register,
                defined_at=insn_idx,
                op_kind=op.kind,
                parent_versions=parent_versions,
                proof_root=proof_root,
            )

        for register in instruction.post_state:
            current_versions.setdefault(
                register,
                new_version(register, defined_at=None, op_kind="entry"),
            )
            point_versions[(trace_pos, register, "post")] = current_versions[register]

    return point_versions, value_versions


def _next_occurrence_position(positions: list[int], trace_pos: int) -> int | None:
    if not positions:
        return None
    next_index = bisect_right(positions, trace_pos)
    if next_index >= len(positions):
        return None
    return positions[next_index]


# ---------------------------------------------------------------------------
# Formal catalog integration helper
# ---------------------------------------------------------------------------


def _try_formal_catalog_obligation(
    fail_insn: InstructionNode,
    op: "_ParsedOperation",
    error_line: str,
    details: dict,
    lowered: str,
) -> "ObligationSpec | None":
    """Try to build an ObligationSpec from the formal obligation catalog.

    Returns an ObligationSpec when the catalog has a match for the error
    message AND we know how to build the ObligationSpec for that family.
    Returns None only when no family handler exists.

    For most families, the catalog's evaluable flag indicates whether the
    precondition can be checked purely from LOG_LEVEL2 trace state.
    We extend coverage to a few families whose preconditions can be partially
    recovered from error-message text (e.g. map_value_access recovers
    value_size from "value_size=%d" in the error line).
    """
    formal_matches = _catalog_match_error_message(error_line)
    if not formal_matches:
        return None

    # Prefer evaluable matches; also accept non-evaluable matches for families
    # where we can supplement the missing info from the error message text.
    _RECOVERABLE_NON_EVALUABLE = frozenset({
        "map_value_access",   # value_size is in the error message text
        "memory_access",      # mem_size is in the error message text
    })
    evaluable_matches = [m for m in formal_matches if m.evaluable]
    recoverable_matches = [
        m for m in formal_matches
        if not m.evaluable and m.family in _RECOVERABLE_NON_EVALUABLE
    ]
    candidate_matches = evaluable_matches or recoverable_matches
    if not candidate_matches:
        return None

    formal = candidate_matches[0]
    family = formal.family

    # Map formal families to ObligationSpec kinds and build atoms from the
    # formal precondition / fields_needed.  We only handle the families
    # that have clear, evaluable structure in LOG_LEVEL2 data; the rest
    # fall through to old code.

    # Shared helpers
    base_reg = op.base_reg
    access_size = op.size or details.get("size") or 0

    # -------------------------------------------------------------------
    # null_check: reg.type != NOT_INIT  /  frame pointer read-only
    # -------------------------------------------------------------------
    if family == "null_check":
        target_reg = (
            base_reg
            or _extract_error_register(error_line)
            or _first_nullable_register(fail_insn)
        )
        if target_reg is None:
            return None
        return ObligationSpec(
            kind="null_check",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="non_null",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type not nullable ({formal.precondition})",
                )
            ],
        )

    # -------------------------------------------------------------------
    # packet_access: smin >= 0  /  off + size <= range
    # -------------------------------------------------------------------
    if family == "packet_access":
        target_reg = (
            base_reg
            or _extract_error_register(error_line)
            or _select_access_register(fail_insn, error_line, _is_packet_ptr)
        )
        if target_reg is None:
            return None
        access_off = details.get("off", op.offset)
        return ObligationSpec(
            kind="packet_access",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=access_off,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="base_is_pkt",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type == pkt",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=f"{access_off} + {access_size} <= {target_reg}.range",
                ),
            ],
        )

    # -------------------------------------------------------------------
    # map_value_access: smin + off >= 0 AND umax + off + size <= value_size
    # -------------------------------------------------------------------
    if family == "map_value_access":
        target_reg = (
            base_reg
            or _extract_error_register(error_line)
            or _select_access_register(fail_insn, error_line, _is_map_value)
        )
        if target_reg is None:
            return None
        value_size = details.get("value_size")
        range_expr = (
            f"{op.offset} + {access_size} <= {value_size}"
            if value_size is not None
            else f"{op.offset} + {access_size} <= {target_reg}.range"
        )
        return ObligationSpec(
            kind="map_value_access",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches map_value",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=range_expr,
                ),
            ],
        )

    # -------------------------------------------------------------------
    # stack_access: min_off >= -512 AND max_off <= 0
    # -------------------------------------------------------------------
    if family == "stack_access":
        target_reg = base_reg or _extract_error_register(error_line)
        if target_reg is None:
            return None
        return ObligationSpec(
            kind="stack_access",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches fp",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=f"{abs(op.offset)} + {access_size} <= 512",
                ),
            ],
        )

    # -------------------------------------------------------------------
    # scalar_bounds: pointer arithmetic / shift / div-by-zero errors
    # -------------------------------------------------------------------
    if family == "scalar_bounds":
        target_reg = _extract_error_register(error_line) or base_reg
        if target_reg is None:
            return None
        return ObligationSpec(
            kind="scalar_deref",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="type_is_pointer",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type is pointer-compatible",
                )
            ],
        )

    # -------------------------------------------------------------------
    # helper_arg / trusted_null_check
    # -------------------------------------------------------------------
    if family in {"helper_arg", "trusted_null_check"}:
        # "unbounded memory access" errors on call instructions have
        # context-specific handling in the old code (e.g. dynptr_slice ->
        # buffer_length_pair).  Let old code decide.
        if "unbounded memory access" in lowered and op.kind == "call":
            return None

        # trusted_null_check vs null_check distinction is subtle: the old
        # code decides between the two based on register state and call
        # context (e.g. "Possibly NULL pointer passed to helper argN" can
        # be either null_check or trusted_null_check depending on the
        # full state).  Let old code handle trusted_null_check entirely so
        # we don't change the null_check / trusted_null_check classification.
        if family == "trusted_null_check":
            return None

        target_reg = (
            _extract_error_register(error_line)
            or _extract_error_arg_register(error_line)
            or base_reg
        )
        if target_reg is None:
            return None
        # helper_arg: type match — only use formal catalog for non-null,
        # non-trusted cases where the error message clearly mentions type mismatch.
        # For contract errors (helper contract mismatch, etc.) let old code handle.
        if not _is_helper_contract_error(error_line) and not _error_mentions_null(lowered):
            expected_types = _helper_contract_expected_types(error_line, "")
            if not expected_types:
                expected_types = ["ptr", "map_ptr", "map_value"]
            return ObligationSpec(
                kind="helper_arg",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=0,
                access_size=0,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type matches {','.join(expected_types)}",
                    )
                ],
            )
        return None

    # -------------------------------------------------------------------
    # memory_access
    # -------------------------------------------------------------------
    if family == "memory_access":
        target_reg = (
            base_reg
            or _extract_error_register(error_line)
        )
        if target_reg is None:
            return None

        # If the error message contains a quoted non-pointer type (e.g.
        # "invalid mem access 'scalar'") the issue is actually that the
        # register holds a scalar, not a pointer — classify as scalar_deref.
        _quoted_type_match = re.search(r"invalid mem access '([^']+)'", error_line)
        if _quoted_type_match:
            quoted_type = _quoted_type_match.group(1).lower()
            if quoted_type in {"scalar", "inv", "not_init"} or not is_pointer_type_name(quoted_type):
                return ObligationSpec(
                    kind="scalar_deref",
                    failing_insn=fail_insn.insn_idx,
                    base_reg=target_reg,
                    index_reg=None,
                    const_off=op.offset,
                    access_size=access_size,
                    atoms=[
                        PredicateAtom(
                            atom_id="type_is_pointer",
                            registers=(target_reg,),
                            expression=f"{target_reg}.type is pointer-compatible",
                        )
                    ],
                )

        # Check if it's a null pointer access (PTR_MAYBE_NULL)
        if "PTR_MAYBE_NULL" in formal.precondition or "may_be_null" in formal.precondition:
            return ObligationSpec(
                kind="null_check",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=op.offset,
                access_size=access_size,
                atoms=[
                    PredicateAtom(
                        atom_id="non_null",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type not nullable",
                    )
                ],
            )
        return ObligationSpec(
            kind="memory_access",
            failing_insn=fail_insn.insn_idx,
            base_reg=target_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=access_size,
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches mem,ptr",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=(
                        f"{target_reg}.off + {op.offset} + {access_size} <= "
                        f"{details.get('mem_size', 0)}"
                    ),
                ),
            ],
        )

    # -------------------------------------------------------------------
    # unreleased_reference: evaluable=False in catalog, but just in case
    # -------------------------------------------------------------------
    if family == "unreleased_reference":
        return ObligationSpec(
            kind="unreleased_reference",
            failing_insn=fail_insn.insn_idx,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    # -------------------------------------------------------------------
    # execution_context: evaluable=False for most, skip
    # -------------------------------------------------------------------
    if family == "execution_context":
        return None  # let old code handle it

    # Unknown family — let the old if-else tree handle it
    return None


def infer_formal_obligation(
    trace_ir: TraceIR,
    fail_insn: InstructionNode,
    error_line: str,
) -> ObligationSpec | None:
    """Infer the failing instruction's proof obligation from opcode and state.

    The formal obligation catalog is the PRIMARY and ONLY path for all error
    families that are directly observable from LOG_LEVEL2 trace data.  After
    the catalog, we only handle the small set of obligation kinds that the
    catalog genuinely cannot cover (ptr_add, protocol families, BTF errors,
    execution-context / limits errors, trusted-null-check).
    """

    op = _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode)
    lowered = error_line.lower()
    details = _extract_error_details(error_line)

    # -----------------------------------------------------------------------
    # STEP 1: Formal catalog (primary path).
    # For all error families whose preconditions are directly evaluable from
    # LOG_LEVEL2 data, the catalog builds the complete ObligationSpec.
    # -----------------------------------------------------------------------
    # Pre-check: dynptr protocol errors appear as "invalid mem access 'scalar'"
    # on load/store ops, which the formal catalog would misclassify as
    # scalar_deref.  Detect them first so the catalog is not consulted.
    if op.kind in {"load", "store"} and "invalid mem access" in lowered:
        if _looks_like_dynptr_state_access_error(trace_ir, fail_insn, error_line):
            access_size = op.size or details.get("size") or 0
            base_reg = op.base_reg
            target_reg = _select_protocol_register_from_trace(
                trace_ir, fail_insn, error_line, expected_type="dynptr",
            ) or base_reg
            if target_reg is not None:
                return ObligationSpec(
                    kind="dynptr_protocol",
                    failing_insn=fail_insn.insn_idx,
                    base_reg=target_reg,
                    index_reg=None,
                    const_off=op.offset,
                    access_size=access_size,
                    atoms=[
                        PredicateAtom(
                            atom_id="type_matches",
                            registers=(target_reg,),
                            expression=f"{target_reg}.type matches dynptr",
                        )
                    ],
                )

    formal_obligation_spec = _try_formal_catalog_obligation(
        fail_insn, op, error_line, details, lowered
    )
    if formal_obligation_spec is not None:
        return formal_obligation_spec

    # -----------------------------------------------------------------------
    # STEP 2: Cases the formal catalog cannot cover.
    # Only the obligation kinds below are NOT handled by the catalog, so only
    # these branches are reachable after the catalog returns None.
    # -----------------------------------------------------------------------

    # --- load/store errors NOT matched by the formal catalog -----------------
    # The catalog covers most load/store error families (null_check, packet_access,
    # map_value_access, scalar_deref, memory_access) but misses a few specific
    # error message patterns.  Handle them here with minimal, targeted checks.
    if op.kind in {"load", "store"}:
        access_size = op.size or details.get("size") or 0
        base_reg = op.base_reg

        # Null-check: nullable pointer type used without null check.
        # The formal catalog handles "or_null" errors via null_check/memory_access
        # families BUT the pattern "invalid mem access 'X_or_null'" without a
        # register prefix doesn't match the catalog regex ("R\\d+ invalid mem...").
        # Handle it here using the base register state directly.
        if base_reg is not None and (_is_nullable(_lookup_state(fail_insn, base_reg)) or _error_mentions_null(lowered)):
            target_reg = base_reg
            return ObligationSpec(
                kind="null_check",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=op.offset,
                access_size=access_size,
                atoms=[
                    PredicateAtom(
                        atom_id="non_null",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type not nullable",
                    )
                ],
            )

        # Dynptr state access — must check BEFORE stack since dynptr errors
        # often occur on fp-relative stores (R10-based) but are classified by
        # error content, not by the register type.
        if _looks_like_dynptr_state_access_error(trace_ir, fail_insn, error_line):
            target_reg = _select_protocol_register_from_trace(
                trace_ir, fail_insn, error_line, expected_type="dynptr",
            ) or base_reg
            if target_reg is not None:
                return ObligationSpec(
                    kind="dynptr_protocol",
                    failing_insn=fail_insn.insn_idx,
                    base_reg=target_reg,
                    index_reg=None,
                    const_off=op.offset,
                    access_size=access_size,
                    atoms=[
                        PredicateAtom(
                            atom_id="type_matches",
                            registers=(target_reg,),
                            expression=f"{target_reg}.type matches dynptr",
                        )
                    ],
                )

        # Stack access: fp-relative errors with stack-specific error messages
        # ("invalid indirect read/write from stack") not matched by catalog.
        if base_reg is not None and ("stack" in lowered or _is_stack_base(_lookup_state(fail_insn, base_reg), base_reg)):
            return ObligationSpec(
                kind="stack_access",
                failing_insn=fail_insn.insn_idx,
                base_reg=base_reg,
                index_reg=None,
                const_off=op.offset,
                access_size=access_size,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(base_reg,),
                        expression=f"{base_reg}.type matches fp",
                    ),
                    PredicateAtom(
                        atom_id="range_at_least",
                        registers=(base_reg,),
                        expression=f"{abs(op.offset)} + {access_size} <= {STACK_FRAME_BYTES}",
                    ),
                ],
            )

        # Generic memory access not covered by catalog (e.g. "invalid access to
        # memory, mem_size=N off=N size=N") — build memory_access obligation.
        if base_reg is not None and ("invalid access to memory" in lowered or "mem_size" in lowered):
            return ObligationSpec(
                kind="memory_access",
                failing_insn=fail_insn.insn_idx,
                base_reg=base_reg,
                index_reg=None,
                const_off=op.offset,
                access_size=access_size,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(base_reg,),
                        expression=f"{base_reg}.type matches mem,ptr",
                    ),
                    PredicateAtom(
                        atom_id="range_at_least",
                        registers=(base_reg,),
                        expression=(
                            f"{base_reg}.off + {op.offset} + {access_size} <= "
                            f"{details.get('mem_size', 0)}"
                        ),
                    ),
                ],
            )

        # State-based map_value inference: when error message is absent or
        # doesn't match any catalog pattern, infer map_value_access from the
        # register state directly.  This covers cases where the error line
        # describes a downstream consequence (e.g. "R4 must be a known
        # constant") while the actual obligation failure is the out-of-bounds
        # load from the map_value register.
        base_state = _lookup_state(fail_insn, base_reg) if base_reg is not None else None
        if base_reg is not None and _is_map_value(base_state):
            value_size = details.get("value_size")
            range_expr = (
                f"{op.offset} + {access_size} <= {value_size}"
                if value_size is not None
                else f"{op.offset} + {access_size} <= {base_reg}.range"
            )
            return ObligationSpec(
                kind="map_value_access",
                failing_insn=fail_insn.insn_idx,
                base_reg=base_reg,
                index_reg=None,
                const_off=op.offset,
                access_size=access_size,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(base_reg,),
                        expression=f"{base_reg}.type matches map_value",
                    ),
                    PredicateAtom(
                        atom_id="range_at_least",
                        registers=(base_reg,),
                        expression=range_expr,
                    ),
                ],
            )

    # --- packet_ptr_add: pointer arithmetic error on pkt register ----------

    if op.kind == "ptr_add":
        base_state = _lookup_state(fail_insn, op.dst_reg)
        if _is_packet_ptr(base_state):
            atoms = [
                PredicateAtom(
                    atom_id="base_is_pkt",
                    registers=(op.dst_reg,),
                    expression=f"{op.dst_reg}.type == pkt",
                )
            ]
            if op.src_reg is not None:
                atoms.extend(
                    [
                        PredicateAtom(
                            atom_id="offset_non_negative",
                            registers=(op.src_reg,),
                            expression=f"{op.src_reg}.smin >= 0",
                        ),
                        PredicateAtom(
                            atom_id="offset_bounded",
                            registers=(op.src_reg,),
                            expression=f"{op.src_reg}.umax is bounded",
                        ),
                    ]
                )
            return ObligationSpec(
                kind="packet_ptr_add",
                failing_insn=fail_insn.insn_idx,
                base_reg=op.dst_reg,
                index_reg=op.src_reg,
                const_off=op.immediate or 0,
                access_size=0,
                atoms=atoms,
            )

    # --- call: only handle the edge cases not covered by the formal catalog ---
    # Most call-site errors (packet_access, map_value_access, helper_arg, null_check)
    # are already matched by the formal catalog above.  Only dynptr_slice (unbounded
    # memory access on bpf_dynptr_slice) and trusted_null_check (call-site heuristic)
    # need special handling here.
    if op.kind == "call":
        call_target = _call_target_name(fail_insn.bytecode)

        # dynptr_slice: "unbounded memory access" on bpf_dynptr_slice is a
        # buffer_length_pair violation — formal catalog cannot detect the call target.
        if "unbounded memory access" in lowered and "dynptr_slice" in call_target:
            return ObligationSpec(
                kind="buffer_length_pair",
                failing_insn=fail_insn.insn_idx,
                base_reg="R3",
                index_reg=_extract_error_register(error_line) or "R4",
                const_off=0,
                access_size=0,
                atoms=[],
            )

        # trusted_null_check: call-site heuristic for functions that require
        # non-null trusted pointers (formal catalog explicitly returns None for this).
        if _looks_like_trusted_null_call(call_target, fail_insn):
            reg = (
                _extract_error_register(error_line)
                or _extract_error_arg_register(error_line)
                or _first_zero_scalar_register(fail_insn)
                or _first_nullable_register(fail_insn)
                or "R1"
            )
            return ObligationSpec(
                kind="trusted_null_check",
                failing_insn=fail_insn.insn_idx,
                base_reg=reg,
                index_reg=None,
                const_off=0,
                access_size=0,
                atoms=[
                    PredicateAtom(
                        atom_id="non_null",
                        registers=(reg,),
                        expression=f"{reg} is non-null",
                    )
                ],
            )

        # helper access to packet not allowed: catalog doesn't match this message.
        if "helper access to the packet is not allowed" in lowered:
            target_reg = _select_access_register(fail_insn, error_line, _is_packet_ptr) or "R1"
            return ObligationSpec(
                kind="packet_access",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=details.get("off", 0),
                access_size=details.get("size", 0),
                atoms=[
                    PredicateAtom(
                        atom_id="base_is_pkt",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type == pkt",
                    ),
                    PredicateAtom(
                        atom_id="range_at_least",
                        registers=(target_reg,),
                        expression=f"{details.get('off', 0)} + {details.get('size', 0)} <= {target_reg}.range",
                    ),
                ],
            )

        # helper_arg contract errors: "must be a rcu pointer", "unsupported reg type",
        # etc.  These are not in the formal catalog.
        reg = _extract_error_register(error_line) or _extract_error_arg_register(error_line)
        if _is_helper_contract_error(error_line) or (
            "trusted_ptr_" in lowered and _call_target_suggests_pointer_contract(call_target)
        ):
            target_reg = reg or _select_helper_contract_register(fail_insn, call_target)
            if target_reg is not None:
                expected_types = _helper_contract_expected_types(error_line, call_target)
                return ObligationSpec(
                    kind="helper_arg",
                    failing_insn=fail_insn.insn_idx,
                    base_reg=target_reg,
                    index_reg=None,
                    const_off=0,
                    access_size=0,
                    atoms=[
                        PredicateAtom(
                            atom_id="type_matches",
                            registers=(target_reg,),
                            expression=f"{target_reg}.type matches {','.join(expected_types)}",
                        )
                    ],
                )

    # --- protocol / context / meta errors (opcode-independent) ---------------

    if _is_reference_leak_error(error_line):
        return ObligationSpec(
            kind="unreleased_reference",
            failing_insn=fail_insn.insn_idx,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_exit_return_type_error(error_line):
        return ObligationSpec(
            kind="exit_return_type",
            failing_insn=fail_insn.insn_idx,
            base_reg="R0",
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[
                PredicateAtom(
                    atom_id="scalar_bounds_known",
                    registers=("R0",),
                    expression="R0 has known scalar bounds",
                )
            ],
        )

    if _is_verifier_limits_error(error_line):
        return ObligationSpec(
            kind="verifier_limits",
            failing_insn=fail_insn.insn_idx,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_exception_callback_context_error(error_line):
        return ObligationSpec(
            kind="exception_callback_context",
            failing_insn=fail_insn.insn_idx,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_execution_context_error(trace_ir, fail_insn, error_line):
        return ObligationSpec(
            kind="execution_context",
            failing_insn=fail_insn.insn_idx,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_dynptr_protocol_error(fail_insn.bytecode, error_line):
        target_reg = _select_protocol_register_from_trace(
            trace_ir,
            fail_insn,
            error_line,
            expected_type="dynptr",
        )
        if target_reg is not None:
            return ObligationSpec(
                kind="dynptr_protocol",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=0,
                access_size=0,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type matches dynptr",
                    )
                ],
            )

    # iterator_protocol: "reference type size cannot be determined" on bpf_iter_*
    # calls overlaps with the BTF reference type error pattern.  Check iterator
    # BEFORE btf_reference_type so iterator errors are classified correctly.
    if _is_iterator_protocol_error(fail_insn.bytecode, error_line):
        target_reg = _select_protocol_register_from_trace(
            trace_ir, fail_insn, error_line, expected_type="iter",
        )
        if target_reg is not None:
            return ObligationSpec(
                kind="iterator_protocol",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=0,
                access_size=0,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type matches iter",
                    )
                ],
            )

    if _is_btf_reference_type_error(error_line) or _is_btf_metadata_error(error_line):
        reg = _extract_error_register(error_line) or _extract_error_arg_register(error_line)
        return ObligationSpec(
            kind="btf_reference_type",
            failing_insn=fail_insn.insn_idx,
            base_reg=reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_buffer_length_pair_error(error_line):
        base_arg, index_arg = _extract_error_arg_pair(error_line)
        return ObligationSpec(
            kind="buffer_length_pair",
            failing_insn=fail_insn.insn_idx,
            base_reg=base_arg,
            index_reg=index_arg,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _looks_like_iterator_leak(trace_ir, fail_insn):
        target_reg = _select_protocol_register_from_trace(
            trace_ir,
            fail_insn,
            error_line,
            expected_type="iter",
        )
        if target_reg is not None:
            return ObligationSpec(
                kind="iterator_protocol",
                failing_insn=fail_insn.insn_idx,
                base_reg=target_reg,
                index_reg=None,
                const_off=0,
                access_size=0,
                atoms=[
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(target_reg,),
                        expression=f"{target_reg}.type matches iter",
                    )
                ],
            )

    if _is_trusted_null_error(error_line) or _is_trusted_reference_error(error_line):
        reg = (
            _extract_error_register(error_line)
            or _extract_error_arg_register(error_line)
            or _first_nullable_register(fail_insn)
        )
        if reg is None:
            return None
        return ObligationSpec(
            kind="trusted_null_check",
            failing_insn=fail_insn.insn_idx,
            base_reg=reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=(
                [
                    PredicateAtom(
                        atom_id="type_matches",
                        registers=(reg,),
                        expression=f"{reg}.type matches trusted_ptr_,rcu_ptr_,ptr_,ptr",
                    )
                ]
                if _is_trusted_reference_error(error_line)
                else [
                    PredicateAtom(
                        atom_id="non_null",
                        registers=(reg,),
                        expression=f"{reg} is non-null",
                    )
                ]
            ),
        )

    if _error_mentions_null(lowered):
        reg = _extract_error_register(error_line) or _first_nullable_register(fail_insn)
        if reg is None:
            return None
        return ObligationSpec(
            kind="null_check",
            failing_insn=fail_insn.insn_idx,
            base_reg=reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[
                PredicateAtom(
                    atom_id="non_null",
                    registers=(reg,),
                    expression=f"{reg}.type not nullable",
                )
            ],
        )

    return None


def infer_obligation(
    parsed_trace: ParsedTrace,
    error_line: str,
    error_insn: int | None = None,
) -> ObligationSpec | None:
    """Infer a formal obligation directly from a parsed verifier trace."""

    _trace_ir, _fail_insn, obligation = _infer_obligation_internal(
        parsed_trace,
        error_line,
        error_insn,
        allow_low_confidence_fallback=True,
        include_related_candidates=True,
    )
    return obligation


def _infer_obligation_internal(
    parsed_trace: ParsedTrace,
    error_line: str,
    error_insn: int | None = None,
    *,
    trace_ir: TraceIR | None = None,
    allow_low_confidence_fallback: bool = True,
    include_related_candidates: bool = True,
) -> tuple[TraceIR, InstructionNode | None, ObligationSpec | None]:
    active_trace_ir = trace_ir or build_trace_ir(parsed_trace)
    fail_insn = _select_failing_instruction(parsed_trace, active_trace_ir, error_line, error_insn)
    for candidate in _candidate_inference_nodes(
        active_trace_ir,
        fail_insn,
        include_related_candidates=include_related_candidates,
    ):
        obligation = infer_formal_obligation(active_trace_ir, candidate, error_line)
        if obligation is not None:
            obligation.failing_trace_pos = candidate.trace_pos
            return active_trace_ir, fail_insn, obligation
    obligation = _infer_obligation_fallback(active_trace_ir, fail_insn, error_line)
    if (
        obligation is not None
        and not allow_low_confidence_fallback
        and (
            (
                obligation.kind == "verifier_limits"
                and _is_processed_summary_line(error_line)
            )
            or (
                obligation.kind == "helper_arg"
                and (
                    fail_insn is None
                    or _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode).kind != "call"
                )
            )
        )
    ):
        obligation = None
    if obligation is not None and fail_insn is not None and obligation.failing_trace_pos is None:
        obligation.failing_trace_pos = fail_insn.trace_pos
    return active_trace_ir, fail_insn, obligation


def _candidate_inference_nodes(
    trace_ir: TraceIR,
    fail_insn: InstructionNode | None,
    *,
    include_related_candidates: bool = True,
) -> list[InstructionNode]:
    candidates: list[InstructionNode] = []
    seen: set[int] = set()

    def add(node: InstructionNode | None) -> None:
        if node is None or node.trace_pos in seen:
            return
        seen.add(node.trace_pos)
        candidates.append(node)

    add(fail_insn)
    if include_related_candidates and (
        fail_insn is None or _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode).kind != "call"
    ):
        add(_last_call_instruction(trace_ir))
    return candidates


def _last_call_instruction(trace_ir: TraceIR) -> InstructionNode | None:
    for node in reversed(trace_ir.instructions):
        if _parse_bytecode(node.insn_idx, node.bytecode).kind == "call":
            return node
    return None


def _infer_obligation_fallback(
    trace_ir: TraceIR,
    fail_insn: InstructionNode | None,
    error_line: str,
) -> ObligationSpec | None:
    lowered = error_line.lower()
    details = _extract_error_details(error_line)
    failing_insn = _fallback_failing_insn(trace_ir, fail_insn)
    reg = _extract_error_register(error_line) or _extract_error_arg_register(error_line)

    if fail_insn is not None and _node_has_async_callback_state(fail_insn):
        return ObligationSpec(
            kind="verifier_limits",
            failing_insn=failing_insn,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_verifier_limits_fallback_error(error_line):
        return ObligationSpec(
            kind="verifier_limits",
            failing_insn=failing_insn,
            base_reg=None,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if _is_btf_metadata_error(error_line):
        return ObligationSpec(
            kind="btf_reference_type",
            failing_insn=failing_insn,
            base_reg=reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[],
        )

    if "invalid access to packet" in lowered or "helper access to the packet is not allowed" in lowered:
        target_reg = reg or "R1"
        return ObligationSpec(
            kind="packet_access",
            failing_insn=failing_insn,
            base_reg=target_reg,
            index_reg=None,
            const_off=details.get("off", 0),
            access_size=details.get("size", 0),
            atoms=[
                PredicateAtom(
                    atom_id="base_is_pkt",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type == pkt",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=f"{details.get('off', 0)} + {details.get('size', 0)} <= {target_reg}.range",
                ),
            ],
        )

    if "invalid access to map value" in lowered:
        target_reg = reg or "R1"
        value_size = details.get("value_size")
        range_expr = (
            f"{details.get('off', 0)} + {details.get('size', 0)} <= {value_size}"
            if value_size is not None
            else f"{details.get('off', 0)} + {details.get('size', 0)} <= {target_reg}.range"
        )
        return ObligationSpec(
            kind="map_value_access",
            failing_insn=failing_insn,
            base_reg=target_reg,
            index_reg=None,
            const_off=details.get("off", 0),
            access_size=details.get("size", 0),
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches map_value,map_ptr,ptr",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=range_expr,
                ),
            ],
        )

    if _helper_arg_error_clue(error_line) and "reg type unsupported for arg#0 function" not in lowered:
        target_reg = reg or "R1"
        # Try to extract the expected type directly from "expected=X" in the
        # error message.  The verifier emits "R%d type=%s expected=%s" where
        # the last token is the comma-separated list of accepted types.  Prefer
        # this over the keyword-based heuristic so that, e.g., "expected=fp"
        # maps to ["fp"] rather than the catch-all wide list.
        _expected_match = re.search(r"expected=(\S+)", error_line)
        if _expected_match:
            raw_expected = _expected_match.group(1).rstrip(",")
            expected_types = [t.strip() for t in raw_expected.split(",") if t.strip()]
        else:
            expected_types = _expected_types_from_helper_text(error_line) or ["ptr", "scalar", "map_value", "pkt", "fp"]
        return ObligationSpec(
            kind="helper_arg",
            failing_insn=failing_insn,
            base_reg=target_reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches {','.join(expected_types)}",
                )
            ],
        )

    if "invalid mem access 'scalar'" in lowered or "invalid mem access 'inv'" in lowered:
        target_reg = reg or "R1"
        return ObligationSpec(
            kind="scalar_deref",
            failing_insn=failing_insn,
            base_reg=target_reg,
            index_reg=None,
            const_off=0,
            access_size=details.get("size", 0),
            atoms=[
                PredicateAtom(
                    atom_id="type_is_pointer",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type is pointer-compatible",
                )
            ],
        )

    if "invalid bpf_context access" in lowered or "unbounded memory access" in lowered or "invalid mem access" in lowered:
        target_reg = reg or "R1"
        return ObligationSpec(
            kind="memory_access",
            failing_insn=failing_insn,
            base_reg=target_reg,
            index_reg=None,
            const_off=details.get("off", 0),
            access_size=details.get("size", 0),
            atoms=[
                PredicateAtom(
                    atom_id="type_matches",
                    registers=(target_reg,),
                    expression=f"{target_reg}.type matches mem,ptr,ctx,fp",
                ),
                PredicateAtom(
                    atom_id="range_at_least",
                    registers=(target_reg,),
                    expression=f"{details.get('off', 0)} + {details.get('size', 0)} <= {target_reg}.range",
                ),
            ],
        )

    if _is_specific_verifier_safety_error(error_line):
        return ObligationSpec(
            kind="safety_violation",
            failing_insn=failing_insn,
            base_reg=reg,
            index_reg=None,
            const_off=details.get("off", 0),
            access_size=details.get("size", 0),
            atoms=[],
        )

    return None


def _fallback_failing_insn(
    trace_ir: TraceIR,
    fail_insn: InstructionNode | None,
) -> int:
    if fail_insn is not None:
        return fail_insn.insn_idx
    if trace_ir.instructions:
        return trace_ir.instructions[-1].insn_idx
    return 0


def evaluate_obligation(trace_ir: TraceIR, obligation: ObligationSpec) -> list[PredicateEval]:
    """Evaluate every predicate atom over every instruction state."""

    evaluations: list[PredicateEval] = []
    atom_targets = _atom_targets(trace_ir, obligation)

    for instruction in trace_ir.instructions:
        for phase, state_map in (("pre", instruction.pre_state), ("post", instruction.post_state)):
            for atom in obligation.atoms:
                result, witness, carrier_register = _eval_atom(
                    trace_ir=trace_ir,
                    trace_pos=instruction.trace_pos,
                    insn_idx=instruction.insn_idx,
                    phase=phase,
                    atom=atom,
                    state_map=state_map,
                    obligation=obligation,
                    target=atom_targets.get(atom.atom_id),
                )
                evaluations.append(
                    PredicateEval(
                        insn_idx=instruction.insn_idx,
                        phase=phase,
                        atom_id=atom.atom_id,
                        result=result,
                        witness=witness,
                        carrier_register=carrier_register,
                        trace_pos=instruction.trace_pos,
                    )
                )

    return evaluations


def find_loss_transition(
    evals: list[PredicateEval],
    fail_insn: int,
    *,
    point_order: dict[tuple[int, str], int] | None = None,
    include_fail_post: bool = True,
    fail_trace_pos: int | None = None,
) -> TransitionWitness | None:
    """Find the first loss after the last fully satisfied predicate point."""

    fail_point = fail_trace_pos if fail_trace_pos is not None else fail_insn
    fail_cutoff = _point_rank(fail_point, "pre", point_order)
    if include_fail_post:
        fail_cutoff = _point_rank(fail_point, "post", point_order)
    grouped: dict[tuple[int, str], list[PredicateEval]] = defaultdict(list)
    for evaluation in evals:
        point = evaluation.trace_pos if evaluation.trace_pos is not None else evaluation.insn_idx
        if _point_rank(point, evaluation.phase, point_order) <= fail_cutoff:
            grouped[(point, evaluation.phase)].append(evaluation)

    if not grouped:
        return None

    timeline: list[tuple[_OverallPoint, dict[str, PredicateEval]]] = []
    for key in sorted(grouped, key=lambda item: _point_rank(item[0], item[1], point_order)):
        entries = grouped[key]
        by_atom = {entry.atom_id: entry for entry in entries}
        overall = _combine_results([entry.result for entry in by_atom.values()])
        sample = entries[0]
        timeline.append(
            (
                _OverallPoint(
                    insn_idx=sample.insn_idx,
                    phase=key[1],
                    result=overall,
                    trace_pos=sample.trace_pos,
                ),
                by_atom,
            )
        )

    fail_pre_rank = _point_rank(fail_point, "pre", point_order)
    last_satisfied_idx = max(
        (
            index
            for index, (point, _) in enumerate(timeline)
            if point.result == "satisfied"
            and _point_rank(point.trace_pos if point.trace_pos is not None else point.insn_idx, point.phase, point_order) <= fail_pre_rank
        ),
        default=-1,
    )
    if last_satisfied_idx < 0 or last_satisfied_idx + 1 >= len(timeline):
        return None

    previous_point, previous_atoms = timeline[last_satisfied_idx]
    current_point, current_atoms = timeline[last_satisfied_idx + 1]
    if current_point.result == "satisfied":
        return None

    candidates: list[tuple[int, int, str, PredicateEval, str]] = []
    for atom_id, current in current_atoms.items():
        if current.result == "satisfied":
            continue
        previous = previous_atoms.get(atom_id)
        previous_result = previous.result if previous is not None else "unknown"
        candidates.append(
            (
                0 if previous_result == "satisfied" else 1,
                RESULT_ORDER[current.result],
                atom_id,
                current,
                previous_result,
            )
        )

    if not candidates:
        return None

    _, _, atom_id, current, previous_result = min(candidates)
    return TransitionWitness(
        atom_id=atom_id,
        insn_idx=current_point.insn_idx,
        before_result=previous_result,
        after_result=current.result,
        witness=current.witness,
        carrier_register=current.carrier_register,
        trace_pos=current_point.trace_pos,
    )


def backward_slice(
    trace_ir: TraceIR,
    obligation: ObligationSpec,
    transition: TransitionWitness,
) -> list[SliceEdge]:
    """Build a complete backward slice from the violated predicate atom.

    Strategy A (preferred): when mark_precise backtrack chains are available for the
    relevant registers, follow the COMPLETE chain — it is the verifier's own root-cause
    analysis and constitutes ground truth for which instructions are causally relevant.
    All consecutive (src, dst) pairs in each chain are recorded as backtrack_hint edges
    and the chain endpoints are seeded into the def-use BFS worklist so that the two
    strategies compose naturally.

    Strategy B (fallback / always runs): def-use chain traversal starting from the
    transition witness.  A visited set (not a depth limit) prevents infinite loops.
    The traversal is bounded only by the trace boundaries.
    """

    node_by_pos = {instruction.trace_pos: instruction for instruction in trace_ir.instructions}
    seed_registers = (
        [transition.carrier_register]
        if transition.carrier_register is not None
        else _registers_for_atom(obligation, transition.atom_id)
    )
    start_pos = transition.trace_pos
    if start_pos is None:
        start_node = _find_obligation_node(trace_ir, obligation)
        start_pos = start_node.trace_pos if start_node is not None else None
    if start_pos is None:
        return []

    # Strategy A-prime (lineage): extend seed registers with all aliases of the
    # carrier register at the transition point.  This surfaces spill/fill chains
    # that the def-use BFS might miss if the intermediate stack slot is not in
    # the instruction's explicit defs/uses list.
    if trace_ir.value_lineage is not None:
        extra_seed_registers: list[str] = []
        for seed_reg in list(seed_registers):
            aliases = trace_ir.value_lineage.get_all_aliases(start_pos, seed_reg)
            for alias in aliases:
                if alias not in seed_registers and alias not in extra_seed_registers:
                    extra_seed_registers.append(alias)
        seed_registers = list(seed_registers) + extra_seed_registers

    # Build a fast lookup: insn_idx -> trace_pos for Strategy A chain seeding.
    pos_by_insn: dict[int, int] = {
        instruction.insn_idx: instruction.trace_pos
        for instruction in trace_ir.instructions
    }

    seen_points: set[tuple[int, str]] = set()
    edge_keys: set[tuple[tuple[int, str], tuple[int, str], str]] = set()
    edges: list[SliceEdge] = []

    # Strategy A: seed ALL backtrack chain edges upfront for relevant registers.
    # These are the verifier's own mark_precise backward chains — follow them completely.
    for register in seed_registers:
        for chain_edge in _all_backtrack_edges(trace_ir.backtrack_chains, register):
            _record_edge(chain_edge, edge_keys, edges)

    worklist: deque[tuple[int, str]] = deque(
        (start_pos, register) for register in seed_registers
    )
    # Also seed worklist from the earliest point in each relevant backtrack chain.
    for register in seed_registers:
        for chain in trace_ir.backtrack_chains:
            relevant_links = [
                link for link in chain.links if register in _decode_regs_mask(link.regs)
            ]
            if not relevant_links:
                continue
            # links are stored error→root; chronologically the last element is the root.
            root_link = relevant_links[-1]
            chain_start_pos = pos_by_insn.get(root_link.insn_idx)
            if chain_start_pos is not None:
                worklist.append((chain_start_pos, register))

    # Strategy B: def-use BFS — no depth limit, visited set prevents cycles.
    while worklist:
        trace_pos, register = worklist.popleft()
        if (trace_pos, register) in seen_points:
            continue
        seen_points.add((trace_pos, register))

        node = node_by_pos.get(trace_pos)
        if node is None:
            continue

        if register in node.defs:
            for input_register in _definition_inputs(node, register):
                def_node = _find_reaching_definition(trace_ir, trace_pos, input_register)
                if def_node is None:
                    continue
                edge = SliceEdge(
                    src=(def_node.insn_idx, input_register),
                    dst=(node.insn_idx, register),
                    kind="def_use",
                    reason=(
                        f"{register} at insn {node.insn_idx} depends on {input_register} from insn {def_node.insn_idx}"
                    ),
                )
                if _record_edge(edge, edge_keys, edges):
                    worklist.append((def_node.trace_pos, input_register))
        else:
            def_node = _find_reaching_definition(trace_ir, trace_pos, register)
            if def_node is not None:
                edge = SliceEdge(
                    src=(def_node.insn_idx, register),
                    dst=(node.insn_idx, register),
                    kind="def_use",
                    reason=f"{register} flows from insn {def_node.insn_idx} to insn {node.insn_idx}",
                )
                if _record_edge(edge, edge_keys, edges):
                    worklist.append((def_node.trace_pos, register))

        guard_node = _find_guard_that_changed_atom(
            trace_ir,
            obligation,
            transition.atom_id,
            trace_pos,
            transition.carrier_register,
        )
        if guard_node is not None:
            edge = SliceEdge(
                src=(guard_node.insn_idx, register),
                dst=(node.insn_idx, register),
                kind="control",
                reason=(
                    f"branch at insn {guard_node.insn_idx} changed {transition.atom_id} "
                    f"before insn {node.insn_idx}"
                ),
            )
            _record_edge(edge, edge_keys, edges)

        # Per-node backtrack hints (single-hop edges touching this specific node).
        for hint in _matching_backtrack_edges(trace_ir.backtrack_chains, node.insn_idx, register):
            _record_edge(hint, edge_keys, edges)

    return sorted(edges, key=lambda edge: (edge.dst[0], edge.src[0], edge.kind, edge.src[1]))


def backward_obligation_slice(
    parsed_trace: ParsedTrace,
    transition_witness_idx: int,
    obligation: ObligationSpec,
) -> list[tuple[int, str]]:
    """
    Walk backward from the transition witness and retain instructions that shaped the obligation.

    The returned chain is ordered from earliest cause to the transition witness.
    """

    trace_ir = build_trace_ir(parsed_trace)
    return _backward_obligation_slice_from_ir(
        trace_ir,
        parsed_trace,
        transition_witness_idx,
        obligation,
    )


def _backward_obligation_slice_from_ir(
    trace_ir: TraceIR,
    parsed_trace: ParsedTrace,
    transition_witness_idx: int,
    obligation: ObligationSpec,
    transition: TransitionWitness | None = None,
) -> list[tuple[int, str]]:
    ordered = list(trace_ir.instructions)
    if transition is not None and transition.trace_pos is not None:
        start = transition.trace_pos
    else:
        start = next(
            (
                instruction.trace_pos
                for instruction in reversed(ordered)
                if instruction.insn_idx == transition_witness_idx
            ),
            None,
        )
    if start is None:
        return []

    tracked_registers = _transition_seed_registers(obligation, transition)
    reasons_by_insn: dict[int, list[str]] = {}

    for position in range(start, -1, -1):
        instruction = ordered[position]
        op = _parse_bytecode(instruction.insn_idx, instruction.bytecode)

        backtrack_registers = _matching_backtrack_registers(
            parsed_trace.backtrack_chains,
            instruction.insn_idx,
            tracked_registers,
            transition_witness_idx,
        )
        if backtrack_registers:
            reasons = [
                f"mark_precise backtrack target for {register}"
                for register in backtrack_registers
            ]
            _record_causal_reasons(reasons_by_insn, instruction.insn_idx, reasons)
            tracked_registers.update(backtrack_registers)

        affected_registers = [register for register in instruction.defs if register in tracked_registers]
        if affected_registers:
            reasons = [
                _slice_write_reason(register, obligation)
                for register in affected_registers
            ]
            _record_causal_reasons(reasons_by_insn, instruction.insn_idx, reasons)
            tracked_registers.update(instruction.uses)

        narrowed_registers = _branch_narrowed_registers(instruction, op, tracked_registers)
        if narrowed_registers:
            reasons = [
                _branch_narrowing_reason(register, instruction)
                for register in narrowed_registers
            ]
            _record_causal_reasons(reasons_by_insn, instruction.insn_idx, reasons)
            tracked_registers.update(instruction.uses)

    return [
        (insn_idx, "; ".join(reasons_by_insn[insn_idx]))
        for insn_idx in sorted(reasons_by_insn)
    ]


def _analyze_obligation(
    parsed_trace: ParsedTrace,
    trace_ir: TraceIR,
    obligation: ObligationSpec,
    reject_site: int | None,
) -> ProofAnalysisResult:
    if not obligation.atoms:
        return ProofAnalysisResult(
            obligation=obligation,
            predicate_evals=[],
            transition=None,
            slice_edges=[],
            proof_status="unknown",
            establish_site=None,
            loss_site=None,
            reject_site=reject_site,
            status_reason="obligation family has no formal predicate atoms",
            causal_chain=[],
        )

    fail_insn = _find_obligation_node(trace_ir, obligation)
    if fail_insn is None:
        return ProofAnalysisResult(
            obligation=obligation,
            predicate_evals=[],
            transition=None,
            slice_edges=[],
            proof_status="unknown",
            establish_site=None,
            loss_site=None,
            reject_site=reject_site,
            status_reason="failing instruction missing from trace IR",
            causal_chain=[],
        )

    fail_op = _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode)
    predicate_evals = evaluate_obligation(trace_ir, obligation)
    transition = find_loss_transition(
        predicate_evals,
        fail_insn.insn_idx,
        point_order=trace_ir.point_order,
        include_fail_post=not (fail_op.kind == "call" and not fail_insn.post_state),
        fail_trace_pos=fail_insn.trace_pos,
    )
    overall_timeline = [
        point
        for point in _overall_timeline(predicate_evals, obligation, point_order=trace_ir.point_order)
        if _point_rank(
            point.trace_pos if point.trace_pos is not None else point.insn_idx,
            point.phase,
            trace_ir.point_order,
        )
        <= _point_rank(fail_insn.trace_pos, "pre", trace_ir.point_order)
    ]
    last_satisfied = next(
        (point for point in reversed(overall_timeline) if point.result == "satisfied"),
        None,
    )
    status_reason = None
    causal_chain: list[tuple[int, str]] = []

    if _should_defer_subprog_memory_access(parsed_trace, obligation, last_satisfied):
        proof_status = "unknown"
        transition = None
        slice_edges = []
        last_satisfied = None
        status_reason = "callee-only memory-access trace does not show caller-side proof context"
    elif last_satisfied is None:
        proof_status = "never_established"
        transition = None
        slice_edges = []
    elif transition is not None:
        proof_status = "established_then_lost"
        slice_edges = backward_slice(trace_ir, obligation, transition)
        causal_chain = _backward_obligation_slice_from_ir(
            trace_ir,
            parsed_trace,
            transition.insn_idx,
            obligation,
            transition,
        )
    else:
        proof_status = "established_but_insufficient"
        slice_edges = []

    return ProofAnalysisResult(
        obligation=obligation,
        predicate_evals=predicate_evals,
        transition=transition,
        slice_edges=slice_edges,
        proof_status=proof_status,
        establish_site=last_satisfied.insn_idx if last_satisfied is not None else None,
        loss_site=transition.insn_idx if transition is not None else None,
        reject_site=reject_site,
        status_reason=status_reason,
        causal_chain=causal_chain,
    )


def analyze_proof(
    parsed_trace: ParsedTrace,
    error_line: str,
    error_insn: int | None,
) -> ProofAnalysisResult:
    """Run the formal proof engine end-to-end on a parsed trace."""

    trace_ir, fail_insn, obligation = _infer_obligation_internal(
        parsed_trace,
        error_line,
        error_insn,
        allow_low_confidence_fallback=False,
        include_related_candidates=False,
    )
    reject_site = fail_insn.insn_idx if fail_insn is not None else error_insn

    if fail_insn is None:
        return ProofAnalysisResult(
            obligation=None,
            predicate_evals=[],
            transition=None,
            slice_edges=[],
            proof_status="unknown",
            establish_site=None,
            loss_site=None,
            reject_site=reject_site,
            status_reason="failing instruction could not be identified",
        )

    if obligation is None:
        return ProofAnalysisResult(
            obligation=None,
            predicate_evals=[],
            transition=None,
            slice_edges=[],
            proof_status="unknown",
            establish_site=None,
            loss_site=None,
            reject_site=reject_site,
            status_reason="proof obligation could not be inferred",
        )

    return _analyze_obligation(parsed_trace, trace_ir, obligation, reject_site)


def track_composite(parsed_trace: ParsedTrace, composite: CompositeObligation) -> dict:
    """Track each sub-obligation independently and report the earliest observed failure."""

    trace_ir = build_trace_ir(parsed_trace)
    sub_results = [
        _analyze_obligation(
            parsed_trace,
            trace_ir,
            obligation,
            obligation.failing_insn,
        )
        for obligation in composite.sub_obligations
    ]

    ranked_failures: list[tuple[tuple[int, int], int, ProofAnalysisResult]] = []
    for index, result in enumerate(sub_results):
        if result.loss_site is not None:
            loss_point = (
                result.transition.trace_pos
                if result.transition is not None and result.transition.trace_pos is not None
                else result.loss_site
            )
            rank = _point_rank(loss_point, "pre", trace_ir.point_order)
            ranked_failures.append((rank, index, result))
            continue
        if result.proof_status == "never_established" and result.reject_site is not None:
            reject_point = (
                result.obligation.failing_trace_pos
                if result.obligation is not None and result.obligation.failing_trace_pos is not None
                else result.reject_site
            )
            rank = _point_rank(reject_point, "pre", trace_ir.point_order)
            ranked_failures.append((rank, index, result))

    first_failed_index = None
    first_failed_obligation = None
    first_failure_site = None
    first_failure_status = None
    if ranked_failures:
        _, first_failed_index, first_failed_result = min(ranked_failures)
        first_failed_obligation = composite.sub_obligations[first_failed_index]
        first_failure_site = (
            first_failed_result.loss_site
            if first_failed_result.loss_site is not None
            else first_failed_result.reject_site
        )
        first_failure_status = first_failed_result.proof_status

    return {
        "sub_results": sub_results,
        "first_failed_index": first_failed_index,
        "first_failed_obligation": first_failed_obligation,
        "first_failure_site": first_failure_site,
        "first_failure_status": first_failure_status,
    }


def _canonicalize_instructions(instructions: list[TracedInstruction]) -> list[TracedInstruction]:
    merged: dict[int, TracedInstruction] = {}
    for instruction in instructions:
        existing = merged.get(instruction.insn_idx)
        if existing is None:
            merged[instruction.insn_idx] = _clone_instruction(instruction)
        else:
            merged[instruction.insn_idx] = _merge_instruction(existing, instruction)
    return [merged[insn_idx] for insn_idx in sorted(merged)]


def _clone_instruction(instruction: TracedInstruction) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=instruction.insn_idx,
        bytecode=instruction.bytecode,
        source_line=instruction.source_line,
        pre_state=dict(instruction.pre_state),
        post_state=dict(instruction.post_state),
        backtrack=instruction.backtrack,
        is_error=instruction.is_error,
        error_text=instruction.error_text,
    )


def _merge_instruction(left: TracedInstruction, right: TracedInstruction) -> TracedInstruction:
    preferred, secondary = (
        (right, left)
        if _instruction_quality(right) >= _instruction_quality(left)
        else (left, right)
    )

    return TracedInstruction(
        insn_idx=preferred.insn_idx,
        bytecode=preferred.bytecode or secondary.bytecode,
        source_line=preferred.source_line or secondary.source_line,
        pre_state=_supplement_states(preferred.pre_state, secondary.pre_state),
        post_state=_supplement_states(preferred.post_state, secondary.post_state),
        backtrack=preferred.backtrack or secondary.backtrack,
        is_error=left.is_error or right.is_error,
        error_text=_merge_error_text(left.error_text, right.error_text),
    )


def _instruction_quality(instruction: TracedInstruction) -> tuple[int, int, int, int, int]:
    return (
        1 if instruction.is_error else 0,
        _changed_registers(instruction),
        len(instruction.pre_state) + len(instruction.post_state),
        1 if instruction.backtrack is not None else 0,
        1 if instruction.source_line else 0,
    )


def _changed_registers(instruction: TracedInstruction) -> int:
    changed = 0
    for register in set(instruction.pre_state) | set(instruction.post_state):
        before = instruction.pre_state.get(register)
        after = instruction.post_state.get(register)
        if before is None or after is None:
            if before is not after:
                changed += 1
            continue
        if not _same_state(before, after):
            changed += 1
    return changed


def _merge_error_text(left: str | None, right: str | None) -> str | None:
    parts = [part for part in (left, right) if part]
    if not parts:
        return None
    deduped: list[str] = []
    for part in parts:
        if part not in deduped:
            deduped.append(part)
    return "\n".join(deduped)


def _supplement_states(
    primary: dict[str, RegisterState],
    secondary: dict[str, RegisterState],
) -> dict[str, RegisterState]:
    merged = dict(primary)
    for register, state in secondary.items():
        merged.setdefault(register, state)
    return merged


def _compute_successors(
    op: _ParsedOperation,
    insn_idx: int,
    next_idx: int | None,
) -> list[int]:
    if op.kind == "jump_cond":
        succs = [op.target] if op.target is not None else []
        if next_idx is not None:
            succs.append(next_idx)
        return [succ for succ in succs if succ is not None]
    if op.kind == "jump":
        return [op.target] if op.target is not None else []
    if op.kind == "exit":
        return []
    if next_idx is None:
        return []
    return [next_idx]


def _parse_bytecode(insn_idx: int, bytecode: str) -> _ParsedOperation:
    text = bytecode.strip()
    lowered = text.lower()

    branch = BRANCH_RE.match(lowered)
    if branch:
        uses = [_normalize_register(branch.group("lhs"))]
        rhs = branch.group("rhs").strip()
        if _looks_like_register(rhs):
            uses.append(_normalize_register(rhs))
        return _ParsedOperation(
            kind="jump_cond",
            defs=[],
            uses=_dedupe_preserve_order(uses),
            target=insn_idx + 1 + int(branch.group("delta")),
        )

    jump = JUMP_RE.match(lowered)
    if jump:
        return _ParsedOperation(
            kind="jump",
            defs=[],
            uses=[],
            target=insn_idx + 1 + int(jump.group("delta")),
        )

    if lowered == "exit":
        return _ParsedOperation(kind="exit", defs=[], uses=["R0"])

    call = CALL_RE.match(lowered)
    if call:
        helper_id = _parse_helper_id(call.group("target"))
        return _ParsedOperation(
            kind="call",
            defs=["R0"],
            uses=["R1", "R2", "R3", "R4", "R5"],
            helper_id=helper_id,
        )

    load = LOAD_RE.match(lowered)
    if load:
        base_reg = _normalize_register(load.group("base"))
        return _ParsedOperation(
            kind="load",
            defs=[_normalize_register(load.group("dst"))],
            uses=[base_reg],
            dst_reg=_normalize_register(load.group("dst")),
            base_reg=base_reg,
            offset=_signed_offset(load.group("sign"), load.group("offset")),
            size=_width_to_size(load.group("width")),
        )

    store = STORE_RE.match(lowered)
    if store:
        base_reg = _normalize_register(store.group("base"))
        uses = [base_reg]
        src = store.group("src").strip()
        src_reg = _normalize_register(src) if _looks_like_register(src) else None
        if src_reg is not None:
            uses.append(src_reg)
        return _ParsedOperation(
            kind="store",
            defs=[],
            uses=_dedupe_preserve_order(uses),
            src_reg=src_reg,
            base_reg=base_reg,
            offset=_signed_offset(store.group("sign"), store.group("offset")),
            size=_width_to_size(store.group("width")),
            immediate=_parse_int(src) if src_reg is None else None,
        )

    aug_assign = AUG_ASSIGN_RE.match(lowered)
    if aug_assign:
        dst_reg = _normalize_register(aug_assign.group("dst"))
        src = aug_assign.group("src").strip()
        src_reg = _normalize_register(src) if _looks_like_register(src) else None
        uses = [dst_reg]
        if src_reg is not None:
            uses.append(src_reg)
        immediate = _parse_int(src) if src_reg is None else None
        kind = "ptr_add" if aug_assign.group("op") in {"+=", "-="} else "alu"
        return _ParsedOperation(
            kind=kind,
            defs=[dst_reg],
            uses=_dedupe_preserve_order(uses),
            dst_reg=dst_reg,
            src_reg=src_reg,
            immediate=immediate,
        )

    assign = ASSIGN_RE.match(lowered)
    if assign:
        dst_reg = _normalize_register(assign.group("dst"))
        rhs = assign.group("rhs").strip()
        if _looks_like_register(rhs):
            return _ParsedOperation(
                kind="mov",
                defs=[dst_reg],
                uses=[_normalize_register(rhs)],
                dst_reg=dst_reg,
                src_reg=_normalize_register(rhs),
            )
        if rhs.startswith(("be16 ", "be32 ", "be64 ", "le16 ", "le32 ", "le64 ")):
            source_reg = _normalize_register(rhs.split()[-1])
            return _ParsedOperation(
                kind="alu",
                defs=[dst_reg],
                uses=[source_reg],
                dst_reg=dst_reg,
                src_reg=source_reg,
            )
        return _ParsedOperation(
            kind="alu",
            defs=[dst_reg],
            uses=[],
            dst_reg=dst_reg,
            immediate=_parse_int(rhs),
        )

    registers = _extract_registers(text)
    defs = registers[:1]
    uses = registers[1:]
    return _ParsedOperation(kind="unknown", defs=defs, uses=uses)


def _width_to_size(width: str) -> int:
    digits = "".join(character for character in width if character.isdigit())
    if not digits:
        return 0
    return max(1, int(digits) // 8)


def _signed_offset(sign: str, raw_offset: str) -> int:
    value = _parse_int(raw_offset) or 0
    return value if sign == "+" else -abs(value)


def _parse_helper_id(target: str) -> int | None:
    match = re.search(r"#(\d+)", target)
    if match:
        return int(match.group(1))
    if target.isdigit():
        return int(target)
    return None


def _extract_error_details(error_line: str) -> dict[str, int]:
    details: dict[str, int] = {}
    for pattern, key in (
        (VALUE_SIZE_RE, "value_size"),
        (MEM_SIZE_RE, "mem_size"),
        (OFF_RE, "off"),
        (SIZE_RE, "size"),
    ):
        match = pattern.search(error_line)
        if match:
            details[key] = _parse_int(match.group(key)) or 0
    return details


def _lookup_state(
    instruction: InstructionNode,
    register: str | None,
) -> RegisterState | None:
    if register is None:
        return None
    return instruction.pre_state.get(register) or instruction.post_state.get(register)


def _best_effort_lookup_state(
    instruction: InstructionNode,
    register: str | None,
) -> RegisterState | None:
    if register is None:
        return None
    pre_state = instruction.pre_state.get(register)
    post_state = instruction.post_state.get(register)
    for candidate in (pre_state, post_state):
        if candidate is not None and not _is_scalar_like(candidate):
            return candidate
    return pre_state or post_state


def _is_packet_ptr(state: RegisterState | None) -> bool:
    if state is None:
        return False
    return is_packet_pointer_type(state.type)


def _is_map_value(state: RegisterState | None) -> bool:
    if state is None:
        return False
    return is_map_value_type_name(state.type)


def _is_nullable(state: RegisterState | None) -> bool:
    return state is not None and "or_null" in state.type.lower()


def _is_stack_base(state: RegisterState | None, register: str | None) -> bool:
    if register == "R10":
        return True
    return state is not None and state.type.lower() == "fp"


def _error_mentions_null(error_line: str) -> bool:
    return any(
        token in error_line
        for token in ("or_null", "possibly null", "null pointer", "null ptr", "non-null")
    )


def _extract_error_register(error_line: str) -> str | None:
    match = ERROR_REGISTER_RE.search(error_line)
    if match:
        return _normalize_register(match.group(1))
    return None


def _extract_error_arg_register(error_line: str) -> str | None:
    match = ERROR_ARG_RE.search(error_line)
    if match is None:
        return None
    plain = match.group("plain")
    if plain is not None and plain.isdigit():
        register_index = int(plain)
        if "trusted arg" in error_line.lower():
            register_index += 1
        if register_index == 0:
            register_index = 1
        return f"R{register_index}"

    indexed = match.group("spaced") or match.group("compact")
    if indexed is None or not indexed.isdigit():
        return None
    return f"R{int(indexed) + 1}"


def _first_nullable_register(instruction: InstructionNode) -> str | None:
    for register, state in instruction.pre_state.items():
        if _is_nullable(state):
            return register
    for register, state in instruction.post_state.items():
        if _is_nullable(state):
            return register
    return None


def _first_zero_scalar_register(instruction: InstructionNode) -> str | None:
    for state_map in (instruction.pre_state, instruction.post_state):
        for register, state in state_map.items():
            if _is_zero_scalar(state):
                return register
    return None


def _select_access_register(
    instruction: InstructionNode,
    error_line: str,
    predicate,
) -> str | None:
    reg = _extract_error_register(error_line)
    if reg is not None:
        return reg

    for register in ("R1", "R2", "R3", "R4", "R5"):
        if predicate(_best_effort_lookup_state(instruction, register)):
            return register

    for state_map in (instruction.pre_state, instruction.post_state):
        for register, state in state_map.items():
            if register.startswith("R") and predicate(state):
                return register
    return None


def _expected_types_for_helper(
    helper_id: int | None,
    register: str,
    error_line: str,
) -> list[str]:
    match = HELPER_EXPECTED_RE.search(error_line)
    if match:
        expected = match.group("expected")
        return [part.strip().lower() for part in expected.split(",") if part.strip()]

    if helper_id is not None and helper_id in HELPER_ARG_EXPECTATIONS:
        expectations = HELPER_ARG_EXPECTATIONS[helper_id].get(register)
        if expectations:
            return list(expectations)

    inferred = _expected_types_from_helper_text(error_line)
    if inferred:
        return inferred

    return ["ptr", "map_value", "pkt", "fp"]


def _expected_types_from_helper_text(error_line: str) -> list[str]:
    lowered = error_line.lower()
    expected: list[str] = []

    if "pointer to stack" in lowered:
        expected.append("fp")
    if "dynptr" in lowered:
        expected.extend(["ptr", "fp"])
    if "map value" in lowered:
        expected.append("map_value")
    if "map_ptr" in lowered or "map ptr" in lowered:
        expected.append("map_ptr")
    if "packet" in lowered or "pkt" in lowered:
        expected.append("pkt")
    if "ctx" in lowered or "context" in lowered:
        expected.append("ctx")
    if "sock" in lowered or "socket" in lowered:
        expected.append("sock")
    if "ptr" in lowered or "pointer" in lowered or "buf" in lowered:
        expected.append("ptr")

    return _dedupe_preserve_order(expected)


def _helper_arg_error_clue(error_line: str) -> bool:
    lowered = error_line.lower()
    return bool(HELPER_ARG_CLUE_RE.search(error_line)) or "trusted arg" in lowered


def _is_helper_contract_error(error_line: str) -> bool:
    lowered = error_line.lower()
    if "reg type unsupported for arg#0 function" in lowered:
        return False
    return any(
        token in lowered
        for token in (
            "must be a rcu pointer",
            "has no valid kptr",
            "unsupported reg type",
            "expects refcounted",
        )
    )


def _call_target_suggests_pointer_contract(call_target: str) -> bool:
    return any(
        token in call_target
        for token in ("cgroup_acquire", "cgroup_release", "cpumask_", "kptr_xchg")
    )


def _select_helper_contract_register(
    instruction: InstructionNode,
    call_target: str,
) -> str | None:
    if "dynptr_from_mem" in call_target:
        return "R1"

    if "cpumask" in call_target:
        for register in ("R2", "R1", "R3", "R4", "R5"):
            state = _best_effort_lookup_state(instruction, register)
            if state is not None and "cpumask" in state.type.lower():
                return register

    for register in ("R1", "R2", "R3", "R4", "R5"):
        state = _best_effort_lookup_state(instruction, register)
        if state is None:
            continue
        lowered = state.type.lower()
        if any(token in lowered for token in ("rcu_ptr", "trusted_ptr", "kptr", "ptr_")):
            return register

    if "acquire" in call_target or "release" in call_target:
        return "R1"
    return None


def _helper_contract_expected_types(
    error_line: str,
    call_target: str,
) -> list[str]:
    lowered = error_line.lower()
    if "rcu pointer" in lowered:
        return ["rcu_ptr_", "trusted_ptr_", "ptr_", "ptr"]
    if "valid kptr" in lowered:
        return ["kptr", "map_value", "ptr"]
    if "expects refcounted" in lowered:
        return ["ptr_", "trusted_ptr_", "rcu_ptr_"]
    if "dynptr_from_mem" in call_target:
        return ["ptr", "map_value", "pkt", "mem"]
    if "cpumask" in call_target:
        return ["bpf_cpumask", "ptr"]
    return ["ptr", "trusted_ptr_", "rcu_ptr_", "ptr_", "kptr"]


def _is_scalar_deref_error(error_line: str, base_state: RegisterState | None) -> bool:
    lowered = error_line.lower()
    if (
        "invalid mem access 'scalar'" in lowered
        or "invalid mem access 'inv'" in lowered
    ):
        return True
    return base_state is not None and _is_scalar_like(base_state)


def _is_trusted_null_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return "possibly null pointer" in lowered and "trusted arg" in lowered


def _is_trusted_reference_error(error_line: str) -> bool:
    return "must be referenced or trusted" in error_line.lower()


def _looks_like_trusted_null_call(
    call_target: str,
    instruction: InstructionNode,
) -> bool:
    return "acquire" in call_target and _first_zero_scalar_register(instruction) is not None


def _is_generic_reference_type_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return "reference type" in lowered and "size cannot be determined" in lowered


def _is_btf_reference_type_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return _is_generic_reference_type_error(error_line) or "invalid btf_id" in lowered


def _is_btf_metadata_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return any(
        token in lowered
        for token in (
            "missing btf func_info",
            "number of funcs in func_info doesn't match number of subprogs",
            "failed to find kernel btf type id",
            "invalid name",
        )
    )


def _is_reference_leak_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return "reference leak" in lowered or "unreleased reference" in lowered


def _is_exception_callback_context_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return bool(
        re.search(r"cannot (?:call|be called).*\bfrom callback", lowered)
        or "cannot call exception cb directly" in lowered
    )


def _is_buffer_length_pair_error(error_line: str) -> bool:
    return "memory, len pair leads to invalid memory access" in error_line.lower()


def _extract_error_arg_pair(error_line: str) -> tuple[str | None, str | None]:
    match = ARG_PAIR_RE.search(error_line)
    if match is None:
        return None, None
    return f"R{int(match.group('base')) + 1}", f"R{int(match.group('index')) + 1}"


def _is_exit_return_type_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return "at program exit the register r0 has unknown scalar" in lowered


def _is_verifier_limits_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return "combined stack size of" in lowered and "calls is" in lowered


def _is_processed_summary_line(error_line: str) -> bool:
    return error_line.lstrip().lower().startswith("processed ")


def _call_target_name(bytecode: str) -> str:
    match = CALL_RE.match(bytecode.strip())
    if match is None:
        return ""
    return match.group("target").strip().lower()


def _is_dynptr_protocol_error(bytecode: str, error_line: str) -> bool:
    lowered = error_line.lower()
    call_target = _call_target_name(bytecode)
    if (
        "expected an initialized dynptr" in lowered
        or "cannot pass in dynptr" in lowered
        or "cannot overwrite referenced dynptr" in lowered
        or "dynptr has to be an uninitialized dynptr" in lowered
    ):
        return True
    return "dynptr" in call_target and _is_generic_reference_type_error(error_line)


def _looks_like_dynptr_state_access_error(
    trace_ir: TraceIR,
    fail_insn: InstructionNode,
    error_line: str,
) -> bool:
    lowered = error_line.lower()
    if any(
        token in lowered
        for token in (
            "cannot overwrite referenced dynptr",
            "cannot pass in dynptr at an offset",
            "dynptr has to be at a constant offset",
            "potential write to dynptr",
        )
    ):
        return True
    if "invalid mem access" not in lowered:
        return False
    if _last_typed_stack_slot(trace_ir, fail_insn.insn_idx, "dynptr") is None:
        return False

    slice_seen = False
    invalidator_seen = False
    for node in trace_ir.instructions:
        if node.insn_idx > fail_insn.insn_idx:
            continue
        target = _call_target_name(node.bytecode)
        if any(token in target for token in ("dynptr_data", "dynptr_slice", "dynptr_slice_rdwr")):
            slice_seen = True
        if any(
            token in target
            for token in (
                "dynptr_clone",
                "dynptr_write",
                "ringbuf_submit_dynptr",
                "ringbuf_discard_dynptr",
                "skb_pull_data",
                "xdp_adjust_head",
            )
        ):
            invalidator_seen = True
    return slice_seen and invalidator_seen


def _is_iterator_protocol_error(bytecode: str, error_line: str) -> bool:
    lowered = error_line.lower()
    call_target = _call_target_name(bytecode)
    if "expected an initialized iter" in lowered:
        return True
    return "bpf_iter_" in call_target and (
        not error_line or _is_generic_reference_type_error(error_line)
    )


def _looks_like_iterator_leak(
    trace_ir: TraceIR,
    fail_insn: InstructionNode,
) -> bool:
    if _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode).kind != "exit":
        return False
    if not any("bpf_iter_" in _call_target_name(node.bytecode) for node in trace_ir.instructions):
        return False
    return _last_typed_stack_slot(trace_ir, fail_insn.insn_idx, "iter") is not None


def _is_execution_context_error(
    trace_ir: TraceIR,
    fail_insn: InstructionNode,
    error_line: str,
) -> bool:
    lowered = error_line.lower()
    call_target = _call_target_name(fail_insn.bytecode)
    if "cannot restore irq state" in lowered:
        return True
    if "bpf_exit" in lowered and "irq" in lowered:
        return True
    if "bpf_local_irq_save-ed region" in lowered:
        return True
    if "function calls are not allowed while holding a lock" in lowered:
        return True
    if "calling kernel function" in lowered and "not allowed" in lowered:
        return True
    if "jit does not support calling kfunc" in lowered:
        return True
    if "global functions that may sleep are not allowed in non-sleepable context" in lowered:
        return True
    if "sleepable" in lowered and "non-sleepable" in lowered:
        return True
    if "bpf_throw" in call_target and _is_processed_summary_line(error_line):
        return True
    if "irqrestore" in call_target or "local_irq_restore" in call_target:
        return True
    if _parse_bytecode(fail_insn.insn_idx, fail_insn.bytecode).kind != "exit":
        return False
    return any(
        any(token in _call_target_name(node.bytecode) for token in ("irqsave", "local_irq_save"))
        for node in trace_ir.instructions
    )


def _is_verifier_limits_fallback_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return bool(
        _is_processed_summary_line(error_line)
        or "combined stack size of" in lowered
        or "program is too large" in lowered
        or "back-edge from insn" in lowered
        or "stack depth" in lowered
        or "infinite loops" in lowered
        or "async_cb" in lowered
    )


def _node_has_async_callback_state(instruction: InstructionNode) -> bool:
    for state_map in (instruction.pre_state, instruction.post_state):
        for state in state_map.values():
            if "async_cb" in state.type.lower():
                return True
    return False


def _is_specific_verifier_safety_error(error_line: str) -> bool:
    lowered = error_line.lower()
    return any(
        token in lowered
        for token in (
            "only read from bpf_array is supported",
            "attach to unsupported member",
            "pointer comparison prohibited",
            "invalid zero-sized read",
            "the prog does not allow writes to packet data",
            "math between fp pointer and register with unbounded min value is not allowed",
        )
    )


def _is_zero_scalar(state: RegisterState | None) -> bool:
    if state is None or not _is_scalar_like(state):
        return False
    return any(
        lower == upper == 0
        for lower, upper in (
            (state.umin, state.umax),
            (state.smin, state.smax),
        )
        if lower is not None and upper is not None
    )


def _select_protocol_register(
    instruction: InstructionNode,
    error_line: str,
    *,
    expected_type: str,
) -> str | None:
    reg = _extract_error_register(error_line) or _extract_error_arg_register(error_line)
    if reg is not None:
        return _protocol_target_register(instruction, reg, expected_type)

    typed_slots = _typed_stack_slots(instruction, expected_type)
    if len(typed_slots) == 1:
        return typed_slots[0]

    for candidate_reg in ("R1", "R2", "R3", "R4", "R5"):
        state = _lookup_state(instruction, candidate_reg)
        if state is None or not state.type.lower().startswith("fp") or state.off is None:
            continue
        return _protocol_target_register(instruction, candidate_reg, expected_type)
    return typed_slots[0] if typed_slots else None


def _select_protocol_register_from_trace(
    trace_ir: TraceIR,
    instruction: InstructionNode,
    error_line: str,
    *,
    expected_type: str,
) -> str | None:
    target = _select_protocol_register(instruction, error_line, expected_type=expected_type)
    if target is not None:
        return target
    return _last_typed_stack_slot(trace_ir, instruction.insn_idx, expected_type)


def _protocol_target_register(
    instruction: InstructionNode,
    register: str,
    expected_type: str,
) -> str:
    state = _lookup_state(instruction, register)
    if state is None:
        return register
    if _type_matches(state.type.lower(), expected_type):
        return register

    typed_slots = _typed_stack_slots(instruction, expected_type)
    if typed_slots:
        if not state.type.lower().startswith("fp") or state.off is None:
            return typed_slots[0]
        nearest = min(
            typed_slots,
            key=lambda slot: abs((_parse_stack_slot_offset(slot) or state.off) - state.off),
        )
        return nearest

    if not state.type.lower().startswith("fp") or state.off is None:
        return register

    return _stack_slot_name(state.off)


def _typed_stack_slots(instruction: InstructionNode, expected_type: str) -> list[str]:
    slots: list[str] = []
    for state_map in (instruction.pre_state, instruction.post_state):
        for register, state in state_map.items():
            if _parse_stack_slot_offset(register) is None:
                continue
            if _type_matches(state.type.lower(), expected_type) and register not in slots:
                slots.append(register)
    return slots


def _last_typed_stack_slot(
    trace_ir: TraceIR,
    max_insn_idx: int,
    expected_type: str,
) -> str | None:
    for node in reversed(trace_ir.instructions):
        if node.insn_idx > max_insn_idx:
            continue
        slots = _typed_stack_slots(node, expected_type)
        if slots:
            return slots[0]
    return None


def _stack_slot_name(offset: int) -> str:
    return f"fp{offset}"


def _parse_stack_slot_offset(register: str) -> int | None:
    match = STACK_SLOT_RE.match(register)
    if match is None:
        return None
    return _parse_int(match.group("off"))


def _eval_atom(
    *,
    trace_ir: TraceIR,
    trace_pos: int,
    insn_idx: int,
    phase: str,
    atom: PredicateAtom,
    state_map: dict[str, RegisterState],
    obligation: ObligationSpec,
    target: _AtomTarget | None,
) -> tuple[str, str, str | None]:
    if not atom.registers:
        return "unknown", "atom has no registers", None

    carriers = _candidate_carriers(
        trace_ir,
        trace_pos,
        insn_idx,
        phase,
        atom,
        state_map,
        obligation,
        target,
    )
    if not carriers:
        register = atom.registers[0]
        return "unknown", f"{register}: no matching value version", None

    evaluations = [
        (
            register,
            *_eval_atom_on_state(atom, register, state, obligation),
        )
        for register, state in carriers
    ]
    register, result, witness = _select_carrier_result(evaluations)
    return result, witness, register


def _atom_targets(trace_ir: TraceIR, obligation: ObligationSpec) -> dict[str, _AtomTarget]:
    targets: dict[str, _AtomTarget] = {}
    fail_node = _find_obligation_node(trace_ir, obligation)
    if fail_node is None:
        return targets

    for atom in obligation.atoms:
        if not atom.registers:
            targets[atom.atom_id] = _AtomTarget(
                version_id=None,
                proof_root=None,
                register=None,
                state=None,
            )
            continue

        register = atom.registers[0]
        state = fail_node.pre_state.get(register) or fail_node.post_state.get(register)
        version_id = None
        proof_root = None
        for candidate_phase in ("pre", "post"):
            candidate_version_id = trace_ir.point_versions.get(
                (fail_node.trace_pos, register, candidate_phase)
            )
            if candidate_version_id is None:
                continue
            version = trace_ir.value_versions.get(candidate_version_id)
            version_id = candidate_version_id
            proof_root = version.proof_root if version is not None else None
            if proof_root is not None:
                break
        targets[atom.atom_id] = _AtomTarget(
            version_id=version_id,
            proof_root=proof_root,
            register=register,
            state=state,
        )
    return targets


def _candidate_carriers(
    trace_ir: TraceIR,
    trace_pos: int,
    insn_idx: int,
    phase: str,
    atom: PredicateAtom,
    state_map: dict[str, RegisterState],
    obligation: ObligationSpec,
    target: _AtomTarget | None,
) -> list[tuple[str, RegisterState]]:
    if not atom.registers:
        return []

    register = atom.registers[0]
    primary_state = state_map.get(register)
    if target is None or (target.version_id is None and target.proof_root is None):
        return [(register, primary_state)] if primary_state is not None else []

    primary_version = trace_ir.point_versions.get((trace_pos, register, phase))
    if primary_state is not None and primary_version is not None:
        if _version_matches_target(trace_ir, primary_version, target):
            return [(register, primary_state)]

    candidates: list[tuple[str, RegisterState]] = []
    for candidate_register, candidate_state in state_map.items():
        version_id = trace_ir.point_versions.get((trace_pos, candidate_register, phase))
        same_lineage = version_id is not None and _version_matches_target(trace_ir, version_id, target)
        same_alias = _state_matches_target_alias(candidate_state, target.state, obligation.kind)
        if same_lineage or same_alias:
            candidates.append((candidate_register, candidate_state))

    # Lineage-based alias fallback: if version-tracking found nothing AND the primary
    # register is completely absent from this instruction's state (i.e., it was spilled
    # to the stack or moved to another register before this point), consult the
    # value_lineage graph to find an equivalent register holding the same proof-root
    # value through spills, fills, and copies.
    #
    # Deliberately avoid this fallback when primary_state is present: if the register
    # appears in the state, its abstract value should be evaluated directly — using an
    # alias could mask a genuine null / type violation on the primary register.
    if not candidates and primary_state is None and trace_ir.value_lineage is not None:
        aliases = trace_ir.value_lineage.get_all_aliases(trace_pos, register)
        for alias_reg in aliases:
            if alias_reg == register:
                continue
            alias_state = state_map.get(alias_reg)
            if alias_state is not None:
                candidates.append((alias_reg, alias_state))

    return candidates


def _find_obligation_node(trace_ir: TraceIR, obligation: ObligationSpec) -> InstructionNode | None:
    if obligation.failing_trace_pos is not None:
        return _node_at_trace_pos(trace_ir, obligation.failing_trace_pos)
    for instruction in reversed(trace_ir.instructions):
        if instruction.insn_idx == obligation.failing_insn:
            return instruction
    return None


def _state_matches_target_alias(
    state: RegisterState,
    target_state: RegisterState | None,
    obligation_kind: str,
) -> bool:
    if target_state is None or state.id is None or target_state.id is None:
        return False
    if state.id != target_state.id or state.off != target_state.off:
        return False
    if obligation_kind == "packet_access":
        return _is_packet_ptr(state) and _is_packet_ptr(target_state)
    if obligation_kind == "map_value_access":
        return _is_map_value(state) and _is_map_value(target_state)
    if obligation_kind == "memory_access":
        return state.type.lower().startswith("mem") and target_state.type.lower().startswith("mem")
    return False


def _version_matches_target(
    trace_ir: TraceIR,
    version_id: int,
    target: _AtomTarget,
) -> bool:
    target_version = target.version_id
    if target_version is not None and (
        version_id == target_version or _is_ancestor_version(trace_ir, version_id, target_version)
    ):
        return True

    if target.proof_root is None:
        return False

    version = trace_ir.value_versions.get(version_id)
    return version is not None and version.proof_root == target.proof_root


def _is_ancestor_version(
    trace_ir: TraceIR,
    candidate_version: int,
    target_version: int,
) -> bool:
    target = trace_ir.value_versions.get(target_version)
    if target is None:
        return False
    worklist = list(target.parent_versions)
    seen: set[int] = set()
    while worklist:
        version_id = worklist.pop()
        if version_id in seen:
            continue
        if version_id == candidate_version:
            return True
        seen.add(version_id)
        version = trace_ir.value_versions.get(version_id)
        if version is not None:
            worklist.extend(version.parent_versions)
    return False


def _select_carrier_result(
    evaluations: list[tuple[str, str, str]],
) -> tuple[str | None, str, str]:
    for register, result, witness in evaluations:
        if result == "satisfied":
            return register, result, witness
    for register, result, witness in evaluations:
        if result == "violated":
            return register, result, witness
    register, result, witness = evaluations[0]
    return register, result, witness


def _eval_atom_on_state(
    atom: PredicateAtom,
    register: str,
    state: RegisterState,
    obligation: ObligationSpec,
) -> tuple[str, str]:
    if state is None:
        return "unknown", f"{register}: state unavailable"

    # -------------------------------------------------------------------
    # Abstract domain evaluator — primary path for ALL atom types.
    #
    # eval_atom_abstract uses the full interval arithmetic + tnum domain.
    # Its "unknown" result is the honest answer when the abstract domain
    # cannot determine satisfaction from the available state fields.
    # We fall through to obligation-context-aware helpers for three atom
    # types that need either obligation context or eBPF-specific semantics:
    #   - range_at_least: bound depends on obligation.kind and access size
    #   - non_null: additionally checks for scalar zero (umin==umax==0)
    #   - offset_non_negative: eBPF uses "violates if smin < 0" semantics
    #                          (abstract domain returns "unknown" when smin<0
    #                          but smax>=0, which is too conservative here)
    # Everything else uses eval_atom_abstract as the authoritative answer.
    # -------------------------------------------------------------------
    if atom.atom_id not in {"range_at_least", "non_null", "offset_non_negative", "offset_bounded"}:
        try:
            abstract_result, abstract_witness = eval_atom_abstract(
                atom.atom_id, atom.expression, state
            )
            return abstract_result, f"{register}: {abstract_witness}"
        except Exception:
            return "unknown", f"{register}: abstract domain error for {atom.atom_id}"

    # --- range_at_least: uses obligation-specific bound and access extent ---
    if atom.atom_id == "range_at_least":
        required = _required_access_extent(state, obligation)
        bound = _bound_for_range_atom(atom, state, obligation)
        if bound is None:
            return "unknown", f"{register}: required={required}, bound=unknown"
        result = "satisfied" if required <= bound else "violated"
        fixed_off = state.off if state.off is not None else 0
        return (
            result,
            f"{register}: fixed_off={fixed_off}, required={required}, bound={bound}, type={state.type}",
        )

    # --- non_null: includes scalar-zero detection (umin==umax==0) ----------
    if atom.atom_id == "non_null":
        result = "violated" if _is_nullable(state) or _is_definitely_null(state) else "satisfied"
        return result, f"{register}.type={state.type}"

    # --- offset_non_negative: eBPF verifier semantics ----------------------
    # The verifier treats an offset as "violated" whenever smin < 0 (meaning
    # the scalar CAN take a negative value and cannot be proven non-negative).
    # This differs from the three-valued abstract domain which returns "unknown"
    # when smin < 0 but smax >= 0.
    if atom.atom_id == "offset_non_negative":
        lower_bound = state.smin if state.smin is not None else state.umin
        if lower_bound is None and state.umax is not None and _is_scalar_like(state):
            # Scalar with umax but no smin/umin: treat umin=0 (non-negative)
            lower_bound = 0
        if lower_bound is None:
            return "unknown", f"{register}: no lower bound"
        result = "satisfied" if lower_bound >= 0 else "violated"
        return result, f"{register}: lower_bound={lower_bound}"

    # --- offset_bounded: use abstract domain with explicit fallback --------
    # eval_atom_abstract for offset_bounded can mis-parse expressions like
    # "R0.umax is bounded" (extracting the register index as the limit).
    # We use it when umax is present; fall back to checking umax is None.
    if atom.atom_id == "offset_bounded":
        try:
            abstract_result, abstract_witness = eval_atom_abstract(
                "offset_bounded", atom.expression, state
            )
            if abstract_result != "unknown":
                return abstract_result, f"{register}: {abstract_witness}"
        except Exception:
            pass
        upper_bound = state.umax
        if upper_bound is None:
            # Fallback: use tnum upper bound from var_off when umax is not set.
            # This catches scalars constrained only via bitwise ops (e.g., &= 0xff).
            sb = scalar_bounds_from_register_state(state)
            tnum_ub = sb.upper_bound()
            _U64_MAX = (1 << 64) - 1
            if tnum_ub < _U64_MAX:
                upper_bound = tnum_ub
        if upper_bound is None:
            return "violated", f"{register}: umax=None (unbounded)"
        expected_bound = _extract_explicit_bound(atom.expression)
        if expected_bound is not None and upper_bound > expected_bound:
            return "violated", f"{register}: umax={upper_bound}, limit={expected_bound}"
        return "satisfied", f"{register}: umax={upper_bound}"

    return "unknown", f"{atom.atom_id}: unsupported"


def _required_access_extent(
    state: RegisterState,
    obligation: ObligationSpec,
) -> int:
    fixed_off = state.off if state.off is not None else 0
    variable_off = _max_variable_offset(state, obligation.kind)
    if obligation.kind == "packet_access":
        return obligation.const_off + obligation.access_size
    if obligation.kind in {"map_value_access", "memory_access"}:
        return fixed_off + variable_off + obligation.const_off + obligation.access_size
    if obligation.kind == "stack_access":
        return abs(fixed_off + obligation.const_off) + obligation.access_size
    return obligation.const_off + obligation.access_size


def _max_variable_offset(state: RegisterState, obligation_kind: str) -> int:
    if obligation_kind in {"map_value_access", "memory_access"}:
        # Primary: use umax from the parsed interval bounds
        if state.umax is not None:
            return max(0, state.umax)
        # Fallback: use tnum upper bound (value | mask) when umax is not set.
        # This catches cases like `r0 &= 0xff` where the verifier tracks
        # var_off=(0x0; 0xff) but hasn't propagated a tight umax yet.
        sb = scalar_bounds_from_register_state(state)
        tnum_ub = sb.upper_bound()  # min(umax, tnum_upper_bound)
        if tnum_ub < (1 << 64) - 1:  # only use if tnum actually constrains
            return max(0, tnum_ub)
    return 0


def _bound_for_range_atom(
    atom: PredicateAtom,
    state: RegisterState,
    obligation: ObligationSpec,
) -> int | None:
    if obligation.kind == "packet_access":
        return state.range
    if obligation.kind == "map_value_access":
        return state.range if state.range is not None else _extract_trailing_int(atom.expression)
    if obligation.kind == "memory_access":
        return _extract_trailing_int(atom.expression)
    if obligation.kind == "stack_access":
        return _extract_trailing_int(atom.expression) or STACK_FRAME_BYTES
    return state.range


def _extract_trailing_int(expression: str) -> int | None:
    matches = re.findall(r"(-?(?:0x[0-9a-fA-F]+|\d+))", expression)
    if not matches:
        return None
    return _parse_int(matches[-1])


def _extract_explicit_bound(expression: str) -> int | None:
    if "<=" not in expression:
        return None
    _, _, rhs = expression.rpartition("<=")
    return _extract_trailing_int(rhs)


def _parse_expected_types(expression: str) -> list[str]:
    if "matches" not in expression:
        return []
    _, _, rhs = expression.partition("matches")
    return [part.strip().lower() for part in rhs.split(",") if part.strip()]


def _type_matches(actual: str, expected: str) -> bool:
    if actual == expected:
        return True
    if expected.endswith("_") and actual.startswith(expected):
        return True
    if expected == "fp" and actual.startswith("fp"):
        return True
    if expected == "ptr" and actual.startswith("ptr"):
        return True
    if expected == "mem" and actual.startswith("mem"):
        return True
    if expected == "dynptr" and "dynptr" in actual:
        return True
    if expected == "iter" and actual.startswith("iter"):
        return True
    return False


def _looks_pointer_like(actual: str) -> bool:
    lowered = actual.lower()
    if lowered in {"unknown", "scalar", "inv"} or _is_raw_stack_content(lowered):
        return False
    return is_pointer_type_name(actual)


def _is_raw_stack_content(actual: str) -> bool:
    return bool(actual) and set(actual) <= set("?0123456789abcdefm")


def _is_definitely_null(state: RegisterState) -> bool:
    if not _is_scalar_like(state):
        return False
    bounds = [bound for bound in (state.umin, state.umax, state.smin, state.smax) if bound is not None]
    return bool(bounds) and all(bound == 0 for bound in bounds)


def _overall_timeline(
    evaluations: list[PredicateEval],
    obligation: ObligationSpec,
    *,
    point_order: dict[tuple[int, str], int] | None = None,
) -> list[_OverallPoint]:
    grouped: dict[tuple[int, str], list[PredicateEval]] = defaultdict(list)
    for evaluation in evaluations:
        point = evaluation.trace_pos if evaluation.trace_pos is not None else evaluation.insn_idx
        grouped[(point, evaluation.phase)].append(evaluation)

    timeline: list[_OverallPoint] = []
    required_atoms = {atom.atom_id for atom in obligation.atoms}
    for (_point, phase), entries in sorted(
        grouped.items(),
        key=lambda item: _point_rank(item[0][0], item[0][1], point_order),
    ):
        by_atom = {entry.atom_id: entry.result for entry in entries}
        results = [by_atom.get(atom_id, "unknown") for atom_id in required_atoms]
        sample = entries[0]
        timeline.append(
            _OverallPoint(
                insn_idx=sample.insn_idx,
                phase=phase,
                result=_combine_results(results),
                trace_pos=sample.trace_pos,
            )
        )
    return timeline


def _combine_results(results: list[str]) -> str:
    if results and all(result == "satisfied" for result in results):
        return "satisfied"
    if any(result == "violated" for result in results):
        return "violated"
    return "unknown"


def _evaluation_sort_key(evaluation: PredicateEval) -> tuple[int, int]:
    point = evaluation.trace_pos if evaluation.trace_pos is not None else evaluation.insn_idx
    return (point, PHASE_ORDER[evaluation.phase])


def _point_rank(
    point: int,
    phase: str,
    point_order: dict[tuple[int, str], int] | None,
) -> tuple[int, int]:
    if point_order is not None:
        order = point_order.get((point, phase))
        if order is not None:
            return (0, order)
    return (1, point * 2 + PHASE_ORDER[phase])


def _should_defer_subprog_memory_access(
    parsed_trace: ParsedTrace,
    obligation: ObligationSpec,
    last_satisfied: _OverallPoint | None,
) -> bool:
    if obligation.kind != "memory_access":
        return False
    if not parsed_trace.validated_functions:
        return False
    if any(func_id == 0 for func_id in parsed_trace.validated_functions):
        return False
    return not parsed_trace.caller_transfer_sites


def _transition_seed_registers(
    obligation: ObligationSpec,
    transition: TransitionWitness | None = None,
) -> set[str]:
    seeds = set(_obligation_registers(obligation))
    if transition is not None:
        seeds.update(_registers_for_atom(obligation, transition.atom_id))
        if transition.carrier_register is not None:
            seeds.add(transition.carrier_register)
    return {register for register in seeds if register}


def _obligation_registers(obligation: ObligationSpec) -> list[str]:
    registers: list[str] = []
    for atom in obligation.atoms:
        for register in atom.registers:
            if register not in registers:
                registers.append(register)
    for register in (obligation.base_reg, obligation.index_reg):
        if register is not None and register not in registers:
            registers.append(register)
    return registers


def _record_causal_reasons(
    reasons_by_insn: dict[int, list[str]],
    insn_idx: int,
    reasons: list[str],
) -> None:
    bucket = reasons_by_insn.setdefault(insn_idx, [])
    for reason in reasons:
        if reason and reason not in bucket:
            bucket.append(reason)


def _slice_write_reason(register: str, obligation: ObligationSpec) -> str:
    if register == obligation.base_reg:
        return f"writes to {register} (obligation base register)"
    if register == obligation.index_reg:
        return f"writes to {register} (obligation index register)"
    return f"writes to {register} (predicate register)"


def _branch_narrowed_registers(
    instruction: InstructionNode,
    op: _ParsedOperation,
    tracked_registers: set[str],
) -> list[str]:
    if op.kind != "jump_cond":
        return []

    narrowed: list[str] = []
    for register in instruction.uses:
        if register not in tracked_registers:
            continue
        before = instruction.pre_state.get(register)
        after = instruction.post_state.get(register)
        if before is None or after is None or _same_state(before, after):
            continue
        narrowed.append(register)
    return narrowed


def _branch_narrowing_reason(register: str, instruction: InstructionNode) -> str:
    before = instruction.pre_state.get(register)
    after = instruction.post_state.get(register)
    if before is not None and after is not None:
        if before.range != after.range:
            return f"branch narrowing {register} bounds"
        if before.type != after.type:
            return f"branch refining {register} type"
    return f"branch constraining {register}"


def _matching_backtrack_registers(
    chains: list[BacktrackChain],
    insn_idx: int,
    tracked_registers: set[str],
    transition_witness_idx: int,
) -> list[str]:
    matches: list[str] = []
    for chain in chains:
        if chain.error_insn < transition_witness_idx:
            continue
        for link in chain.links:
            if link.insn_idx != insn_idx or link.insn_idx > transition_witness_idx:
                continue
            decoded = _decode_regs_mask(link.regs)
            if not set(decoded) & tracked_registers:
                continue
            for register in decoded:
                if register not in matches:
                    matches.append(register)
    return matches


def _registers_for_atom(obligation: ObligationSpec, atom_id: str) -> list[str]:
    for atom in obligation.atoms:
        if atom.atom_id == atom_id:
            return list(atom.registers)
    return []


def _definition_inputs(node: InstructionNode, register: str) -> list[str]:
    inputs: list[str] = []
    for used in node.uses:
        if used not in inputs:
            inputs.append(used)
    return inputs


def _find_reaching_definition(
    trace_ir: TraceIR,
    trace_pos: int,
    register: str,
) -> InstructionNode | None:
    for instruction in _iter_reachable_predecessors(trace_ir, trace_pos):
        if register in instruction.defs:
            return instruction
    return None


def _find_guard_that_changed_atom(
    trace_ir: TraceIR,
    obligation: ObligationSpec,
    atom_id: str,
    trace_pos: int,
    carrier_register: str | None = None,
) -> InstructionNode | None:
    atom = next((candidate for candidate in obligation.atoms if candidate.atom_id == atom_id), None)
    if atom is None:
        return None

    atom_targets = _atom_targets(trace_ir, obligation)
    target = atom_targets.get(atom_id)
    tracked_registers = set(atom.registers)
    if carrier_register is not None:
        tracked_registers.add(carrier_register)

    for instruction in _iter_reachable_predecessors(trace_ir, trace_pos):
        op = _parse_bytecode(instruction.insn_idx, instruction.bytecode)
        if op.kind != "jump_cond":
            continue
        if not tracked_registers & set(op.uses):
            continue
        before, _, _ = _eval_atom(
            trace_ir=trace_ir,
            trace_pos=instruction.trace_pos,
            insn_idx=instruction.insn_idx,
            phase="pre",
            atom=atom,
            state_map=instruction.pre_state,
            obligation=obligation,
            target=target,
        )
        after, _, _ = _eval_atom(
            trace_ir=trace_ir,
            trace_pos=instruction.trace_pos,
            insn_idx=instruction.insn_idx,
            phase="post",
            atom=atom,
            state_map=instruction.post_state,
            obligation=obligation,
            target=target,
        )
        if RESULT_ORDER[after] > RESULT_ORDER[before]:
            return instruction
    return None


def _iter_reachable_predecessors(
    trace_ir: TraceIR,
    trace_pos: int,
) -> list[InstructionNode]:
    start = _node_at_trace_pos(trace_ir, trace_pos)
    if start is None:
        return []

    ordered: list[InstructionNode] = []
    seen: set[int] = set()
    worklist = deque(sorted(start.pred_positions, reverse=True))
    while worklist:
        current_pos = worklist.popleft()
        if current_pos in seen:
            continue
        seen.add(current_pos)
        node = _node_at_trace_pos(trace_ir, current_pos)
        if node is None:
            continue
        ordered.append(node)
        for pred_pos in sorted(node.pred_positions, reverse=True):
            if pred_pos not in seen:
                worklist.append(pred_pos)
    return ordered


def _all_backtrack_edges(
    chains: list[BacktrackChain],
    register: str,
) -> list[SliceEdge]:
    """Return ALL consecutive backtrack edges for *register* across every chain.

    Unlike ``_matching_backtrack_edges`` (which filters to a single insn_idx), this
    function follows the complete mark_precise chain and records every hop, making it
    suitable for Strategy A complete-chain extraction in ``backward_slice``.
    """
    if _register_index(register) is None:
        return []

    edges: list[SliceEdge] = []
    for chain in chains:
        relevant_links = [link for link in chain.links if register in _decode_regs_mask(link.regs)]
        # links are stored in error→root order; reverse to get chronological (root→error).
        chronological = list(reversed(relevant_links))
        for previous, current in zip(chronological, chronological[1:]):
            edges.append(
                SliceEdge(
                    src=(previous.insn_idx, register),
                    dst=(current.insn_idx, register),
                    kind="backtrack_hint",
                    reason=(
                        f"verifier backtracking kept {register} live from insn {previous.insn_idx} "
                        f"to insn {current.insn_idx}"
                    ),
                )
            )
    return edges


def _matching_backtrack_edges(
    chains: list[BacktrackChain],
    insn_idx: int,
    register: str,
) -> list[SliceEdge]:
    if _register_index(register) is None:
        return []

    edges: list[SliceEdge] = []
    for chain in chains:
        relevant_links = [link for link in chain.links if register in _decode_regs_mask(link.regs)]
        chronological = list(reversed(relevant_links))
        for previous, current in zip(chronological, chronological[1:]):
            if current.insn_idx != insn_idx:
                continue
            edges.append(
                SliceEdge(
                    src=(previous.insn_idx, register),
                    dst=(current.insn_idx, register),
                    kind="backtrack_hint",
                    reason=(
                        f"verifier backtracking kept {register} live from insn {previous.insn_idx} "
                        f"to insn {current.insn_idx}"
                    ),
                )
            )
    return edges


def _record_edge(
    edge: SliceEdge,
    edge_keys: set[tuple[tuple[int, str], tuple[int, str], str]],
    edges: list[SliceEdge],
) -> bool:
    key = (edge.src, edge.dst, edge.kind)
    if key in edge_keys:
        return False
    edge_keys.add(key)
    edges.append(edge)
    return True


def _decode_regs_mask(mask: str | None) -> list[str]:
    return _shared_decode_regs_mask(mask)


def _register_index(register: str) -> int | None:
    return _shared_register_index(register)


def _node_at_trace_pos(trace_ir: TraceIR, trace_pos: int | None) -> InstructionNode | None:
    if trace_pos is None:
        return None
    if 0 <= trace_pos < len(trace_ir.instructions):
        node = trace_ir.instructions[trace_pos]
        if node.trace_pos == trace_pos:
            return node
    return next((instruction for instruction in trace_ir.instructions if instruction.trace_pos == trace_pos), None)


def _select_failing_instruction(
    parsed_trace: ParsedTrace,
    trace_ir: TraceIR,
    error_line: str,
    error_insn: int | None,
) -> InstructionNode | None:
    if error_insn is not None:
        best_position = _best_trace_position_for_insn(parsed_trace.instructions, error_insn)
        if best_position is not None:
            return _node_at_trace_pos(trace_ir, best_position)

    error_indices = {candidate.insn_idx for candidate in parsed_trace.instructions if candidate.is_error}
    for instruction in reversed(trace_ir.instructions):
        if instruction.insn_idx in error_indices:
            return instruction

    if parsed_trace.error_line == error_line and trace_ir.instructions:
        return trace_ir.instructions[-1]

    return trace_ir.instructions[-1] if trace_ir.instructions else None


def _best_trace_position_for_insn(
    instructions: list[TracedInstruction],
    insn_idx: int,
) -> int | None:
    best_position = None
    best_quality = None
    for position, instruction in enumerate(instructions):
        if instruction.insn_idx != insn_idx:
            continue
        quality = (
            1 if instruction.is_error else 0,
            1 if instruction.error_text else 0,
            len(instruction.pre_state) + len(instruction.post_state),
            1 if instruction.source_line else 0,
            1 if instruction.backtrack else 0,
            position,
        )
        if best_quality is None or quality > best_quality:
            best_quality = quality
            best_position = position
    return best_position


def _extract_registers(text: str) -> list[str]:
    return _shared_extract_registers(text)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _looks_like_register(text: str) -> bool:
    lowered = text.strip().lower()
    return bool(re.fullmatch(r"[rw]\d+", lowered))


def _normalize_register(register: str) -> str:
    return _shared_normalize_register(register)


def _parse_int(text: str) -> int | None:
    value = text.strip()
    try:
        return int(value, 0)
    except ValueError:
        return None


def _is_scalar_like(state: RegisterState) -> bool:
    lowered = state.type.lower()
    return lowered.startswith("inv") or lowered.startswith("scalar") or lowered == "unknown"


def _same_state(left: RegisterState, right: RegisterState) -> bool:
    return (
        left.type,
        left.id,
        left.off,
        left.range,
        left.umin,
        left.umax,
        left.smin,
        left.smax,
        left.var_off,
    ) == (
        right.type,
        right.id,
        right.off,
        right.range,
        right.umin,
        right.umax,
        right.smin,
        right.smax,
        right.var_off,
    )
