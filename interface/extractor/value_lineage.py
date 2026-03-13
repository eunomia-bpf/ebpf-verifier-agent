"""Register value lineage tracking for eBPF verifier proof traces.

Tracks how values flow between registers and stack slots across the instruction
trace, enabling:
- Register copy chains (r3 = r0 -> R3 inherits R0's lineage)
- Spill/fill tracking (stack <-> register, the most common cause of lost
  proof propagation in compiler-lowered artifacts)
- ALU operations that preserve type/lineage (add/sub with constant)
- ALU operations that destroy lineage (bitwise OR with register, etc.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .trace_parser_parts._impl import TracedInstruction


# ---------------------------------------------------------------------------
# Instruction patterns (matching what obligation_inference._parse_bytecode uses)
# ---------------------------------------------------------------------------

_MOV_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*=\s*(?P<src>[rw]\d+)$",
    re.IGNORECASE,
)
# Load from memory: r5 = *(u64 *)(r10 -8)
_LOAD_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*=\s*\*\([us]\d+\s*\*\)\("
    r"(?P<base>[rw]\d+)\s*(?P<sign>[+-])\s*(?P<off>(?:0x[0-9a-fA-F]+|\d+))\)$",
    re.IGNORECASE,
)
# Store to memory: *(u64 *)(r10 -8) = r0
_STORE_RE = re.compile(
    r"^\*\([us]\d+\s*\*\)\("
    r"(?P<base>[rw]\d+)\s*(?P<sign>[+-])\s*(?P<off>(?:0x[0-9a-fA-F]+|\d+))\)\s*=\s*(?P<src>.+)$",
    re.IGNORECASE,
)
# ALU aug-assign with constant: r0 += 14  /  r0 -= 4
_ALU_CONST_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*(?P<op>[+\-]=)\s*(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
# ALU aug-assign with register: r0 += r2  (non-constant — destroys lineage)
_ALU_REG_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*(?P<op>s?[+\-*/%]?=|s?<<=|s?>>=|&=|\|=|\^=)\s*(?P<src>[rw]\d+)$",
    re.IGNORECASE,
)
# ALU assignment (= expr): r0 = 5  or  r0 = r1  (simple constant or handled by MOV above)
_ALU_ASSIGN_RE = re.compile(
    r"^(?P<dst>[rw]\d+)\s*=\s*(?P<rhs>.+)$",
    re.IGNORECASE,
)


def _normalize_reg(name: str) -> str:
    """Normalize w-prefixed and lower-case register names to Rn form."""
    lower = name.strip().lower()
    if lower.startswith(("r", "w")):
        return f"R{lower[1:]}"
    return name.strip()


def _signed_offset(sign: str, raw: str) -> int:
    value = int(raw, 0)
    return value if sign == "+" else -value


def _is_fp_relative(base_reg_normalized: str) -> bool:
    return base_reg_normalized in {"R10", "r10"}


def _stack_key(offset: int) -> str:
    """Canonical name for a stack slot: 'fp-8', 'fp-16', etc."""
    return f"fp{offset}"  # offset is negative for frame locals


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ValueNode:
    """A single node in the value lineage graph.

    Each node represents a *definition* of a value in a particular location
    (register or stack slot) at a specific instruction index.
    """

    value_id: int
    location: str          # Rn or fp-N
    defined_at: int | None  # insn_idx (None = entry / parameter)
    op_kind: str            # 'entry', 'mov', 'spill', 'fill', 'ptr_add', 'alu', 'call', 'unknown'
    parent_id: int | None   # value_id of the source value (for copy/fill/ptr_add)
    offset_delta: int = 0   # cumulative offset added relative to the proof root
    # The proof root is the earliest value_id that established the proof
    proof_root: int = 0     # filled in after construction


@dataclass
class ValueLineage:
    """Complete lineage graph for all values in a trace.

    Use the query methods rather than accessing internals directly.
    """

    # Map value_id -> ValueNode
    _nodes: dict[int, ValueNode] = field(default_factory=dict)

    # Current live version at each location (Rn or fp-N) as of each trace position
    # _live[trace_pos][location] = value_id
    _live_at: list[dict[str, int]] = field(default_factory=list)

    # Total number of instructions processed
    _n_instructions: int = 0

    # --------------------------------------------------------------------------
    # Query API
    # --------------------------------------------------------------------------

    def get_value_origin(
        self, trace_pos: int, location: str
    ) -> tuple[int | None, str] | None:
        """Return (original_insn_idx, original_location) for the value live at
        (trace_pos, location).

        Follows the lineage chain all the way to the root definition.
        Returns None if the location is not live at that position.
        """
        vid = self._vid_at(trace_pos, location)
        if vid is None:
            return None
        return self._ultimate_origin(vid)

    def get_all_aliases(self, trace_pos: int, location: str) -> set[str]:
        """Return all locations currently holding the same proof-root value as
        (trace_pos, location).

        'Currently' means at trace_pos (i.e., in _live_at[trace_pos]).
        """
        vid = self._vid_at(trace_pos, location)
        if vid is None:
            return set()
        root = self._nodes[vid].proof_root
        live = self._live_at[trace_pos] if trace_pos < len(self._live_at) else {}
        return {loc for loc, lvid in live.items() if self._nodes[lvid].proof_root == root}

    def is_same_value(self, trace_pos: int, loc1: str, loc2: str) -> bool:
        """Return True if loc1 and loc2 hold values with the same proof root."""
        vid1 = self._vid_at(trace_pos, loc1)
        vid2 = self._vid_at(trace_pos, loc2)
        if vid1 is None or vid2 is None:
            return False
        return self._nodes[vid1].proof_root == self._nodes[vid2].proof_root

    def get_offset_delta(self, trace_pos: int, location: str) -> int:
        """Return the cumulative offset added to the value relative to its
        proof root (e.g., after r0 += 14, delta is +14).
        """
        vid = self._vid_at(trace_pos, location)
        if vid is None:
            return 0
        return self._nodes[vid].offset_delta

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _vid_at(self, trace_pos: int, location: str) -> int | None:
        if trace_pos >= len(self._live_at):
            return None
        return self._live_at[trace_pos].get(location)

    def _ultimate_origin(self, vid: int) -> tuple[int | None, str]:
        """Walk parent chain to the root definition."""
        seen: set[int] = set()
        node = self._nodes[vid]
        while node.parent_id is not None and node.parent_id not in seen:
            seen.add(node.value_id)
            parent = self._nodes.get(node.parent_id)
            if parent is None:
                break
            node = parent
        return (node.defined_at, node.location)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_value_lineage(instructions: list[TracedInstruction]) -> ValueLineage:
    """Build a complete ValueLineage from an ordered list of TracedInstructions.

    Instructions must be in trace order (the same order as ParsedTrace.instructions).
    """
    lineage = ValueLineage()
    next_id = _IDAllocator()

    # Current live versions: location -> value_id
    current: dict[str, int] = {}

    # Stack slots: fp-N -> value_id (persists independently of register live set)
    stack: dict[str, int] = {}

    def new_node(
        location: str,
        *,
        defined_at: int | None,
        op_kind: str,
        parent_id: int | None = None,
        offset_delta: int = 0,
    ) -> int:
        vid = next_id()
        proof_root = vid  # will be replaced if there is a parent
        if parent_id is not None:
            parent = lineage._nodes.get(parent_id)
            if parent is not None:
                proof_root = parent.proof_root
        node = ValueNode(
            value_id=vid,
            location=location,
            defined_at=defined_at,
            op_kind=op_kind,
            parent_id=parent_id,
            offset_delta=offset_delta,
            proof_root=proof_root,
        )
        lineage._nodes[vid] = node
        return vid

    for trace_pos, insn in enumerate(instructions):
        insn_idx = insn.insn_idx
        bytecode = insn.bytecode.strip()

        # Ensure all registers visible in pre_state have a live version
        for reg in insn.pre_state:
            if reg not in current:
                current[reg] = new_node(reg, defined_at=None, op_kind="entry")
            # Also register stack slots that appear as fp-N keys in the state
            if reg.startswith("fp") or reg.startswith("FP"):
                if reg not in stack:
                    stack[reg] = current[reg]

        # Snapshot live versions *before* processing this instruction
        # (this is the "pre" snapshot; index == trace_pos)
        pre_snapshot = _make_snapshot(current, stack)
        lineage._live_at.append(pre_snapshot)

        # Parse the instruction and update lineage
        _process_instruction(
            bytecode=bytecode,
            insn_idx=insn_idx,
            current=current,
            stack=stack,
            new_node=new_node,
            lineage=lineage,
        )

        # Ensure all registers visible in post_state also have live versions
        for reg in insn.post_state:
            if reg not in current:
                current[reg] = new_node(reg, defined_at=insn_idx, op_kind="entry")

    # Append a final "post" snapshot after the last instruction so that
    # callers can query the state after all instructions have been processed
    # (trace_pos == len(instructions)).
    lineage._live_at.append(_make_snapshot(current, stack))

    lineage._n_instructions = len(instructions)
    return lineage


def _process_instruction(
    bytecode: str,
    insn_idx: int,
    current: dict[str, int],
    stack: dict[str, int],
    new_node,
    lineage: ValueLineage,
) -> None:
    """Update current/stack based on the bytecode of one instruction."""

    lowered = bytecode.strip().lower()

    # --- MOV: r3 = r0 -------------------------------------------------------
    mov = _MOV_RE.match(lowered)
    if mov:
        dst = _normalize_reg(mov.group("dst"))
        src = _normalize_reg(mov.group("src"))
        src_vid = current.get(src)
        if src_vid is not None:
            # Copy: inherit same proof root, zero additional offset
            current[dst] = new_node(
                dst,
                defined_at=insn_idx,
                op_kind="mov",
                parent_id=src_vid,
                offset_delta=lineage._nodes[src_vid].offset_delta,
            )
        else:
            # Source unknown — new independent value
            current[dst] = new_node(dst, defined_at=insn_idx, op_kind="mov")
        return

    # --- LOAD: r5 = *(u64 *)(r10 -8) ----------------------------------------
    load = _LOAD_RE.match(lowered)
    if load:
        dst = _normalize_reg(load.group("dst"))
        base = _normalize_reg(load.group("base"))
        if _is_fp_relative(base):
            offset = _signed_offset(load.group("sign"), load.group("off"))
            slot_key = _stack_key(offset)
            slot_vid = stack.get(slot_key)
            if slot_vid is not None:
                # Fill from stack -> register inherits stack slot's lineage
                current[dst] = new_node(
                    dst,
                    defined_at=insn_idx,
                    op_kind="fill",
                    parent_id=slot_vid,
                    offset_delta=lineage._nodes[slot_vid].offset_delta,
                )
            else:
                # Stack slot was not previously recorded — new unknown value
                current[dst] = new_node(dst, defined_at=insn_idx, op_kind="fill")
        else:
            # Load from non-stack memory — new independent value
            current[dst] = new_node(dst, defined_at=insn_idx, op_kind="load")
        return

    # --- STORE: *(u64 *)(r10 -8) = r0 ----------------------------------------
    store = _STORE_RE.match(lowered)
    if store:
        base = _normalize_reg(store.group("base"))
        if _is_fp_relative(base):
            offset = _signed_offset(store.group("sign"), store.group("off"))
            slot_key = _stack_key(offset)
            src_text = store.group("src").strip().lower()
            src_reg = _normalize_reg(src_text) if _looks_like_register(src_text) else None
            if src_reg is not None:
                src_vid = current.get(src_reg)
                if src_vid is not None:
                    # Spill: stack slot inherits register's lineage
                    stack[slot_key] = new_node(
                        slot_key,
                        defined_at=insn_idx,
                        op_kind="spill",
                        parent_id=src_vid,
                        offset_delta=lineage._nodes[src_vid].offset_delta,
                    )
                    return
            # Constant store or unknown source — kill stack slot lineage
            stack[slot_key] = new_node(slot_key, defined_at=insn_idx, op_kind="store")
        # Non-stack stores don't affect register lineage
        return

    # --- ALU with constant: r0 += 14 -----------------------------------------
    alu_const = _ALU_CONST_RE.match(lowered)
    if alu_const:
        dst = _normalize_reg(alu_const.group("dst"))
        op = alu_const.group("op")
        imm = int(alu_const.group("imm"), 0)
        delta = imm if op == "+=" else -imm
        src_vid = current.get(dst)
        if src_vid is not None:
            old_delta = lineage._nodes[src_vid].offset_delta
            current[dst] = new_node(
                dst,
                defined_at=insn_idx,
                op_kind="ptr_add",
                parent_id=src_vid,
                offset_delta=old_delta + delta,
            )
        else:
            current[dst] = new_node(dst, defined_at=insn_idx, op_kind="ptr_add")
        return

    # --- ALU with register: r0 += r2, r0 |= r6, etc. (destroys lineage) ------
    alu_reg = _ALU_REG_RE.match(lowered)
    if alu_reg:
        dst = _normalize_reg(alu_reg.group("dst"))
        # Non-linear / register-register operations destroy provable lineage
        current[dst] = new_node(dst, defined_at=insn_idx, op_kind="alu")
        return

    # --- Any other assignment: r0 = 5, r0 = ~r1, etc. -----------------------
    alu_assign = _ALU_ASSIGN_RE.match(lowered)
    if alu_assign:
        dst = _normalize_reg(alu_assign.group("dst"))
        rhs = alu_assign.group("rhs").strip()
        if not _looks_like_register(rhs):
            # Constant or complex expression — new independent value
            current[dst] = new_node(dst, defined_at=insn_idx, op_kind="alu")
        # If rhs is a register, it's a plain MOV — already caught above; but
        # just in case the MOV_RE didn't match (e.g., wide regs), handle here:
        else:
            src = _normalize_reg(rhs)
            src_vid = current.get(src)
            if src_vid is not None:
                current[dst] = new_node(
                    dst,
                    defined_at=insn_idx,
                    op_kind="mov",
                    parent_id=src_vid,
                    offset_delta=lineage._nodes[src_vid].offset_delta,
                )
            else:
                current[dst] = new_node(dst, defined_at=insn_idx, op_kind="alu")
        return

    # Calls: R0 is a fresh return value; R1-R5 are consumed but not killed here
    if lowered.startswith("call "):
        current["R0"] = new_node("R0", defined_at=insn_idx, op_kind="call")
        return

    # Unknown / unrecognized — no lineage update


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_REG_NAME_RE = re.compile(r"^[rw]\d+$", re.IGNORECASE)


def _looks_like_register(text: str) -> bool:
    return bool(_REG_NAME_RE.match(text.strip()))


class _IDAllocator:
    """Simple monotonic integer ID generator."""

    def __init__(self) -> None:
        self._next = 1

    def __call__(self) -> int:
        vid = self._next
        self._next += 1
        return vid


def _make_snapshot(current: dict[str, int], stack: dict[str, int]) -> dict[str, int]:
    """Merge register and stack live versions into one snapshot dict."""
    snapshot = dict(current)
    for slot_key, slot_vid in stack.items():
        snapshot.setdefault(slot_key, slot_vid)
    return snapshot
