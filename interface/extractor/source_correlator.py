"""Correlate proof events back to source or bytecode spans."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .trace_parser import ParsedTrace, RegisterState, TracedInstruction

try:
    from .proof_analysis import ProofEvent, ProofObligation
except ImportError:  # pragma: no cover - Step 2 lands in parallel.
    @dataclass(slots=True)
    class ProofEvent:
        event_type: str
        insn_idx: int
        register: str | None = None
        before: RegisterState | None = None
        after: RegisterState | None = None
        source_line: str | None = None
        reason: str | None = None
        description: str | None = None
        state_change: str | None = None

    @dataclass(slots=True)
    class ProofObligation:
        type: str
        required: str


SOURCE_LOCATION_SUFFIX_RE = re.compile(r"@\s*([\w./+-]+):(\d+)\s*$")
MAX_SOURCE_SPANS = 5
ROLE_PRIORITY = {
    "proof_propagated": 0,
    "proof_established": 1,
    "proof_lost": 2,
    "rejected": 3,
}


@dataclass(slots=True)
class SourceSpan:
    file: str | None
    line: int | None
    source_text: str
    insn_range: tuple[int, int]
    role: str
    register: str | None
    state_change: str | None
    reason: str | None


def correlate_to_source(
    parsed_trace: ParsedTrace,
    proof_events: list[ProofEvent],
) -> list[SourceSpan]:
    """Map proof events onto source or bytecode spans."""

    if not proof_events:
        return []

    indexed = {instruction.insn_idx: instruction for instruction in parsed_trace.instructions}
    positions = {
        instruction.insn_idx: idx for idx, instruction in enumerate(parsed_trace.instructions)
    }
    spans: list[SourceSpan] = []

    for event in sorted(proof_events, key=lambda item: item.insn_idx):
        instruction = indexed.get(event.insn_idx)
        if instruction is None:
            continue

        source_text, file_name, line_number = _extract_source_fields(
            source_line=_event_source_line(event) or instruction.source_line,
            fallback_text=instruction.bytecode,
        )
        start_insn, end_insn = _expand_source_range(
            parsed_trace.instructions,
            positions[event.insn_idx],
        )
        role = _normalize_role(event.event_type)
        register = event.register or _guess_relevant_register(instruction)
        before = _event_before(event)
        after = _event_after(event)
        state_change = _event_state_change(event) or (
            format_state_change(before, after, register)
            if register is not None
            else None
        )
        if state_change is None and register is not None:
            snapshot = after or before
            if snapshot is not None:
                state_change = _format_register_snapshot(snapshot, register)
        if state_change is None and role == "rejected":
            state_change = _format_rejected_state_change(instruction, register)

        spans.append(
            SourceSpan(
                file=file_name,
                line=line_number,
                source_text=source_text,
                insn_range=(start_insn, end_insn),
                role=role,
                register=register,
                state_change=state_change,
                reason=_event_reason(event) or _infer_reason(role, instruction, before, after),
            )
        )

    return prune_redundant_spans(group_by_source_line(spans))


def group_by_source_line(spans: list[SourceSpan]) -> list[SourceSpan]:
    """Merge spans that point at the same logical source location."""

    merged_by_key: dict[tuple[str | None, int | None, str, str], SourceSpan] = {}
    order: list[tuple[str | None, int | None, str, str]] = []

    for span in spans:
        key = (span.file, span.line, span.source_text, span.role)
        existing = merged_by_key.get(key)
        if existing is None:
            merged_by_key[key] = span
            order.append(key)
            continue

        preferred = _prefer_span(existing, span)
        merged_by_key[key] = SourceSpan(
            file=preferred.file,
            line=preferred.line,
            source_text=preferred.source_text,
            insn_range=(
                min(existing.insn_range[0], span.insn_range[0]),
                max(existing.insn_range[1], span.insn_range[1]),
            ),
            role=preferred.role,
            register=preferred.register or existing.register or span.register,
            state_change=preferred.state_change or existing.state_change or span.state_change,
            reason=preferred.reason or existing.reason or span.reason,
        )

    return [merged_by_key[key] for key in order]


def prune_redundant_spans(spans: list[SourceSpan]) -> list[SourceSpan]:
    """Limit verbose span streams while preserving the core proof story."""

    if not spans:
        return []

    ordered = sorted(spans, key=lambda span: (span.insn_range[0], span.insn_range[1]))
    merged = _merge_consecutive_propagated_spans(ordered)
    if len(merged) <= MAX_SOURCE_SPANS:
        return merged

    keep_indexes: set[int] = set()

    first_established = next(
        (idx for idx, span in enumerate(merged) if span.role == "proof_established"),
        None,
    )
    last_lost = next(
        (idx for idx in range(len(merged) - 1, -1, -1) if merged[idx].role == "proof_lost"),
        None,
    )
    last_rejected = next(
        (idx for idx in range(len(merged) - 1, -1, -1) if merged[idx].role == "rejected"),
        None,
    )

    for index in (first_established, last_lost, last_rejected):
        if index is not None:
            keep_indexes.add(index)

    for role in ("proof_established", "proof_lost", "rejected", "proof_propagated"):
        for idx, span in enumerate(merged):
            if idx in keep_indexes or span.role != role:
                continue
            keep_indexes.add(idx)
            if len(keep_indexes) >= MAX_SOURCE_SPANS:
                return [span for idx, span in enumerate(merged) if idx in keep_indexes]

    return [span for idx, span in enumerate(merged) if idx in keep_indexes]


def format_state_change(
    before: RegisterState | None,
    after: RegisterState | None,
    register: str,
) -> str | None:
    """Render a compact register-state transition."""

    if before is None and after is None:
        return None
    if before is None and after is not None:
        return _format_register_snapshot(after, register)
    if after is None and before is not None:
        return _format_register_snapshot(before, register)
    assert before is not None
    assert after is not None
    return f"{register}: {_format_state(before)} -> {_format_state(after)}"


def _extract_source_fields(
    source_line: str | None,
    fallback_text: str,
) -> tuple[str, str | None, int | None]:
    if source_line:
        stripped = source_line.strip()
        match = SOURCE_LOCATION_SUFFIX_RE.search(stripped)
        if match:
            source_text = stripped[: match.start()].strip() or fallback_text
            return source_text, match.group(1), int(match.group(2))
        if stripped:
            return stripped, None, None
    return fallback_text, None, None


def _event_before(event: ProofEvent) -> RegisterState | None:
    return getattr(event, "before", None) or getattr(event, "state_before", None)


def _event_after(event: ProofEvent) -> RegisterState | None:
    return getattr(event, "after", None) or getattr(event, "state_after", None)


def _event_reason(event: ProofEvent) -> str | None:
    return getattr(event, "reason", None)


def _event_source_line(event: ProofEvent) -> str | None:
    return getattr(event, "source_line", None)


def _event_state_change(event: ProofEvent) -> str | None:
    return getattr(event, "state_change", None)


def _expand_source_range(
    instructions: list[TracedInstruction],
    position: int,
) -> tuple[int, int]:
    anchor = instructions[position]
    anchor_key = _grouping_key(anchor)

    start = position
    while start > 0 and _grouping_key(instructions[start - 1]) == anchor_key:
        start -= 1

    end = position
    while end + 1 < len(instructions) and _grouping_key(instructions[end + 1]) == anchor_key:
        end += 1

    return instructions[start].insn_idx, instructions[end].insn_idx


def _grouping_key(instruction: TracedInstruction) -> tuple[str, str | None]:
    if instruction.source_line:
        return ("source", instruction.source_line.strip())
    return ("bytecode", instruction.bytecode.strip())


def _normalize_role(event_type: str) -> str:
    normalized = event_type.strip().lower()
    mapping = {
        "proof_established": "proof_established",
        "established": "proof_established",
        "narrowed": "proof_established",
        "proof_propagated": "proof_propagated",
        "propagated": "proof_propagated",
        "proof_lost": "proof_lost",
        "lost": "proof_lost",
        "reject": "rejected",
        "rejected": "rejected",
        "error": "rejected",
        "symptom": "rejected",
    }
    return mapping.get(normalized, normalized if normalized in ROLE_PRIORITY else "proof_propagated")


def _prefer_span(left: SourceSpan, right: SourceSpan) -> SourceSpan:
    left_priority = ROLE_PRIORITY.get(left.role, -1)
    right_priority = ROLE_PRIORITY.get(right.role, -1)
    if right_priority > left_priority:
        return right
    if right_priority < left_priority:
        return left
    if right.reason and not left.reason:
        return right
    if right.state_change and not left.state_change:
        return right
    return left


def _merge_consecutive_propagated_spans(spans: list[SourceSpan]) -> list[SourceSpan]:
    merged: list[SourceSpan] = []
    for span in spans:
        if merged and _can_merge_propagated(merged[-1], span):
            merged[-1] = _merge_span_pair(merged[-1], span)
            continue
        merged.append(span)
    return merged


def _can_merge_propagated(left: SourceSpan, right: SourceSpan) -> bool:
    if left.role != "proof_propagated" or right.role != "proof_propagated":
        return False
    return (
        left.file,
        left.line,
        left.source_text,
    ) == (
        right.file,
        right.line,
        right.source_text,
    )


def _merge_span_pair(left: SourceSpan, right: SourceSpan) -> SourceSpan:
    preferred = _prefer_span(left, right)
    return SourceSpan(
        file=preferred.file,
        line=preferred.line,
        source_text=preferred.source_text,
        insn_range=(
            min(left.insn_range[0], right.insn_range[0]),
            max(left.insn_range[1], right.insn_range[1]),
        ),
        role=preferred.role,
        register=preferred.register or left.register or right.register,
        state_change=preferred.state_change or left.state_change or right.state_change,
        reason=preferred.reason or left.reason or right.reason,
    )


def _format_register_snapshot(state: RegisterState, register: str) -> str:
    return f"{register}: {_format_state(state)}"


def _format_state(state: RegisterState) -> str:
    state_type = _normalize_state_type(state.type)

    if state_type == "scalar":
        attrs: list[str] = []
        constant = _constant_value(state)
        if constant is not None:
            attrs.append(str(constant))
        else:
            if state.umin is not None:
                attrs.append(f"umin={state.umin}")
            if state.umax is not None:
                attrs.append(f"umax={state.umax}")
            if state.smin is not None:
                attrs.append(f"smin={state.smin}")
            if state.smax is not None:
                attrs.append(f"smax={state.smax}")
            if state.var_off is not None:
                attrs.append(f"var_off={state.var_off}")
            if not attrs:
                attrs.append("unbounded")
        return f"{state_type}({', '.join(attrs)})"

    attrs = []
    if state.range is not None:
        attrs.append(f"range={state.range}")
    if state.off is not None:
        attrs.append(f"off={state.off}")
    if state.id is not None and not attrs:
        attrs.append(f"id={state.id}")
    if attrs:
        return f"{state_type}({', '.join(attrs)})"
    return state_type


def _normalize_state_type(state_type: str) -> str:
    lowered = state_type.lower()
    if lowered in {"inv", "invp", "scalar", "unknown"} or lowered.startswith("inv"):
        return "scalar"
    if lowered.startswith("pkt"):
        return "pkt"
    return state_type


def _constant_value(state: RegisterState) -> int | None:
    if state.umin is None or state.umax is None:
        return None
    if state.umin != state.umax:
        return None
    if state.smin is not None and state.smax is not None and state.smin != state.smax:
        return None
    return state.umin


def _infer_reason(
    role: str,
    instruction: TracedInstruction,
    before: RegisterState | None,
    after: RegisterState | None,
) -> str | None:
    if role != "proof_lost":
        return None

    bytecode = instruction.bytecode.lower()
    if "|=" in bytecode:
        return "OR operation destroys bounds"
    if "&=" in bytecode:
        return "bitmasking changed the verifier-visible bounds"
    if any(token in bytecode for token in ("<<=", ">>=", " s>>=", "be16", "be32")):
        return "shift or endian transform widens scalar bounds"
    if bytecode.startswith("call "):
        return "helper boundary loses the tracked proof"
    if "(r10" in bytecode:
        return "spill or reload loses the tracked proof"
    if bytecode.startswith("if "):
        return "branch join loses the earlier refinement"
    if before is not None and after is not None:
        if _normalize_state_type(before.type) == "pkt" and _normalize_state_type(after.type) == "scalar":
            return "pointer provenance was degraded to a scalar"
        if _normalize_state_type(after.type) == "scalar" and _is_unbounded_scalar(after):
            return "arithmetic destroys scalar bounds"
    return "verifier-visible bounds were lost"


def _is_unbounded_scalar(state: RegisterState) -> bool:
    return _normalize_state_type(state.type) == "scalar" and all(
        value is None
        for value in (state.umin, state.umax, state.smin, state.smax, state.var_off)
    )


def _guess_relevant_register(instruction: TracedInstruction) -> str | None:
    if instruction.error_text:
        match = re.search(r"\b(R\d+)\b", instruction.error_text)
        if match:
            return match.group(1)
    for register in sorted(instruction.pre_state):
        if register.startswith("R"):
            return register
    for register in sorted(instruction.post_state):
        if register.startswith("R"):
            return register
    return None


def _format_rejected_state_change(
    instruction: TracedInstruction,
    register: str | None,
) -> str | None:
    bytecode = instruction.bytecode.lower()
    arithmetic = re.match(
        r"^(?P<dst>r\d+)\s*(?P<op>\+=|-=)\s*(?P<src>r\d+)$",
        bytecode,
    )
    if arithmetic:
        dst = arithmetic.group("dst").upper()
        src = arithmetic.group("src").upper()
        dst_state = instruction.pre_state.get(dst)
        src_state = instruction.pre_state.get(src)
        if dst_state is not None and src_state is not None:
            return f"{dst}: {_format_state(dst_state)} + {_format_state(src_state)}"

    if register is None:
        return None
    state = instruction.pre_state.get(register) or instruction.post_state.get(register)
    if state is None:
        return None
    return _format_register_snapshot(state, register)
