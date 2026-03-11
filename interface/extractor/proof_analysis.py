"""Analyze proof obligations and proof lifecycles from parsed verifier traces."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .trace_parser import (
    BacktrackChain,
    CriticalTransition,
    ParsedTrace,
    RegisterState,
    TracedInstruction,
)


REGISTER_RE = re.compile(r"\b([RrWw]\d+)\b")
POINTER_TYPE_MARKERS = ("pkt", "map_", "ptr", "sock", "ctx", "fp")
LOSS_TRANSITIONS = {"BOUNDS_COLLAPSE", "RANGE_LOSS"}


@dataclass(slots=True)
class ProofEvent:
    insn_idx: int
    event_type: str
    register: str
    state_before: RegisterState | None
    state_after: RegisterState | None
    source_line: str | None
    description: str


@dataclass(slots=True)
class ProofObligation:
    obligation_type: str
    register: str
    required_condition: str
    description: str


@dataclass(slots=True)
class ProofLifecycle:
    obligation: ProofObligation
    events: list[ProofEvent]
    status: str
    loss_site: ProofEvent | None
    establish_site: ProofEvent | None


def infer_obligation(
    error_line: str,
    error_register: str,
    error_instruction: TracedInstruction | None,
) -> ProofObligation | None:
    """Infer the missing proof obligation from verifier text and error context."""

    lowered = error_line.lower()
    obligation_type: str | None = None

    if any(token in lowered for token in ("invalid access to packet", "pkt pointer", "packet")):
        obligation_type = "packet_access"
    elif "invalid access to map value" in lowered:
        obligation_type = "map_value_access"
    elif "invalid mem access" in lowered and _instruction_has_type(
        error_instruction, ("map_value", "map_value_or_null")
    ):
        obligation_type = "map_value_access"
    elif any(token in lowered for token in ("mem_or_null", "ptr_or_null", "or_null")):
        obligation_type = "null_check"
    elif "helper" in lowered and ("arg" in lowered or "type" in lowered):
        obligation_type = "helper_arg"
    elif "stack" in lowered and any(token in lowered for token in ("invalid", "bounds", "access")):
        obligation_type = "stack_access"

    if obligation_type is None:
        return None

    register = _select_obligation_register(
        obligation_type=obligation_type,
        error_register=error_register,
        error_instruction=error_instruction,
    )
    required_condition, description = _describe_obligation(obligation_type, register)
    return ProofObligation(
        obligation_type=obligation_type,
        register=register,
        required_condition=required_condition,
        description=description,
    )


def analyze_proof_lifecycle(
    parsed_trace: ParsedTrace,
    obligation: ProofObligation,
    backtrack_chains: list[BacktrackChain],
    error_insn: int | None,
) -> ProofLifecycle:
    """
    Analyze where a proof is established, propagated, lost, or rejected.

    The analysis prioritizes verifier backtracking chains when they are present and
    falls back to transition and state-evolution heuristics otherwise.
    """

    events = build_proof_events(parsed_trace, obligation, backtrack_chains)
    if error_insn is not None:
        events = [event for event in events if event.insn_idx <= error_insn]

    establish_site = next((event for event in events if _event_counts_as_established(event)), None)
    loss_site = next((event for event in events if event.event_type == "lost"), None)
    rejected = next((event for event in events if event.event_type == "rejected"), None)

    if establish_site is None:
        status = "never_established" if rejected is not None else "satisfied"
    elif loss_site is not None:
        status = "established_then_lost"
    elif rejected is not None:
        status = "established_but_insufficient"
    else:
        status = "satisfied"

    return ProofLifecycle(
        obligation=obligation,
        events=events,
        status=status,
        loss_site=loss_site,
        establish_site=establish_site,
    )


def build_proof_events(
    parsed_trace: ParsedTrace,
    obligation: ProofObligation,
    backtrack_chains: list[BacktrackChain],
) -> list[ProofEvent]:
    """
    Build an ordered timeline of proof-relevant events.

    The event stream combines verifier backtracking, critical transitions, and
    state evolution from the parsed instruction trace.
    """

    error_instruction = _find_error_instruction(parsed_trace)
    relevant_chain = _select_relevant_chain(
        parsed_trace=parsed_trace,
        backtrack_chains=backtrack_chains,
        error_insn=error_instruction.insn_idx if error_instruction is not None else None,
    )
    relevant_registers = _collect_relevant_registers(
        obligation=obligation,
        chain=relevant_chain,
        error_instruction=error_instruction,
    )

    events: list[ProofEvent] = []
    events.extend(
        _events_from_backtrack_chain(
            chain=relevant_chain,
            parsed_trace=parsed_trace,
            obligation=obligation,
            relevant_registers=relevant_registers,
        )
    )
    events.extend(
        _events_from_state_evolution(
            parsed_trace=parsed_trace,
            obligation=obligation,
            relevant_registers=relevant_registers,
        )
    )

    if error_instruction is not None and error_instruction.is_error:
        events.append(
            ProofEvent(
                insn_idx=error_instruction.insn_idx,
                event_type="rejected",
                register=obligation.register,
                state_before=error_instruction.pre_state.get(obligation.register),
                state_after=error_instruction.post_state.get(obligation.register),
                source_line=error_instruction.source_line,
                description=error_instruction.error_text or "verifier rejected the program",
            )
        )

    deduped: list[ProofEvent] = []
    seen: set[tuple[int, str, str]] = set()
    for event in sorted(events, key=_event_sort_key):
        key = (event.insn_idx, event.event_type, event.register)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _describe_obligation(obligation_type: str, register: str) -> tuple[str, str]:
    if obligation_type == "packet_access":
        return (
            "ptr.off + scalar_offset + access_size <= ptr.range and scalar_offset is bounded",
            f"Packet access through {register} requires a bounded offset and in-range packet proof.",
        )
    if obligation_type == "map_value_access":
        return (
            "reg.off + access_size <= map_value_size",
            f"Map-value access through {register} requires an in-bounds offset proof.",
        )
    if obligation_type == "stack_access":
        return (
            "fp offset stays within initialized stack bounds",
            f"Stack access through {register} requires a valid frame offset and initialization proof.",
        )
    if obligation_type == "helper_arg":
        return (
            "register type matches the helper argument contract",
            f"Helper call argument {register} must satisfy the helper's expected type.",
        )
    if obligation_type == "null_check":
        return (
            "register is proven non-NULL on all incoming paths",
            f"{register} must be checked for NULL before dereference or helper use.",
        )
    return ("proof is required", f"{register} needs an earlier dominating proof.")


def _select_obligation_register(
    obligation_type: str,
    error_register: str,
    error_instruction: TracedInstruction | None,
) -> str:
    if error_instruction is not None:
        if obligation_type == "packet_access":
            pointer_register = _first_register_with_type(error_instruction, ("pkt",))
            if pointer_register is not None:
                return pointer_register
        if obligation_type == "map_value_access":
            map_register = _first_register_with_type(error_instruction, ("map_value",))
            if map_register is not None:
                return map_register
        if obligation_type == "null_check":
            nullable_register = _first_register_with_type(error_instruction, ("_or_null",))
            if nullable_register is not None:
                return nullable_register

        registers = _extract_registers(error_instruction.bytecode)
        if registers:
            return registers[0]

    return _normalize_register(error_register) if error_register else "R0"


def _instruction_has_type(
    instruction: TracedInstruction | None,
    type_markers: tuple[str, ...],
) -> bool:
    if instruction is None:
        return False
    for state in list(instruction.pre_state.values()) + list(instruction.post_state.values()):
        lowered = state.type.lower()
        if any(marker in lowered for marker in type_markers):
            return True
    return False


def _first_register_with_type(
    instruction: TracedInstruction,
    type_markers: tuple[str, ...],
) -> str | None:
    for register in _extract_registers(instruction.bytecode):
        state = instruction.pre_state.get(register) or instruction.post_state.get(register)
        if state is None:
            continue
        lowered = state.type.lower()
        if any(marker in lowered for marker in type_markers):
            return register
    return None


def _select_relevant_chain(
    parsed_trace: ParsedTrace,
    backtrack_chains: list[BacktrackChain],
    error_insn: int | None,
) -> BacktrackChain | None:
    if not backtrack_chains:
        return None
    if error_insn is not None:
        for chain in backtrack_chains:
            if chain.error_insn == error_insn:
                return chain
    if parsed_trace.backtrack_chains:
        return parsed_trace.backtrack_chains[-1]
    return backtrack_chains[-1]


def _collect_relevant_registers(
    obligation: ProofObligation,
    chain: BacktrackChain | None,
    error_instruction: TracedInstruction | None,
) -> list[str]:
    registers = [obligation.register]
    if chain is not None:
        for link in chain.links:
            registers.extend(_decode_regs_mask(link.regs))
    if error_instruction is not None:
        registers.extend(_extract_registers(error_instruction.bytecode))

    deduped: list[str] = []
    for register in registers:
        normalized = _normalize_register(register)
        if normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _events_from_backtrack_chain(
    chain: BacktrackChain | None,
    parsed_trace: ParsedTrace,
    obligation: ProofObligation,
    relevant_registers: list[str],
) -> list[ProofEvent]:
    if chain is None:
        return []

    instructions_by_idx = {instruction.insn_idx: instruction for instruction in parsed_trace.instructions}
    transitions_by_key = _transitions_by_key(parsed_trace.critical_transitions)

    events: list[ProofEvent] = []
    previous_regs: set[str] = set()
    established_registers: set[str] = set()

    for link in reversed(chain.links):
        instruction = instructions_by_idx.get(link.insn_idx)
        current_regs = set(_decode_regs_mask(link.regs))
        regs_to_consider = current_regs | previous_regs | set(relevant_registers)

        loss_emitted = False
        for register in sorted(regs_to_consider):
            transition = transitions_by_key.get((link.insn_idx, register))
            if transition is None or not _is_loss_transition(transition, obligation):
                continue
            events.append(
                ProofEvent(
                    insn_idx=link.insn_idx,
                    event_type="lost",
                    register=register,
                    state_before=transition.before,
                    state_after=transition.after,
                    source_line=instruction.source_line if instruction is not None else None,
                    description=transition.description,
                )
            )
            loss_emitted = True

        if loss_emitted:
            previous_regs = current_regs
            continue

        introduced = [register for register in sorted(current_regs) if register not in previous_regs]
        for register in introduced:
            if register not in relevant_registers:
                continue
            established_registers.add(register)
            events.append(
                _build_instruction_event(
                    instruction=instruction,
                    insn_idx=link.insn_idx,
                    event_type="established",
                    register=register,
                    fallback_description=(
                        f"{register} entered the verifier backtracking chain at insn {link.insn_idx}."
                    ),
                )
            )

        if introduced:
            previous_regs = current_regs
            continue

        register = _select_primary_register(current_regs, relevant_registers, obligation)
        if register is None:
            previous_regs = current_regs
            continue

        event_type = "propagated"
        before = instruction.pre_state.get(register) if instruction is not None else None
        after = instruction.post_state.get(register) if instruction is not None else None
        if _is_narrowing(before, after):
            event_type = "narrowed"
            established_registers.add(register)
        elif register not in established_registers and _state_has_useful_proof(after or before):
            event_type = "established"
            established_registers.add(register)

        events.append(
            _build_instruction_event(
                instruction=instruction,
                insn_idx=link.insn_idx,
                event_type=event_type,
                register=register,
                fallback_description=(
                    f"{register} remained part of the verifier backtracking chain at insn {link.insn_idx}."
                ),
            )
        )
        previous_regs = current_regs

    return events


def _events_from_state_evolution(
    parsed_trace: ParsedTrace,
    obligation: ProofObligation,
    relevant_registers: list[str],
) -> list[ProofEvent]:
    transitions_by_key = _transitions_by_key(parsed_trace.critical_transitions)
    events: list[ProofEvent] = []
    established_registers: set[str] = set()

    for instruction in parsed_trace.instructions:
        if instruction.is_error:
            continue
        for register in relevant_registers:
            before = instruction.pre_state.get(register)
            after = instruction.post_state.get(register)
            if before is None and after is None:
                continue

            transition = transitions_by_key.get((instruction.insn_idx, register))
            if transition is not None and _is_loss_transition(transition, obligation):
                events.append(
                    ProofEvent(
                        insn_idx=instruction.insn_idx,
                        event_type="lost",
                        register=register,
                        state_before=transition.before,
                        state_after=transition.after,
                        source_line=instruction.source_line,
                        description=transition.description,
                    )
                )
                continue

            if not _register_is_destination(instruction.bytecode, register) and not _state_changed(
                before, after
            ):
                continue

            if register not in established_registers and _state_has_useful_proof(after or before):
                established_registers.add(register)
                events.append(
                    ProofEvent(
                        insn_idx=instruction.insn_idx,
                        event_type="established",
                        register=register,
                        state_before=before,
                        state_after=after,
                        source_line=instruction.source_line,
                        description=(
                            f"{register} gained a tracked verifier state at insn {instruction.insn_idx}."
                        ),
                    )
                )
                continue

            if _is_narrowing(before, after):
                established_registers.add(register)
                events.append(
                    ProofEvent(
                        insn_idx=instruction.insn_idx,
                        event_type="narrowed",
                        register=register,
                        state_before=before,
                        state_after=after,
                        source_line=instruction.source_line,
                        description=(
                            f"{register} narrowed to a tighter state at insn {instruction.insn_idx}."
                        ),
                    )
                )

    return events


def _build_instruction_event(
    instruction: TracedInstruction | None,
    insn_idx: int,
    event_type: str,
    register: str,
    fallback_description: str,
) -> ProofEvent:
    before = instruction.pre_state.get(register) if instruction is not None else None
    after = instruction.post_state.get(register) if instruction is not None else None
    if event_type == "established":
        description = f"{register} became relevant to the proof at insn {insn_idx}."
    elif event_type == "narrowed":
        description = f"{register} narrowed to a tighter state at insn {insn_idx}."
    else:
        description = fallback_description
    return ProofEvent(
        insn_idx=insn_idx,
        event_type=event_type,
        register=register,
        state_before=before,
        state_after=after,
        source_line=instruction.source_line if instruction is not None else None,
        description=description,
    )


def _transitions_by_key(
    transitions: list[CriticalTransition],
) -> dict[tuple[int, str], CriticalTransition]:
    by_key: dict[tuple[int, str], CriticalTransition] = {}
    for transition in transitions:
        key = (transition.insn_idx, transition.register)
        existing = by_key.get(key)
        if existing is None or _transition_priority(transition) < _transition_priority(existing):
            by_key[key] = transition
    return by_key


def _transition_priority(transition: CriticalTransition) -> int:
    if transition.transition_type in LOSS_TRANSITIONS:
        return 0
    if transition.transition_type == "PROVENANCE_LOSS":
        return 1
    return 2


def _is_loss_transition(
    transition: CriticalTransition,
    obligation: ProofObligation,
) -> bool:
    if transition.transition_type == "BOUNDS_COLLAPSE":
        return _has_destructive_bound_loss(transition.before, transition.after)
    if transition.transition_type == "RANGE_LOSS":
        return True
    if transition.register != obligation.register:
        return False
    return transition.transition_type in {"PROVENANCE_LOSS", "TYPE_DOWNGRADE"}


def _select_primary_register(
    current_regs: set[str],
    relevant_registers: list[str],
    obligation: ProofObligation,
) -> str | None:
    if obligation.register in current_regs:
        return obligation.register
    for register in relevant_registers:
        if register in current_regs:
            return register
    if current_regs:
        return sorted(current_regs)[0]
    return None


def _decode_regs_mask(mask: str | None) -> list[str]:
    if not mask:
        return []

    text = mask.strip().lower()
    if text in {"0", "0x0"}:
        return []

    try:
        value = int(text, 16)
    except ValueError:
        try:
            value = int(text, 0)
        except ValueError:
            return []

    registers: list[str] = []
    bit = 0
    while value:
        if value & 1:
            registers.append(f"R{bit}")
        value >>= 1
        bit += 1
    return registers


def _extract_registers(text: str | None) -> list[str]:
    if not text:
        return []

    registers: list[str] = []
    for match in REGISTER_RE.finditer(text):
        normalized = _normalize_register(match.group(1))
        if normalized not in registers:
            registers.append(normalized)
    return registers


def _normalize_register(register: str) -> str:
    lowered = register.lower()
    if lowered.startswith(("r", "w")):
        return f"R{lowered[1:]}"
    return register


def _state_has_useful_proof(state: RegisterState | None) -> bool:
    if state is None:
        return False
    lowered = state.type.lower()
    if any(marker in lowered for marker in POINTER_TYPE_MARKERS):
        return not state.type.lower().endswith("_or_null") and (
            state.range is None or state.range > 0 or state.id is not None or state.off is not None
        )
    return any(value is not None for value in (state.umin, state.umax, state.smin, state.smax)) or (
        state.var_off is not None
    )


def _is_narrowing(before: RegisterState | None, after: RegisterState | None) -> bool:
    if before is None or after is None:
        return False
    if before.type.lower().endswith("_or_null") and not after.type.lower().endswith("_or_null"):
        return True
    if before.range is not None and after.range is not None and after.range > before.range:
        return True
    if before.umin is not None and after.umin is not None and after.umin > before.umin:
        return True
    if before.umax is not None and after.umax is not None and after.umax < before.umax:
        return True
    if before.smin is not None and after.smin is not None and after.smin > before.smin:
        return True
    if before.smax is not None and after.smax is not None and after.smax < before.smax:
        return True
    return False


def _event_counts_as_established(event: ProofEvent) -> bool:
    if event.event_type in {"established", "narrowed"}:
        return True
    if event.event_type != "propagated":
        return False
    return _state_has_useful_proof(event.state_after or event.state_before)


def _find_error_instruction(parsed_trace: ParsedTrace) -> TracedInstruction | None:
    for instruction in reversed(parsed_trace.instructions):
        if instruction.is_error:
            return instruction
    if parsed_trace.instructions:
        return parsed_trace.instructions[-1]
    return None


def _has_destructive_bound_loss(before: RegisterState, after: RegisterState) -> bool:
    scalar_fields = ("umin", "umax", "smin", "smax")
    if any(getattr(before, field) is not None and getattr(after, field) is None for field in scalar_fields):
        return True
    if before.var_off is not None and after.var_off is None:
        return True
    return False


def _register_is_destination(bytecode: str, register: str) -> bool:
    match = re.match(r"^\s*(?P<reg>[rw]\d+)\s*(?:=|\+=|-=|\*=|/=|<<=|>>=|&=|\|=|\^=)", bytecode)
    if not match:
        return False
    return _normalize_register(match.group("reg")) == register


def _state_changed(before: RegisterState | None, after: RegisterState | None) -> bool:
    if before is None or after is None:
        return before is not after
    return (
        before.type,
        before.id,
        before.off,
        before.range,
        before.umin,
        before.umax,
        before.smin,
        before.smax,
        before.var_off,
    ) != (
        after.type,
        after.id,
        after.off,
        after.range,
        after.umin,
        after.umax,
        after.smin,
        after.smax,
        after.var_off,
    )


def _event_sort_key(event: ProofEvent) -> tuple[int, int, str]:
    priorities = {
        "established": 0,
        "narrowed": 1,
        "propagated": 2,
        "lost": 3,
        "rejected": 4,
    }
    return (event.insn_idx, priorities.get(event.event_type, 99), event.register)
