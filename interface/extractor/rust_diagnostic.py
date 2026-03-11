"""Top-level entry point for Rust-style verifier diagnostics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .diagnoser import Diagnosis, diagnose
from .log_parser import ParsedLog, parse_log
from .renderer import DiagnosticOutput, render_diagnostic
from .source_correlator import (
    ProofEvent,
    ProofObligation,
    correlate_to_source,
)
from .trace_parser import (
    ChainLink as _ChainLink,
    CausalChain as _CausalChain,
    CriticalTransition,
    ParsedTrace,
    RegisterState,
    TracedInstruction,
    parse_trace,
)

try:
    from .proof_analysis import analyze_proof_lifecycle, infer_obligation
except ImportError:  # pragma: no cover - Step 2 lands in parallel.
    analyze_proof_lifecycle = None
    infer_obligation = None

try:
    from .trace_parser import BacktrackChain, BacktrackLink
except ImportError:  # pragma: no cover - compatibility shim until trace_parser exposes them.
    BacktrackLink = _ChainLink
    BacktrackChain = _CausalChain


OBLIGATION_DETAILS: dict[str, tuple[str, str]] = {
    "OBLIGE-O001": ("packet_access", "reg.off+size <= reg.range"),
    "OBLIGE-O002": ("non_null_dereference", "pointer must be proven non-null before dereference"),
    "OBLIGE-O003": ("initialized_stack", "every read byte must be initialized"),
    "OBLIGE-O004": ("reference_lifetime", "all acquired references are released on every path"),
    "OBLIGE-O005": ("packet_access", "reg.off+size <= reg.range"),
    "OBLIGE-O006": (
        "pointer_provenance",
        "pointer registers must retain verifier-tracked provenance",
    ),
    "OBLIGE-O007": ("state_explosion", "control flow must stay within verifier limits"),
    "OBLIGE-O008": ("bounded_loop", "loop progress and a finite bound must be visible"),
}
TRANSITION_PRIORITY = {
    "TYPE_DOWNGRADE": 0,
    "PROVENANCE_LOSS": 1,
    "RANGE_LOSS": 2,
    "BOUNDS_COLLAPSE": 3,
}


@dataclass(slots=True)
class _FallbackProofResult:
    proof_status: str | None
    proof_events: list[ProofEvent] = field(default_factory=list)
    obligation: ProofObligation | None = None


def generate_diagnostic(verifier_log: str, catalog_path: str | None = None) -> DiagnosticOutput:
    """Run the full parser → proof summary → source correlation → renderer pipeline."""

    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)
    parsed_trace = parse_trace(verifier_log)
    diagnosis = diagnose(verifier_log, catalog_path=catalog_path)
    proof_result = _analyze_proof(parsed_log, parsed_trace, diagnosis)

    proof_status = proof_result.proof_status or diagnosis.proof_status or "unknown"
    obligation = proof_result.obligation or _infer_obligation(parsed_log, diagnosis)
    spans = correlate_to_source(parsed_trace, proof_result.proof_events)
    note = _build_note(diagnosis, obligation)
    help_text = _build_help_text(parsed_log, diagnosis)

    return render_diagnostic(
        error_id=diagnosis.error_id or parsed_log.error_id or "OBLIGE-UNKNOWN",
        taxonomy_class=diagnosis.taxonomy_class or parsed_log.taxonomy_class or "unknown",
        proof_status=proof_status,
        spans=spans,
        obligation=obligation,
        note=note,
        help_text=help_text,
    )


def _analyze_proof(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> _FallbackProofResult:
    if diagnosis.taxonomy_class == "source_bug" and diagnosis.proof_status == "never_established":
        obligation = _infer_with_proof_analysis(parsed_log, parsed_trace, diagnosis)
        return _FallbackProofResult(
            proof_status=diagnosis.proof_status,
            proof_events=_synthesize_proof_events(parsed_trace, diagnosis),
            obligation=obligation,
        )

    real_result = _infer_with_proof_analysis(parsed_log, parsed_trace, diagnosis)
    if real_result is not None:
        obligation, lifecycle = real_result
        return _FallbackProofResult(
            proof_status=getattr(lifecycle, "status", None) or diagnosis.proof_status,
            proof_events=list(getattr(lifecycle, "events", None) or []),
            obligation=obligation,
        )

    return _FallbackProofResult(
        proof_status=diagnosis.proof_status,
        proof_events=_synthesize_proof_events(parsed_trace, diagnosis),
        obligation=None,
    )


def _infer_with_proof_analysis(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> tuple[ProofObligation, Any] | ProofObligation | None:
    if analyze_proof_lifecycle is not None and infer_obligation is not None:
        error_instruction = _find_instruction(parsed_trace.instructions, diagnosis.symptom_insn)
        error_register = ""
        if parsed_trace.causal_chain is not None:
            error_register = parsed_trace.causal_chain.error_register
        if not error_register:
            error_register = _register_from_error(parsed_trace.error_line or parsed_log.error_line) or ""

        try:
            obligation = infer_obligation(
                parsed_trace.error_line or parsed_log.error_line or "",
                error_register,
                error_instruction,
            )
            if obligation is not None:
                if diagnosis.taxonomy_class == "source_bug" and diagnosis.proof_status == "never_established":
                    return obligation
                lifecycle = analyze_proof_lifecycle(
                    parsed_trace=parsed_trace,
                    obligation=obligation,
                    backtrack_chains=parsed_trace.backtrack_chains,
                    error_insn=diagnosis.symptom_insn,
                )
                return obligation, lifecycle
        except Exception:
            pass

    return None


def _synthesize_proof_events(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> list[ProofEvent]:
    events: list[ProofEvent] = []
    symptom_instruction = _find_instruction(parsed_trace.instructions, diagnosis.symptom_insn)
    rejected_event = _build_rejected_event(parsed_trace, diagnosis, symptom_instruction)

    if diagnosis.proof_status in {"established_then_lost", "established_but_insufficient"}:
        established_event = _find_established_event(parsed_trace, diagnosis, symptom_instruction)
        if established_event is not None:
            events.append(established_event)

    if diagnosis.proof_status == "established_then_lost":
        lost_event = _build_lost_event(parsed_trace, diagnosis)
        if lost_event is not None:
            events.append(lost_event)

    if diagnosis.proof_status == "never_established" and parsed_trace.causal_chain is not None:
        propagated = _build_causal_context_event(parsed_trace.causal_chain)
        if propagated is not None:
            events.append(propagated)

    if rejected_event is not None:
        events.append(rejected_event)

    deduped: list[ProofEvent] = []
    seen: set[tuple[str, int, str | None]] = set()
    for event in sorted(events, key=lambda item: (item.insn_idx, item.event_type)):
        key = (event.event_type, event.insn_idx, event.register)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _build_rejected_event(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
    symptom_instruction: TracedInstruction | None,
) -> ProofEvent | None:
    if symptom_instruction is None or diagnosis.symptom_insn is None:
        return None

    register = None
    if parsed_trace.causal_chain is not None:
        register = parsed_trace.causal_chain.error_register
    if register is None:
        register = _parse_dst_register(symptom_instruction.bytecode)
    if register is None:
        register = _register_from_error(symptom_instruction.error_text)

    before = symptom_instruction.pre_state.get(register) if register else None
    after = symptom_instruction.post_state.get(register) if register else None
    return _make_proof_event(
        insn_idx=diagnosis.symptom_insn,
        event_type="rejected",
        register=register or "R0",
        before=before,
        after=after,
        source_line=symptom_instruction.source_line,
        description=symptom_instruction.error_text or "verifier rejected the access",
    )


def _find_established_event(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
    symptom_instruction: TracedInstruction | None,
) -> ProofEvent | None:
    anchor = diagnosis.root_cause_insn or diagnosis.symptom_insn
    if anchor is None:
        return None

    candidate_registers = _candidate_pointer_registers(symptom_instruction)
    if not candidate_registers and parsed_trace.causal_chain is not None:
        candidate_registers.append(parsed_trace.causal_chain.error_register)

    prior_instructions = [
        instruction
        for instruction in parsed_trace.instructions
        if instruction.insn_idx < anchor
    ]

    for instruction in reversed(prior_instructions):
        if not _looks_like_guard(instruction):
            continue
        for register in candidate_registers:
            state = instruction.post_state.get(register) or instruction.pre_state.get(register)
            if state is None or not _looks_like_established_proof(state):
                continue
            return _make_proof_event(
                insn_idx=instruction.insn_idx,
                event_type="proof_established",
                register=register,
                before=instruction.pre_state.get(register),
                after=instruction.post_state.get(register) or state,
                source_line=instruction.source_line,
                description=f"{register} carries a usable verifier proof at insn {instruction.insn_idx}.",
            )

    for instruction in reversed(prior_instructions):
        for register in candidate_registers:
            state = instruction.post_state.get(register) or instruction.pre_state.get(register)
            if state is None or not _looks_like_established_proof(state):
                continue
            return _make_proof_event(
                insn_idx=instruction.insn_idx,
                event_type="proof_established",
                register=register,
                before=instruction.pre_state.get(register),
                after=instruction.post_state.get(register) or state,
                source_line=instruction.source_line,
                description=f"{register} carries a usable verifier proof at insn {instruction.insn_idx}.",
            )
    return None


def _build_lost_event(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> ProofEvent | None:
    if not diagnosis.critical_transitions:
        return None

    symptom_register = parsed_trace.causal_chain.error_register if parsed_trace.causal_chain else None
    relevant = list(diagnosis.critical_transitions)
    if diagnosis.symptom_insn is not None:
        relevant = [
            transition for transition in relevant if transition.insn_idx <= diagnosis.symptom_insn
        ]
    if symptom_register and any(t.register == symptom_register for t in relevant):
        relevant = [t for t in relevant if t.register == symptom_register]

    if not relevant:
        return None

    transition = max(relevant, key=_loss_transition_score)
    instruction = _find_instruction(parsed_trace.instructions, transition.insn_idx)
    return _make_proof_event(
        insn_idx=transition.insn_idx,
        event_type="proof_lost",
        register=transition.register,
        before=transition.before,
        after=transition.after,
        source_line=instruction.source_line if instruction is not None else None,
        description=_transition_reason(parsed_trace, transition) or transition.description,
    )


def _build_causal_context_event(causal_chain: BacktrackChain) -> ProofEvent | None:
    chain = getattr(causal_chain, "chain", None) or []
    for link in chain:
        if getattr(link, "role", None) == "error_site":
            continue
        state = getattr(link, "state", None)
        return _make_proof_event(
            insn_idx=getattr(link, "insn_idx"),
            event_type="proof_propagated",
            register=getattr(link, "register", None) or "R0",
            before=None,
            after=state if isinstance(state, RegisterState) else None,
            source_line=None,
            description=getattr(link, "description", None) or "state propagated to the reject site",
        )
    return None


def _loss_transition_score(transition: CriticalTransition) -> tuple[int, int, int]:
    after_unbounded = 1 if _is_unbounded(transition.after) else 0
    priority = TRANSITION_PRIORITY.get(transition.transition_type, -1)
    return after_unbounded, priority, transition.insn_idx


def _transition_reason(
    parsed_trace: ParsedTrace,
    transition: CriticalTransition,
) -> str | None:
    instruction = _find_instruction(parsed_trace.instructions, transition.insn_idx)
    if instruction is None:
        return None
    text = instruction.bytecode.lower()
    if "|=" in text:
        return "OR operation destroys bounds"
    if any(token in text for token in ("<<=", ">>=", " s>>=", "be16", "be32")):
        return "shift or endian transform widens scalar bounds"
    if text.startswith("call "):
        return "helper boundary loses pointer provenance"
    if "(r10" in text:
        return "spill or reload loses pointer provenance"
    if transition.transition_type == "RANGE_LOSS":
        return "pointer arithmetic lost the earlier packet range proof"
    if transition.transition_type == "PROVENANCE_LOSS":
        return "lowering degraded the pointer to a scalar"
    if transition.transition_type == "TYPE_DOWNGRADE":
        return "verifier-visible pointer type was downgraded"
    return "verifier-visible proof was lost"


def _infer_obligation(parsed_log: ParsedLog, diagnosis: Diagnosis) -> ProofObligation | None:
    catalog_path = Path(__file__).resolve().parents[2] / "taxonomy" / "obligation_catalog.yaml"
    try:
        templates = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except OSError:
        templates = {}

    error_id = diagnosis.error_id or parsed_log.error_id
    for template in templates.get("templates", []):
        if error_id and error_id in template.get("related_error_ids", []):
            detail = OBLIGATION_DETAILS.get(template["obligation_id"])
            if detail is not None:
                obligation_type, required = detail
                if "packet" in (parsed_log.error_line or "").lower():
                    obligation_type, required = OBLIGATION_DETAILS["OBLIGE-O001"]
                return _make_proof_obligation(obligation_type, required)

    error_text = (parsed_log.error_line or "").lower()
    if "mem_or_null" in error_text or "or_null" in error_text or "null" in error_text:
        detail = OBLIGATION_DETAILS["OBLIGE-O002"]
        return _make_proof_obligation(detail[0], detail[1])
    if "packet" in error_text or "pkt pointer" in error_text:
        detail = OBLIGATION_DETAILS["OBLIGE-O001"]
        return _make_proof_obligation(detail[0], detail[1])
    if diagnosis.taxonomy_class == "lowering_artifact":
        detail = OBLIGATION_DETAILS["OBLIGE-O005"]
        return _make_proof_obligation(detail[0], detail[1])
    return None


def _build_note(diagnosis: Diagnosis, obligation: ProofObligation | None) -> str | None:
    if diagnosis.taxonomy_class == "lowering_artifact":
        if diagnosis.loss_context == "arithmetic":
            return "A verifier-visible proof existed earlier, but arithmetic lowering widened the offset before the rejected access."
        if diagnosis.loss_context == "function_boundary":
            return "A proof existed earlier, but a helper or function boundary erased the verifier-tracked provenance."
        if diagnosis.loss_context == "register_spill":
            return "A proof existed earlier, but spill and reload lowered the pointer into a verifier-hostile form."
        if diagnosis.proof_status == "established_then_lost":
            return "A verifier-visible proof existed earlier but was lost before the rejected instruction."

    if diagnosis.error_id == "OBLIGE-E002":
        return "The dereference happens while the pointer is still nullable on this control-flow path."

    if obligation is not None and diagnosis.proof_status == "never_established":
        obligation_type = _obligation_type(obligation)
        return f"The required {obligation_type.replace('_', ' ')} proof was never established."

    for line in diagnosis.evidence:
        if line.startswith("Proof existed earlier") or line.startswith("No earlier"):
            return line
    return None


def _build_help_text(parsed_log: ParsedLog, diagnosis: Diagnosis) -> str | None:
    if diagnosis.recommended_fix:
        return diagnosis.recommended_fix

    catalog_path = Path(__file__).resolve().parents[2] / "taxonomy" / "obligation_catalog.yaml"
    try:
        templates = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except OSError:
        return None

    error_id = diagnosis.error_id or parsed_log.error_id
    for template in templates.get("templates", []):
        if error_id and error_id in template.get("related_error_ids", []):
            hints = template.get("repair_hints") or []
            if hints:
                return hints[0]
    return None


def _find_instruction(
    instructions: list[TracedInstruction],
    insn_idx: int | None,
) -> TracedInstruction | None:
    if insn_idx is None:
        return None
    for instruction in instructions:
        if instruction.insn_idx == insn_idx:
            return instruction
    return None


def _candidate_pointer_registers(
    symptom_instruction: TracedInstruction | None,
) -> list[str]:
    if symptom_instruction is None:
        return []

    candidates: list[str] = []
    dst_register = _parse_dst_register(symptom_instruction.bytecode)
    if dst_register is not None:
        candidates.append(dst_register)

    for register, state in symptom_instruction.pre_state.items():
        if _looks_like_established_proof(state) and register not in candidates:
            candidates.append(register)
    return candidates


def _parse_dst_register(bytecode: str) -> str | None:
    match = re.match(r"^\s*(?P<dst>r\d+)\s*(?:=|\+=|-=|\*=|/=|<<=|>>=|&=|\|=|\^=)", bytecode)
    if not match:
        return None
    return match.group("dst").upper()


def _register_from_error(error_text: str | None) -> str | None:
    if not error_text:
        return None
    match = re.search(r"\b(R\d+)\b", error_text)
    return match.group(1) if match else None


def _looks_like_guard(instruction: TracedInstruction) -> bool:
    if instruction.bytecode.startswith("if "):
        return True
    source_line = instruction.source_line or ""
    return any(token in source_line for token in ("if (", "<=", ">=", "==", "!=", "<", ">"))


def _looks_like_established_proof(state: RegisterState) -> bool:
    if state.range is not None and state.range > 0:
        return True
    return any(value is not None for value in (state.umin, state.umax)) and not _is_unbounded(state)


def _is_unbounded(state: RegisterState) -> bool:
    return all(
        value is None for value in (state.umin, state.umax, state.smin, state.smax, state.var_off)
    )


def _make_proof_event(
    *,
    insn_idx: int,
    event_type: str,
    register: str,
    before: RegisterState | None,
    after: RegisterState | None,
    source_line: str | None,
    description: str,
) -> ProofEvent:
    try:
        return ProofEvent(
            insn_idx=insn_idx,
            event_type=event_type,
            register=register,
            state_before=before,
            state_after=after,
            source_line=source_line,
            description=description,
        )
    except TypeError:
        return ProofEvent(
            event_type=event_type,
            insn_idx=insn_idx,
            register=register,
            before=before,
            after=after,
            reason=description,
        )


def _make_proof_obligation(obligation_type: str, required: str) -> ProofObligation:
    try:
        return ProofObligation(
            obligation_type=obligation_type,
            register="R0",
            required_condition=required,
            description=required,
        )
    except TypeError:
        return ProofObligation(type=obligation_type, required=required)


def _obligation_type(obligation: ProofObligation) -> str:
    return getattr(obligation, "type", None) or getattr(obligation, "obligation_type", "unknown")
