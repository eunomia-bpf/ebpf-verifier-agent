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
    SourceSpan,
    correlate_to_source,
)
from .proof_engine import (
    ObligationSpec as _EngineObligationSpec,
    ProofAnalysisResult as _EngineResult,
    analyze_proof as _analyze_proof_engine,
    infer_obligation as _infer_engine_obligation_spec,
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
SPAN_IMPORTANCE = {
    "proof_propagated": 0,
    "proof_established": 2,
    "proof_lost": 3,
    "rejected": 4,
}
REGISTER_TYPE_EXPECTED_RE = re.compile(
    r"(?P<register>R\d+)\s+type=(?P<actual>[^,\s]+)\s+expected=(?P<expected>.+)",
    re.IGNORECASE,
)
ARG_POINTER_CONTRACT_RE = re.compile(
    r"arg#(?P<arg_index>\d+)\s+pointer type\s+(?P<actual>.+?)\s+must point to\s+(?P<expected>.+)",
    re.IGNORECASE,
)
ARG_EXPECTED_CONTRACT_RE = re.compile(
    r"arg#(?P<arg_index>\d+)\s+expected\s+(?P<expected>.+)",
    re.IGNORECASE,
)
CALL_TARGET_RE = re.compile(r"\bcall\s+(?P<target>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)\b")
NULL_ARG_RE = re.compile(
    r"Possibly NULL pointer passed to (?P<target>helper|trusted) arg(?P<arg_index>\d+)",
    re.IGNORECASE,
)
ITERATOR_PROTOCOL_RE = re.compile(
    r"expected\s+(?P<state>an initialized|uninitialized)\s+(?P<iter_type>[a-zA-Z0-9_]+)\s+as arg\s*#(?P<arg_index>\d+)",
    re.IGNORECASE,
)
DYNPTR_INITIALIZED_RE = re.compile(
    r"expected an initialized dynptr as arg\s*#(?P<arg_index>\d+)",
    re.IGNORECASE,
)
UNACQUIRED_REFERENCE_RE = re.compile(
    r"arg\s+(?P<arg_index>\d+)\s+is an unacquired reference",
    re.IGNORECASE,
)
HELPER_UNAVAILABLE_RE = re.compile(
    r"program of this type cannot use helper\s+(?P<helper>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)",
    re.IGNORECASE,
)
UNKNOWN_FUNC_RE = re.compile(
    r"unknown func\s+(?P<helper>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)",
    re.IGNORECASE,
)
RAW_CALLBACK_CONTEXT_RE = re.compile(
    r"cannot (?:call|be called).*\bfrom callback",
    re.IGNORECASE,
)
REFERENCE_LEAK_RE = re.compile(r"(?:reference leak|unreleased reference)", re.IGNORECASE)
TYPE_LABELS = {
    "fp": "a stack pointer",
    "inv": "an untyped scalar value",
    "scalar": "a scalar value",
    "struct with scalar": "a struct with scalar fields",
    "map_ptr": "a map pointer",
    "map_value": "a map-value pointer",
    "map_key": "a map-key pointer",
    "pkt": "a packet pointer",
    "pkt_meta": "a packet-metadata pointer",
    "ptr": "a generic pointer",
    "ptr_": "a typed pointer",
    "pointer to stack": "a stack pointer",
    "const struct bpf_dynptr": "a const struct bpf_dynptr",
    "trusted_ptr_": "a trusted pointer",
    "rcu_ptr_": "an RCU-protected pointer",
    "ctx": "a context pointer",
    "unknown": "UNKNOWN data",
}


@dataclass(slots=True)
class _FallbackProofResult:
    proof_status: str | None
    proof_events: list[ProofEvent] = field(default_factory=list)
    obligation: ProofObligation | None = None


@dataclass(slots=True)
class _SpecificContractMismatch:
    raw: str
    register: str | None = None
    arg_index: int | None = None
    actual: str | None = None
    expected_text: str = ""
    expected_tokens: tuple[str, ...] = ()


@dataclass(slots=True)
class _SpecificRejectInfo:
    raw: str
    kind: str
    note: str | None = None
    help_text: str | None = None
    obligation_type: str | None = None
    obligation_required: str | None = None


def generate_diagnostic(verifier_log: str, catalog_path: str | None = None) -> DiagnosticOutput:
    """Run the full parser → proof summary → source correlation → renderer pipeline."""

    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)
    parsed_trace = parse_trace(verifier_log)
    diagnosis = diagnose(verifier_log, catalog_path=catalog_path)
    proof_result = _analyze_proof(parsed_log, parsed_trace, diagnosis)

    proof_status = proof_result.proof_status or diagnosis.proof_status or "unknown"
    obligation = (
        proof_result.obligation
        or _infer_obligation_from_engine(parsed_log, parsed_trace, diagnosis)
        or _infer_obligation(parsed_log, diagnosis)
    )
    specific_reject = _extract_specific_reject_info(parsed_log)
    obligation = _refine_obligation_with_specific_reject(obligation, specific_reject)
    spans = correlate_to_source(parsed_trace, proof_result.proof_events)
    spans = _normalize_spans(
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        diagnosis=diagnosis,
        proof_status=proof_status,
        spans=spans,
    )
    note = _build_note(parsed_log, diagnosis, obligation, proof_status, specific_reject)
    help_text = _build_help_text(parsed_log, diagnosis, obligation, proof_status, specific_reject)

    return render_diagnostic(
        error_id=diagnosis.error_id or parsed_log.error_id or "OBLIGE-UNKNOWN",
        taxonomy_class=diagnosis.taxonomy_class or parsed_log.taxonomy_class or "unknown",
        proof_status=proof_status,
        spans=spans,
        obligation=obligation,
        note=note,
        help_text=help_text,
        confidence=diagnosis.confidence,
        diagnosis_evidence=diagnosis.evidence,
        raw_log_excerpt=(specific_reject.raw if specific_reject is not None else parsed_log.error_line)
        or None,
    )


def _analyze_proof(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> _FallbackProofResult:
    engine_result = _try_proof_engine(parsed_log, parsed_trace, diagnosis)
    engine_obligation = engine_result.obligation if engine_result is not None else None
    if engine_result is not None and not _should_ignore_engine_result(engine_result, diagnosis):
        return engine_result

    if diagnosis.taxonomy_class == "source_bug" and diagnosis.proof_status == "never_established":
        obligation = _infer_with_proof_analysis(parsed_log, parsed_trace, diagnosis) or engine_obligation
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
            obligation=obligation or engine_obligation,
        )

    return _FallbackProofResult(
        proof_status=diagnosis.proof_status,
        proof_events=_synthesize_proof_events(parsed_trace, diagnosis),
        obligation=engine_obligation,
    )


def _should_ignore_engine_result(
    result: _FallbackProofResult,
    diagnosis: Diagnosis,
) -> bool:
    if result.proof_status != "unknown":
        return False
    if diagnosis.proof_status in {None, "unknown"}:
        return False
    return not any(event.event_type != "rejected" for event in result.proof_events)


def _try_proof_engine(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> _FallbackProofResult | None:
    try:
        error_line = parsed_trace.error_line or parsed_log.error_line or ""
        error_insn = diagnosis.symptom_insn
        result = _analyze_proof_engine(parsed_trace, error_line, error_insn)

        events = _engine_result_to_events(result, parsed_trace)
        obligation = _engine_obligation_to_proof_obligation(result)
        if obligation is None:
            obligation = _infer_obligation_from_engine(parsed_log, parsed_trace, diagnosis)
        if obligation is None and result.proof_status == "unknown":
            return None
        proof_status = result.proof_status
        if (
            proof_status == "never_established"
            and result.obligation is not None
            and result.obligation.kind == "helper_arg"
        ):
            specific_contract = _extract_specific_contract_mismatch(error_line)
            if specific_contract is not None:
                obligation = _make_proof_obligation("helper_arg", specific_contract.raw)

        return _FallbackProofResult(
            proof_status=proof_status,
            proof_events=events,
            obligation=obligation,
        )
    except Exception:
        return None


def _engine_result_to_events(
    result: _EngineResult,
    parsed_trace: ParsedTrace,
) -> list[ProofEvent]:
    events: list[ProofEvent] = []

    if result.establish_site is not None:
        insn = _find_instruction(parsed_trace.instructions, result.establish_site)
        reg = result.obligation.base_reg if result.obligation else "R0"
        before_state = insn.pre_state.get(reg) if insn and reg else None
        after_state = insn.post_state.get(reg) if insn and reg else None
        events.append(
            _make_proof_event(
                insn_idx=result.establish_site,
                event_type="proof_established",
                register=reg or "R0",
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=f"Proof obligation satisfied at insn {result.establish_site}",
            )
        )

    if result.loss_site is not None and result.transition is not None:
        insn = _find_instruction(parsed_trace.instructions, result.loss_site)
        transition_atom = None
        if result.obligation is not None:
            transition_atom = next(
                (
                    atom
                    for atom in result.obligation.atoms
                    if atom.atom_id == result.transition.atom_id
                ),
                None,
            )
        reg = "R0"
        if transition_atom is not None and transition_atom.registers:
            reg = transition_atom.registers[0]
        elif result.transition.carrier_register:
            reg = result.transition.carrier_register
        before_state = insn.pre_state.get(reg) if insn and reg else None
        after_state = insn.post_state.get(reg) if insn and reg else None
        reason = (
            f"{transition_atom.atom_id}: {transition_atom.expression}"
            if transition_atom is not None
            else f"{result.transition.atom_id}: {result.transition.witness}"
        )
        events.append(
            _make_proof_event(
                insn_idx=result.loss_site,
                event_type="proof_lost",
                register=reg,
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=reason,
            )
        )

    if result.reject_site is not None:
        insn = _find_instruction(parsed_trace.instructions, result.reject_site)
        reg = result.obligation.base_reg if result.obligation else "R0"
        before_state = insn.pre_state.get(reg) if insn and reg else None
        after_state = insn.post_state.get(reg) if insn and reg else None
        error_text = insn.error_text if insn else "verifier rejected"
        events.append(
            _make_proof_event(
                insn_idx=result.reject_site,
                event_type="rejected",
                register=reg or "R0",
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=error_text or "verifier rejected the access",
            )
        )

    return events


def _engine_obligation_spec_to_proof_obligation(
    spec: _EngineObligationSpec | None,
) -> ProofObligation | None:
    if spec is None:
        return None
    obligation_type = "packet_access" if spec.kind == "packet_ptr_add" else spec.kind
    atoms_desc = "; ".join(a.expression for a in spec.atoms)
    return _make_proof_obligation(obligation_type, atoms_desc or obligation_type)


def _engine_obligation_to_proof_obligation(result: _EngineResult) -> ProofObligation | None:
    return _engine_obligation_spec_to_proof_obligation(result.obligation)


def _infer_obligation_from_engine(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> ProofObligation | None:
    error_line = parsed_trace.error_line or parsed_log.error_line or ""
    if not error_line:
        return None
    try:
        spec = _infer_engine_obligation_spec(parsed_trace, error_line, diagnosis.symptom_insn)
    except Exception:
        return None
    return _engine_obligation_spec_to_proof_obligation(spec)


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
    for transition in diagnosis.critical_transitions:
        if transition.register not in candidate_registers:
            candidate_registers.append(transition.register)

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
    transition = _select_loss_transition(parsed_trace, diagnosis)
    if transition is None:
        return None

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


def _normalize_spans(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
    proof_status: str,
    spans: list[SourceSpan],
) -> list[SourceSpan]:
    normalized = _dedupe_spans(_merge_adjacent_propagated_spans(spans))
    normalized = _ensure_minimum_role_coverage(
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        diagnosis=diagnosis,
        proof_status=proof_status,
        spans=normalized,
    )
    normalized = _dedupe_spans(_merge_adjacent_propagated_spans(normalized))
    return _prune_spans(normalized, proof_status)


def _ensure_minimum_role_coverage(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
    proof_status: str,
    spans: list[SourceSpan],
) -> list[SourceSpan]:
    augmented = list(spans)
    synthesized_events: list[ProofEvent] = []

    if not _has_span_role(augmented, "rejected"):
        rejected_event = _build_minimum_rejected_event(parsed_trace, diagnosis)
        if rejected_event is not None:
            synthesized_events.append(rejected_event)

    if proof_status == "established_then_lost":
        if not _has_span_role(augmented, "proof_established"):
            established_event = _synthesize_established_event_from_transition(
                parsed_trace,
                diagnosis,
            )
            if established_event is not None:
                synthesized_events.append(established_event)
        if not _has_span_role(augmented, "proof_lost"):
            lost_event = _build_lost_event(parsed_trace, diagnosis)
            if lost_event is not None:
                synthesized_events.append(lost_event)
    elif proof_status == "established_but_insufficient" and not _has_span_role(
        augmented,
        "proof_established",
    ):
        established_event = _synthesize_established_event_from_transition(
            parsed_trace,
            diagnosis,
        )
        if established_event is not None:
            synthesized_events.append(established_event)

    if synthesized_events:
        augmented.extend(correlate_to_source(parsed_trace, synthesized_events))
        augmented = _dedupe_spans(augmented)

    if not augmented:
        augmented.append(_build_placeholder_rejected_span(parsed_log, parsed_trace, diagnosis))
        return augmented

    if not _has_span_role(augmented, "rejected"):
        augmented.append(_build_placeholder_rejected_span(parsed_log, parsed_trace, diagnosis))

    return augmented


def _merge_adjacent_propagated_spans(spans: list[SourceSpan]) -> list[SourceSpan]:
    if not spans:
        return []

    ordered = sorted(spans, key=_span_sort_key)
    merged: list[SourceSpan] = [ordered[0]]

    for span in ordered[1:]:
        previous = merged[-1]
        if (
            previous.role == "proof_propagated"
            and span.role == "proof_propagated"
            and previous.file == span.file
            and previous.line == span.line
            and previous.source_text == span.source_text
        ):
            merged[-1] = SourceSpan(
                file=previous.file,
                line=previous.line,
                source_text=previous.source_text,
                insn_range=(
                    min(previous.insn_range[0], span.insn_range[0]),
                    max(previous.insn_range[1], span.insn_range[1]),
                ),
                role=previous.role,
                register=previous.register or span.register,
                state_change=previous.state_change or span.state_change,
                reason=previous.reason or span.reason,
            )
            continue
        merged.append(span)

    return merged


def _dedupe_spans(spans: list[SourceSpan]) -> list[SourceSpan]:
    deduped_by_key: dict[
        tuple[str | None, int | None, str, tuple[int, int], str],
        SourceSpan,
    ] = {}
    order: list[tuple[str | None, int | None, str, tuple[int, int], str]] = []
    for span in sorted(spans, key=_span_sort_key):
        key = (
            span.file,
            span.line,
            span.source_text,
            span.insn_range,
            span.role,
        )
        existing = deduped_by_key.get(key)
        if existing is None:
            deduped_by_key[key] = span
            order.append(key)
            continue
        deduped_by_key[key] = SourceSpan(
            file=existing.file,
            line=existing.line,
            source_text=existing.source_text,
            insn_range=existing.insn_range,
            role=existing.role,
            register=existing.register or span.register,
            state_change=existing.state_change or span.state_change,
            reason=existing.reason or span.reason,
        )
    return [deduped_by_key[key] for key in order]


def _prune_spans(spans: list[SourceSpan], proof_status: str) -> list[SourceSpan]:
    ordered = sorted(spans, key=_span_sort_key)
    if len(ordered) <= 5:
        return ordered

    keep: list[SourceSpan] = []
    if proof_status in {"established_then_lost", "established_but_insufficient"}:
        _append_first_matching(keep, ordered, lambda span: span.role == "proof_established")
    if proof_status == "established_then_lost":
        _append_last_matching(keep, ordered, lambda span: span.role == "proof_lost")
    _append_last_matching(keep, ordered, lambda span: span.role == "rejected")

    candidates = [span for span in ordered if span not in keep]
    non_propagated = [span for span in candidates if span.role != "proof_propagated"]
    non_propagated.sort(key=_span_priority_key, reverse=True)
    for span in non_propagated:
        if len(keep) >= 5:
            break
        keep.append(span)

    if len(keep) < 5:
        propagated = [span for span in candidates if span.role == "proof_propagated"]
        propagated.sort(key=_span_priority_key, reverse=True)
        for span in propagated:
            if len(keep) >= 5:
                break
            keep.append(span)

    return sorted(_dedupe_spans(keep), key=_span_sort_key)


def _append_first_matching(
    keep: list[SourceSpan],
    spans: list[SourceSpan],
    predicate: Any,
) -> None:
    for span in spans:
        if predicate(span) and span not in keep:
            keep.append(span)
            return


def _append_last_matching(
    keep: list[SourceSpan],
    spans: list[SourceSpan],
    predicate: Any,
) -> None:
    for span in reversed(spans):
        if predicate(span) and span not in keep:
            keep.append(span)
            return


def _span_sort_key(span: SourceSpan) -> tuple[int, int, int]:
    return (span.insn_range[0], span.insn_range[1], SPAN_IMPORTANCE.get(span.role, -1))


def _span_priority_key(span: SourceSpan) -> tuple[int, int, int, int]:
    return (
        SPAN_IMPORTANCE.get(span.role, -1),
        1 if span.reason else 0,
        1 if span.file and span.line is not None else 0,
        -span.insn_range[0],
    )


def _has_span_role(spans: list[SourceSpan], role: str) -> bool:
    return any(span.role == role for span in spans)


def _build_minimum_rejected_event(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> ProofEvent | None:
    symptom_instruction = _find_rejected_instruction(parsed_trace, diagnosis)
    if symptom_instruction is None:
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
        insn_idx=symptom_instruction.insn_idx,
        event_type="rejected",
        register=register or "R0",
        before=before,
        after=after,
        source_line=symptom_instruction.source_line,
        description=symptom_instruction.error_text
        or parsed_trace.error_line
        or "verifier rejected the access",
    )


def _build_placeholder_rejected_span(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> SourceSpan:
    fallback_instruction = _find_rejected_instruction(parsed_trace, diagnosis)
    insn_idx = fallback_instruction.insn_idx if fallback_instruction is not None else (
        diagnosis.symptom_insn or 0
    )
    source_text = (
        parsed_trace.error_line
        or parsed_log.error_line
        or (diagnosis.evidence[0] if diagnosis.evidence else None)
        or "verifier rejected the program"
    )
    return SourceSpan(
        file=None,
        line=None,
        source_text=source_text.splitlines()[0],
        insn_range=(insn_idx, insn_idx),
        role="rejected",
        register=None,
        state_change=None,
        reason=None,
    )


def _find_rejected_instruction(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> TracedInstruction | None:
    symptom_instruction = _find_instruction(parsed_trace.instructions, diagnosis.symptom_insn)
    if symptom_instruction is not None:
        return symptom_instruction
    for instruction in reversed(parsed_trace.instructions):
        if instruction.is_error:
            return instruction
    return parsed_trace.instructions[-1] if parsed_trace.instructions else None


def _relevant_transitions(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> list[CriticalTransition]:
    if not diagnosis.critical_transitions:
        return []

    symptom_register = parsed_trace.causal_chain.error_register if parsed_trace.causal_chain else None
    relevant = list(diagnosis.critical_transitions)
    if diagnosis.symptom_insn is not None:
        relevant = [
            transition for transition in relevant if transition.insn_idx <= diagnosis.symptom_insn
        ]
    if symptom_register and any(t.register == symptom_register for t in relevant):
        relevant = [t for t in relevant if t.register == symptom_register]
    return relevant


def _select_loss_transition(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> CriticalTransition | None:
    relevant = _relevant_transitions(parsed_trace, diagnosis)
    if not relevant:
        return None
    return max(relevant, key=_loss_transition_score)


def _synthesize_established_event_from_transition(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> ProofEvent | None:
    transition = _select_establish_transition(parsed_trace, diagnosis)
    if transition is None:
        return None

    instruction = _find_instruction(parsed_trace.instructions, transition.insn_idx)
    return _make_proof_event(
        insn_idx=transition.insn_idx,
        event_type="proof_established",
        register=transition.register,
        before=None,
        after=transition.before,
        source_line=instruction.source_line if instruction is not None else None,
        description=(
            f"{transition.register} carried a verifier-visible proof before it was lost "
            f"at insn {transition.insn_idx}."
        ),
    )


def _select_establish_transition(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> CriticalTransition | None:
    relevant = _relevant_transitions(parsed_trace, diagnosis)
    if not relevant:
        return None

    loss_transition = _select_loss_transition(parsed_trace, diagnosis)
    if loss_transition is not None:
        same_register = [
            transition
            for transition in relevant
            if transition.register == loss_transition.register
            and transition.insn_idx <= loss_transition.insn_idx
        ]
        if same_register:
            relevant = same_register

    proof_like = [
        transition for transition in relevant if _transition_before_looks_like_proof(transition)
    ]
    if proof_like:
        return min(proof_like, key=lambda transition: transition.insn_idx)
    if loss_transition is not None:
        return loss_transition
    return min(relevant, key=lambda transition: transition.insn_idx)


def _transition_before_looks_like_proof(transition: CriticalTransition) -> bool:
    before = transition.before
    if _looks_like_established_proof(before):
        return True
    lowered = before.type.lower()
    return lowered not in {"scalar", "inv", "invp", "unknown"}


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


def _extract_specific_reject_info(parsed_log: ParsedLog) -> _SpecificRejectInfo | None:
    surface_line = _select_specific_verifier_line(parsed_log)
    if not surface_line:
        return None

    specific_contract = _extract_specific_contract_mismatch(surface_line)
    if specific_contract is not None:
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="helper_arg",
            note=_specific_contract_note(specific_contract),
            help_text=_specific_contract_help(parsed_log, specific_contract),
            obligation_type="helper_arg",
            obligation_required=specific_contract.raw,
        )

    for builder in (
        _specific_null_reject_info,
        _specific_iterator_reject_info,
        _specific_dynptr_reject_info,
        _specific_execution_context_reject_info,
        _specific_reference_leak_reject_info,
        _specific_env_helper_reject_info,
    ):
        result = builder(parsed_log, surface_line)
        if result is not None:
            return result

    if surface_line != (parsed_log.error_line or ""):
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="verifier_reject",
            note=f"Verifier reject line: {surface_line}",
        )
    return None


def _select_specific_verifier_line(parsed_log: ParsedLog) -> str | None:
    best_line = _normalize_verifier_line(parsed_log.error_line)
    best_score = _specific_reject_line_score(best_line)

    for line in parsed_log.lines:
        candidate = _normalize_verifier_line(line)
        if not candidate:
            continue
        score = _specific_reject_line_score(candidate)
        if score > best_score or (score == best_score and score > 0 and candidate != best_line):
            best_line = candidate
            best_score = score

    return best_line or None


def _normalize_verifier_line(line: str | None) -> str:
    if not line:
        return ""
    normalized = " ".join(line.strip().split())
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    if not normalized or normalized.startswith(";"):
        return ""
    if re.match(r"^\d+:\s+\([0-9a-f]{2}\)", normalized, flags=re.IGNORECASE):
        return ""
    return normalized


def _specific_reject_line_score(line: str) -> int:
    if not line:
        return -1

    lowered = line.lower()
    if _extract_specific_contract_mismatch(line) is not None:
        return 100
    if NULL_ARG_RE.search(line):
        return 95
    if ITERATOR_PROTOCOL_RE.search(line):
        return 94
    if DYNPTR_INITIALIZED_RE.search(line):
        return 94
    if (
        "unacquired reference" in lowered
        or "cannot pass in dynptr at an offset" in lowered
        or "dynptr has to be at a constant offset" in lowered
        or "cannot overwrite referenced dynptr" in lowered
    ):
        return 93
    if "function calls are not allowed while holding a lock" in lowered:
        return 92
    if "cannot call exception cb directly" in lowered or RAW_CALLBACK_CONTEXT_RE.search(line):
        return 92
    if REFERENCE_LEAK_RE.search(line):
        return 92
    if HELPER_UNAVAILABLE_RE.search(line):
        return 91
    if UNKNOWN_FUNC_RE.search(line):
        return 90
    if "caller passes invalid args into func" in lowered:
        return 80
    if "reference type('unknown ')" in lowered and "size cannot be determined" in lowered:
        return 5
    if "invalid argument (os error 22)" in lowered:
        return 1
    return 0


def _specific_null_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    match = NULL_ARG_RE.search(surface_line)
    if match is None:
        return None

    arg_index = int(match.group("arg_index"))
    target = match.group("target").lower()
    subject = f"arg{arg_index}"
    call_type = "trusted call site" if target == "trusted" else "helper call"
    obligation_type = "trusted_null_check" if target == "trusted" else "null_check"

    return _SpecificRejectInfo(
        raw=surface_line,
        kind="null_check",
        note=(
            f"The verifier still treats {subject} as nullable at this {call_type}, "
            "so NULL can flow to the callee on one path."
        ),
        help_text=(
            f"Add a dominating null check for the value passed as {subject} and keep the "
            "checked register/value through the call."
        ),
        obligation_type=obligation_type,
        obligation_required=f"{subject} not nullable",
    )


def _specific_iterator_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    match = ITERATOR_PROTOCOL_RE.search(surface_line)
    if match is None:
        return None

    arg_index = int(match.group("arg_index"))
    iter_type = match.group("iter_type")
    helper_target = (_last_helper_target(parsed_log.raw_log) or "").lower()
    needs_initialized = "initialized" in match.group("state").lower()

    if needs_initialized:
        note = (
            f"This call expects an initialized {iter_type} in arg#{arg_index}, "
            "but that iterator slot was never created on this path."
        )
        if "destroy" in helper_target:
            help_text = (
                "Initialize the iterator with the matching create/new helper before destroy, "
                "or avoid destroy on an uninitialized iterator."
            )
        elif "next" in helper_target:
            help_text = (
                "Create the iterator before calling next, and only advance it after successful "
                "initialization."
            )
        else:
            help_text = (
                "Initialize the iterator with the matching create/new helper before this call, "
                "and keep the iterator live until its matching release/destroy."
            )
    else:
        note = (
            f"This call expects an uninitialized {iter_type} in arg#{arg_index}, "
            "but the iterator slot is already live."
        )
        help_text = (
            "Use a fresh iterator slot for creation, or destroy the existing iterator before "
            "reinitializing it."
        )

    return _SpecificRejectInfo(
        raw=surface_line,
        kind="iterator_protocol",
        note=note,
        help_text=help_text,
        obligation_type="iterator_protocol",
        obligation_required=surface_line,
    )


def _specific_dynptr_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    lowered = surface_line.lower()

    match = DYNPTR_INITIALIZED_RE.search(surface_line)
    if match is not None:
        arg_index = int(match.group("arg_index"))
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note=(
                f"This helper expects an initialized dynptr in arg#{arg_index}, "
                "but the dynptr was never successfully created on this path."
            ),
            help_text=(
                "Create the dynptr first and pass the original stack-backed dynptr slot "
                "to the helper."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if "cannot pass in dynptr at an offset" in lowered or "dynptr has to be at a constant offset" in lowered:
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="The verifier requires the dynptr object to stay at its exact stack slot and constant offset.",
            help_text=(
                "Pass the dynptr at its exact stack slot / constant base address, not at a shifted "
                "or forged offset."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if "cannot overwrite referenced dynptr" in lowered:
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="A live slice/reference still depends on this dynptr, so the dynptr cannot be overwritten yet.",
            help_text=(
                "Release or stop using derived slices/references before reinitializing or overwriting "
                "the dynptr."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if UNACQUIRED_REFERENCE_RE.search(surface_line) and "dynptr" in parsed_log.raw_log.lower():
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="This call is using a dynptr reference that has already been released or was never acquired.",
            help_text=(
                "Release or discard the dynptr exactly once and stop using it after submit/discard/release."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    return None


def _specific_execution_context_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    lowered = surface_line.lower()
    if "function calls are not allowed while holding a lock" in lowered:
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="execution_context",
            note="The verifier rejects this call because the program is still holding a lock at the call site.",
            help_text=(
                "Move the subprogram/helper call out of the locked region, or unlock before calling."
            ),
            obligation_type="execution_context",
            obligation_required=surface_line,
        )

    if "cannot call exception cb directly" in lowered or RAW_CALLBACK_CONTEXT_RE.search(surface_line):
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="callback_context",
            note="This callback may only be invoked from the verifier-approved callback context.",
            help_text=(
                "Invoke the callback through its owning helper/iterator framework instead of calling "
                "it directly from program code."
            ),
            obligation_type="exception_callback_context",
            obligation_required=surface_line,
        )

    return None


def _specific_reference_leak_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    if REFERENCE_LEAK_RE.search(surface_line) is None:
        return None

    return _SpecificRejectInfo(
        raw=surface_line,
        kind="reference_leak",
        note="A referenced object remains live at exit on this path.",
        help_text=(
            "Release or destroy the acquired reference on every exit path, including early returns "
            "and callee-return paths."
        ),
        obligation_type="unreleased_reference",
        obligation_required=surface_line,
    )


def _specific_env_helper_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> _SpecificRejectInfo | None:
    match = HELPER_UNAVAILABLE_RE.search(surface_line)
    if match is not None:
        helper = match.group("helper")
        return _SpecificRejectInfo(
            raw=surface_line,
            kind="env_helper",
            note=f"This program type does not permit the helper {helper}#{match.group('helper_id')}.",
            help_text=(
                f"Use a helper allowed in this program type, or move the logic to a program type "
                f"that permits {helper}."
            ),
        )

    match = UNKNOWN_FUNC_RE.search(surface_line)
    if match is None:
        return None

    helper = match.group("helper")
    if helper == "bpf_get_current_pid_tgid":
        help_text = (
            "Read the PID from the program context instead of calling bpf_get_current_pid_tgid "
            "in this program type."
        )
    else:
        help_text = (
            f"Use a supported helper in this program type/kernel, or target an environment that "
            f"provides {helper}."
        )

    return _SpecificRejectInfo(
        raw=surface_line,
        kind="env_helper",
        note=f"The target verifier context does not expose the helper {helper}#{match.group('helper_id')}.",
        help_text=help_text,
    )


def _refine_obligation_with_specific_reject(
    obligation: ProofObligation | None,
    specific_reject: _SpecificRejectInfo | None,
) -> ProofObligation | None:
    if specific_reject is None:
        return obligation
    if specific_reject.obligation_type is None or specific_reject.obligation_required is None:
        return obligation

    if obligation is None:
        return _make_proof_obligation(
            specific_reject.obligation_type,
            specific_reject.obligation_required,
        )

    current_type = _obligation_type(obligation)
    current_required = getattr(obligation, "required_condition", None) or getattr(
        obligation,
        "required",
        None,
    )
    current_required_text = str(current_required or "").lower()
    if current_type in {"unknown", "btf_reference_type"}:
        return _make_proof_obligation(
            specific_reject.obligation_type,
            specific_reject.obligation_required,
        )
    if current_type == "helper_arg" and (
        not current_required
        or "reference type('unknown ')" in current_required_text
        or "type matches" in current_required_text
    ):
        return _make_proof_obligation(
            specific_reject.obligation_type,
            specific_reject.obligation_required,
        )
    return obligation


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
    specific_contract = _extract_specific_contract_mismatch(parsed_log.error_line)
    if specific_contract is not None:
        return _make_proof_obligation("helper_arg", specific_contract.raw)
    return None


def _build_note(
    parsed_log: ParsedLog,
    diagnosis: Diagnosis,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: _SpecificRejectInfo | None = None,
) -> str | None:
    if specific_reject is not None and specific_reject.note:
        return specific_reject.note

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

    specific_contract = _extract_specific_contract_mismatch(parsed_log.error_line)
    if (
        diagnosis.taxonomy_class == "source_bug"
        and specific_contract is not None
        and proof_status in {"never_established", "unknown"}
    ):
        return _specific_contract_note(specific_contract)

    if obligation is not None and proof_status == "never_established":
        obligation_type = _obligation_type(obligation)
        return f"The required {obligation_type.replace('_', ' ')} proof was never established."

    for line in diagnosis.evidence:
        if line.startswith("Proof existed earlier") or line.startswith("No earlier"):
            return line
    return None


def _build_help_text(
    parsed_log: ParsedLog,
    diagnosis: Diagnosis,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: _SpecificRejectInfo | None = None,
) -> str | None:
    if specific_reject is not None and specific_reject.help_text:
        return specific_reject.help_text

    specific_contract = _extract_specific_contract_mismatch(parsed_log.error_line)
    if (
        diagnosis.taxonomy_class == "source_bug"
        and specific_contract is not None
        and (
            proof_status == "never_established"
            or (obligation is not None and _obligation_type(obligation) == "helper_arg")
            or diagnosis.error_id == "OBLIGE-E023"
        )
    ):
        specific_help = _specific_contract_help(parsed_log, specific_contract)
        if specific_help is not None:
            return specific_help

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


def _extract_specific_contract_mismatch(error_line: str | None) -> _SpecificContractMismatch | None:
    if not error_line:
        return None

    raw = " ".join(error_line.strip().split())
    match = REGISTER_TYPE_EXPECTED_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return _SpecificContractMismatch(
            raw=raw,
            register=match.group("register").upper(),
            actual=match.group("actual").strip(),
            expected_text=expected_text,
            expected_tokens=_split_expected_tokens(expected_text),
        )

    match = ARG_POINTER_CONTRACT_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return _SpecificContractMismatch(
            raw=raw,
            arg_index=int(match.group("arg_index")),
            actual=match.group("actual").strip(),
            expected_text=expected_text,
            expected_tokens=_split_expected_tokens(expected_text),
        )

    match = ARG_EXPECTED_CONTRACT_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return _SpecificContractMismatch(
            raw=raw,
            arg_index=int(match.group("arg_index")),
            expected_text=expected_text,
            expected_tokens=_split_expected_tokens(expected_text),
        )

    return None


def _split_expected_tokens(expected_text: str) -> tuple[str, ...]:
    tokens: list[str] = []
    for token in re.split(
        r",\s*(?:or\s+)?|\s+or\s+",
        expected_text.strip(),
        flags=re.IGNORECASE,
    ):
        cleaned = token.strip().strip(".")
        if cleaned:
            tokens.append(cleaned.lower())
    return tuple(tokens)


def _specific_contract_note(contract: _SpecificContractMismatch) -> str:
    subject = contract.register or (
        f"arg#{contract.arg_index}" if contract.arg_index is not None else "this argument"
    )
    expected = _humanize_expected(contract)
    if contract.actual:
        actual = _describe_type_token(contract.actual)
        return f"The verifier sees {subject} as {actual}, but this call requires {expected}."
    return f"This call requires {expected}."


def _specific_contract_help(
    parsed_log: ParsedLog,
    contract: _SpecificContractMismatch,
) -> str | None:
    expected = set(contract.expected_tokens)
    helper_target = _last_helper_target(parsed_log.raw_log)

    if "map_ptr" in expected:
        return (
            "Pass the map object itself as this argument, not a pointer to a map value. "
            "Preserve the loader-generated map reference so the verifier sees map_ptr."
        )

    if "fp" in expected:
        if helper_target == "bpf_map_update_elem" and contract.register == "R2":
            return (
                "Pass a stack-backed key pointer as arg2 instead of NULL or a scalar value. "
                "If this map type has no key, use the map API that matches that map type "
                "instead of bpf_map_update_elem()."
            )
        return "Pass a stack pointer for this argument, not a map, packet, or scalar value."

    lowered_expected = contract.expected_text.lower()
    if "scalar" in expected or "struct with scalar" in lowered_expected:
        return (
            "Pass data whose pointee is scalar-compatible, or change the kfunc signature to "
            "accept the exact BTF-typed object you pass. Casts alone will not satisfy the "
            "verifier-visible contract."
        )

    if "trusted_ptr_" in expected or "trusted" in lowered_expected:
        return (
            "Pass a trusted/BTF-typed object obtained from a verifier-recognized source. "
            "Casts from unrelated pointers will not satisfy this call."
        )

    if "map_value" in expected:
        return "Pass a map-value pointer returned by lookup, not the map object itself."

    if {"pkt", "pkt_meta"} & expected:
        return "Pass a packet pointer for this argument, not a stack, map, or scalar value."

    if "ctx" in expected:
        return "Pass the program context pointer for this argument."

    if "pointer to stack" in lowered_expected and "bpf_dynptr" in lowered_expected:
        return (
            "Pass a stack pointer or a const struct bpf_dynptr for this argument. "
            "Plain scalars or unrelated pointers will not satisfy the contract."
        )

    if contract.expected_text:
        return (
            "Match the verifier-visible call contract from the reject line directly: "
            f"{contract.expected_text}."
        )
    return None


def _last_helper_target(raw_log: str) -> str | None:
    matches = list(CALL_TARGET_RE.finditer(raw_log))
    if not matches:
        return None
    return matches[-1].group("target")


def _humanize_expected(contract: _SpecificContractMismatch) -> str:
    if contract.expected_tokens:
        if len(contract.expected_tokens) == 1:
            return _describe_expected_token(contract.expected_tokens[0])
        options = ", ".join(_describe_expected_token(token) for token in contract.expected_tokens)
        return f"one of: {options}"
    lowered = contract.expected_text.lower()
    if lowered:
        return lowered
    return "a different verifier-visible argument type"


def _describe_type_token(token: str) -> str:
    lowered = token.strip().lower()
    if lowered in TYPE_LABELS:
        return f"{TYPE_LABELS[lowered]} ({token.strip()})"
    return token.strip()


def _describe_expected_token(token: str) -> str:
    lowered = token.strip().lower()
    if lowered in TYPE_LABELS:
        return TYPE_LABELS[lowered]
    return token.strip()
