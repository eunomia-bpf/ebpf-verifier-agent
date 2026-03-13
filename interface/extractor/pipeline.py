"""Rust-style diagnostic orchestration pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .bpftool_parser import parse_bpftool_xlated_linum
from .diagnoser import Diagnosis, diagnose
from .log_parser import ParsedLog, parse_log
from .obligation_refinement import (
    engine_obligation_to_proof_obligation,
    infer_catalog_obligation,
    infer_obligation_from_engine_result,
    infer_with_proof_analysis_result,
    obligation_type,
    refine_obligation_with_specific_reject,
)
from .proof_engine import analyze_proof as analyze_proof_engine
from .reject_info import (
    SpecificRejectInfo,
    extract_specific_contract_mismatch,
    extract_specific_reject_info,
    specific_contract_help,
    specific_contract_note,
)
from .renderer import DiagnosticOutput, render_diagnostic
from .source_correlator import ProofEvent, ProofObligation, correlate_to_source
from .spans import (
    find_instruction,
    make_proof_event,
    normalize_spans,
    register_from_error,
    synthesize_proof_events,
)
from .trace_parser import ParsedTrace, parse_trace


@dataclass(slots=True)
class FallbackProofResult:
    proof_status: str | None
    proof_events: list[ProofEvent] = field(default_factory=list)
    obligation: ProofObligation | None = None
    fallback_reasons: list[str] = field(default_factory=list)
    causal_chain: list[tuple[int, str]] = field(default_factory=list)


def generate_diagnostic(
    verifier_log: str,
    catalog_path: str | None = None,
    bpftool_xlated: str | None = None,
) -> DiagnosticOutput:
    """Run the full parser → proof summary → source correlation → renderer pipeline."""

    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)
    parsed_trace = parse_trace(verifier_log)
    diagnosis = diagnose(verifier_log, catalog_path=catalog_path)
    proof_result = analyze_proof(parsed_log, parsed_trace, diagnosis)
    bpftool_source_map = (
        parse_bpftool_xlated_linum(bpftool_xlated) if bpftool_xlated else None
    )

    proof_status = proof_result.proof_status or diagnosis.proof_status or "unknown"
    fallback_obligation, fallback_notes = infer_obligation_from_engine_result(
        parsed_log,
        parsed_trace,
        diagnosis,
    )
    proof_result.fallback_reasons.extend(
        note for note in fallback_notes if note not in proof_result.fallback_reasons
    )
    obligation = (
        proof_result.obligation
        or fallback_obligation
        or infer_catalog_obligation(parsed_log, diagnosis)
    )
    specific_reject = extract_specific_reject_info(parsed_log)
    obligation = refine_obligation_with_specific_reject(obligation, specific_reject)
    spans = correlate_to_source(
        parsed_trace,
        proof_result.proof_events,
        bpftool_source_map=bpftool_source_map,
    )
    spans = normalize_spans(
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        diagnosis=diagnosis,
        proof_status=proof_status,
        spans=spans,
        bpftool_source_map=bpftool_source_map,
    )
    note = build_note(parsed_log, diagnosis, obligation, proof_status, specific_reject)
    help_text = build_help_text(parsed_log, diagnosis, obligation, proof_status, specific_reject)

    output = render_diagnostic(
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
    attach_proof_analysis_metadata(output, proof_result)
    return output


def analyze_proof(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> FallbackProofResult:
    engine_result = try_proof_engine(parsed_log, parsed_trace, diagnosis)
    fallback_reasons = list(engine_result.fallback_reasons) if engine_result is not None else []
    engine_obligation = engine_result.obligation if engine_result is not None else None
    engine_causal_chain = list(engine_result.causal_chain) if engine_result is not None else []
    if engine_result is not None and not should_ignore_engine_result(engine_result, diagnosis):
        return engine_result

    if diagnosis.taxonomy_class == "source_bug" and diagnosis.proof_status == "never_established":
        obligation_result, proof_analysis_notes = infer_with_proof_analysis_result(
            parsed_log,
            parsed_trace,
            diagnosis,
            find_instruction=find_instruction,
            register_from_error=_register_from_error,
        )
        fallback_reasons.extend(proof_analysis_notes)
        obligation = obligation_result or engine_obligation
        return FallbackProofResult(
            proof_status=diagnosis.proof_status,
            proof_events=synthesize_proof_events(parsed_trace, diagnosis),
            obligation=obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=engine_causal_chain,
        )

    real_result, proof_analysis_notes = infer_with_proof_analysis_result(
        parsed_log,
        parsed_trace,
        diagnosis,
        find_instruction=find_instruction,
        register_from_error=_register_from_error,
    )
    fallback_reasons.extend(proof_analysis_notes)
    if real_result is not None:
        obligation, lifecycle = real_result
        return FallbackProofResult(
            proof_status=getattr(lifecycle, "status", None) or diagnosis.proof_status,
            proof_events=list(getattr(lifecycle, "events", None) or []),
            obligation=obligation or engine_obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=engine_causal_chain,
        )

    return FallbackProofResult(
        proof_status=diagnosis.proof_status,
        proof_events=synthesize_proof_events(parsed_trace, diagnosis),
        obligation=engine_obligation,
        fallback_reasons=fallback_reasons,
        causal_chain=engine_causal_chain,
    )


def should_ignore_engine_result(
    result: FallbackProofResult,
    diagnosis: Diagnosis,
) -> bool:
    if result.obligation is None and not result.proof_events and result.fallback_reasons:
        return True
    if result.proof_status != "unknown":
        return False
    if diagnosis.proof_status in {None, "unknown"}:
        return False
    return not any(event.event_type != "rejected" for event in result.proof_events)


def attach_proof_analysis_metadata(
    output: DiagnosticOutput,
    proof_result: FallbackProofResult,
) -> None:
    if not proof_result.fallback_reasons and not proof_result.causal_chain:
        return
    metadata = output.json_data.setdefault("metadata", {})
    if proof_result.causal_chain:
        metadata["causal_chain"] = list(proof_result.causal_chain)
    if proof_result.fallback_reasons:
        metadata["proof_analysis"] = {
            "fallback_reasons": proof_result.fallback_reasons,
        }


def try_proof_engine(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> FallbackProofResult | None:
    error_line = parsed_trace.error_line or parsed_log.error_line or ""
    error_insn = diagnosis.symptom_insn
    fallback_reasons: list[str] = []
    try:
        result = analyze_proof_engine(parsed_trace, error_line, error_insn)
    except Exception as exc:
        if not _is_expected_proof_failure(exc):
            raise
        return FallbackProofResult(
            proof_status="unknown",
            proof_events=[],
            obligation=None,
            fallback_reasons=[_proof_failure_note("proof_engine.analyze_proof", exc)],
        )

    events = engine_result_to_events(result, parsed_trace)
    obligation = engine_obligation_to_proof_obligation(result)
    if obligation is None:
        obligation, obligation_notes = infer_obligation_from_engine_result(
            parsed_log,
            parsed_trace,
            diagnosis,
        )
        fallback_reasons.extend(obligation_notes)
    if obligation is None and result.proof_status == "unknown":
        return FallbackProofResult(
            proof_status="unknown",
            proof_events=[],
            obligation=None,
            fallback_reasons=fallback_reasons,
        )
    proof_status = result.proof_status
    if (
        proof_status == "never_established"
        and result.obligation is not None
        and result.obligation.kind == "helper_arg"
    ):
        specific_contract = extract_specific_contract_mismatch(error_line)
        if specific_contract is not None:
            obligation = _make_helper_contract_obligation(specific_contract.raw)

    return FallbackProofResult(
        proof_status=proof_status,
        proof_events=events,
        obligation=obligation,
        fallback_reasons=fallback_reasons,
        causal_chain=list(getattr(result, "causal_chain", []) or []),
    )


def engine_result_to_events(
    result: Any,
    parsed_trace: ParsedTrace,
) -> list[ProofEvent]:
    events: list[ProofEvent] = []

    if result.establish_site is not None:
        insn = find_instruction(parsed_trace.instructions, result.establish_site)
        reg = result.obligation.base_reg if result.obligation else "R0"
        before_state = insn.pre_state.get(reg) if insn and reg else None
        after_state = insn.post_state.get(reg) if insn and reg else None
        events.append(
            make_proof_event(
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
        insn = find_instruction(parsed_trace.instructions, result.loss_site)
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
            make_proof_event(
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
        insn = find_instruction(parsed_trace.instructions, result.reject_site)
        reg = result.obligation.base_reg if result.obligation else "R0"
        before_state = insn.pre_state.get(reg) if insn and reg else None
        after_state = insn.post_state.get(reg) if insn and reg else None
        error_text = insn.error_text if insn else "verifier rejected"
        events.append(
            make_proof_event(
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


def build_note(
    parsed_log: ParsedLog,
    diagnosis: Diagnosis,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None = None,
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

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    if (
        diagnosis.taxonomy_class == "source_bug"
        and specific_contract is not None
        and proof_status in {"never_established", "unknown"}
    ):
        return specific_contract_note(specific_contract)

    if obligation is not None and proof_status == "never_established":
        current_type = obligation_type(obligation)
        return f"The required {current_type.replace('_', ' ')} proof was never established."

    for line in diagnosis.evidence:
        if line.startswith("Proof existed earlier") or line.startswith("No earlier"):
            return line
    return None


def build_help_text(
    parsed_log: ParsedLog,
    diagnosis: Diagnosis,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None = None,
) -> str | None:
    if specific_reject is not None and specific_reject.help_text:
        return specific_reject.help_text

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    if (
        diagnosis.taxonomy_class == "source_bug"
        and specific_contract is not None
        and (
            proof_status == "never_established"
            or (obligation is not None and obligation_type(obligation) == "helper_arg")
            or diagnosis.error_id == "OBLIGE-E023"
        )
    ):
        specific_help = specific_contract_help(parsed_log, specific_contract)
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


def _register_from_error(error_text: str | None) -> str | None:
    return register_from_error(error_text)


def _make_helper_contract_obligation(required: str) -> ProofObligation:
    return ProofObligation(
        obligation_type="helper_arg",
        register="R0",
        required_condition=required,
        description=required,
    )


def _proof_failure_note(stage: str, exc: Exception) -> str:
    detail = str(exc).strip()
    if detail:
        return f"{stage} fell back after {type(exc).__name__}: {detail}"
    return f"{stage} fell back after {type(exc).__name__}"


def _is_expected_proof_failure(exc: Exception) -> bool:
    return isinstance(exc, (ValueError, LookupError))
