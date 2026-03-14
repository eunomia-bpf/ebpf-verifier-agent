"""Rust-style diagnostic orchestration pipeline."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .bpftool_parser import parse_bpftool_xlated_linum
from .engine.monitor import TraceMonitor
from .engine.opcode_safety import (
    OpcodeConditionPredicate,
    find_violated_condition,
    infer_conditions_from_error_insn,
)
from .engine.transition_analyzer import TransitionAnalyzer
from .log_parser import ParsedLog, parse_log
from .reject_info import (
    SpecificRejectInfo,
    extract_specific_contract_mismatch,
    extract_specific_reject_info,
    specific_contract_help,
    specific_contract_note,
)
from .renderer import DiagnosticOutput, render_diagnostic
from .source_correlator import ProofEvent, ProofObligation, SourceSpan, correlate_to_source
from .trace_parser import ParsedTrace, parse_trace


# ---------------------------------------------------------------------------
# Diagnosis dataclass and diagnose() function (inlined from deleted diagnoser.py)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Diagnosis:
    """Structured diagnosis from a verifier log."""

    error_id: str | None
    taxonomy_class: str | None
    proof_status: str | None
    symptom_insn: int | None
    evidence: list[str]
    confidence: str | None = None
    loss_context: str | None = None
    recommended_fix: str | None = None


def diagnose(
    verifier_log: str,
    catalog_path: str | Path | None = None,
) -> Diagnosis:
    """Diagnose a verifier log by delegating to log_parser and trace_parser."""
    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)
    parsed_trace = parse_trace(verifier_log)

    instructions = list(getattr(parsed_trace, "instructions", []))
    transitions = list(getattr(parsed_trace, "critical_transitions", []))

    has_established = any(
        t.transition_type in {"NULL_CHECK_ESTABLISHED", "BOUNDS_ESTABLISHED"}
        for t in transitions
    )
    has_lost = any(
        t.transition_type in {"BOUNDS_COLLAPSE", "TYPE_DOWNGRADE", "PROVENANCE_LOSS"}
        for t in transitions
    )
    has_error = any(insn.is_error for insn in instructions)

    if has_established and has_lost:
        proof_status: str | None = "established_then_lost"
        loss_context: str | None = _infer_loss_context(transitions)
    elif has_established and has_error:
        proof_status = "established_but_insufficient"
        loss_context = None
    elif has_error:
        proof_status = "never_established"
        loss_context = None
    else:
        proof_status = "unknown"
        loss_context = None

    symptom_insn: int | None = None
    for insn in instructions:
        if insn.is_error:
            symptom_insn = insn.insn_idx
            break

    return Diagnosis(
        error_id=parsed_log.error_id,
        taxonomy_class=parsed_log.taxonomy_class,
        proof_status=proof_status,
        symptom_insn=symptom_insn,
        evidence=parsed_log.evidence,
        confidence=parsed_log.catalog_confidence,
        loss_context=loss_context,
    )


def _infer_loss_context(transitions: list) -> str | None:
    for t in transitions:
        desc = (t.description or "").lower()
        if "spill" in desc or "fill" in desc or "stack" in desc:
            return "register_spill"
        if "arithmetic" in desc or "alu" in desc:
            return "arithmetic"
        if "call" in desc or "function" in desc:
            return "function_boundary"
    return None


# ---------------------------------------------------------------------------
# Obligation helpers (inlined from deleted obligation_refinement.py)
# ---------------------------------------------------------------------------

def obligation_type(obligation: Any) -> str:
    """Return the type string of an obligation."""
    if obligation is None:
        return "unknown"
    return (
        getattr(obligation, "obligation_type", None)
        or getattr(obligation, "kind", None)
        or "unknown"
    )


def infer_catalog_obligation(
    parsed_log: Any,
    diagnosis: Any,
) -> tuple[Any | None, list[str]]:
    """Infer obligation from catalog matching."""
    return None, []


def infer_obligation_from_engine_result(
    parsed_log: Any,
    parsed_trace: Any,
    diagnosis: Any,
) -> tuple[Any | None, list[str]]:
    """Infer obligation from engine result using opcode-driven analysis."""
    try:
        obligation = _infer_obligation_from_trace(parsed_log, parsed_trace)
        return obligation, []
    except Exception:
        return None, ["obligation inference failed"]


def _infer_obligation_from_trace(
    parsed_log: Any,
    parsed_trace: Any,
) -> ProofObligation | None:
    """Infer obligation from trace using opcode-driven safety analysis.

    Only applies when the error instruction is explicitly marked as is_error=True.
    For structural/environmental errors without an explicit error instruction,
    falls back to None (caller will use the classification-only path).
    """
    try:
        # Find the error instruction — only use explicitly-marked error instructions
        instructions = list(getattr(parsed_trace, "instructions", []))
        error_insn = None
        for insn in instructions:
            if insn.is_error:
                error_insn = insn
                break

        # Do NOT use fallback (last instruction) for structural errors.
        # If no instruction is explicitly marked as error, opcode analysis does not apply.
        if error_insn is None:
            return None

        # Derive conditions from the error instruction's opcode
        conditions = infer_conditions_from_error_insn(error_insn)
        if not conditions:
            return None

        violated = find_violated_condition(error_insn, conditions)
        if violated is None:
            return None

        error_line = getattr(parsed_log, "error_line", "") or ""
        return ProofObligation(
            obligation_type=_safety_domain_to_obligation_type(violated.domain),
            register=violated.critical_register,
            required_condition=violated.required_property,
            description=f"ISA-derived from opcode: {error_line}",
        )
    except Exception:
        return None


def refine_obligation_with_specific_reject(
    obligation: Any,
    specific_reject: Any,
) -> Any:
    """Refine an obligation with specific reject info."""
    if specific_reject is None or obligation is None:
        return obligation

    specific_required = getattr(specific_reject, "obligation_required", None)
    if not specific_required:
        return obligation

    current_required = getattr(obligation, "required_condition", None) or ""

    if specific_required and specific_required != current_required:
        try:
            specific_type = getattr(specific_reject, "obligation_type", None) or obligation_type(obligation)
            return ProofObligation(
                obligation_type=specific_type,
                register=getattr(obligation, "register", "R0"),
                required_condition=specific_required,
                description=getattr(obligation, "description", specific_required),
                catalog_id=getattr(obligation, "catalog_id", None),
            )
        except Exception:
            return obligation

    return obligation


# ---------------------------------------------------------------------------
# Instruction and span helpers (inlined from deleted spans.py)
# ---------------------------------------------------------------------------

def find_instruction(instructions: Any, insn_idx: int | None) -> Any | None:
    """Find a TracedInstruction by index from a list."""
    if instructions is None or insn_idx is None:
        return None
    for insn in instructions:
        if insn.insn_idx == insn_idx:
            return insn
    return None


def make_proof_event(
    *,
    insn_idx: int,
    event_type: str,
    register: str,
    before: Any = None,
    after: Any = None,
    source_line: str | None = None,
    description: str = "",
) -> ProofEvent:
    """Create a ProofEvent."""
    return ProofEvent(
        insn_idx=insn_idx,
        event_type=event_type,
        register=register,
        state_before=before,
        state_after=after,
        source_line=source_line,
        description=description,
    )


def register_from_error(error_text: str | None) -> str:
    """Extract register name from error line."""
    match = re.search(r'\b(R\d+)\b', error_text or "")
    return match.group(1) if match else "R0"


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
    source_code: str | None = None,
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
    catalog_obligation, _ = infer_catalog_obligation(parsed_log, diagnosis)
    obligation = (
        proof_result.obligation
        or fallback_obligation
        or catalog_obligation
    )
    specific_reject = extract_specific_reject_info(parsed_log)
    # When we have a specific contract mismatch but no obligation yet, create one from it.
    # This handles cases where the error is structural (no explicit error instruction) but
    # the raw log contains a concrete contract violation (e.g., "arg#0 expected pointer to...").
    if obligation is None and specific_reject is not None:
        specific_required = getattr(specific_reject, "obligation_required", None)
        specific_type = getattr(specific_reject, "obligation_type", None)
        if specific_required and specific_type:
            obligation = ProofObligation(
                obligation_type=specific_type,
                register="R1",
                required_condition=specific_required,
                description=f"Contract violation: {specific_required}",
            )
    obligation = refine_obligation_with_specific_reject(obligation, specific_reject)
    spans = correlate_to_source(
        parsed_trace,
        proof_result.proof_events,
        bpftool_source_map=bpftool_source_map,
    )
    spans = _normalize_spans(
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
        confidence=_confidence_to_float(diagnosis.confidence),
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
        return FallbackProofResult(
            proof_status=diagnosis.proof_status,
            proof_events=_synthesize_proof_events(parsed_trace, diagnosis),
            obligation=engine_obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=engine_causal_chain,
        )

    return FallbackProofResult(
        proof_status=diagnosis.proof_status,
        proof_events=_synthesize_proof_events(parsed_trace, diagnosis),
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
        metadata["causal_chain"] = [
            {"insn_idx": entry[0], "reason": entry[1]}
            for entry in proof_result.causal_chain
        ]
    if proof_result.fallback_reasons:
        metadata["proof_analysis"] = {
            "fallback_reasons": proof_result.fallback_reasons,
        }


def try_proof_engine(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> FallbackProofResult | None:
    """Run the new engine (TraceMonitor + TransitionAnalyzer) on the parsed trace."""
    error_line = parsed_trace.error_line or parsed_log.error_line or ""
    fallback_reasons: list[str] = []

    instructions = list(getattr(parsed_trace, "instructions", []))
    if not instructions:
        # No instructions — infer from error line only
        empty_obligation, _ = infer_obligation_from_engine_result(parsed_log, parsed_trace, diagnosis)
        error_line_noinsn = parsed_trace.error_line or parsed_log.error_line or ""

        # Only report "never_established" when we have a specific contract violation
        # (i.e., the error message is concrete enough). Otherwise keep "unknown".
        specific_contract_noinsn = extract_specific_contract_mismatch(error_line_noinsn)
        if specific_contract_noinsn is not None:
            no_insn_status = "never_established"
            if empty_obligation is None:
                empty_obligation = _make_helper_contract_obligation(specific_contract_noinsn.raw)
        else:
            no_insn_status = "unknown"

        return FallbackProofResult(
            proof_status=no_insn_status,
            proof_events=[],
            obligation=empty_obligation,
            fallback_reasons=["no instructions in trace"],
        )

    try:
        # Step 1: derive safety conditions from the error instruction's opcode (ISA-driven)
        # Only use opcode analysis when the instruction is explicitly marked as error
        # (is_error=True). When no instruction has is_error, the error is structural/
        # environmental and opcode-driven lifecycle analysis does not apply.
        error_insn = None
        has_explicit_error_insn = False
        for insn in instructions:
            if insn.is_error:
                error_insn = insn
                has_explicit_error_insn = True
                break
        if error_insn is None and instructions:
            error_insn = instructions[-1]

        predicate = None
        if error_insn is not None and has_explicit_error_insn:
            conditions = infer_conditions_from_error_insn(error_insn)
            violated = find_violated_condition(error_insn, conditions)
            if violated is not None:
                predicate = OpcodeConditionPredicate(violated)

        # Step 2: run TraceMonitor to find establish/loss sites
        monitor = TraceMonitor()
        monitor_result = monitor.monitor(predicate, instructions)

        # Step 3: determine proof registers from predicate for TransitionAnalyzer
        proof_registers: set[str] = set()
        if predicate is not None:
            target_regs = getattr(predicate, "target_regs", [])
            proof_registers = set(target_regs)

        # Step 4: run TransitionAnalyzer for richer causal chain
        analyzer = TransitionAnalyzer()
        transition_chain = analyzer.analyze(instructions, proof_registers)

    except Exception as exc:
        if not _is_expected_proof_failure(exc):
            raise
        return FallbackProofResult(
            proof_status="unknown",
            proof_events=[],
            obligation=None,
            fallback_reasons=[_proof_failure_note("engine.analyze", exc)],
        )

    # Build causal chain from TransitionAnalyzer
    causal_chain: list[tuple[int, str]] = []
    for detail in transition_chain.chain:
        if detail.effect.value in ("destroying", "widening"):
            causal_chain.append((detail.insn_idx, detail.reason))

    # When predicate was inferred (and is NOT classification-only), use MonitorResult
    # for proof_status and events. ClassificationOnlyPredicate always returns "unknown"
    # from evaluate(), so for those we always fall through to TransitionAnalyzer.
    from .engine.predicate import ClassificationOnlyPredicate as _COP
    is_classification_only = isinstance(predicate, _COP)

    # prefer_ta: use TransitionAnalyzer result instead of monitor result.
    # We prefer TA when:
    # - monitor returned "established_but_insufficient" but TA found "established_then_lost"
    #   (TA provides a specific loss site, which is more informative)
    prefer_ta = (
        not is_classification_only
        and predicate is not None
        and monitor_result.proof_status == "established_but_insufficient"
        and transition_chain.proof_status == "established_then_lost"
        and transition_chain.establish_point is not None
        and transition_chain.loss_point is not None
    )

    if (
        predicate is not None
        and not is_classification_only
        and not prefer_ta
        and monitor_result.proof_status not in {"unknown"}
    ):
        # Use monitor result — but correct temporal ordering if loss is after error
        from .engine.monitor import MonitorResult as _MR
        effective_monitor = monitor_result
        if (
            monitor_result.loss_site is not None
            and monitor_result.error_insn is not None
            and monitor_result.loss_site > monitor_result.error_insn
        ):
            # loss_site is after error in bytecode — find a DESTROYING event that is
            # strictly before the error instruction index
            from .engine.transition_analyzer import TransitionEffect as _TE
            best_loss_before_error: Any = None
            for detail in transition_chain.chain:
                if detail.effect not in (_TE.DESTROYING, _TE.WIDENING):
                    continue
                if detail.insn_idx >= monitor_result.error_insn:
                    continue
                if best_loss_before_error is None or detail.insn_idx > best_loss_before_error.insn_idx:
                    best_loss_before_error = detail

            if best_loss_before_error is not None:
                effective_monitor = _MR(
                    proof_status=monitor_result.proof_status,
                    establish_site=monitor_result.establish_site,
                    loss_site=best_loss_before_error.insn_idx,
                    loss_reason=best_loss_before_error.reason,
                    last_satisfied_insn=monitor_result.last_satisfied_insn,
                    error_insn=monitor_result.error_insn,
                )
            else:
                # No DESTROYING event before error — use error_insn as loss site
                # (the proof was lost at the rejection point itself)
                effective_monitor = _MR(
                    proof_status=monitor_result.proof_status,
                    establish_site=monitor_result.establish_site,
                    loss_site=monitor_result.error_insn,
                    loss_reason="proof lost at rejection point",
                    last_satisfied_insn=monitor_result.last_satisfied_insn,
                    error_insn=monitor_result.error_insn,
                )
        events = _monitor_result_to_events(effective_monitor, parsed_trace, predicate)
        target_regs = getattr(predicate, "target_regs", ["R0"])
        base_reg = target_regs[0] if target_regs else "R0"
        required_condition = _predicate_required_condition(predicate, effective_monitor, parsed_trace) or error_line
        obligation: ProofObligation | None = ProofObligation(
            obligation_type=_predicate_to_obligation_type(predicate),
            register=base_reg,
            required_condition=required_condition,
            description=f"Inferred from: {error_line}",
        )
        proof_status = effective_monitor.proof_status
        if proof_status == "never_established":
            specific_contract = extract_specific_contract_mismatch(error_line)
            if specific_contract is not None:
                obligation = _make_helper_contract_obligation(specific_contract.raw)
        return FallbackProofResult(
            proof_status=proof_status,
            proof_events=events,
            obligation=obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=causal_chain,
        )

    # KEY INVARIANT: TransitionAnalyzer must NOT drive proof_status when no real predicate
    # exists. Without a predicate, ANY register change looks like proof lifecycle, which
    # produces false-positive "established_then_lost" for cases that are really "unknown"
    # or "never_established". TransitionAnalyzer is only used for the causal_chain (which
    # is informational) and for lifecycle analysis when a REAL predicate provides proof_registers.
    #
    # When predicate is None or ClassificationOnlyPredicate:
    # - Do NOT report established_then_lost from TransitionAnalyzer
    # - Report "unknown" (no predicate) or "never_established" (classification-only + taxonomy)
    # - Still include causal_chain for informational purposes

    if predicate is None or is_classification_only:
        # No real predicate — use taxonomy classification from log_parser, not TransitionAnalyzer
        obligation, obligation_notes = infer_obligation_from_engine_result(
            parsed_log,
            parsed_trace,
            diagnosis,
        )
        fallback_reasons.extend(obligation_notes)
        if obligation is None and is_classification_only and predicate is not None:
            obligation = _classification_only_obligation(predicate)

        # Determine proof_status purely from classification, NOT from TransitionAnalyzer
        cop_taxonomy = getattr(predicate, "taxonomy_class", None) if is_classification_only else None
        cop_error_id = getattr(predicate, "error_id", None) if is_classification_only else None
        _ALWAYS_NEVER_ESTABLISHED_IDS = {"OBLIGE-E022"}

        # Verifier limits and structural errors are always "never_established":
        # the program violated a structural constraint, not a register safety property.
        # This applies both to ClassificationOnlyPredicate cases and to cases where
        # predicate is None but the taxonomy class is verifier_limit/verifier_bug.
        diag_taxonomy = diagnosis.taxonomy_class or ""
        diag_error_id = diagnosis.error_id or ""
        is_verifier_limit = (
            (is_classification_only and cop_taxonomy in {"verifier_limit", "verifier_bug"})
            or (predicate is None and diag_taxonomy in {"verifier_limit", "verifier_bug"})
            or (is_classification_only and cop_error_id in _ALWAYS_NEVER_ESTABLISHED_IDS)
            or (predicate is None and diag_error_id in _ALWAYS_NEVER_ESTABLISHED_IDS)
        )

        if is_verifier_limit:
            final_status = "never_established"
        else:
            # For env_mismatch and unclassified errors: defer to diagnosis (log_parser classification)
            # Do NOT use TransitionAnalyzer proof_status here
            diag_status = diagnosis.proof_status
            if diag_status and diag_status != "unknown":
                final_status = diag_status
            else:
                final_status = "unknown"

        # Always check for specific contract violations from the error message,
        # regardless of final_status. This covers helper/type mismatch cases where
        # no error instruction is explicitly marked but the error_line contains a
        # concrete contract violation (e.g., "R2 type=inv expected=fp").
        specific_contract = extract_specific_contract_mismatch(error_line)
        if specific_contract is not None:
            obligation = _make_helper_contract_obligation(specific_contract.raw)
            # Upgrade "unknown" to "never_established" when we have a concrete contract violation
            if final_status == "unknown":
                final_status = "never_established"

        return FallbackProofResult(
            proof_status=final_status,
            proof_events=[],
            obligation=obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=causal_chain,
        )

    # predicate is a real (non-classification-only) predicate that the monitor evaluated as
    # "unknown" (e.g., monitor couldn't find establish/loss sites). Only use TransitionAnalyzer
    # lifecycle if it found meaningful transitions AND they are temporally consistent.
    if causal_chain or transition_chain.establish_point is not None or transition_chain.loss_point is not None:
        # Find the best loss point: the DESTROYING event closest before the first error instruction
        best_loss_point = _select_best_loss_point(transition_chain, parsed_trace)
        effective_chain = transition_chain

        # Sanity check: if establish_point is AFTER loss_point (verifier backtracking artifact),
        # override to never_established — the TransitionAnalyzer found a false positive.
        ep = transition_chain.establish_point
        lp = best_loss_point or transition_chain.loss_point
        is_backtracking_artifact = (
            ep is not None
            and lp is not None
            and ep.insn_idx > lp.insn_idx
        )

        if transition_chain.proof_status == "established_then_lost" and is_backtracking_artifact:
            # Override to never_established — not a real established_then_lost
            from .engine.transition_analyzer import TransitionChain as _TC
            effective_chain = _TC(
                proof_status="never_established",
                establish_point=None,
                loss_point=None,
                chain=transition_chain.chain,
            )
        elif best_loss_point is not None and best_loss_point is not transition_chain.loss_point:
            from .engine.transition_analyzer import TransitionChain as _TC
            effective_chain = _TC(
                proof_status=transition_chain.proof_status,
                establish_point=transition_chain.establish_point,
                loss_point=best_loss_point,
                chain=transition_chain.chain,
            )
        events = _transition_chain_to_events(effective_chain, parsed_trace, error_line)
        obligation, obligation_notes = infer_obligation_from_engine_result(
            parsed_log,
            parsed_trace,
            diagnosis,
        )
        fallback_reasons.extend(obligation_notes)
        if obligation is None:
            reg = transition_chain.establish_point.register if transition_chain.establish_point else "R0"
            obligation = ProofObligation(
                obligation_type="scalar_bound",
                register=reg,
                required_condition=error_line,
                description=f"Inferred from transition analysis: {error_line}",
            )
        proof_status = effective_chain.proof_status
        if proof_status == "never_established":
            specific_contract = extract_specific_contract_mismatch(error_line)
            if specific_contract is not None:
                obligation = _make_helper_contract_obligation(specific_contract.raw)
        return FallbackProofResult(
            proof_status=proof_status,
            proof_events=events,
            obligation=obligation,
            fallback_reasons=fallback_reasons,
            causal_chain=causal_chain,
        )

    # Final fallback: real predicate but no transitions found
    obligation, obligation_notes = infer_obligation_from_engine_result(
        parsed_log,
        parsed_trace,
        diagnosis,
    )
    fallback_reasons.extend(obligation_notes)
    # Use the TransitionAnalyzer's status if available and not "unknown"
    final_status = transition_chain.proof_status if transition_chain.proof_status != "unknown" else "unknown"

    # For ClassificationOnlyPredicate with no transitions found, build obligation from predicate
    if obligation is None and is_classification_only and predicate is not None:
        obligation = _classification_only_obligation(predicate)

    if final_status == "never_established":
        specific_contract = extract_specific_contract_mismatch(error_line)
        if specific_contract is not None:
            obligation = _make_helper_contract_obligation(specific_contract.raw)

    return FallbackProofResult(
        proof_status=final_status,
        proof_events=[],
        obligation=obligation,
        fallback_reasons=fallback_reasons,
        causal_chain=causal_chain,
    )


def _monitor_result_to_events(
    monitor_result: Any,
    parsed_trace: ParsedTrace,
    predicate: Any,
) -> list[ProofEvent]:
    """Convert a MonitorResult to a list of ProofEvent objects."""
    events: list[ProofEvent] = []

    # Determine relevant register from predicate
    target_regs = getattr(predicate, "target_regs", []) if predicate is not None else []
    primary_reg = target_regs[0] if target_regs else "R0"

    if monitor_result.establish_site is not None:
        insn = find_instruction(parsed_trace.instructions, monitor_result.establish_site)
        before_state = insn.pre_state.get(primary_reg) if insn else None
        after_state = insn.post_state.get(primary_reg) if insn else None
        events.append(
            make_proof_event(
                insn_idx=monitor_result.establish_site,
                event_type="proof_established",
                register=primary_reg,
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=f"Proof obligation satisfied at insn {monitor_result.establish_site}",
            )
        )

    if monitor_result.loss_site is not None:
        insn = find_instruction(parsed_trace.instructions, monitor_result.loss_site)
        before_state = insn.pre_state.get(primary_reg) if insn else None
        after_state = insn.post_state.get(primary_reg) if insn else None
        reason = monitor_result.loss_reason or "proof property violated"
        events.append(
            make_proof_event(
                insn_idx=monitor_result.loss_site,
                event_type="proof_lost",
                register=primary_reg,
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=reason,
            )
        )

    # Add the error/reject site if present
    error_insn_idx = monitor_result.error_insn
    if error_insn_idx is not None:
        insn = find_instruction(parsed_trace.instructions, error_insn_idx)
        before_state = insn.pre_state.get(primary_reg) if insn else None
        after_state = insn.post_state.get(primary_reg) if insn else None
        error_text = (insn.error_text if insn else None) or "verifier rejected"
        events.append(
            make_proof_event(
                insn_idx=error_insn_idx,
                event_type="rejected",
                register=primary_reg,
                before=before_state,
                after=after_state,
                source_line=insn.source_line if insn else None,
                description=error_text,
            )
        )
    else:
        # Fall back: find the last error instruction in the trace
        for insn in reversed(parsed_trace.instructions):
            if insn.is_error:
                before_state = insn.pre_state.get(primary_reg)
                after_state = insn.post_state.get(primary_reg)
                error_text = insn.error_text or "verifier rejected"
                events.append(
                    make_proof_event(
                        insn_idx=insn.insn_idx,
                        event_type="rejected",
                        register=primary_reg,
                        before=before_state,
                        after=after_state,
                        source_line=insn.source_line,
                        description=error_text,
                    )
                )
                break

    return events


def _select_best_loss_point(transition_chain: Any, parsed_trace: ParsedTrace) -> Any:
    """Select the best loss point from a TransitionChain.

    Prefers the DESTROYING event that is closest before the error instruction
    in bytecode index order (not trace order). This ensures we pick the most
    causally relevant loss site.
    """
    # Find the first error instruction's bytecode index
    error_insn_idx: int | None = None
    for insn in parsed_trace.instructions:
        if insn.is_error:
            if error_insn_idx is None or insn.insn_idx < error_insn_idx:
                error_insn_idx = insn.insn_idx

    if error_insn_idx is None:
        return transition_chain.loss_point

    from .engine.transition_analyzer import TransitionEffect
    # Find the last DESTROYING event with insn_idx < error_insn_idx
    best: Any = None
    for detail in transition_chain.chain:
        if detail.effect not in (TransitionEffect.DESTROYING, TransitionEffect.WIDENING):
            continue
        if detail.insn_idx >= error_insn_idx:
            continue
        if best is None or detail.insn_idx > best.insn_idx:
            best = detail

    return best or transition_chain.loss_point


def _transition_chain_to_events(
    transition_chain: Any,
    parsed_trace: ParsedTrace,
    error_line: str,
) -> list[ProofEvent]:
    """Convert a TransitionChain to ProofEvent objects.

    Ensures temporal ordering: proof_established.insn_idx <= proof_lost.insn_idx <= rejected.insn_idx.
    When loss_point is after the error instruction in bytecode, the loss is placed at the
    error instruction itself (the proof was lost at the rejection point).
    """
    events: list[ProofEvent] = []

    # Find the error instruction first (to enforce temporal ordering)
    error_insn_idx: int | None = None
    error_insn = None
    for insn in parsed_trace.instructions:
        if insn.is_error:
            if error_insn_idx is None or insn.insn_idx < error_insn_idx:
                error_insn_idx = insn.insn_idx
                error_insn = insn

    reg = transition_chain.establish_point.register if transition_chain.establish_point else "R0"

    # Add proof_established event from establish_point
    if transition_chain.establish_point is not None:
        ep = transition_chain.establish_point
        insn = find_instruction(parsed_trace.instructions, ep.insn_idx)
        before_state = insn.pre_state.get(ep.register) if insn else None
        after_state = insn.post_state.get(ep.register) if insn else None
        events.append(
            make_proof_event(
                insn_idx=ep.insn_idx,
                event_type="proof_established",
                register=ep.register,
                before=before_state,
                after=after_state,
                source_line=ep.source_text,
                description=f"Proof established: {ep.reason}",
            )
        )

    # Add proof_lost event from loss_point, enforcing temporal ordering with error
    if transition_chain.loss_point is not None:
        lp = transition_chain.loss_point
        # If loss_point is after the error in bytecode, cap it at the error instruction
        lp_idx = lp.insn_idx
        lp_insn = find_instruction(parsed_trace.instructions, lp_idx)
        lp_source = lp.source_text

        if error_insn_idx is not None and lp_idx > error_insn_idx:
            # Loss happened after error in bytecode — this is a verifier backtracking artifact.
            # Place the loss at the error instruction for temporal coherence.
            lp_idx = error_insn_idx
            lp_insn = error_insn
            lp_source = error_insn.source_line if error_insn else lp_source

        before_state = lp_insn.pre_state.get(lp.register) if lp_insn else None
        after_state = lp_insn.post_state.get(lp.register) if lp_insn else None
        events.append(
            make_proof_event(
                insn_idx=lp_idx,
                event_type="proof_lost",
                register=lp.register,
                before=before_state,
                after=after_state,
                source_line=lp_source,
                description=lp.reason,
            )
        )

    # Add rejected event from the error instruction
    if error_insn is not None:
        before_state = error_insn.pre_state.get(reg)
        after_state = error_insn.post_state.get(reg)
        events.append(
            make_proof_event(
                insn_idx=error_insn.insn_idx,
                event_type="rejected",
                register=reg,
                before=before_state,
                after=after_state,
                source_line=error_insn.source_line,
                description=error_insn.error_text or error_line or "verifier rejected",
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

    recommended_fix = getattr(diagnosis, "recommended_fix", None)
    if recommended_fix:
        return recommended_fix

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


def _classification_only_obligation(predicate: Any) -> ProofObligation:
    """Build an obligation for ClassificationOnlyPredicate based on error_id and taxonomy_class."""
    error_id = getattr(predicate, "error_id", None) or ""
    taxonomy_class = getattr(predicate, "taxonomy_class", None) or ""

    # Map error_id to a semantic obligation type
    _ERROR_ID_TO_OBLIGATION_TYPE = {
        "OBLIGE-E021": "btf_reference_type",  # BTF reference metadata missing
        "OBLIGE-E022": "safety_violation",     # Mutable global state unsupported
        "OBLIGE-E023": "helper_arg",           # Helper contract mismatch
    }

    obligation_type = _ERROR_ID_TO_OBLIGATION_TYPE.get(error_id)
    if obligation_type is None:
        # Fall back to taxonomy-based mapping
        _TAXONOMY_TO_OBLIGATION_TYPE = {
            "env_mismatch": "safety_violation",
            "verifier_limit": "verifier_limit",
            "verifier_bug": "verifier_bug",
        }
        obligation_type = _TAXONOMY_TO_OBLIGATION_TYPE.get(taxonomy_class, "safety_violation")

    return ProofObligation(
        obligation_type=obligation_type,
        register="R0",
        required_condition=obligation_type,  # tests expect the type string as required
        description=getattr(predicate, "description", obligation_type),
    )


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


def _predicate_required_condition(
    predicate: Any,
    monitor_result: Any,
    parsed_trace: ParsedTrace,
) -> str | None:
    """Generate a human-readable required condition from a predicate and monitor result.

    This produces text like "R5.type == pkt; R0.smin >= 0; R0.umax is bounded"
    that describes what the verifier needed to prove.
    """
    from .engine.predicate import PacketArithScalarBound as _PASB
    from .engine.predicate import PacketAccessPredicate as _PAP
    from .engine.predicate import NullCheckPredicate as _NCP
    from .engine.predicate import ScalarBound as _SB
    from .engine.predicate import TypeMembership as _TM

    target_regs = getattr(predicate, "target_regs", [])
    if not target_regs:
        return None

    parts: list[str] = []

    if isinstance(predicate, _PASB):
        # Math between pkt pointer and unbounded register
        # Find the pkt register at the error site (reject site)
        pkt_reg_found = None
        for insn in reversed(parsed_trace.instructions):
            if insn.is_error:
                for reg_name in sorted(insn.pre_state):
                    reg = insn.pre_state.get(reg_name)
                    reg_type = getattr(reg, "type", "").lower()
                    if reg is not None and "pkt" in reg_type and "pkt_end" not in reg_type:
                        pkt_reg_found = reg_name
                        break
                break
        if pkt_reg_found:
            parts.append(f"{pkt_reg_found}.type == pkt")
        # Only use the first target_reg (scalar being added to pkt)
        scalar_reg = target_regs[0] if target_regs else "R0"
        parts.append(f"{scalar_reg}.smin >= 0")
        parts.append(f"{scalar_reg}.umax is bounded")
        return "; ".join(parts) if parts else None

    if isinstance(predicate, _PAP):
        for reg_name in target_regs:
            parts.append(f"{reg_name}.type == pkt; {reg_name}.range > 0")
        return "; ".join(parts) if parts else None

    if isinstance(predicate, _NCP):
        for reg_name in target_regs:
            parts.append(f"{reg_name} != null")
        return "; ".join(parts) if parts else None

    if isinstance(predicate, _SB):
        umax_limit = getattr(predicate, "umax_limit", None)
        for reg_name in target_regs:
            if umax_limit is not None:
                parts.append(f"{reg_name}.umax <= {umax_limit}")
            else:
                parts.append(f"{reg_name} is bounded")
        return "; ".join(parts) if parts else None

    if isinstance(predicate, _TM):
        allowed = getattr(predicate, "allowed_types", set())
        for reg_name in target_regs:
            parts.append(f"{reg_name}.type in {{{', '.join(sorted(allowed))}}}")
        return "; ".join(parts) if parts else None

    # OpcodeConditionPredicate: use the required_property from the SafetyCondition
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP
    if isinstance(predicate, _OCP):
        cond = predicate.condition
        for reg_name in target_regs:
            parts.append(f"{reg_name}: {cond.required_property}")
        return "; ".join(parts) if parts else None

    return None


def _predicate_to_obligation_type(predicate: Any) -> str:
    """Map a Predicate instance to a semantic obligation type string."""
    # Handle OpcodeConditionPredicate (opcode-driven analysis)
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP
    if isinstance(predicate, _OCP):
        return _safety_domain_to_obligation_type(predicate.condition.domain)

    class_name = type(predicate).__name__
    mapping = {
        "PacketAccessPredicate": "packet_access",
        "PacketArithScalarBound": "packet_access",
        "NullCheckPredicate": "null_check",
        "TypeMembership": "type_check",
        "IntervalContainment": "bounds_check",
        "ScalarBound": "scalar_bound",
        "CompositeAllPredicate": "composite",
    }
    return mapping.get(class_name, class_name.lower())


def _safety_domain_to_obligation_type(domain: Any) -> str:
    """Map a SafetyDomain enum value to a semantic obligation type string."""
    from .engine.opcode_safety import SafetyDomain
    mapping = {
        SafetyDomain.MEMORY_BOUNDS: "bounds_check",
        SafetyDomain.POINTER_TYPE: "type_check",
        SafetyDomain.SCALAR_BOUND: "scalar_bound",
        SafetyDomain.NULL_SAFETY: "null_check",
        SafetyDomain.REFERENCE_BALANCE: "ref_balance",
        SafetyDomain.ARG_CONTRACT: "helper_arg",
        SafetyDomain.WRITE_PERMISSION: "write_permission",
        SafetyDomain.ARITHMETIC_LEGALITY: "arith_legality",
    }
    return mapping.get(domain, str(domain).lower())


def _confidence_to_float(confidence: str | float | None) -> float | None:
    """Convert a string confidence level to a float in [0, 1]."""
    if confidence is None:
        return None
    if isinstance(confidence, float):
        return confidence
    mapping = {
        "high": 0.9,
        "medium": 0.6,
        "low": 0.3,
        "very_low": 0.1,
    }
    lowered = str(confidence).lower().strip()
    return mapping.get(lowered, None)


def _normalize_spans(
    *,
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
    proof_status: str,
    spans: list[SourceSpan],
    bpftool_source_map: Any,
) -> list[SourceSpan]:
    """Normalize and augment spans — add a rejected span if none is present."""
    from .source_correlator import SourceSpan as _SourceSpan

    has_rejected = any(s.role == "rejected" for s in spans)

    if not has_rejected:
        # Try to synthesize a rejected span from the trace error instruction
        error_span_added = False
        for insn in reversed(parsed_trace.instructions):
            if insn.is_error:
                spans = list(spans) + [
                    _SourceSpan(
                        file=None,
                        line=None,
                        source_text=insn.bytecode,
                        insn_range=(insn.insn_idx, insn.insn_idx),
                        role="rejected",
                        register=None,
                        state_change=None,
                        reason=insn.error_text or "verifier rejected",
                    )
                ]
                error_span_added = True
                break

        if not error_span_added:
            # No error instruction in trace — use the last instruction as reject site
            instructions = list(getattr(parsed_trace, "instructions", []))
            if instructions:
                last_insn = instructions[-1]
                # Parse the source_line to extract file and line number
                from .source_correlator import _extract_source_fields as _esf
                raw_source = last_insn.source_line or last_insn.bytecode
                source_text, file_name, line_number = _esf(last_insn.source_line, last_insn.bytecode)
                spans = list(spans) + [
                    _SourceSpan(
                        file=file_name,
                        line=line_number,
                        source_text=source_text,
                        insn_range=(last_insn.insn_idx, last_insn.insn_idx),
                        role="rejected",
                        register=None,
                        state_change=None,
                        reason=parsed_log.error_line or "verifier rejected",
                    )
                ]
            elif parsed_log.error_line:
                spans = list(spans) + [
                    _SourceSpan(
                        file=None,
                        line=None,
                        source_text=parsed_log.error_line,
                        insn_range=(0, 0),
                        role="rejected",
                        register=None,
                        state_change=None,
                        reason=parsed_log.error_line,
                    )
                ]

    return spans


def _synthesize_proof_events(
    parsed_trace: ParsedTrace,
    diagnosis: Diagnosis,
) -> list[ProofEvent]:
    """Synthesize minimal proof events from trace and diagnosis.

    Only generates a rejected event from error instructions.
    Does NOT fabricate proof_established or proof_lost from arbitrary
    register transitions — that requires a real predicate.
    """
    events: list[ProofEvent] = []
    for insn in getattr(parsed_trace, "instructions", []):
        if insn.is_error:
            events.append(
                make_proof_event(
                    insn_idx=insn.insn_idx,
                    event_type="rejected",
                    register="R0",
                    source_line=insn.source_line,
                    description=insn.error_text or "verifier rejected",
                )
            )
            break
    return events
