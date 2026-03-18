"""Rust-style diagnostic orchestration pipeline — single clean path.

Flow:
  parse_log → parse_trace → find error insn → opcode safety conditions
  → monitor (lifecycle) → transition_analyzer (causal chain)
  → derive taxonomy from analysis → build proof events
  → correlate to source → render
"""

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
from .engine.slicer import backward_slice
from .engine.transition_analyzer import TransitionAnalyzer, TransitionEffect
from .log_parser import ParsedLog, parse_log
from .reject_info import (
    SpecificRejectInfo,
    extract_specific_contract_mismatch,
    extract_specific_reject_info,
    specific_contract_help,
    specific_contract_note,
)
from .renderer import DiagnosticOutput, render_diagnostic
from .shared_utils import extract_registers
from .source_correlator import ProofEvent, ProofObligation, SourceSpan, correlate_to_source
from .trace_parser import ParsedTrace, parse_trace


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_diagnostic(
    verifier_log: str,
    catalog_path: str | None = None,
    bpftool_xlated: str | None = None,
    source_code: str | None = None,
) -> DiagnosticOutput:
    """Run the full parser → engine → source correlation → renderer pipeline.

    Single path — no fallbacks, no parallel systems, no keyword heuristics.
    """
    # Step 1: parse log (error_id, taxonomy_class, error_line from catalog matching)
    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)

    # Step 2: parse trace (per-instruction abstract state)
    parsed_trace = parse_trace(verifier_log)

    bpftool_source_map = (
        parse_bpftool_xlated_linum(bpftool_xlated) if bpftool_xlated else None
    )

    # Step 3: find the error instruction (explicitly marked is_error=True)
    instructions = list(getattr(parsed_trace, "instructions", []))
    error_insn = next((i for i in instructions if i.is_error), None)
    error_line = parsed_trace.error_line or parsed_log.error_line or ""

    # Step 4: derive safety conditions from error instruction opcode (ISA-driven, no keywords)
    predicate = None
    if error_insn is not None:
        error_register = getattr(getattr(parsed_trace, "causal_chain", None), "error_register", None)
        if error_register is None:
            registers = extract_registers(getattr(error_insn, "error_text", None))
            error_register = registers[0] if registers else None

        conditions = infer_conditions_from_error_insn(
            error_insn,
            error_register=error_register,
        )
        violated = find_violated_condition(error_insn, conditions)
        if violated is not None:
            predicate = OpcodeConditionPredicate(violated)

    # Step 5: run TraceMonitor — find where proof was established and where it was lost
    monitor = TraceMonitor()
    monitor_result = monitor.monitor(predicate, instructions)

    # Step 6: run TransitionAnalyzer — build causal chain of state-degrading transitions
    proof_registers: set[str] = set()
    if predicate is not None:
        proof_registers = set(getattr(predicate, "target_regs", []))
    analyzer = TransitionAnalyzer()
    transition_chain = analyzer.analyze(instructions, proof_registers)

    # Step 7: derive proof_status from analysis results (not keywords)
    proof_status = _derive_proof_status(
        monitor_result=monitor_result,
        transition_chain=transition_chain,
        predicate=predicate,
        parsed_log=parsed_log,
        error_line=error_line,
        instructions=instructions,
    )

    # Step 8: derive obligation from violated condition or specific contract mismatch
    obligation = _derive_obligation(
        predicate=predicate,
        monitor_result=monitor_result,
        parsed_trace=parsed_trace,
        parsed_log=parsed_log,
        error_line=error_line,
    )

    # Refine obligation with specific reject info (helper contract violations, etc.)
    specific_reject = extract_specific_reject_info(parsed_log)
    if specific_reject is not None:
        obligation = _refine_obligation(obligation, specific_reject, error_line)

    # Step 9: build proof events from monitor + transition results
    proof_events = _build_proof_events(
        monitor_result=monitor_result,
        transition_chain=transition_chain,
        predicate=predicate,
        parsed_trace=parsed_trace,
        error_line=error_line,
        proof_status=proof_status,
    )

    # Step 10: correlate events to source spans
    spans = correlate_to_source(
        parsed_trace,
        proof_events,
        bpftool_source_map=bpftool_source_map,
    )
    spans = _ensure_rejected_span(spans, parsed_trace, parsed_log, bpftool_source_map)

    # Step 11: build note and help text
    note = _build_note(parsed_log, obligation, proof_status, specific_reject)
    help_text = _build_help_text(parsed_log, obligation, proof_status, specific_reject)

    # Step 12: compute principled backward slice for causal chain.
    # This replaces the old heuristic mark_precise + value_lineage chain.
    #
    # Determine the criterion: error instruction + the primary register of interest.
    # Prefer the predicate's target register; fall back to the first register
    # used or defined by the error instruction.
    slice_criterion_insn: int | None = None
    slice_criterion_reg: str | None = None

    if error_insn is not None:
        slice_criterion_insn = error_insn.insn_idx
        if predicate is not None:
            target_regs = getattr(predicate, "target_regs", [])
            slice_criterion_reg = target_regs[0] if target_regs else None
        if slice_criterion_reg is None:
            # Fall back to primary register from obligation or first used/defined reg
            if obligation is not None:
                slice_criterion_reg = getattr(obligation, "register", None)
        if slice_criterion_reg is None:
            # Last resort: use the monitor or transition chain loss register
            if monitor_result is not None and hasattr(monitor_result, "loss_site"):
                pass  # we'll figure out below
            from .engine.dataflow import extract_uses, extract_defs
            bytecode = error_insn.bytecode or ""
            uses = extract_uses(bytecode)
            defs = extract_defs(bytecode)
            regs = list(uses) or list(defs)
            slice_criterion_reg = regs[0] if regs else "R0"

    # Build the backward slice (principled data + control dependence).
    # Only run if we have a clear criterion; otherwise fall back to TA chain.
    use_slice_chain = (
        slice_criterion_insn is not None
        and slice_criterion_reg is not None
        and len(instructions) > 0
    )

    causal_chain: list[tuple[int, str]]

    if use_slice_chain:
        bslice = backward_slice(
            instructions,
            criterion_insn=slice_criterion_insn,
            criterion_register=slice_criterion_reg,
        )
        # Build causal chain entries: each instruction in the ordered slice
        # (excluding the criterion itself, which appears as the rejected event).
        from .engine.dataflow import compute_reaching_defs as _crd
        _df_chain = _crd(instructions)
        causal_chain = []
        indexed = {insn.insn_idx: insn for insn in instructions}
        for insn_idx in bslice.ordered:
            if insn_idx == slice_criterion_insn:
                continue
            insn_obj = indexed.get(insn_idx)
            bytecode_text = insn_obj.bytecode if insn_obj else ""
            # Annotate with "data" or "control" for the reason field.
            if insn_idx in bslice.data_deps:
                reason = f"data_dep: {bytecode_text}"
            else:
                reason = f"control_dep: {bytecode_text}"
            causal_chain.append((insn_idx, reason))
    else:
        # Fallback: use transition_chain (old heuristic path) when no clear criterion.
        causal_chain = [
            (d.insn_idx, d.reason)
            for d in transition_chain.chain
            if d.effect in (TransitionEffect.DESTROYING, TransitionEffect.WIDENING)
        ]

    output = render_diagnostic(
        error_id=parsed_log.error_id or "OBLIGE-UNKNOWN",
        taxonomy_class=parsed_log.taxonomy_class or "unknown",
        proof_status=proof_status,
        spans=spans,
        obligation=obligation,
        note=note,
        help_text=help_text,
        confidence=_confidence_to_float(parsed_log.catalog_confidence),
        diagnosis_evidence=parsed_log.evidence,
        raw_log_excerpt=(specific_reject.raw if specific_reject is not None else parsed_log.error_line) or None,
    )

    # Attach causal chain to metadata if present
    if causal_chain:
        metadata = output.json_data.setdefault("metadata", {})
        metadata["causal_chain"] = [
            {"insn_idx": idx, "reason": reason} for idx, reason in causal_chain
        ]

    # Also attach backward slice metadata when available.
    if use_slice_chain and bslice.full_slice:
        metadata = output.json_data.setdefault("metadata", {})
        metadata["backward_slice"] = {
            "criterion_insn": slice_criterion_insn,
            "criterion_register": slice_criterion_reg,
            "full_slice": sorted(bslice.full_slice),
            "data_deps": sorted(bslice.data_deps),
            "control_deps": sorted(bslice.control_deps),
        }

    return output


# ---------------------------------------------------------------------------
# Step 7: derive proof status from engine results
# ---------------------------------------------------------------------------

def _derive_proof_status(
    *,
    monitor_result: Any,
    transition_chain: Any,
    predicate: Any,
    parsed_log: ParsedLog,
    error_line: str,
    instructions: list,
) -> str:
    """Derive proof_status from analysis results — no keyword heuristics.

    Priority:
    1. If predicate exists and monitor found a definitive result → use it
    2. If no predicate but specific contract mismatch → never_established
    3. If no predicate and verifier_limit/verifier_bug taxonomy → never_established
    4. If no predicate but TA found established_then_lost with real establish+loss points → use it
    5. Otherwise → unknown (no error instruction = no proof lifecycle to classify)
    """
    has_error_insn = any(i.is_error for i in instructions)

    if predicate is not None:
        # Real predicate: trust the monitor result
        status = monitor_result.proof_status
        # If monitor says established_but_insufficient but TA found established_then_lost
        # with a valid loss point, prefer TA (it found a specific loss site)
        if (
            status == "established_but_insufficient"
            and transition_chain.proof_status == "established_then_lost"
            and transition_chain.establish_point is not None
            and transition_chain.loss_point is not None
        ):
            return "established_then_lost"
        return status

    # No predicate: only classify based on strong signals

    # Specific contract mismatch in error line → never_established (concrete violation)
    # This applies even without an error instruction — the error line IS the signal
    if extract_specific_contract_mismatch(error_line) is not None:
        return "never_established"

    # Verifier limits, bugs, and env mismatches are structural — always never_established
    taxonomy = parsed_log.taxonomy_class or ""
    if taxonomy in {"verifier_limit", "verifier_bug", "env_mismatch"}:
        return "never_established"

    # TA found established_then_lost with explicit establish AND loss points AND an error insn → real lifecycle
    # Without an error instruction, the TA lifecycle is a spurious artifact (no proof failure occurred)
    if (
        has_error_insn
        and transition_chain.proof_status == "established_then_lost"
        and transition_chain.establish_point is not None
        and transition_chain.loss_point is not None
    ):
        return "established_then_lost"

    # No clear signal → unknown (don't fabricate proof lifecycle)
    return "unknown"


# ---------------------------------------------------------------------------
# Step 8: derive obligation
# ---------------------------------------------------------------------------

def _derive_obligation(
    *,
    predicate: Any,
    monitor_result: Any,
    parsed_trace: ParsedTrace,
    parsed_log: ParsedLog,
    error_line: str,
) -> ProofObligation | None:
    """Derive proof obligation from violated safety condition or error line."""
    if predicate is not None:
        target_regs = getattr(predicate, "target_regs", [])
        base_reg = target_regs[0] if target_regs else "R0"
        required = _predicate_required_condition(predicate, monitor_result, parsed_trace) or error_line
        return ProofObligation(
            obligation_type=_predicate_to_obligation_type(predicate),
            register=base_reg,
            required_condition=required,
            description=f"Inferred from: {error_line}",
        )

    # No predicate: check for specific contract mismatch in error line
    specific_contract = extract_specific_contract_mismatch(error_line)
    if specific_contract is not None:
        return ProofObligation(
            obligation_type="helper_arg",
            register="R0",
            required_condition=specific_contract.raw,
            description=specific_contract.raw,
        )

    return None


def _refine_obligation(
    obligation: ProofObligation | None,
    specific_reject: SpecificRejectInfo,
    error_line: str,
) -> ProofObligation | None:
    """Refine or replace obligation with info from specific reject (helper contracts, etc.)."""
    specific_required = getattr(specific_reject, "obligation_required", None)
    specific_type = getattr(specific_reject, "obligation_type", None)

    if specific_required and specific_type:
        if obligation is None:
            return ProofObligation(
                obligation_type=specific_type,
                register="R1",
                required_condition=specific_required,
                description=f"Contract violation: {specific_required}",
            )
        # Refine existing obligation with more specific info
        current_required = getattr(obligation, "required_condition", None) or ""
        if specific_required and specific_required != current_required:
            return ProofObligation(
                obligation_type=specific_type,
                register=getattr(obligation, "register", "R0"),
                required_condition=specific_required,
                description=getattr(obligation, "description", specific_required),
                catalog_id=getattr(obligation, "catalog_id", None),
            )

    return obligation


# ---------------------------------------------------------------------------
# Step 9: build proof events
# ---------------------------------------------------------------------------

def _build_proof_events(
    *,
    monitor_result: Any,
    transition_chain: Any,
    predicate: Any,
    parsed_trace: ParsedTrace,
    error_line: str,
    proof_status: str,
) -> list[ProofEvent]:
    """Build proof events from monitor and/or transition_chain results."""
    instructions = list(getattr(parsed_trace, "instructions", []))
    indexed = {insn.insn_idx: insn for insn in instructions}

    target_regs = getattr(predicate, "target_regs", []) if predicate is not None else []
    primary_reg = target_regs[0] if target_regs else "R0"

    events: list[ProofEvent] = []

    if predicate is not None and monitor_result.proof_status not in {"unknown"}:
        # Real SafetyCondition exists: use monitor result for establish/loss sites.
        # The monitor found a real predicate satisfaction/violation, so lifecycle spans are meaningful.
        events = _monitor_result_to_events(monitor_result, indexed, primary_reg)
    # No predicate (structural errors, or opcode_safety returned None):
    # Do NOT produce proof_established/proof_lost spans from TA fallback.
    # TA transition chain is already attached as causal_chain metadata (see step 12).

    # Always add the rejected event if not already present
    if not any(e.event_type == "rejected" for e in events):
        error_insn = next((i for i in instructions if i.is_error), None)
        if error_insn is not None:
            events.append(ProofEvent(
                insn_idx=error_insn.insn_idx,
                event_type="rejected",
                register=primary_reg,
                state_before=error_insn.pre_state.get(primary_reg),
                state_after=error_insn.post_state.get(primary_reg),
                source_line=error_insn.source_line,
                description=error_insn.error_text or "verifier rejected",
            ))

    return events


def _monitor_result_to_events(
    monitor_result: Any,
    indexed: dict[int, Any],
    primary_reg: str,
) -> list[ProofEvent]:
    """Convert MonitorResult to ProofEvent list.

    Temporal ordering is enforced: establish <= loss <= rejected.
    If loss_site > error_insn (verifier backtracking artifact), loss is capped at error_insn.
    """
    events: list[ProofEvent] = []
    error_insn_idx = monitor_result.error_insn

    if monitor_result.establish_site is not None:
        insn = indexed.get(monitor_result.establish_site)
        events.append(ProofEvent(
            insn_idx=monitor_result.establish_site,
            event_type="proof_established",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=f"Proof obligation satisfied at insn {monitor_result.establish_site}",
        ))

    if monitor_result.loss_site is not None:
        # Cap loss_site at error_insn to preserve temporal ordering
        loss_idx = monitor_result.loss_site
        if error_insn_idx is not None and loss_idx > error_insn_idx:
            loss_idx = error_insn_idx
        insn = indexed.get(loss_idx)
        reason = monitor_result.loss_reason or "proof property violated"
        events.append(ProofEvent(
            insn_idx=loss_idx,
            event_type="proof_lost",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=reason,
        ))

    if error_insn_idx is not None:
        insn = indexed.get(error_insn_idx)
        events.append(ProofEvent(
            insn_idx=error_insn_idx,
            event_type="rejected",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=(insn.error_text if insn else None) or "verifier rejected",
        ))

    return events


def _transition_chain_to_events(
    transition_chain: Any,
    indexed: dict[int, Any],
    primary_reg: str,
    error_line: str,
) -> list[ProofEvent]:
    """Convert TransitionChain to ProofEvent list."""
    events: list[ProofEvent] = []
    reg = transition_chain.establish_point.register if transition_chain.establish_point else primary_reg

    # Find error instruction index for temporal ordering
    error_insn_idx = next(
        (idx for idx, insn in indexed.items() if insn.is_error), None
    )

    if transition_chain.establish_point is not None:
        ep = transition_chain.establish_point
        insn = indexed.get(ep.insn_idx)
        events.append(ProofEvent(
            insn_idx=ep.insn_idx,
            event_type="proof_established",
            register=ep.register,
            state_before=insn.pre_state.get(ep.register) if insn else None,
            state_after=insn.post_state.get(ep.register) if insn else None,
            source_line=ep.source_text,
            description=f"Proof established: {ep.reason}",
        ))

    if transition_chain.loss_point is not None:
        lp = transition_chain.loss_point
        # Cap loss at error instruction for temporal coherence
        lp_idx = lp.insn_idx
        if error_insn_idx is not None and lp_idx > error_insn_idx:
            lp_idx = error_insn_idx
        insn = indexed.get(lp_idx)
        events.append(ProofEvent(
            insn_idx=lp_idx,
            event_type="proof_lost",
            register=lp.register,
            state_before=insn.pre_state.get(lp.register) if insn else None,
            state_after=insn.post_state.get(lp.register) if insn else None,
            source_line=lp.source_text if lp.insn_idx == lp_idx else (insn.source_line if insn else None),
            description=lp.reason,
        ))

    if error_insn_idx is not None:
        insn = indexed.get(error_insn_idx)
        events.append(ProofEvent(
            insn_idx=error_insn_idx,
            event_type="rejected",
            register=reg,
            state_before=insn.pre_state.get(reg) if insn else None,
            state_after=insn.post_state.get(reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=(insn.error_text if insn else None) or error_line or "verifier rejected",
        ))

    return events


# ---------------------------------------------------------------------------
# Step 10: ensure there's always a rejected span
# ---------------------------------------------------------------------------

def _ensure_rejected_span(
    spans: list[SourceSpan],
    parsed_trace: ParsedTrace,
    parsed_log: ParsedLog,
    bpftool_source_map: Any,
) -> list[SourceSpan]:
    """Ensure there is at least one rejected span in the output."""
    if any(s.role == "rejected" for s in spans):
        return spans

    instructions = list(getattr(parsed_trace, "instructions", []))

    # Try error instruction first
    for insn in reversed(instructions):
        if insn.is_error:
            return list(spans) + [SourceSpan(
                file=None,
                line=None,
                source_text=insn.bytecode,
                insn_range=(insn.insn_idx, insn.insn_idx),
                role="rejected",
                register=None,
                state_change=None,
                reason=insn.error_text or "verifier rejected",
            )]

    # Last instruction as fallback
    if instructions:
        last_insn = instructions[-1]
        from .source_correlator import _extract_source_fields
        source_text, file_name, line_number = _extract_source_fields(
            last_insn.source_line, last_insn.bytecode
        )
        return list(spans) + [SourceSpan(
            file=file_name,
            line=line_number,
            source_text=source_text,
            insn_range=(last_insn.insn_idx, last_insn.insn_idx),
            role="rejected",
            register=None,
            state_change=None,
            reason=parsed_log.error_line or "verifier rejected",
        )]

    # Error line only
    if parsed_log.error_line:
        return list(spans) + [SourceSpan(
            file=None,
            line=None,
            source_text=parsed_log.error_line,
            insn_range=(0, 0),
            role="rejected",
            register=None,
            state_change=None,
            reason=parsed_log.error_line,
        )]

    return spans


# ---------------------------------------------------------------------------
# Step 11: note and help text
# ---------------------------------------------------------------------------

def _build_note(
    parsed_log: ParsedLog,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None,
) -> str | None:
    if specific_reject is not None and specific_reject.note:
        return specific_reject.note

    taxonomy = parsed_log.taxonomy_class or ""

    if taxonomy == "lowering_artifact" and proof_status == "established_then_lost":
        return "A verifier-visible proof existed earlier but was lost before the rejected instruction."

    if parsed_log.error_id == "OBLIGE-E002":
        return "The dereference happens while the pointer is still nullable on this control-flow path."

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    if taxonomy == "source_bug" and specific_contract is not None and proof_status in {"never_established", "unknown"}:
        return specific_contract_note(specific_contract)

    if obligation is not None and proof_status == "never_established":
        obl_type = getattr(obligation, "obligation_type", "unknown")
        return f"The required {obl_type.replace('_', ' ')} proof was never established."

    for line in (parsed_log.evidence or []):
        if line.startswith("Proof existed earlier") or line.startswith("No earlier"):
            return line

    return None


def _build_help_text(
    parsed_log: ParsedLog,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None,
) -> str | None:
    if specific_reject is not None and specific_reject.help_text:
        return specific_reject.help_text

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    taxonomy = parsed_log.taxonomy_class or ""
    obl_type = getattr(obligation, "obligation_type", None) if obligation else None

    if (
        taxonomy == "source_bug"
        and specific_contract is not None
        and (
            proof_status == "never_established"
            or obl_type == "helper_arg"
            or parsed_log.error_id == "OBLIGE-E023"
        )
    ):
        specific_help = specific_contract_help(parsed_log, specific_contract)
        if specific_help is not None:
            return specific_help

    catalog_path = Path(__file__).resolve().parents[2] / "taxonomy" / "obligation_catalog.yaml"
    try:
        templates = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except OSError:
        return None

    error_id = parsed_log.error_id
    for template in templates.get("templates", []):
        if error_id and error_id in template.get("related_error_ids", []):
            hints = template.get("repair_hints") or []
            if hints:
                return hints[0]

    return None


# ---------------------------------------------------------------------------
# Helpers: predicate introspection
# ---------------------------------------------------------------------------

def _predicate_required_condition(
    predicate: Any,
    monitor_result: Any,
    parsed_trace: ParsedTrace,
) -> str | None:
    """Extract the required condition string from a predicate."""
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP
    if isinstance(predicate, _OCP):
        cond = predicate.condition
        target_regs = getattr(predicate, "target_regs", [])
        parts = [f"{r}: {cond.required_property}" for r in target_regs]
        return "; ".join(parts) if parts else None
    return None


def _predicate_to_obligation_type(predicate: Any) -> str:
    """Map a Predicate instance to a semantic obligation type string."""
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP, SafetyDomain
    if isinstance(predicate, _OCP):
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
        return mapping.get(predicate.condition.domain, "safety_violation")
    return type(predicate).__name__.lower()


def _confidence_to_float(confidence: str | float | None) -> float | None:
    if confidence is None:
        return None
    if isinstance(confidence, float):
        return confidence
    mapping = {"high": 0.9, "medium": 0.6, "low": 0.3, "very_low": 0.1}
    return mapping.get(str(confidence).lower().strip())


# ---------------------------------------------------------------------------
# Legacy compatibility: diagnose() — kept for eval scripts that import it
# ---------------------------------------------------------------------------

def diagnose(verifier_log: str, catalog_path: str | None = None) -> Any:
    """Thin wrapper that returns generate_diagnostic() result for legacy callers."""
    return generate_diagnostic(verifier_log, catalog_path=catalog_path)
