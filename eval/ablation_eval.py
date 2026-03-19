#!/usr/bin/env python3
"""Run BPFix, the regex baseline, and ablation variants on the eligible corpus."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.baseline import generate_baseline_diagnostic
from interface.extractor.engine.cfg_builder import build_cfg
from interface.extractor.engine.monitor import CarrierBoundPredicate, TraceMonitor, monitor_carriers
from interface.extractor.engine.opcode_safety import (
    OpcodeConditionPredicate,
    discover_compatible_carriers,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
    infer_safety_schemas,
    instantiate_primary_carrier,
    instantiate_schema,
)
from interface.extractor.engine.slicer import backward_slice
from interface.extractor.pipeline import (
    _STRUCTURAL_TAXONOMY_BY_ERROR_ID,
    _build_proof_events,
    _ensure_rejected_span,
    aggregate_atom_classes,
    classify_atom,
    compute_forward_dominators,
)
from interface.extractor.rust_diagnostic import generate_diagnostic
from interface.extractor.source_correlator import correlate_to_source
from interface.extractor.log_parser import parse_log
from interface.extractor.trace_parser import parse_trace


DEFAULT_MANIFEST_PATH = ROOT / "case_study" / "eval_manifest.yaml"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "ablation_results.json"
CASE_ROOT = ROOT / "case_study" / "cases"
EXPECTED_ELIGIBLE_CASES = 262
METHOD_KEYS = ("bpfix", "baseline", "ablation_a", "ablation_b", "ablation_c")


@dataclass(slots=True)
class CaseContext:
    case_id: str
    case_path: Path
    source: str
    verifier_log: str
    parsed_log: Any
    parsed_trace: Any
    instructions: list[Any]
    error_insn: Any | None
    structural_taxonomy: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit for debugging.",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Optional case_id filter; can be passed multiple times.",
    )
    parser.add_argument(
        "--print-every",
        type=int,
        default=25,
        help="Progress logging interval.",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined", "")
        if isinstance(combined, str) and combined.strip():
            return combined
        blocks = verifier_log.get("blocks", [])
        if isinstance(blocks, list):
            return "\n".join(block for block in blocks if isinstance(block, str))
    return ""


def build_case_path_index() -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in sorted(CASE_ROOT.rglob("*.yaml")):
        if path.name == "index.yaml":
            continue
        case_data = load_yaml(path) or {}
        case_id = str(case_data.get("case_id") or path.stem)
        if case_id in index and index[case_id] != path:
            raise ValueError(f"duplicate case_id {case_id}: {index[case_id]} vs {path}")
        index[case_id] = path
    return index


def iter_eligible_entries(
    manifest_path: Path,
    *,
    limit: int | None = None,
    include_case_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    manifest = list(load_yaml(manifest_path) or [])
    eligible = [entry for entry in manifest if entry.get("eligible")]
    if include_case_ids:
        eligible = [entry for entry in eligible if str(entry.get("case_id")) in include_case_ids]
    if limit is not None:
        eligible = eligible[:limit]
    return eligible


def load_case_context(entry: dict[str, Any], case_paths: dict[str, Path]) -> CaseContext:
    case_id = str(entry["case_id"])
    case_path = case_paths.get(case_id)
    if case_path is None:
        raise FileNotFoundError(f"unable to locate case file for {case_id}")

    case_data = load_yaml(case_path) or {}
    verifier_log = extract_verifier_log(case_data)
    parsed_log = parse_log(verifier_log)
    parsed_trace = parse_trace(verifier_log)
    instructions = list(getattr(parsed_trace, "instructions", []))
    error_insn = next((insn for insn in instructions if getattr(insn, "is_error", False)), None)
    structural_taxonomy = _STRUCTURAL_TAXONOMY_BY_ERROR_ID.get(parsed_log.error_id)

    return CaseContext(
        case_id=case_id,
        case_path=case_path,
        source=str(entry.get("source") or ""),
        verifier_log=verifier_log,
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        instructions=instructions,
        error_insn=error_insn,
        structural_taxonomy=structural_taxonomy,
    )


def _method_error_id(parsed_log: Any) -> str:
    error_id = getattr(parsed_log, "error_id", None)
    return str(error_id) if error_id else "BPFIX-UNKNOWN"


def _metadata(json_data: dict[str, Any]) -> dict[str, Any]:
    metadata = json_data.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _count_spans(json_data: dict[str, Any]) -> int:
    spans = json_data.get("spans")
    if isinstance(spans, list):
        return len(spans)
    proof_spans = _metadata(json_data).get("proof_spans")
    if isinstance(proof_spans, list):
        return len(proof_spans)
    return 0


def _normalize_taxonomy(json_data: dict[str, Any]) -> str:
    taxonomy = json_data.get("taxonomy_class") or json_data.get("failure_class")
    return str(taxonomy) if taxonomy else "source_bug"


def _has_carrier_establishment(active_atoms: list[dict[str, Any]]) -> bool:
    for atom in active_atoms:
        lifecycles = atom.get("carrier_lifecycles")
        if not isinstance(lifecycles, dict):
            continue
        for lifecycle in lifecycles.values():
            if not isinstance(lifecycle, dict):
                continue
            events = lifecycle.get("events")
            if not isinstance(events, list):
                continue
            if any(isinstance(event, dict) and event.get("kind") == "establish" for event in events):
                return True
    return False


def _bpfix_result(ctx: CaseContext) -> dict[str, Any]:
    output = generate_diagnostic(ctx.verifier_log)
    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    metadata = _metadata(json_data)
    active_atoms = metadata.get("active_atoms")
    if not isinstance(active_atoms, list):
        active_atoms = []

    return {
        "error_id": str(json_data.get("error_id") or _method_error_id(ctx.parsed_log)),
        "taxonomy": _normalize_taxonomy(json_data),
        "proof_status": str(metadata.get("proof_status") or "unknown"),
        "spans": _count_spans(json_data),
        "cross_class": metadata.get("cross_analysis_class"),
        "active_atom_classes": [
            str(atom.get("classification"))
            for atom in active_atoms
            if isinstance(atom, dict) and atom.get("classification")
        ],
        "has_carrier_establishment": _has_carrier_establishment(active_atoms),
    }


def _baseline_result(ctx: CaseContext) -> dict[str, Any]:
    output = generate_baseline_diagnostic(ctx.verifier_log)
    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    metadata = _metadata(json_data)
    return {
        "error_id": str(json_data.get("error_id") or _method_error_id(ctx.parsed_log)),
        "taxonomy": _normalize_taxonomy(json_data),
        "proof_status": str(metadata.get("proof_status") or "unknown"),
        "spans": _count_spans(json_data),
    }


def _proof_status_without_predicate(ctx: CaseContext) -> str:
    return "never_established" if ctx.error_insn is not None else "unknown"


def _span_count_from_monitor(ctx: CaseContext, predicate: Any, monitor_result: Any) -> int:
    proof_events = _build_proof_events(
        monitor_result=monitor_result,
        predicate=predicate,
        parsed_trace=ctx.parsed_trace,
    )
    spans = correlate_to_source(ctx.parsed_trace, proof_events)
    spans = _ensure_rejected_span(spans, ctx.parsed_trace, ctx.parsed_log)
    return len(spans)


def _monitor_none(ctx: CaseContext) -> Any:
    return TraceMonitor().monitor(None, ctx.instructions)


def _structural_result(ctx: CaseContext) -> dict[str, Any]:
    monitor_result = _monitor_none(ctx)
    return {
        "error_id": _method_error_id(ctx.parsed_log),
        "taxonomy": str(ctx.structural_taxonomy),
        "proof_status": "unknown",
        "spans": _span_count_from_monitor(ctx, None, monitor_result),
    }


def _ablation_a_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return _structural_result(ctx)

    predicate = None
    proof_status = _proof_status_without_predicate(ctx)
    monitor_result = _monitor_none(ctx)

    if ctx.error_insn is not None:
        conditions = infer_conditions_from_error_insn(ctx.error_insn)
        violated = find_violated_condition(ctx.error_insn, conditions)
        if violated is not None:
            predicate = OpcodeConditionPredicate(violated)
            monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
            proof_status = monitor_result.proof_status

    taxonomy = "lowering_artifact" if proof_status == "established_then_lost" else "source_bug"
    return {
        "error_id": _method_error_id(ctx.parsed_log),
        "taxonomy": taxonomy,
        "proof_status": proof_status,
        "spans": _span_count_from_monitor(ctx, predicate, monitor_result),
    }


def _select_primary_monitor_for_no_slice(ctx: CaseContext) -> tuple[Any, Any, str]:
    selected_predicate = None
    selected_monitor_result = _monitor_none(ctx)
    selected_proof_status = _proof_status_without_predicate(ctx)

    if ctx.error_insn is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    lowering_candidate: tuple[Any, Any] | None = None
    fallback_candidate: tuple[Any, Any] | None = None

    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            continue

        predicate = CarrierBoundPredicate(condition, primary)
        monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
        carriers = discover_compatible_carriers(schema, primary, ctx.error_insn.pre_state)
        lifecycles = monitor_carriers(schema, carriers, ctx.instructions)
        primary_lifecycle = lifecycles.get(primary.register)
        any_establish = any(
            any(event.kind == "establish" for event in lifecycle.events)
            for lifecycle in lifecycles.values()
        )
        primary_loss = bool(primary_lifecycle and primary_lifecycle.loss_site is not None)

        if fallback_candidate is None:
            fallback_candidate = (predicate, monitor_result)
        if lowering_candidate is None and any_establish and not primary_loss:
            lowering_candidate = (predicate, monitor_result)

    chosen = lowering_candidate or fallback_candidate
    if chosen is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    selected_predicate, selected_monitor_result = chosen
    selected_proof_status = selected_monitor_result.proof_status
    return selected_predicate, selected_monitor_result, selected_proof_status


def _ablation_b_taxonomy(ctx: CaseContext) -> str:
    if ctx.error_insn is None:
        return "source_bug"

    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            continue

        carriers = discover_compatible_carriers(schema, primary, ctx.error_insn.pre_state)
        lifecycles = monitor_carriers(schema, carriers, ctx.instructions)
        primary_lifecycle = lifecycles.get(primary.register)
        any_establish = any(
            any(event.kind == "establish" for event in lifecycle.events)
            for lifecycle in lifecycles.values()
        )
        primary_loss = bool(primary_lifecycle and primary_lifecycle.loss_site is not None)
        if any_establish and not primary_loss:
            return "lowering_artifact"

    return "source_bug"


def _ablation_b_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return _structural_result(ctx)

    predicate, monitor_result, proof_status = _select_primary_monitor_for_no_slice(ctx)
    taxonomy = _ablation_b_taxonomy(ctx)
    return {
        "error_id": _method_error_id(ctx.parsed_log),
        "taxonomy": taxonomy,
        "proof_status": proof_status,
        "spans": _span_count_from_monitor(ctx, predicate, monitor_result),
    }


def _select_primary_monitor_for_no_carrier(ctx: CaseContext) -> tuple[Any, Any, str]:
    selected_predicate = None
    selected_monitor_result = _monitor_none(ctx)
    selected_proof_status = _proof_status_without_predicate(ctx)

    if ctx.error_insn is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    cfg = build_cfg(ctx.instructions) if ctx.instructions else None
    dominators = compute_forward_dominators(cfg) if cfg is not None else {}
    lowering_candidate: tuple[Any, Any] | None = None
    fallback_candidate: tuple[Any, Any] | None = None

    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            continue

        predicate = CarrierBoundPredicate(condition, primary)
        lifecycle = TraceMonitor().monitor_events(predicate, ctx.instructions)
        bslice = backward_slice(
            ctx.instructions,
            criterion_insn=ctx.error_insn.insn_idx,
            criterion_register=primary.register,
            cfg=cfg,
        )
        atom = classify_atom(
            schema,
            ctx.error_insn,
            ctx.instructions,
            cfg,
            dominators,
            primary=primary,
            monitoring={primary.register: lifecycle},
            bslice=bslice,
            reject_evaluation=reject_evaluation,
        )
        monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
        classification = atom.classification

        if fallback_candidate is None:
            fallback_candidate = (predicate, monitor_result)
        if lowering_candidate is None and classification in {"lowering_artifact", "established_then_lost"}:
            lowering_candidate = (predicate, monitor_result)

    chosen = lowering_candidate or fallback_candidate
    if chosen is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    selected_predicate, selected_monitor_result = chosen
    selected_proof_status = selected_monitor_result.proof_status
    return selected_predicate, selected_monitor_result, selected_proof_status


def _ablation_c_taxonomy(ctx: CaseContext) -> str:
    if ctx.error_insn is None:
        return "source_bug"

    cfg = build_cfg(ctx.instructions) if ctx.instructions else None
    dominators = compute_forward_dominators(cfg) if cfg is not None else {}
    atom_classes: list[str] = []

    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            atom_classes.append("ambiguous")
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            atom_classes.append("inactive")
            continue

        predicate = CarrierBoundPredicate(condition, primary)
        lifecycle = TraceMonitor().monitor_events(predicate, ctx.instructions)
        bslice = backward_slice(
            ctx.instructions,
            criterion_insn=ctx.error_insn.insn_idx,
            criterion_register=primary.register,
            cfg=cfg,
        )
        atom = classify_atom(
            schema,
            ctx.error_insn,
            ctx.instructions,
            cfg,
            dominators,
            primary=primary,
            monitoring={primary.register: lifecycle},
            bslice=bslice,
            reject_evaluation=reject_evaluation,
        )
        atom_classes.append(atom.classification)

    cross_class = aggregate_atom_classes(atom_classes)
    if cross_class in {"lowering_artifact", "established_then_lost"}:
        return "lowering_artifact"
    return "source_bug"


def _ablation_c_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return _structural_result(ctx)

    predicate, monitor_result, proof_status = _select_primary_monitor_for_no_carrier(ctx)
    taxonomy = _ablation_c_taxonomy(ctx)
    return {
        "error_id": _method_error_id(ctx.parsed_log),
        "taxonomy": taxonomy,
        "proof_status": proof_status,
        "spans": _span_count_from_monitor(ctx, predicate, monitor_result),
    }


def evaluate_case(ctx: CaseContext) -> dict[str, Any]:
    return {
        "case_id": ctx.case_id,
        "bpfix": _bpfix_result(ctx),
        "baseline": _baseline_result(ctx),
        "ablation_a": _ablation_a_result(ctx),
        "ablation_b": _ablation_b_result(ctx),
        "ablation_c": _ablation_c_result(ctx),
    }


def validate_payload(payload: dict[str, Any]) -> None:
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise ValueError("payload.cases must be a list")
    for row in cases:
        if not isinstance(row, dict):
            raise ValueError("every case row must be a mapping")
        if not row.get("case_id"):
            raise ValueError("case row missing case_id")
        for method in METHOD_KEYS:
            value = row.get(method)
            if not isinstance(value, dict):
                raise ValueError(f"{row['case_id']}: missing method payload {method}")
            if not value.get("taxonomy"):
                raise ValueError(f"{row['case_id']}:{method} missing taxonomy")


def main() -> int:
    args = parse_args()
    include_case_ids = set(args.case_id) if args.case_id else None
    case_paths = build_case_path_index()
    eligible_entries = iter_eligible_entries(
        args.manifest_path,
        limit=args.limit,
        include_case_ids=include_case_ids,
    )

    if args.limit is None and include_case_ids is None and len(eligible_entries) != EXPECTED_ELIGIBLE_CASES:
        print(
            f"[ablation_eval] warning: expected {EXPECTED_ELIGIBLE_CASES} eligible cases, got {len(eligible_entries)}",
            file=sys.stderr,
        )

    cases: list[dict[str, Any]] = []
    for index, entry in enumerate(eligible_entries, start=1):
        ctx = load_case_context(entry, case_paths)
        cases.append(evaluate_case(ctx))
        if args.print_every > 0 and (index % args.print_every == 0 or index == len(eligible_entries)):
            print(f"[ablation_eval] processed {index}/{len(eligible_entries)}", file=sys.stderr)

    payload = {"cases": cases}
    validate_payload(payload)

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    with args.results_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")

    print(f"Wrote {args.results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
