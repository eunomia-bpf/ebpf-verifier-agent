#!/usr/bin/env python3
"""Evaluate how well BPFix repair hints align with ground-truth fix types."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.ground_truth import DEFAULT_GROUND_TRUTH_PATH, GroundTruthLabel, load_ground_truth_labels


DEFAULT_BATCH_RESULTS_PATH = ROOT / "eval" / "results" / "batch_diagnostic_results.json"
DEFAULT_OUTPUT_JSON = ROOT / "eval" / "results" / "fix_type_eval.json"
DEFAULT_OUTPUT_MD = ROOT / "docs" / "tmp" / "fix-type-eval-report.md"
FIX_TYPE_ORDER = (
    "bounds_check",
    "null_check",
    "type_cast",
    "clamp",
    "mask",
    "refcount",
    "env_fix",
    "loop_rewrite",
    "inline",
    "reorder",
    "other",
)
TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "env_mismatch",
    "verifier_limit",
    "verifier_bug",
)


@dataclass(slots=True)
class FixTypeCaseResult:
    case_id: str
    gt_taxonomy_class: str
    gt_fix_type: str
    gt_fix_direction: str
    bpfix_taxonomy_class: str | None
    candidate_repair_action: str | None
    help_text: str | None
    note_text: str | None
    repair_hint: str | None
    predicted_fix_type: str
    mapping_rule: str
    fix_type_match: bool


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ground-truth-path",
        type=Path,
        default=DEFAULT_GROUND_TRUTH_PATH,
        help=f"Path to case_study/ground_truth.yaml (default: {DEFAULT_GROUND_TRUTH_PATH})",
    )
    parser.add_argument(
        "--batch-results-path",
        type=Path,
        default=DEFAULT_BATCH_RESULTS_PATH,
        help=f"Path to eval/results/batch_diagnostic_results.json (default: {DEFAULT_BATCH_RESULTS_PATH})",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_OUTPUT_JSON,
        help=f"Where to write the raw JSON metrics (default: {DEFAULT_OUTPUT_JSON})",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=DEFAULT_OUTPUT_MD,
        help=f"Where to write the markdown report (default: {DEFAULT_OUTPUT_MD})",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_batch_results(path: Path) -> dict[str, dict[str, Any]]:
    payload = load_json(path)
    rows = payload.get("results", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError(f"{path} did not contain a top-level results list")
    results: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        case_id = row.get("case_id")
        if isinstance(case_id, str):
            results[case_id] = row
    return results


def first_candidate_repair(diagnostic_json: dict[str, Any]) -> dict[str, Any] | None:
    repairs = diagnostic_json.get("candidate_repairs") or []
    if not isinstance(repairs, list) or not repairs:
        return None
    repair = repairs[0]
    return repair if isinstance(repair, dict) else None


def normalize_text(*parts: str | None) -> str:
    return " ".join(part.strip() for part in parts if isinstance(part, str) and part.strip()).lower()


def classify_fix_type(
    *,
    predicted_taxonomy: str | None,
    candidate_repair_action: str | None,
    help_text: str | None,
    note_text: str | None,
    repair_hint: str | None,
    diagnostic_text: str | None,
) -> tuple[str, str]:
    text = normalize_text(help_text, repair_hint, note_text, diagnostic_text)
    action = candidate_repair_action or ""

    if action == "ADD_NULL_CHECK" or "null check" in text or "nullable" in text:
        return "null_check", "null-check signal"

    if (
        action == "GATE_BY_KERNEL_CAPABILITY"
        or predicted_taxonomy == "env_mismatch"
        or any(
            phrase in text
            for phrase in (
                "program type",
                "target kernel",
                "toolchain",
                "btf artifacts",
                "helper allowed",
                "current program type",
                "valid for the current program type",
                "map object itself as this argument",
                "move mutable state into an explicit map",
                "read the pid from the program context",
            )
        )
    ):
        return "env_fix", "environment-compatibility signal"

    if any(
        phrase in text
        for phrase in (
            "release or destroy the acquired reference",
            "release or destroy the acquired reference on every exit path",
            "release or discard the dynptr exactly once",
            "referenced object remains live at exit",
            "release or discard",
            "release on every exit path",
        )
    ):
        return "refcount", "lifetime/reference signal"

    if (
        "processed " in text and "insns" in text
        or "max-iteration" in text
        or "iteration counter" in text
        or "reduce the loop bounds" in text
    ):
        return "loop_rewrite", "loop/complexity signal"

    if (
        action == "SIMPLIFY_CFG"
        or any(
            phrase in text
            for phrase in (
                "smaller helpers",
                "tail-call stages",
                "hoist shared checks",
                "reduce branching fan-out",
            )
        )
    ):
        return "inline", "control-flow simplification signal"

    if any(
        phrase in text
        for phrase in (
            "balance save and restore operations",
            "move the subprogram/helper call out of the locked region",
            "unlock before calling",
            "invoke the callback through its owning helper",
            "re-derive the pointer from a verified base immediately before dereference",
            "re-derive the required pointer or reference from a verified source immediately before the failing use site",
        )
    ):
        return "reorder", "proof-restoration ordering signal"

    if any(
        phrase in text
        for phrase in (
            "initialize the iterator with the matching create/new helper",
            "keep dynptr values in a dedicated stack slot",
            "pass the dynptr at its exact stack slot",
            "pass a stack pointer for this argument",
            "pass data whose pointee is scalar-compatible",
            "zero the full struct or stack region before use",
            "keep the saved irq flag in a dedicated stack variable",
            "release or stop using derived slices/references before reinitializing",
            "keep iterator storage on the stack location expected by the api",
            "pass a stack-backed key pointer as arg2",
            "pass the original trusted pointer from the verifier-approved source",
        )
    ):
        return "other", "specialized contract signal"

    if help_text == "Add masking or explicit casts.":
        if action == "TIGHTEN_RANGE" or "invalid argument" in text:
            return "type_cast", "mask/cast tightening signal"
        return "bounds_check", "mask/cast fallback to bounds signal"

    if action == "ADD_BOUNDS_GUARD":
        if "computed offsets and sizes" in text or "clamp" in text:
            return "clamp", "offset/size clamp signal"
        return "bounds_check", "explicit bounds-guard signal"

    if "data_end" in text or "bounds check" in text:
        if "computed offsets and sizes" in text or "clamp" in text:
            return "clamp", "bounds-and-clamp text signal"
        return "bounds_check", "bounds text signal"

    if "mask" in text and "cast" not in text:
        return "mask", "masking signal"

    if any(
        phrase in text
        for phrase in (
            "explicit casts",
            "generic temporaries",
            "forged offset",
            "shifted or forged offset",
        )
    ):
        return "type_cast", "cast/temporary signal"

    if action == "TIGHTEN_RANGE" or any(
        phrase in text
        for phrase in (
            "clamp",
            "tighten",
            "narrow",
            "bounded unsigned",
        )
    ):
        return "clamp", "range-tightening signal"

    return "other", "fallback-other"


def evaluate_case(label: GroundTruthLabel, batch_row: dict[str, Any]) -> FixTypeCaseResult:
    diagnostic_json = batch_row.get("diagnostic_json") or {}
    metadata = diagnostic_json.get("metadata") or {}
    repair = first_candidate_repair(diagnostic_json)
    candidate_repair_action = (
        str(repair.get("action")) if repair and repair.get("action") is not None else None
    )
    repair_hint = (
        str(repair.get("patch_hint")) if repair and repair.get("patch_hint") is not None else None
    )
    help_text = str(metadata.get("help")) if metadata.get("help") is not None else None
    note_text = str(metadata.get("note")) if metadata.get("note") is not None else None
    predicted_taxonomy = (
        str(diagnostic_json.get("failure_class"))
        if diagnostic_json.get("failure_class") is not None
        else (str(batch_row.get("taxonomy_class")) if batch_row.get("taxonomy_class") is not None else None)
    )
    predicted_fix_type, mapping_rule = classify_fix_type(
        predicted_taxonomy=predicted_taxonomy,
        candidate_repair_action=candidate_repair_action,
        help_text=help_text,
        note_text=note_text,
        repair_hint=repair_hint,
        diagnostic_text=str(batch_row.get("diagnostic_text")) if batch_row.get("diagnostic_text") is not None else None,
    )
    gt_fix_type = label.fix_type or "other"
    return FixTypeCaseResult(
        case_id=label.case_id,
        gt_taxonomy_class=label.taxonomy_class,
        gt_fix_type=gt_fix_type,
        gt_fix_direction=label.fix_direction,
        bpfix_taxonomy_class=predicted_taxonomy,
        candidate_repair_action=candidate_repair_action,
        help_text=help_text,
        note_text=note_text,
        repair_hint=repair_hint,
        predicted_fix_type=predicted_fix_type,
        mapping_rule=mapping_rule,
        fix_type_match=predicted_fix_type == gt_fix_type,
    )


def metric_entry(count: int, denominator: int) -> dict[str, Any]:
    return {
        "count": count,
        "denominator": denominator,
        "rate": (count / denominator) if denominator else 0.0,
    }


def metric_str(metric: dict[str, Any]) -> str:
    return f"{metric['count']}/{metric['denominator']} ({metric['rate'] * 100.0:.1f}%)"


def ordered_labels(rows: list[FixTypeCaseResult]) -> list[str]:
    labels = list(FIX_TYPE_ORDER)
    extras = sorted(
        {
            row.gt_fix_type
            for row in rows
            if row.gt_fix_type not in FIX_TYPE_ORDER
        }
        | {
            row.predicted_fix_type
            for row in rows
            if row.predicted_fix_type not in FIX_TYPE_ORDER
        }
    )
    labels.extend(extras)
    return labels


def confusion_matrix(rows: list[FixTypeCaseResult], labels: list[str]) -> list[list[int]]:
    counter = Counter((row.gt_fix_type, row.predicted_fix_type) for row in rows)
    return [[counter.get((gt_label, pred_label), 0) for pred_label in labels] for gt_label in labels]


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_report(
    *,
    rows: list[FixTypeCaseResult],
    overall: dict[str, Any],
    by_taxonomy: dict[str, dict[str, Any]],
    labels: list[str],
    matrix: list[list[int]],
    prediction_distribution: Counter[str],
    mapping_rule_distribution: Counter[str],
) -> str:
    taxonomy_rows = [
        [
            f"`{taxonomy}`",
            metric_str(summary["fix_type_exact_match"]),
        ]
        for taxonomy, summary in [(taxonomy, by_taxonomy[taxonomy]) for taxonomy in TAXONOMY_ORDER if taxonomy in by_taxonomy]
    ]
    taxonomy_rows.extend(
        [
            [
                f"`{taxonomy}`",
                metric_str(summary["fix_type_exact_match"]),
            ]
            for taxonomy, summary in sorted(by_taxonomy.items())
            if taxonomy not in TAXONOMY_ORDER
        ]
    )

    matrix_rows = [
        [f"`{gt_label}`", *[str(value) for value in row_values]]
        for gt_label, row_values in zip(labels, matrix, strict=True)
    ]
    prediction_rows = [
        [f"`{label}`", str(prediction_distribution.get(label, 0))]
        for label in labels
        if prediction_distribution.get(label, 0)
    ]
    rule_rows = [
        [rule, str(count)]
        for rule, count in mapping_rule_distribution.most_common()
    ]

    return "\n".join(
        [
            "# Fix-Type Evaluation",
            "",
            f"- Generated at: `{now_iso()}`",
            f"- Evaluated labeled cases: `{overall['cases']}`",
            f"- Fix-type exact match: `{metric_str(overall['fix_type_exact_match'])}`",
            "",
            "## Match Rate By Taxonomy Class",
            "",
            markdown_table(["Ground-Truth Taxonomy", "Fix-Type Match"], taxonomy_rows),
            "",
            "## Predicted Fix-Type Distribution",
            "",
            markdown_table(["Predicted Fix Type", "Count"], prediction_rows),
            "",
            "## Confusion Matrix",
            "",
            markdown_table(["GT \\ Pred", *[f"`{label}`" for label in labels]], matrix_rows),
            "",
            "## Mapping Rules Used",
            "",
            markdown_table(["Rule", "Cases"], rule_rows),
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    ground_truth_labels = load_ground_truth_labels(args.ground_truth_path, include_quarantined=False)
    batch_results = load_batch_results(args.batch_results_path)

    missing_results = sorted(case_id for case_id in ground_truth_labels if case_id not in batch_results)
    if missing_results:
        raise KeyError(
            "Missing batch-diagnostic results for ground-truth cases: "
            + ", ".join(missing_results[:10])
            + ("..." if len(missing_results) > 10 else "")
        )

    rows = [
        evaluate_case(label, batch_results[label.case_id])
        for label in ground_truth_labels.values()
        if label.fix_type is not None
    ]

    overall = {
        "cases": len(rows),
        "fix_type_exact_match": metric_entry(sum(row.fix_type_match for row in rows), len(rows)),
    }

    by_taxonomy: dict[str, dict[str, Any]] = {}
    for taxonomy in sorted({row.gt_taxonomy_class for row in rows}):
        subset = [row for row in rows if row.gt_taxonomy_class == taxonomy]
        by_taxonomy[taxonomy] = {
            "cases": len(subset),
            "fix_type_exact_match": metric_entry(sum(row.fix_type_match for row in subset), len(subset)),
        }

    labels = ordered_labels(rows)
    matrix = confusion_matrix(rows, labels)
    prediction_distribution = Counter(row.predicted_fix_type for row in rows)
    mapping_rule_distribution = Counter(row.mapping_rule for row in rows)

    payload = {
        "generated_at": now_iso(),
        "inputs": {
            "ground_truth_path": str(args.ground_truth_path),
            "batch_results_path": str(args.batch_results_path),
        },
        "overall": overall,
        "by_gt_taxonomy_class": by_taxonomy,
        "prediction_distribution": dict(prediction_distribution),
        "mapping_rule_distribution": dict(mapping_rule_distribution),
        "confusion_matrix": {
            "labels": labels,
            "rows": matrix,
        },
        "cases": [asdict(row) for row in rows],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(
        build_report(
            rows=rows,
            overall=overall,
            by_taxonomy=by_taxonomy,
            labels=labels,
            matrix=matrix,
            prediction_distribution=prediction_distribution,
            mapping_rule_distribution=mapping_rule_distribution,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
