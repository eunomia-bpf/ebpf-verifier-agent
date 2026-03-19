#!/usr/bin/env python3
"""Evaluate BPFix localization spans against the canonical ground truth."""

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
DEFAULT_OUTPUT_JSON = ROOT / "eval" / "results" / "localization_eval.json"
DEFAULT_OUTPUT_MD = ROOT / "docs" / "tmp" / "localization-eval-report.md"
TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
)
DISTANCE_BUCKET_ORDER = ("0", "1-5", "6-10", "11-25", "26+")


@dataclass(slots=True)
class CaseLocalizationResult:
    case_id: str
    taxonomy_class: str
    distance_insns: int
    distance_bucket: str
    gt_root_before_reject: bool
    gt_root_after_reject: bool
    gt_root_cause_insn_idx: int
    gt_rejected_insn_idx: int
    bpfix_proof_lost_insn_idx: int | None
    bpfix_proof_established_insn_idx: int | None
    bpfix_rejected_insn_idx: int | None
    bpfix_has_earlier_non_rejected_span: bool
    proof_lost_exact_match: bool
    proof_lost_within_5: bool
    proof_lost_within_10: bool
    proof_lost_abs_error: int | None
    rejected_exact_match: bool
    rejected_abs_error: int | None
    proof_lost_span_present: bool
    proof_established_span_present: bool
    rejected_span_present: bool


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


def distance_bucket(distance: int) -> str:
    if distance == 0:
        return "0"
    if distance <= 5:
        return "1-5"
    if distance <= 10:
        return "6-10"
    if distance <= 25:
        return "11-25"
    return "26+"


def extract_role_insn(spans: list[dict[str, Any]], role: str) -> int | None:
    for span in spans:
        if not isinstance(span, dict) or span.get("role") != role:
            continue
        insn_range = span.get("insn_range")
        if (
            isinstance(insn_range, list)
            and insn_range
            and isinstance(insn_range[0], int)
        ):
            return insn_range[0]
    return None


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


def evaluate_case(label: GroundTruthLabel, batch_row: dict[str, Any]) -> CaseLocalizationResult:
    diagnostic_json = batch_row.get("diagnostic_json") or {}
    metadata = diagnostic_json.get("metadata") or {}
    spans = metadata.get("proof_spans") or []
    if not isinstance(spans, list):
        spans = []

    proof_lost = extract_role_insn(spans, "proof_lost")
    proof_established = extract_role_insn(spans, "proof_established")
    rejected = extract_role_insn(spans, "rejected")
    non_rejected_spans = [insn for insn in (proof_lost, proof_established) if insn is not None]
    earlier_non_rejected_span = (
        bool(non_rejected_spans)
        and rejected is not None
        and min(non_rejected_spans) < rejected
    )

    proof_lost_abs_error = (
        abs(proof_lost - label.root_cause_insn_idx)
        if proof_lost is not None and label.root_cause_insn_idx is not None
        else None
    )
    rejected_abs_error = (
        abs(rejected - label.rejected_insn_idx)
        if rejected is not None and label.rejected_insn_idx is not None
        else None
    )

    return CaseLocalizationResult(
        case_id=label.case_id,
        taxonomy_class=label.taxonomy_class,
        distance_insns=label.distance_insns or 0,
        distance_bucket=distance_bucket(label.distance_insns or 0),
        gt_root_before_reject=bool(
            label.root_cause_insn_idx is not None
            and label.rejected_insn_idx is not None
            and label.root_cause_insn_idx < label.rejected_insn_idx
        ),
        gt_root_after_reject=bool(
            label.root_cause_insn_idx is not None
            and label.rejected_insn_idx is not None
            and label.root_cause_insn_idx > label.rejected_insn_idx
        ),
        gt_root_cause_insn_idx=label.root_cause_insn_idx or 0,
        gt_rejected_insn_idx=label.rejected_insn_idx or 0,
        bpfix_proof_lost_insn_idx=proof_lost,
        bpfix_proof_established_insn_idx=proof_established,
        bpfix_rejected_insn_idx=rejected,
        bpfix_has_earlier_non_rejected_span=earlier_non_rejected_span,
        proof_lost_exact_match=proof_lost == label.root_cause_insn_idx,
        proof_lost_within_5=proof_lost_abs_error is not None and proof_lost_abs_error <= 5,
        proof_lost_within_10=proof_lost_abs_error is not None and proof_lost_abs_error <= 10,
        proof_lost_abs_error=proof_lost_abs_error,
        rejected_exact_match=rejected == label.rejected_insn_idx,
        rejected_abs_error=rejected_abs_error,
        proof_lost_span_present=proof_lost is not None,
        proof_established_span_present=proof_established is not None,
        rejected_span_present=rejected is not None,
    )


def rate_str(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0/0 (n/a)"
    return f"{numerator}/{denominator} ({(100.0 * numerator / denominator):.1f}%)"


def summarize_group(rows: list[CaseLocalizationResult]) -> dict[str, Any]:
    proof_lost_present = [row for row in rows if row.proof_lost_span_present]
    rejected_present = [row for row in rows if row.rejected_span_present]
    gt_earlier = [row for row in rows if row.gt_root_before_reject]
    gt_later = [row for row in rows if row.gt_root_after_reject]
    proof_lost_errors = [
        row.proof_lost_abs_error
        for row in proof_lost_present
        if row.proof_lost_abs_error is not None
    ]
    rejected_errors = [
        row.rejected_abs_error
        for row in rejected_present
        if row.rejected_abs_error is not None
    ]

    return {
        "cases": len(rows),
        "proof_lost_present": len(proof_lost_present),
        "proof_established_present": sum(row.proof_established_span_present for row in rows),
        "rejected_present": len(rejected_present),
        "proof_lost_exact_match": sum(row.proof_lost_exact_match for row in rows),
        "proof_lost_within_5": sum(row.proof_lost_within_5 for row in rows),
        "proof_lost_within_10": sum(row.proof_lost_within_10 for row in rows),
        "rejected_exact_match": sum(row.rejected_exact_match for row in rows),
        "gt_root_before_reject": len(gt_earlier),
        "gt_root_after_reject": len(gt_later),
        "bpfix_found_earlier_span": sum(row.bpfix_has_earlier_non_rejected_span for row in gt_earlier),
        "mean_proof_lost_abs_error": (
            round(sum(proof_lost_errors) / len(proof_lost_errors), 2)
            if proof_lost_errors
            else None
        ),
        "mean_rejected_abs_error": (
            round(sum(rejected_errors) / len(rejected_errors), 2)
            if rejected_errors
            else None
        ),
    }


def ordered_items(summary: dict[str, dict[str, Any]], order: tuple[str, ...]) -> list[tuple[str, dict[str, Any]]]:
    keys = [key for key in order if key in summary]
    keys.extend(sorted(key for key in summary if key not in keys))
    return [(key, summary[key]) for key in keys]


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_report(
    *,
    results: list[CaseLocalizationResult],
    overall: dict[str, Any],
    by_taxonomy: dict[str, dict[str, Any]],
    by_distance_bucket: dict[str, dict[str, Any]],
    nonzero_distance_summary: dict[str, Any],
) -> str:
    total_nonzero = sum(1 for row in results if row.distance_insns > 0)
    gt_earlier = sum(row.gt_root_before_reject for row in results)
    gt_later = sum(row.gt_root_after_reject for row in results)

    taxonomy_rows = []
    for taxonomy_class, summary in ordered_items(by_taxonomy, TAXONOMY_ORDER):
        taxonomy_rows.append(
            [
                f"`{taxonomy_class}`",
                str(summary["cases"]),
                rate_str(summary["proof_lost_exact_match"], summary["cases"]),
                rate_str(summary["proof_lost_within_5"], summary["cases"]),
                rate_str(summary["proof_lost_within_10"], summary["cases"]),
                rate_str(summary["rejected_exact_match"], summary["cases"]),
            ]
        )

    distance_rows = []
    for bucket, summary in ordered_items(by_distance_bucket, DISTANCE_BUCKET_ORDER):
        distance_rows.append(
            [
                f"`{bucket}`",
                str(summary["cases"]),
                rate_str(summary["proof_lost_exact_match"], summary["cases"]),
                rate_str(summary["proof_lost_within_5"], summary["cases"]),
                rate_str(summary["proof_lost_within_10"], summary["cases"]),
                rate_str(summary["rejected_exact_match"], summary["cases"]),
            ]
        )

    focus_rows = []
    for row in sorted(
        [item for item in results if item.distance_insns > 0],
        key=lambda item: (item.distance_insns, item.case_id),
        reverse=True,
    ):
        focus_rows.append(
            [
                f"`{row.case_id}`",
                f"`{row.taxonomy_class}`",
                str(row.gt_root_cause_insn_idx),
                str(row.gt_rejected_insn_idx),
                str(row.bpfix_proof_lost_insn_idx) if row.bpfix_proof_lost_insn_idx is not None else "n/a",
                str(row.bpfix_proof_established_insn_idx) if row.bpfix_proof_established_insn_idx is not None else "n/a",
                str(row.bpfix_rejected_insn_idx) if row.bpfix_rejected_insn_idx is not None else "n/a",
                "Yes" if row.proof_lost_exact_match else "No",
                "Yes" if row.proof_lost_within_5 else "No",
                "Yes" if row.bpfix_has_earlier_non_rejected_span else "No",
            ]
        )

    lines = [
        "# Localization Evaluation",
        "",
        f"- Generated at: `{now_iso()}`",
        f"- Evaluated non-quarantined ground-truth cases: `{overall['cases']}`",
        f"- Cases with `root_cause_insn_idx != rejected_insn_idx`: `{total_nonzero}`",
        f"- Earlier-root cases (`root_cause_insn_idx < rejected_insn_idx`): `{gt_earlier}`",
        f"- Later-root cases (`root_cause_insn_idx > rejected_insn_idx`): `{gt_later}`",
        "",
        "## Overall",
        "",
        f"- Proof-lost span present: `{rate_str(overall['proof_lost_present'], overall['cases'])}`",
        f"- Proof-lost exact match: `{rate_str(overall['proof_lost_exact_match'], overall['cases'])}`",
        f"- Proof-lost within 5 instructions: `{rate_str(overall['proof_lost_within_5'], overall['cases'])}`",
        f"- Proof-lost within 10 instructions: `{rate_str(overall['proof_lost_within_10'], overall['cases'])}`",
        f"- Rejected span exact match: `{rate_str(overall['rejected_exact_match'], overall['cases'])}`",
        f"- Earlier-span found on earlier-root cases: `{rate_str(overall['bpfix_found_earlier_span'], overall['gt_root_before_reject'])}`",
        "",
        "## By Taxonomy Class",
        "",
        markdown_table(
            ["Taxonomy", "Cases", "Exact", "Within 5", "Within 10", "Rejected Exact"],
            taxonomy_rows,
        ),
        "",
        "## By Distance Bucket",
        "",
        markdown_table(
            ["Distance", "Cases", "Exact", "Within 5", "Within 10", "Rejected Exact"],
            distance_rows,
        ),
        "",
        "## Nonzero-Distance Focus",
        "",
        f"- Nonzero-distance cases: `{nonzero_distance_summary['cases']}`",
        f"- Proof-lost exact match: `{rate_str(nonzero_distance_summary['proof_lost_exact_match'], nonzero_distance_summary['cases'])}`",
        f"- Proof-lost within 5 instructions: `{rate_str(nonzero_distance_summary['proof_lost_within_5'], nonzero_distance_summary['cases'])}`",
        f"- Proof-lost within 10 instructions: `{rate_str(nonzero_distance_summary['proof_lost_within_10'], nonzero_distance_summary['cases'])}`",
        f"- Earlier-span found on earlier-root cases: `{rate_str(nonzero_distance_summary['bpfix_found_earlier_span'], nonzero_distance_summary['gt_root_before_reject'])}`",
        "- Note: `distance_insns > 0` is not always an earlier-root case in the canonical labels. In the current ground truth there is one later-root case: `stackoverflow-74178703` (`root=204`, `reject=195`).",
        "",
        markdown_table(
            [
                "Case",
                "Taxonomy",
                "GT Root",
                "GT Reject",
                "BPFix Lost",
                "BPFix Est",
                "BPFix Reject",
                "Exact",
                "Within 5",
                "Earlier Span?",
            ],
            focus_rows,
        ),
        "",
    ]
    return "\n".join(lines)


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

    results = [
        evaluate_case(label, batch_results[label.case_id])
        for label in ground_truth_labels.values()
        if label.root_cause_insn_idx is not None and label.rejected_insn_idx is not None
    ]

    by_taxonomy: dict[str, dict[str, Any]] = {}
    for taxonomy_class in sorted({row.taxonomy_class for row in results}):
        by_taxonomy[taxonomy_class] = summarize_group(
            [row for row in results if row.taxonomy_class == taxonomy_class]
        )

    by_distance_bucket: dict[str, dict[str, Any]] = {}
    for bucket in sorted({row.distance_bucket for row in results}):
        by_distance_bucket[bucket] = summarize_group(
            [row for row in results if row.distance_bucket == bucket]
        )

    overall = summarize_group(results)
    nonzero_distance_rows = [row for row in results if row.distance_insns > 0]
    nonzero_distance_summary = summarize_group(nonzero_distance_rows)

    payload = {
        "generated_at": now_iso(),
        "inputs": {
            "ground_truth_path": str(args.ground_truth_path),
            "batch_results_path": str(args.batch_results_path),
        },
        "overall": overall,
        "by_taxonomy_class": by_taxonomy,
        "by_distance_bucket": by_distance_bucket,
        "nonzero_distance_focus": nonzero_distance_summary,
        "cases": [asdict(row) for row in results],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(
        build_report(
            results=results,
            overall=overall,
            by_taxonomy=by_taxonomy,
            by_distance_bucket=by_distance_bucket,
            nonzero_distance_summary=nonzero_distance_summary,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
