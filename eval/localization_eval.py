#!/usr/bin/env python3
"""Evaluate BPFix localization spans against the canonical ground truth."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.ground_truth import DEFAULT_GROUND_TRUTH_PATH, GroundTruthLabel, load_ground_truth_labels
from eval.source_strata import STRATUM_LABELS, STRATUM_ORDER, case_source


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
    bpfix_has_any_earlier_span: bool
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
        if isinstance(insn_range, list) and insn_range and isinstance(insn_range[0], int):
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
    any_earlier_span = bool(non_rejected_spans) and rejected is not None and min(non_rejected_spans) < rejected

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
        bpfix_has_any_earlier_span=any_earlier_span,
        bpfix_has_earlier_non_rejected_span=any_earlier_span,
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


def metric_entry(count: int, denominator: int, *, na_when_zero: bool = False) -> dict[str, Any]:
    rate = None if na_when_zero and denominator == 0 else ((count / denominator) if denominator else 0.0)
    return {
        "count": count,
        "denominator": denominator,
        "rate": rate,
    }


def metric_str(metric: dict[str, Any]) -> str:
    count = int(metric["count"])
    denominator = int(metric["denominator"])
    rate = metric["rate"]
    if rate is None:
        return f"{count}/{denominator} (n/a)"
    return f"{count}/{denominator} ({(100.0 * rate):.1f}%)"


def mean_or_none(values: list[int | None]) -> float | None:
    concrete = [value for value in values if value is not None]
    if not concrete:
        return None
    return round(sum(concrete) / len(concrete), 2)


def summarize_subset(rows: list[CaseLocalizationResult]) -> dict[str, Any]:
    proof_lost_rows = [row for row in rows if row.proof_lost_span_present]
    return {
        "cases": len(rows),
        "gt_root_before_reject": sum(row.gt_root_before_reject for row in rows),
        "gt_root_after_reject": sum(row.gt_root_after_reject for row in rows),
        "coverage": {
            "proof_lost": metric_entry(sum(row.proof_lost_span_present for row in rows), len(rows)),
            "any_earlier_span": metric_entry(sum(row.bpfix_has_any_earlier_span for row in rows), len(rows)),
            "proof_established": metric_entry(sum(row.proof_established_span_present for row in rows), len(rows)),
            "rejected": metric_entry(sum(row.rejected_span_present for row in rows), len(rows)),
        },
        "accuracy_given_proof_lost": {
            "cases": len(proof_lost_rows),
            "exact": metric_entry(sum(row.proof_lost_exact_match for row in proof_lost_rows), len(proof_lost_rows), na_when_zero=True),
            "within_5": metric_entry(sum(row.proof_lost_within_5 for row in proof_lost_rows), len(proof_lost_rows), na_when_zero=True),
            "within_10": metric_entry(sum(row.proof_lost_within_10 for row in proof_lost_rows), len(proof_lost_rows), na_when_zero=True),
            "mean_abs_error": mean_or_none([row.proof_lost_abs_error for row in proof_lost_rows]),
        },
        "end_to_end": {
            "exact": metric_entry(sum(row.proof_lost_exact_match for row in rows), len(rows)),
            "within_5": metric_entry(sum(row.proof_lost_within_5 for row in rows), len(rows)),
            "within_10": metric_entry(sum(row.proof_lost_within_10 for row in rows), len(rows)),
        },
        "rejected_exact_match": metric_entry(sum(row.rejected_exact_match for row in rows), len(rows)),
        "mean_rejected_abs_error": mean_or_none([row.rejected_abs_error for row in rows]),
    }


def summarize_source_strata(rows: list[CaseLocalizationResult]) -> dict[str, dict[str, Any]]:
    subsets = {
        "selftest_cases": [row for row in rows if case_source(row.case_id) == "kernel_selftests"],
        "real_world_cases": [
            row
            for row in rows
            if case_source(row.case_id) in {"stackoverflow", "github_issues"}
        ],
        "all_cases": list(rows),
    }
    return {
        stratum: summarize_subset(subset_rows)
        for stratum, subset_rows in subsets.items()
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


def build_conditional_accuracy_rows(
    overall: dict[str, Any],
    has_proof_lost: dict[str, Any],
    no_proof_lost: dict[str, Any],
) -> list[list[str]]:
    return [
        [
            "Proof-lost coverage",
            metric_str(overall["coverage"]["proof_lost"]),
            metric_str(has_proof_lost["coverage"]["proof_lost"]),
            metric_str(no_proof_lost["coverage"]["proof_lost"]),
        ],
        [
            "Any-earlier coverage",
            metric_str(overall["coverage"]["any_earlier_span"]),
            metric_str(has_proof_lost["coverage"]["any_earlier_span"]),
            metric_str(no_proof_lost["coverage"]["any_earlier_span"]),
        ],
        [
            "Exact GT root match",
            metric_str(overall["end_to_end"]["exact"]),
            metric_str(has_proof_lost["accuracy_given_proof_lost"]["exact"]),
            metric_str(no_proof_lost["accuracy_given_proof_lost"]["exact"]),
        ],
        [
            "Within 5 insns",
            metric_str(overall["end_to_end"]["within_5"]),
            metric_str(has_proof_lost["accuracy_given_proof_lost"]["within_5"]),
            metric_str(no_proof_lost["accuracy_given_proof_lost"]["within_5"]),
        ],
        [
            "Within 10 insns",
            metric_str(overall["end_to_end"]["within_10"]),
            metric_str(has_proof_lost["accuracy_given_proof_lost"]["within_10"]),
            metric_str(no_proof_lost["accuracy_given_proof_lost"]["within_10"]),
        ],
    ]


def build_breakdown_rows(summary_by_key: dict[str, dict[str, Any]], order: tuple[str, ...]) -> list[list[str]]:
    rows: list[list[str]] = []
    for key, summary in ordered_items(summary_by_key, order):
        rows.append(
            [
                f"`{key}`",
                str(summary["cases"]),
                metric_str(summary["coverage"]["proof_lost"]),
                metric_str(summary["coverage"]["any_earlier_span"]),
                metric_str(summary["accuracy_given_proof_lost"]["exact"]),
                metric_str(summary["accuracy_given_proof_lost"]["within_5"]),
                metric_str(summary["accuracy_given_proof_lost"]["within_10"]),
            ]
        )
    return rows


def build_source_stratum_rows(by_source_stratum: dict[str, dict[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for stratum in STRATUM_ORDER:
        summary = by_source_stratum[stratum]
        rows.append(
            [
                STRATUM_LABELS[stratum],
                str(summary["cases"]),
                metric_str(summary["coverage"]["proof_lost"]),
                metric_str(summary["coverage"]["any_earlier_span"]),
                metric_str(summary["end_to_end"]["exact"]),
                metric_str(summary["end_to_end"]["within_5"]),
                metric_str(summary["end_to_end"]["within_10"]),
                metric_str(summary["rejected_exact_match"]),
            ]
        )
    return rows


def build_nonzero_focus_rows(rows: list[CaseLocalizationResult]) -> list[list[str]]:
    table_rows: list[list[str]] = []
    for row in sorted(rows, key=lambda item: (item.distance_insns, item.case_id), reverse=True):
        table_rows.append(
            [
                f"`{row.case_id}`",
                f"`{row.taxonomy_class}`",
                str(row.gt_root_cause_insn_idx),
                str(row.gt_rejected_insn_idx),
                str(row.bpfix_proof_lost_insn_idx) if row.bpfix_proof_lost_insn_idx is not None else "n/a",
                str(row.bpfix_proof_established_insn_idx) if row.bpfix_proof_established_insn_idx is not None else "n/a",
                str(row.bpfix_rejected_insn_idx) if row.bpfix_rejected_insn_idx is not None else "n/a",
                "Yes" if row.bpfix_has_any_earlier_span else "No",
                "Yes" if row.proof_lost_exact_match else "No",
                "Yes" if row.proof_lost_within_5 else "No",
                "Yes" if row.proof_lost_within_10 else "No",
            ]
        )
    return table_rows


def build_report(
    *,
    results: list[CaseLocalizationResult],
    overall: dict[str, Any],
    has_proof_lost: dict[str, Any],
    no_proof_lost: dict[str, Any],
    by_source_stratum: dict[str, dict[str, Any]],
    by_taxonomy: dict[str, dict[str, Any]],
    by_distance_bucket: dict[str, dict[str, Any]],
    nonzero_distance_summary: dict[str, Any],
    nonzero_with_any_earlier_summary: dict[str, Any],
) -> str:
    nonzero_distance_rows = [row for row in results if row.distance_insns > 0]
    later_root_cases = [row.case_id for row in nonzero_distance_rows if row.gt_root_after_reject]

    lines = [
        "# Localization Evaluation",
        "",
        f"- Generated at: `{now_iso()}`",
        f"- Evaluated non-quarantined ground-truth cases: `{overall['cases']}`",
        f"- Cases with `root_cause_insn_idx != rejected_insn_idx`: `{nonzero_distance_summary['cases']}`",
        f"- Earlier-root cases (`root_cause_insn_idx < rejected_insn_idx`): `{overall['gt_root_before_reject']}`",
        f"- Later-root cases (`root_cause_insn_idx > rejected_insn_idx`): `{overall['gt_root_after_reject']}`",
        "",
        "## Coverage Metrics",
        "",
        f"- Proof-lost span emitted: `{metric_str(overall['coverage']['proof_lost'])}`",
        f"- Any earlier span before the rejected span: `{metric_str(overall['coverage']['any_earlier_span'])}`",
        f"- Proof-established span emitted: `{metric_str(overall['coverage']['proof_established'])}`",
        f"- Rejected span emitted: `{metric_str(overall['coverage']['rejected'])}`",
        f"- Rejected span exact match: `{metric_str(overall['rejected_exact_match'])}`",
        "",
        "## Accuracy When `proof_lost` Is Present",
        "",
        f"- Cases with `proof_lost`: `{has_proof_lost['cases']}`",
        f"- Exact GT root-cause match: `{metric_str(has_proof_lost['accuracy_given_proof_lost']['exact'])}`",
        f"- Within 5 instructions: `{metric_str(has_proof_lost['accuracy_given_proof_lost']['within_5'])}`",
        f"- Within 10 instructions: `{metric_str(has_proof_lost['accuracy_given_proof_lost']['within_10'])}`",
        f"- Mean absolute error on `proof_lost` cases: `{has_proof_lost['accuracy_given_proof_lost']['mean_abs_error']}`" if has_proof_lost["accuracy_given_proof_lost"]["mean_abs_error"] is not None else "- Mean absolute error on `proof_lost` cases: `n/a`",
        "",
        "## Conditional Accuracy Table",
        "",
        "- `All` uses end-to-end denominators over all labeled cases; `Has proof_lost` is the conditional root-cause accuracy slice.",
        "",
        markdown_table(
            [
                "Metric",
                f"All (N={overall['cases']})",
                f"Has proof_lost (N={has_proof_lost['cases']})",
                f"No proof_lost (N={no_proof_lost['cases']})",
            ],
            build_conditional_accuracy_rows(overall, has_proof_lost, no_proof_lost),
        ),
        "",
        "## By Source Stratum",
        "",
        markdown_table(
            [
                "Stratum",
                "Cases",
                "Proof-lost Coverage",
                "Any-earlier Coverage",
                "Exact (all cases)",
                "Within 5 (all cases)",
                "Within 10 (all cases)",
                "Rejected Exact",
            ],
            build_source_stratum_rows(by_source_stratum),
        ),
        "",
        "## By Taxonomy Class",
        "",
        markdown_table(
            [
                "Taxonomy",
                "Cases",
                "Proof-lost Coverage",
                "Any-earlier Coverage",
                "Exact (proof_lost)",
                "Within 5 (proof_lost)",
                "Within 10 (proof_lost)",
            ],
            build_breakdown_rows(by_taxonomy, TAXONOMY_ORDER),
        ),
        "",
        "## By Distance Bucket",
        "",
        markdown_table(
            [
                "Distance",
                "Cases",
                "Proof-lost Coverage",
                "Any-earlier Coverage",
                "Exact (proof_lost)",
                "Within 5 (proof_lost)",
                "Within 10 (proof_lost)",
            ],
            build_breakdown_rows(by_distance_bucket, DISTANCE_BUCKET_ORDER),
        ),
        "",
        "## Distance Analysis",
        "",
        f"- Nonzero-distance cases: `{nonzero_distance_summary['cases']}`",
        f"- Any earlier span on nonzero-distance cases: `{metric_str(nonzero_distance_summary['coverage']['any_earlier_span'])}`",
        f"- Any earlier span on earlier-root cases only: `{metric_str(metric_entry(nonzero_with_any_earlier_summary['cases'], nonzero_distance_summary['gt_root_before_reject']))}`",
        f"- Cases with any earlier span in the nonzero-distance slice: `{nonzero_with_any_earlier_summary['cases']}`",
        f"- Exact GT root-cause match among that earlier-span slice: `{metric_str(nonzero_with_any_earlier_summary['accuracy_given_proof_lost']['exact'])}`",
        f"- Within 5 instructions among that earlier-span slice: `{metric_str(nonzero_with_any_earlier_summary['accuracy_given_proof_lost']['within_5'])}`",
        f"- Within 10 instructions among that earlier-span slice: `{metric_str(nonzero_with_any_earlier_summary['accuracy_given_proof_lost']['within_10'])}`",
        "- Note: the current labeled set has one later-root outlier where the ground-truth root cause is after the reject site."
        if later_root_cases
        else "- Note: all nonzero-distance cases are earlier-root cases.",
    ]
    if later_root_cases:
        lines.append(f"- Later-root outlier(s): `{', '.join(later_root_cases)}`")
    lines.extend(
        (
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
                    "Any Earlier?",
                    "Exact",
                    "Within 5",
                    "Within 10",
                ],
                build_nonzero_focus_rows(nonzero_distance_rows),
            ),
            "",
        )
    )
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

    overall = summarize_subset(results)
    has_proof_lost_rows = [row for row in results if row.proof_lost_span_present]
    no_proof_lost_rows = [row for row in results if not row.proof_lost_span_present]
    has_proof_lost = summarize_subset(has_proof_lost_rows)
    no_proof_lost = summarize_subset(no_proof_lost_rows)
    by_source_stratum = summarize_source_strata(results)

    by_taxonomy: dict[str, dict[str, Any]] = {}
    for taxonomy_class in sorted({row.taxonomy_class for row in results}):
        by_taxonomy[taxonomy_class] = summarize_subset(
            [row for row in results if row.taxonomy_class == taxonomy_class]
        )

    by_distance_bucket: dict[str, dict[str, Any]] = {}
    for bucket in sorted({row.distance_bucket for row in results}):
        by_distance_bucket[bucket] = summarize_subset(
            [row for row in results if row.distance_bucket == bucket]
        )

    nonzero_distance_rows = [row for row in results if row.distance_insns > 0]
    nonzero_distance_summary = summarize_subset(nonzero_distance_rows)
    nonzero_with_any_earlier_rows = [row for row in nonzero_distance_rows if row.bpfix_has_any_earlier_span]
    nonzero_with_any_earlier_summary = summarize_subset(nonzero_with_any_earlier_rows)

    payload = {
        "generated_at": now_iso(),
        "inputs": {
            "ground_truth_path": str(args.ground_truth_path),
            "batch_results_path": str(args.batch_results_path),
        },
        "overall": overall,
        "has_proof_lost": has_proof_lost,
        "no_proof_lost": no_proof_lost,
        "by_source_stratum": by_source_stratum,
        "conditional_accuracy_table": {
            "all_cases": overall,
            "has_proof_lost": has_proof_lost,
            "no_proof_lost": no_proof_lost,
        },
        "by_taxonomy_class": by_taxonomy,
        "by_distance_bucket": by_distance_bucket,
        "distance_analysis": {
            "nonzero_distance": nonzero_distance_summary,
            "nonzero_with_any_earlier_span": nonzero_with_any_earlier_summary,
            "later_root_case_ids": [row.case_id for row in nonzero_distance_rows if row.gt_root_after_reject],
        },
        "cases": [asdict(row) for row in results],
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(
        build_report(
            results=results,
            overall=overall,
            has_proof_lost=has_proof_lost,
            no_proof_lost=no_proof_lost,
            by_source_stratum=by_source_stratum,
            by_taxonomy=by_taxonomy,
            by_distance_bucket=by_distance_bucket,
            nonzero_distance_summary=nonzero_distance_summary,
            nonzero_with_any_earlier_summary=nonzero_with_any_earlier_summary,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
