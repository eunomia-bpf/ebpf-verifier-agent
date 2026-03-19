#!/usr/bin/env python3
"""Build a unified comparison report for BPFix, the baseline, and ablations."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "ablation_results.json"
DEFAULT_MANIFEST_PATH = ROOT / "case_study" / "eval_manifest.yaml"
DEFAULT_LABELS_PATH = ROOT / "case_study" / "ground_truth.yaml"
ARCHIVE_LABELS_PATH = ROOT / "case_study" / "archive" / "ground_truth_labels.yaml"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "comparison-report-2026-03-18.md"
METHOD_ORDER = ("bpfix", "baseline", "ablation_a", "ablation_b", "ablation_c")
METHOD_LABELS = {
    "bpfix": "BPFix",
    "baseline": "Baseline",
    "ablation_a": "Ablation A",
    "ablation_b": "Ablation B",
    "ablation_c": "Ablation C",
}
CLASS_ORDER = ("source_bug", "lowering_artifact", "env_mismatch", "verifier_limit")


@dataclass(slots=True)
class AccuracySummary:
    correct: int
    total: int
    accuracy: float
    ci_low: float
    ci_high: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument(
        "--labels-path",
        type=Path,
        default=None,
        help="Optional explicit labels file. Defaults to ground_truth.yaml.",
    )
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_labels_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    return DEFAULT_LABELS_PATH


def ratio_str(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0/0"
    return f"{numerator}/{denominator}"


def pct(value: float) -> str:
    return f"{value * 100.0:.1f}%"


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def wilson_interval(correct: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    phat = correct / total
    denominator = 1.0 + (z * z) / total
    centre = phat + (z * z) / (2.0 * total)
    margin = z * math.sqrt((phat * (1.0 - phat) / total) + (z * z) / (4.0 * total * total))
    low = max(0.0, (centre - margin) / denominator)
    high = min(1.0, (centre + margin) / denominator)
    return low, high


def accuracy_summary(predictions: dict[str, str], truth: dict[str, str], case_ids: list[str]) -> AccuracySummary:
    correct = sum(1 for case_id in case_ids if predictions.get(case_id) == truth.get(case_id))
    total = len(case_ids)
    low, high = wilson_interval(correct, total)
    return AccuracySummary(
        correct=correct,
        total=total,
        accuracy=(correct / total) if total else 0.0,
        ci_low=low,
        ci_high=high,
    )


def precision_recall_f1(
    predictions: dict[str, str],
    truth: dict[str, str],
    case_ids: list[str],
    target_class: str,
) -> tuple[float, float, float, int, int, int]:
    tp = sum(
        1
        for case_id in case_ids
        if predictions.get(case_id) == target_class and truth.get(case_id) == target_class
    )
    fp = sum(
        1
        for case_id in case_ids
        if predictions.get(case_id) == target_class and truth.get(case_id) != target_class
    )
    fn = sum(
        1
        for case_id in case_ids
        if predictions.get(case_id) != target_class and truth.get(case_id) == target_class
    )
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1, tp, fp, fn


def mcnemar_exact(
    left: dict[str, str],
    right: dict[str, str],
    truth: dict[str, str],
    case_ids: list[str],
) -> dict[str, Any]:
    left_only = sum(
        1
        for case_id in case_ids
        if left.get(case_id) == truth.get(case_id) and right.get(case_id) != truth.get(case_id)
    )
    right_only = sum(
        1
        for case_id in case_ids
        if right.get(case_id) == truth.get(case_id) and left.get(case_id) != truth.get(case_id)
    )
    total = left_only + right_only
    if total == 0:
        return {"left_only": left_only, "right_only": right_only, "p_value": 1.0}
    tail = sum(math.comb(total, k) for k in range(0, min(left_only, right_only) + 1)) / (2 ** total)
    return {
        "left_only": left_only,
        "right_only": right_only,
        "p_value": min(1.0, 2.0 * tail),
    }


def labels_by_case(path: Path) -> dict[str, str]:
    payload = load_yaml(path) or {}
    rows = payload.get("cases", []) if isinstance(payload, dict) else payload
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("quarantined"):
            continue
        case_id = row.get("case_id")
        taxonomy = row.get("taxonomy") or row.get("taxonomy_class")
        if case_id and taxonomy:
            result[str(case_id)] = str(taxonomy)
    return result


def manifest_case_sets(path: Path) -> tuple[list[str], list[str]]:
    manifest = list(load_yaml(path) or [])
    eligible_ids: list[str] = []
    core_ids: list[str] = []
    for row in manifest:
        if not isinstance(row, dict) or not row.get("eligible"):
            continue
        case_id = str(row.get("case_id"))
        eligible_ids.append(case_id)
        if row.get("eval_split") == "core":
            core_ids.append(case_id)
    return eligible_ids, core_ids


def results_by_case(path: Path) -> dict[str, dict[str, Any]]:
    payload = load_json(path) or {}
    rows = payload.get("cases", []) if isinstance(payload, dict) else []
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        case_id = row.get("case_id")
        if case_id:
            result[str(case_id)] = row
    return result


def method_predictions(results: dict[str, dict[str, Any]], method: str, case_ids: list[str]) -> dict[str, str]:
    predictions: dict[str, str] = {}
    for case_id in case_ids:
        row = results.get(case_id)
        if not row:
            continue
        method_row = row.get(method)
        if isinstance(method_row, dict) and method_row.get("taxonomy"):
            predictions[case_id] = str(method_row["taxonomy"])
    return predictions


def shared_case_ids(
    results: dict[str, dict[str, Any]],
    labels: dict[str, str],
    case_ids: list[str],
) -> list[str]:
    return [case_id for case_id in case_ids if case_id in results and case_id in labels]


def markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---:" if idx else "---" for idx in range(len(headers))) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def build_overall_rows(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
) -> list[list[str]]:
    rows: list[list[str]] = []
    for method in METHOD_ORDER:
        predictions = method_predictions(results, method, case_ids)
        summary = accuracy_summary(predictions, truth, case_ids)
        rows.append(
            [
                METHOD_LABELS[method],
                ratio_str(summary.correct, summary.total),
                pct(summary.accuracy),
                f"{pct(summary.ci_low)} to {pct(summary.ci_high)}",
            ]
        )
    return rows


def build_core_delta_rows(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    full_case_ids: list[str],
    core_case_ids: list[str],
) -> list[list[str]]:
    rows: list[list[str]] = []
    for method in METHOD_ORDER:
        predictions_full = method_predictions(results, method, full_case_ids)
        predictions_core = method_predictions(results, method, core_case_ids)
        full_summary = accuracy_summary(predictions_full, truth, full_case_ids)
        core_summary = accuracy_summary(predictions_core, truth, core_case_ids)
        delta = core_summary.accuracy - full_summary.accuracy
        rows.append(
            [
                METHOD_LABELS[method],
                pct(full_summary.accuracy),
                pct(core_summary.accuracy),
                f"{delta * 100.0:+.1f}pp",
            ]
        )
    return rows


def build_per_class_rows(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
) -> list[list[str]]:
    rows: list[list[str]] = []
    for target_class in CLASS_ORDER:
        for method in METHOD_ORDER:
            predictions = method_predictions(results, method, case_ids)
            precision, recall, f1, tp, fp, fn = precision_recall_f1(
                predictions,
                truth,
                case_ids,
                target_class,
            )
            rows.append(
                [
                    target_class,
                    METHOD_LABELS[method],
                    pct(precision),
                    pct(recall),
                    pct(f1),
                    str(tp),
                    str(fp),
                    str(fn),
                ]
            )
    return rows


def build_mcnemar_rows(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
) -> list[list[str]]:
    bpfix = method_predictions(results, "bpfix", case_ids)
    rows: list[list[str]] = []
    for other in ("baseline", "ablation_a", "ablation_b", "ablation_c"):
        other_predictions = method_predictions(results, other, case_ids)
        stats = mcnemar_exact(bpfix, other_predictions, truth, case_ids)
        rows.append(
            [
                f"BPFix vs {METHOD_LABELS[other]}",
                str(stats["left_only"]),
                str(stats["right_only"]),
                f"{stats['p_value']:.4f}",
            ]
        )
    return rows


def baseline_right_bpfix_wrong(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for case_id in case_ids:
        result_row = results.get(case_id, {})
        baseline = ((result_row.get("baseline") or {}).get("taxonomy"))
        bpfix = ((result_row.get("bpfix") or {}).get("taxonomy"))
        gt = truth.get(case_id)
        if baseline == gt and bpfix != gt:
            rows.append(
                {
                    "case_id": case_id,
                    "ground_truth": str(gt),
                    "baseline": str(baseline),
                    "bpfix": str(bpfix),
                    "cross_class": str((result_row.get("bpfix") or {}).get("cross_class")),
                }
            )
    return rows


def confusion_counter(rows: list[dict[str, str]]) -> Counter[tuple[str, str]]:
    return Counter((row["ground_truth"], row["bpfix"]) for row in rows)


def cross_class_distribution(rows: dict[str, dict[str, Any]], case_ids: list[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for case_id in case_ids:
        cross_class = ((rows.get(case_id, {}).get("bpfix") or {}).get("cross_class"))
        counter[str(cross_class) if cross_class is not None else "None"] += 1
    return counter


def multi_span_case_ids(rows: dict[str, dict[str, Any]], case_ids: list[str]) -> list[str]:
    return [
        case_id
        for case_id in case_ids
        if int(((rows.get(case_id, {}).get("bpfix") or {}).get("spans") or 0)) >= 2
    ]


def count_has_carrier_establishment(rows: dict[str, dict[str, Any]], case_ids: list[str]) -> int:
    return sum(
        1
        for case_id in case_ids
        if bool(((rows.get(case_id, {}).get("bpfix") or {}).get("has_carrier_establishment")))
    )


def append_section(lines: list[str], title: str, body: list[str]) -> None:
    lines.append(f"## {title}")
    lines.append("")
    lines.extend(body)
    lines.append("")


def render_inputs_section(
    results_path: Path,
    labels_path: Path,
    manifest_path: Path,
    full_ids: list[str],
    core_ids: list[str],
) -> list[str]:
    lines = [
        f"- Results: `{display_path(results_path)}`",
        f"- Labels: `{display_path(labels_path)}`",
        f"- Manifest: `{display_path(manifest_path)}`",
        f"- Eligible cases in comparison run: `{len(full_ids)}`",
        f"- Core-set eligible cases: `{len(core_ids)}`",
    ]
    if labels_path == DEFAULT_LABELS_PATH and ARCHIVE_LABELS_PATH.exists():
        lines.append(
            "- `ground_truth.yaml` is used for the primary tables; the older `ground_truth_labels.yaml` is still used below for the historical 70.2% vs 75.7% gap analysis."
        )
        lines.append("- Quarantined cases in `ground_truth.yaml` are excluded from the primary tables.")
    elif labels_path == ARCHIVE_LABELS_PATH and DEFAULT_LABELS_PATH.exists():
        lines.append(
            "- `ground_truth_labels.yaml` is used for the primary tables; `ground_truth.yaml` remains the canonical label set."
        )
    return lines


def render_dataset_section(
    title: str,
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
) -> list[str]:
    lines = [
        f"- Labeled cases: `{len(case_ids)}`",
        "",
        "### Overall Accuracy",
        "",
    ]
    lines.extend(
        markdown_table(
            ["Method", "Correct / N", "Accuracy", "Wilson 95% CI"],
            build_overall_rows(results, truth, case_ids),
        )
    )
    lines.extend(
        (
            "",
            "### Per-Class Precision / Recall / F1",
            "",
        )
    )
    lines.extend(
        markdown_table(
            ["Class", "Method", "Precision", "Recall", "F1", "TP", "FP", "FN"],
            build_per_class_rows(results, truth, case_ids),
        )
    )
    lines.extend(
        (
            "",
            "### McNemar Tests",
            "",
        )
    )
    lines.extend(
        markdown_table(
            ["Comparison", "BPFix-only correct", "Other-only correct", "Exact p"],
            build_mcnemar_rows(results, truth, case_ids),
        )
    )
    return lines


def render_gap_analysis(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    case_ids: list[str],
    heading_note: str,
) -> list[str]:
    rows = baseline_right_bpfix_wrong(results, truth, case_ids)
    confusion = confusion_counter(rows)
    lowering_on_source = sum(
        1
        for row in rows
        if row["ground_truth"] == "source_bug" and row["bpfix"] == "lowering_artifact"
    )
    lines = [
        heading_note,
        f"- Baseline-correct / BPFix-wrong cases: `{len(rows)}`",
        f"- `source_bug -> lowering_artifact` within that bucket: `{lowering_on_source}`",
        "",
        "### Confusion Patterns",
        "",
    ]

    confusion_rows = [
        [gt, pred, str(count)]
        for (gt, pred), count in sorted(confusion.items(), key=lambda item: (-item[1], item[0]))
    ]
    if confusion_rows:
        lines.extend(markdown_table(["Ground Truth", "BPFix Prediction", "Count"], confusion_rows))
    else:
        lines.append("No baseline-correct / BPFix-wrong cases in this slice.")

    case_rows = [
        [row["case_id"], row["ground_truth"], row["bpfix"], row["cross_class"]]
        for row in rows
    ]
    if case_rows:
        lines.extend(
            (
                "",
                "### Case List",
                "",
            )
        )
        lines.extend(markdown_table(["Case ID", "Ground Truth", "BPFix", "cross_analysis_class"], case_rows))
    return lines


def render_multi_span_analysis(
    results: dict[str, dict[str, Any]],
    eligible_case_ids: list[str],
) -> list[str]:
    multi_span_ids = multi_span_case_ids(results, eligible_case_ids)
    cross_counter = cross_class_distribution(results, eligible_case_ids)
    multi_cross_counter = cross_class_distribution(results, multi_span_ids)
    concrete_cross = sum(
        1
        for case_id in eligible_case_ids
        if ((results.get(case_id, {}).get("bpfix") or {}).get("cross_class")) is not None
    )
    concrete_non_source_bug = sum(
        1
        for case_id in eligible_case_ids
        if ((results.get(case_id, {}).get("bpfix") or {}).get("cross_class")) not in {None, "source_bug"}
    )
    ambiguous = sum(
        1
        for case_id in eligible_case_ids
        if ((results.get(case_id, {}).get("bpfix") or {}).get("cross_class")) == "ambiguous"
    )
    established_then_lost = sum(
        1
        for case_id in eligible_case_ids
        if ((results.get(case_id, {}).get("bpfix") or {}).get("cross_class")) == "established_then_lost"
    )
    any_carrier_establish = count_has_carrier_establishment(results, eligible_case_ids)
    multi_any_carrier_establish = count_has_carrier_establishment(results, multi_span_ids)
    missing_cross = len(eligible_case_ids) - concrete_cross

    if established_then_lost == 0:
        carrier_interpretation = (
            f"- Interpretation: carrier establishment is rare and `cross_analysis_class == established_then_lost` never occurs in this run, so the {len(multi_span_ids)} multi-span outputs mostly come from the legacy proof-loss path rather than cross-analysis success cases."
        )
    else:
        carrier_interpretation = (
            f"- Interpretation: carrier establishment is rare, but `cross_analysis_class == established_then_lost` does appear in `{established_then_lost}/{len(eligible_case_ids)}` eligible cases, so only a small slice of the {len(multi_span_ids)} multi-span outputs come from explicit cross-analysis loss tracking."
        )

    lines = [
        f"- Multi-span BPFix outputs: `{len(multi_span_ids)}/{len(eligible_case_ids)}`",
        f"- Concrete `cross_analysis_class` present: `{concrete_cross}/{len(eligible_case_ids)}`",
        f"- Missing `cross_analysis_class`: `{missing_cross}/{len(eligible_case_ids)}`",
        f"- Concrete `cross_analysis_class != source_bug`: `{concrete_non_source_bug}/{len(eligible_case_ids)}`",
        f"- `cross_analysis_class == ambiguous`: `{ambiguous}/{len(eligible_case_ids)}`",
        f"- `cross_analysis_class == established_then_lost`: `{established_then_lost}/{len(eligible_case_ids)}`",
        f"- Any carrier establishment: `{any_carrier_establish}/{len(eligible_case_ids)}`",
        f"- Multi-span cases with any carrier establishment: `{multi_any_carrier_establish}/{len(multi_span_ids)}`" if multi_span_ids else "- Multi-span cases with any carrier establishment: `0/0`",
        "- Interpretation: most eligible cases never emit a concrete `cross_analysis_class`, so the pipeline usually falls back to a single rejected span instead of a richer carrier story.",
        carrier_interpretation,
        "",
        "### cross_analysis_class Distribution",
        "",
    ]
    lines.extend(
        markdown_table(
            ["Bucket", "All Eligible", "Multi-Span Subset"],
            [
                [
                    label,
                    str(cross_counter.get(label, 0)),
                    str(multi_cross_counter.get(label, 0)),
                ]
                for label in sorted(set(cross_counter) | set(multi_cross_counter))
            ],
        )
    )
    return lines


def render_core_delta_section(
    results: dict[str, dict[str, Any]],
    truth: dict[str, str],
    full_case_ids: list[str],
    core_case_ids: list[str],
) -> list[str]:
    if not full_case_ids or not core_case_ids:
        return ["Insufficient labeled cases to compare the full corpus against the core subset."]
    bpfix_full = accuracy_summary(method_predictions(results, "bpfix", full_case_ids), truth, full_case_ids)
    bpfix_core = accuracy_summary(method_predictions(results, "bpfix", core_case_ids), truth, core_case_ids)
    baseline_full = accuracy_summary(method_predictions(results, "baseline", full_case_ids), truth, full_case_ids)
    baseline_core = accuracy_summary(method_predictions(results, "baseline", core_case_ids), truth, core_case_ids)
    lines = [
        f"- BPFix improves from `{pct(bpfix_full.accuracy)}` to `{pct(bpfix_core.accuracy)}` on the core subset (`+{(bpfix_core.accuracy - bpfix_full.accuracy) * 100.0:.1f}pp`).",
        f"- Baseline also improves from `{pct(baseline_full.accuracy)}` to `{pct(baseline_core.accuracy)}` (`+{(baseline_core.accuracy - baseline_full.accuracy) * 100.0:.1f}pp`), so the BPFix-vs-baseline gap is nearly unchanged on trace-rich cases.",
        "",
    ]
    lines.extend(markdown_table(
        ["Method", "Full Accuracy", "Core Accuracy", "Core - Full"],
        build_core_delta_rows(results, truth, full_case_ids, core_case_ids),
    ))
    return lines


def main() -> int:
    args = parse_args()
    labels_path = resolve_labels_path(args.labels_path)

    results = results_by_case(args.results_path)
    labels = labels_by_case(labels_path)
    eligible_ids, core_ids = manifest_case_sets(args.manifest_path)

    full_case_ids = shared_case_ids(results, labels, eligible_ids)
    core_case_ids = shared_case_ids(results, labels, core_ids)
    eligible_case_ids_with_results = [case_id for case_id in eligible_ids if case_id in results]

    lines = ["# Comparison Report 2026-03-18", ""]
    append_section(
        lines,
        "Inputs",
        render_inputs_section(args.results_path, labels_path, args.manifest_path, full_case_ids, core_case_ids),
    )
    append_section(
        lines,
        "Full Corpus",
        render_dataset_section("Full Corpus", results, labels, full_case_ids),
    )
    append_section(
        lines,
        "Core Set",
        render_dataset_section("Core Set", results, labels, core_case_ids),
    )
    append_section(
        lines,
        "Core vs Full Delta",
        render_core_delta_section(results, labels, full_case_ids, core_case_ids),
    )

    if ARCHIVE_LABELS_PATH.exists():
        old_labels = labels_by_case(ARCHIVE_LABELS_PATH)
        old_case_ids = shared_case_ids(results, old_labels, eligible_ids)
        append_section(
            lines,
            "Why BPFix Trails Baseline",
            render_gap_analysis(
                results,
                old_labels,
                old_case_ids,
                "This section uses the older `ground_truth_labels.yaml` split so it lines up with the cited 70.2% BPFix vs 75.7% baseline comparison.",
            ),
        )
    else:
        append_section(
            lines,
            "Why BPFix Trails Baseline",
            render_gap_analysis(
                results,
                labels,
                full_case_ids,
                "This section uses the same label file as the primary tables because `case_study/archive/ground_truth_labels.yaml` is unavailable.",
            ),
        )

    append_section(
        lines,
        "Multi-Span Analysis",
        render_multi_span_analysis(results, eligible_case_ids_with_results),
    )

    report = "\n".join(lines).rstrip() + "\n"
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    with args.report_path.open("w", encoding="utf-8") as handle:
        handle.write(report)

    print(f"Wrote {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
