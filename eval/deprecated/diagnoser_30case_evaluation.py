#!/usr/bin/env python3
"""Run the proof-aware diagnoser on the 30 manually labeled benchmark cases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.diagnoser import Diagnosis, diagnose


CASE_DIRS = (
    ROOT / "case_study" / "cases" / "kernel_selftests",
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
)
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
DEFAULT_PV_COMPARISON = ROOT / "docs" / "tmp" / "pretty-verifier-comparison.md"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "diagnoser_30case_results.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "diagnoser-30case-evaluation.md"

TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
)


@dataclass(slots=True)
class ManualLabel:
    case_id: str
    source_bucket: str
    difficulty: str
    taxonomy_class: str
    error_id: str
    confidence: str
    localizability: str
    specificity: str
    rationale: str
    ground_truth_fix: str


@dataclass(slots=True)
class PrettyVerifierRow:
    case_id: str
    manual_label: str
    pv_diagnosis: str
    oblige_diagnosis: str
    pv_correct: bool
    oblige_correct: bool


@dataclass(slots=True)
class CaseResult:
    case_id: str
    case_path: str
    source_bucket: str
    difficulty: str
    manual_label: str
    manual_error_id: str
    pv_diagnosis: str | None
    pv_correct: bool | None
    diagnoser_error_id: str | None
    diagnoser_class: str | None
    correct: bool
    symptom_insn: int | None
    root_cause_insn: int | None
    root_cause_distinct_from_symptom: bool | None
    proof_status: str | None
    loss_context: str | None
    recommended_fix: str | None
    confidence: float | None
    diagnosis_exception: str | None
    verifier_log_chars: int
    verifier_log_lines: int
    diagnosis: dict[str, Any] | None


def parse_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def load_manual_labels(path: Path) -> dict[str, ManualLabel]:
    labels: dict[str, ManualLabel] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 10:
            continue
        case_id = cells[0].strip("`")
        labels[case_id] = ManualLabel(
            case_id=case_id,
            source_bucket=cells[1],
            difficulty=cells[2],
            taxonomy_class=cells[3].strip("`"),
            error_id=cells[4].strip("`"),
            confidence=cells[5],
            localizability=cells[6],
            specificity=cells[7],
            rationale=cells[8],
            ground_truth_fix=cells[9],
        )
    return labels


def load_pretty_verifier_table(path: Path) -> dict[str, PrettyVerifierRow]:
    rows: dict[str, PrettyVerifierRow] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    in_table = False
    for line in lines:
        if line.startswith("## Table 2: Per-Case Accuracy on the 30 Manually Labeled Cases"):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("| `"):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 6:
            continue
        case_id = cells[0].strip("`")
        rows[case_id] = PrettyVerifierRow(
            case_id=case_id,
            manual_label=cells[1].strip("`"),
            pv_diagnosis=cells[2],
            oblige_diagnosis=cells[3],
            pv_correct=cells[4].lower() == "yes",
            oblige_correct=cells[5].lower() == "yes",
        )
    return rows


def build_case_index(case_dirs: tuple[Path, ...]) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for case_dir in case_dirs:
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            index[path.stem] = path
    return index


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined", "")
        if isinstance(combined, str) and combined:
            return combined
        blocks = verifier_log.get("blocks", [])
        if isinstance(blocks, list):
            return "\n\n".join(block for block in blocks if isinstance(block, str))
    return ""


def diagnosis_to_dict(diagnosis: Diagnosis | None) -> dict[str, Any] | None:
    if diagnosis is None:
        return None
    return asdict(diagnosis)


def root_cause_differs(
    symptom_insn: int | None,
    root_cause_insn: int | None,
) -> bool | None:
    if symptom_insn is None or root_cause_insn is None:
        return None
    return symptom_insn != root_cause_insn


def run_case(
    case_id: str,
    label: ManualLabel,
    case_path: Path,
    pv_row: PrettyVerifierRow | None,
) -> CaseResult:
    case_data = read_yaml(case_path)
    verifier_log = extract_verifier_log(case_data)

    diagnosis: Diagnosis | None = None
    diagnosis_exception: str | None = None
    if verifier_log.strip():
        try:
            diagnosis = diagnose(verifier_log)
        except Exception as exc:  # pragma: no cover - evaluation must record failures.
            diagnosis_exception = f"{type(exc).__name__}: {exc}"
    else:
        diagnosis_exception = "Missing verifier_log"

    diagnosis_dict = diagnosis_to_dict(diagnosis)
    diagnoser_class = diagnosis.taxonomy_class if diagnosis is not None else None
    symptom_insn = diagnosis.symptom_insn if diagnosis is not None else None
    root_cause_insn = diagnosis.root_cause_insn if diagnosis is not None else None

    return CaseResult(
        case_id=case_id,
        case_path=str(case_path),
        source_bucket=label.source_bucket,
        difficulty=label.difficulty,
        manual_label=label.taxonomy_class,
        manual_error_id=label.error_id,
        pv_diagnosis=pv_row.pv_diagnosis if pv_row is not None else None,
        pv_correct=pv_row.pv_correct if pv_row is not None else None,
        diagnoser_error_id=diagnosis.error_id if diagnosis is not None else None,
        diagnoser_class=diagnoser_class,
        correct=diagnoser_class == label.taxonomy_class,
        symptom_insn=symptom_insn,
        root_cause_insn=root_cause_insn,
        root_cause_distinct_from_symptom=root_cause_differs(symptom_insn, root_cause_insn),
        proof_status=diagnosis.proof_status if diagnosis is not None else None,
        loss_context=diagnosis.loss_context if diagnosis is not None else None,
        recommended_fix=diagnosis.recommended_fix if diagnosis is not None else None,
        confidence=diagnosis.confidence if diagnosis is not None else None,
        diagnosis_exception=diagnosis_exception,
        verifier_log_chars=len(verifier_log),
        verifier_log_lines=len(verifier_log.splitlines()) if verifier_log else 0,
        diagnosis=diagnosis_dict,
    )


def percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def ratio(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator}"


def accuracy_cell(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator} ({percentage(numerator, denominator):.1f}%)"


def cell_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"\s+", " ", text.strip())
    return text.replace("|", "\\|")


def bool_cell(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def aggregate_results(results: list[CaseResult]) -> dict[str, Any]:
    overall_correct = sum(result.correct for result in results)
    pv_overall_correct = sum(result.pv_correct is True for result in results)
    diagnoser_failures = sum(result.diagnosis_exception is not None for result in results)
    recommended_fix_count = sum(bool(result.recommended_fix) for result in results)
    earlier_root_cause_count = sum(result.root_cause_distinct_from_symptom is True for result in results)

    per_class: list[dict[str, Any]] = []
    for taxonomy_class in TAXONOMY_ORDER:
        bucket = [result for result in results if result.manual_label == taxonomy_class]
        correct = sum(result.correct for result in bucket)
        pv_correct = sum(result.pv_correct is True for result in bucket)
        earlier_root = sum(result.root_cause_distinct_from_symptom is True for result in bucket)
        per_class.append(
            {
                "taxonomy_class": taxonomy_class,
                "cases": len(bucket),
                "diagnoser_correct": correct,
                "diagnoser_accuracy": percentage(correct, len(bucket)),
                "pv_correct": pv_correct,
                "pv_accuracy": percentage(pv_correct, len(bucket)),
                "earlier_root_cause": earlier_root,
            }
        )

    proof_status_counter = Counter(
        result.proof_status or "unknown"
        for result in results
    )
    correct_proof_status_counter = Counter(
        result.proof_status or "unknown"
        for result in results
        if result.correct
    )
    failure_pairs = Counter(
        (
            result.manual_label,
            result.diagnoser_class or "unclassified",
        )
        for result in results
        if not result.correct
    )

    diagnoser_beats_pv = [
        result.case_id
        for result in results
        if result.correct and result.pv_correct is False
    ]
    pv_beats_diagnoser = [
        result.case_id
        for result in results
        if not result.correct and result.pv_correct is True
    ]
    both_correct = [
        result.case_id
        for result in results
        if result.correct and result.pv_correct is True
    ]
    both_wrong = [
        result.case_id
        for result in results
        if not result.correct and result.pv_correct is False
    ]

    return {
        "overall": {
            "cases": len(results),
            "diagnoser_correct": overall_correct,
            "diagnoser_accuracy": percentage(overall_correct, len(results)),
            "pv_correct": pv_overall_correct,
            "pv_accuracy": percentage(pv_overall_correct, len(results)),
            "diagnoser_failures": diagnoser_failures,
            "recommended_fix_count": recommended_fix_count,
            "earlier_root_cause_count": earlier_root_cause_count,
        },
        "per_class": per_class,
        "proof_status_distribution": dict(sorted(proof_status_counter.items())),
        "correct_proof_status_distribution": dict(sorted(correct_proof_status_counter.items())),
        "failure_pairs": [
            {
                "manual_label": manual_label,
                "diagnoser_class": diagnoser_class,
                "count": count,
            }
            for (manual_label, diagnoser_class), count in sorted(
                failure_pairs.items(),
                key=lambda item: (-item[1], item[0][0], item[0][1]),
            )
        ],
        "comparison_vs_pv": {
            "diagnoser_beats_pv": diagnoser_beats_pv,
            "pv_beats_diagnoser": pv_beats_diagnoser,
            "both_correct": both_correct,
            "both_wrong": both_wrong,
        },
    }


def infer_failure_reason(result: CaseResult) -> str:
    if result.diagnosis_exception:
        return f"diagnose() failed: {result.diagnosis_exception}"
    if result.diagnoser_class is None:
        return "No taxonomy class returned from the combined verifier log."
    if result.manual_label == "source_bug" and result.diagnoser_class == "env_mismatch":
        return "The catalog seed was source_bug, but the final diagnosis was overridden to `OBLIGE-E021` by BTF- or `UNKNOWN`-typed symptom text."
    if result.manual_label == "lowering_artifact" and result.diagnoser_class == "source_bug":
        if result.proof_status == "never_established":
            return "Stayed on the final access symptom and treated it as a source bug instead of a proof-loss artifact."
        return "Saw a concrete memory/access symptom, but did not elevate it to a lowering-artifact diagnosis."
    if result.manual_label == "source_bug" and result.diagnoser_class == "lowering_artifact":
        return "Detected a real proof-loss transition, but over-attributed the failure to lowering instead of the underlying source-side contract bug."
    if result.manual_label == "lowering_artifact" and result.diagnoser_class == "verifier_limit":
        return "The case still has a lowering-artifact seed, but the current diagnoser latched onto a stronger-looking limit/budget signal."
    if result.manual_label == "env_mismatch" and result.diagnoser_class == "source_bug":
        return "Matched the surface verifier contract violation, but not the environment or ABI mismatch behind it."
    if result.manual_label == "env_mismatch" and result.diagnoser_class == "lowering_artifact":
        return "The environment-dependent rejection also contains proof-loss structure, and the diagnoser over-read that as a lowering artifact."
    if result.manual_label == "verifier_bug" and result.diagnoser_class == "source_bug":
        return "Matched the symptom line, but not the kernel-side false-rejection pattern."
    if result.manual_label == "verifier_limit" and result.diagnoser_class in {None, "source_bug", "env_mismatch"}:
        return "The combined log did not preserve a clear verifier-limit signal for the diagnoser."
    return f"Predicted `{result.diagnoser_class}` instead of `{result.manual_label}`."


def build_report(
    results: list[CaseResult],
    summary: dict[str, Any],
    manual_labels_path: Path,
    pv_comparison_path: Path,
) -> str:
    overall = summary["overall"]
    comparison = summary["comparison_vs_pv"]
    per_class = summary["per_class"]
    per_class_by_name = {
        row["taxonomy_class"]: row
        for row in per_class
    }

    per_case_rows = [
        [
            f"`{result.case_id}`",
            f"`{result.manual_label}`",
            f"`{result.diagnoser_class}`" if result.diagnoser_class else "`unclassified`",
            "Yes" if result.correct else "No",
            f"`{result.proof_status}`" if result.proof_status else "",
            bool_cell(result.root_cause_distinct_from_symptom),
            f"`{result.loss_context}`" if result.loss_context else "",
            cell_text(result.recommended_fix),
        ]
        for result in results
    ]

    overall_rows = [
        ["Diagnoser overall accuracy", accuracy_cell(overall["diagnoser_correct"], overall["cases"])],
        ["Pretty Verifier overall accuracy", accuracy_cell(overall["pv_correct"], overall["cases"])],
        ["Diagnoser earlier root cause found", accuracy_cell(overall["earlier_root_cause_count"], overall["cases"])],
        ["Diagnoser recommended fix populated", accuracy_cell(overall["recommended_fix_count"], overall["cases"])],
        ["Diagnoser failures", accuracy_cell(overall["diagnoser_failures"], overall["cases"])],
    ]

    per_class_rows = [
        [
            f"`{row['taxonomy_class']}`",
            str(row["cases"]),
            accuracy_cell(row["diagnoser_correct"], row["cases"]),
            accuracy_cell(row["pv_correct"], row["cases"]),
            accuracy_cell(row["earlier_root_cause"], row["cases"]),
        ]
        for row in per_class
    ]

    comparison_rows = [
        ["Diagnoser correct, PV wrong", str(len(comparison["diagnoser_beats_pv"])), ", ".join(f"`{case_id}`" for case_id in comparison["diagnoser_beats_pv"]) or "-"],
        ["PV correct, diagnoser wrong", str(len(comparison["pv_beats_diagnoser"])), ", ".join(f"`{case_id}`" for case_id in comparison["pv_beats_diagnoser"]) or "-"],
        ["Both correct", str(len(comparison["both_correct"])), ", ".join(f"`{case_id}`" for case_id in comparison["both_correct"]) or "-"],
        ["Both wrong", str(len(comparison["both_wrong"])), ", ".join(f"`{case_id}`" for case_id in comparison["both_wrong"]) or "-"],
    ]

    incorrect_results = [result for result in results if not result.correct]
    incorrect_bullets = [
        f"- `{result.case_id}`: manual `{result.manual_label}`, diagnoser `{result.diagnoser_class or 'unclassified'}`. {infer_failure_reason(result)}"
        for result in incorrect_results
    ]

    strongest_class = max(per_class, key=lambda row: (row["diagnoser_accuracy"], row["cases"]))
    weakest_class = min(per_class, key=lambda row: (row["diagnoser_accuracy"], -row["cases"]))
    source_bug_as_env_mismatch = sum(
        1
        for result in results
        if result.manual_label == "source_bug" and result.diagnoser_class == "env_mismatch"
    )
    lowering_row = per_class_by_name["lowering_artifact"]
    verifier_limit_row = per_class_by_name["verifier_limit"]
    env_mismatch_row = per_class_by_name["env_mismatch"]
    source_bug_row = per_class_by_name["source_bug"]

    proof_status_distribution = ", ".join(
        f"`{status}`={count}"
        for status, count in summary["proof_status_distribution"].items()
    )
    correct_proof_status_distribution = ", ".join(
        f"`{status}`={count}"
        for status, count in summary["correct_proof_status_distribution"].items()
    )

    findings = [
        f"- The diagnoser classified `{overall['diagnoser_correct']}/{overall['cases']}` cases correctly ({overall['diagnoser_accuracy']:.1f}%), versus `{overall['pv_correct']}/{overall['cases']}` ({overall['pv_accuracy']:.1f}%) for Pretty Verifier on the same 30 cases.",
        f"- Despite lower overall accuracy, the diagnoser still beat Pretty Verifier on `{lowering_row['taxonomy_class']}` (`{lowering_row['diagnoser_correct']}/{lowering_row['cases']}` vs `{lowering_row['pv_correct']}/{lowering_row['cases']}`), `{verifier_limit_row['taxonomy_class']}` (`{verifier_limit_row['diagnoser_correct']}/{verifier_limit_row['cases']}` vs `{verifier_limit_row['pv_correct']}/{verifier_limit_row['cases']}`), and `{env_mismatch_row['taxonomy_class']}` (`{env_mismatch_row['diagnoser_correct']}/{env_mismatch_row['cases']}` vs `{env_mismatch_row['pv_correct']}/{env_mismatch_row['cases']}`).",
        f"- The dominant failure mode was `source_bug -> env_mismatch`: `{source_bug_as_env_mismatch}` cases, mostly driven by final overrides to `OBLIGE-E021` after BTF-flavored symptom text.",
        f"- The diagnoser returned a distinct root-cause instruction on `{overall['earlier_root_cause_count']}/{overall['cases']}` cases and a non-empty recommended fix on `{overall['recommended_fix_count']}/{overall['cases']}` cases.",
    ]

    report_lines = [
        "# Diagnoser 30-Case Evaluation",
        "",
        "## Method",
        "",
        f"- Manual labels were loaded from `{manual_labels_path.relative_to(ROOT)}`.",
        f"- Pretty Verifier accuracy was read from Table 2 in `{pv_comparison_path.relative_to(ROOT)}`.",
        "- Each case YAML was loaded from `case_study/cases/...`, and `verifier_log` was extracted exactly as `string` or `dict['combined']` falling back to joined `dict['blocks']`.",
        "- The runner invoked `interface.extractor.diagnoser.diagnose(verifier_log)` once per case and recorded failures instead of aborting the batch.",
        "- This report evaluates the current `diagnose()` entry point only. The earlier OBLIGE column in `pretty-verifier-comparison.md` came from a different `parse_log(...) + parse_trace(...)` path, so the numbers are not expected to match exactly.",
        "- `root_cause != symptom` is `Yes` only when both instruction indices exist and differ.",
        "",
        "## Per-Case Results",
        "",
        markdown_table(
            [
                "case_id",
                "manual_label",
                "diagnoser_class",
                "correct?",
                "proof_status",
                "root_cause != symptom?",
                "loss_context",
                "recommended_fix",
            ],
            per_case_rows,
        ),
        "",
        "## Aggregate Accuracy",
        "",
        markdown_table(["Metric", "Value"], overall_rows),
        "",
        markdown_table(
            ["Taxonomy class", "Cases", "Diagnoser accuracy", "PV accuracy", "Earlier root cause"],
            per_class_rows,
        ),
        "",
        "## Comparison vs Pretty Verifier",
        "",
        markdown_table(["Outcome", "Count", "Cases"], comparison_rows),
        "",
        "## Analysis",
        "",
        f"The diagnoser's proof-status distribution across all 30 cases was {proof_status_distribution or 'none'}. On the correctly classified subset, the distribution was {correct_proof_status_distribution or 'none'}.",
        "",
        f"The current `diagnose()` entry point scored `{overall['diagnoser_correct']}/{overall['cases']}` overall, slightly below Pretty Verifier's `{overall['pv_correct']}/{overall['cases']}`. That is also materially below the earlier OBLIGE column in `pretty-verifier-comparison.md`, which is expected here because that earlier document evaluated a lower-level `parse_log(...) + parse_trace(...)` pipeline rather than the current single-entry-point diagnoser.",
        "",
        f"The strongest class was `{strongest_class['taxonomy_class']}` and the weakest was `{weakest_class['taxonomy_class']}`. The diagnoser still keeps its intended advantage on trace-sensitive classes: `lowering_artifact` is `{lowering_row['diagnoser_correct']}/{lowering_row['cases']}` vs Pretty Verifier's `{lowering_row['pv_correct']}/{lowering_row['cases']}`, `verifier_limit` is `{verifier_limit_row['diagnoser_correct']}/{verifier_limit_row['cases']}` vs `{verifier_limit_row['pv_correct']}/{verifier_limit_row['cases']}`, and `env_mismatch` is `{env_mismatch_row['diagnoser_correct']}/{env_mismatch_row['cases']}` vs `{env_mismatch_row['pv_correct']}/{env_mismatch_row['cases']}`.",
        "",
        f"The main regression driver is `source_bug`: only `{source_bug_row['diagnoser_correct']}/{source_bug_row['cases']}` correct, with `{source_bug_as_env_mismatch}` cases specifically drifting to `env_mismatch`. In those cases the evidence often still contains a `source_bug` catalog seed, but the final classification overrides it to `OBLIGE-E021` because the symptom line mentions `reference type('UNKNOWN ')` or similar environment-looking text.",
        "",
        f"Relative to Pretty Verifier, the diagnoser gained `{len(comparison['diagnoser_beats_pv'])}` cases and lost `{len(comparison['pv_beats_diagnoser'])}`. The wins are concentrated where trace structure matters more than the final line, while the losses are dominated by these `source_bug` override errors.",
        "",
        "Incorrect cases and likely reasons:",
        *incorrect_bullets,
        "",
        "## Key Findings",
        "",
        *findings,
        "",
    ]
    return "\n".join(report_lines)


def build_json_payload(
    results: list[CaseResult],
    summary: dict[str, Any],
    manual_labels_path: Path,
    pv_comparison_path: Path,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "manual_labels_path": str(manual_labels_path),
            "pv_comparison_path": str(pv_comparison_path),
            "case_dirs": [str(path) for path in CASE_DIRS],
        },
        "summary": summary,
        "results": [asdict(result) for result in results],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manual-labels",
        type=Path,
        default=DEFAULT_MANUAL_LABELS,
        help="Path to docs/tmp/manual-labeling-30cases.md.",
    )
    parser.add_argument(
        "--pv-comparison",
        type=Path,
        default=DEFAULT_PV_COMPARISON,
        help="Path to docs/tmp/pretty-verifier-comparison.md.",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help="Where to write the raw JSON results.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Where to write the markdown report.",
    )
    args = parser.parse_args()

    manual_labels = load_manual_labels(args.manual_labels)
    pv_rows = load_pretty_verifier_table(args.pv_comparison)
    case_index = build_case_index(CASE_DIRS)

    missing_case_paths = sorted(case_id for case_id in manual_labels if case_id not in case_index)
    missing_pv_rows = sorted(case_id for case_id in manual_labels if case_id not in pv_rows)
    if missing_case_paths:
        raise SystemExit(f"Missing YAML files for manual cases: {', '.join(missing_case_paths)}")
    if missing_pv_rows:
        raise SystemExit(f"Missing Pretty Verifier rows for manual cases: {', '.join(missing_pv_rows)}")

    results = [
        run_case(
            case_id=case_id,
            label=label,
            case_path=case_index[case_id],
            pv_row=pv_rows.get(case_id),
        )
        for case_id, label in manual_labels.items()
    ]
    summary = aggregate_results(results)
    report = build_report(results, summary, args.manual_labels, args.pv_comparison)
    payload = build_json_payload(results, summary, args.manual_labels, args.pv_comparison)

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    args.report_path.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
