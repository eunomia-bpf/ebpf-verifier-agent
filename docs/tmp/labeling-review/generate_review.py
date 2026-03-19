#!/usr/bin/env python3
from __future__ import annotations

import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


TAXONOMY_ORDER = [
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


ROOT = repo_root()
OUTPUT_DIR = ROOT / "docs/tmp/labeling-review"
LABEL_A_PATH = ROOT / "docs/tmp/labeling-a/labels.yaml"
LABEL_B_PATH = ROOT / "docs/tmp/labeling-b/labels.yaml"
MANUAL_PATH = ROOT / "docs/tmp/manual-labeling-30cases.md"
ERROR_CATALOG_PATH = ROOT / "taxonomy/error_catalog.yaml"
ADJUDICATIONS_PATH = OUTPUT_DIR / "adjudications.yaml"
AGREEMENT_MD_PATH = OUTPUT_DIR / "agreement_analysis.md"
GROUND_TRUTH_PATH = ROOT / "case_study/ground_truth.yaml"
SUMMARY_MD_PATH = OUTPUT_DIR / "review_summary.md"

CASE_DIRS = [
    ROOT / "case_study/cases/kernel_selftests",
    ROOT / "case_study/cases/stackoverflow",
    ROOT / "case_study/cases/github_issues",
]


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def format_pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def format_rate(value: float) -> str:
    return f"{value:.3f}"


def taxonomy_order(classes: list[str]) -> list[str]:
    ordered = [name for name in TAXONOMY_ORDER if name in classes]
    ordered.extend(sorted(set(classes) - set(ordered)))
    return ordered


def load_labels(path: Path) -> dict[str, Any]:
    data = load_yaml(path)
    cases = data["cases"]
    return {
        "metadata": data.get("metadata", {}),
        "cases": cases,
        "by_id": {case["case_id"]: case for case in cases},
    }


def load_error_catalog(path: Path) -> dict[str, str]:
    data = load_yaml(path)
    return {
        entry["error_id"]: entry["taxonomy_class"]
        for entry in data["error_types"]
    }


def load_case_paths() -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for case_dir in CASE_DIRS:
        for path in case_dir.glob("*.yaml"):
            if path.name == "index.yaml":
                continue
            paths[path.stem] = path
    return paths


def load_manual_labels(path: Path) -> dict[str, dict[str, str]]:
    lines = path.read_text().splitlines()
    inside_table = False
    manual: dict[str, dict[str, str]] = {}
    for line in lines:
        if line.startswith("## Labeled Cases"):
            inside_table = True
            continue
        if inside_table and line.startswith("## Distribution Across Taxonomy Classes"):
            break
        if inside_table and line.startswith("| `"):
            parts = [part.strip() for part in line.strip("|").split("|")]
            if len(parts) < 10:
                continue
            case_id = parts[0].strip("` ")
            manual[case_id] = {
                "taxonomy_class": parts[3].strip("` "),
                "error_id": parts[4].strip("` "),
                "confidence": parts[5].strip("` "),
                "rationale": parts[8],
                "ground_truth_fix": parts[9],
            }
    return manual


def compute_agreement(
    a_by_id: dict[str, dict[str, Any]],
    b_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    case_ids = list(a_by_id)
    classes = taxonomy_order(
        sorted(
            {
                a_by_id[case_id]["taxonomy_class"]
                for case_id in case_ids
            }
            | {
                b_by_id[case_id]["taxonomy_class"]
                for case_id in case_ids
            }
        )
    )

    confusion = {
        row: {col: 0 for col in classes}
        for row in classes
    }
    disagreements = []

    for case_id in case_ids:
        a_class = a_by_id[case_id]["taxonomy_class"]
        b_class = b_by_id[case_id]["taxonomy_class"]
        confusion[a_class][b_class] += 1
        if a_class != b_class:
            disagreements.append(case_id)

    agree_count = len(case_ids) - len(disagreements)
    agreement_rate = agree_count / len(case_ids)

    a_counts = Counter(a_by_id[case_id]["taxonomy_class"] for case_id in case_ids)
    b_counts = Counter(b_by_id[case_id]["taxonomy_class"] for case_id in case_ids)
    expected = sum(
        (a_counts[label] / len(case_ids)) * (b_counts[label] / len(case_ids))
        for label in classes
    )
    if math.isclose(1.0 - expected, 0.0):
        kappa = 1.0
    else:
        kappa = (agreement_rate - expected) / (1.0 - expected)

    per_class = []
    for label in classes:
        both = confusion[label][label]
        union = (
            a_counts[label]
            + b_counts[label]
            - both
        )
        per_class.append(
            {
                "taxonomy_class": label,
                "a_count": a_counts[label],
                "b_count": b_counts[label],
                "both_count": both,
                "union_count": union,
                "agreement_rate": 0.0 if union == 0 else both / union,
            }
        )

    return {
        "case_ids": case_ids,
        "classes": classes,
        "confusion": confusion,
        "disagreements": disagreements,
        "agree_count": agree_count,
        "agreement_rate": agreement_rate,
        "kappa": kappa,
        "a_counts": a_counts,
        "b_counts": b_counts,
        "per_class": per_class,
    }


def choose_consensus_record(
    a_case: dict[str, Any],
    b_case: dict[str, Any],
    error_id_to_class: dict[str, str],
) -> dict[str, Any]:
    target_class = a_case["taxonomy_class"]
    if a_case["taxonomy_class"] != b_case["taxonomy_class"]:
        raise ValueError("Consensus selection requires matching taxonomy classes")

    def score(index: int, record: dict[str, Any]) -> tuple[float, float]:
        score_value = 0.0
        if error_id_to_class.get(record["error_id"]) == target_class:
            score_value += 10.0
        if record.get("fix_type") and record["fix_type"] != "other":
            score_value += 1.0
        score_value += min(len(record.get("root_cause_description", "")) / 1000.0, 0.5)
        return (score_value, -index)

    return max(enumerate([a_case, b_case]), key=lambda item: score(item[0], item[1]))[1]


def render_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def write_agreement_analysis(
    stats: dict[str, Any],
    a_by_id: dict[str, dict[str, Any]],
    b_by_id: dict[str, dict[str, Any]],
    case_paths: dict[str, Path],
    manual_labels: dict[str, dict[str, str]],
) -> None:
    lines: list[str] = []
    lines.append("# Agreement Analysis")
    lines.append("")
    lines.append("## Overall Statistics")
    lines.append("")
    lines.append(f"- Total cases: `{len(stats['case_ids'])}`")
    lines.append(
        f"- Exact taxonomy-class agreement: `{stats['agree_count']}/{len(stats['case_ids'])}` "
        f"({format_pct(stats['agreement_rate'])})"
    )
    lines.append(f"- Cohen's kappa: `{stats['kappa']:.3f}`")
    lines.append(f"- Disagreement count: `{len(stats['disagreements'])}`")
    lines.append("")
    lines.append("## Confusion Matrix")
    lines.append("")

    headers = ["A \\\\ B", *stats["classes"], "Row Total"]
    rows = []
    for row_label in stats["classes"]:
        row_total = sum(stats["confusion"][row_label].values())
        rows.append(
            [
                f"`{row_label}`",
                *[str(stats["confusion"][row_label][col]) for col in stats["classes"]],
                str(row_total),
            ]
        )
    col_totals = [
        str(sum(stats["confusion"][row][col] for row in stats["classes"]))
        for col in stats["classes"]
    ]
    rows.append(["Column Total", *col_totals, str(len(stats["case_ids"]))])
    lines.append(render_markdown_table(headers, rows))
    lines.append("")
    lines.append("## Per-Class Agreement")
    lines.append("")
    lines.append(
        "Definition: `agreement_rate = both_labeled_this_class / "
        "(A_labeled_this_class + B_labeled_this_class - both_labeled_this_class)`."
    )
    lines.append("")
    per_class_rows = []
    for row in stats["per_class"]:
        per_class_rows.append(
            [
                f"`{row['taxonomy_class']}`",
                str(row["a_count"]),
                str(row["b_count"]),
                str(row["both_count"]),
                str(row["union_count"]),
                format_pct(row["agreement_rate"]),
            ]
        )
    lines.append(
        render_markdown_table(
            ["Class", "A Count", "B Count", "Both", "Union", "Agreement Rate"],
            per_class_rows,
        )
    )
    lines.append("")
    lines.append("## Disagreement Cases")
    lines.append("")
    for case_id in stats["disagreements"]:
        a_case = a_by_id[case_id]
        b_case = b_by_id[case_id]
        case_path = case_paths.get(case_id)
        manual_note = manual_labels.get(case_id)
        lines.append(f"### `{case_id}`")
        if case_path:
            lines.append(f"- Case file: `{case_path.relative_to(ROOT)}`")
        lines.append(
            f"- Labeler A: `{a_case['taxonomy_class']}` (`{a_case['error_id']}`)"
        )
        lines.append(
            f"- Labeler B: `{b_case['taxonomy_class']}` (`{b_case['error_id']}`)"
        )
        if manual_note:
            lines.append(
                f"- Manual calibration label: `{manual_note['taxonomy_class']}` "
                f"(`{manual_note['error_id']}`)"
            )
        lines.append(f"- A root cause: {a_case['root_cause_description']}")
        lines.append(f"- A reasoning: {a_case['reasoning']}")
        lines.append(f"- B root cause: {b_case['root_cause_description']}")
        lines.append(f"- B reasoning: {b_case['reasoning']}")
        lines.append("")

    AGREEMENT_MD_PATH.write_text("\n".join(lines).rstrip() + "\n")


def build_final_cases(
    a_cases: list[dict[str, Any]],
    a_by_id: dict[str, dict[str, Any]],
    b_by_id: dict[str, dict[str, Any]],
    adjudications: dict[str, dict[str, Any]],
    error_id_to_class: dict[str, str],
) -> list[dict[str, Any]]:
    final_cases: list[dict[str, Any]] = []

    for a_case in a_cases:
        case_id = a_case["case_id"]
        b_case = b_by_id[case_id]
        if case_id in adjudications:
            override = adjudications[case_id]
            final_cases.append(
                {
                    "case_id": case_id,
                    "taxonomy_class": override["final_class"],
                    "error_id": override["error_id"],
                    "root_cause_description": override["root_cause_description"],
                    "fix_type": override["fix_type"],
                    "fix_direction": override["fix_direction"],
                    "confidence": "medium",
                    "label_source": "adjudicated",
                    "labeler_a_class": a_case["taxonomy_class"],
                    "labeler_b_class": b_case["taxonomy_class"],
                    "adjudication_note": override["adjudication_reasoning"],
                }
            )
            continue

        selected = choose_consensus_record(a_case, b_case, error_id_to_class)
        final_cases.append(
            {
                "case_id": case_id,
                "taxonomy_class": selected["taxonomy_class"],
                "error_id": selected["error_id"],
                "root_cause_description": selected["root_cause_description"],
                "fix_type": selected["fix_type"],
                "fix_direction": selected["fix_direction"],
                "confidence": "high",
                "label_source": "agree",
                "labeler_a_class": a_case["taxonomy_class"],
                "labeler_b_class": b_case["taxonomy_class"],
                "adjudication_note": None,
            }
        )

    return final_cases


def validate_final_cases(
    final_cases: list[dict[str, Any]],
    error_id_to_class: dict[str, str],
) -> None:
    for case in final_cases:
        error_id = case["error_id"]
        taxonomy_class = case["taxonomy_class"]
        mapped_class = error_id_to_class.get(error_id)
        if mapped_class is not None and mapped_class != taxonomy_class:
            raise ValueError(
                f"{case['case_id']}: error_id {error_id} maps to {mapped_class}, "
                f"not {taxonomy_class}"
            )


def write_ground_truth(
    final_cases: list[dict[str, Any]],
    stats: dict[str, Any],
) -> None:
    payload = {
        "metadata": {
            "generated_at": "2026-03-19",
            "description": "Independent LLM-labeled ground truth with cross-review adjudication",
            "total_cases": len(final_cases),
            "method": "Two independent LLM labelers + expert adjudication of disagreements",
            "agreement_rate": format_pct(stats["agreement_rate"]),
            "cohens_kappa": round(stats["kappa"], 2),
            "labeler_a_source": "docs/tmp/labeling-a/labels.yaml",
            "labeler_b_source": "docs/tmp/labeling-b/labels.yaml",
        },
        "cases": final_cases,
    }
    GROUND_TRUTH_PATH.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=False)
    )


def manual_validation(
    final_cases: list[dict[str, Any]],
    manual_labels: dict[str, dict[str, str]],
) -> dict[str, Any]:
    final_by_id = {case["case_id"]: case for case in final_cases}
    overlaps = sorted(case_id for case_id in manual_labels if case_id in final_by_id)
    class_matches = [
        case_id
        for case_id in overlaps
        if final_by_id[case_id]["taxonomy_class"] == manual_labels[case_id]["taxonomy_class"]
    ]
    error_overlaps = [
        case_id
        for case_id in overlaps
        if manual_labels[case_id]["error_id"] != "unmatched"
    ]
    error_matches = [
        case_id
        for case_id in error_overlaps
        if final_by_id[case_id]["error_id"] == manual_labels[case_id]["error_id"]
    ]
    mismatches = [
        {
            "case_id": case_id,
            "manual_class": manual_labels[case_id]["taxonomy_class"],
            "final_class": final_by_id[case_id]["taxonomy_class"],
            "manual_error_id": manual_labels[case_id]["error_id"],
            "final_error_id": final_by_id[case_id]["error_id"],
        }
        for case_id in overlaps
        if final_by_id[case_id]["taxonomy_class"] != manual_labels[case_id]["taxonomy_class"]
    ]
    return {
        "manual_total": len(manual_labels),
        "overlap_total": len(overlaps),
        "class_match_total": len(class_matches),
        "class_match_rate": 0.0 if not overlaps else len(class_matches) / len(overlaps),
        "error_overlap_total": len(error_overlaps),
        "error_match_total": len(error_matches),
        "error_match_rate": 0.0
        if not error_overlaps
        else len(error_matches) / len(error_overlaps),
        "mismatches": mismatches,
    }


def write_review_summary(
    final_cases: list[dict[str, Any]],
    stats: dict[str, Any],
    adjudications: dict[str, dict[str, Any]],
    validation: dict[str, Any],
) -> None:
    final_counts = Counter(case["taxonomy_class"] for case in final_cases)
    final_rows = [
        [
            f"`{label}`",
            str(final_counts[label]),
            format_pct(final_counts[label] / len(final_cases)),
        ]
        for label in taxonomy_order(list(final_counts))
    ]

    a_to_final = Counter()
    b_to_final = Counter()
    close_calls = []
    disagreement_total = 0
    manual_override_total = 0
    for case_id, record in adjudications.items():
        if record["kind"] == "disagreement":
            disagreement_total += 1
        elif record["kind"] == "manual_override":
            manual_override_total += 1
        a_to_final[(record["labeler_a_class"], record["final_class"])] += 1
        b_to_final[(record["labeler_b_class"], record["final_class"])] += 1
        if record.get("close_call"):
            close_calls.append((case_id, record["adjudication_reasoning"]))

    def transition_lines(counter: Counter[tuple[str, str]]) -> list[str]:
        items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        return [
            f"- `{src} -> {dst}`: `{count}`"
            for (src, dst), count in items
            if src != dst
        ]

    lines: list[str] = []
    lines.append("# Labeling Review Summary")
    lines.append("")
    lines.append("## Agreement Statistics")
    lines.append("")
    lines.append(
        f"- Overall agreement: `{stats['agree_count']}/{len(stats['case_ids'])}` "
        f"({format_pct(stats['agreement_rate'])})"
    )
    lines.append(f"- Cohen's kappa: `{stats['kappa']:.3f}`")
    lines.append(f"- Disagreement count: `{len(stats['disagreements'])}`")
    lines.append("")
    lines.append(
        render_markdown_table(
            ["Class", "A Count", "B Count", "Both", "Union", "Agreement Rate"],
            [
                [
                    f"`{row['taxonomy_class']}`",
                    str(row["a_count"]),
                    str(row["b_count"]),
                    str(row["both_count"]),
                    str(row["union_count"]),
                    format_pct(row["agreement_rate"]),
                ]
                for row in stats["per_class"]
            ],
        )
    )
    lines.append("")
    lines.append("## Adjudication Summary")
    lines.append("")
    lines.append(f"- Inter-label disagreements reviewed: `{disagreement_total}`")
    lines.append(f"- Additional manual-calibration overrides: `{manual_override_total}`")
    lines.append(f"- Total adjudicated cases in v3: `{len(adjudications)}`")
    lines.append("")
    lines.append("A-to-final transition counts:")
    lines.extend(transition_lines(a_to_final) or ["- None"])
    lines.append("")
    lines.append("B-to-final transition counts:")
    lines.extend(transition_lines(b_to_final) or ["- None"])
    lines.append("")
    lines.append("## Validation Against Manual 30")
    lines.append("")
    lines.append(f"- Manual labels parsed: `{validation['manual_total']}`")
    lines.append(f"- Overlap with the 139-case set: `{validation['overlap_total']}`")
    lines.append(
        f"- Taxonomy-class match rate: "
        f"`{validation['class_match_total']}/{validation['overlap_total']}` "
        f"({format_pct(validation['class_match_rate'])})"
    )
    if validation["error_overlap_total"]:
        lines.append(
            f"- Error-ID match rate on catalog-matched overlaps: "
            f"`{validation['error_match_total']}/{validation['error_overlap_total']}` "
            f"({format_pct(validation['error_match_rate'])})"
        )
    if validation["mismatches"]:
        lines.append("")
        lines.append("Manual mismatches that still remain:")
        for mismatch in validation["mismatches"]:
            lines.append(
                f"- `{mismatch['case_id']}`: manual `{mismatch['manual_class']}` "
                f"vs v3 `{mismatch['final_class']}`"
            )
    else:
        lines.append("- No taxonomy-class mismatches remain on the overlapping manual cases.")
    lines.append("")
    lines.append("## Final Taxonomy Distribution")
    lines.append("")
    lines.append(render_markdown_table(["Class", "Count", "Share"], final_rows))
    lines.append("")
    lines.append("## Recommended Human Review")
    lines.append("")
    if close_calls:
        for case_id, note in close_calls:
            lines.append(f"- `{case_id}`: {note}")
    else:
        lines.append("- No additional close-call cases were flagged.")

    SUMMARY_MD_PATH.write_text("\n".join(lines).rstrip() + "\n")


def main() -> None:
    label_a = load_labels(LABEL_A_PATH)
    label_b = load_labels(LABEL_B_PATH)
    error_id_to_class = load_error_catalog(ERROR_CATALOG_PATH)
    manual_labels = load_manual_labels(MANUAL_PATH)
    case_paths = load_case_paths()
    adjudications_data = load_yaml(ADJUDICATIONS_PATH)
    adjudications_list = adjudications_data["cases"]
    adjudications = {case["case_id"]: case for case in adjudications_list}

    if set(label_a["by_id"]) != set(label_b["by_id"]):
        raise ValueError("Labeler A and B case sets do not match")

    stats = compute_agreement(label_a["by_id"], label_b["by_id"])
    write_agreement_analysis(
        stats,
        label_a["by_id"],
        label_b["by_id"],
        case_paths,
        manual_labels,
    )

    missing_disagreement_adjudications = sorted(
        case_id
        for case_id in stats["disagreements"]
        if case_id not in adjudications
    )
    if missing_disagreement_adjudications:
        raise ValueError(
            "Missing adjudications for disagreement cases: "
            + ", ".join(missing_disagreement_adjudications)
        )

    for case_id, record in adjudications.items():
        if case_id not in label_a["by_id"]:
            raise ValueError(f"Adjudication references unknown case: {case_id}")
        if record["kind"] == "manual_override":
            continue
        record["labeler_a_class"] = label_a["by_id"][case_id]["taxonomy_class"]
        record["labeler_b_class"] = label_b["by_id"][case_id]["taxonomy_class"]

    for case_id, record in adjudications.items():
        if record["kind"] == "manual_override":
            record["labeler_a_class"] = label_a["by_id"][case_id]["taxonomy_class"]
            record["labeler_b_class"] = label_b["by_id"][case_id]["taxonomy_class"]

    final_cases = build_final_cases(
        label_a["cases"],
        label_a["by_id"],
        label_b["by_id"],
        adjudications,
        error_id_to_class,
    )
    validate_final_cases(final_cases, error_id_to_class)
    write_ground_truth(final_cases, stats)

    validation = manual_validation(final_cases, manual_labels)
    write_review_summary(final_cases, stats, adjudications, validation)


if __name__ == "__main__":
    main()
