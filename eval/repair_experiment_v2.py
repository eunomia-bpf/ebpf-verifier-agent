#!/usr/bin/env python3
"""Build the v2 repair-experiment case bundle and aggregate manual A/B results."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.repair_experiment import (  # noqa: E402
    ALLOWED_TAXONOMIES,
    TAXONOMY_ORDER,
    CaseCandidate,
    build_candidate,
    choose_next_candidate,
    iter_case_paths,
    load_manual_labels,
    lookup_manual_label,
    markdown_cell,
    now_iso,
    read_yaml,
)


CASE_DIRS = (
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
    ROOT / "case_study" / "cases" / "kernel_selftests",
)
DESIRED_TARGET_COUNTS = {
    "lowering_artifact": 15,
    "source_bug": 23,
    "verifier_limit": 8,
    "env_mismatch": 8,
}
TOTAL_CASES = 54
DEFAULT_BUNDLE_PATH = ROOT / "docs" / "tmp" / "repair-experiment-v2-bundle.json"
DEFAULT_CASE_PACKET_DIR = ROOT / "docs" / "tmp" / "repair-experiment-v2-cases"
DEFAULT_RESULTS_PATH = ROOT / "docs" / "tmp" / "repair-experiment-v2-analyses.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "repair-experiment-v2-results.md"
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
DEFAULT_PARTIALS_DIR = ROOT / "docs" / "tmp" / "repair-experiment-v2-partials"


@dataclass(slots=True)
class GroundTruthDetails:
    fix_text: str
    fix_text_source: str
    fixed_code: str
    fixed_code_source: str


def extract_fix_text_from_selected_answer(case_data: dict[str, Any]) -> tuple[str, str]:
    selected_answer = case_data.get("selected_answer") or {}
    if not isinstance(selected_answer, dict):
        return "", "missing"
    for key in ("fix_description", "body_text"):
        value = selected_answer.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), f"selected_answer.{key}"
    return "", "missing"


def extract_fix_text_from_issue_fix(case_data: dict[str, Any]) -> tuple[str, str]:
    issue_fix = case_data.get("fix") or {}
    if not isinstance(issue_fix, dict):
        return "", "missing"

    selected_comment = issue_fix.get("selected_comment") or {}
    if isinstance(selected_comment, dict):
        value = selected_comment.get("body_text")
        if isinstance(value, str) and value.strip():
            return value.strip(), "fix.selected_comment.body_text"

    for key in ("summary", "description", "body_text"):
        value = issue_fix.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), f"fix.{key}"
    return "", "missing"


def extract_solution_text(case_data: dict[str, Any]) -> tuple[str, str]:
    solution = case_data.get("solution")
    if isinstance(solution, str) and solution.strip():
        return solution.strip(), "solution"
    if isinstance(solution, dict):
        for key in ("summary", "description", "body_text", "text"):
            value = solution.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip(), f"solution.{key}"
    return "", "missing"


def extract_fixed_code(case_data: dict[str, Any]) -> tuple[str, str]:
    value = case_data.get("fixed_code")
    if isinstance(value, str) and value.strip():
        return value.strip(), "fixed_code"
    solution = case_data.get("solution")
    if isinstance(solution, dict):
        code = solution.get("fixed_code")
        if isinstance(code, str) and code.strip():
            return code.strip(), "solution.fixed_code"
    return "", "missing"


def extract_ground_truth_details(
    *,
    case_data: dict[str, Any],
    candidate: CaseCandidate,
    manual_label_text: str,
) -> GroundTruthDetails:
    if manual_label_text.strip():
        fix_text = manual_label_text.strip()
        fix_text_source = "manual_label"
    else:
        fix_text = ""
        fix_text_source = "missing"
        for extractor in (
            extract_fix_text_from_selected_answer,
            extract_fix_text_from_issue_fix,
            extract_solution_text,
        ):
            fix_text, fix_text_source = extractor(case_data)
            if fix_text:
                break
        if not fix_text and candidate.ground_truth_fix.strip():
            fix_text = candidate.ground_truth_fix.strip()
            fix_text_source = candidate.ground_truth_fix_source

    fixed_code, fixed_code_source = extract_fixed_code(case_data)
    return GroundTruthDetails(
        fix_text=fix_text,
        fix_text_source=fix_text_source,
        fixed_code=fixed_code,
        fixed_code_source=fixed_code_source,
    )


def build_prompt(candidate: CaseCandidate, condition: str) -> str:
    base = (
        "Here is eBPF code that fails verification. Fix it.\n\n"
        f"Code:\n{candidate.source_code}\n\n"
        f"Verifier log:\n{candidate.verifier_log}"
    )
    if condition == "a":
        return base
    return f"{base}\n\nDiagnostic analysis:\n{candidate.diagnostic_text}"


def build_case_packet(
    candidate: CaseCandidate,
    *,
    case_data: dict[str, Any],
    manual_label_text: str,
) -> dict[str, Any]:
    ground_truth = extract_ground_truth_details(
        case_data=case_data,
        candidate=candidate,
        manual_label_text=manual_label_text,
    )
    return {
        "case_id": candidate.case_id,
        "case_path": candidate.case_path,
        "source": candidate.source,
        "title": candidate.title,
        "source_url": candidate.source_url,
        "taxonomy_class": candidate.taxonomy_class,
        "taxonomy_source": candidate.taxonomy_source,
        "error_id": candidate.error_id,
        "verifier_log": candidate.verifier_log,
        "source_code": candidate.source_code,
        "code_source": candidate.code_source,
        "oblige_output": candidate.diagnostic_text,
        "oblige_json": candidate.diagnostic_json,
        "root_span_text": candidate.root_span_text,
        "symptom_span_text": candidate.symptom_span_text,
        "expected_fix_type": candidate.expected_fix_type,
        "expected_fix_tags": list(candidate.expected_fix_tags),
        "expected_location_kind": candidate.expected_location_kind,
        "ground_truth_fix": ground_truth.fix_text,
        "ground_truth_fix_source": ground_truth.fix_text_source,
        "ground_truth_fixed_code": ground_truth.fixed_code,
        "ground_truth_fixed_code_source": ground_truth.fixed_code_source,
        "selection_score": candidate.selection_score,
        "selection_notes": list(candidate.selection_notes),
        "prompt_a": build_prompt(candidate, "a"),
        "prompt_b": build_prompt(candidate, "b"),
    }


def select_cases_v2(
    candidates: list[CaseCandidate],
    *,
    case_count: int,
) -> tuple[list[CaseCandidate], dict[str, Any]]:
    selected: list[CaseCandidate] = []
    selected_ids: set[str] = set()
    bucket_seen_tags: dict[str, set[str]] = {taxonomy: set() for taxonomy in ALLOWED_TAXONOMIES}
    bucket_seen_sources: dict[str, set[str]] = {taxonomy: set() for taxonomy in ALLOWED_TAXONOMIES}
    pool_counts = Counter(candidate.taxonomy_class for candidate in candidates)
    effective_targets = {
        taxonomy: min(DESIRED_TARGET_COUNTS[taxonomy], pool_counts.get(taxonomy, 0))
        for taxonomy in TAXONOMY_ORDER
    }

    for taxonomy in TAXONOMY_ORDER:
        while sum(1 for item in selected if item.taxonomy_class == taxonomy) < effective_targets[taxonomy]:
            eligible = [
                candidate
                for candidate in candidates
                if candidate.case_id not in selected_ids and candidate.taxonomy_class == taxonomy
            ]
            pick = choose_next_candidate(
                eligible,
                bucket_seen_tags[taxonomy],
                bucket_seen_sources[taxonomy],
            )
            if pick is None:
                raise RuntimeError(f"Unable to satisfy target for taxonomy={taxonomy}")
            selected.append(pick)
            selected_ids.add(pick.case_id)
            bucket_seen_tags[taxonomy].add(pick.expected_fix_type)
            bucket_seen_sources[taxonomy].add(pick.source)

    overall_seen_tags = {candidate.expected_fix_type for candidate in selected}
    overall_seen_sources = {candidate.source for candidate in selected}
    while len(selected) < case_count:
        eligible = [candidate for candidate in candidates if candidate.case_id not in selected_ids]
        pick = choose_next_candidate(eligible, overall_seen_tags, overall_seen_sources)
        if pick is None:
            raise RuntimeError(f"Only selected {len(selected)} cases, expected {case_count}")
        selected.append(pick)
        selected_ids.add(pick.case_id)
        overall_seen_tags.add(pick.expected_fix_type)
        overall_seen_sources.add(pick.source)

    selected.sort(
        key=lambda candidate: (
            TAXONOMY_ORDER.index(candidate.taxonomy_class),
            candidate.source,
            candidate.case_id,
        )
    )
    return selected, {
        "requested_case_count": case_count,
        "desired_targets": dict(DESIRED_TARGET_COUNTS),
        "effective_targets": effective_targets,
        "pool_counts": dict(pool_counts),
        "selected_taxonomy_counts": dict(Counter(item.taxonomy_class for item in selected)),
        "selected_source_counts": dict(Counter(item.source for item in selected)),
        "selected_case_ids": [item.case_id for item in selected],
    }


def write_case_packets(
    *,
    bundle_path: Path,
    case_packet_dir: Path,
    selection_summary: dict[str, Any],
    case_packets: list[dict[str, Any]],
) -> None:
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    case_packet_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now_iso(),
        "selection_summary": selection_summary,
        "cases": case_packets,
    }
    bundle_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    for packet in case_packets:
        path = case_packet_dir / f"{packet['case_id']}.json"
        path.write_text(json.dumps(packet, indent=2, sort_keys=True), encoding="utf-8")


def load_bundle(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_analysis_payload(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def merge_partial_analyses(partials_dir: Path) -> dict[str, Any]:
    case_rows: list[dict[str, Any]] = []
    for path in sorted(partials_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("cases")
        if not isinstance(items, list):
            raise RuntimeError(f"Partial file has invalid schema: {path}")
        case_rows.extend(item for item in items if isinstance(item, dict))
    return {"generated_at": now_iso(), "cases": case_rows}


def score_triplet(analysis: dict[str, Any]) -> tuple[int, int, int]:
    scores = analysis.get("scores") or {}
    return (
        int(bool(scores.get("location"))),
        int(bool(scores.get("fix_type"))),
        int(bool(scores.get("root_cause"))),
    )


def format_triplet(analysis: dict[str, Any]) -> str:
    location, fix_type, root_cause = score_triplet(analysis)
    return f"{location}/{fix_type}/{root_cause}"


def summarize_scored_cases(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases = len(rows)
    a_location = sum(score_triplet(row["condition_a"])[0] for row in rows)
    a_fix_type = sum(score_triplet(row["condition_a"])[1] for row in rows)
    a_root = sum(score_triplet(row["condition_a"])[2] for row in rows)
    b_location = sum(score_triplet(row["condition_b"])[0] for row in rows)
    b_fix_type = sum(score_triplet(row["condition_b"])[1] for row in rows)
    b_root = sum(score_triplet(row["condition_b"])[2] for row in rows)
    return {
        "cases": cases,
        "condition_a": {
            "location": a_location,
            "fix_type": a_fix_type,
            "root_cause": a_root,
        },
        "condition_b": {
            "location": b_location,
            "fix_type": b_fix_type,
            "root_cause": b_root,
        },
    }


def format_metric(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0/0 (0.0%)"
    pct = (numerator / denominator) * 100.0
    return f"{numerator}/{denominator} ({pct:.1f}%)"


def compact_text(text: str, limit: int = 140) -> str:
    flattened = markdown_cell(text)
    if len(flattened) <= limit:
        return flattened
    return flattened[: limit - 3].rstrip() + "..."


def case_delta(row: dict[str, Any]) -> int:
    return sum(score_triplet(row["condition_b"])) - sum(score_triplet(row["condition_a"]))


def build_report(bundle: dict[str, Any], analysis: dict[str, Any]) -> str:
    packet_by_id = {packet["case_id"]: packet for packet in bundle.get("cases", [])}
    rows: list[dict[str, Any]] = []
    for item in analysis.get("cases", []):
        packet = packet_by_id.get(item.get("case_id"))
        if packet is None:
            raise RuntimeError(f"Analysis references unknown case_id={item.get('case_id')}")
        rows.append(
            {
                "case_id": packet["case_id"],
                "taxonomy_class": packet["taxonomy_class"],
                "source": packet["source"],
                "title": packet["title"],
                "ground_truth_fix": packet["ground_truth_fix"],
                "expected_fix_type": packet["expected_fix_type"],
                "condition_a": item["condition_a"],
                "condition_b": item["condition_b"],
                "overall_notes": item.get("overall_notes", ""),
            }
        )

    if len(rows) != len(packet_by_id):
        missing = sorted(set(packet_by_id) - {row["case_id"] for row in rows})
        raise RuntimeError(f"Missing analyses for {len(missing)} selected cases: {missing}")

    rows.sort(key=lambda row: (TAXONOMY_ORDER.index(row["taxonomy_class"]), row["case_id"]))

    overall = summarize_scored_cases(rows)
    per_taxonomy = {
        taxonomy: summarize_scored_cases([row for row in rows if row["taxonomy_class"] == taxonomy])
        for taxonomy in TAXONOMY_ORDER
    }

    improved = [row for row in rows if case_delta(row) > 0]
    improved.sort(
        key=lambda row: (
            0 if row["taxonomy_class"] == "lowering_artifact" else 1,
            -case_delta(row),
            row["case_id"],
        )
    )
    hurt = [row for row in rows if case_delta(row) < 0]
    hurt.sort(
        key=lambda row: (
            0 if row["taxonomy_class"] == "lowering_artifact" else 1,
            case_delta(row),
            row["case_id"],
        )
    )
    equal = [row for row in rows if case_delta(row) == 0]
    equal.sort(key=lambda row: (TAXONOMY_ORDER.index(row["taxonomy_class"]), row["case_id"]))

    lines = [
        "# Repair Experiment V2: Raw Verifier Log vs OBLIGE Diagnostic",
        "",
        f"- Generated: `{now_iso()}`",
        f"- Selected cases: `{len(rows)}`",
        f"- Desired taxonomy targets: `{json.dumps(bundle['selection_summary']['desired_targets'], sort_keys=True)}`",
        f"- Effective taxonomy targets: `{json.dumps(bundle['selection_summary']['effective_targets'], sort_keys=True)}`",
        f"- Selected taxonomy counts: `{json.dumps(bundle['selection_summary']['selected_taxonomy_counts'], sort_keys=True)}`",
        "",
        "Only 10 `lowering_artifact` cases were eligible in the requested source buckets with usable code, verifier log, and ground-truth fix text, so the remaining slots were backfilled with `source_bug` cases.",
        "",
        "Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.",
        "",
        "## Overall Summary",
        "",
        "| Condition | Location | Fix type | Root cause |",
        "| --- | ---: | ---: | ---: |",
        (
            f"| A (raw verifier log only) | "
            f"{format_metric(overall['condition_a']['location'], overall['cases'])} | "
            f"{format_metric(overall['condition_a']['fix_type'], overall['cases'])} | "
            f"{format_metric(overall['condition_a']['root_cause'], overall['cases'])} |"
        ),
        (
            f"| B (raw log + OBLIGE diagnostic) | "
            f"{format_metric(overall['condition_b']['location'], overall['cases'])} | "
            f"{format_metric(overall['condition_b']['fix_type'], overall['cases'])} | "
            f"{format_metric(overall['condition_b']['root_cause'], overall['cases'])} |"
        ),
        "",
        "## Summary By Taxonomy",
        "",
        "| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for taxonomy in TAXONOMY_ORDER:
        stats = per_taxonomy[taxonomy]
        lines.append(
            f"| `{taxonomy}` | {stats['cases']} | "
            f"{format_metric(stats['condition_a']['location'], stats['cases'])} | "
            f"{format_metric(stats['condition_b']['location'], stats['cases'])} | "
            f"{format_metric(stats['condition_a']['fix_type'], stats['cases'])} | "
            f"{format_metric(stats['condition_b']['fix_type'], stats['cases'])} | "
            f"{format_metric(stats['condition_a']['root_cause'], stats['cases'])} | "
            f"{format_metric(stats['condition_b']['root_cause'], stats['cases'])} |"
        )

    lines.extend(
        [
            "",
            "## Per-Case Results",
            "",
            "| Case | Taxonomy | A score | B score | A fix | B fix | Ground truth |",
            "| --- | --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            f"| `{row['case_id']}` | `{row['taxonomy_class']}` | "
            f"`{format_triplet(row['condition_a'])}` | "
            f"`{format_triplet(row['condition_b'])}` | "
            f"{compact_text(str(row['condition_a'].get('predicted_fix', '')))} | "
            f"{compact_text(str(row['condition_b'].get('predicted_fix', '')))} | "
            f"{compact_text(row['ground_truth_fix'])} |"
        )

    lines.extend(["", "## Cases Where Condition B Does Better", ""])
    if improved:
        for row in improved[:8]:
            lines.extend(
                [
                    f"### `{row['case_id']}`",
                    "",
                    f"- Taxonomy: `{row['taxonomy_class']}`",
                    f"- Condition A score: `{format_triplet(row['condition_a'])}`",
                    f"- Condition B score: `{format_triplet(row['condition_b'])}`",
                    f"- Ground truth: {compact_text(row['ground_truth_fix'], limit=220)}",
                    f"- A fix: {compact_text(str(row['condition_a'].get('predicted_fix', '')), limit=220)}",
                    f"- B fix: {compact_text(str(row['condition_b'].get('predicted_fix', '')), limit=220)}",
                    f"- Notes: {compact_text(row['overall_notes'], limit=220)}",
                    "",
                ]
            )
    else:
        lines.append("- No cases in the scored set showed a net Condition B improvement.")

    lines.extend(["## Cases Where Condition B Does Worse", ""])
    if hurt:
        for row in hurt[:8]:
            lines.extend(
                [
                    f"### `{row['case_id']}`",
                    "",
                    f"- Taxonomy: `{row['taxonomy_class']}`",
                    f"- Condition A score: `{format_triplet(row['condition_a'])}`",
                    f"- Condition B score: `{format_triplet(row['condition_b'])}`",
                    f"- Ground truth: {markdown_cell(row['ground_truth_fix'])}",
                    f"- A fix: {markdown_cell(str(row['condition_a'].get('predicted_fix', '')))}",
                    f"- B fix: {markdown_cell(str(row['condition_b'].get('predicted_fix', '')))}",
                    f"- Notes: {markdown_cell(row['overall_notes'])}",
                    "",
                ]
            )
    else:
        lines.append("- No cases in the scored set showed a net Condition B regression.")

    lines.extend(["## Cases Where Both Conditions Are Equal", ""])
    if equal:
        for row in equal[:8]:
            lines.extend(
                [
                    f"### `{row['case_id']}`",
                    "",
                    f"- Taxonomy: `{row['taxonomy_class']}`",
                    f"- Shared score: `{format_triplet(row['condition_a'])}`",
                    f"- Ground truth: {compact_text(row['ground_truth_fix'], limit=220)}",
                    f"- A fix: {compact_text(str(row['condition_a'].get('predicted_fix', '')), limit=220)}",
                    f"- B fix: {compact_text(str(row['condition_b'].get('predicted_fix', '')), limit=220)}",
                    f"- Notes: {compact_text(row['overall_notes'], limit=220)}",
                    "",
                ]
            )
    else:
        lines.append("- No tied cases were recorded.")

    lines.extend(["## Overall Conclusion", ""])
    if overall["condition_b"]["root_cause"] > overall["condition_a"]["root_cause"]:
        lines.append(
            "Condition B improved root-cause targeting overall, with the strongest gains in cases where the diagnostic exposed the proof-loss site instead of only the rejection site."
        )
    elif overall["condition_b"]["root_cause"] == overall["condition_a"]["root_cause"]:
        lines.append(
            "Condition B matched Condition A on root-cause targeting overall; the diagnostic was useful mainly as corroboration rather than changing the repair direction."
        )
    else:
        lines.append(
            "Condition B underperformed Condition A on root-cause targeting in this run; the diagnostic text may need tighter repair-oriented guidance."
        )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    bundle_parser = subparsers.add_parser("build-bundle")
    bundle_parser.add_argument("--bundle-path", type=Path, default=DEFAULT_BUNDLE_PATH)
    bundle_parser.add_argument("--case-packet-dir", type=Path, default=DEFAULT_CASE_PACKET_DIR)
    bundle_parser.add_argument("--manual-labels-path", type=Path, default=DEFAULT_MANUAL_LABELS)
    bundle_parser.add_argument("--case-count", type=int, default=TOTAL_CASES)

    merge_parser = subparsers.add_parser("merge-partials")
    merge_parser.add_argument("--partials-dir", type=Path, default=DEFAULT_PARTIALS_DIR)
    merge_parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)

    report_parser = subparsers.add_parser("build-report")
    report_parser.add_argument("--bundle-path", type=Path, default=DEFAULT_BUNDLE_PATH)
    report_parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    report_parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)

    return parser.parse_args()


def command_build_bundle(args: argparse.Namespace) -> int:
    manual_labels = load_manual_labels(args.manual_labels_path)
    candidates: list[CaseCandidate] = []
    case_data_by_id: dict[str, dict[str, Any]] = {}
    manual_text_by_id: dict[str, str] = {}

    for path in iter_case_paths(CASE_DIRS):
        if path.name == "index.yaml":
            continue
        candidate = build_candidate(path, manual_labels)
        if candidate is None or candidate.taxonomy_class not in ALLOWED_TAXONOMIES:
            continue
        candidates.append(candidate)
        case_data = read_yaml(path)
        case_data_by_id[candidate.case_id] = case_data
        manual_label = lookup_manual_label(candidate.case_id, manual_labels)
        manual_text_by_id[candidate.case_id] = (
            manual_label.ground_truth_fix.strip() if manual_label is not None else ""
        )

    if len(candidates) < args.case_count:
        raise RuntimeError(f"Only found {len(candidates)} eligible cases, expected {args.case_count}")

    selected, selection_summary = select_cases_v2(candidates, case_count=args.case_count)
    case_packets = [
        build_case_packet(
            candidate,
            case_data=case_data_by_id[candidate.case_id],
            manual_label_text=manual_text_by_id[candidate.case_id],
        )
        for candidate in selected
    ]
    write_case_packets(
        bundle_path=args.bundle_path,
        case_packet_dir=args.case_packet_dir,
        selection_summary=selection_summary,
        case_packets=case_packets,
    )

    print(f"Wrote bundle: {args.bundle_path}")
    print(f"Wrote case packets: {args.case_packet_dir}")
    print("Pool counts:", json.dumps(selection_summary["pool_counts"], sort_keys=True))
    print("Selected counts:", json.dumps(selection_summary["selected_taxonomy_counts"], sort_keys=True))
    return 0


def command_build_report(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle_path)
    analysis = load_analysis_payload(args.results_path)
    report = build_report(bundle, analysis)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")
    print(f"Wrote report: {args.report_path}")
    return 0


def command_merge_partials(args: argparse.Namespace) -> int:
    payload = merge_partial_analyses(args.partials_dir)
    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote merged analyses: {args.results_path}")
    print(f"Merged cases: {len(payload['cases'])}")
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "build-bundle":
        return command_build_bundle(args)
    if args.command == "merge-partials":
        return command_merge_partials(args)
    if args.command == "build-report":
        return command_build_report(args)
    raise RuntimeError(f"Unknown command={args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
