#!/usr/bin/env python3
"""Assemble a refresh report from manifest, batch, latency, and baseline outputs."""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_PATH = ROOT / "case_study" / "eval_manifest.yaml"
DEFAULT_BATCH_RESULTS_PATH = ROOT / "eval" / "results" / "batch_diagnostic_results.json"
DEFAULT_LATENCY_RESULTS_PATH = ROOT / "eval" / "results" / "latency_benchmark.json"
DEFAULT_BASELINE_RESULTS_PATH = ROOT / "eval" / "results" / "baseline_results.json"
DEFAULT_LABELS_PATH = ROOT / "case_study" / "ground_truth.yaml"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "eval-refresh.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--batch-results-path", type=Path, default=DEFAULT_BATCH_RESULTS_PATH)
    parser.add_argument("--latency-results-path", type=Path, default=DEFAULT_LATENCY_RESULTS_PATH)
    parser.add_argument("--baseline-results-path", type=Path, default=DEFAULT_BASELINE_RESULTS_PATH)
    parser.add_argument("--labels-path", type=Path, default=DEFAULT_LABELS_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def markdown_cell(value: str | None) -> str:
    if value is None or value == "":
        return "_None_"
    return value.replace("|", "\\|")


def ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0/0 (0.0%)"
    pct = (numerator / denominator) * 100.0
    return f"{numerator}/{denominator} ({pct:.1f}%)"


def format_float(value: float | None, digits: int = 2) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def summarize_manifest(manifest: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Manifest Stats",
        "",
        "| Source | Total | Core | Noisy | Excluded |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]

    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in manifest:
        grouped[str(entry["source"])]["total"] += 1
        grouped[str(entry["source"])][str(entry["eval_split"])] += 1

    for source in ("kernel_selftests", "stackoverflow", "github_issues"):
        counts = grouped[source]
        lines.append(
            f"| `{source}` | {counts['total']} | {counts['core']} | "
            f"{counts['noisy']} | {counts['excluded']} |"
        )

    total = len(manifest)
    eligible = sum(1 for entry in manifest if entry["eligible"])
    core = sum(1 for entry in manifest if entry["eval_split"] == "core")
    noisy = sum(1 for entry in manifest if entry["eval_split"] == "noisy")
    excluded = sum(1 for entry in manifest if entry["eval_split"] == "excluded")
    lines.extend(
        (
            "",
            f"- Total logged cases: `{total}`",
            f"- Eligible: `{eligible}`",
            f"- Core: `{core}`",
            f"- Noisy: `{noisy}`",
            f"- Excluded: `{excluded}`",
        )
    )
    return lines


def summarize_selftest_families(manifest: list[dict[str, Any]]) -> list[str]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ungrouped = 0
    for entry in manifest:
        if entry["source"] != "kernel_selftests":
            continue
        duplicate_group = entry.get("duplicate_group")
        if duplicate_group:
            grouped[str(duplicate_group)].append(entry)
        else:
            ungrouped += 1

    lines = ["## Selftest Family Analysis", ""]
    representative_total = sum(
        1
        for entry in manifest
        if entry["source"] == "kernel_selftests" and entry["core_representative"]
    )
    lines.extend(
        (
            f"- Families with a terminal rejection line: `{len(grouped)}`",
            f"- Ungrouped selftests with empty/no terminal message: `{ungrouped}`",
            f"- Core representatives retained across families: `{representative_total}`",
            "",
            "| Family (terminal rejection line) | Total | Core | Noisy | Excluded | Representatives |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        )
    )

    ordered_groups = sorted(
        grouped.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )
    for family, entries in ordered_groups:
        core = sum(1 for entry in entries if entry["eval_split"] == "core")
        noisy = sum(1 for entry in entries if entry["eval_split"] == "noisy")
        excluded = sum(1 for entry in entries if entry["eval_split"] == "excluded")
        representatives = sorted(
            entry["case_id"] for entry in entries if entry["core_representative"]
        )
        representative_text = ", ".join(f"`{case_id}`" for case_id in representatives) or "_None_"
        lines.append(
            f"| {markdown_cell(family)} | {len(entries)} | {core} | {noisy} | "
            f"{excluded} | {representative_text} |"
        )
    return lines


def summarize_batch(batch_payload: dict[str, Any]) -> list[str]:
    results = list(batch_payload.get("results", []))
    eligible = [row for row in results if not row.get("skipped")]
    successes = [row for row in eligible if row.get("success")]
    failures = [row for row in eligible if not row.get("success")]
    proof_counts = Counter(str(row.get("proof_status") or "unknown") for row in successes)
    taxonomy_counts = Counter(str(row.get("taxonomy_class") or "unknown") for row in successes)
    avg_spans = statistics.fmean(float(row.get("num_spans", 0)) for row in successes) if successes else 0.0
    btf_count = sum(1 for row in successes if row.get("has_btf_file_line"))

    lines = [
        "## Batch Eval",
        "",
        f"- Generated at: `{batch_payload.get('generated_at', 'unknown')}`",
        f"- Eligible success rate: `{ratio(len(successes), len(eligible))}`",
        f"- Eligible failures: `{len(failures)}`",
        f"- Skipped for short logs: `{sum(1 for row in results if row.get('skipped'))}`",
        f"- Average spans on successful eligible cases: `{avg_spans:.2f}`",
        f"- BTF file:line coverage on successful eligible cases: `{ratio(btf_count, len(successes))}`",
        "",
        "### Proof Status",
        "",
        "| Value | Count | Share |",
        "| --- | ---: | ---: |",
    ]
    for value, count in sorted(proof_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{value}` | {count} | {ratio(count, len(successes)).split(' ', 1)[1]} |")

    lines.extend(("", "### Taxonomy", "", "| Value | Count | Share |", "| --- | ---: | ---: |"))
    for value, count in sorted(taxonomy_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{value}` | {count} | {ratio(count, len(successes)).split(' ', 1)[1]} |")
    return lines


def summarize_latency(latency_payload: dict[str, Any]) -> list[str]:
    stage_summary = latency_payload.get("stage_summary_ms", {}).get("generate_diagnostic", {})
    correlation = latency_payload.get("correlation", {})
    slowest_cases = latency_payload.get("slowest_cases", [])
    slowest_case = slowest_cases[0] if slowest_cases else {}

    lines = [
        "## Latency",
        "",
        f"- Generated at: `{latency_payload.get('generated_at', 'unknown')}`",
        f"- Successful benchmarked cases: `{latency_payload.get('totals', {}).get('successes', 'unknown')}`",
        "",
        "| Metric | ms |",
        "| --- | ---: |",
        f"| min | {format_float(stage_summary.get('min_ms'), 3)} |",
        f"| median | {format_float(stage_summary.get('median_ms'), 3)} |",
        f"| mean | {format_float(stage_summary.get('mean_ms'), 3)} |",
        f"| p95 | {format_float(stage_summary.get('p95_ms'), 3)} |",
        f"| p99 | {format_float(stage_summary.get('p99_ms'), 3)} |",
        f"| max | {format_float(stage_summary.get('max_ms'), 3)} |",
        "",
        f"- Pearson r(log lines, latency): `{format_float(correlation.get('value'), 3)}`",
    ]

    if slowest_case:
        lines.append(
            f"- Slowest case: `{slowest_case.get('case_id', 'unknown')}` at "
            f"`{format_float((slowest_case.get('timings_ms') or {}).get('generate_diagnostic'), 3)}` ms"
        )
    return lines


def normalize_expected_error_id(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.lower() in {"unmatched", "unknown", "none"}:
        return "BPFIX-UNKNOWN"
    return normalized


def normalize_predicted_error_id(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.lower() in {"unmatched", "unknown"}:
        return "BPFIX-UNKNOWN"
    return normalized


def summarize_comparison(
    batch_payload: dict[str, Any],
    baseline_payload: dict[str, Any],
    labels_payload: dict[str, Any],
) -> list[str]:
    batch_by_id = {
        row["case_id"]: row
        for row in batch_payload.get("results", [])
        if not row.get("skipped")
    }
    baseline_by_id = {row["case_id"]: row for row in baseline_payload.get("results", [])}
    common_ids = sorted(set(batch_by_id) & set(baseline_by_id))

    labels = list(labels_payload.get("cases", []))
    taxonomy_by_id = {row["case_id"]: str(row["taxonomy"]) for row in labels if row.get("taxonomy")}
    manual_error_id_by_case: dict[str, str] = {}
    for row in labels:
        notes = str(row.get("notes") or "")
        match = re.search(r"error_id:\s*([A-Za-z0-9_-]+)", notes)
        if match:
            normalized = normalize_expected_error_id(match.group(1))
            if normalized:
                manual_error_id_by_case[str(row["case_id"])] = normalized

    taxonomy_cases = [case_id for case_id in common_ids if case_id in taxonomy_by_id]
    manual_error_cases = [case_id for case_id in common_ids if case_id in manual_error_id_by_case]

    bpfix_tax_correct = sum(
        1
        for case_id in taxonomy_cases
        if str(batch_by_id[case_id].get("taxonomy_class") or "") == taxonomy_by_id[case_id]
    )
    baseline_tax_correct = sum(
        1
        for case_id in taxonomy_cases
        if str(baseline_by_id[case_id].get("taxonomy") or "") == taxonomy_by_id[case_id]
    )

    bpfix_error_correct = sum(
        1
        for case_id in manual_error_cases
        if normalize_predicted_error_id(batch_by_id[case_id].get("error_id"))
        == manual_error_id_by_case[case_id]
    )
    baseline_error_correct = sum(
        1
        for case_id in manual_error_cases
        if normalize_predicted_error_id(baseline_by_id[case_id].get("error_id"))
        == manual_error_id_by_case[case_id]
    )

    bpfix_avg_spans = statistics.fmean(float(batch_by_id[case_id].get("num_spans", 0)) for case_id in common_ids)
    baseline_avg_spans = statistics.fmean(float(baseline_by_id[case_id].get("spans", 0)) for case_id in common_ids)
    bpfix_multi_span = sum(1 for case_id in common_ids if int(batch_by_id[case_id].get("num_spans", 0)) >= 2)
    baseline_multi_span = sum(1 for case_id in common_ids if int(baseline_by_id[case_id].get("spans", 0)) >= 2)
    bpfix_known_proof = sum(
        1
        for case_id in common_ids
        if str(batch_by_id[case_id].get("proof_status") or "unknown") != "unknown"
    )
    baseline_known_proof = sum(
        1
        for case_id in common_ids
        if str(baseline_by_id[case_id].get("proof_status") or "unknown") != "unknown"
    )
    baseline_zero_spans = all(int(baseline_by_id[case_id].get("spans", 0)) == 0 for case_id in common_ids)

    lines = [
        "## Baseline vs BPFix",
        "",
        f"- Compared eligible cases: `{len(common_ids)}`",
        f"- Eligible cases with taxonomy labels: `{len(taxonomy_cases)}`",
        f"- Eligible cases with manual error IDs: `{len(manual_error_cases)}`",
        "",
        "| Metric | Regex baseline | BPFix |",
        "| --- | ---: | ---: |",
        f"| Taxonomy accuracy on labeled eligible cases | {ratio(baseline_tax_correct, len(taxonomy_cases))} | {ratio(bpfix_tax_correct, len(taxonomy_cases))} |",
        f"| Error ID accuracy on manual eligible cases | {ratio(baseline_error_correct, len(manual_error_cases))} | {ratio(bpfix_error_correct, len(manual_error_cases))} |",
        f"| Average spans per eligible case | {baseline_avg_spans:.2f} | {bpfix_avg_spans:.2f} |",
        f"| Multi-span outputs (>=2 spans) | {ratio(baseline_multi_span, len(common_ids))} | {ratio(bpfix_multi_span, len(common_ids))} |",
        f"| Non-unknown proof status | {ratio(baseline_known_proof, len(common_ids))} | {ratio(bpfix_known_proof, len(common_ids))} |",
    ]
    if baseline_zero_spans:
        lines.extend(
            (
                "",
                "- The saved baseline `spans` metric follows the prescribed batch command and reads the top-level `spans` field.",
                "- The regex baseline stores its rejected span under `metadata.proof_spans`, so the recorded `spans` count is `0` for all saved rows.",
            )
        )
    return lines


def main() -> int:
    args = parse_args()
    manifest = list(load_yaml(args.manifest_path) or [])
    batch_payload = dict(load_json(args.batch_results_path) or {})
    latency_payload = dict(load_json(args.latency_results_path) or {})
    baseline_payload = dict(load_json(args.baseline_results_path) or {})
    labels_payload = dict(load_yaml(args.labels_path) or {})

    generated_on = datetime.now(timezone.utc).date().isoformat()
    lines = [
        f"# Eval Refresh {generated_on}",
        "",
        f"- Manifest: `{args.manifest_path.relative_to(ROOT)}`",
        f"- Batch results: `{args.batch_results_path.relative_to(ROOT)}`",
        f"- Latency results: `{args.latency_results_path.relative_to(ROOT)}`",
        f"- Baseline results: `{args.baseline_results_path.relative_to(ROOT)}`",
        "",
    ]
    lines.extend(summarize_manifest(manifest))
    lines.extend(("",))
    lines.extend(summarize_selftest_families(manifest))
    lines.extend(("",))
    lines.extend(summarize_batch(batch_payload))
    lines.extend(("",))
    lines.extend(summarize_latency(latency_payload))
    lines.extend(("",))
    lines.extend(summarize_comparison(batch_payload, baseline_payload, labels_payload))
    report = "\n".join(lines).rstrip() + "\n"

    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    with args.report_path.open("w", encoding="utf-8") as handle:
        handle.write(report)

    print(f"Wrote {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
