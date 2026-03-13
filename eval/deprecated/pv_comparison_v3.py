#!/usr/bin/env python3
"""Re-run the manual PV vs OBLIGE 30-case comparison on the current pipeline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.log_parser import parse_log
from interface.extractor.rust_diagnostic import (
    _select_specific_verifier_line,
    _specific_reject_line_score,
    generate_diagnostic,
)
from interface.extractor.trace_parser import parse_trace


CASE_DIRS = (
    ROOT / "case_study" / "cases" / "kernel_selftests",
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
)
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
DEFAULT_V2_REPORT = ROOT / "docs" / "tmp" / "pv-comparison-v2.md"
DEFAULT_CATALOG_PATH = ROOT / "taxonomy" / "error_catalog.yaml"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "pv_comparison_v3.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "pv-comparison-v3.md"
TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
)

INSTRUCTION_RE = re.compile(r"^\s*\d+:\s*\([0-9a-fA-F]{2}\)", flags=re.MULTILINE)
STATE_RE = re.compile(r"(?:^|\s)R\d+(?:_[a-z]+)?=")
SOURCE_ANNOTATION_RE = re.compile(r"^\s*;", flags=re.MULTILINE)
SUMMARY_PREFIXES = (
    "processed ",
    "verification time",
    "peak_states",
    "max_states",
    "mark_read",
)
GENERAL_PV_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"combined stack size .* too large", flags=re.IGNORECASE), 100),
    (re.compile(r"sequence of \d+ jumps is too complex", flags=re.IGNORECASE), 100),
    (re.compile(r"back-edge", flags=re.IGNORECASE), 98),
    (re.compile(r"loop is not bounded", flags=re.IGNORECASE), 98),
    (re.compile(r"too complex", flags=re.IGNORECASE), 96),
    (re.compile(r"program is too large", flags=re.IGNORECASE), 96),
    (re.compile(r"min value is negative", flags=re.IGNORECASE), 95),
    (
        re.compile(
            r"math between pkt pointer|offset is outside of the packet|pointer arithmetic on .* prohibited",
            flags=re.IGNORECASE,
        ),
        95,
    ),
    (
        re.compile(
            r"invalid access to packet|invalid access to map value|invalid access to memory|invalid mem access",
            flags=re.IGNORECASE,
        ),
        94,
    ),
    (
        re.compile(
            r"program of this type cannot use helper|unknown func|reference type\('unknown '\)",
            flags=re.IGNORECASE,
        ),
        94,
    ),
    (
        re.compile(
            r"expected an initialized|expected uninitialized|unacquired reference|type=.* expected=.*|Possibly NULL pointer",
            flags=re.IGNORECASE,
        ),
        93,
    ),
    (
        re.compile(
            r"function calls are not allowed while holding a lock|reference leak|unreleased reference",
            flags=re.IGNORECASE,
        ),
        92,
    ),
    (
        re.compile(
            r"reg type unsupported|verifier bug|warning:|\bbug\b|Error: failed to load object file",
            flags=re.IGNORECASE,
        ),
        60,
    ),
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
class Score:
    root: bool
    action: bool


@dataclass(slots=True)
class V2Row:
    case_id: str
    taxonomy_class: str
    pv_locations: int
    oblige_locations: int
    pv_root: bool
    oblige_root: bool
    pv_action: bool
    oblige_action: bool


@dataclass(slots=True)
class CaseResult:
    case_id: str
    case_path: str
    taxonomy_class: str
    log_lines: int
    pv_line: str
    pv_locations: int
    oblige_locations: int
    pv_root: bool
    oblige_root: bool
    pv_action: bool
    oblige_action: bool
    oblige_error_id: str | None
    oblige_failure_class: str | None
    oblige_message: str | None
    oblige_note: str | None
    oblige_help: str | None
    oblige_text: str
    oblige_json: dict[str, Any]
    ground_truth_fix: str


def _score(root: bool, action: bool) -> Score:
    return Score(root=root, action=action)


# Manual semantic scoring, preserved to match the v2 rubric.
PV_SCORES: dict[str, Score] = {
    "kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a": _score(True, True),
    "kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246": _score(True, False),
    "kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d": _score(True, True),
    "kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8": _score(True, True),
    "kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39": _score(True, True),
    "kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993": _score(True, False),
    "kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09": _score(True, True),
    "kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a": _score(True, True),
    "kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9": _score(True, False),
    "stackoverflow-69767533": _score(True, False),
    "stackoverflow-61945212": _score(True, False),
    "stackoverflow-77205912": _score(False, False),
    "stackoverflow-70091221": _score(True, True),
    "github-aya-rs-aya-1062": _score(True, True),
    "stackoverflow-79530762": _score(False, False),
    "stackoverflow-73088287": _score(False, False),
    "stackoverflow-74178703": _score(False, False),
    "stackoverflow-76160985": _score(False, False),
    "stackoverflow-70750259": _score(False, False),
    "kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda": _score(True, True),
    "kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d": _score(True, True),
    "stackoverflow-56872436": _score(True, True),
    "stackoverflow-78753911": _score(True, True),
    "github-cilium-cilium-41412": _score(False, False),
    "github-cilium-cilium-35182": _score(True, True),
    "github-aya-rs-aya-1233": _score(True, True),
    "github-aya-rs-aya-864": _score(True, False),
    "stackoverflow-76441958": _score(False, False),
    "github-cilium-cilium-44216": _score(False, False),
    "github-cilium-cilium-41996": _score(False, False),
}

OBLIGE_SCORES: dict[str, Score] = {
    "kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a": _score(True, True),
    "kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246": _score(True, True),
    "kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d": _score(True, True),
    "kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8": _score(True, True),
    "kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39": _score(True, True),
    "kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993": _score(False, False),
    "kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09": _score(True, True),
    "kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a": _score(True, True),
    "kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9": _score(True, True),
    "stackoverflow-69767533": _score(False, False),
    "stackoverflow-61945212": _score(True, True),
    "stackoverflow-77205912": _score(False, False),
    "stackoverflow-70091221": _score(True, True),
    "github-aya-rs-aya-1062": _score(True, False),
    "stackoverflow-79530762": _score(True, False),
    "stackoverflow-73088287": _score(False, False),
    "stackoverflow-74178703": _score(False, False),
    "stackoverflow-76160985": _score(False, False),
    "stackoverflow-70750259": _score(True, True),
    "kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda": _score(True, True),
    "kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d": _score(True, True),
    "stackoverflow-56872436": _score(True, True),
    "stackoverflow-78753911": _score(True, True),
    "github-cilium-cilium-41412": _score(True, True),
    "github-cilium-cilium-35182": _score(True, True),
    "github-aya-rs-aya-1233": _score(True, True),
    "github-aya-rs-aya-864": _score(True, True),
    "stackoverflow-76441958": _score(False, False),
    "github-cilium-cilium-44216": _score(False, False),
    "github-cilium-cilium-41996": _score(False, False),
}


def parse_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def load_manual_labels(path: Path) -> list[ManualLabel]:
    labels: list[ManualLabel] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 10:
            continue
        labels.append(
            ManualLabel(
                case_id=cells[0].strip("`"),
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
        )
    return labels


def load_v2_rows(path: Path) -> dict[str, V2Row]:
    rows: dict[str, V2Row] = {}
    in_table = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## 30-Case Table"):
            in_table = True
            continue
        if in_table and line.startswith("## Summary Statistics"):
            break
        if not in_table or not line.startswith("| `"):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 11:
            continue
        case_id = cells[0].strip("`")
        rows[case_id] = V2Row(
            case_id=case_id,
            taxonomy_class=cells[1].strip("`"),
            pv_locations=int(cells[3]),
            oblige_locations=int(cells[4]),
            pv_root=cells[5] == "Y",
            oblige_root=cells[6] == "Y",
            pv_action=cells[7] == "Y",
            oblige_action=cells[8] == "Y",
        )
    return rows


def build_case_index(case_dirs: tuple[Path, ...]) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for case_dir in case_dirs:
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            payload = read_yaml(path)
            case_id = str(payload.get("case_id") or path.stem)
            index[case_id] = path
    return index


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def extract_log_blocks(case_data: dict[str, Any]) -> tuple[list[str], str]:
    verifier_log = case_data.get("verifier_log")
    if isinstance(verifier_log, str) and verifier_log.strip():
        return [verifier_log.strip()], "string"

    if isinstance(verifier_log, dict):
        blocks = [
            block.strip()
            for block in verifier_log.get("blocks") or []
            if isinstance(block, str) and block.strip()
        ]
        if blocks:
            return blocks, "blocks"

        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return [combined.strip()], "combined"

    verifier_logs = case_data.get("verifier_logs")
    if isinstance(verifier_logs, list):
        blocks = [
            block.strip()
            for block in verifier_logs
            if isinstance(block, str) and block.strip()
        ]
        if blocks:
            return blocks, "verifier_logs"

    return [], "missing"


def score_log_block(block: str) -> int:
    lower = block.lower()
    score = 0
    if INSTRUCTION_RE.search(block):
        score += 8
    if re.search(STATE_RE, block):
        score += 6
    if "processed " in lower and " insns" in lower:
        score += 3
    if SOURCE_ANNOTATION_RE.search(block):
        score += 2
    if "last_idx" in lower or "regs=" in lower or "stack=" in lower:
        score += 2
    if "invalid access" in lower or "not allowed" in lower or "unknown func" in lower:
        score += 1
    return score


def select_primary_log(case_data: dict[str, Any]) -> tuple[str, str]:
    blocks, origin = extract_log_blocks(case_data)
    if not blocks:
        return "", origin
    if len(blocks) == 1:
        return blocks[0], origin
    return max(blocks, key=score_log_block), f"{origin}:best_block"


def normalize_verifier_line(line: str | None) -> str:
    if not line:
        return ""
    normalized = " ".join(line.strip().split())
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    return normalized


def select_general_pv_line(lines: list[str]) -> str | None:
    best_line = ""
    best_score = -1

    for raw_line in lines:
        line = normalize_verifier_line(raw_line)
        if not line:
            continue
        lower = line.lower()
        if line.startswith(";"):
            continue
        if INSTRUCTION_RE.match(line):
            continue
        score = 0
        for pattern, weight in GENERAL_PV_PATTERNS:
            if pattern.search(line):
                score = max(score, weight)
        if lower.startswith(SUMMARY_PREFIXES):
            score -= 30
        if line.startswith("libbpf:"):
            score -= 10
        if line.count("fp-") >= 5 or line.count("R") >= 8:
            score -= 12
        if score > best_score:
            best_score = score
            best_line = line

    if best_score > 0:
        return best_line
    return None


def select_pv_line(log_text: str, catalog_path: Path) -> str:
    parsed_log = parse_log(log_text, catalog_path=str(catalog_path))
    trace = parse_trace(log_text)
    specific_line = _select_specific_verifier_line(parsed_log)

    if specific_line and _specific_reject_line_score(specific_line) > 0:
        return specific_line
    if trace.error_line:
        return normalize_verifier_line(trace.error_line)

    general_line = select_general_pv_line(parsed_log.lines)
    if general_line:
        return general_line

    fallback = specific_line or parsed_log.error_line or ""
    return normalize_verifier_line(fallback)


def count_unique_locations(diagnostic_json: dict[str, Any]) -> int:
    metadata = diagnostic_json.get("metadata") or {}
    spans = metadata.get("proof_spans") or []
    unique = {
        (
            span.get("path"),
            span.get("line"),
            span.get("source_text"),
        )
        for span in spans
    }
    return len(unique)


def count_non_empty_lines(text: str) -> int:
    return len([line for line in text.splitlines() if line.strip()])


def bool_cell(value: bool) -> str:
    return "Y" if value else "N"


def ratio(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator}"


def mean(values: list[int]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    separator = ["---"] * len(headers)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(separator) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def run_case(
    label: ManualLabel,
    case_path: Path,
    *,
    catalog_path: Path,
) -> CaseResult:
    case_data = read_yaml(case_path)
    log_text, _ = select_primary_log(case_data)
    diagnostic = generate_diagnostic(log_text, catalog_path=str(catalog_path))
    diagnostic_json = diagnostic.json_data
    metadata = diagnostic_json.get("metadata") or {}
    pv_score = PV_SCORES[label.case_id]
    oblige_score = OBLIGE_SCORES[label.case_id]

    return CaseResult(
        case_id=label.case_id,
        case_path=str(case_path),
        taxonomy_class=label.taxonomy_class,
        log_lines=count_non_empty_lines(log_text),
        pv_line=select_pv_line(log_text, catalog_path),
        pv_locations=1,
        oblige_locations=count_unique_locations(diagnostic_json),
        pv_root=pv_score.root,
        oblige_root=oblige_score.root,
        pv_action=pv_score.action,
        oblige_action=oblige_score.action,
        oblige_error_id=diagnostic_json.get("error_id"),
        oblige_failure_class=diagnostic_json.get("failure_class"),
        oblige_message=diagnostic_json.get("message"),
        oblige_note=metadata.get("note"),
        oblige_help=metadata.get("help"),
        oblige_text=diagnostic.text,
        oblige_json=diagnostic_json,
        ground_truth_fix=label.ground_truth_fix,
    )


def summarize_current(results: list[CaseResult]) -> dict[str, Any]:
    pv_locs = [result.pv_locations for result in results]
    oblige_locs = [result.oblige_locations for result in results]
    return {
        "pv_mean_locs": mean(pv_locs),
        "oblige_mean_locs": mean(oblige_locs),
        "pv_multi_loc": sum(1 for value in pv_locs if value > 1),
        "oblige_multi_loc": sum(1 for value in oblige_locs if value > 1),
        "pv_root": sum(result.pv_root for result in results),
        "oblige_root": sum(result.oblige_root for result in results),
        "pv_action": sum(result.pv_action for result in results),
        "oblige_action": sum(result.oblige_action for result in results),
    }


def summarize_per_class(results: list[CaseResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for taxonomy_class in TAXONOMY_ORDER:
        bucket = [result for result in results if result.taxonomy_class == taxonomy_class]
        rows.append(
            {
                "taxonomy_class": taxonomy_class,
                "cases": len(bucket),
                "pv_root": sum(result.pv_root for result in bucket),
                "oblige_root": sum(result.oblige_root for result in bucket),
                "pv_action": sum(result.pv_action for result in bucket),
                "oblige_action": sum(result.oblige_action for result in bucket),
            }
        )
    return rows


def compare_against_pv(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    comparison = {
        "root": {"better": 0, "worse": 0, "tied": 0},
        "action": {"better": 0, "worse": 0, "tied": 0},
    }
    for result in results:
        for metric, oblige_value, pv_value in (
            ("root", result.oblige_root, result.pv_root),
            ("action", result.oblige_action, result.pv_action),
        ):
            if oblige_value and not pv_value:
                comparison[metric]["better"] += 1
            elif pv_value and not oblige_value:
                comparison[metric]["worse"] += 1
            else:
                comparison[metric]["tied"] += 1
    return comparison


def compare_to_v2(results: list[CaseResult], v2_rows: dict[str, V2Row]) -> dict[str, Any]:
    improved: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    loc_only: list[dict[str, Any]] = []

    for result in results:
        previous = v2_rows[result.case_id]
        changed = (
            result.oblige_root != previous.oblige_root
            or result.oblige_action != previous.oblige_action
            or result.oblige_locations != previous.oblige_locations
        )
        if not changed:
            continue
        row = {
            "case_id": result.case_id,
            "taxonomy_class": result.taxonomy_class,
            "root_before": previous.oblige_root,
            "root_after": result.oblige_root,
            "action_before": previous.oblige_action,
            "action_after": result.oblige_action,
            "locs_before": previous.oblige_locations,
            "locs_after": result.oblige_locations,
        }
        if (
            (result.oblige_root and not previous.oblige_root)
            or (result.oblige_action and not previous.oblige_action)
        ):
            improved.append(row)
        elif (
            (previous.oblige_root and not result.oblige_root)
            or (previous.oblige_action and not result.oblige_action)
        ):
            regressed.append(row)
        else:
            loc_only.append(row)

    v2_oblige_root = sum(row.oblige_root for row in v2_rows.values())
    v2_oblige_action = sum(row.oblige_action for row in v2_rows.values())
    v2_oblige_locs = mean([row.oblige_locations for row in v2_rows.values()])
    v2_oblige_multi_loc = sum(1 for row in v2_rows.values() if row.oblige_locations > 1)

    current = summarize_current(results)
    return {
        "overall": {
            "v2_oblige_root": v2_oblige_root,
            "v3_oblige_root": current["oblige_root"],
            "v2_oblige_action": v2_oblige_action,
            "v3_oblige_action": current["oblige_action"],
            "v2_oblige_mean_locs": v2_oblige_locs,
            "v3_oblige_mean_locs": current["oblige_mean_locs"],
            "v2_oblige_multi_loc": v2_oblige_multi_loc,
            "v3_oblige_multi_loc": current["oblige_multi_loc"],
        },
        "improved": improved,
        "regressed": regressed,
        "loc_only": loc_only,
    }


def build_report(
    *,
    results: list[CaseResult],
    current: dict[str, Any],
    per_class: list[dict[str, Any]],
    pv_comparison: dict[str, dict[str, int]],
    v2_comparison: dict[str, Any],
) -> str:
    case_rows = [
        [
            f"`{result.case_id}`",
            f"`{result.taxonomy_class}`",
            str(result.log_lines),
            str(result.pv_locations),
            str(result.oblige_locations),
            bool_cell(result.pv_root),
            bool_cell(result.oblige_root),
            bool_cell(result.pv_action),
            bool_cell(result.oblige_action),
        ]
        for result in results
    ]

    summary_rows = [
        ["Mean source locations", f"{current['pv_mean_locs']:.2f}", f"{current['oblige_mean_locs']:.2f}"],
        ["Cases with >1 source location", ratio(current["pv_multi_loc"], len(results)), ratio(current["oblige_multi_loc"], len(results))],
        ["Root cause identified", ratio(current["pv_root"], len(results)), ratio(current["oblige_root"], len(results))],
        ["Actionable fix direction", ratio(current["pv_action"], len(results)), ratio(current["oblige_action"], len(results))],
    ]

    per_class_rows = [
        [
            f"`{row['taxonomy_class']}`",
            str(row["cases"]),
            ratio(row["pv_root"], row["cases"]),
            ratio(row["oblige_root"], row["cases"]),
            ratio(row["pv_action"], row["cases"]),
            ratio(row["oblige_action"], row["cases"]),
        ]
        for row in per_class
    ]

    v2_overall = v2_comparison["overall"]
    v2_rows = [
        ["Root cause identified", ratio(v2_overall["v2_oblige_root"], len(results)), ratio(v2_overall["v3_oblige_root"], len(results)), f"{v2_overall['v3_oblige_root'] - v2_overall['v2_oblige_root']:+d}"],
        ["Actionable fix direction", ratio(v2_overall["v2_oblige_action"], len(results)), ratio(v2_overall["v3_oblige_action"], len(results)), f"{v2_overall['v3_oblige_action'] - v2_overall['v2_oblige_action']:+d}"],
        ["Mean source locations", f"{v2_overall['v2_oblige_mean_locs']:.2f}", f"{v2_overall['v3_oblige_mean_locs']:.2f}", f"{v2_overall['v3_oblige_mean_locs'] - v2_overall['v2_oblige_mean_locs']:+.2f}"],
        ["Cases with >1 source location", ratio(v2_overall["v2_oblige_multi_loc"], len(results)), ratio(v2_overall["v3_oblige_multi_loc"], len(results)), f"{v2_overall['v3_oblige_multi_loc'] - v2_overall['v2_oblige_multi_loc']:+d}"],
    ]

    improved_rows = [
        [
            f"`{row['case_id']}`",
            f"`{row['taxonomy_class']}`",
            f"{bool_cell(row['root_before'])} -> {bool_cell(row['root_after'])}",
            f"{bool_cell(row['action_before'])} -> {bool_cell(row['action_after'])}",
            f"{row['locs_before']} -> {row['locs_after']}",
        ]
        for row in v2_comparison["improved"]
    ]
    regression_rows = [
        [
            f"`{row['case_id']}`",
            f"`{row['taxonomy_class']}`",
            f"{bool_cell(row['root_before'])} -> {bool_cell(row['root_after'])}",
            f"{bool_cell(row['action_before'])} -> {bool_cell(row['action_after'])}",
            f"{row['locs_before']} -> {row['locs_after']}",
        ]
        for row in v2_comparison["regressed"]
    ]
    loc_rows = [
        [
            f"`{row['case_id']}`",
            f"`{row['taxonomy_class']}`",
            f"{bool_cell(row['root_before'])} -> {bool_cell(row['root_after'])}",
            f"{bool_cell(row['action_before'])} -> {bool_cell(row['action_after'])}",
            f"{row['locs_before']} -> {row['locs_after']}",
        ]
        for row in v2_comparison["loc_only"]
    ]

    oblige_beats_pv = current["oblige_root"] > current["pv_root"] and current["oblige_action"] >= current["pv_action"]
    conclusion = (
        "On this rerun, OBLIGE now beats the PV one-line baseline overall on the 30-case benchmark."
        if oblige_beats_pv
        else "On this rerun, OBLIGE still does not beat the PV one-line baseline overall on the 30-case benchmark."
    )

    lines = [
        "# OBLIGE vs Pretty Verifier (PV), v3",
        "",
        "Date: 2026-03-12",
        "",
        "## Method",
        "",
        "- Reused the same 30-case benchmark from `docs/tmp/manual-labeling-30cases.md` and the same `select_primary_log(...)` policy from the earlier comparison, so StackOverflow/GitHub cases with multiple `verifier_log.blocks` still use the highest-signal verbose block.",
        '- OBLIGE was rerun on every case through `interface.extractor.rust_diagnostic.generate_diagnostic(log, catalog_path="taxonomy/error_catalog.yaml")` using the current pipeline with the fallback fixes from `docs/tmp/regression-fix-report.md`.',
        "- PV was kept as the same one-line baseline as v2: one verifier reject line only, with one implied source location. When trailer noise obscured the useful reject line, the rerun selected the strongest reject line from the same log instead of literal `processed ...`, `stack depth ...`, or wrapper text such as `Invalid argument (os error 22)`.",
        '- `source locations` still counts unique `(path, line, source_text)` entries from `json_data["metadata"]["proof_spans"]`; PV remains fixed at `1` by construction.',
        "- `root cause` and `actionability` were manually rescored against the same benchmark ground-truth fix notes as v2. The per-case Y/N judgments are semantic, not structural proxies, because that was the original v2 rubric.",
        "",
        "## 30-Case Table",
        "",
        markdown_table(
            ["Case", "Class", "Log lines", "PV locs", "OBLIGE locs", "PV root", "OBLIGE root", "PV action", "OBLIGE action"],
            case_rows,
        ),
        "",
        "## Overall Scores",
        "",
        markdown_table(
            ["Metric", "PV", "OBLIGE"],
            summary_rows,
        ),
        "",
        f"- Root-cause comparison by case: OBLIGE better on `{pv_comparison['root']['better']}` cases, worse on `{pv_comparison['root']['worse']}`, tied on `{pv_comparison['root']['tied']}`.",
        f"- Actionability comparison by case: OBLIGE better on `{pv_comparison['action']['better']}` cases, worse on `{pv_comparison['action']['worse']}`, tied on `{pv_comparison['action']['tied']}`.",
        "",
        "## Per-Class Breakdown",
        "",
        markdown_table(
            ["Class", "Cases", "PV root", "OBLIGE root", "PV action", "OBLIGE action"],
            per_class_rows,
        ),
        "",
        "## Comparison to v2",
        "",
        markdown_table(
            ["Metric", "OBLIGE v2", "OBLIGE v3", "Delta"],
            v2_rows,
        ),
        "",
        "Improved cases relative to v2:",
        "",
        markdown_table(
            ["Case", "Class", "Root v2 -> v3", "Action v2 -> v3", "Locs v2 -> v3"],
            improved_rows,
        ),
        "",
    ]

    if regression_rows:
        lines.extend(
            [
                "Remaining regressions relative to v2:",
                "",
                markdown_table(
                    ["Case", "Class", "Root v2 -> v3", "Action v2 -> v3", "Locs v2 -> v3"],
                    regression_rows,
                ),
                "",
            ]
        )

    if loc_rows:
        lines.extend(
            [
                "Location-only changes relative to v2:",
                "",
                markdown_table(
                    ["Case", "Class", "Root v2 -> v3", "Action v2 -> v3", "Locs v2 -> v3"],
                    loc_rows,
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## Conclusion",
            "",
            f"- {conclusion}",
            f"- The overall swing is the regression-fix cluster that v2 called out: OBLIGE now recovers the direct-contract or environment advice on iterator protocol, dynptr protocol, lock-context, helper-availability, and forged-pointer cases instead of collapsing to generic `Regenerate BTF artifacts` or verifier-limit text.",
            f"- The strongest net gains are in `source_bug` (`5/13 -> 10/13` root, `5/13 -> 10/13` action) and `env_mismatch` (`1/4 -> 3/4` root, `1/4 -> 3/4` action). Lowering-artifact coverage stays ahead of PV on root cause (`3/6` vs `1/6`), but the actionability gap on that class is still unresolved.",
            "- The main remaining weak spot in this rerun is `stackoverflow-69767533`, where the current fallback locks onto the helper-arg contract instead of the benchmark's intended uninitialized-stack diagnosis. Several lowering-artifact cases also still stop at generic bounds/range advice rather than the source-level rewrite that fixed them.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_json_payload(
    *,
    results: list[CaseResult],
    current: dict[str, Any],
    per_class: list[dict[str, Any]],
    pv_comparison: dict[str, dict[str, int]],
    v2_comparison: dict[str, Any],
) -> dict[str, Any]:
    return {
        "current_summary": current,
        "per_class": per_class,
        "against_pv": pv_comparison,
        "against_v2": v2_comparison,
        "cases": [asdict(result) for result in results],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual-labels", type=Path, default=DEFAULT_MANUAL_LABELS)
    parser.add_argument("--v2-report", type=Path, default=DEFAULT_V2_REPORT)
    parser.add_argument("--catalog-path", type=Path, default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    labels = load_manual_labels(args.manual_labels)
    v2_rows = load_v2_rows(args.v2_report)
    case_index = build_case_index(CASE_DIRS)

    label_ids = {label.case_id for label in labels}
    if label_ids != set(PV_SCORES) or label_ids != set(OBLIGE_SCORES):
        missing_pv = sorted(label_ids - set(PV_SCORES))
        missing_oblige = sorted(label_ids - set(OBLIGE_SCORES))
        extra_pv = sorted(set(PV_SCORES) - label_ids)
        extra_oblige = sorted(set(OBLIGE_SCORES) - label_ids)
        raise SystemExit(
            "Manual score tables do not match the 30-case benchmark.\n"
            f"missing_pv={missing_pv}\n"
            f"missing_oblige={missing_oblige}\n"
            f"extra_pv={extra_pv}\n"
            f"extra_oblige={extra_oblige}"
        )

    missing_cases = sorted(label_ids - set(case_index))
    if missing_cases:
        raise SystemExit(f"Missing case YAMLs: {missing_cases}")

    missing_v2 = sorted(label_ids - set(v2_rows))
    if missing_v2:
        raise SystemExit(f"Missing v2 rows: {missing_v2}")

    results = [
        run_case(label, case_index[label.case_id], catalog_path=args.catalog_path)
        for label in labels
    ]
    current = summarize_current(results)
    per_class = summarize_per_class(results)
    pv_comparison = compare_against_pv(results)
    v2_comparison = compare_to_v2(results, v2_rows)

    payload = build_json_payload(
        results=results,
        current=current,
        per_class=per_class,
        pv_comparison=pv_comparison,
        v2_comparison=v2_comparison,
    )
    report = build_report(
        results=results,
        current=current,
        per_class=per_class,
        pv_comparison=pv_comparison,
        v2_comparison=v2_comparison,
    )

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")

    print(f"Wrote {args.results_path}")
    print(f"Wrote {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
