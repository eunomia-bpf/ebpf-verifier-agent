#!/usr/bin/env python3
"""Offline cross-log stability analysis for multi-block verifier logs."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.pipeline import diagnose
from interface.extractor.log_parser import parse_log


CASE_ROOT = ROOT / "case_study" / "cases"
DEFAULT_OUTPUT = ROOT / "docs" / "tmp" / "cross-log-stability-analysis.md"
TARGET_CASE_IDS = (
    "github-cilium-cilium-37478",
    "github-cilium-cilium-36936",
    "github-cilium-cilium-41996",
    "stackoverflow-75515263",
    "stackoverflow-69413427",
    "github-aya-rs-aya-1233",
)
TARGET_CASE_SET = set(TARGET_CASE_IDS)

STRONG_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"invalid mem access",
        r"invalid access",
        r"outside of the packet",
        r"unbounded memory access",
        r"unreleased reference",
        r"unacquired reference",
        r"unknown func",
        r"not allowed",
        r"program of this type cannot use helper",
        r"cannot use helper",
        r"cannot restore",
        r"too many states",
        r"too complex",
        r"complexity limit",
        r"loop is not bounded",
        r"back-edge",
        r"unreachable insn",
        r"min value is negative",
        r"expected=",
        r" expected ",
        r"arg#\d+",
        r"reference type\('unknown '\)",
        r"invalid btf",
        r"missing btf func_info",
        r"must be referenced",
        r"trusted",
        r"dynptr",
        r"math between pkt pointer",
    )
)
MEDIUM_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"verifier error",
        r"load bpf program failed",
        r"failed program load",
        r"failed to load program",
        r"permission denied",
        r"invalid argument",
        r"unknown error",
    )
)
WEAK_CONTEXT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r'error="',
        r'"message":',
        r" verifier output:",
    )
)
INSTRUCTION_LINE_RE = re.compile(r"^\s*\d+:\s*\([0-9a-f]{2}\)", re.IGNORECASE)
REGISTER_STATE_RE = re.compile(r"\bR\d+[_a-zA-Z]*=", re.IGNORECASE)


@dataclass(slots=True)
class BlockAnalysis:
    block_index: int
    raw_error_line: str
    error_id: str | None
    taxonomy_class: str | None
    root_cause_insn: int | None
    proof_status: str | None
    diagnose_error: str | None = None


@dataclass(slots=True)
class CaseAnalysis:
    case_id: str
    case_path: Path
    source_bucket: str
    block_count: int
    blocks: list[BlockAnalysis]
    error_id_stable: bool
    taxonomy_stable: bool
    diagnosis_stable: bool
    root_cause_stable: bool
    proof_stable: bool
    raw_text_stable: bool
    min_jaccard: float
    avg_jaccard: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze every case YAML with multiple verifier_log blocks, run BPFix "
            "diagnosis on each block, and emit a Markdown stability report."
        )
    )
    parser.add_argument(
        "--cases-root",
        type=Path,
        default=CASE_ROOT,
        help="Directory that contains the case YAML corpus.",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Destination Markdown report path.",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> dict | None:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def extract_blocks(payload: dict) -> list[str]:
    verifier_log = payload.get("verifier_log")
    if not isinstance(verifier_log, dict):
        return []
    blocks = verifier_log.get("blocks")
    if not isinstance(blocks, list):
        return []
    normalized: list[str] = []
    for block in blocks:
        if isinstance(block, str):
            normalized.append(block)
        elif block is None:
            normalized.append("")
        else:
            normalized.append(str(block))
    return normalized


def score_error_line(line: str) -> int:
    if not line:
        return -999

    score = 0
    lowered = line.lower()

    for pattern in STRONG_ERROR_PATTERNS:
        if pattern.search(line):
            score += 12
    for pattern in MEDIUM_ERROR_PATTERNS:
        if pattern.search(line):
            score += 6
    for pattern in WEAK_CONTEXT_PATTERNS:
        if pattern.search(line):
            score += 2

    if INSTRUCTION_LINE_RE.match(line):
        score -= 2
        if any(pattern.search(line) for pattern in STRONG_ERROR_PATTERNS):
            score += 5
    if REGISTER_STATE_RE.search(line):
        score -= 3
    if lowered.startswith(
        (
            "processed ",
            "verification time",
            "stack depth",
            "last_idx",
            "regs=",
            "parent didn't",
            "libbpf: -- begin",
            "libbpf: -- end",
        )
    ):
        score -= 8
    if lowered.startswith(";"):
        score -= 4
    if len(line) > 220:
        score -= 2

    return score


def clean_error_line(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""

    quoted_error = re.search(r'error="([^"]+)"', stripped)
    if quoted_error:
        return quoted_error.group(1).strip()

    message_field = re.search(r'"message":\s*"([^"]+)"', stripped)
    if message_field:
        return message_field.group(1).strip()

    return stripped


def extract_raw_error_line(block: str) -> str:
    parsed_error = parse_log(block).error_line.strip()
    best_line = parsed_error
    best_score = score_error_line(parsed_error) if parsed_error else -999

    for raw_line in str(block).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        score = score_error_line(line)
        if score > best_score:
            best_line = line
            best_score = score

    return clean_error_line(best_line)


def jaccard_similarity(left: str, right: str) -> float:
    left_tokens = set(left.split()) if left else set()
    right_tokens = set(right.split()) if right else set()
    if not left_tokens and not right_tokens:
        return 1.0
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def stable_across[T](values: list[T]) -> bool:
    return len(set(values)) == 1


def analyze_case(case_path: Path) -> CaseAnalysis | None:
    payload = load_yaml(case_path)
    if payload is None:
        return None

    blocks = extract_blocks(payload)
    if len(blocks) <= 1:
        return None

    block_analyses: list[BlockAnalysis] = []
    for block_index, block in enumerate(blocks, start=1):
        try:
            diagnosis = diagnose(block)
            block_analyses.append(
                BlockAnalysis(
                    block_index=block_index,
                    raw_error_line=extract_raw_error_line(block),
                    error_id=diagnosis.error_id,
                    taxonomy_class=diagnosis.taxonomy_class,
                    root_cause_insn=diagnosis.root_cause_insn,
                    proof_status=diagnosis.proof_status,
                )
            )
        except Exception as exc:
            block_analyses.append(
                BlockAnalysis(
                    block_index=block_index,
                    raw_error_line=extract_raw_error_line(block),
                    error_id=None,
                    taxonomy_class=None,
                    root_cause_insn=None,
                    proof_status=None,
                    diagnose_error=str(exc),
                )
            )

    error_ids = [block.error_id for block in block_analyses]
    taxonomy_classes = [block.taxonomy_class for block in block_analyses]
    raw_lines = [block.raw_error_line for block in block_analyses]
    root_cause_insns = [block.root_cause_insn for block in block_analyses]
    proof_statuses = [block.proof_status for block in block_analyses]
    pairwise_scores = [
        jaccard_similarity(left.raw_error_line, right.raw_error_line)
        for left, right in combinations(block_analyses, 2)
    ]

    return CaseAnalysis(
        case_id=str(payload.get("case_id", case_path.stem)),
        case_path=case_path,
        source_bucket=case_path.parent.name,
        block_count=len(block_analyses),
        blocks=block_analyses,
        error_id_stable=stable_across(error_ids),
        taxonomy_stable=stable_across(taxonomy_classes),
        diagnosis_stable=stable_across(
            [(block.error_id, block.taxonomy_class) for block in block_analyses]
        ),
        root_cause_stable=stable_across(root_cause_insns),
        proof_stable=stable_across(proof_statuses),
        raw_text_stable=stable_across(raw_lines),
        min_jaccard=min(pairwise_scores) if pairwise_scores else 1.0,
        avg_jaccard=sum(pairwise_scores) / len(pairwise_scores) if pairwise_scores else 1.0,
    )


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def pct(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def format_float(value: float) -> str:
    return f"{value:.3f}"


def truncate(text: str, limit: int = 140) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def md_escape(text: str) -> str:
    return text.replace("|", r"\|").replace("\n", " ").strip()


def render_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(cell) for cell in row) + " |")
    return lines


def top_examples(cases: list[CaseAnalysis], limit: int = 5) -> list[CaseAnalysis]:
    varied_stable = [
        case
        for case in cases
        if case.diagnosis_stable and not case.raw_text_stable
    ]
    varied_stable.sort(key=lambda case: (case.min_jaccard, case.case_id))

    prioritized = [
        case for case in varied_stable if case.case_id in TARGET_CASE_SET
    ]
    other_cases = [
        case for case in varied_stable if case.case_id not in TARGET_CASE_SET
    ]
    combined = prioritized + other_cases
    return combined[:limit]


def summarize_target_cases(cases: list[CaseAnalysis]) -> list[CaseAnalysis]:
    case_by_id = {case.case_id: case for case in cases}
    return [case_by_id[case_id] for case_id in TARGET_CASE_IDS if case_id in case_by_id]


def sort_cases(cases: list[CaseAnalysis]) -> list[CaseAnalysis]:
    return sorted(
        cases,
        key=lambda case: (case.case_id not in TARGET_CASE_SET, case.case_id),
    )


def render_markdown(cases: list[CaseAnalysis]) -> str:
    total_cases = len(cases)
    stable_diagnosis_cases = sum(case.diagnosis_stable for case in cases)
    unstable_raw_but_stable_error_id = sum(
        case.error_id_stable and not case.raw_text_stable for case in cases
    )
    root_stable_cases = sum(case.root_cause_stable for case in cases)
    proof_stable_cases = sum(case.proof_stable for case in cases)
    raw_stable_cases = sum(case.raw_text_stable for case in cases)
    github_cases = sum(case.source_bucket == "github_issues" for case in cases)
    stackoverflow_cases = sum(case.source_bucket == "stackoverflow" for case in cases)

    lines = [
        "# Cross-Log Stability Analysis",
        "",
        "Date: 2026-03-11",
        "",
        "## Scope",
        "",
        (
            f"- Scanned `{total_cases}` case YAMLs with multiple `verifier_log.blocks` "
            f"under `case_study/cases/`."
        ),
        (
            f"- Source buckets represented: `{github_cases}` GitHub issue cases and "
            f"`{stackoverflow_cases}` Stack Overflow cases."
        ),
        (
            "- Included the 6 feasibility-report examples plus every other case whose "
            "`verifier_log.blocks` list has length > 1."
        ),
        (
            "- `stable BPFix diagnosis` means every block in a case keeps the same "
            "`(error_id, taxonomy_class)` pair."
        ),
        (
            "- `raw text unstable` means the extracted raw error lines are not all "
            "identical; pairwise similarity uses whitespace-token Jaccard."
        ),
        "",
        "## Aggregate",
        "",
        (
            f"- Stable BPFix diagnosis: `{stable_diagnosis_cases}/{total_cases}` "
            f"({pct(stable_diagnosis_cases, total_cases)})."
        ),
        (
            f"- Unstable raw error text but stable BPFix `error_id`: "
            f"`{unstable_raw_but_stable_error_id}/{total_cases}` "
            f"({pct(unstable_raw_but_stable_error_id, total_cases)})."
        ),
        (
            f"- Stable `root_cause_insn`: `{root_stable_cases}/{total_cases}` "
            f"({pct(root_stable_cases, total_cases)})."
        ),
        (
            f"- Stable `proof_status`: `{proof_stable_cases}/{total_cases}` "
            f"({pct(proof_stable_cases, total_cases)})."
        ),
        (
            f"- Stable raw error line text after report-side extraction: "
            f"`{raw_stable_cases}/{total_cases}` ({pct(raw_stable_cases, total_cases)})."
        ),
        "",
        "## Feasibility-Report Cases",
        "",
    ]

    target_summary_rows: list[list[str]] = []
    for case in summarize_target_cases(cases):
        target_summary_rows.append(
            [
                case.case_id,
                str(case.block_count),
                yes_no(case.error_id_stable),
                yes_no(case.taxonomy_stable),
                yes_no(case.root_cause_stable),
                yes_no(case.proof_stable),
                yes_no(case.raw_text_stable),
                format_float(case.min_jaccard),
                format_float(case.avg_jaccard),
            ]
        )
    lines.extend(
        render_table(
            [
                "case",
                "blocks",
                "error_id stable",
                "taxonomy stable",
                "root stable",
                "proof stable",
                "raw text stable",
                "min Jaccard",
                "avg Jaccard",
            ],
            target_summary_rows,
        )
    )
    lines.extend(["", "## All Multi-Block Cases", ""])

    summary_rows: list[list[str]] = []
    for case in sort_cases(cases):
        summary_rows.append(
            [
                case.case_id,
                case.source_bucket,
                str(case.block_count),
                yes_no(case.diagnosis_stable),
                yes_no(case.root_cause_stable),
                yes_no(case.proof_stable),
                yes_no(case.raw_text_stable),
                format_float(case.min_jaccard),
                format_float(case.avg_jaccard),
            ]
        )
    lines.extend(
        render_table(
            [
                "case",
                "bucket",
                "blocks",
                "diag stable",
                "root stable",
                "proof stable",
                "raw text stable",
                "min Jaccard",
                "avg Jaccard",
            ],
            summary_rows,
        )
    )
    lines.extend(["", "## Per-Block Detail", ""])
    lines.append(
        "`stable?` below is case-level diagnosis stability for the whole case, repeated on each block row."
    )
    lines.append("")

    detail_rows: list[list[str]] = []
    for case in sort_cases(cases):
        for block in case.blocks:
            raw_line = block.raw_error_line or "<empty>"
            if block.diagnose_error:
                raw_line = f"{raw_line} [diagnose error: {block.diagnose_error}]"
            detail_rows.append(
                [
                    case.case_id,
                    str(block.block_index),
                    truncate(raw_line),
                    block.error_id or "None",
                    block.taxonomy_class or "None",
                    yes_no(case.diagnosis_stable),
                ]
            )
    lines.extend(
        render_table(
            ["case", "block#", "raw error line", "BPFix error_id", "taxonomy_class", "stable?"],
            detail_rows,
        )
    )
    lines.extend(["", "## Key Stable-Despite-Drift Examples", ""])

    for case in top_examples(cases):
        lines.append(
            (
                f"- `{case.case_id}`: stable `{case.blocks[0].error_id}` / "
                f"`{case.blocks[0].taxonomy_class}` across `{case.block_count}` blocks, "
                f"but raw lines drifted (`min Jaccard = {format_float(case.min_jaccard)}`, "
                f"`avg = {format_float(case.avg_jaccard)}`)."
            )
        )
        unique_examples: list[str] = []
        for block in case.blocks:
            candidate = truncate(block.raw_error_line or "<empty>", limit=120)
            if candidate not in unique_examples:
                unique_examples.append(candidate)
            if len(unique_examples) == 3:
                break
        for example in unique_examples:
            lines.append(f"  - `{example}`")

    unstable_targets = [
        case for case in summarize_target_cases(cases) if not case.diagnosis_stable
    ]
    if unstable_targets:
        lines.extend(["", "## Notable Unstable Target Cases", ""])
        for case in unstable_targets:
            signatures = sorted(
                {
                    (block.error_id or "None", block.taxonomy_class or "None")
                    for block in case.blocks
                }
            )
            rendered_signatures = ", ".join(
                f"`{error_id}/{taxonomy}`" for error_id, taxonomy in signatures
            )
            lines.append(
                (
                    f"- `{case.case_id}`: diagnosis is not stable across blocks "
                    f"({rendered_signatures}); `min Jaccard = {format_float(case.min_jaccard)}`."
                )
            )

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    cases = [
        analyzed
        for path in sorted(args.cases_root.rglob("*.yaml"))
        if (analyzed := analyze_case(path)) is not None
    ]
    cases = sort_cases(cases)

    output_text = render_markdown(cases)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.write_text(output_text, encoding="utf-8")

    print(
        f"Wrote {len(cases)} multi-block case analyses to "
        f"{args.output_markdown.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
