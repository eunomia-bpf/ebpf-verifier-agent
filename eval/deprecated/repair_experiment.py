#!/usr/bin/env python3
"""Run an A/B repair experiment for raw verifier logs vs OBLIGE diagnostics."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml
from openai import OpenAI


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.diagnoser import diagnose
from interface.extractor.rust_diagnostic import generate_diagnostic


CASE_DIRS = (
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
    ROOT / "case_study" / "cases" / "kernel_selftests",
)
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "repair_experiment_results.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "repair-experiment-report.md"
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
TARGET_CASE_COUNTS = {
    "lowering_artifact": 18,
    "source_bug": 20,
    "verifier_limit": 8,
    "env_mismatch": 8,
}
TOTAL_CASES = sum(TARGET_CASE_COUNTS.values())
MODEL_CANDIDATES = ("gpt-4.1-mini", "gpt-4.1-nano")
SOURCE_PRIORITY = {
    "stackoverflow": 0,
    "github_issues": 1,
    "kernel_selftests": 2,
}
TRACE_RICH_LOG_LINES = 80
TRACE_RICH_STATE_LINES = 20
ALLOWED_TAXONOMIES = tuple(TARGET_CASE_COUNTS.keys())
TAXONOMY_ORDER = (
    "lowering_artifact",
    "source_bug",
    "verifier_limit",
    "env_mismatch",
)

STOPWORDS = {
    "a",
    "about",
    "after",
    "all",
    "an",
    "and",
    "any",
    "are",
    "as",
    "at",
    "be",
    "before",
    "because",
    "but",
    "by",
    "can",
    "do",
    "does",
    "for",
    "from",
    "get",
    "has",
    "have",
    "here",
    "how",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "just",
    "make",
    "my",
    "need",
    "not",
    "of",
    "on",
    "one",
    "only",
    "or",
    "out",
    "so",
    "that",
    "the",
    "their",
    "then",
    "there",
    "these",
    "this",
    "to",
    "up",
    "use",
    "using",
    "want",
    "was",
    "when",
    "with",
    "will",
    "work",
    "would",
    "you",
    "your",
}

SYSTEM_PROMPT = (
    "You repair Linux eBPF programs that fail verification. "
    "Choose the most likely single repair, not a list of unrelated ideas. "
    "Prefer concise, concrete fixes that correspond to the verifier root cause. "
    "Respond with valid JSON only."
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
class TagSpec:
    tag: str
    label: str
    taxonomy_hint: str | None
    location_kind: str
    patterns: tuple[re.Pattern[str], ...]


@dataclass(slots=True)
class CaseCandidate:
    case_id: str
    case_path: str
    source: str
    title: str
    source_url: str
    taxonomy_class: str
    taxonomy_source: str
    error_id: str | None
    verifier_log: str
    log_lines: int
    trace_state_lines: int
    source_code: str
    code_source: str
    raw_fix_text: str
    raw_fix_source: str
    raw_fix_is_accepted: bool
    ground_truth_fix: str
    ground_truth_fix_source: str
    manual_label_present: bool
    manual_confidence: str | None
    expected_fix_tags: list[str]
    expected_fix_type: str
    expected_fix_type_source: str
    expected_location_kind: str
    root_span_text: str
    symptom_span_text: str
    root_tokens: list[str]
    symptom_tokens: list[str]
    diagnostic_text: str
    diagnostic_json: dict[str, Any]
    recommended_fix: str | None
    selection_score: int
    selection_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ConditionResult:
    condition: str
    prompt: str
    model: str | None
    raw_response: str
    parsed_response: dict[str, Any] | None
    api_error: str | None
    usage_output_tokens: int | None
    predicted_fix_tags: list[str]
    predicted_fix_type: str
    predicted_location_kind: str | None
    fix_type_match: bool
    location_correct: bool | None
    semantic_similarity: bool | None
    semantic_overlap: list[str]


@dataclass(slots=True)
class CaseExperimentResult:
    case_id: str
    case_path: str
    source: str
    taxonomy_class: str
    error_id: str | None
    title: str
    source_url: str
    expected_fix_type: str
    expected_fix_tags: list[str]
    ground_truth_fix: str
    ground_truth_fix_source: str
    root_span_text: str
    symptom_span_text: str
    condition_a: ConditionResult
    condition_b: ConditionResult


FIX_TAG_SPECS = (
    TagSpec(
        tag="inline_hint",
        label="add __always_inline",
        taxonomy_hint="lowering_artifact",
        location_kind="root_cause",
        patterns=(
            re.compile(r"__always_inline", re.IGNORECASE),
            re.compile(r"static inline", re.IGNORECASE),
            re.compile(r"\binline\b", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="no_panic_unwrap",
        label="remove unwrap/panic",
        taxonomy_hint="lowering_artifact",
        location_kind="root_cause",
        patterns=(
            re.compile(r"\bpanic\b", re.IGNORECASE),
            re.compile(r"\bunwrap\b", re.IGNORECASE),
            re.compile(r"handle all errors", re.IGNORECASE),
            re.compile(r"explicit error handling", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="checked_pointer_reuse",
        label="reuse checked pointer",
        taxonomy_hint="lowering_artifact",
        location_kind="root_cause",
        patterns=(
            re.compile(r"same checked pointer", re.IGNORECASE),
            re.compile(r"checked pointer.*identical", re.IGNORECASE),
            re.compile(r"recompute and access through the same", re.IGNORECASE),
            re.compile(r"re-?read packet pointers", re.IGNORECASE),
            re.compile(r"rebuild packet pointers", re.IGNORECASE),
            re.compile(r"reuse (?:the )?checked pointer", re.IGNORECASE),
            re.compile(r"proof survives lowering", re.IGNORECASE),
            re.compile(r"compiler (?:optimized|reorganized)", re.IGNORECASE),
            re.compile(r"verifier seems to get lost", re.IGNORECASE),
            re.compile(r"keep the proof within one function", re.IGNORECASE),
            re.compile(r"verifier-friendly loop rewrite", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="unsigned_clamp",
        label="add unsigned clamp",
        taxonomy_hint="lowering_artifact",
        location_kind="root_cause",
        patterns=(
            re.compile(r"\bunsigned\b", re.IGNORECASE),
            re.compile(r"non-negative", re.IGNORECASE),
            re.compile(r"\bclamp\b", re.IGNORECASE),
            re.compile(r"var\s*&=\s*const", re.IGNORECASE),
            re.compile(r"unbounded min value", re.IGNORECASE),
            re.compile(r"upper-bound clamp", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="spill_reload_avoid",
        label="avoid spill/reload proof loss",
        taxonomy_hint="lowering_artifact",
        location_kind="root_cause",
        patterns=(
            re.compile(r"\bspill\b", re.IGNORECASE),
            re.compile(r"\breload\b", re.IGNORECASE),
            re.compile(r"separate registers", re.IGNORECASE),
            re.compile(r"keep pointer and offset separate", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="loop_unroll",
        label="unroll or strengthen loop bound",
        taxonomy_hint="verifier_limit",
        location_kind="root_cause",
        patterns=(
            re.compile(r"\bunroll", re.IGNORECASE),
            re.compile(r"pragma clang loop unroll", re.IGNORECASE),
            re.compile(r"fully unroll", re.IGNORECASE),
            re.compile(r"loop form the verifier can fully unroll", re.IGNORECASE),
            re.compile(r"bound/invariant explicit", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="reduce_branching",
        label="reduce branching/state fan-out",
        taxonomy_hint="verifier_limit",
        location_kind="root_cause",
        patterns=(
            re.compile(r"reduce branching", re.IGNORECASE),
            re.compile(r"state fan-?out", re.IGNORECASE),
            re.compile(r"simpler stages", re.IGNORECASE),
            re.compile(r"split the logic", re.IGNORECASE),
            re.compile(r"too complex for the verifier", re.IGNORECASE),
            re.compile(r"minimize the branching factor", re.IGNORECASE),
            re.compile(r"hoist common checks", re.IGNORECASE),
            re.compile(r"1 million instructions", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="reduce_stack_depth",
        label="reduce stack depth",
        taxonomy_hint="verifier_limit",
        location_kind="root_cause",
        patterns=(
            re.compile(r"reduce combined stack use", re.IGNORECASE),
            re.compile(r"shrink frame", re.IGNORECASE),
            re.compile(r"frame sizes", re.IGNORECASE),
            re.compile(r"stack depth", re.IGNORECASE),
            re.compile(r"stack use", re.IGNORECASE),
            re.compile(r"per-frame stack", re.IGNORECASE),
            re.compile(r"call tree", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="release_mode",
        label="build in release mode",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"release mode", re.IGNORECASE),
            re.compile(r"build .*release", re.IGNORECASE),
            re.compile(r"only build ebpf in release mode", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="btf_regen",
        label="regenerate or align BTF",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"\bbtf\b", re.IGNORECASE),
            re.compile(r"func_info", re.IGNORECASE),
            re.compile(r"regenerate", re.IGNORECASE),
            re.compile(r"align.*btf", re.IGNORECASE),
            re.compile(r"toolchain/kernel combination", re.IGNORECASE),
            re.compile(r"llvm 18", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="helper_switch",
        label="switch helper or program type",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"helper allowed", re.IGNORECASE),
            re.compile(r"cannot use helper", re.IGNORECASE),
            re.compile(r"switch.*helper", re.IGNORECASE),
            re.compile(r"use a helper allowed", re.IGNORECASE),
            re.compile(r"move the logic to a program type", re.IGNORECASE),
            re.compile(r"program type that permits", re.IGNORECASE),
            re.compile(r"unavailable helper", re.IGNORECASE),
            re.compile(r"instead of calling the unavailable helper", re.IGNORECASE),
            re.compile(r"read the PID from TcContext", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="alignment_fix",
        label="fix data alignment",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"align your data", re.IGNORECASE),
            re.compile(r"aligned data", re.IGNORECASE),
            re.compile(r"fill bytes", re.IGNORECASE),
            re.compile(r"\bpadding\b", re.IGNORECASE),
            re.compile(r"architecture", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="use_map_state",
        label="move state into a BPF map",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"static item", re.IGNORECASE),
            re.compile(r"maintain state in a BPF map", re.IGNORECASE),
            re.compile(r"written to maps", re.IGNORECASE),
            re.compile(r"data must instead be written to maps", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="kernel_upgrade",
        label="upgrade or backport kernel/toolchain",
        taxonomy_hint="env_mismatch",
        location_kind="root_cause",
        patterns=(
            re.compile(r"newer kernel", re.IGNORECASE),
            re.compile(r"upgrade .*kernel", re.IGNORECASE),
            re.compile(r"\bbackport\b", re.IGNORECASE),
            re.compile(r"kernel bugfix", re.IGNORECASE),
            re.compile(r"version newer", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="queue_map_api",
        label="use the queue-map helper API",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"map_push_elem", re.IGNORECASE),
            re.compile(r"\bpull\b", re.IGNORECASE),
            re.compile(r"\bpeek\b", re.IGNORECASE),
            re.compile(r"queue maps", re.IGNORECASE),
            re.compile(r"queue map", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="map_declaration",
        label='fix map declaration / `SEC("maps")`',
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r'SEC\("maps"\)', re.IGNORECASE),
            re.compile(r"map pointer relocation", re.IGNORECASE),
            re.compile(r"loader-generated map pointer", re.IGNORECASE),
            re.compile(r"loader is not creating maps", re.IGNORECASE),
            re.compile(r"declare the map", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="init_stack",
        label="initialize stack buffer",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"initiali[sz]e .*buffer", re.IGNORECASE),
            re.compile(r"initiali[sz]e .*stack", re.IGNORECASE),
            re.compile(r"zeroed out buffer", re.IGNORECASE),
            re.compile(r"tmp_buffer", re.IGNORECASE),
            re.compile(r"before the helper call", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="bounds_check",
        label="add or tighten bounds check",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"bounds check", re.IGNORECASE),
            re.compile(r"check the packet is long enough", re.IGNORECASE),
            re.compile(r"<=\s*data_end", re.IGNORECASE),
            re.compile(r"\bdata_end\b", re.IGNORECASE),
            re.compile(r"length explicitly bounded", re.IGNORECASE),
            re.compile(r"perform the bounds check", re.IGNORECASE),
            re.compile(r"check for the bounds", re.IGNORECASE),
            re.compile(r"upper bound for the string length", re.IGNORECASE),
            re.compile(r"bound explicit", re.IGNORECASE),
            re.compile(r"check.*long enough", re.IGNORECASE),
            re.compile(r"maximum amount of iterations", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="null_check",
        label="add null check",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"null check", re.IGNORECASE),
            re.compile(r"pointer isn'?t null", re.IGNORECASE),
            re.compile(r"possibly null", re.IGNORECASE),
            re.compile(r"==\s*NULL", re.IGNORECASE),
            re.compile(r"!=\s*NULL", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="context_member_read",
        label="read through a verifier-safe API",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"use bpf_probe_read to read", re.IGNORECASE),
            re.compile(r"read .*member.*sk_buff", re.IGNORECASE),
            re.compile(r"read any memeber in sk_buff", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="use_value_not_pointer",
        label="pass the value, not a pointer/unsupported type",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"pass event as the argument, not &event", re.IGNORECASE),
            re.compile(r"value type is not a pointer", re.IGNORECASE),
            re.compile(r"not a pointer anymore", re.IGNORECASE),
            re.compile(r"u64 or i64 will work", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="pointer_type_fix",
        label="use a valid pointer/object",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"valid destination object", re.IGNORECASE),
            re.compile(r"actual dynptr", re.IGNORECASE),
            re.compile(r"exact stack slot", re.IGNORECASE),
            re.compile(r"stack slot / constant base address", re.IGNORECASE),
            re.compile(r"unrelated pointer type", re.IGNORECASE),
            re.compile(r"pointer type", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="release_balance",
        label="balance acquire/release",
        taxonomy_hint="source_bug",
        location_kind="local",
        patterns=(
            re.compile(r"release exactly once", re.IGNORECASE),
            re.compile(r"release on every path", re.IGNORECASE),
            re.compile(r"destroy .* every exit path", re.IGNORECASE),
            re.compile(r"balance acquire release", re.IGNORECASE),
        ),
    ),
    TagSpec(
        tag="other_refactor",
        label="refactor or rewrite",
        taxonomy_hint=None,
        location_kind="root_cause",
        patterns=(
            re.compile(r"\brewrite\b", re.IGNORECASE),
            re.compile(r"\brestructure\b", re.IGNORECASE),
            re.compile(r"\brefactor\b", re.IGNORECASE),
            re.compile(r"work around the verifier issue", re.IGNORECASE),
        ),
    ),
)

FIX_TAG_LABELS = {spec.tag: spec.label for spec in FIX_TAG_SPECS}
FIX_TAG_TAXONOMY = {
    spec.tag: spec.taxonomy_hint for spec in FIX_TAG_SPECS if spec.taxonomy_hint is not None
}
ROOT_CAUSE_TAGS = {
    spec.tag for spec in FIX_TAG_SPECS if spec.location_kind == "root_cause"
}
LOCAL_FIX_TAGS = {spec.tag for spec in FIX_TAG_SPECS if spec.location_kind == "local"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def parse_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_manual_labels(path: Path) -> dict[str, ManualLabel]:
    labels: dict[str, ManualLabel] = {}
    if not path.exists():
        return labels
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


def lookup_manual_label(case_id: str, manual_labels: dict[str, ManualLabel]) -> ManualLabel | None:
    direct = manual_labels.get(case_id)
    if direct is not None:
        return direct
    if not case_id.startswith("kernel-selftest-"):
        return None

    prefix_matches = [
        label
        for label_id, label in manual_labels.items()
        if label_id.startswith(case_id + "-") or case_id.startswith(label_id + "-")
    ]
    if len(prefix_matches) == 1:
        return prefix_matches[0]
    return None


def iter_case_paths(paths: Iterable[Path]) -> list[Path]:
    resolved: list[Path] = []
    for path in paths:
        if path.is_dir():
            resolved.extend(sorted(p for p in path.glob("*.yaml") if p.name != "index.yaml"))
        elif path.suffix == ".yaml" and path.name != "index.yaml":
            resolved.append(path)
    return sorted({path.resolve() for path in resolved})


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log")
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            joined = "\n\n".join(str(block).strip() for block in blocks if str(block).strip())
            return joined.strip()
    if isinstance(verifier_log, str) and verifier_log.strip():
        return verifier_log.strip()

    verifier_logs = case_data.get("verifier_logs")
    if isinstance(verifier_logs, list):
        joined = "\n\n".join(str(block).strip() for block in verifier_logs if str(block).strip())
        return joined.strip()
    if isinstance(verifier_logs, dict):
        combined = verifier_logs.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
    return ""


def is_log_like_snippet(snippet: str) -> bool:
    lines = [line for line in snippet.splitlines() if line.strip()]
    if not lines:
        return False
    log_hits = 0
    for line in lines[:10]:
        stripped = line.strip()
        if stripped.startswith(("libbpf:", "Validating ", "processed ")):
            log_hits += 1
        if re.match(r"^\d+: \([0-9a-f]{2}\)", stripped, flags=re.IGNORECASE):
            log_hits += 1
        if re.match(r"^(R\d|last_idx|regs=|invalid access|math between)", stripped):
            log_hits += 1
    return log_hits >= 2


def is_code_like_snippet(snippet: str) -> bool:
    if not snippet.strip():
        return False
    if is_log_like_snippet(snippet):
        return False
    markers = (
        'SEC("',
        '__section("',
        "__always_inline",
        "#define",
        "struct ",
        "enum ",
        "typedef ",
        "fn ",
        "impl ",
        "match ",
        "unsafe ",
        "let ",
        "use ",
        "return ",
        "goto ",
        "if (",
        "for (",
        "while (",
        "asm volatile",
        "int ",
        "__u",
    )
    return any(marker in snippet for marker in markers)


def extract_code_from_diff(snippet: str) -> str:
    body: list[str] = []
    for line in snippet.splitlines():
        if line.startswith(("diff --git", "index ", "--- ", "+++ ")):
            continue
        if line.startswith("@@"):
            continue
        if line.startswith("+"):
            continue
        if line.startswith("-"):
            body.append(line[1:])
            continue
        if line.startswith(" "):
            body.append(line[1:])
            continue
    return "\n".join(body).strip()


def extract_code_from_text(text: str) -> str:
    if not text.strip():
        return ""
    lines = text.splitlines()
    start_idx: int | None = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if re.match(
            r'^(#include|#define|struct\s+\w+|static\s+__always_inline|SEC\("|__section\("|int\s+\w+\(|enum\s+\w+|typedef\s+|__u\d+|fn\s+\w+\(|use\s+\w+|unsafe\s+fn\s+\w+\()',
            stripped,
        ):
            start_idx = idx
            break
    if start_idx is None:
        return ""

    end_idx = len(lines)
    for idx in range(start_idx + 1, len(lines)):
        stripped = lines[idx].strip()
        if stripped.startswith(
            (
                "Following is the complete verifier log",
                "Following is the verifier log",
                "Here are a few last lines",
                "Full log is available here.",
                "When I try to load",
                "I get this error when",
                "Here is the full error message",
                "Verifier output:",
                "libbpf:",
                "Validating ",
                "Traceback",
                "Error:",
            )
        ):
            end_idx = idx
            break
        if re.match(r"^\d+: \([0-9a-f]{2}\)", stripped, flags=re.IGNORECASE):
            end_idx = idx
            break
    return "\n".join(lines[start_idx:end_idx]).strip()


def extract_source_code(case_data: dict[str, Any]) -> tuple[str, str]:
    code_candidates: list[tuple[str, str]] = []

    for snippet in case_data.get("source_snippets") or []:
        if isinstance(snippet, dict):
            code = snippet.get("code")
            if isinstance(code, str) and code.strip():
                code_candidates.append((code.strip(), "source_snippets.code"))
            continue
        if not isinstance(snippet, str) or not snippet.strip():
            continue
        if snippet.startswith("diff --git"):
            diff_code = extract_code_from_diff(snippet)
            if diff_code:
                code_candidates.append((diff_code, "source_snippets.diff"))
            continue
        if is_code_like_snippet(snippet):
            code_candidates.append((snippet.strip(), "source_snippets"))

    for body_key in ("question_body_text", "issue_body_text"):
        recovered = extract_code_from_text(str(case_data.get(body_key, "")))
        if recovered:
            code_candidates.append((recovered, body_key))

    if not code_candidates:
        return "", "missing"

    code, source = max(code_candidates, key=lambda item: len(item[0]))
    return code, source


def extract_title(case_data: dict[str, Any]) -> str:
    question = case_data.get("question") or {}
    issue = case_data.get("issue") or {}
    selftest = case_data.get("selftest") or {}
    return (
        str(question.get("title") or "")
        or str(issue.get("title") or "")
        or str(selftest.get("function") or "")
        or str(selftest.get("description") or "")
        or str(case_data.get("case_id") or "")
    )


def extract_source_url(case_data: dict[str, Any]) -> str:
    question = case_data.get("question") or {}
    issue = case_data.get("issue") or {}
    return (
        str(question.get("url") or "")
        or str(issue.get("url") or "")
        or str(case_data.get("question_url") or "")
        or str(case_data.get("issue_url") or "")
    )


def extract_raw_fix_text(case_data: dict[str, Any]) -> tuple[str, str, bool]:
    selected_answer = case_data.get("selected_answer") or {}
    if isinstance(selected_answer, dict):
        text = (
            selected_answer.get("fix_description")
            or selected_answer.get("body_text")
            or ""
        ).strip()
        if text:
            return text, "selected_answer", bool(selected_answer.get("is_accepted"))

    issue_fix = case_data.get("fix") or {}
    if isinstance(issue_fix, dict):
        selected_comment = issue_fix.get("selected_comment") or {}
        text = (
            selected_comment.get("body_text")
            or issue_fix.get("summary")
            or ""
        ).strip()
        if text:
            return text, "issue_fix", True
    return "", "missing", False


def significant_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", text.lower()):
        if token in STOPWORDS:
            continue
        if len(token) < 4 and not token.isdigit():
            continue
        tokens.append(token)
    deduped: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        deduped.append(token)
    return deduped


def classify_fix_tags(texts: Iterable[str]) -> list[str]:
    combined = "\n".join(text for text in texts if text and text.strip())
    if not combined.strip():
        return []
    tags: list[str] = []
    for spec in FIX_TAG_SPECS:
        if any(pattern.search(combined) for pattern in spec.patterns):
            tags.append(spec.tag)
    return tags


def infer_taxonomy(
    *,
    manual_label: ManualLabel | None,
    expected_fix_tags: list[str],
    diagnosis_taxonomy: str | None,
) -> tuple[str, str]:
    if manual_label is not None and manual_label.taxonomy_class in ALLOWED_TAXONOMIES:
        return manual_label.taxonomy_class, "manual_label"

    scores: Counter[str] = Counter()
    for tag in expected_fix_tags:
        hint = FIX_TAG_TAXONOMY.get(tag)
        if hint in ALLOWED_TAXONOMIES:
            scores[hint] += 3
    if scores:
        taxonomy = max(
            ALLOWED_TAXONOMIES,
            key=lambda item: (scores.get(item, 0), -TAXONOMY_ORDER.index(item)),
        )
        if scores[taxonomy] > 0:
            return taxonomy, "fix_tag_heuristic"

    if diagnosis_taxonomy in ALLOWED_TAXONOMIES:
        return str(diagnosis_taxonomy), "oblige_diagnosis"
    return "source_bug", "default"


def generic_fix_type_for_taxonomy(taxonomy_class: str) -> str:
    mapping = {
        "lowering_artifact": "other_refactor",
        "source_bug": "bounds_check",
        "verifier_limit": "reduce_branching",
        "env_mismatch": "helper_switch",
    }
    return mapping.get(taxonomy_class, "other_refactor")


def location_kind_for_expected(taxonomy_class: str, expected_fix_type: str) -> str:
    if taxonomy_class in {"lowering_artifact", "verifier_limit", "env_mismatch"}:
        return "root_cause"
    if expected_fix_type in ROOT_CAUSE_TAGS:
        return "root_cause"
    if expected_fix_type in LOCAL_FIX_TAGS:
        return "local"
    return "unknown"


def extract_root_and_symptom_spans(diagnostic_json: dict[str, Any]) -> tuple[str, str]:
    spans = diagnostic_json.get("spans") or []
    root_text = ""
    for role in ("proof_lost", "proof_established", "proof_propagated"):
        for span in spans:
            if span.get("role") == role and span.get("source_text"):
                root_text = str(span["source_text"])
                break
        if root_text:
            break
    symptom_text = ""
    for span in reversed(spans):
        if span.get("role") == "rejected" and span.get("source_text"):
            symptom_text = str(span["source_text"])
            break
    if not root_text and spans:
        root_text = str(spans[0].get("source_text") or "")
    if not symptom_text and spans:
        symptom_text = str(spans[-1].get("source_text") or "")
    return root_text, symptom_text


def count_trace_state_lines(verifier_log: str) -> int:
    count = 0
    for line in verifier_log.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^\d+:\s+R\d+(?:_[A-Za-z]+)?=", stripped):
            count += 1
            continue
        if re.match(r"^R\d+(?:_[A-Za-z]+)?=", stripped):
            count += 1
            continue
        if re.match(r"^from \d+ to \d+:\s+R\d+(?:_[A-Za-z]+)?=", stripped):
            count += 1
            continue
        if stripped.startswith(("last_idx", "regs=", "parent didn't have regs")):
            count += 1
    return count


def is_trace_rich(candidate: CaseCandidate) -> bool:
    return (
        candidate.log_lines >= TRACE_RICH_LOG_LINES
        or candidate.trace_state_lines >= TRACE_RICH_STATE_LINES
    )


def selection_score(candidate: CaseCandidate) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []

    source_bonus = {"stackoverflow": 320, "github_issues": 220, "kernel_selftests": 40}.get(
        candidate.source,
        0,
    )
    score += source_bonus
    notes.append(f"source:+{source_bonus}")

    if candidate.manual_label_present:
        score += 120
        notes.append("manual_label:+120")

    if candidate.ground_truth_fix_source == "manual_label":
        score += 80
        notes.append("curated_fix:+80")
    elif candidate.ground_truth_fix_source != "missing":
        score += 50
        notes.append("raw_fix:+50")
    else:
        score -= 120
        notes.append("missing_fix:-120")

    if candidate.raw_fix_is_accepted:
        score += 25
        notes.append("accepted_fix:+25")

    if candidate.expected_fix_type_source == "ground_truth":
        score += 40
        notes.append("expected_from_gt:+40")
    elif candidate.expected_fix_type_source == "raw_fix":
        score += 25
        notes.append("expected_from_raw_fix:+25")
    elif candidate.expected_fix_type_source == "diagnosis_fallback":
        score -= 120
        notes.append("diagnosis_fallback:-120")

    if candidate.expected_fix_type not in {"other_refactor"}:
        score += 35
        notes.append("specific_fix:+35")

    if candidate.taxonomy_source == "manual_label":
        score += 50
        notes.append("manual_taxonomy:+50")
    elif candidate.taxonomy_source == "fix_tag_heuristic":
        score += 20
        notes.append("tag_taxonomy:+20")

    if candidate.source == "kernel_selftests" and not candidate.manual_label_present:
        score -= 120
        notes.append("selftest_without_manual_gt:-120")

    line_bonus = min(candidate.log_lines, 220) * 2
    score += line_bonus
    notes.append(f"log_lines:+{line_bonus}")

    trace_bonus = min(candidate.trace_state_lines, 80) * 4
    score += trace_bonus
    notes.append(f"trace_state_lines:+{trace_bonus}")

    if is_trace_rich(candidate):
        score += 60
        notes.append("trace_rich:+60")

    return score, notes


def build_candidate(path: Path, manual_labels: dict[str, ManualLabel]) -> CaseCandidate | None:
    case_data = read_yaml(path)
    case_id = str(case_data.get("case_id") or path.stem)
    verifier_log = extract_verifier_log(case_data)
    if not verifier_log:
        return None

    source_code, code_source = extract_source_code(case_data)
    if not source_code:
        return None

    try:
        diagnosis = diagnose(verifier_log)
    except Exception as exc:
        print(f"[warn] diagnose failed for {case_id}: {type(exc).__name__}: {exc}")
        return None

    try:
        diagnostic = generate_diagnostic(verifier_log)
        diagnostic_text = diagnostic.text
        diagnostic_json = diagnostic.json_data
    except Exception as exc:
        diagnostic_text = f"OBLIGE diagnostic generation failed: {type(exc).__name__}: {exc}"
        diagnostic_json = {}

    manual_label = lookup_manual_label(case_id, manual_labels)
    raw_fix_text, raw_fix_source, raw_fix_is_accepted = extract_raw_fix_text(case_data)

    if manual_label is not None and manual_label.ground_truth_fix.strip():
        ground_truth_fix = manual_label.ground_truth_fix.strip()
        ground_truth_fix_source = "manual_label"
    elif raw_fix_text:
        ground_truth_fix = raw_fix_text
        ground_truth_fix_source = raw_fix_source
    else:
        ground_truth_fix = ""
        ground_truth_fix_source = "missing"
    if not ground_truth_fix.strip():
        return None

    expected_fix_tags = classify_fix_tags([ground_truth_fix])
    expected_fix_type_source = "ground_truth" if expected_fix_tags else "missing"
    if not expected_fix_tags and raw_fix_text:
        expected_fix_tags = classify_fix_tags([raw_fix_text])
        expected_fix_type_source = "raw_fix" if expected_fix_tags else "missing"
    if not expected_fix_tags and diagnosis.recommended_fix:
        expected_fix_tags = classify_fix_tags([diagnosis.recommended_fix])
        expected_fix_type_source = "diagnosis_fallback" if expected_fix_tags else "missing"

    taxonomy_class, taxonomy_source = infer_taxonomy(
        manual_label=manual_label,
        expected_fix_tags=expected_fix_tags,
        diagnosis_taxonomy=diagnosis.taxonomy_class,
    )
    expected_fix_type = (
        expected_fix_tags[0] if expected_fix_tags else generic_fix_type_for_taxonomy(taxonomy_class)
    )
    expected_location_kind = location_kind_for_expected(taxonomy_class, expected_fix_type)
    root_span_text, symptom_span_text = extract_root_and_symptom_spans(diagnostic_json)

    candidate = CaseCandidate(
        case_id=case_id,
        case_path=str(path),
        source=str(case_data.get("source") or ""),
        title=extract_title(case_data),
        source_url=extract_source_url(case_data),
        taxonomy_class=taxonomy_class,
        taxonomy_source=taxonomy_source,
        error_id=diagnosis.error_id,
        verifier_log=verifier_log,
        log_lines=len([line for line in verifier_log.splitlines() if line.strip()]),
        trace_state_lines=count_trace_state_lines(verifier_log),
        source_code=source_code,
        code_source=code_source,
        raw_fix_text=raw_fix_text,
        raw_fix_source=raw_fix_source,
        raw_fix_is_accepted=raw_fix_is_accepted,
        ground_truth_fix=ground_truth_fix,
        ground_truth_fix_source=ground_truth_fix_source,
        manual_label_present=manual_label is not None,
        manual_confidence=manual_label.confidence if manual_label is not None else None,
        expected_fix_tags=expected_fix_tags,
        expected_fix_type=expected_fix_type,
        expected_fix_type_source=expected_fix_type_source,
        expected_location_kind=expected_location_kind,
        root_span_text=root_span_text,
        symptom_span_text=symptom_span_text,
        root_tokens=significant_tokens(root_span_text),
        symptom_tokens=significant_tokens(symptom_span_text),
        diagnostic_text=diagnostic_text,
        diagnostic_json=diagnostic_json,
        recommended_fix=diagnosis.recommended_fix,
        selection_score=0,
    )
    score, notes = selection_score(candidate)
    candidate.selection_score = score
    candidate.selection_notes = notes
    return candidate


def choose_next_candidate(
    candidates: list[CaseCandidate],
    seen_tags: set[str],
    seen_sources: set[str],
) -> CaseCandidate | None:
    if not candidates:
        return None

    def sort_key(candidate: CaseCandidate) -> tuple[int, int, str]:
        new_tag_bonus = int(
            candidate.expected_fix_type not in seen_tags and candidate.expected_fix_type != "other_refactor"
        )
        new_source_bonus = int(candidate.source not in seen_sources)
        composite = (
            candidate.selection_score
            + new_tag_bonus * 30
            + new_source_bonus * 10
            + int(candidate.manual_label_present) * 10
        )
        return (
            composite,
            candidate.selection_score,
            candidate.case_id,
        )

    return max(candidates, key=sort_key)


def select_cases(
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
        taxonomy: min(TARGET_CASE_COUNTS[taxonomy], pool_counts.get(taxonomy, 0))
        for taxonomy in TAXONOMY_ORDER
    }
    minimum_case_count = sum(effective_targets.values())
    effective_case_count = max(case_count, minimum_case_count)
    effective_case_count = min(effective_case_count, len(candidates))
    if effective_case_count < minimum_case_count:
        raise RuntimeError(
            "Unable to satisfy requested taxonomy mix with the eligible fix-backed pool: "
            f"need at least {minimum_case_count} cases, found {len(candidates)}"
        )
    summary: dict[str, Any] = {
        "requested_case_count": case_count,
        "effective_case_count": effective_case_count,
        "requested_targets": dict(TARGET_CASE_COUNTS),
        "effective_targets": effective_targets,
        "pool_counts": pool_counts,
        "selected_by_taxonomy": {},
    }

    for taxonomy, target in effective_targets.items():
        selected_for_taxonomy = 0
        while selected_for_taxonomy < target:
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
                raise RuntimeError(f"Unable to satisfy minimum for taxonomy={taxonomy}")
            selected.append(pick)
            selected_ids.add(pick.case_id)
            bucket_seen_tags[taxonomy].add(pick.expected_fix_type)
            bucket_seen_sources[taxonomy].add(pick.source)
            selected_for_taxonomy += 1

    overall_seen_tags = {candidate.expected_fix_type for candidate in selected}
    overall_seen_sources = {candidate.source for candidate in selected}
    while len(selected) < effective_case_count:
        eligible = [
            candidate for candidate in candidates if candidate.case_id not in selected_ids
        ]
        pick = choose_next_candidate(eligible, overall_seen_tags, overall_seen_sources)
        if pick is None:
            raise RuntimeError(
                f"Only selected {len(selected)} cases, but requested {effective_case_count}"
            )
        selected.append(pick)
        selected_ids.add(pick.case_id)
        overall_seen_tags.add(pick.expected_fix_type)
        overall_seen_sources.add(pick.source)

    selected.sort(
        key=lambda candidate: (
            TAXONOMY_ORDER.index(candidate.taxonomy_class),
            SOURCE_PRIORITY.get(candidate.source, 99),
            candidate.case_id,
        )
    )
    summary["selected_case_ids"] = [candidate.case_id for candidate in selected]
    summary["selected_taxonomy_counts"] = Counter(candidate.taxonomy_class for candidate in selected)
    summary["selected_source_counts"] = Counter(candidate.source for candidate in selected)
    summary["selected_trace_rich_count"] = sum(1 for candidate in selected if is_trace_rich(candidate))
    summary["selected_trace_state_lines"] = sum(candidate.trace_state_lines for candidate in selected)
    summary["selected_log_lines_total"] = sum(candidate.log_lines for candidate in selected)
    summary["selected_by_taxonomy"] = {
        taxonomy: [candidate.case_id for candidate in selected if candidate.taxonomy_class == taxonomy]
        for taxonomy in TAXONOMY_ORDER
    }
    return selected, summary


def fix_type_label(tag: str) -> str:
    return FIX_TAG_LABELS.get(tag, tag.replace("_", " "))


def markdown_cell(text: str) -> str:
    return text.replace("`", "'").replace("\n", " ").strip()


def build_prompt(candidate: CaseCandidate, condition: str) -> str:
    prompt_lines = [
        "Fix this BPF program.",
        "Here is the verifier error log:",
        "```text",
        candidate.verifier_log,
        "```",
    ]
    if condition == "b":
        prompt_lines.extend(
            [
                "Here is OBLIGE's diagnostic analysis:",
                "```text",
                candidate.diagnostic_text,
                "```",
            ]
        )
    prompt_lines.extend(
        [
            "Here is the source code:",
            "```c",
            candidate.source_code,
            "```",
            "Respond with JSON only using this schema:",
            '{"summary":"<one short paragraph>","fix_type":"<short label>","target_location":"<function/statement to change>","patched_code":"<minimal code snippet or patch>"}',
        ]
    )
    return "\n".join(prompt_lines)


def extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if candidate.startswith("```"):
        fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, flags=re.DOTALL)
        if fence_match:
            candidate = fence_match.group(1)
    try:
        payload = json.loads(candidate)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass

    for match in re.finditer(r"\{.*?\}", candidate, flags=re.DOTALL):
        snippet = match.group(0)
        try:
            payload = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def response_text_for_scoring(raw_response: str, parsed_response: dict[str, Any] | None) -> str:
    parts: list[str] = [raw_response]
    if parsed_response:
        for key in ("summary", "fix_type", "target_location", "patched_code"):
            value = parsed_response.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
    return "\n".join(part for part in parts if part)


def token_overlap(left: Iterable[str], right: Iterable[str]) -> list[str]:
    right_set = set(right)
    return [token for token in left if token in right_set]


def infer_predicted_location_kind(
    *,
    candidate: CaseCandidate,
    response_text: str,
    predicted_fix_tags: list[str],
) -> str | None:
    if predicted_fix_tags:
        primary = predicted_fix_tags[0]
        if primary in ROOT_CAUSE_TAGS:
            return "root_cause"
        if primary in LOCAL_FIX_TAGS:
            return "local"

    response_tokens = significant_tokens(response_text)
    root_hits = token_overlap(candidate.root_tokens, response_tokens)
    symptom_hits = token_overlap(candidate.symptom_tokens, response_tokens)
    if root_hits and len(root_hits) > len(symptom_hits):
        return "root_cause"
    if symptom_hits and len(symptom_hits) > len(root_hits):
        return "local"
    return None


def evaluate_response(
    *,
    candidate: CaseCandidate,
    condition: str,
    prompt: str,
    model: str | None,
    raw_response: str,
    parsed_response: dict[str, Any] | None,
    api_error: str | None,
    usage_output_tokens: int | None,
) -> ConditionResult:
    scoring_text = response_text_for_scoring(raw_response, parsed_response)
    predicted_fix_tags = classify_fix_tags([scoring_text])
    predicted_fix_type = predicted_fix_tags[0] if predicted_fix_tags else "other_refactor"
    fix_type_match = candidate.expected_fix_type in predicted_fix_tags

    predicted_location_kind = infer_predicted_location_kind(
        candidate=candidate,
        response_text=scoring_text,
        predicted_fix_tags=predicted_fix_tags,
    )
    if candidate.taxonomy_class in {"lowering_artifact", "verifier_limit", "env_mismatch"}:
        location_correct = predicted_location_kind == "root_cause"
    elif candidate.expected_location_kind == "local":
        location_correct = fix_type_match or predicted_location_kind == "local"
    elif candidate.expected_location_kind == "root_cause":
        location_correct = predicted_location_kind == "root_cause"
    else:
        location_correct = None

    semantic_similarity: bool | None
    semantic_overlap: list[str] = []
    if candidate.ground_truth_fix.strip():
        gt_tokens = significant_tokens(candidate.ground_truth_fix)
        response_tokens = significant_tokens(scoring_text)
        semantic_overlap = token_overlap(gt_tokens, response_tokens)
        semantic_similarity = fix_type_match or len(semantic_overlap) >= 2
    else:
        semantic_similarity = None

    return ConditionResult(
        condition=condition,
        prompt=prompt,
        model=model,
        raw_response=raw_response,
        parsed_response=parsed_response,
        api_error=api_error,
        usage_output_tokens=usage_output_tokens,
        predicted_fix_tags=predicted_fix_tags,
        predicted_fix_type=predicted_fix_type,
        predicted_location_kind=predicted_location_kind,
        fix_type_match=fix_type_match,
        location_correct=location_correct,
        semantic_similarity=semantic_similarity,
        semantic_overlap=semantic_overlap[:12],
    )


def save_results_bundle(
    *,
    path: Path,
    selection_summary: dict[str, Any],
    selected_cases: list[CaseCandidate],
    results: list[CaseExperimentResult],
    aggregates: dict[str, Any] | None,
    config: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now_iso(),
        "config": config,
        "selection_summary": {
            key: dict(value) if isinstance(value, Counter) else value
            for key, value in selection_summary.items()
        },
        "selected_cases": [asdict(candidate) for candidate in selected_cases],
        "results": [asdict(result) for result in results],
        "aggregates": aggregates,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_existing_results(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def call_openai_with_fallback(
    *,
    client: OpenAI,
    prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_seconds: int,
) -> tuple[str, dict[str, Any] | None, str | None, str | None, int | None]:
    last_error: str | None = None
    for model in MODEL_CANDIDATES:
        try:
            response = client.responses.create(
                model=model,
                instructions=SYSTEM_PROMPT,
                input=prompt,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
                text={"format": {"type": "text"}},
                timeout=timeout_seconds,
            )
            payload = response.model_dump(mode="python")
            text = str(payload.get("output_text") or "").strip()
            if not text:
                parts: list[str] = []
                for item in payload.get("output", []) or []:
                    if item.get("type") != "message":
                        continue
                    for content in item.get("content", []) or []:
                        if content.get("type") == "output_text":
                            parts.append(str(content.get("text") or ""))
                text = "\n".join(part for part in parts if part).strip()
            usage = payload.get("usage") or {}
            parsed = extract_json_object(text)
            return text, parsed, model, None, usage.get("output_tokens")
        except Exception as exc:  # pragma: no cover - network/API behavior.
            last_error = f"{type(exc).__name__}: {exc}"
    return "", None, None, last_error, None


def summarize_condition(results: list[ConditionResult]) -> dict[str, Any]:
    total = len(results)
    fix_correct = sum(1 for result in results if result.fix_type_match)
    location_available = sum(1 for result in results if result.location_correct is not None)
    location_correct = sum(1 for result in results if result.location_correct)
    semantic_available = sum(1 for result in results if result.semantic_similarity is not None)
    semantic_correct = sum(1 for result in results if result.semantic_similarity)
    return {
        "cases": total,
        "fix_type_correct": fix_correct,
        "fix_type_accuracy": percentage(fix_correct, total),
        "location_available": location_available,
        "location_correct": location_correct,
        "location_accuracy": percentage(location_correct, location_available),
        "semantic_available": semantic_available,
        "semantic_correct": semantic_correct,
        "semantic_accuracy": percentage(semantic_correct, semantic_available),
    }


def mcnemar_exact(case_results: list[CaseExperimentResult]) -> dict[str, Any]:
    a_only = sum(
        1
        for result in case_results
        if result.condition_a.fix_type_match and not result.condition_b.fix_type_match
    )
    b_only = sum(
        1
        for result in case_results
        if result.condition_b.fix_type_match and not result.condition_a.fix_type_match
    )
    total = a_only + b_only
    if total == 0:
        return {"a_only": a_only, "b_only": b_only, "p_value": 1.0}
    tail = sum(math.comb(total, k) for k in range(0, min(a_only, b_only) + 1)) / (2**total)
    p_value = min(1.0, 2 * tail)
    return {"a_only": a_only, "b_only": b_only, "p_value": p_value}


def aggregate_results(results: list[CaseExperimentResult]) -> dict[str, Any]:
    condition_a = summarize_condition([result.condition_a for result in results])
    condition_b = summarize_condition([result.condition_b for result in results])

    per_taxonomy: dict[str, Any] = {}
    for taxonomy in TAXONOMY_ORDER:
        bucket = [result for result in results if result.taxonomy_class == taxonomy]
        if not bucket:
            continue
        per_taxonomy[taxonomy] = {
            "cases": len(bucket),
            "condition_a": summarize_condition([result.condition_a for result in bucket]),
            "condition_b": summarize_condition([result.condition_b for result in bucket]),
        }

    return {
        "condition_a": condition_a,
        "condition_b": condition_b,
        "per_taxonomy": per_taxonomy,
        "mcnemar_fix_type": mcnemar_exact(results),
    }


def format_accuracy(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator} ({percentage(numerator, denominator):.1f}%)"


def describe_examples(results: list[CaseExperimentResult], limit: int = 5) -> list[CaseExperimentResult]:
    preferred = [
        result
        for result in results
        if result.condition_b.fix_type_match and not result.condition_a.fix_type_match
    ]
    preferred.sort(
        key=lambda result: (
            TAXONOMY_ORDER.index(result.taxonomy_class),
            not bool(result.condition_b.semantic_similarity),
            SOURCE_PRIORITY.get(result.source, 99),
            result.case_id,
        )
    )
    return preferred[:limit]


def build_report(
    *,
    selected_cases: list[CaseCandidate],
    results: list[CaseExperimentResult],
    aggregates: dict[str, Any],
    config: dict[str, Any],
) -> str:
    selection_taxonomy = Counter(candidate.taxonomy_class for candidate in selected_cases)
    selection_source = Counter(candidate.source for candidate in selected_cases)
    a_summary = aggregates["condition_a"]
    b_summary = aggregates["condition_b"]
    stats = aggregates["mcnemar_fix_type"]

    lines = [
        "# Repair Experiment: Raw Logs vs Raw Logs + OBLIGE",
        "",
        f"- Generated: `{now_iso()}`",
        f"- Model: `{MODEL_CANDIDATES[0]}` with fallback `{MODEL_CANDIDATES[1]}`",
        f"- Cases: `{len(selected_cases)}`",
        f"- API delay: `{config['delay_seconds']}` seconds between calls",
        "",
        "## Selection Summary",
        "",
        "| Taxonomy | Cases |",
        "| --- | ---: |",
    ]
    for taxonomy in TAXONOMY_ORDER:
        lines.append(f"| `{taxonomy}` | {selection_taxonomy.get(taxonomy, 0)} |")
    lines.extend(
        [
            "",
            "| Source | Cases |",
            "| --- | ---: |",
        ]
    )
    for source in ("stackoverflow", "github_issues", "kernel_selftests"):
        if selection_source.get(source, 0):
            lines.append(f"| `{source}` | {selection_source[source]} |")

    lines.extend(
        [
            "",
            "## Fix-Type Success Rate",
            "",
            "| Condition | Fix type match | Root-cause targeting | Semantic similarity |",
            "| --- | ---: | ---: | ---: |",
            (
                f"| A (raw log only) | "
                f"{format_accuracy(a_summary['fix_type_correct'], a_summary['cases'])} | "
                f"{format_accuracy(a_summary['location_correct'], a_summary['location_available'])} | "
                f"{format_accuracy(a_summary['semantic_correct'], a_summary['semantic_available'])} |"
            ),
            (
                f"| B (raw log + OBLIGE) | "
                f"{format_accuracy(b_summary['fix_type_correct'], b_summary['cases'])} | "
                f"{format_accuracy(b_summary['location_correct'], b_summary['location_available'])} | "
                f"{format_accuracy(b_summary['semantic_correct'], b_summary['semantic_available'])} |"
            ),
            "",
            "## Per-Taxonomy Breakdown",
            "",
            "| Taxonomy | Cases | A fix-type | B fix-type | Delta |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for taxonomy in TAXONOMY_ORDER:
        bucket = aggregates["per_taxonomy"].get(taxonomy)
        if not bucket:
            continue
        a_correct = bucket["condition_a"]["fix_type_correct"]
        b_correct = bucket["condition_b"]["fix_type_correct"]
        lines.append(
            f"| `{taxonomy}` | {bucket['cases']} | "
            f"{format_accuracy(a_correct, bucket['cases'])} | "
            f"{format_accuracy(b_correct, bucket['cases'])} | "
            f"{percentage(b_correct - a_correct, bucket['cases']):+.1f} pp |"
        )

    lines.extend(
        [
            "",
            "## Concrete Cases Where OBLIGE Helped",
            "",
        ]
    )
    examples = describe_examples(results)
    if not examples:
        lines.append("- No cases where Condition B fixed the type mismatch while Condition A did not.")
    else:
        for result in examples:
            lines.extend(
                [
                    f"### `{result.case_id}`",
                    "",
                    f"- Taxonomy: `{result.taxonomy_class}`",
                    f"- Expected fix: `{fix_type_label(result.expected_fix_type)}`",
                    f"- Condition A predicted: `{fix_type_label(result.condition_a.predicted_fix_type)}`",
                    f"- Condition B predicted: `{fix_type_label(result.condition_b.predicted_fix_type)}`",
                    (
                        f"- Ground truth fix: {markdown_cell(result.ground_truth_fix)}"
                        if result.ground_truth_fix
                        else "- Ground truth fix: unavailable"
                    ),
                    (
                        f"- B response summary: {result.condition_b.parsed_response.get('summary', '').strip()}"
                        if result.condition_b.parsed_response
                        else f"- B response excerpt: {result.condition_b.raw_response[:240].strip()}"
                    ),
                    "",
                ]
            )

    lines.extend(
        [
            "## Statistical Comparison",
            "",
            f"- Condition A fix-type accuracy: `{a_summary['fix_type_correct']}/{a_summary['cases']}` ({a_summary['fix_type_accuracy']:.1f}%).",
            f"- Condition B fix-type accuracy: `{b_summary['fix_type_correct']}/{b_summary['cases']}` ({b_summary['fix_type_accuracy']:.1f}%).",
            (
                f"- McNemar exact test on paired fix-type correctness: "
                f"`A-only={stats['a_only']}`, `B-only={stats['b_only']}`, `p={stats['p_value']:.4f}`."
            ),
            "",
            "## Raw Results",
            "",
            "| Case | Taxonomy | Expected fix | Condition A fix | Condition B fix | A correct | B correct |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for result in results:
        lines.append(
            f"| `{result.case_id}` | `{result.taxonomy_class}` | "
            f"`{markdown_cell(fix_type_label(result.expected_fix_type))}` | "
            f"`{markdown_cell(fix_type_label(result.condition_a.predicted_fix_type))}` | "
            f"`{markdown_cell(fix_type_label(result.condition_b.predicted_fix_type))}` | "
            f"{'yes' if result.condition_a.fix_type_match else 'no'} | "
            f"{'yes' if result.condition_b.fix_type_match else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-count", type=int, default=TOTAL_CASES)
    parser.add_argument("--delay-seconds", type=float, default=1.0)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-output-tokens", type=int, default=900)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--manual-labels-path", type=Path, default=DEFAULT_MANUAL_LABELS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--rescore-only",
        action="store_true",
        help="Recompute heuristic scores and rebuild outputs from cached responses in results-path.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manual_labels = load_manual_labels(args.manual_labels_path)

    candidates: list[CaseCandidate] = []
    for path in iter_case_paths(CASE_DIRS):
        candidate = build_candidate(path, manual_labels)
        if candidate is None:
            continue
        if candidate.taxonomy_class not in ALLOWED_TAXONOMIES:
            continue
        candidates.append(candidate)

    if not candidates:
        raise RuntimeError("No eligible cases with verifier logs and source code were found.")

    selected_cases, selection_summary = select_cases(candidates, case_count=args.case_count)
    print("Requested taxonomy counts:", selection_summary["requested_targets"])
    print("Effective taxonomy counts:", selection_summary["effective_targets"])
    print("Eligible pool counts:", dict(selection_summary["pool_counts"]))
    print(
        "Requested total cases:",
        selection_summary["requested_case_count"],
        "Selected total cases:",
        selection_summary["effective_case_count"],
    )
    print("Selected case counts:", dict(selection_summary["selected_taxonomy_counts"]))
    print("Selected source counts:", dict(selection_summary["selected_source_counts"]))
    print(
        "Selected trace stats:",
        {
            "trace_rich_cases": (
                f"{selection_summary['selected_trace_rich_count']}/{len(selected_cases)}"
            ),
            "total_log_lines": selection_summary["selected_log_lines_total"],
            "total_state_dump_lines": selection_summary["selected_trace_state_lines"],
        },
    )
    for candidate in selected_cases:
        print(
            f"  - {candidate.case_id} [{candidate.taxonomy_class}] "
            f"{fix_type_label(candidate.expected_fix_type)} "
            f"({candidate.source})"
        )

    config = {
        "case_count": args.case_count,
        "delay_seconds": args.delay_seconds,
        "temperature": args.temperature,
        "max_output_tokens": args.max_output_tokens,
        "timeout_seconds": args.timeout_seconds,
        "model_candidates": list(MODEL_CANDIDATES),
    }

    if args.dry_run:
        return 0

    if args.rescore_only:
        cached_payload = load_existing_results(args.results_path)
        cached_by_case = {
            item["case_id"]: item for item in cached_payload.get("results", []) if isinstance(item, dict)
        }
        rescored_results: list[CaseExperimentResult] = []
        for candidate in selected_cases:
            cached = cached_by_case.get(candidate.case_id)
            if cached is None:
                raise RuntimeError(
                    f"Missing cached responses for case_id={candidate.case_id} in {args.results_path}"
                )

            cached_a = cached.get("condition_a") or {}
            cached_b = cached.get("condition_b") or {}
            condition_a = evaluate_response(
                candidate=candidate,
                condition="a",
                prompt=str(cached_a.get("prompt") or build_prompt(candidate, "a")),
                model=cached_a.get("model"),
                raw_response=str(cached_a.get("raw_response") or ""),
                parsed_response=cached_a.get("parsed_response"),
                api_error=cached_a.get("api_error"),
                usage_output_tokens=cached_a.get("usage_output_tokens"),
            )
            condition_b = evaluate_response(
                candidate=candidate,
                condition="b",
                prompt=str(cached_b.get("prompt") or build_prompt(candidate, "b")),
                model=cached_b.get("model"),
                raw_response=str(cached_b.get("raw_response") or ""),
                parsed_response=cached_b.get("parsed_response"),
                api_error=cached_b.get("api_error"),
                usage_output_tokens=cached_b.get("usage_output_tokens"),
            )
            rescored_results.append(
                CaseExperimentResult(
                    case_id=candidate.case_id,
                    case_path=candidate.case_path,
                    source=candidate.source,
                    taxonomy_class=candidate.taxonomy_class,
                    error_id=candidate.error_id,
                    title=candidate.title,
                    source_url=candidate.source_url,
                    expected_fix_type=candidate.expected_fix_type,
                    expected_fix_tags=list(candidate.expected_fix_tags),
                    ground_truth_fix=candidate.ground_truth_fix,
                    ground_truth_fix_source=candidate.ground_truth_fix_source,
                    root_span_text=candidate.root_span_text,
                    symptom_span_text=candidate.symptom_span_text,
                    condition_a=condition_a,
                    condition_b=condition_b,
                )
            )

        aggregates = aggregate_results(rescored_results)
        report = build_report(
            selected_cases=selected_cases,
            results=rescored_results,
            aggregates=aggregates,
            config=config,
        )
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(report, encoding="utf-8")
        save_results_bundle(
            path=args.results_path,
            selection_summary=selection_summary,
            selected_cases=selected_cases,
            results=rescored_results,
            aggregates=aggregates,
            config=config,
        )
        print(f"Rescored cached results in {args.results_path}")
        print(f"Rebuilt report at {args.report_path}")
        return 0

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    client = OpenAI(api_key=api_key)

    results: list[CaseExperimentResult] = []
    total_calls = len(selected_cases) * 2
    completed_calls = 0

    for index, candidate in enumerate(selected_cases, start=1):
        print(
            f"[{index}/{len(selected_cases)}] {candidate.case_id} "
            f"taxonomy={candidate.taxonomy_class} expected={candidate.expected_fix_type}"
        )
        condition_outputs: dict[str, ConditionResult] = {}
        for condition in ("a", "b"):
            completed_calls += 1
            prompt = build_prompt(candidate, condition)
            print(f"  -> condition {condition.upper()} ({completed_calls}/{total_calls})")
            raw_response, parsed_response, model, api_error, usage_output_tokens = call_openai_with_fallback(
                client=client,
                prompt=prompt,
                temperature=args.temperature,
                max_output_tokens=args.max_output_tokens,
                timeout_seconds=args.timeout_seconds,
            )
            if api_error:
                print(f"     API error: {api_error}")
            condition_outputs[condition] = evaluate_response(
                candidate=candidate,
                condition=condition,
                prompt=prompt,
                model=model,
                raw_response=raw_response,
                parsed_response=parsed_response,
                api_error=api_error,
                usage_output_tokens=usage_output_tokens,
            )
            time.sleep(args.delay_seconds)

        case_result = CaseExperimentResult(
            case_id=candidate.case_id,
            case_path=candidate.case_path,
            source=candidate.source,
            taxonomy_class=candidate.taxonomy_class,
            error_id=candidate.error_id,
            title=candidate.title,
            source_url=candidate.source_url,
            expected_fix_type=candidate.expected_fix_type,
            expected_fix_tags=list(candidate.expected_fix_tags),
            ground_truth_fix=candidate.ground_truth_fix,
            ground_truth_fix_source=candidate.ground_truth_fix_source,
            root_span_text=candidate.root_span_text,
            symptom_span_text=candidate.symptom_span_text,
            condition_a=condition_outputs["a"],
            condition_b=condition_outputs["b"],
        )
        results.append(case_result)

        partial_aggregates = aggregate_results(results)
        save_results_bundle(
            path=args.results_path,
            selection_summary=selection_summary,
            selected_cases=selected_cases,
            results=results,
            aggregates=partial_aggregates,
            config=config,
        )

    aggregates = aggregate_results(results)
    report = build_report(
        selected_cases=selected_cases,
        results=results,
        aggregates=aggregates,
        config=config,
    )
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")
    save_results_bundle(
        path=args.results_path,
        selection_summary=selection_summary,
        selected_cases=selected_cases,
        results=results,
        aggregates=aggregates,
        config=config,
    )
    print(f"Wrote results to {args.results_path}")
    print(f"Wrote report to {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
