#!/usr/bin/env python3
"""Evaluate whether BPFix spans cover known fix locations."""

from __future__ import annotations

import argparse
import difflib
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

from eval.ground_truth import (
    DEFAULT_GROUND_TRUTH_PATH,
    GroundTruthLabel,
    load_ground_truth_labels,
)
from interface.extractor.rust_diagnostic import generate_diagnostic


LOG_CASE_DIRS: tuple[tuple[str, Path], ...] = (
    ("stackoverflow", ROOT / "case_study" / "cases" / "stackoverflow"),
    ("github_issues", ROOT / "case_study" / "cases" / "github_issues"),
    ("kernel_selftests", ROOT / "case_study" / "cases" / "kernel_selftests"),
)
SYNTHETIC_DIR = ROOT / "case_study" / "cases" / "eval_commits_synthetic"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "span_coverage_results.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "span-coverage-eval.md"

FIX_PATTERN_TO_TAXONOMY: dict[str, str] = {
    "alignment": "source_bug",
    "attribute_annotation": "lowering_artifact",
    "bounds_check": "source_bug",
    "btf_metadata": "env_mismatch",
    "complexity_reduction": "verifier_limit",
    "helper_switch": "env_mismatch",
    "inline_hint": "lowering_artifact",
    "kernel_upgrade": "verifier_bug",
    "loop_rewrite": "verifier_limit",
    "null_check": "source_bug",
    "other": "source_bug",
    "ref_release": "source_bug",
    "stack_init": "source_bug",
    "type_cast": "source_bug",
    "volatile_hack": "lowering_artifact",
}
PATTERN_DEFAULT_LOCALIZABILITY: dict[str, str] = {
    "alignment": "yes",
    "attribute_annotation": "partial",
    "bounds_check": "yes",
    "btf_metadata": "no",
    "complexity_reduction": "no",
    "helper_switch": "yes",
    "inline_hint": "partial",
    "kernel_upgrade": "no",
    "loop_rewrite": "partial",
    "null_check": "yes",
    "other": "partial",
    "ref_release": "partial",
    "stack_init": "yes",
    "type_cast": "yes",
    "volatile_hack": "partial",
}
GROUND_TRUTH_FIX_TYPE_TO_PATTERN: dict[str, str] = {
    "bounds_check": "bounds_check",
    "clamp": "bounds_check",
    "env_fix": "helper_switch",
    "inline": "inline_hint",
    "loop_rewrite": "loop_rewrite",
    "null_check": "null_check",
    "refcount": "ref_release",
    "reorder": "other",
    "type_cast": "type_cast",
}
TAXONOMY_ORDER: tuple[str, ...] = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
)
STOPWORDS = {
    "a",
    "actual",
    "add",
    "added",
    "after",
    "all",
    "an",
    "and",
    "are",
    "as",
    "avoid",
    "before",
    "between",
    "by",
    "call",
    "calling",
    "checks",
    "code",
    "compiler",
    "context",
    "dominates",
    "dominating",
    "each",
    "every",
    "exactly",
    "explicit",
    "explicitly",
    "failure",
    "fix",
    "for",
    "from",
    "function",
    "functions",
    "helper",
    "in",
    "inside",
    "into",
    "is",
    "it",
    "keep",
    "kernel",
    "loader",
    "logic",
    "loop",
    "mark",
    "missing",
    "move",
    "must",
    "new",
    "not",
    "null",
    "object",
    "of",
    "on",
    "one",
    "or",
    "outside",
    "pass",
    "pointer",
    "proof",
    "program",
    "range",
    "read",
    "recompute",
    "reduce",
    "refactor",
    "regenerate",
    "release",
    "rewrite",
    "same",
    "safe",
    "so",
    "stack",
    "the",
    "their",
    "this",
    "through",
    "to",
    "toolchain",
    "upgrade",
    "use",
    "valid",
    "value",
    "verifier",
    "with",
    "without",
}
CODE_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
WHITESPACE_RE = re.compile(r"\s+")

PATTERN_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "inline_hint",
        (
            r"__always_inline",
            r"\bforce inline\b",
            r"\bmark .* inline\b",
            r"\bkeep the proof within one function\b",
            r"\binline the helper\b",
        ),
    ),
    (
        "volatile_hack",
        (
            r"\bvolatile\b",
        ),
    ),
    (
        "attribute_annotation",
        (
            r"\battribute\b",
            r"\bannotation\b",
            r"\b__noinline\b",
            r"\bsec\(\"maps\"\)\b",
            r"\bmap pointer relocation\b",
        ),
    ),
    (
        "null_check",
        (
            r"\bnull-?check\b",
            r"\bnon-null\b",
            r"\bpossibly null\b",
            r"\bnullable\b",
            r"\bif \(!?[a-z_][a-z0-9_]*\)\b",
        ),
    ),
    (
        "stack_init",
        (
            r"\binitialize\b.*\bstack\b",
            r"\binitialize\b.*\bslot\b",
            r"\binitialize\b.*\bbuffer\b",
            r"\binitialized stack\b",
            r"\bindirect read from stack\b",
        ),
    ),
    (
        "ref_release",
        (
            r"\brelease .* once\b",
            r"\brelease twice\b",
            r"\bdestroy .* every exit path\b",
            r"\bunreleased reference\b",
            r"\bleak\b",
            r"\breusing it after release\b",
        ),
    ),
    (
        "helper_switch",
        (
            r"\bhelper\b.*\bnot allowed\b",
            r"\bhelper\b.*\bunavailable\b",
            r"\bprogram type\b",
            r"\buse .* instead\b",
            r"\bmove the logic to a program type\b",
            r"\bpreserve the loader-generated map pointer relocation\b",
            r"\bqueue maps\b",
        ),
    ),
    (
        "other",
        (
            r"\bunwrap\b",
            r"\bpanic(?:ing|ed)?\b",
            r"\bexplicit error handling\b",
        ),
    ),
    (
        "btf_metadata",
        (
            r"\bbtf\b",
            r"\breference metadata\b",
            r"\breference size\b",
            r"\bunknown\b.*\bsize\b",
            r"\bartifacts\b",
        ),
    ),
    (
        "loop_rewrite",
        (
            r"\bloop\b",
            r"\bback-edge\b",
            r"\bunroll\b",
            r"\bverifier-friendly loop\b",
        ),
    ),
    (
        "complexity_reduction",
        (
            r"\bstate fan-out\b",
            r"\btoo complex\b",
            r"\bcombined stack\b",
            r"\bstack budget\b",
            r"\bcomplexity\b",
            r"\bbranching\b",
            r"\bsimpler stages\b",
        ),
    ),
    (
        "alignment",
        (
            r"\balign(?:ment|ed|ing)?\b",
            r"\bmisalign(?:ed|ment)?\b",
        ),
    ),
    (
        "type_cast",
        (
            r"\bcast\b",
            r"\bwrong type\b",
            r"\bpointer type\b",
            r"\bactual dynptr\b",
            r"\bscalar address\b",
            r"\bvalid destination object\b",
        ),
    ),
    (
        "bounds_check",
        (
            r"\bbounds? check\b",
            r"\bupper-bound\b",
            r"\blower-bound\b",
            r"\bclamp\b",
            r"\brange proof\b",
            r"\bre-read packet pointers\b",
            r"\bchecked pointer\b",
            r"\bunsigned form\b",
            r"\bcopy length explicitly bounded\b",
            r"\bunbounded memory access\b",
            r"\boutside of the allowed memory range\b",
        ),
    ),
    (
        "kernel_upgrade",
        (
            r"\bupgrade to a newer kernel\b",
            r"\bkernel with the verifier fix\b",
            r"\bverifier bug\b",
            r"\bbackport\b",
            r"\bkernel upgrade\b",
        ),
    ),
)


@dataclass(slots=True)
class CodeSnippet:
    file: str | None
    code: str


@dataclass(slots=True)
class DiffSummary:
    source: str
    removed_lines: list[str]
    added_lines: list[str]
    changed_line_count: int
    pattern_summary: str


@dataclass(slots=True)
class GroundTruth:
    taxonomy_class: str | None
    fix_pattern: str | None
    fix_text: str
    fix_text_source: str
    localizability: str | None
    specificity: str | None
    expected_messages: list[str]
    diff_summary: DiffSummary | None
    anchor_identifiers: list[str]


@dataclass(slots=True)
class CaseEvaluation:
    case_id: str
    source: str
    case_path: str
    verifier_log_chars: int
    diagnostic_success: bool
    exception: str | None
    output_error_id: str | None
    output_taxonomy_class: str | None
    output_proof_status: str | None
    num_spans: int
    span_roles: list[str]
    rejected_span_matches_error: str
    rejected_span_match_basis: str | None
    fix_location_covered: str
    fix_location_basis: str | None
    ground_truth_taxonomy_class: str | None
    ground_truth_fix_pattern: str | None
    ground_truth_fix_text_source: str
    ground_truth_localizability: str | None
    fix_type_matches_taxonomy: str
    expected_message_count: int
    diff_changed_line_count: int
    matched_span_texts: list[str]
    anchor_identifiers: list[str]
    spans: list[dict[str, Any]]
    note: str | None
    help_text: str | None


@dataclass(slots=True)
class SyntheticEvaluation:
    case_id: str
    original_case_id: str | None
    case_path: str
    fix_type: str
    taxonomy_class: str | None
    changed_line_count: int
    added_lines: list[str]
    removed_lines: list[str]
    pattern_summary: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ground-truth-path",
        type=Path,
        default=DEFAULT_GROUND_TRUTH_PATH,
        help=f"Path to case_study/ground_truth.yaml (default: {DEFAULT_GROUND_TRUTH_PATH})",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help=f"Where to save raw JSON results (default: {DEFAULT_RESULTS_PATH})",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"Where to save the markdown report (default: {DEFAULT_REPORT_PATH})",
    )
    return parser.parse_args()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_space(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def normalize_line(text: str) -> str:
    return normalize_space(text).strip().strip(";")


def normalize_text(text: str) -> str:
    return normalize_space(text.lower())


def normalize_source(source: str) -> str:
    mapping = {
        "stackoverflow": "SO",
        "github_issues": "GH",
        "kernel_selftests": "KS",
        "eval_commits_synthetic": "SYN",
    }
    return mapping.get(source, source.upper())


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log.strip()
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined", "")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            return "\n\n".join(block.strip() for block in blocks if isinstance(block, str) and block.strip())
    return ""


def extract_fix_text(
    case_data: dict[str, Any],
    ground_truth_label: GroundTruthLabel | None,
) -> tuple[str, str]:
    if ground_truth_label is not None and ground_truth_label.fix_direction:
        return ground_truth_label.fix_direction.strip(), "ground_truth"

    selected_answer = case_data.get("selected_answer") or {}
    if isinstance(selected_answer, dict):
        text = (
            selected_answer.get("fix_description")
            or selected_answer.get("body_text")
            or ""
        ).strip()
        if text:
            return text, "yaml_selected_answer"

    issue_fix = case_data.get("fix") or {}
    if isinstance(issue_fix, dict):
        selected_comment = issue_fix.get("selected_comment") or {}
        text = (
            selected_comment.get("body_text")
            or issue_fix.get("summary")
            or ""
        ).strip()
        if text:
            return text, "yaml_issue_fix"

    return "", "missing"


def extract_expected_messages(case_data: dict[str, Any]) -> list[str]:
    raw = case_data.get("expected_verifier_messages")
    if isinstance(raw, dict):
        combined = raw.get("combined")
        if isinstance(combined, list):
            return [msg.strip() for msg in combined if isinstance(msg, str) and msg.strip()]
        out: list[str] = []
        for key in ("privileged", "unprivileged"):
            value = raw.get(key)
            if isinstance(value, list):
                out.extend(msg.strip() for msg in value if isinstance(msg, str) and msg.strip())
        return out
    if isinstance(raw, list):
        return [msg.strip() for msg in raw if isinstance(msg, str) and msg.strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def extract_source_snippets(case_data: dict[str, Any]) -> list[CodeSnippet]:
    snippets = case_data.get("source_snippets") or []
    out: list[CodeSnippet] = []
    if not isinstance(snippets, list):
        return out
    for snippet in snippets:
        if isinstance(snippet, dict):
            code = snippet.get("code")
            if isinstance(code, str) and code.strip():
                file_name = snippet.get("file")
                out.append(
                    CodeSnippet(
                        file=str(file_name).strip() if isinstance(file_name, str) and file_name.strip() else None,
                        code=code.strip(),
                    )
                )
        elif isinstance(snippet, str) and snippet.strip():
            out.append(CodeSnippet(file=None, code=snippet.strip()))
    return out


def meaningful_changed_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("// CONTEXT:") or line.startswith("// FILE:"):
            continue
        if line in {"{", "}", ");", "(", ")", "else", "else {", "};"}:
            continue
        normalized = normalize_line(line)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(line)
    return out


def compute_diff_summary(before: str, after: str, source: str) -> DiffSummary:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
    removed: list[str] = []
    added: list[str] = []
    for opcode, i1, i2, j1, j2 in matcher.get_opcodes():
        if opcode in {"replace", "delete"}:
            removed.extend(before_lines[i1:i2])
        if opcode in {"replace", "insert"}:
            added.extend(after_lines[j1:j2])
    removed = meaningful_changed_lines(removed)
    added = meaningful_changed_lines(added)
    changed_count = len(removed) + len(added)
    return DiffSummary(
        source=source,
        removed_lines=removed,
        added_lines=added,
        changed_line_count=changed_count,
        pattern_summary=diff_pattern_summary(added, removed, None),
    )


def similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(a=a, b=b).ratio()


def score_candidate_diff(before: str, after: str, hint_text: str) -> tuple[float, DiffSummary]:
    diff = compute_diff_summary(before, after, "snippet_pair")
    changed_lines = diff.added_lines + diff.removed_lines
    ratio = similarity_ratio(before, after)
    hint_overlap = overlap_score(changed_lines, extract_anchor_identifiers(hint_text))
    score = ratio * 10.0 + hint_overlap - (0.35 * diff.changed_line_count)
    return score, diff


def select_source_snippet_diff(snippets: list[CodeSnippet], hint_text: str) -> DiffSummary | None:
    if len(snippets) < 2:
        return None

    best_score = float("-inf")
    best_diff: DiffSummary | None = None
    for idx, first in enumerate(snippets):
        for second in snippets[idx + 1 :]:
            score, diff = score_candidate_diff(first.code, second.code, hint_text)
            if diff.changed_line_count == 0 or diff.changed_line_count > 12:
                continue
            if similarity_ratio(first.code, second.code) < 0.45:
                continue
            if score > best_score:
                best_score = score
                best_diff = diff
    if best_diff is None:
        return None
    if best_score < 4.0:
        return None
    best_diff.source = "source_snippets"
    best_diff.pattern_summary = diff_pattern_summary(best_diff.added_lines, best_diff.removed_lines, None)
    return best_diff


def extract_anchor_identifiers(text: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for match in CODE_IDENTIFIER_RE.finditer(text):
        token = match.group(0)
        lowered = token.lower()
        if lowered in STOPWORDS:
            continue
        if len(token) < 3 and not token.startswith("__"):
            continue
        if "_" not in token and token.islower() and len(token) < 5:
            continue
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def overlap_score(lines: list[str], identifiers: list[str]) -> int:
    if not lines or not identifiers:
        return 0
    score = 0
    normalized_lines = [normalize_text(line) for line in lines]
    for identifier in identifiers:
        needle = normalize_text(identifier)
        if any(needle in line for line in normalized_lines):
            score += 1
    return score


def infer_fix_pattern(text: str) -> str | None:
    normalized = normalize_text(text)
    if not normalized:
        return None
    for pattern, regexes in PATTERN_RULES:
        if any(re.search(regex, normalized) for regex in regexes):
            return pattern
    return None


def fix_pattern_from_ground_truth(label: GroundTruthLabel | None) -> str | None:
    if label is None:
        return None
    if label.fix_type:
        mapped = GROUND_TRUTH_FIX_TYPE_TO_PATTERN.get(label.fix_type)
        if mapped is not None:
            return mapped
    return infer_fix_pattern(label.fix_direction)


def infer_pattern_from_expected_messages(messages: list[str]) -> str | None:
    if not messages:
        return None
    normalized = normalize_text(" ".join(messages))
    if "possibly null" in normalized or "null pointer passed" in normalized:
        return "null_check"
    if "combined stack size" in normalized or "too complex" in normalized:
        return "complexity_reduction"
    if "back-edge" in normalized or "loop is not bounded" in normalized:
        return "loop_rewrite"
    if "unreleased reference" in normalized or "expects release" in normalized:
        return "ref_release"
    if "reference type('unknown" in normalized or "invalid btf" in normalized:
        return "btf_metadata"
    if "not allowed" in normalized or "unsupported" in normalized:
        return "helper_switch"
    if "misaligned" in normalized:
        return "alignment"
    if "initialized" in normalized and ("dynptr" in normalized or "stack" in normalized or "iter" in normalized):
        return "stack_init"
    if "type=" in normalized or "must point" in normalized or "trusted" in normalized:
        return "type_cast"
    if (
        "invalid access" in normalized
        or "invalid mem access" in normalized
        or "invalid read" in normalized
        or "invalid write" in normalized
        or "outside of the allowed memory range" in normalized
        or "unbounded memory access" in normalized
    ):
        return "bounds_check"
    return None


def diff_pattern_summary(added_lines: list[str], removed_lines: list[str], fix_type: str | None) -> str:
    joined_added = normalize_text("\n".join(added_lines))
    joined_removed = normalize_text("\n".join(removed_lines))
    if fix_type == "inline_hint" or "__always_inline" in joined_added:
        return "added __always_inline or similar inlining hint"
    if fix_type == "volatile_hack" or "volatile" in joined_added:
        return "added volatile annotation to preserve verifier-visible proof"
    if fix_type == "null_check" or ("if (" in joined_added and "null" in joined_added):
        return "added an explicit null guard before the failing operation"
    if fix_type == "bounds_check" or "if (" in joined_added or "if(" in joined_added:
        return "added or strengthened an explicit bounds guard"
    if fix_type == "helper_switch":
        before_helpers = [tok for tok in extract_anchor_identifiers(joined_removed) if tok.startswith("bpf_")]
        after_helpers = [tok for tok in extract_anchor_identifiers(joined_added) if tok.startswith("bpf_")]
        if before_helpers or after_helpers:
            return "switched helper or API usage"
        return "switched environment-specific helper or API usage"
    if fix_type == "loop_rewrite" or "for (" in joined_added or "while (" in joined_added:
        return "rewrote the loop shape or its verifier-visible bound"
    if fix_type == "alignment" or "memcpy" in joined_added:
        return "copied or reshaped data to satisfy alignment constraints"
    if fix_type == "type_cast":
        return "changed the type, cast, or object provenance at the failing site"
    if fix_type == "attribute_annotation":
        return "added an attribute or annotation that changes lowering behavior"
    if fix_type == "refactor":
        return "refactored control or data flow around the failing path"
    if fix_type == "other":
        return "other localized source change"
    if "return 0" in joined_added and "unwrap" in joined_removed:
        return "replaced panic-style unwrap with explicit error handling"
    if "bpf_core_read" in joined_added:
        return "replaced direct field access with BPF_CORE_READ"
    if added_lines or removed_lines:
        preview = (added_lines or removed_lines)[0]
        return f"changed lines around `{normalize_space(preview)[:60]}`"
    return "no diff detected"


def build_ground_truth(
    case_data: dict[str, Any],
    ground_truth_label: GroundTruthLabel | None,
) -> GroundTruth:
    fix_text, fix_text_source = extract_fix_text(case_data, ground_truth_label)
    expected_messages = extract_expected_messages(case_data)
    source_snippets = extract_source_snippets(case_data)

    pattern = fix_pattern_from_ground_truth(ground_truth_label)
    if pattern is None:
        pattern = infer_fix_pattern(fix_text)
    if pattern is None:
        pattern = infer_pattern_from_expected_messages(expected_messages)

    taxonomy_class = ground_truth_label.taxonomy_class if ground_truth_label is not None else None
    if taxonomy_class is None and pattern is not None:
        taxonomy_class = FIX_PATTERN_TO_TAXONOMY.get(pattern)

    localizability = None
    if localizability is None and pattern is not None:
        localizability = PATTERN_DEFAULT_LOCALIZABILITY.get(pattern)

    diff_summary: DiffSummary | None = None
    fixed_code = case_data.get("fixed_code")
    if isinstance(fixed_code, str) and fixed_code.strip() and source_snippets:
        diff_summary = compute_diff_summary(source_snippets[0].code, fixed_code.strip(), "fixed_code")
        diff_summary.pattern_summary = diff_pattern_summary(
            diff_summary.added_lines,
            diff_summary.removed_lines,
            str(case_data.get("fix_type") or "").strip() or None,
        )
    elif source_snippets:
        diff_summary = select_source_snippet_diff(source_snippets, fix_text)

    identifiers: list[str] = []
    for text in (
        fix_text,
        " ".join(expected_messages),
        "\n".join(diff_summary.added_lines + diff_summary.removed_lines) if diff_summary else "",
    ):
        for token in extract_anchor_identifiers(text):
            if token not in identifiers:
                identifiers.append(token)

    return GroundTruth(
        taxonomy_class=taxonomy_class,
        fix_pattern=pattern,
        fix_text=fix_text,
        fix_text_source=fix_text_source,
        localizability=localizability,
        specificity=None,
        expected_messages=expected_messages,
        diff_summary=diff_summary,
        anchor_identifiers=identifiers,
    )


def span_roles(spans: list[dict[str, Any]]) -> list[str]:
    roles = sorted(
        {
            str(span.get("role", "")).strip()
            for span in spans
            if isinstance(span, dict) and span.get("role")
        }
    )
    return roles


def output_bundle_text(json_data: dict[str, Any]) -> str:
    parts: list[str] = [
        str(json_data.get("taxonomy_class") or ""),
        str(json_data.get("proof_status") or ""),
        str(json_data.get("note") or ""),
        str(json_data.get("help") or ""),
    ]
    obligation = json_data.get("obligation")
    if isinstance(obligation, dict):
        parts.append(str(obligation.get("type") or ""))
        parts.append(str(obligation.get("required") or ""))
    spans = json_data.get("spans") or []
    if isinstance(spans, list):
        for span in spans:
            if not isinstance(span, dict):
                continue
            parts.append(str(span.get("source_text") or ""))
            parts.append(str(span.get("reason") or ""))
            parts.append(str(span.get("state_change") or ""))
    return normalize_text(" ".join(parts))


def rejected_spans(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for span in spans:
        if isinstance(span, dict) and span.get("role") == "rejected":
            out.append(span)
    return out


def span_texts(spans: list[dict[str, Any]]) -> list[str]:
    texts: list[str] = []
    seen: set[str] = set()
    for span in spans:
        if not isinstance(span, dict):
            continue
        text = str(span.get("source_text") or "").strip()
        if text and text not in seen:
            seen.add(text)
            texts.append(text)
    return texts


def match_diff_lines(spans: list[dict[str, Any]], diff_summary: DiffSummary | None) -> list[str]:
    if diff_summary is None:
        return []
    span_line_map = {
        normalize_line(text): text
        for text in span_texts(spans)
    }
    matches: list[str] = []
    for line in diff_summary.added_lines + diff_summary.removed_lines:
        normalized = normalize_line(line)
        if not normalized:
            continue
        if normalized in span_line_map:
            matches.append(span_line_map[normalized])
            continue
        for key, text in span_line_map.items():
            if len(normalized) >= 12 and (normalized in key or key in normalized):
                matches.append(text)
                break
    deduped: list[str] = []
    seen: set[str] = set()
    for item in matches:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def match_identifiers(spans: list[dict[str, Any]], identifiers: list[str]) -> list[str]:
    if not identifiers:
        return []
    normalized_spans = [normalize_text(text) for text in span_texts(spans)]
    matches: list[str] = []
    seen: set[str] = set()
    for identifier in identifiers:
        needle = normalize_text(identifier)
        if not needle:
            continue
        if any(needle in span_text for span_text in normalized_spans):
            if identifier not in seen:
                seen.add(identifier)
                matches.append(identifier)
    return matches


def expected_error_match(
    ground_truth: GroundTruth,
    output_json: dict[str, Any],
) -> tuple[str, str | None]:
    if not ground_truth.expected_messages:
        return "unknown", None

    spans = output_json.get("spans") or []
    if not isinstance(spans, list) or not rejected_spans(spans):
        return "no", "no_rejected_span"

    pattern = ground_truth.fix_pattern or infer_pattern_from_expected_messages(ground_truth.expected_messages)
    normalized_output = output_bundle_text(output_json)
    taxonomy = str(output_json.get("taxonomy_class") or "")

    if pattern == "null_check":
        if "null" in normalized_output or "helper arg proof" in normalized_output or taxonomy == "source_bug":
            return "yes", "semantic_nullability_match"
        return "no", "semantic_nullability_mismatch"
    if pattern == "ref_release":
        if "release" in normalized_output or "reference" in normalized_output:
            return "yes", "semantic_release_match"
        return "no", "semantic_release_mismatch"
    if pattern in {"complexity_reduction", "loop_rewrite"}:
        if taxonomy == "verifier_limit":
            return "yes", "taxonomy_verifier_limit"
        return "no", "taxonomy_not_verifier_limit"
    if pattern == "helper_switch":
        if taxonomy == "env_mismatch":
            return "yes", "taxonomy_env_mismatch"
        return "no", "taxonomy_not_env_mismatch"
    if pattern == "btf_metadata":
        if taxonomy == "env_mismatch" and "btf" in normalized_output:
            return "yes", "btf_metadata_match"
        return "no", "btf_metadata_mismatch"
    if pattern in {"inline_hint", "volatile_hack", "attribute_annotation"}:
        if taxonomy == "lowering_artifact":
            return "yes", "taxonomy_lowering_artifact"
        return "no", "taxonomy_not_lowering_artifact"
    if pattern in {"bounds_check", "stack_init", "alignment", "type_cast", "other"}:
        if taxonomy in {"source_bug", "lowering_artifact"}:
            return "yes", "coarse_memory_or_source_match"
        return "no", "coarse_memory_or_source_mismatch"

    if ground_truth.taxonomy_class and taxonomy == ground_truth.taxonomy_class:
        return "yes", "taxonomy_match_fallback"
    return "unknown", None


def evaluate_fix_location(
    ground_truth: GroundTruth,
    output_json: dict[str, Any],
) -> tuple[str, str | None, list[str]]:
    spans = output_json.get("spans") or []
    if not isinstance(spans, list):
        spans = []
    if not spans:
        if ground_truth.localizability == "yes":
            return "no", "no_spans", []
        return "unknown", "no_spans", []

    matched_texts = match_diff_lines(spans, ground_truth.diff_summary)
    if matched_texts:
        return "yes", "span_matches_diff_line", matched_texts

    matched_identifiers = match_identifiers(spans, ground_truth.anchor_identifiers)
    pattern = ground_truth.fix_pattern
    normalized_output = output_bundle_text(output_json)

    if pattern == "null_check":
        if "null" in normalized_output or "dominating null check" in normalized_output:
            return "yes", "diagnostic_mentions_null_check", span_texts(rejected_spans(spans))[:2]
        if matched_identifiers:
            return "yes", "identifier_match", matched_identifiers
    if pattern == "helper_switch":
        if matched_identifiers:
            return "yes", "helper_identifier_match", matched_identifiers
        if any("call bpf_" in normalize_text(text) for text in span_texts(rejected_spans(spans))):
            return "yes", "rejected_helper_call_span", span_texts(rejected_spans(spans))[:2]
        if "program type support the helper" in normalized_output or "cannot use helper" in normalized_output:
            return "yes", "diagnostic_mentions_helper_contract", span_texts(rejected_spans(spans))[:2]
    if pattern in {"bounds_check", "stack_init", "alignment", "type_cast"}:
        if matched_identifiers:
            return "yes", "identifier_match", matched_identifiers
        if "bounds" in normalized_output or "range" in normalized_output or "proof" in normalized_output:
            return "yes", "diagnostic_mentions_bounds", span_texts(rejected_spans(spans))[:2]
    if pattern == "ref_release":
        if any(
            any(keyword in normalize_text(text) for keyword in ("release", "destroy"))
            for text in span_texts(spans)
        ):
            return "yes", "release_or_destroy_span", span_texts(spans)[:2]
        if "release" in normalized_output or "reference" in normalized_output:
            return "yes", "diagnostic_mentions_release", span_texts(rejected_spans(spans))[:2]
    if pattern == "loop_rewrite":
        if any(
            any(keyword in normalize_text(text) for keyword in ("for (", "while (", "goto pc-", "loop"))
            for text in span_texts(spans)
        ):
            return "yes", "loop_related_span", span_texts(spans)[:2]
    if pattern in {"inline_hint", "volatile_hack", "attribute_annotation"} and matched_identifiers:
        return "yes", "identifier_match", matched_identifiers

    if ground_truth.localizability == "yes":
        return "no", "no_localized_match", []
    if ground_truth.diff_summary is not None:
        if ground_truth.fix_pattern in {"helper_switch", "null_check", "bounds_check", "stack_init", "alignment", "type_cast"}:
            return "no", "diff_present_but_unmatched", []
        return "unknown", "diff_present_but_unmatched", []
    if ground_truth.fix_pattern in {"helper_switch", "null_check", "bounds_check", "stack_init", "alignment", "type_cast"}:
        return "no", "localizable_pattern_without_match", []
    return "unknown", "insufficient_localization_anchor", []


def evaluate_logged_case(
    source: str,
    path: Path,
    ground_truth_labels: dict[str, GroundTruthLabel],
) -> CaseEvaluation:
    case_data = read_yaml(path)
    case_id = str(case_data.get("case_id") or path.stem)
    ground_truth_label = ground_truth_labels.get(case_id)
    ground_truth = build_ground_truth(case_data, ground_truth_label)
    verifier_log = extract_verifier_log(case_data)

    if not verifier_log:
        return CaseEvaluation(
            case_id=case_id,
            source=source,
            case_path=str(path),
            verifier_log_chars=0,
            diagnostic_success=False,
            exception="Missing verifier_log",
            output_error_id=None,
            output_taxonomy_class=None,
            output_proof_status=None,
            num_spans=0,
            span_roles=[],
            rejected_span_matches_error="unknown",
            rejected_span_match_basis=None,
            fix_location_covered="unknown",
            fix_location_basis="missing_verifier_log",
            ground_truth_taxonomy_class=ground_truth.taxonomy_class,
            ground_truth_fix_pattern=ground_truth.fix_pattern,
            ground_truth_fix_text_source=ground_truth.fix_text_source,
            ground_truth_localizability=ground_truth.localizability,
            fix_type_matches_taxonomy="unknown",
            expected_message_count=len(ground_truth.expected_messages),
            diff_changed_line_count=ground_truth.diff_summary.changed_line_count if ground_truth.diff_summary else 0,
            matched_span_texts=[],
            anchor_identifiers=ground_truth.anchor_identifiers,
            spans=[],
            note=None,
            help_text=None,
        )

    try:
        output = generate_diagnostic(verifier_log)
    except Exception as exc:  # pragma: no cover - batch eval should keep going.
        return CaseEvaluation(
            case_id=case_id,
            source=source,
            case_path=str(path),
            verifier_log_chars=len(verifier_log),
            diagnostic_success=False,
            exception=f"{type(exc).__name__}: {exc}",
            output_error_id=None,
            output_taxonomy_class=None,
            output_proof_status=None,
            num_spans=0,
            span_roles=[],
            rejected_span_matches_error="unknown",
            rejected_span_match_basis=None,
            fix_location_covered="unknown",
            fix_location_basis="diagnostic_exception",
            ground_truth_taxonomy_class=ground_truth.taxonomy_class,
            ground_truth_fix_pattern=ground_truth.fix_pattern,
            ground_truth_fix_text_source=ground_truth.fix_text_source,
            ground_truth_localizability=ground_truth.localizability,
            fix_type_matches_taxonomy="unknown",
            expected_message_count=len(ground_truth.expected_messages),
            diff_changed_line_count=ground_truth.diff_summary.changed_line_count if ground_truth.diff_summary else 0,
            matched_span_texts=[],
            anchor_identifiers=ground_truth.anchor_identifiers,
            spans=[],
            note=None,
            help_text=None,
        )

    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    spans = json_data.get("spans") or []
    if not isinstance(spans, list):
        spans = []

    error_match, error_basis = expected_error_match(ground_truth, json_data)
    coverage, coverage_basis, matched_texts = evaluate_fix_location(ground_truth, json_data)

    output_taxonomy = str(json_data.get("taxonomy_class") or "") or None
    taxonomy_match = "unknown"
    if ground_truth.taxonomy_class and output_taxonomy:
        taxonomy_match = "yes" if output_taxonomy == ground_truth.taxonomy_class else "no"

    return CaseEvaluation(
        case_id=case_id,
        source=source,
        case_path=str(path),
        verifier_log_chars=len(verifier_log),
        diagnostic_success=True,
        exception=None,
        output_error_id=str(json_data.get("error_id") or "") or None,
        output_taxonomy_class=output_taxonomy,
        output_proof_status=str(json_data.get("proof_status") or "") or None,
        num_spans=len(spans),
        span_roles=span_roles(spans),
        rejected_span_matches_error=error_match,
        rejected_span_match_basis=error_basis,
        fix_location_covered=coverage,
        fix_location_basis=coverage_basis,
        ground_truth_taxonomy_class=ground_truth.taxonomy_class,
        ground_truth_fix_pattern=ground_truth.fix_pattern,
        ground_truth_fix_text_source=ground_truth.fix_text_source,
        ground_truth_localizability=ground_truth.localizability,
        fix_type_matches_taxonomy=taxonomy_match,
        expected_message_count=len(ground_truth.expected_messages),
        diff_changed_line_count=ground_truth.diff_summary.changed_line_count if ground_truth.diff_summary else 0,
        matched_span_texts=matched_texts,
        anchor_identifiers=ground_truth.anchor_identifiers,
        spans=spans,
        note=str(json_data.get("note") or "") or None,
        help_text=str(json_data.get("help") or "") or None,
    )


def evaluate_synthetic_case(path: Path) -> SyntheticEvaluation:
    case_data = read_yaml(path)
    snippets = extract_source_snippets(case_data)
    buggy = snippets[0].code if snippets else ""
    fixed = str(case_data.get("fixed_code") or "").strip()
    diff = compute_diff_summary(buggy, fixed, "fixed_code")
    fix_type = str(case_data.get("fix_type") or "other").strip() or "other"
    diff.pattern_summary = diff_pattern_summary(diff.added_lines, diff.removed_lines, fix_type)
    return SyntheticEvaluation(
        case_id=str(case_data.get("case_id") or path.stem),
        original_case_id=str(case_data.get("original_case_id") or "") or None,
        case_path=str(path),
        fix_type=fix_type,
        taxonomy_class=str(case_data.get("taxonomy_class") or "") or None,
        changed_line_count=diff.changed_line_count,
        added_lines=diff.added_lines,
        removed_lines=diff.removed_lines,
        pattern_summary=diff.pattern_summary,
    )


def format_counter_table(counter: Counter[str], header: str) -> list[str]:
    lines = [f"| {header} | Count |", "| --- | ---: |"]
    for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{key}` | {count} |")
    return lines


def summarize_case_results(results: list[CaseEvaluation]) -> dict[str, Any]:
    by_source: dict[str, dict[str, Any]] = {}
    for source in sorted({result.source for result in results}):
        source_results = [result for result in results if result.source == source]
        coverage_counts = Counter(result.fix_location_covered for result in source_results)
        taxonomy_known = [result for result in source_results if result.fix_type_matches_taxonomy != "unknown"]
        error_known = [result for result in source_results if result.rejected_span_matches_error != "unknown"]
        by_source[source] = {
            "cases": len(source_results),
            "diagnostic_success": sum(1 for result in source_results if result.diagnostic_success),
            "coverage": dict(coverage_counts),
            "taxonomy_match_yes": sum(1 for result in taxonomy_known if result.fix_type_matches_taxonomy == "yes"),
            "taxonomy_match_total": len(taxonomy_known),
            "rejected_match_yes": sum(1 for result in error_known if result.rejected_span_matches_error == "yes"),
            "rejected_match_total": len(error_known),
        }

    labeled_results = [result for result in results if result.ground_truth_fix_text_source == "ground_truth"]
    evaluable_labeled = [result for result in labeled_results if result.fix_location_covered != "unknown"]
    evaluable_taxonomy = [result for result in labeled_results if result.fix_type_matches_taxonomy != "unknown"]
    evaluable_rejected = [result for result in labeled_results if result.rejected_span_matches_error != "unknown"]
    coverage_counts = Counter(result.fix_location_covered for result in results)

    return {
        "total_cases": len(results),
        "diagnostic_success": sum(1 for result in results if result.diagnostic_success),
        "coverage": dict(coverage_counts),
        "taxonomy_match_yes": sum(1 for result in results if result.fix_type_matches_taxonomy == "yes"),
        "taxonomy_match_total": sum(1 for result in results if result.fix_type_matches_taxonomy != "unknown"),
        "rejected_match_yes": sum(1 for result in results if result.rejected_span_matches_error == "yes"),
        "rejected_match_total": sum(1 for result in results if result.rejected_span_matches_error != "unknown"),
        "ground_truth_labeled": {
            "cases": len(labeled_results),
            "coverage": dict(Counter(result.fix_location_covered for result in labeled_results)),
            "coverage_yes": sum(1 for result in evaluable_labeled if result.fix_location_covered == "yes"),
            "coverage_total": len(evaluable_labeled),
            "taxonomy_match_yes": sum(1 for result in evaluable_taxonomy if result.fix_type_matches_taxonomy == "yes"),
            "taxonomy_match_total": len(evaluable_taxonomy),
            "rejected_match_yes": sum(1 for result in evaluable_rejected if result.rejected_span_matches_error == "yes"),
            "rejected_match_total": len(evaluable_rejected),
        },
        "by_source": by_source,
        "exceptions": Counter(result.exception for result in results if result.exception),
    }


def summarize_synthetic_results(results: list[SyntheticEvaluation]) -> dict[str, Any]:
    return {
        "total_cases": len(results),
        "fix_type_counts": Counter(result.fix_type for result in results),
        "taxonomy_counts": Counter(result.taxonomy_class or "unknown" for result in results),
        "pattern_summary_counts": Counter(result.pattern_summary for result in results),
        "avg_changed_lines": round(
            sum(result.changed_line_count for result in results) / len(results), 2
        )
        if results
        else 0.0,
    }


def percent(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{(100.0 * numerator / denominator):.1f}%"


def build_report(
    case_results: list[CaseEvaluation],
    synthetic_results: list[SyntheticEvaluation],
    summary: dict[str, Any],
    synthetic_summary: dict[str, Any],
) -> str:
    lines: list[str] = [
        "# Span Coverage Evaluation",
        "",
        f"- Generated at: `{now_iso()}`",
        f"- Logged cases evaluated: `{summary['total_cases']}`",
        f"- Synthetic diff-only cases analyzed: `{synthetic_summary['total_cases']}`",
        f"- Successful `generate_diagnostic()` runs: `{summary['diagnostic_success']}/{summary['total_cases']}`",
        "",
        "## Per-source Span Coverage",
        "",
        "| Source | Cases | Diagnostic success | Covered | Not covered | Unknown |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for source in ("stackoverflow", "github_issues", "kernel_selftests"):
        source_summary = summary["by_source"].get(source, {})
        coverage = source_summary.get("coverage", {})
        lines.append(
            "| "
            f"`{normalize_source(source)}` | "
            f"{source_summary.get('cases', 0)} | "
            f"{source_summary.get('diagnostic_success', 0)} | "
            f"{coverage.get('yes', 0)} | "
            f"{coverage.get('no', 0)} | "
            f"{coverage.get('unknown', 0)} |"
        )

    lines.extend(
        [
            "",
            "## Rejected Span vs Verifier Error",
            "",
            "| Source | Semantic match | Total with expected message | Rate |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for source in ("stackoverflow", "github_issues", "kernel_selftests"):
        source_summary = summary["by_source"].get(source, {})
        yes_count = source_summary.get("rejected_match_yes", 0)
        total = source_summary.get("rejected_match_total", 0)
        lines.append(
            f"| `{normalize_source(source)}` | {yes_count} | {total} | {percent(yes_count, total)} |"
        )

    lines.extend(
        [
            "",
            "## Taxonomy Match vs Ground Truth",
            "",
            "| Source | Taxonomy matches | Total with ground truth taxonomy | Rate |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for source in ("stackoverflow", "github_issues", "kernel_selftests"):
        source_summary = summary["by_source"].get(source, {})
        yes_count = source_summary.get("taxonomy_match_yes", 0)
        total = source_summary.get("taxonomy_match_total", 0)
        lines.append(
            f"| `{normalize_source(source)}` | {yes_count} | {total} | {percent(yes_count, total)} |"
        )

    manual_summary = summary["ground_truth_labeled"]
    lines.extend(
        [
            "",
            "## Ground-Truth-Labeled Subset",
            "",
            f"- Coverage among evaluable labeled cases: `{manual_summary['coverage_yes']}/{manual_summary['coverage_total']}` ({percent(manual_summary['coverage_yes'], manual_summary['coverage_total'])})",
            f"- Taxonomy match on labeled cases: `{manual_summary['taxonomy_match_yes']}/{manual_summary['taxonomy_match_total']}` ({percent(manual_summary['taxonomy_match_yes'], manual_summary['taxonomy_match_total'])})",
            f"- Rejected-span/error semantic match on labeled cases: `{manual_summary['rejected_match_yes']}/{manual_summary['rejected_match_total']}` ({percent(manual_summary['rejected_match_yes'], manual_summary['rejected_match_total'])})",
            "",
            "| Coverage state | Count |",
            "| --- | ---: |",
        ]
    )
    for key in ("yes", "no", "unknown"):
        lines.append(f"| `{key}` | {manual_summary['coverage'].get(key, 0)} |")

    lines.extend(
        [
            "",
            "## Synthetic Fix-pattern Distribution",
            "",
            *format_counter_table(synthetic_summary["fix_type_counts"], "fix_type"),
            "",
            "### Synthetic Pattern Summary",
            "",
            *format_counter_table(synthetic_summary["pattern_summary_counts"], "pattern_summary")[:12],
            "",
            f"- Average changed lines per synthetic case: `{synthetic_summary['avg_changed_lines']}`",
        ]
    )

    covered = summary["coverage"].get("yes", 0)
    not_covered = summary["coverage"].get("no", 0)
    unknown = summary["coverage"].get("unknown", 0)
    top_uncovered = [
        result for result in case_results if result.fix_location_covered == "no"
    ][:5]
    top_unknown = [
        result for result in case_results if result.fix_location_covered == "unknown"
    ][:5]
    top_exceptions = summary["exceptions"].most_common(5)

    lines.extend(
        [
            "",
            "## Key Findings",
            "",
            f"- Overall span coverage is `{covered}/{summary['total_cases']}` cases marked `yes`, `{not_covered}` marked `no`, and `{unknown}` marked `unknown`. The `unknown` bucket is dominated by fixes that are not source-localizable from the available artifacts, such as verifier-limit, BTF/toolchain, or kernel-upgrade remedies.",
            "- Rejected-span/error semantic agreement is strongest where the ground truth is an expected verifier message, especially kernel selftests. Coverage is stricter than error agreement because some fixes are diffuse even when the reject site is correctly identified.",
            "- Taxonomy agreement is computed only when a usable ground-truth taxonomy can be inferred or is explicitly labeled in `ground_truth.yaml`.",
            "- The synthetic corpus is heavily skewed toward `inline_hint`, `other`, and `loop_rewrite` patterns, so future span coverage work should expect many lowering-artifact and verifier-limit style fixes even when no verifier log is available yet.",
        ]
    )

    if top_uncovered:
        lines.extend(
            [
                "",
                "## Example Uncovered Cases",
                "",
                "| Case | Src | Ground-truth pattern | Basis |",
                "| --- | --- | --- | --- |",
            ]
        )
        for result in top_uncovered:
            lines.append(
                f"| `{result.case_id}` | `{normalize_source(result.source)}` | "
                f"`{result.ground_truth_fix_pattern or 'unknown'}` | `{result.fix_location_basis or 'n/a'}` |"
            )

    if top_unknown:
        lines.extend(
            [
                "",
                "## Example Unknown Cases",
                "",
                "| Case | Src | Ground-truth pattern | Localizability |",
                "| --- | --- | --- | --- |",
            ]
        )
        for result in top_unknown:
            lines.append(
                f"| `{result.case_id}` | `{normalize_source(result.source)}` | "
                f"`{result.ground_truth_fix_pattern or 'unknown'}` | `{result.ground_truth_localizability or 'unknown'}` |"
            )

    if top_exceptions:
        lines.extend(
            [
                "",
                "## Exceptions",
                "",
                "| Exception | Count |",
                "| --- | ---: |",
            ]
        )
        for exception, count in top_exceptions:
            lines.append(f"| `{exception}` | {count} |")

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
            "- Promote exact changed-line matching wherever paired buggy/fixed snippets are available; it is the strongest coverage signal and is already available for all synthetic cases.",
            "- Keep a separate `rejected span matches verifier error` metric from `fix location covered`. The former is stable on selftests, while the latter is often unknowable for verifier-limit or environment-only fixes.",
            "- For future data collection, preserve explicit fixed snippets for Stack Overflow and GitHub cases. Many current `unknown` outcomes are caused by good fix descriptions without a line-level before/after artifact.",
            "- For lowering-artifact cases, add provenance from caller/callee or subprogram identity into the diagnostic JSON. That would convert many current `partial` or `unknown` inline-fix cases into direct span matches.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    ground_truth_labels = load_ground_truth_labels(args.ground_truth_path)

    case_results: list[CaseEvaluation] = []
    for source, case_dir in LOG_CASE_DIRS:
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            case_data = read_yaml(path)
            verifier_log = extract_verifier_log(case_data)
            if not verifier_log:
                continue
            case_results.append(evaluate_logged_case(source, path, ground_truth_labels))

    synthetic_results = [
        evaluate_synthetic_case(path)
        for path in sorted(SYNTHETIC_DIR.glob("*.yaml"))
        if path.name != "index.yaml"
    ]

    summary = summarize_case_results(case_results)
    synthetic_summary = summarize_synthetic_results(synthetic_results)

    payload = {
        "generated_at": now_iso(),
        "summary": summary,
        "synthetic_summary": {
            "total_cases": synthetic_summary["total_cases"],
            "fix_type_counts": dict(synthetic_summary["fix_type_counts"]),
            "taxonomy_counts": dict(synthetic_summary["taxonomy_counts"]),
            "pattern_summary_counts": dict(synthetic_summary["pattern_summary_counts"]),
            "avg_changed_lines": synthetic_summary["avg_changed_lines"],
        },
        "case_results": [asdict(result) for result in case_results],
        "synthetic_results": [asdict(result) for result in synthetic_results],
    }

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    args.report_path.write_text(
        build_report(case_results, synthetic_results, summary, synthetic_summary),
        encoding="utf-8",
    )
    print(f"Wrote {args.results_path}")
    print(f"Wrote {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
