#!/usr/bin/env python3
"""Near-duplicate analysis for the v3 Stack Overflow and GitHub core cases."""

from __future__ import annotations

import itertools
import math
import re
import string
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[3]
CASE_ID_PATH = ROOT / "docs" / "tmp" / "labeling_case_ids.txt"
SO_DIR = ROOT / "case_study" / "cases" / "stackoverflow"
GH_DIR = ROOT / "case_study" / "cases" / "github_issues"
OUTPUT_PATH = ROOT / "docs" / "tmp" / "labeling-review" / "dedup_analysis.md"
SIMILARITY_THRESHOLD = 0.70

STOP_WORDS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "to",
    "of",
    "in",
    "on",
    "for",
    "with",
    "from",
    "by",
    "at",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "that",
    "this",
    "it",
    "as",
    "if",
    "when",
    "then",
    "than",
    "into",
    "after",
    "before",
    "can",
    "could",
    "would",
    "should",
    "do",
    "does",
    "did",
    "done",
    "how",
    "why",
    "what",
    "which",
    "using",
    "use",
    "used",
    "i",
    "my",
    "we",
    "you",
    "your",
    "our",
    "their",
    "they",
    "them",
    "he",
    "she",
    "his",
    "her",
    "its",
    "not",
    "no",
    "yes",
    "but",
    "so",
    "too",
    "very",
    "have",
    "has",
    "had",
    "will",
    "just",
    "get",
    "got",
    "trying",
    "try",
    "load",
    "program",
    "ebpf",
    "bpf",
    "verifier",
    "error",
    "failed",
    "fails",
    "issue",
    "question",
}

TEXT_TOKEN_RE = re.compile(r"[a-z_][a-z0-9_+-]{1,}")
CODE_TOKEN_RE = re.compile(r"[a-z_][a-z0-9_]*|==|!=|<=|>=|->|&&|\|\||[{}()\[\];,+\-*/%<>]")
TEXT_PUNCT_TABLE = str.maketrans({char: " " for char in string.punctuation if char not in "_+-"})

ERROR_LINE_MARKERS = (
    "invalid access",
    "outside of the packet",
    "not allowed",
    "must be",
    "last insn is not",
    "too large",
    "leak",
    "math between fp pointer",
    "invalid mem access",
    "expected=",
    "misaligned access",
    "unreleased reference",
    "type=scalar",
    "pointer arithmetic on",
    "write into map forbidden",
    "helper access to the packet",
    "cannot pass map_type",
)


@dataclass(slots=True)
class CaseData:
    case_id: str
    source: str
    title: str
    topic_text: str
    code_text: str
    error_text: str


@dataclass(slots=True)
class PairScore:
    case_a: CaseData
    case_b: CaseData
    source_similarity: float | None
    error_similarity: float
    topic_similarity: float
    overall_similarity: float


def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"0x[0-9a-f]+", " HEX ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = text.translate(TEXT_PUNCT_TABLE)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_code(text: str) -> str:
    text = text.lower()
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//.*", " ", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', " STR ", text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", " CHR ", text)
    text = re.sub(r"0x[0-9a-f]+", " HEX ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def text_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for token in TEXT_TOKEN_RE.findall(normalize_text(text)):
        if token in STOP_WORDS or len(token) <= 1:
            continue
        tokens.append(token)
    return tokens


def code_tokens(text: str) -> list[str]:
    return CODE_TOKEN_RE.findall(normalize_code(text))


def weighted_jaccard(tokens_a: list[str], tokens_b: list[str]) -> float:
    counts_a = Counter(tokens_a)
    counts_b = Counter(tokens_b)
    if not counts_a or not counts_b:
        return 0.0
    keys = set(counts_a) | set(counts_b)
    intersection = sum(min(counts_a[key], counts_b[key]) for key in keys)
    union = sum(max(counts_a[key], counts_b[key]) for key in keys)
    return intersection / union if union else 0.0


def text_similarity(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    normalized_a = normalize_text(text_a)[:4000]
    normalized_b = normalize_text(text_b)[:4000]
    seq_score = SequenceMatcher(None, normalized_a, normalized_b).ratio()
    jaccard_score = weighted_jaccard(text_tokens(normalized_a), text_tokens(normalized_b))
    return max(seq_score, jaccard_score, (seq_score + jaccard_score) / 2.0)


def code_similarity(code_a: str, code_b: str) -> float | None:
    if not code_a or not code_b:
        return None
    normalized_a = normalize_code(code_a)[:6000]
    normalized_b = normalize_code(code_b)[:6000]
    seq_score = SequenceMatcher(None, normalized_a, normalized_b).ratio()
    jaccard_score = weighted_jaccard(code_tokens(normalized_a), code_tokens(normalized_b))
    return max(seq_score, jaccard_score, (seq_score + jaccard_score) / 2.0)


def case_ids() -> tuple[list[str], list[str]]:
    case_ids = [line.strip() for line in CASE_ID_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    stackoverflow_ids = [case_id for case_id in case_ids if case_id.startswith("stackoverflow-")]
    github_ids = [case_id for case_id in case_ids if case_id.startswith("github-")]
    return stackoverflow_ids, github_ids


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_case(case_id: str) -> CaseData:
    if case_id.startswith("stackoverflow-"):
        path = SO_DIR / f"{case_id}.yaml"
    elif case_id.startswith("github-"):
        path = GH_DIR / f"{case_id}.yaml"
    else:
        raise ValueError(f"Unsupported case id: {case_id}")

    payload = read_yaml(path)
    source = str(payload.get("source") or "")
    source_snippets = payload.get("source_snippets")
    if isinstance(source_snippets, list):
        code_text = "\n\n".join(snippet for snippet in source_snippets if isinstance(snippet, str))
    elif isinstance(source_snippets, str):
        code_text = source_snippets
    else:
        code_text = ""

    if source == "stackoverflow":
        question = payload.get("question") or {}
        title = str(question.get("title") or "")
        topic_parts = [
            title,
            payload.get("question_body_text"),
        ]
    else:
        issue = payload.get("issue") or {}
        fix = payload.get("fix") or {}
        title = str(issue.get("title") or "")
        topic_parts = [
            issue.get("repository"),
            title,
            payload.get("issue_body_text"),
            fix.get("summary"),
        ]

    topic_text = " ".join(part for part in topic_parts if isinstance(part, str) and part)
    error_text = extract_error_text(payload)
    return CaseData(
        case_id=case_id,
        source=source,
        title=title,
        topic_text=topic_text,
        code_text=code_text,
        error_text=error_text,
    )


def verifier_log_text(payload: dict[str, Any]) -> str:
    verifier_log = payload.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            return "\n".join(block for block in blocks if isinstance(block, str))
    return ""


def extract_error_text(payload: dict[str, Any]) -> str:
    lines = [line.strip() for line in verifier_log_text(payload).splitlines() if line.strip()]
    selected: list[str] = []
    for line in lines:
        lower_line = line.lower()
        if "verifier output:" in lower_line:
            selected.append(line.split("Verifier output:", 1)[-1].strip())
        if any(marker in lower_line for marker in ERROR_LINE_MARKERS):
            selected.append(line)

    if not selected:
        selected = lines[-8:]

    deduped: list[str] = []
    seen: set[str] = set()
    for item in selected:
        normalized = normalize_text(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(item)
    return "\n".join(deduped[:4])


def score_pairs(cases: list[CaseData]) -> list[PairScore]:
    scores: list[PairScore] = []
    for case_a, case_b in itertools.combinations(cases, 2):
        source_score = code_similarity(case_a.code_text, case_b.code_text)
        error_score = text_similarity(case_a.error_text, case_b.error_text)
        topic_score = text_similarity(case_a.topic_text, case_b.topic_text)
        if source_score is not None:
            # For deduping user-authored posts, repeated verifier errors are supporting
            # evidence only. Topic and code overlap should dominate the decision.
            overall = (0.45 * topic_score) + (0.45 * source_score) + (0.10 * error_score)
        else:
            overall = (0.70 * topic_score) + (0.30 * error_score)
        scores.append(
            PairScore(
                case_a=case_a,
                case_b=case_b,
                source_similarity=source_score,
                error_similarity=error_score,
                topic_similarity=topic_score,
                overall_similarity=overall,
            )
        )
    return sorted(scores, key=lambda row: row.overall_similarity, reverse=True)


def format_similarity(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.3f}"


def short_error(text: str) -> str:
    if not text:
        return ""
    line = text.splitlines()[0].strip()
    return line[:160] + ("..." if len(line) > 160 else "")


def markdown_table(rows: list[list[str]]) -> list[str]:
    lines = [
        "| Pair | Source Snippets | Verifier Log | Topic | Overall |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def top_rows(scores: list[PairScore], limit: int = 10) -> list[list[str]]:
    rows: list[list[str]] = []
    for score in scores[:limit]:
        rows.append(
            [
                f"`{score.case_a.case_id}` / `{score.case_b.case_id}`",
                format_similarity(score.source_similarity),
                f"{score.error_similarity:.3f}",
                f"{score.topic_similarity:.3f}",
                f"{score.overall_similarity:.3f}",
            ]
        )
    return rows


def flagged_rows(scores: list[PairScore]) -> list[PairScore]:
    return [score for score in scores if score.overall_similarity > SIMILARITY_THRESHOLD]


def report_for_source(label: str, scores: list[PairScore]) -> list[str]:
    flagged = flagged_rows(scores)
    lines = [
        f"## {label}",
        "",
        f"- Pair count reviewed: {len(scores)}",
        f"- Near-duplicate threshold: overall similarity > {SIMILARITY_THRESHOLD:.2f}",
        f"- Flagged pairs: {len(flagged)}",
        "",
        "### Top scored pairs",
        "",
    ]
    lines.extend(markdown_table(top_rows(scores)))
    lines.extend(["", "### Flagged near-duplicates", ""])
    if not flagged:
        lines.append("No pairs crossed the 0.70 threshold.")
        lines.append("")
        return lines

    for score in flagged:
        lines.extend(
            [
                f"#### `{score.case_a.case_id}` vs `{score.case_b.case_id}`",
                "",
                f"- Source snippet similarity: {format_similarity(score.source_similarity)}",
                f"- Verifier-log similarity: {score.error_similarity:.3f}",
                f"- Topic similarity: {score.topic_similarity:.3f}",
                f"- Overall similarity: {score.overall_similarity:.3f}",
                f"- `{score.case_a.case_id}` title: {score.case_a.title}",
                f"- `{score.case_b.case_id}` title: {score.case_b.title}",
                f"- `{score.case_a.case_id}` error excerpt: {short_error(score.case_a.error_text)}",
                f"- `{score.case_b.case_id}` error excerpt: {short_error(score.case_b.error_text)}",
                "",
            ]
        )
    return lines


def build_report() -> str:
    so_ids, gh_ids = case_ids()
    so_cases = [load_case(case_id) for case_id in so_ids]
    gh_cases = [load_case(case_id) for case_id in gh_ids]
    so_scores = score_pairs(so_cases)
    gh_scores = score_pairs(gh_cases)

    lines = [
        "# v3 Core Near-Duplicate Analysis",
        "",
        "Method: lexical similarity over three signals per same-source pair.",
        "",
        "- `source_snippets`: normalized code similarity when both cases include code",
        "- `verifier_log`: similarity between extracted verifier-error lines or the final message-bearing lines",
        "- `topic`: similarity between Stack Overflow titles/bodies or GitHub issue titles/bodies",
        "- `overall`: weighted duplicate score that emphasizes user-authored content",
        "- When code is present: `0.45 * topic + 0.45 * source_snippets + 0.10 * verifier_log`",
        "- When code is absent: `0.70 * topic + 0.30 * verifier_log`",
        "- Rationale: generic verifier failures such as `invalid access to packet` recur across unrelated posts, so topic and code overlap should dominate duplicate detection",
        "",
        f"Threshold for flagging near-duplicates: overall similarity > {SIMILARITY_THRESHOLD:.2f}",
        "",
    ]
    lines.extend(report_for_source("Stack Overflow", so_scores))
    lines.extend(report_for_source("GitHub Issues", gh_scores))
    return "\n".join(lines)


def main() -> None:
    OUTPUT_PATH.write_text(build_report() + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
