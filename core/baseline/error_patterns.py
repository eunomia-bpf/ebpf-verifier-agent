"""Regex patterns for the straw-man baseline diagnostic."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re

import yaml

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[2] / "taxonomy" / "error_catalog.yaml"

INSTRUCTION_RE = re.compile(r"^(?P<idx>\d+):\s+\([0-9a-f]{2}\)", flags=re.IGNORECASE)
REGISTER_STATE_RE = re.compile(r"^R\d+(?:_[a-z]+)?=", flags=re.IGNORECASE)
SUMMARY_RE = re.compile(
    r"^(processed|max_states|peak_states|mark_read|verification time|stack depth)\b",
    flags=re.IGNORECASE,
)
BACKTRACK_RE = re.compile(
    r"^(last_idx|first_idx|parent didn't have|regs=\d+ stack=|from \d+ to \d+:|mark_precise:)\b",
    flags=re.IGNORECASE,
)
COMMENT_RE = re.compile(r"^;", flags=re.IGNORECASE)
ERROR_HINT_RE = re.compile(
    r"\b("
    r"invalid|unknown|unreleased|unbounded|expected|cannot|too many|"
    r"loop is not bounded|back-edge|complexity limit|out of bounds|"
    r"pointer comparison prohibited|must be|not allowed|warning|bug"
    r")\b",
    flags=re.IGNORECASE,
)
PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^libbpf:\s+prog\s+'.*?':\s+", flags=re.IGNORECASE),
    re.compile(r"^libbpf:\s+", flags=re.IGNORECASE),
    re.compile(r"^verifier error:\s+", flags=re.IGNORECASE),
    re.compile(r"^load program:\s+", flags=re.IGNORECASE),
    re.compile(r"^permission denied:\s+", flags=re.IGNORECASE),
)


@dataclass(frozen=True)
class ErrorPattern:
    error_id: str
    failure_class: str
    title: str
    verifier_messages: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class MatchedPattern:
    pattern: ErrorPattern
    matched_regex: str


def normalize_log_line(line: str) -> str:
    """Strip wrapper prefixes so message regexes see the verifier text itself."""

    normalized = line.strip()
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    for prefix in PREFIX_PATTERNS:
        normalized = prefix.sub("", normalized)
    return normalized


def is_noise_line(line: str) -> bool:
    """Reject trace-only lines that are not standalone verifier messages."""

    normalized = normalize_log_line(line)
    if not normalized:
        return True
    return bool(
        COMMENT_RE.match(normalized)
        or INSTRUCTION_RE.match(normalized)
        or REGISTER_STATE_RE.match(normalized)
        or SUMMARY_RE.match(normalized)
        or BACKTRACK_RE.match(normalized)
    )


def looks_like_error_message(line: str) -> bool:
    normalized = normalize_log_line(line)
    if is_noise_line(normalized):
        return False
    return bool(ERROR_HINT_RE.search(normalized))


@lru_cache(maxsize=4)
def load_error_patterns(catalog_path: str | None = None) -> tuple[ErrorPattern, ...]:
    path = Path(catalog_path) if catalog_path else DEFAULT_CATALOG_PATH
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    patterns: list[ErrorPattern] = []
    for entry in payload.get("error_types", []):
        patterns.append(
            ErrorPattern(
                error_id=entry["error_id"],
                failure_class=entry["taxonomy_class"],
                title=entry["title"],
                verifier_messages=tuple(
                    re.compile(message, flags=re.IGNORECASE)
                    for message in entry.get("verifier_messages", [])
                ),
            )
        )
    return tuple(patterns)


def match_error_pattern(
    message: str,
    *,
    catalog_path: str | None = None,
) -> MatchedPattern | None:
    normalized = normalize_log_line(message)
    for pattern in load_error_patterns(catalog_path):
        for regex in pattern.verifier_messages:
            if regex.search(normalized):
                return MatchedPattern(pattern=pattern, matched_regex=regex.pattern)
    return None


def extract_final_error_message(
    verifier_log: str,
    *,
    catalog_path: str | None = None,
) -> tuple[str, int | None]:
    """Return the last verifier-style error line and nearby rejected insn index."""

    lines = [line.rstrip() for line in verifier_log.splitlines() if line.strip()]
    fallback_line = ""
    fallback_idx: int | None = None

    for idx in range(len(lines) - 1, -1, -1):
        normalized = normalize_log_line(lines[idx])
        if not normalized or is_noise_line(normalized):
            continue
        if match_error_pattern(normalized, catalog_path=catalog_path) is not None:
            return normalized, find_nearest_instruction_index(lines, idx)
        if fallback_idx is None and looks_like_error_message(normalized):
            fallback_line = normalized
            fallback_idx = idx

    if fallback_idx is not None:
        return fallback_line, find_nearest_instruction_index(lines, fallback_idx)

    for idx in range(len(lines) - 1, -1, -1):
        normalized = normalize_log_line(lines[idx])
        if normalized and not is_noise_line(normalized):
            return normalized, find_nearest_instruction_index(lines, idx)

    return "", None


def find_nearest_instruction_index(lines: list[str], start_idx: int) -> int | None:
    for idx in range(start_idx, -1, -1):
        match = INSTRUCTION_RE.match(normalize_log_line(lines[idx]))
        if match is not None:
            return int(match.group("idx"))
    return None

