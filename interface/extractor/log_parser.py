"""Parse raw eBPF verifier logs into stable, catalog-backed diagnostic signals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ERROR_LINE_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (
        re.compile(
            r"\binvalid\b|\bunknown\b|unreleased|too many|\bwarning\b|\bbug\b|loop is not bounded|back-edge|complexity limit",
            flags=re.IGNORECASE,
        ),
        5,
    ),
    (
        re.compile(
            "|".join(
                (
                    r"expected an initialized",
                    r"expected uninitialized",
                    r"unacquired reference",
                    r"dynptr",
                    r"irq flag",
                    r"misaligned stack access",
                    r"!read_ok",
                    r"must be referenced",
                    r"trusted",
                    r"pointer type .* must point",
                    r"type=.* expected=.*",
                    r"arg#?\d+",
                    r"reference type\('unknown '\)",
                    r"invalid btf",
                    r"missing btf func_info",
                    r"only read from bpf_array is supported",
                    r"function calls are not allowed",
                    r"cannot call exception cb directly",
                    r"exception cb only supports single integer argument",
                    r"attach to unsupported member",
                    r"unbounded memory access",
                    r"bpf program is too large",
                )
            ),
            flags=re.IGNORECASE,
        ),
        4,
    ),
)
INSTRUCTION_LINE_RE = re.compile(r"^\d+: \([0-9a-f]{2}\)", flags=re.IGNORECASE)
EXACT_VERIFIER_SYMPTOM_RE = re.compile(
    "|".join(
        (
            r"invalid access to (?:packet|map value)",
            r"invalid mem access",
            r"invalid bpf_context access",
            r"offset is outside of the packet",
            r"pointer comparison prohibited",
            r"pointer arithmetic on .* prohibited",
            r"expected (?:an )?initialized irq flag as arg#0",
            r"expected uninitialized irq flag as arg#0",
            r"arg#\d+\s+arg#\d+\s+memory,\s+len pair leads to invalid memory access",
            r"unbounded memory access",
            r"the prog does not allow writes to packet data",
            r"number of funcs in func_info doesn't match(?: number of subprogs)?",
            r"failed to find kernel BTF type ID",
            r"\bInvalid name\b",
            r"pointer type .* must point",
        )
    ),
    flags=re.IGNORECASE,
)
SUMMARY_PREFIXES = (
    "processed ",
    "max_states",
    "peak_states",
    "mark_read",
    "verification time",
)


@dataclass(slots=True)
class ParsedLog:
    """Normalized verifier log information ready for later extraction stages."""

    raw_log: str
    lines: list[str]
    error_line: str
    error_id: str | None
    taxonomy_class: str | None
    source_line: int | None
    evidence: list[str] = field(default_factory=list)


class VerifierLogParser:
    """Apply the initial error catalog and a few line-oriented heuristics."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        self.catalog_path = catalog_path or (
            Path(__file__).resolve().parents[2] / "taxonomy" / "error_catalog.yaml"
        )
        self._catalog = self._load_catalog()

    def _load_catalog(self) -> list[dict[str, Any]]:
        try:
            import yaml
        except ImportError:
            return []

        with self.catalog_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        return payload.get("error_types", [])

    def parse(self, raw_log: str) -> ParsedLog:
        """Extract the likely error line, stable error ID, and supporting evidence."""

        lines = [line.rstrip() for line in raw_log.splitlines() if line.strip()]
        error_line = self._select_error_line(lines)
        error_id, taxonomy_class = self._match_catalog(lines)
        source_line = self._extract_source_line(lines)
        evidence = self._collect_evidence(lines)

        return ParsedLog(
            raw_log=raw_log,
            lines=lines,
            error_line=error_line,
            error_id=error_id,
            taxonomy_class=taxonomy_class,
            source_line=source_line,
            evidence=evidence,
        )

    def _select_error_line(self, lines: list[str]) -> str:
        best_line = ""
        best_score = -1

        for idx, line in enumerate(lines):
            normalized = line.strip()
            while normalized.startswith(":"):
                normalized = normalized[1:].lstrip()
            if not normalized:
                continue

            lowered = normalized.lower()
            score = 0
            for pattern, weight in ERROR_LINE_PATTERNS:
                if pattern.search(normalized):
                    score += weight

            if _is_specific_verifier_symptom(normalized):
                score += 7
            if INSTRUCTION_LINE_RE.match(normalized):
                score -= 4
            if normalized.startswith(";"):
                score -= 6
            if lowered.startswith(SUMMARY_PREFIXES):
                score -= 8
            if lowered.startswith("libbpf:") and any(
                _is_specific_verifier_symptom(later.strip())
                for later in lines[idx + 1 :]
                if later.strip()
            ):
                score -= 5
            if normalized.startswith(("R", "arg#")):
                score += 1

            if score >= best_score:
                best_score = score
                best_line = normalized

        if best_score > 0:
            return best_line
        return lines[-1] if lines else ""

    def _match_catalog(self, lines: list[str]) -> tuple[str | None, str | None]:
        joined = "\n".join(lines)
        for entry in self._catalog:
            for pattern in entry.get("verifier_messages", []):
                if re.search(pattern, joined, flags=re.IGNORECASE):
                    return entry["error_id"], entry["taxonomy_class"]
        return None, None

    def _extract_source_line(self, lines: list[str]) -> int | None:
        patterns = [
            re.compile(r";\s*line\s+(?P<line>\d+)"),
            re.compile(r"line\s+(?P<line>\d+):"),
        ]
        for line in lines:
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    return int(match.group("line"))
        return None

    def _collect_evidence(self, lines: list[str]) -> list[str]:
        evidence_tokens = (
            "R0",
            "R1",
            "R2",
            "stack",
            "packet",
            "helper",
            "loop",
            "reference",
            "dynptr",
            "irq",
            "btf",
            "map",
            "kptr",
            "trusted",
            "rcu",
            "arg#",
            "read_ok",
        )
        return [
            line
            for line in lines
            if any(token.lower() in line.lower() for token in evidence_tokens)
        ][:5]


def parse_log(raw_log: str, catalog_path: str | Path | None = None) -> ParsedLog:
    """Convenience wrapper matching the lightweight comparison-script API."""

    parser = VerifierLogParser(
        catalog_path=Path(catalog_path) if catalog_path is not None else None
    )
    return parser.parse(raw_log)


def _is_specific_verifier_symptom(line: str) -> bool:
    lowered = line.lower()
    if not line or line.startswith(";") or lowered.startswith(SUMMARY_PREFIXES):
        return False
    return EXACT_VERIFIER_SYMPTOM_RE.search(line) is not None
