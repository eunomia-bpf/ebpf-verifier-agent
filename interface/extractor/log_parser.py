"""Parse raw eBPF verifier logs into stable, catalog-backed diagnostic signals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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
        keywords = ("invalid", "unknown", "unreleased", "too many", "warning", "bug")
        for line in reversed(lines):
            if any(keyword in line.lower() for keyword in keywords):
                return line
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
        evidence_tokens = ("R0", "R1", "R2", "stack", "packet", "helper", "loop", "reference")
        return [
            line
            for line in lines
            if any(token.lower() in line.lower() for token in evidence_tokens)
        ][:5]

