"""Public helpers for producing structured diagnostics from raw verifier logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from interface.extractor.btf_mapper import BTFMapper
from interface.extractor.log_parser import VerifierLogParser
from interface.extractor.obligation import ObligationExtractor


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "diagnostic.json"


def load_schema(schema_path: Path | None = None) -> dict[str, Any]:
    """Load the diagnostic JSON schema for validation or downstream tooling."""

    path = schema_path or SCHEMA_PATH
    return json.loads(path.read_text(encoding="utf-8"))


def build_diagnostic(
    raw_log: str,
    *,
    case_id: str | None = None,
    source_path: str | None = None,
    kernel_release: str | None = None,
) -> dict[str, Any]:
    """Create an initial structured diagnostic record from a raw verifier log."""

    parser = VerifierLogParser()
    parsed = parser.parse(raw_log)
    mapper = BTFMapper()
    span = mapper.lookup(parsed.source_line, source_path=source_path)
    obligation = ObligationExtractor().extract(parsed)

    summary = parsed.error_line or "Verifier failure without a parsed headline"
    diagnostic = {
        "schema_version": "0.1.0",
        "case_id": case_id,
        "kernel_release": kernel_release,
        "error_id": parsed.error_id or "OBLIGE-E999",
        "taxonomy_class": parsed.taxonomy_class or "source_bug",
        "source_span": span.to_dict(),
        "expected_state": {
            "summary": "Verifier expects a proof obligation to hold at the failing instruction.",
            "predicates": [],
            "registers": [],
        },
        "observed_state": {
            "summary": summary,
            "predicates": parsed.evidence,
            "registers": [],
        },
        "missing_obligation": obligation.to_dict(),
        "verifier_excerpt": parsed.lines[-5:],
        "evidence": [
            {"kind": "verifier_log", "message": line, "raw": line}
            for line in parsed.evidence
        ],
        "confidence": 0.4 if parsed.error_id is None else 0.8,
    }
    return {key: value for key, value in diagnostic.items() if value is not None}


__all__ = ["build_diagnostic", "load_schema", "SCHEMA_PATH"]

