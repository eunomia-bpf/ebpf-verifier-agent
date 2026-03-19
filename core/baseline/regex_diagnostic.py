"""Regex-only baseline diagnostic for verifier logs."""

from __future__ import annotations

from interface.extractor.renderer import DIAGNOSTIC_VERSION, DiagnosticOutput

from .error_patterns import extract_final_error_message, match_error_pattern
from .taxonomy_rules import classify_failure_class

UNKNOWN_ERROR_ID = "BPFIX-UNKNOWN"
BASELINE_NOTE = "Regex baseline matched the final verifier error message only."


def generate_baseline_diagnostic(
    verifier_log: str,
    catalog_path: str | None = None,
) -> DiagnosticOutput:
    """Emit a schema-compatible diagnostic without trace analysis."""

    error_line, instruction_index = extract_final_error_message(
        verifier_log,
        catalog_path=catalog_path,
    )
    matched_pattern = match_error_pattern(error_line, catalog_path=catalog_path)

    error_id = matched_pattern.pattern.error_id if matched_pattern is not None else UNKNOWN_ERROR_ID
    failure_class = classify_failure_class(error_line, matched_pattern)
    message = matched_pattern.pattern.title if matched_pattern is not None else (
        error_line or "Verifier rejection"
    )
    span_index = instruction_index if instruction_index is not None else 0
    display_line = span_index + 1
    snippet = error_line or message

    json_data: dict[str, object] = {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "error_id": error_id,
        "failure_class": failure_class,
        "message": message,
        "source_span": {
            "path": "<bytecode>",
            "line_start": display_line,
            "line_end": display_line,
            "snippet": snippet,
        },
        "missing_obligation": snippet,
        "evidence": ([{"kind": "verifier_log", "detail": snippet}] if snippet else []),
        "candidate_repairs": [],
        "metadata": {
            "engine": "regex_baseline",
            "proof_status": "unknown",
            "note": BASELINE_NOTE,
            "proof_spans": [
                {
                    "role": "rejected",
                    "path": "<bytecode>",
                    "line": display_line,
                    "source_text": snippet,
                    "insn_range": [span_index, span_index],
                    "register": None,
                    "state_change": None,
                    "reason": "matched from final verifier error message",
                }
            ],
        },
    }

    if instruction_index is not None:
        json_data["verifier_site"] = {"instruction_index": instruction_index}
    if snippet:
        json_data["raw_log_excerpt"] = snippet
    if matched_pattern is not None:
        metadata = json_data["metadata"]
        assert isinstance(metadata, dict)
        metadata["matched_regex"] = matched_pattern.matched_regex

    text = "\n".join(
        (
            f"error[{error_id}]: {failure_class} — {message}",
            f"  = note: {BASELINE_NOTE}",
        )
    )
    return DiagnosticOutput(text=text, json_data=json_data)

