from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
import yaml

from core.baseline.error_patterns import match_error_pattern
from core.baseline.regex_diagnostic import generate_baseline_diagnostic
from interface.extractor.rust_diagnostic import generate_diagnostic

ROOT = Path(__file__).resolve().parents[1]


def _load_verifier_log(relative_path: str) -> str:
    payload = yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))
    verifier_log = payload["verifier_log"]
    if isinstance(verifier_log, str):
        return verifier_log
    combined = verifier_log.get("combined")
    if isinstance(combined, str):
        return combined
    blocks = verifier_log.get("blocks") or []
    return "\n\n".join(block for block in blocks if isinstance(block, str))


def test_baseline_produces_valid_output_on_real_log() -> None:
    log = _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")

    output = generate_baseline_diagnostic(log)

    assert output.json_data["error_id"] == "BPFIX-E005"
    assert output.json_data["failure_class"] == "lowering_artifact"
    assert output.json_data["metadata"]["proof_status"] == "unknown"
    assert len(output.json_data["metadata"]["proof_spans"]) == 1
    assert output.json_data["metadata"]["proof_spans"][0]["role"] == "rejected"
    assert "unbounded min value" in output.json_data["raw_log_excerpt"]


@pytest.mark.parametrize(
    ("message", "expected_id", "expected_class"),
    [
        (
            "math between pkt pointer and register with unbounded min value is not allowed",
            "BPFIX-E005",
            "lowering_artifact",
        ),
        (
            "Unreleased reference id=3 alloc_insn=10",
            "BPFIX-E004",
            "source_bug",
        ),
        (
            "loop is not bounded",
            "BPFIX-E008",
            "verifier_limit",
        ),
        (
            "unknown func bpf_get_current_pid_tgid#14",
            "BPFIX-E009",
            "env_mismatch",
        ),
    ],
)
def test_known_error_patterns_are_matched(
    message: str,
    expected_id: str,
    expected_class: str,
) -> None:
    matched = match_error_pattern(message)
    output = generate_baseline_diagnostic(message)

    assert matched is not None
    assert matched.pattern.error_id == expected_id
    assert output.json_data["error_id"] == expected_id
    assert output.json_data["failure_class"] == expected_class


def test_baseline_output_matches_bpfix_schema() -> None:
    schema = json.loads((ROOT / "interface" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    log = _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")

    baseline_output = generate_baseline_diagnostic(log)
    bpfix_output = generate_diagnostic(log)

    Draft202012Validator(schema).validate(baseline_output.json_data)
    assert baseline_output.json_data["source_span"].keys() == bpfix_output.json_data["source_span"].keys()
    assert "proof_status" in baseline_output.json_data["metadata"]
    assert "proof_spans" in baseline_output.json_data["metadata"]
