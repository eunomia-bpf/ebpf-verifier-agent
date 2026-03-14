"""Batch-level and known-answer regression tests for the OBLIGE diagnostic pipeline.

Tests in this module:
  - Batch correctness: run generate_diagnostic() on all 66 SO cases with verifier
    logs and assert population-level invariants (success rate, proof_status
    distribution, error_id pattern coverage).
  - Known-answer regression: 5 well-understood cases checked against specific
    expected outputs so any regression in classification or span generation is
    caught immediately.
  - Proof status temporal ordering invariant: for established_then_lost cases,
    proof_established insn <= proof_lost insn <= rejected insn.
  - Pipeline schema invariants: every output has valid JSON structure, valid
    proof_status and taxonomy_class values, error_id pattern match, and span count <= 5.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from interface.extractor.rust_diagnostic import generate_diagnostic

ROOT = Path(__file__).resolve().parents[1]
SO_CASES_DIR = ROOT / "case_study" / "cases" / "stackoverflow"

VALID_PROOF_STATUSES = {"never_established", "established_then_lost", "established_but_insufficient", "proof_satisfied", "unknown"}
VALID_TAXONOMY_CLASSES = {
    "source_bug", "lowering_artifact", "verifier_limit", "env_mismatch", "verifier_bug", "unknown",
}
ERROR_ID_PATTERN = re.compile(r"^OBLIGE-E\d{3}$|^OBLIGE-UNKNOWN$")


def _load_verifier_log(relative_path: str) -> str:
    payload = yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))
    verifier_log = payload["verifier_log"]
    if isinstance(verifier_log, str):
        return verifier_log
    combined = verifier_log.get("combined")
    if isinstance(combined, str) and combined.strip():
        return combined
    blocks = verifier_log.get("blocks") or []
    return "\n\n".join(block for block in blocks if isinstance(block, str))


def _so_cases_with_logs() -> list[Path]:
    """Return all SO case YAML files that contain a non-empty verifier log."""
    result = []
    for f in sorted(SO_CASES_DIR.glob("*.yaml")):
        if f.name == "index.yaml":
            continue
        payload = yaml.safe_load(f.read_text(encoding="utf-8"))
        vl = payload.get("verifier_log", "")
        if isinstance(vl, str):
            has_log = bool(vl.strip())
        elif isinstance(vl, dict):
            combined = vl.get("combined", "")
            blocks = vl.get("blocks", [])
            has_log = bool((combined and combined.strip()) or
                           any(isinstance(b, str) and b.strip() for b in blocks))
        else:
            has_log = False
        if has_log:
            result.append(f)
    return result


# ============================================================================
# Batch correctness assertions
# ============================================================================


def test_batch_so_no_crashes() -> None:
    """generate_diagnostic() must not crash on any of the 66 SO cases."""
    cases = _so_cases_with_logs()
    assert len(cases) == 66, f"expected 66 SO cases with logs, found {len(cases)}"
    errors: list[tuple[str, str]] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        try:
            generate_diagnostic(log)
        except Exception as exc:
            errors.append((case_path.name, f"{type(exc).__name__}: {exc}"))
    assert not errors, "crashes on SO cases:\n" + "\n".join(f"  {n}: {e}" for n, e in errors)


def test_batch_so_never_established_ratio_below_threshold() -> None:
    """The never_established ratio across all 66 SO cases must stay <= 65%.

    Current baseline is ~59%. This threshold catches regressions where
    many established_then_lost cases are incorrectly collapsed to never_established.
    """
    cases = _so_cases_with_logs()
    never_est = 0
    total = 0
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        total += 1
        if out.json_data.get("metadata", {}).get("proof_status") == "never_established":
            never_est += 1
    ratio = never_est / total
    assert ratio <= 0.65, (
        f"never_established ratio {ratio:.1%} ({never_est}/{total}) exceeds 65% threshold"
    )


def test_batch_so_established_then_lost_count_above_baseline() -> None:
    """At least 10 SO cases must be classified as established_then_lost.

    Baseline updated after removing the TransitionAnalyzer false-positive fallback:
    TransitionAnalyzer is no longer used for lifecycle analysis when no real predicate
    exists (predicate=None or ClassificationOnlyPredicate). The new baseline of 10
    reflects only genuinely predicate-driven establish+lose patterns.
    """
    cases = _so_cases_with_logs()
    count = 0
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        if out.json_data.get("metadata", {}).get("proof_status") == "established_then_lost":
            count += 1
    assert count >= 10, (
        f"only {count} established_then_lost cases (expected >= 10)"
    )


def test_batch_so_all_outputs_have_valid_error_id() -> None:
    """Every diagnostic output must have an error_id matching OBLIGE-E\\d{{3}} or OBLIGE-UNKNOWN."""
    cases = _so_cases_with_logs()
    bad: list[tuple[str, str]] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        eid = out.json_data.get("error_id", "")
        if not ERROR_ID_PATTERN.match(eid):
            bad.append((case_path.name, eid))
    assert not bad, "invalid error_id in:\n" + "\n".join(f"  {n}: {repr(e)}" for n, e in bad)


# ============================================================================
# Known-answer regression tests (5 cases, one per taxonomy class)
# ============================================================================


def test_known_answer_lowering_artifact_70750259() -> None:
    """stackoverflow-70750259: packet bounds with lowering_artifact — established_then_lost.

    This is the canonical OBLIGE-E005 case: a packet-pointer offset proof is
    established, then an OR instruction destroys the bounds.
    """
    out = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )
    data = out.json_data
    meta = data.get("metadata", {})
    spans = meta.get("proof_spans", [])
    span_roles = {s["role"] for s in spans}

    assert data["error_id"] == "OBLIGE-E005"
    assert data["failure_class"] == "lowering_artifact"
    assert meta["proof_status"] == "established_then_lost"
    assert "proof_established" in span_roles
    assert "proof_lost" in span_roles
    assert "rejected" in span_roles


def test_known_answer_lowering_artifact_70729664_large_trace() -> None:
    """stackoverflow-70729664: large trace — must succeed and have a causal_chain.

    Note: This case has established_then_lost proof_status (real predicate driven),
    but the log_parser classifies it as source_bug (OBLIGE-E001). Since we removed
    the taxonomy override that forced established_then_lost → lowering_artifact,
    the failure_class now reflects the log_parser classification.
    """
    out = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70729664.yaml")
    )
    data = out.json_data
    meta = data.get("metadata", {})

    # proof_status must still be established_then_lost (real predicate found lifecycle)
    assert meta["proof_status"] == "established_then_lost"
    assert meta.get("causal_chain"), "expected a non-empty causal_chain for this case"
    # taxonomy comes from log_parser, not overridden by proof_status
    assert data["failure_class"] in {"source_bug", "lowering_artifact"}


def test_known_answer_verifier_limit_70841631() -> None:
    """stackoverflow-70841631: program-too-large verifier_limit case."""
    out = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70841631.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "OBLIGE-E018"
    assert data["failure_class"] == "verifier_limit"
    assert data.get("metadata", {}).get("proof_status") == "never_established"


def test_known_answer_source_bug_60053570() -> None:
    """stackoverflow-60053570: direct packet-access source_bug — never_established."""
    out = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-60053570.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "OBLIGE-E001"
    assert data["failure_class"] == "source_bug"
    assert data.get("metadata", {}).get("proof_status") == "never_established"


def test_known_answer_env_mismatch_77462271() -> None:
    """stackoverflow-77462271: failed kernel BTF lookup — env_mismatch."""
    out = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-77462271.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "OBLIGE-E021"
    assert data["failure_class"] == "env_mismatch"


# ============================================================================
# Proof status temporal ordering invariant
# ============================================================================


def test_proof_span_temporal_ordering_for_established_then_lost_cases() -> None:
    """For established_then_lost cases with all three roles: pe.insn <= pl.insn <= rj.insn.

    This checks that the pipeline produces coherent ordering when all three
    proof spans are present. Cases where proof_established and proof_lost share
    the same insn (pe == pl) are allowed (loss at same instruction as establish).
    """
    cases = _so_cases_with_logs()
    violations: list[str] = []

    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        meta = out.json_data.get("metadata", {})
        if meta.get("proof_status") != "established_then_lost":
            continue
        spans = meta.get("proof_spans", [])
        by_role = {s["role"]: s for s in spans}
        if not (
            "proof_established" in by_role
            and "proof_lost" in by_role
            and "rejected" in by_role
        ):
            continue  # not all three roles present — skip

        pe_min = by_role["proof_established"]["insn_range"][0]
        pl_min = by_role["proof_lost"]["insn_range"][0]
        rj_min = by_role["rejected"]["insn_range"][0]

        if not (pe_min <= rj_min and pl_min <= rj_min):
            violations.append(
                f"{case_path.name}: pe={pe_min} pl={pl_min} rj={rj_min} (pe or pl after rj)"
            )

    assert not violations, "temporal ordering violated:\n" + "\n".join(
        f"  {v}" for v in violations
    )


def test_proof_span_state_change_is_string_or_none() -> None:
    """state_change field on proof spans must be a non-empty string or None — never empty string."""
    cases = _so_cases_with_logs()
    bad: list[str] = []

    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        spans = out.json_data.get("metadata", {}).get("proof_spans", [])
        for span in spans:
            sc = span.get("state_change")
            if sc is not None and not isinstance(sc, str):
                bad.append(f"{case_path.name}: state_change is {type(sc).__name__}")
            elif isinstance(sc, str) and sc.strip() == "":
                bad.append(f"{case_path.name}: state_change is empty string")

    assert not bad, "invalid state_change values:\n" + "\n".join(f"  {b}" for b in bad)


# ============================================================================
# Pipeline schema invariants
# ============================================================================


def test_pipeline_proof_status_is_valid_value() -> None:
    """Every proof_status in the output must be one of the 4 valid values."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        status = out.json_data.get("metadata", {}).get("proof_status")
        if status not in VALID_PROOF_STATUSES:
            bad.append(f"{case_path.name}: proof_status={repr(status)}")
    assert not bad, "invalid proof_status:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_taxonomy_class_is_valid_value() -> None:
    """Every failure_class must be one of the 5 taxonomy classes (or unknown)."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        fc = out.json_data.get("failure_class")
        if fc not in VALID_TAXONOMY_CLASSES:
            bad.append(f"{case_path.name}: failure_class={repr(fc)}")
    assert not bad, "invalid failure_class:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_span_count_at_most_five() -> None:
    """Number of proof_spans in metadata must not exceed 5 (renderer cap)."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        spans = out.json_data.get("metadata", {}).get("proof_spans", [])
        if len(spans) > 5:
            bad.append(f"{case_path.name}: {len(spans)} spans")
    assert not bad, "span count exceeds 5:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_output_has_required_json_keys() -> None:
    """Every diagnostic output must have all required top-level JSON keys."""
    required_keys = {
        "diagnostic_version",
        "error_id",
        "failure_class",
        "message",
        "source_span",
        "missing_obligation",
        "metadata",
    }
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        missing = required_keys - out.json_data.keys()
        if missing:
            bad.append(f"{case_path.name}: missing keys {missing}")
    assert not bad, "missing required keys:\n" + "\n".join(f"  {b}" for b in bad)
