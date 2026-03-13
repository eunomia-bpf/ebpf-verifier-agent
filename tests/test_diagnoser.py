from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from interface.extractor.diagnoser import _classify_without_catalog, diagnose


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


def _write_empty_catalog(tmp_path: Path) -> str:
    path = tmp_path / "empty_catalog.yaml"
    path.write_text("version: 0.1.0\nerror_types: []\n", encoding="utf-8")
    return str(path)


def test_diagnose_source_bug_packet_access() -> None:
    diagnosis = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-60053570.yaml")
    )

    assert diagnosis.error_id == "OBLIGE-E001"
    assert diagnosis.taxonomy_class == "source_bug"
    assert diagnosis.symptom_insn == 49
    assert diagnosis.root_cause_insn == 49
    assert diagnosis.proof_status == "never_established"
    assert diagnosis.critical_transitions == []
    assert diagnosis.recommended_fix is not None
    assert "bounds check" in diagnosis.recommended_fix.lower()


def test_diagnose_lowering_artifact_from_proof_loss() -> None:
    diagnosis = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )

    assert diagnosis.error_id == "OBLIGE-E005"
    assert diagnosis.taxonomy_class == "lowering_artifact"
    assert diagnosis.symptom_insn == 24
    assert diagnosis.root_cause_insn is not None
    assert diagnosis.root_cause_insn < diagnosis.symptom_insn
    assert diagnosis.proof_status == "established_then_lost"
    assert diagnosis.loss_context == "arithmetic"
    assert diagnosis.critical_transitions
    assert diagnosis.recommended_fix is not None
    assert "unsigned clamp" in diagnosis.recommended_fix.lower()


def test_diagnose_verifier_limit_program_too_large() -> None:
    diagnosis = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70841631.yaml")
    )

    assert diagnosis.error_id == "OBLIGE-E018"
    assert diagnosis.taxonomy_class == "verifier_limit"
    assert diagnosis.symptom_insn == 79
    assert diagnosis.root_cause_insn == 79
    assert diagnosis.loss_context == "loop"
    assert diagnosis.recommended_fix is not None
    assert "tail calls" in diagnosis.recommended_fix.lower()


def test_processed_count_does_not_override_specific_error_reason() -> None:
    verifier_log = (
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-60053570.yaml")
        + "\nprocessed 200001 insns (limit 1000000) max_states_per_insn 4 total_states 8 peak_states 8"
    )

    diagnosis = diagnose(verifier_log)

    assert diagnosis.error_id == "OBLIGE-E001"
    assert diagnosis.taxonomy_class == "source_bug"


def test_differential_diagnosis_same_packet_symptom_different_root_cause() -> None:
    source_bug = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-60053570.yaml")
    )
    lowering_artifact = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70729664.yaml")
    )

    assert source_bug.evidence[0].startswith("Verifier symptom: invalid access to packet")
    assert lowering_artifact.evidence[0].startswith(
        "Verifier symptom: invalid access to packet"
    )

    assert source_bug.error_id == "OBLIGE-E001"
    assert lowering_artifact.error_id == "OBLIGE-E005"
    assert source_bug.taxonomy_class == "source_bug"
    assert lowering_artifact.taxonomy_class == "lowering_artifact"
    assert source_bug.proof_status == "never_established"
    assert lowering_artifact.proof_status == "established_then_lost"
    assert source_bug.root_cause_insn == source_bug.symptom_insn
    assert lowering_artifact.root_cause_insn is not None
    assert lowering_artifact.symptom_insn is not None
    assert lowering_artifact.root_cause_insn < lowering_artifact.symptom_insn


def test_diagnose_fallback_classifies_round2_uncatalogued_symptoms(tmp_path: Path) -> None:
    empty_catalog = _write_empty_catalog(tmp_path)

    ctx = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-67402772.yaml"),
        catalog_path=empty_catalog,
    )
    comparison = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-71351495.yaml"),
        catalog_path=empty_catalog,
    )
    kernel_btf = diagnose(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-77462271.yaml"),
        catalog_path=empty_catalog,
    )

    assert ctx.error_id == "OBLIGE-E023"
    assert ctx.taxonomy_class == "source_bug"
    assert comparison.error_id == "OBLIGE-E023"
    assert comparison.taxonomy_class == "source_bug"
    assert kernel_btf.error_id == "OBLIGE-E021"
    assert kernel_btf.taxonomy_class == "env_mismatch"


def test_diagnose_keeps_scalar_mem_access_as_source_bug_without_same_register_loss() -> None:
    diagnosis = diagnose(
        _load_verifier_log(
            "case_study/cases/kernel_selftests/"
            "kernel-selftest-dynptr-fail-clone-invalidate4-raw-tp-0dfbe587.yaml"
        )
    )

    assert diagnosis.error_id == "OBLIGE-E011"
    assert diagnosis.taxonomy_class == "source_bug"
    assert diagnosis.proof_status == "established_then_lost"



def test_processed_insns_do_not_override_specific_error_reason() -> None:
    classification = _classify_without_catalog(
        verifier_log="processed 200001 insns\ninvalid access to packet",
        error_candidates=["invalid access to packet"],
        error_lowered="invalid access to packet",
        lowered="processed 200001 insns\ninvalid access to packet",
        proof_status="never_established",
        relevant_transitions=[],
        loss_context=None,
    )

    assert classification == ("OBLIGE-E001", "source_bug")
