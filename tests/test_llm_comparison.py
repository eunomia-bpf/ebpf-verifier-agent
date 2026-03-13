from __future__ import annotations

from collections import Counter

import yaml

from eval.llm_comparison import (
    DEFAULT_MANUAL_LABELS_PATH,
    DEFAULT_TARGETS,
    DEFAULT_VERBOSE_AUDIT_PATH,
    REPO_ROOT,
    build_case_record,
    condition_prompt,
    extract_buggy_code,
    extract_verifier_log,
    load_manual_labels,
    load_verbose_audit_ranks,
    select_cases,
)
from interface.extractor.log_parser import VerifierLogParser


def _load_case(relative_path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def test_load_manual_labels_parses_expected_fields() -> None:
    labels = load_manual_labels(DEFAULT_MANUAL_LABELS_PATH)

    assert len(labels) == 30
    assert labels["stackoverflow-70750259"].taxonomy_class == "lowering_artifact"
    assert "non-negative/upper-bound clamp" in labels["stackoverflow-70750259"].ground_truth_fix
    assert labels["kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda"].taxonomy_class == "verifier_limit"


def test_extract_verifier_log_and_buggy_code_handle_yaml_shape_variants() -> None:
    so_case = _load_case("case_study/cases/stackoverflow/stackoverflow-77205912.yaml")
    ks_case = _load_case(
        "case_study/cases/kernel_selftests/"
        "kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-"
        "tp-btf-task-newtask-c8a92e39.yaml"
    )

    so_log = extract_verifier_log(so_case)
    ks_log = extract_verifier_log(ks_case)
    so_code, so_has_code = extract_buggy_code(so_case)
    ks_code, ks_has_code = extract_buggy_code(ks_case)

    assert "R1=ctx" in so_log
    assert "Possibly NULL pointer passed to helper arg2" in ks_log
    assert so_has_code is True
    assert "int tc_egress" in so_code
    assert ks_has_code is True
    assert "tp_btf/task_newtask" in ks_code


def test_build_case_record_normalizes_stackoverflow_and_selftest_cases() -> None:
    labels = load_manual_labels(DEFAULT_MANUAL_LABELS_PATH)
    audit_ranks = load_verbose_audit_ranks(DEFAULT_VERBOSE_AUDIT_PATH)
    parser = VerifierLogParser()

    so_path = REPO_ROOT / "case_study/cases/stackoverflow/stackoverflow-70750259.yaml"
    ks_path = (
        REPO_ROOT
        / "case_study/cases/kernel_selftests/"
        / "kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda.yaml"
    )

    so_record = build_case_record(
        path=so_path,
        manual_label=labels["stackoverflow-70750259"],
        verbose_audit_rank=audit_ranks["stackoverflow-70750259"],
        parser=parser,
    )
    ks_record = build_case_record(
        path=ks_path,
        manual_label=labels["kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda"],
        verbose_audit_rank=audit_ranks.get("kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda"),
        parser=parser,
    )

    assert so_record.source_bucket == "SO"
    assert so_record.log_lines == 109
    assert so_record.has_usable_code is True
    assert so_record.structured_analysis["error_line"] == (
        "math between pkt pointer and register with unbounded min value is not allowed"
    )

    assert ks_record.source_bucket == "KS"
    assert ks_record.log_lines > 400
    assert ks_record.parsed_log["error_line"]
    assert ks_record.ground_truth_fix_source == "manual_label_doc"


def test_default_stratified_selection_matches_expected_distribution() -> None:
    labels = load_manual_labels(DEFAULT_MANUAL_LABELS_PATH)
    audit_ranks = load_verbose_audit_ranks(DEFAULT_VERBOSE_AUDIT_PATH)
    parser = VerifierLogParser()

    case_records = []
    for case_id, manual_label in labels.items():
        path = next((REPO_ROOT / "case_study/cases").rglob(f"{case_id}.yaml"))
        case_records.append(
            build_case_record(
                path=path,
                manual_label=manual_label,
                verbose_audit_rank=audit_ranks.get(case_id),
                parser=parser,
            )
        )

    selected, summary = select_cases(
        case_records=case_records,
        targets=DEFAULT_TARGETS,
        allow_missing_source=False,
    )

    assert len(selected) == 22
    assert summary["shortfalls"] == {}
    assert Counter(case.taxonomy_class for case in selected) == Counter(DEFAULT_TARGETS)
    selected_ids = {case.case_id for case in selected}
    assert "github-cilium-cilium-41412" not in selected_ids
    assert "github-cilium-cilium-35182" not in selected_ids


def test_condition_c_prompt_uses_structured_trace_fields() -> None:
    labels = load_manual_labels(DEFAULT_MANUAL_LABELS_PATH)
    audit_ranks = load_verbose_audit_ranks(DEFAULT_VERBOSE_AUDIT_PATH)
    parser = VerifierLogParser()
    path = REPO_ROOT / "case_study/cases/stackoverflow/stackoverflow-70750259.yaml"
    record = build_case_record(
        path=path,
        manual_label=labels["stackoverflow-70750259"],
        verbose_audit_rank=audit_ranks["stackoverflow-70750259"],
        parser=parser,
    )

    prompt = condition_prompt(record, "structured_trace_analysis")

    assert "Critical state transition:" in prompt
    assert "Causal chain:" in prompt
    assert "Error classification:" in prompt
    assert '"taxonomy_class": "source_bug|lowering_artifact|verifier_limit|env_mismatch|verifier_bug"' in prompt
