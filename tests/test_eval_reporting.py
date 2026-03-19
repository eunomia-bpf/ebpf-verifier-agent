from __future__ import annotations

from eval.comparison_report import (
    METHOD_ORDER,
    build_per_class_rows,
    macro_f1,
)
from eval.fix_type_eval import classify_fix_type
from eval.localization_eval import CaseLocalizationResult, summarize_subset
from eval.source_strata import case_source, real_world_case_ids, source_case_ids


def test_comparison_report_source_filters_and_macro_f1_rows() -> None:
    case_ids = [
        "kernel-selftest-demo",
        "stackoverflow-1",
        "github-demo-1",
    ]
    truth = {
        "kernel-selftest-demo": "source_bug",
        "stackoverflow-1": "lowering_artifact",
        "github-demo-1": "env_mismatch",
    }
    results = {
        case_id: {
            method: {"taxonomy": truth[case_id]}
            for method in METHOD_ORDER
        }
        for case_id in case_ids
    }

    assert case_source("kernel-selftest-demo") == "kernel_selftests"
    assert case_source("stackoverflow-1") == "stackoverflow"
    assert case_source("github-demo-1") == "github_issues"
    assert source_case_ids(case_ids, "kernel_selftests") == ["kernel-selftest-demo"]
    assert real_world_case_ids(case_ids) == ["stackoverflow-1", "github-demo-1"]

    rows = build_per_class_rows(results, truth, case_ids)
    assert rows[-len(METHOD_ORDER):] == [
        ["Macro-F1", "BPFix", "n/a", "n/a", "75.0%", "n/a", "n/a", "n/a"],
        ["Macro-F1", "Baseline", "n/a", "n/a", "75.0%", "n/a", "n/a", "n/a"],
        ["Macro-F1", "Ablation A", "n/a", "n/a", "75.0%", "n/a", "n/a", "n/a"],
        ["Macro-F1", "Ablation B", "n/a", "n/a", "75.0%", "n/a", "n/a", "n/a"],
        ["Macro-F1", "Ablation C", "n/a", "n/a", "75.0%", "n/a", "n/a", "n/a"],
    ]
    assert macro_f1({case_id: truth[case_id] for case_id in case_ids}, truth, case_ids) == 0.75


def test_localization_summary_separates_coverage_from_conditional_accuracy() -> None:
    rows = [
        CaseLocalizationResult(
            case_id="a",
            taxonomy_class="source_bug",
            distance_insns=0,
            distance_bucket="0",
            gt_root_before_reject=False,
            gt_root_after_reject=False,
            gt_root_cause_insn_idx=10,
            gt_rejected_insn_idx=10,
            bpfix_proof_lost_insn_idx=10,
            bpfix_proof_established_insn_idx=None,
            bpfix_rejected_insn_idx=10,
            bpfix_has_any_earlier_span=False,
            bpfix_has_earlier_non_rejected_span=False,
            proof_lost_exact_match=True,
            proof_lost_within_5=True,
            proof_lost_within_10=True,
            proof_lost_abs_error=0,
            rejected_exact_match=True,
            rejected_abs_error=0,
            proof_lost_span_present=True,
            proof_established_span_present=False,
            rejected_span_present=True,
        ),
        CaseLocalizationResult(
            case_id="b",
            taxonomy_class="source_bug",
            distance_insns=5,
            distance_bucket="1-5",
            gt_root_before_reject=True,
            gt_root_after_reject=False,
            gt_root_cause_insn_idx=20,
            gt_rejected_insn_idx=25,
            bpfix_proof_lost_insn_idx=None,
            bpfix_proof_established_insn_idx=19,
            bpfix_rejected_insn_idx=25,
            bpfix_has_any_earlier_span=True,
            bpfix_has_earlier_non_rejected_span=True,
            proof_lost_exact_match=False,
            proof_lost_within_5=False,
            proof_lost_within_10=False,
            proof_lost_abs_error=None,
            rejected_exact_match=True,
            rejected_abs_error=0,
            proof_lost_span_present=False,
            proof_established_span_present=True,
            rejected_span_present=True,
        ),
    ]

    summary = summarize_subset(rows)
    assert summary["coverage"]["proof_lost"] == {"count": 1, "denominator": 2, "rate": 0.5}
    assert summary["coverage"]["any_earlier_span"] == {"count": 1, "denominator": 2, "rate": 0.5}
    assert summary["accuracy_given_proof_lost"]["cases"] == 1
    assert summary["accuracy_given_proof_lost"]["exact"] == {"count": 1, "denominator": 1, "rate": 1.0}
    assert summary["end_to_end"]["exact"] == {"count": 1, "denominator": 2, "rate": 0.5}


def test_fix_type_classifier_uses_explicit_signals() -> None:
    assert classify_fix_type(
        predicted_taxonomy="source_bug",
        candidate_repair_action="ADD_NULL_CHECK",
        help_text="Add a dominating null check for arg0.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("null_check", "null-check signal")

    assert classify_fix_type(
        predicted_taxonomy="env_mismatch",
        candidate_repair_action="GATE_BY_KERNEL_CAPABILITY",
        help_text="Switch to an API that is valid for the current program type or callback context.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("env_fix", "environment-compatibility signal")

    assert classify_fix_type(
        predicted_taxonomy="source_bug",
        candidate_repair_action=None,
        help_text=None,
        note_text="Verifier reject line: processed 496185 insns (limit 1000000)",
        repair_hint=None,
        diagnostic_text=None,
    ) == ("loop_rewrite", "loop/complexity signal")

    assert classify_fix_type(
        predicted_taxonomy="source_bug",
        candidate_repair_action="ADD_BOUNDS_GUARD",
        help_text="Insert a guard using `data_end`.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("bounds_check", "explicit bounds-guard signal")

    assert classify_fix_type(
        predicted_taxonomy="source_bug",
        candidate_repair_action="ADD_BOUNDS_GUARD",
        help_text="Add explicit bounds checks around computed offsets and sizes.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("clamp", "offset/size clamp signal")

    assert classify_fix_type(
        predicted_taxonomy="lowering_artifact",
        candidate_repair_action="TIGHTEN_RANGE",
        help_text="Add masking or explicit casts.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("type_cast", "mask/cast tightening signal")

    assert classify_fix_type(
        predicted_taxonomy="source_bug",
        candidate_repair_action=None,
        help_text="Re-derive the pointer from a verified base immediately before dereference.",
        note_text=None,
        repair_hint=None,
        diagnostic_text=None,
    ) == ("reorder", "proof-restoration ordering signal")
