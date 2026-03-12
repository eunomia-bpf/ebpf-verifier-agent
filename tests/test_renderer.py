from __future__ import annotations

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.rust_diagnostic import generate_diagnostic


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


def _strip_btf_annotations(verifier_log: str) -> str:
    return "\n".join(
        line for line in verifier_log.splitlines() if not line.lstrip().startswith(";")
    )


def test_generate_rust_style_lowering_artifact_with_btf_and_backtracking() -> None:
    output = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )

    assert "error[OBLIGE-E005]" in output.text
    assert "lowering_artifact" in output.text
    assert "proof lost: OR operation destroys bounds" in output.text
    assert "__bpf_htons(ext->len)" in output.text
    assert output.json_data["proof_status"] == "established_then_lost"
    assert output.json_data["obligation"]["type"] == "packet_access"
    assert any(
        span["role"] == "proof_lost"
        and span["insn_idx"] == 22
        and span["reason"] == "OR operation destroys bounds"
        for span in output.json_data["spans"]
    )
    assert any(
        span["role"] == "rejected"
        and "ext_len" in span["source_text"]
        for span in output.json_data["spans"]
    )


def test_generate_rust_style_source_bug_with_btf() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "case_study/cases/kernel_selftests.pre_unique_ids_20260311T0903/"
            "kernel-selftest-dynptr-fail-data-slice-missing-null-check2.yaml"
        )
    )

    assert "error[OBLIGE-E002]" in output.text
    assert "dynptr_fail.c" in output.text
    assert "*data2 = 3;" in output.text
    assert output.json_data["proof_status"] == "never_established"
    assert output.json_data["obligation"]["type"] == "null_check"
    assert any(
        span["role"] == "rejected"
        and span["source"]["file"] == "dynptr_fail.c"
        and span["source"]["line"] == 391
        for span in output.json_data["spans"]
    )


def test_generate_rust_style_reuses_btf_location_for_multi_insn_call_site() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "case_study/cases/kernel_selftests.pre_unique_ids_20260311T0903/"
            "kernel-selftest-dynptr-fail-bpf-prog.yaml"
        )
    )

    assert any(
        span["role"] == "rejected"
        and span["source"]["file"] == "dynptr_fail.c"
        and span["source"]["line"] == 1265
        and "bpf_dynptr_from_skb" in span["source_text"]
        for span in output.json_data["spans"]
    )


def test_renderer_emits_rejected_span_when_trace_has_no_instructions() -> None:
    output = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-48267671.yaml")
    )

    assert output.json_data["spans"]
    assert output.json_data["spans"][0]["role"] == "rejected"
    assert "EINVAL For BPF_PROG_LOAD" in output.json_data["spans"][0]["source_text"]


def test_renderer_synthesizes_missing_established_then_lost_roles() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "case_study/cases/kernel_selftests.pre_unique_ids_20260311T0903/"
            "kernel-selftest-crypto-basic-crypto-acquire.yaml"
        )
    )

    roles = {span["role"] for span in output.json_data["spans"]}
    assert {"proof_established", "proof_lost", "rejected"} <= roles


def test_renderer_caps_redundant_spans_at_five() -> None:
    output = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )

    assert len(output.json_data["spans"]) <= 5
    roles = {span["role"] for span in output.json_data["spans"]}
    assert {"proof_established", "proof_lost", "rejected"} <= roles


def test_renderer_json_output_structure() -> None:
    output = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )

    data = output.json_data
    assert {
        "error_id",
        "taxonomy_class",
        "proof_status",
        "spans",
        "obligation",
        "note",
        "help",
    } <= data.keys()
    assert data["spans"]

    first_span = data["spans"][0]
    assert {"role", "source", "insn_idx", "source_text", "state_change", "reason"} <= first_span.keys()
    assert {"file", "line"} <= first_span["source"].keys()


def test_renderer_falls_back_to_bytecode_without_btf_annotations() -> None:
    verifier_log = _strip_btf_annotations(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )
    output = generate_diagnostic(verifier_log)

    assert "┌─ <bytecode>" in output.text
    assert "r0 |= r6" in output.text
    assert "r5 += r0" in output.text
    assert any(span["source_text"] == "r0 |= r6" for span in output.json_data["spans"])
    assert all(
        span["source"]["file"] is None and span["source"]["line"] is None
        for span in output.json_data["spans"]
    )


def test_renderer_drops_false_satisfied_status_for_round2_zero_trace_cases() -> None:
    cases = (
        "case_study/cases/stackoverflow/stackoverflow-76994829.yaml",
        "case_study/cases/stackoverflow/stackoverflow-77713434.yaml",
        "case_study/cases/stackoverflow/stackoverflow-78591601.yaml",
    )

    for case_path in cases:
        output = generate_diagnostic(_load_verifier_log(case_path))
        assert output.json_data["proof_status"] in {"never_established", "unknown"}
        assert any(span["role"] == "rejected" for span in output.json_data["spans"])
