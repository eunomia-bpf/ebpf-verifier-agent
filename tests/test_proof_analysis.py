from __future__ import annotations

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.proof_analysis import (
    ProofObligation,
    analyze_proof_lifecycle,
    infer_obligation,
)
from interface.extractor.trace_parser import extract_backtrack_chains, parse_trace


def _load_case(relative_path: str) -> dict:
    path = ROOT / relative_path
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _block(case_path: str, index: int) -> str:
    payload = _load_case(case_path)
    return payload["verifier_log"]["blocks"][index]


def test_extract_backtrack_chains_from_real_packet_math_log() -> None:
    chains = extract_backtrack_chains(
        _block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0)
    )

    assert len(chains) == 1
    chain = chains[0]
    assert chain.error_insn == 24
    assert chain.first_insn == 12
    assert chain.regs_mask == "1"
    assert chain.stack_mask == "0"
    assert [(link.insn_idx, link.regs, link.stack) for link in chain.links] == [
        (23, "1", "0"),
        (22, "1", "0"),
        (21, "41", "0"),
        (20, "41", "0"),
        (19, "40", "0"),
    ]
    assert chain.links[1].bytecode == "(4f) r0 |= r6"


def test_infer_packet_access_obligation_from_pkt_pointer_math_error() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))

    obligation = infer_obligation(
        parsed.error_line or "",
        "R0",
        parsed.instructions[-1],
    )

    assert obligation is not None
    assert obligation.obligation_type == "packet_access"
    assert obligation.register == "R5"
    assert "scalar_offset is bounded" in obligation.required_condition


def test_analyze_proof_lifecycle_finds_loss_at_or_instruction() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))
    obligation = infer_obligation(
        parsed.error_line or "",
        "R0",
        parsed.instructions[-1],
    )

    assert obligation is not None
    lifecycle = analyze_proof_lifecycle(
        parsed_trace=parsed,
        obligation=obligation,
        backtrack_chains=parsed.backtrack_chains,
        error_insn=parsed.instructions[-1].insn_idx,
    )

    assert lifecycle.status == "established_then_lost"
    assert lifecycle.loss_site is not None
    assert lifecycle.loss_site.insn_idx == 22
    assert lifecycle.loss_site.register == "R0"
    assert any(
        event.insn_idx == 20
        and event.event_type == "established"
        and event.register == "R0"
        for event in lifecycle.events
    )
    assert any(
        event.insn_idx == 24 and event.event_type == "rejected"
        for event in lifecycle.events
    )


def test_analyze_proof_lifecycle_zero_trace_direct_rejection_is_never_established() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-76994829.yaml", 0))
    obligation = infer_obligation(parsed.error_line or "", "R5", None)

    assert obligation is not None
    lifecycle = analyze_proof_lifecycle(
        parsed_trace=parsed,
        obligation=obligation,
        backtrack_chains=parsed.backtrack_chains,
        error_insn=None,
    )

    assert lifecycle.status == "never_established"
    assert lifecycle.events == []


def test_analyze_proof_lifecycle_zero_trace_loader_failure_is_unknown() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-69192685.yaml", 0))
    obligation = ProofObligation(
        obligation_type="helper_arg",
        register="R1",
        required_condition="register type matches the helper argument contract",
        description="Synthetic obligation for loader-only failure coverage.",
    )

    lifecycle = analyze_proof_lifecycle(
        parsed_trace=parsed,
        obligation=obligation,
        backtrack_chains=parsed.backtrack_chains,
        error_insn=None,
    )

    assert lifecycle.status == "unknown"
    assert lifecycle.events == []
