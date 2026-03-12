from __future__ import annotations

from interface.extractor.proof_analysis import ProofEvent
from interface.extractor.source_correlator import correlate_to_source
from interface.extractor.trace_parser import ParsedTrace, RegisterState, TracedInstruction


def _instruction(
    insn_idx: int,
    bytecode: str,
    source_line: str | None,
    *,
    is_error: bool = False,
    error_text: str | None = None,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=insn_idx,
        bytecode=bytecode,
        source_line=source_line,
        pre_state={},
        post_state={},
        backtrack=None,
        is_error=is_error,
        error_text=error_text,
    )


def _parsed_trace(instructions: list[TracedInstruction]) -> ParsedTrace:
    return ParsedTrace(
        instructions=instructions,
        critical_transitions=[],
        causal_chain=None,
        backtrack_chains=[],
        error_line=None,
        total_instructions=len(instructions),
        has_btf_annotations=any(instruction.source_line for instruction in instructions),
        has_backtracking=False,
    )


def _event(insn_idx: int, event_type: str, source_line: str | None = None) -> ProofEvent:
    return ProofEvent(
        insn_idx=insn_idx,
        event_type=event_type,
        register='R0',
        state_before=None,
        state_after=None,
        source_line=source_line,
        description=event_type,
    )


def test_correlate_to_source_extracts_btf_file_and_line() -> None:
    parsed_trace = _parsed_trace(
        [
            _instruction(
                19,
                'r0 = *(u8 *)(r0 + 0)',
                '*data2 = 3; @ dynptr_fail.c:391',
                is_error=True,
                error_text='invalid mem access',
            )
        ]
    )

    spans = correlate_to_source(parsed_trace, [_event(19, 'rejected')])

    assert len(spans) == 1
    assert spans[0].file == 'dynptr_fail.c'
    assert spans[0].line == 391
    assert spans[0].source_text == '*data2 = 3;'


def test_correlate_to_source_preserves_multiple_roles_on_same_source_line() -> None:
    parsed_trace = _parsed_trace(
        [
            _instruction(
                12,
                'r0 |= r6',
                'volatile int ext_len = __bpf_htons(ext->len); @ stackoverflow.c:22',
            )
        ]
    )

    spans = correlate_to_source(
        parsed_trace,
        [
            _event(12, 'established'),
            _event(12, 'lost'),
            _event(12, 'rejected'),
        ],
    )

    assert [span.role for span in spans] == [
        'proof_established',
        'proof_lost',
        'rejected',
    ]
    assert all(span.line == 22 for span in spans)


def test_correlate_to_source_prunes_propagated_spans_first() -> None:
    instructions = [
        _instruction(1, 'r1 = r1', 'line1; @ test.c:1'),
        _instruction(2, 'r2 = r2', 'line2; @ test.c:2'),
        _instruction(3, 'r3 = r3', 'line3; @ test.c:3'),
        _instruction(4, 'r4 = r4', 'line4; @ test.c:4'),
        _instruction(5, 'r5 = r5', 'line5; @ test.c:5'),
        _instruction(6, 'r6 = r6', 'line6; @ test.c:6'),
        _instruction(7, 'r7 = r7', 'line7; @ test.c:7', is_error=True, error_text='reject'),
    ]
    parsed_trace = _parsed_trace(instructions)

    spans = correlate_to_source(
        parsed_trace,
        [
            _event(1, 'established'),
            _event(2, 'propagated'),
            _event(3, 'propagated'),
            _event(4, 'propagated'),
            _event(5, 'propagated'),
            _event(6, 'lost'),
            _event(7, 'rejected'),
        ],
    )

    assert len(spans) == 5
    assert any(span.role == 'proof_established' for span in spans)
    assert any(span.role == 'proof_lost' for span in spans)
    assert any(span.role == 'rejected' for span in spans)
    assert sum(1 for span in spans if span.role == 'proof_propagated') == 2
