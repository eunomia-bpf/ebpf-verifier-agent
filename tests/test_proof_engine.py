from __future__ import annotations

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.proof_engine import (
    CompositeObligation,
    InstructionNode,
    OBLIGATION_FAMILIES,
    ObligationSpec,
    PredicateAtom,
    TraceIR,
    TransitionWitness,
    analyze_proof,
    backward_obligation_slice,
    backward_slice,
    build_trace_ir,
    evaluate_obligation,
    find_loss_transition,
    infer_formal_obligation,
    infer_obligation,
    track_composite,
)
from interface.extractor.log_parser import parse_verifier_log
from interface.extractor.trace_parser import (
    BacktrackChain,
    BacktrackLink,
    ParsedTrace,
    RegisterState,
    TracedInstruction,
    parse_trace,
    parse_verifier_trace,
)


def _load_case(relative_path: str) -> dict:
    path = ROOT / relative_path
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _block(case_path: str, index: int) -> str:
    payload = _load_case(case_path)
    return payload["verifier_log"]["blocks"][index]


def _parsed_trace(
    instructions: list[TracedInstruction],
    error_line: str | None = None,
    backtrack_chains: list[BacktrackChain] | None = None,
) -> ParsedTrace:
    return ParsedTrace(
        instructions=instructions,
        critical_transitions=[],
        causal_chain=None,
        backtrack_chains=list(backtrack_chains or []),
        error_line=error_line,
        total_instructions=len(instructions),
        has_btf_annotations=any(instruction.source_line for instruction in instructions),
        has_backtracking=bool(backtrack_chains),
    )


def _instruction(
    insn_idx: int,
    bytecode: str,
    *,
    source_line: str | None = None,
    pre_state: dict[str, RegisterState] | None = None,
    post_state: dict[str, RegisterState] | None = None,
    is_error: bool = False,
    error_text: str | None = None,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=insn_idx,
        bytecode=bytecode,
        source_line=source_line,
        pre_state=dict(pre_state or {}),
        post_state=dict(post_state or {}),
        backtrack=None,
        is_error=is_error,
        error_text=error_text,
    )


def _node(
    insn_idx: int,
    bytecode: str,
    *,
    pre_state: dict[str, RegisterState] | None = None,
    post_state: dict[str, RegisterState] | None = None,
) -> InstructionNode:
    return InstructionNode(
        insn_idx=insn_idx,
        bytecode=bytecode,
        source_line=None,
        pre_state=dict(pre_state or {}),
        post_state=dict(post_state or {}),
        defs=[],
        uses=[],
        preds=[],
        succs=[],
    )


def _trace_ir(instructions: list[InstructionNode], backtrack_chains: list[BacktrackChain] | None = None) -> TraceIR:
    parsed = _parsed_trace(
        [
            _instruction(
                instruction.insn_idx,
                instruction.bytecode,
                pre_state=instruction.pre_state,
                post_state=instruction.post_state,
            )
            for instruction in instructions
        ],
        backtrack_chains=backtrack_chains,
    )
    return build_trace_ir(parsed)


def test_analyze_proof_real_lowering_artifact_finds_loss_at_insn_22() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))

    result = analyze_proof(
        parsed_trace=parsed,
        error_line=parsed.error_line or "",
        error_insn=24,
    )

    assert result.obligation is not None
    assert result.obligation.kind == "packet_ptr_add"
    assert result.proof_status == "established_then_lost"
    assert result.loss_site == 22
    assert result.loss_site not in {20, 21}
    assert result.transition is not None
    assert result.transition.insn_idx == 22


def test_analyze_proof_real_source_bug_stays_never_established() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70721661.yaml", 0))

    result = analyze_proof(
        parsed_trace=parsed,
        error_line=parsed.error_line or "",
        error_insn=6,
    )

    assert result.obligation is not None
    assert result.obligation.kind == "packet_access"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.transition is None


def test_simple_packet_bounds_check_case_establishes_packet_access_proof() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "if r3 > r2 goto pc+1",
                source_line="if (data + 4 > data_end)",
                pre_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", off=0, range=0),
                },
                post_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", off=0, range=4),
                },
            ),
            _instruction(
                1,
                "r0 = *(u32 *)(r3 +0)",
                source_line="x = *(__u32 *)data",
                pre_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", off=0, range=4),
                },
                post_state={
                    "R0": RegisterState(type="inv", umin=0, umax=0, smin=0, smax=0),
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", off=0, range=4),
                },
                is_error=True,
                error_text="invalid access to packet, off=0 size=4, R3(id=0,off=0,r=4)",
            ),
        ],
        error_line="invalid access to packet, off=0 size=4, R3(id=0,off=0,r=4)",
    )

    trace_ir = build_trace_ir(parsed)
    failing = next(instruction for instruction in trace_ir.instructions if instruction.insn_idx == 1)
    obligation = infer_formal_obligation(trace_ir, failing, parsed.error_line or "")

    assert obligation is not None
    assert obligation.kind == "packet_access"

    evaluations = evaluate_obligation(trace_ir, obligation)
    range_eval = next(
        evaluation
        for evaluation in evaluations
        if evaluation.insn_idx == 1
        and evaluation.phase == "pre"
        and evaluation.atom_id == "range_at_least"
    )
    assert range_eval.result == "satisfied"


def test_packet_access_range_accounts_for_fixed_pointer_offset() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "r0 = *(u8 *)(r4 -15)",
                pre_state={"R4": RegisterState(type="pkt", id=0, off=135, range=120)},
                post_state={
                    "R0": RegisterState(type="inv", umin=0, umax=0, smin=0, smax=0),
                    "R4": RegisterState(type="pkt", id=0, off=135, range=120),
                },
                is_error=True,
                error_text="invalid access to packet, off=120 size=1, R4(id=0,off=135,r=120)",
            ),
        ],
        error_line="invalid access to packet, off=120 size=1, R4(id=0,off=135,r=120)",
    )

    trace_ir = build_trace_ir(parsed)
    failing = next(instruction for instruction in trace_ir.instructions if instruction.insn_idx == 0)
    obligation = infer_formal_obligation(trace_ir, failing, parsed.error_line or "")

    assert obligation is not None
    assert obligation.kind == "packet_access"

    evaluations = evaluate_obligation(trace_ir, obligation)
    range_eval = next(
        evaluation
        for evaluation in evaluations
        if evaluation.insn_idx == 0
        and evaluation.phase == "pre"
        and evaluation.atom_id == "range_at_least"
    )
    assert range_eval.result == "violated"
    assert range_eval.carrier_register == "R4"


def test_infer_formal_obligation_for_each_access_type() -> None:
    packet_node = _node(
        10,
        "r1 = *(u32 *)(r3 +0)",
        pre_state={"R3": RegisterState(type="pkt", off=0, range=8)},
    )
    packet_ptr_add_node = _node(
        11,
        "r5 += r0",
        pre_state={
            "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
            "R5": RegisterState(type="pkt", off=0, range=8),
        },
    )
    map_node = _node(
        12,
        "r1 = *(u32 *)(r2 +4)",
        pre_state={"R2": RegisterState(type="map_value", off=0)},
    )
    null_node = _node(
        13,
        "r1 = *(u32 *)(r2 +0)",
        pre_state={"R2": RegisterState(type="map_value_or_null", off=0)},
    )
    helper_node = _node(
        14,
        "call bpf_map_lookup_elem#1",
        pre_state={"R1": RegisterState(type="scalar")},
    )
    stack_node = _node(
        15,
        "*(u32 *)(r10 -4) = r1",
        pre_state={
            "R1": RegisterState(type="inv", umin=1, umax=1, smin=1, smax=1),
            "R10": RegisterState(type="fp", off=0),
        },
    )

    packet_obligation = infer_formal_obligation(
        _trace_ir([packet_node]),
        packet_node,
        "invalid access to packet, off=0 size=4, R3(id=0,off=0,r=8)",
    )
    packet_ptr_add_obligation = infer_formal_obligation(
        _trace_ir([packet_ptr_add_node]),
        packet_ptr_add_node,
        "math between pkt pointer and register with unbounded min value is not allowed",
    )
    map_obligation = infer_formal_obligation(
        _trace_ir([map_node]),
        map_node,
        "invalid access to map value, value_size=16 off=4 size=4",
    )
    null_obligation = infer_formal_obligation(
        _trace_ir([null_node]),
        null_node,
        "R2 invalid mem access 'map_value_or_null'",
    )
    helper_obligation = infer_formal_obligation(
        _trace_ir([helper_node]),
        helper_node,
        "R1 type=scalar expected=map_ptr",
    )
    stack_obligation = infer_formal_obligation(
        _trace_ir([stack_node]),
        stack_node,
        "invalid indirect read from stack off -4+0 size 4",
    )
    memory_obligation = infer_formal_obligation(
        _trace_ir(
            [
                _node(
                    16,
                    "r1 = *(u8 *)(r3 +0)",
                    pre_state={"R3": RegisterState(type="mem", off=1)},
                )
            ]
        ),
        _node(
            16,
            "r1 = *(u8 *)(r3 +0)",
            pre_state={"R3": RegisterState(type="mem", off=1)},
        ),
        "invalid access to memory, mem_size=1 off=1 size=1",
    )

    assert packet_obligation is not None and packet_obligation.kind == "packet_access"
    assert packet_ptr_add_obligation is not None and packet_ptr_add_obligation.kind == "packet_ptr_add"
    assert map_obligation is not None and map_obligation.kind == "map_value_access"
    assert null_obligation is not None and null_obligation.kind == "null_check"
    assert helper_obligation is not None and helper_obligation.kind == "helper_arg"
    assert stack_obligation is not None and stack_obligation.kind == "stack_access"
    assert memory_obligation is not None and memory_obligation.kind == "memory_access"


def test_infer_formal_obligation_new_families() -> None:
    scalar_node = _node(
        17,
        "r1 = *(u32 *)(r6 +0)",
        pre_state={"R6": RegisterState(type="mem", off=0)},
    )
    trusted_null_node = _node(
        18,
        "call bpf_cgroup_acquire#71302",
        pre_state={"R1": RegisterState(type="scalar", umin=0, umax=0, smin=0, smax=0)},
    )
    context_save_node = _node(
        19,
        "call bpf_local_irq_save#72094",
        pre_state={"R1": RegisterState(type="fp", off=-8)},
    )
    context_restore_node = _node(
        20,
        "call bpf_local_irq_restore#72093",
        pre_state={"R1": RegisterState(type="fp", off=-8)},
    )

    scalar_obligation = infer_formal_obligation(
        _trace_ir([scalar_node]),
        scalar_node,
        "R6 invalid mem access 'scalar'",
    )
    trusted_null_obligation = infer_formal_obligation(
        _trace_ir([trusted_null_node]),
        trusted_null_node,
        "Possibly NULL pointer passed to trusted arg0",
    )
    context_trace = _trace_ir([context_save_node, context_restore_node])
    context_obligation = infer_formal_obligation(
        context_trace,
        next(node for node in context_trace.instructions if node.insn_idx == 20),
        "cannot restore irq state out of order",
    )

    assert scalar_obligation is not None and scalar_obligation.kind == "scalar_deref"
    assert scalar_obligation.atoms == [
        PredicateAtom("type_is_pointer", ("R6",), "R6.type is pointer-compatible")
    ]
    assert trusted_null_obligation is not None
    assert trusted_null_obligation.kind == "trusted_null_check"
    assert trusted_null_obligation.base_reg == "R1"
    assert context_obligation is not None and context_obligation.kind == "execution_context"
    assert context_obligation.atoms == []


def test_infer_formal_obligation_expanded_families() -> None:
    assert {
        "unreleased_reference",
        "btf_reference_type",
        "exception_callback_context",
        "buffer_length_pair",
        "exit_return_type",
        "verifier_limits",
    }.issubset(OBLIGATION_FAMILIES)

    dynptr_node = _node(
        21,
        "*(u8 *)(r10 -16) = r1",
        pre_state={
            "R10": RegisterState(type="fp"),
            "R1": RegisterState(type="scalar"),
            "fp-16": RegisterState(type="dynptr_ringbuf", off=-16),
        },
    )
    btf_node = _node(
        22,
        "call some_kfunc#1",
        pre_state={"R1": RegisterState(type="ptr_sock")},
    )
    exception_node = _node(23, "call bpf_throw#71500")
    buffer_pair_node = _node(
        24,
        "call bpf_dynptr_slice#71567",
        pre_state={
            "R3": RegisterState(type="fp", off=-32),
            "R4": RegisterState(type="scalar", umin=0, umax=9, smin=0, smax=9),
        },
    )
    exit_node = _node(25, "exit", pre_state={"R0": RegisterState(type="unknown")})
    verifier_limit_node = _node(26, "call bpf_timer_set_callback#170")
    trusted_reference_node = _node(
        27,
        "call bpf_cgroup_release#71323",
        pre_state={"R1": RegisterState(type="rcu_ptr_cgroup")},
    )

    dynptr_obligation = infer_formal_obligation(
        _trace_ir([dynptr_node]),
        dynptr_node,
        "cannot overwrite referenced dynptr",
    )
    btf_obligation = infer_formal_obligation(
        _trace_ir([btf_node]),
        btf_node,
        "arg#0 reference type('UNKNOWN ') size cannot be determined: -22",
    )
    exception_obligation = infer_formal_obligation(
        _trace_ir([exception_node]),
        exception_node,
        "cannot call exception cb directly",
    )
    buffer_pair_obligation = infer_formal_obligation(
        _trace_ir([buffer_pair_node]),
        buffer_pair_node,
        "arg#2 arg#3 memory, len pair leads to invalid memory access",
    )
    exit_obligation = infer_formal_obligation(
        _trace_ir([exit_node]),
        exit_node,
        "At program exit the register R0 has unknown scalar value should have been in [0, 0]",
    )
    verifier_limit_obligation = infer_formal_obligation(
        _trace_ir([verifier_limit_node]),
        verifier_limit_node,
        "combined stack size of 2 calls is 544. Too large",
    )
    trusted_reference_obligation = infer_formal_obligation(
        _trace_ir([trusted_reference_node]),
        trusted_reference_node,
        "R1 must be referenced or trusted",
    )
    sleepable_context_obligation = infer_formal_obligation(
        _trace_ir([verifier_limit_node]),
        verifier_limit_node,
        "global functions that may sleep are not allowed in non-sleepable context",
    )

    assert dynptr_obligation is not None and dynptr_obligation.kind == "dynptr_protocol"
    assert dynptr_obligation.base_reg == "fp-16"
    assert btf_obligation is not None and btf_obligation.kind == "btf_reference_type"
    assert exception_obligation is not None
    assert exception_obligation.kind == "exception_callback_context"
    assert buffer_pair_obligation is not None
    assert buffer_pair_obligation.kind == "buffer_length_pair"
    assert buffer_pair_obligation.base_reg == "R3"
    assert buffer_pair_obligation.index_reg == "R4"
    assert exit_obligation is not None and exit_obligation.kind == "exit_return_type"
    assert exit_obligation.atoms == [
        PredicateAtom("scalar_bounds_known", ("R0",), "R0 has known scalar bounds")
    ]
    assert verifier_limit_obligation is not None and verifier_limit_obligation.kind == "verifier_limits"
    assert trusted_reference_obligation is not None
    assert trusted_reference_obligation.kind == "trusted_null_check"
    assert trusted_reference_obligation.atoms == [
        PredicateAtom(
            "type_matches",
            ("R1",),
            "R1.type matches trusted_ptr_,rcu_ptr_,ptr_,ptr",
        )
    ]
    assert sleepable_context_obligation is not None
    assert sleepable_context_obligation.kind == "execution_context"


def test_infer_formal_obligation_round_two_expansions() -> None:
    processed_throw_node = _node(28, "call bpf_throw#73439")
    packet_call_node = _node(29, "call bpf_csum_diff#28")
    map_call_node = _node(
        30,
        "call bpf_probe_read#4",
        post_state={"R1": RegisterState(type="map_value", off=0)},
    )
    disallowed_kfunc_node = _node(31, "call bpf_dynptr_from_skb#71549")
    dynptr_slice_node = _node(32, "call bpf_dynptr_slice#71567")
    dynptr_exit_node = _node(
        33,
        "exit",
        pre_state={
            "R10": RegisterState(type="fp", off=0),
            "fp-16": RegisterState(type="dynptr_ringbuf"),
        },
    )
    invalid_inv_node = _node(34, "r1 = *(u8 *)(r2 +23)")

    processed_throw_obligation = infer_formal_obligation(
        _trace_ir([processed_throw_node]),
        processed_throw_node,
        "processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0",
    )
    packet_call_obligation = infer_formal_obligation(
        _trace_ir([packet_call_node]),
        packet_call_node,
        "invalid access to packet, off=34 size=64, R3(id=0,off=34,r=42)",
    )
    map_call_obligation = infer_formal_obligation(
        _trace_ir([map_call_node]),
        map_call_node,
        "invalid access to map value, value_size=2048 off=0 size=0",
    )
    disallowed_kfunc_obligation = infer_formal_obligation(
        _trace_ir([disallowed_kfunc_node]),
        disallowed_kfunc_node,
        "calling kernel function bpf_dynptr_from_skb is not allowed",
    )
    dynptr_slice_obligation = infer_formal_obligation(
        _trace_ir([dynptr_slice_node]),
        dynptr_slice_node,
        "R4 unbounded memory access, use 'var &= const' or 'if (var < const)'",
    )
    dynptr_exit_obligation = infer_formal_obligation(
        _trace_ir([dynptr_exit_node]),
        dynptr_exit_node,
        "cannot overwrite referenced dynptr",
    )
    invalid_inv_obligation = infer_formal_obligation(
        _trace_ir([invalid_inv_node]),
        invalid_inv_node,
        "R2 invalid mem access 'inv'",
    )

    assert processed_throw_obligation is not None
    assert processed_throw_obligation.kind == "execution_context"
    assert packet_call_obligation is not None
    assert packet_call_obligation.kind == "packet_access"
    assert packet_call_obligation.base_reg == "R3"
    assert packet_call_obligation.const_off == 34
    assert map_call_obligation is not None
    assert map_call_obligation.kind == "map_value_access"
    assert map_call_obligation.base_reg == "R1"
    assert disallowed_kfunc_obligation is not None
    assert disallowed_kfunc_obligation.kind == "execution_context"
    assert dynptr_slice_obligation is not None
    assert dynptr_slice_obligation.kind == "buffer_length_pair"
    assert dynptr_slice_obligation.base_reg == "R3"
    assert dynptr_slice_obligation.index_reg == "R4"
    assert dynptr_exit_obligation is not None
    assert dynptr_exit_obligation.kind == "dynptr_protocol"
    assert dynptr_exit_obligation.base_reg == "fp-16"
    assert invalid_inv_obligation is not None
    assert invalid_inv_obligation.kind == "scalar_deref"
    assert invalid_inv_obligation.base_reg == "R2"


def test_infer_formal_obligation_round_three_expansions() -> None:
    packet_helper_node = _node(
        35,
        "call bpf_perf_event_output#25",
        pre_state={
            "R1": RegisterState(type="ctx"),
            "R2": RegisterState(type="map_ptr"),
            "R4": RegisterState(type="pkt", off=0, range=0),
        },
    )
    dynptr_helper_node = _node(
        36,
        "call bpf_dynptr_from_mem#197",
        pre_state={
            "R1": RegisterState(type="fp", off=-20),
            "R4": RegisterState(type="fp", off=-16),
            "fp-16": RegisterState(type="dynptr_ringbuf", off=-16),
        },
    )
    cgroup_acquire_node = _node(
        37,
        "call bpf_cgroup_acquire#71302",
        pre_state={"R1": RegisterState(type="ptr_cgroup")},
    )
    btf_node = _node(38, "r2 = 0x11f")

    packet_helper_obligation = infer_formal_obligation(
        _trace_ir([packet_helper_node]),
        packet_helper_node,
        "helper access to the packet is not allowed",
    )
    dynptr_helper_obligation = infer_formal_obligation(
        _trace_ir([dynptr_helper_node]),
        dynptr_helper_node,
        "Unsupported reg type fp for bpf_dynptr_from_mem data",
    )
    cgroup_acquire_obligation = infer_formal_obligation(
        _trace_ir([cgroup_acquire_node]),
        cgroup_acquire_node,
        "R1 must be a rcu pointer",
    )
    btf_obligation = infer_formal_obligation(
        _trace_ir([btf_node]),
        btf_node,
        "missing btf func_info",
    )

    assert packet_helper_obligation is not None
    assert packet_helper_obligation.kind == "packet_access"
    assert packet_helper_obligation.base_reg == "R4"
    assert dynptr_helper_obligation is not None
    assert dynptr_helper_obligation.kind == "helper_arg"
    assert dynptr_helper_obligation.base_reg == "R1"
    assert cgroup_acquire_obligation is not None
    assert cgroup_acquire_obligation.kind == "helper_arg"
    assert cgroup_acquire_obligation.base_reg == "R1"
    assert btf_obligation is not None
    assert btf_obligation.kind == "btf_reference_type"


def test_infer_obligation_wrapper_uses_trace_selection() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "exit",
                pre_state={"R0": RegisterState(type="unknown")},
                is_error=True,
                error_text="At program exit the register R0 has unknown scalar value should have been in [0, 0]",
            )
        ],
        error_line="At program exit the register R0 has unknown scalar value should have been in [0, 0]",
    )

    obligation = infer_obligation(parsed, parsed.error_line or "")

    assert obligation is not None
    assert obligation.kind == "exit_return_type"


def test_predicate_evaluation_correctness() -> None:
    obligation = ObligationSpec(
        kind="packet_ptr_add",
        failing_insn=2,
        base_reg="R5",
        index_reg="R0",
        const_off=0,
        access_size=0,
        atoms=[
            PredicateAtom("base_is_pkt", ("R5",), "R5.type == pkt"),
            PredicateAtom("offset_non_negative", ("R0",), "R0.smin >= 0"),
            PredicateAtom("offset_bounded", ("R0",), "R0.umax is bounded"),
        ],
    )
    trace_ir = _trace_ir(
        [
            _node(
                0,
                "r0 = r0",
                pre_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
                post_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
            ),
            _node(
                1,
                "r0 |= r6",
                pre_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                    "R6": RegisterState(type="inv", umin=0, umax=255, smin=0, smax=255),
                },
                post_state={
                    "R0": RegisterState(type="inv", smin=-1, smax=255),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                    "R6": RegisterState(type="inv", umin=0, umax=255, smin=0, smax=255),
                },
            ),
        ]
    )

    evaluations = evaluate_obligation(trace_ir, obligation)
    loss = find_loss_transition(evaluations, fail_insn=2)

    satisfied = next(
        evaluation
        for evaluation in evaluations
        if evaluation.insn_idx == 0
        and evaluation.phase == "post"
        and evaluation.atom_id == "offset_non_negative"
    )
    violated = next(
        evaluation
        for evaluation in evaluations
        if evaluation.insn_idx == 1
        and evaluation.phase == "post"
        and evaluation.atom_id == "offset_non_negative"
    )
    bounded = next(
        evaluation
        for evaluation in evaluations
        if evaluation.insn_idx == 1
        and evaluation.phase == "post"
        and evaluation.atom_id == "offset_bounded"
    )

    assert satisfied.result == "satisfied"
    assert violated.result == "violated"
    assert bounded.result == "violated"
    assert loss is not None
    assert loss.insn_idx == 1
    assert loss.atom_id in {"offset_non_negative", "offset_bounded"}


def test_null_check_ignores_prior_register_generation_after_redefinition() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "if r2 == 0x0 goto pc+1",
                pre_state={"R2": RegisterState(type="ptr_bpf_cpumask", id=4)},
                post_state={"R2": RegisterState(type="ptr_bpf_cpumask", id=4)},
            ),
            _instruction(
                1,
                "r2 = *(u64 *)(r6 +0)",
                pre_state={"R6": RegisterState(type="map_value", off=0)},
                post_state={
                    "R2": RegisterState(type="rcu_ptr_or_null_bpf_cpumask", id=5),
                    "R6": RegisterState(type="map_value", off=0),
                },
            ),
            _instruction(
                2,
                "call bpf_kptr_xchg#194",
                pre_state={
                    "R1": RegisterState(type="map_value", off=0),
                    "R2": RegisterState(type="rcu_ptr_or_null_bpf_cpumask", id=5),
                },
                post_state={"R0": RegisterState(type="inv")},
                is_error=True,
                error_text="Possibly NULL pointer passed to helper arg2",
            ),
        ],
        error_line="Possibly NULL pointer passed to helper arg2",
    )

    result = analyze_proof(parsed, parsed.error_line or "", error_insn=2)

    assert result.obligation is not None
    assert result.obligation.kind == "null_check"
    assert result.obligation.base_reg == "R2"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None


def test_packet_access_tracks_establishment_through_equivalent_register_before_split() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "if r3 > r2 goto pc+1",
                pre_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", id=7, off=0, range=0),
                },
                post_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", id=7, off=0, range=4),
                },
            ),
            _instruction(
                1,
                "r4 = r3",
                pre_state={"R3": RegisterState(type="pkt", id=7, off=0, range=4)},
                post_state={
                    "R3": RegisterState(type="pkt", id=7, off=0, range=4),
                    "R4": RegisterState(type="pkt", id=7, off=0, range=0),
                },
            ),
            _instruction(
                2,
                "r0 = *(u32 *)(r4 +0)",
                pre_state={
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", id=7, off=0, range=4),
                    "R4": RegisterState(type="pkt", id=7, off=0, range=0),
                },
                post_state={
                    "R0": RegisterState(type="inv", umin=0, umax=0, smin=0, smax=0),
                    "R2": RegisterState(type="pkt_end", off=0),
                    "R3": RegisterState(type="pkt", id=7, off=0, range=4),
                    "R4": RegisterState(type="pkt", id=7, off=0, range=0),
                },
                is_error=True,
                error_text="invalid access to packet, off=0 size=4, R4(id=7,off=0,r=0)",
            ),
        ],
        error_line="invalid access to packet, off=0 size=4, R4(id=7,off=0,r=0)",
    )

    result = analyze_proof(parsed, parsed.error_line or "", error_insn=2)

    assert result.obligation is not None
    assert result.obligation.kind == "packet_access"
    assert result.proof_status == "established_then_lost"
    assert result.establish_site == 1
    assert result.loss_site == 1
    assert result.transition is not None
    assert result.transition.carrier_register == "R4"


def test_backward_slice_produces_expected_edges_for_real_loss_site() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))
    trace_ir = build_trace_ir(parsed)
    failing = next(instruction for instruction in trace_ir.instructions if instruction.insn_idx == 24)
    obligation = infer_formal_obligation(trace_ir, failing, parsed.error_line or "")

    assert obligation is not None
    evaluations = evaluate_obligation(trace_ir, obligation)
    transition = find_loss_transition(evaluations, fail_insn=24)

    assert transition is not None
    edges = backward_slice(trace_ir, obligation, transition)
    edge_set = {(edge.src, edge.dst, edge.kind) for edge in edges}

    assert ((21, "R0"), (22, "R0"), "def_use") in edge_set
    assert ((19, "R6"), (22, "R0"), "def_use") in edge_set
    assert ((21, "R0"), (22, "R0"), "backtrack_hint") in edge_set


def test_backward_slice_decodes_textual_backtrack_register_masks() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                21,
                "r0 = r0",
                pre_state={"R0": RegisterState(type="pkt", range=4)},
                post_state={"R0": RegisterState(type="pkt", range=4)},
            ),
            _instruction(
                22,
                "r1 = *(u8 *)(r0 +0)",
                pre_state={"R0": RegisterState(type="pkt", range=0)},
                post_state={
                    "R0": RegisterState(type="pkt", range=0),
                    "R1": RegisterState(type="scalar", umin=0, umax=0, smin=0, smax=0),
                },
                is_error=True,
                error_text="invalid access to packet, off=0 size=1, R0(id=0,off=0,r=0)",
            ),
        ],
        error_line="invalid access to packet, off=0 size=1, R0(id=0,off=0,r=0)",
        backtrack_chains=[
            BacktrackChain(
                error_insn=22,
                first_insn=21,
                links=[
                    BacktrackLink(insn_idx=22, bytecode="(71) r1 = *(u8 *)(r0 +0)", regs="r0", stack="0"),
                    BacktrackLink(insn_idx=21, bytecode="(bf) r0 = r0", regs="r0", stack="0"),
                ],
                regs_mask="r0",
                stack_mask="0",
            )
        ],
    )
    trace_ir = build_trace_ir(parsed)
    obligation = ObligationSpec(
        kind="packet_access",
        failing_insn=22,
        base_reg="R0",
        index_reg=None,
        const_off=0,
        access_size=1,
        atoms=[
            PredicateAtom(
                atom_id="range_at_least",
                registers=("R0",),
                expression="0 + 1 <= R0.range",
            )
        ],
        failing_trace_pos=1,
    )
    transition = TransitionWitness(
        atom_id="range_at_least",
        insn_idx=22,
        before_result="satisfied",
        after_result="violated",
        witness="R0.range collapsed",
        carrier_register="R0",
        trace_pos=1,
    )

    edges = backward_slice(trace_ir, obligation, transition)
    edge_set = {(edge.src, edge.dst, edge.kind) for edge in edges}

    assert ((21, "R0"), (22, "R0"), "backtrack_hint") in edge_set


def test_backward_obligation_slice_real_case_tracks_mark_precise_chain() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))
    trace_ir = build_trace_ir(parsed)
    failing = next(instruction for instruction in trace_ir.instructions if instruction.insn_idx == 24)
    obligation = infer_formal_obligation(trace_ir, failing, parsed.error_line or "")

    assert obligation is not None

    chain = backward_obligation_slice(parsed, 22, obligation)
    chain_map = dict(chain)

    assert [insn_idx for insn_idx, _ in chain] == [19, 20, 21, 22]
    assert "writes to R0 (obligation index register)" in chain_map[22]
    assert "mark_precise backtrack target" in chain_map[21]
    assert "mark_precise backtrack target" in chain_map[20]
    assert "mark_precise backtrack target" in chain_map[19]


def test_analyze_proof_real_loss_site_includes_instruction_level_causal_chain() -> None:
    parsed = parse_trace(_block("case_study/cases/stackoverflow/stackoverflow-70750259.yaml", 0))

    result = analyze_proof(
        parsed_trace=parsed,
        error_line=parsed.error_line or "",
        error_insn=24,
    )

    assert result.proof_status == "established_then_lost"
    assert result.causal_chain
    assert [insn_idx for insn_idx, _ in result.causal_chain] == [19, 20, 21, 22]
    assert any("mark_precise backtrack target" in reason for _, reason in result.causal_chain)


def test_track_composite_reports_first_failed_sub_obligation() -> None:
    parsed = _parsed_trace(
        [
            _instruction(
                0,
                "r0 = r0",
                pre_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
                post_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
            ),
            _instruction(
                1,
                "r0 += -8",
                pre_state={
                    "R0": RegisterState(type="inv", umin=0, umax=4, smin=0, smax=4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
                post_state={
                    "R0": RegisterState(type="inv", smin=-8, smax=-4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
            ),
            _instruction(
                2,
                "r5 += r0",
                pre_state={
                    "R0": RegisterState(type="inv", smin=-8, smax=-4),
                    "R5": RegisterState(type="pkt", off=0, range=8),
                },
                post_state={},
                is_error=True,
                error_text="math between pkt pointer and register with unbounded min value is not allowed",
            ),
        ],
        error_line="math between pkt pointer and register with unbounded min value is not allowed",
    )
    composite = CompositeObligation(
        sub_obligations=[
            ObligationSpec(
                kind="packet_ptr_add",
                failing_insn=2,
                base_reg="R5",
                index_reg="R0",
                const_off=0,
                access_size=0,
                atoms=[PredicateAtom("base_is_pkt", ("R5",), "R5.type == pkt")],
            ),
            ObligationSpec(
                kind="packet_ptr_add",
                failing_insn=2,
                base_reg="R5",
                index_reg="R0",
                const_off=0,
                access_size=0,
                atoms=[PredicateAtom("offset_non_negative", ("R0",), "R0.smin >= 0")],
            ),
        ]
    )

    result = track_composite(parsed, composite)

    assert len(result["sub_results"]) == 2
    assert result["first_failed_index"] == 1
    assert result["first_failed_obligation"] == composite.sub_obligations[1]
    assert result["first_failure_site"] == 1
    assert result["first_failure_status"] == "established_then_lost"


def _verifier_text(case_path: str, block_index: int | None = None) -> tuple[dict, str]:
    payload = _load_case(case_path)
    verifier_log = payload["verifier_log"]
    if isinstance(verifier_log, dict):
        if block_index is not None:
            return payload, verifier_log["blocks"][block_index]
        combined = verifier_log.get("combined")
        if combined:
            return payload, combined
        return payload, "\n".join(verifier_log.get("blocks", []))
    assert isinstance(verifier_log, str)
    return payload, verifier_log


def _analyze_case(
    case_path: str,
    *,
    block_index: int | None = None,
    error_line: str | None = None,
) -> tuple[dict, ParsedTrace, object]:
    payload, text = _verifier_text(case_path, block_index)
    parsed = parse_trace(text)
    error_insns = [instruction.insn_idx for instruction in parsed.instructions if instruction.is_error]
    error_insn = error_insns[-1] if error_insns else (
        parsed.instructions[-1].insn_idx if parsed.instructions else None
    )
    result = analyze_proof(parsed, error_line or parsed.error_line or "", error_insn)
    return payload, parsed, result


def test_analyze_proof_real_lowering_artifact_old_heuristic_miss_79530762() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/stackoverflow/stackoverflow-79530762.yaml",
        block_index=0,
    )

    assert len(payload["verifier_log"]["blocks"]) == 3
    assert parsed.has_btf_annotations is True
    assert parsed.has_backtracking is True
    assert result.obligation is not None
    assert result.obligation.kind == "packet_access"
    assert result.obligation.base_reg == "R4"
    assert result.proof_status == "established_then_lost"
    assert result.establish_site == 36
    assert result.loss_site == 36
    assert result.reject_site == 36
    assert result.transition is not None
    assert result.transition.atom_id == "base_is_pkt"
    assert result.slice_edges
    assert any(edge.kind == "control" for edge in result.slice_edges)


def test_analyze_proof_real_source_bug_null_selftest_never_established() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-iters-iter-err-too-permissive3-raw-tp-969d109d.yaml",
        error_line="invalid mem access 'map_value_or_null'",
    )

    assert payload["selftest"]["function"] == "iter_err_too_permissive3"
    assert parsed.has_btf_annotations is True
    assert result.obligation is not None
    assert result.obligation.kind == "null_check"
    assert result.obligation.base_reg == "R7"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 28


def test_analyze_proof_real_source_bug_type_selftest_never_established() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a.yaml",
        error_line="type=scalar expected=fp",
    )

    assert payload["selftest"]["function"] == "test_populate_invalid_destination"
    assert parsed.has_btf_annotations is True
    assert result.obligation is not None
    assert result.obligation.kind == "helper_arg"
    assert result.obligation.base_reg == "R1"
    assert result.proof_status == "never_established"
    assert result.loss_site is None
    assert result.reject_site == 4


def test_analyze_proof_real_source_bug_null_cpumask_reuse_now_never_established() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39.yaml",
        error_line="Possibly NULL pointer passed to helper arg2",
    )

    assert payload["selftest"]["function"] == "test_global_mask_rcu_no_null_check"
    assert parsed.has_btf_annotations is True
    assert result.obligation is not None
    assert result.obligation.kind == "null_check"
    assert result.obligation.base_reg == "R2"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 15


def test_analyze_proof_real_source_bug_helper_arg_so_61945212() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/stackoverflow/stackoverflow-61945212.yaml",
        block_index=0,
        error_line="R2 type=inv expected=fp",
    )

    assert parsed.has_btf_annotations is False
    assert result.obligation is not None
    assert result.obligation.kind == "helper_arg"
    assert result.obligation.base_reg == "R2"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 8


def test_analyze_proof_real_dynptr_protocol_uses_stack_slot() -> None:
    payload, text = _verifier_text(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993.yaml"
    )
    parsed = parse_trace(text)

    result = analyze_proof(
        parsed,
        "Expected an initialized dynptr as arg #2",
        error_insn=29,
    )

    assert payload["selftest"]["function"] == "invalid_read2"
    assert result.obligation is not None
    assert result.obligation.kind == "dynptr_protocol"
    assert result.obligation.base_reg == "fp-16"
    assert result.reject_site == 29


def test_analyze_proof_real_dynptr_clone_slice_state_infers_protocol() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-clone-invalidate5-raw-tp-1e91d4af.yaml",
        error_line="R6 invalid mem access 'scalar'",
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "dynptr_protocol"
    assert result.obligation.base_reg == "fp-16"
    assert result.reject_site == 26


def test_analyze_proof_real_iterator_protocol_infers_from_generic_raw_error_line() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-iters-state-safety-next-without-new-fail-raw-tp-8645b906.yaml",
        error_line="arg#0 reference type('UNKNOWN ') size cannot be determined: -22",
    )

    assert result.obligation is not None
    assert result.obligation.kind == "iterator_protocol"
    assert result.obligation.base_reg == "fp-8"
    assert result.reject_site == 3


def test_analyze_proof_real_iterator_leak_exit_infers_protocol() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-iters-state-safety-create-and-forget-to-destroy-fail-raw-tp-074de205.yaml"
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "iterator_protocol"
    assert result.obligation.base_reg == "fp-8"
    assert result.reject_site == 7


def test_analyze_proof_real_execution_context_infers_from_irq_restore_trace() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-irq-irq-restore-ooo-tc-84ede29d.yaml"
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "execution_context"
    assert result.reject_site == 9


def test_infer_obligation_real_round_two_coverage_regressions() -> None:
    cases = [
        (
            "case_study/cases/kernel_selftests/kernel-selftest-exceptions-assert-check-assert-generic-tc-22b5248c.yaml",
            "execution_context",
            None,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-exceptions-fail-reject-with-lock-tc-66db0d44.yaml",
            "execution_context",
            None,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-skb-invalid-ctx-xdp-1a32a21f.yaml",
            "execution_context",
            None,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-dynptr-pruning-overwrite-tc-6e6ed521.yaml",
            "dynptr_protocol",
            "fp-16",
        ),
        (
            "case_study/cases/stackoverflow/stackoverflow-60053570.yaml",
            "packet_access",
            "R3",
        ),
        (
            "case_study/cases/stackoverflow/stackoverflow-72560675.yaml",
            "map_value_access",
            "R1",
        ),
        (
            "case_study/cases/github_issues/github-cilium-cilium-41996.yaml",
            "scalar_deref",
            "R2",
        ),
    ]

    for case_path, expected_kind, expected_base in cases:
        _, text = _verifier_text(case_path, None)
        parsed_log = parse_verifier_log(text)
        parsed_trace = parse_verifier_trace(text)
        error_line = parsed_trace.error_line or parsed_log.error_line or ""

        obligation = infer_obligation(parsed_trace, error_line)

        assert obligation is not None
        assert obligation.kind == expected_kind
        assert obligation.base_reg == expected_base


def test_infer_obligation_real_round_three_coverage_regressions() -> None:
    assert "safety_violation" in OBLIGATION_FAMILIES

    cases = [
        (
            "case_study/cases/kernel_selftests/kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda.yaml",
            "verifier_limits",
            None,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-trusted-walked-tp-btf-cgroup-mkdir-6deeac84.yaml",
            "helper_arg",
            "R1",
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-unacquired-tp-btf-cgroup-mkdir-39ffb658.yaml",
            "helper_arg",
            "R1",
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cpumask-failure-test-global-mask-out-of-rcu-tp-btf-task-newtask-55a16b69.yaml",
            "helper_arg",
            "R2",
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cpumask-failure-test-invalid-nested-array-tp-btf-task-newtask-bd05d03f.yaml",
            "helper_arg",
            "R1",
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-dynptr-from-mem-invalid-api-raw-tp-1040be69.yaml",
            "helper_arg",
            "R1",
        ),
        (
            "case_study/cases/stackoverflow/stackoverflow-56872436.yaml",
            "verifier_limits",
            None,
        ),
        (
            "case_study/cases/stackoverflow/stackoverflow-78591601.yaml",
            "packet_access",
            "R2",
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-dummy-st-ops-fail-test-unsupported-field-sleepable-struct-ops-s-test-2-e009f86b.yaml",
            "safety_violation",
            None,
        ),
    ]

    for case_path, expected_kind, expected_base in cases:
        _, text = _verifier_text(case_path, None)
        parsed_log = parse_verifier_log(text)
        parsed_trace = parse_verifier_trace(text)
        error_line = parsed_trace.error_line or parsed_log.error_line or ""

        obligation = infer_obligation(parsed_trace, error_line)

        assert obligation is not None
        assert obligation.kind == expected_kind
        assert obligation.base_reg == expected_base


def test_analyze_proof_real_expanded_obligation_family_matches() -> None:
    cases = [
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unreleased-tp-btf-cgroup-mkdir-0f46d712.yaml",
            "BPF_EXIT instruction in main prog would lead to reference leak",
            "unreleased_reference",
            None,
            None,
            4,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-exceptions-fail-reject-exception-cb-call-global-func-tc-bd94f6f8.yaml",
            "cannot call exception cb directly",
            "exception_callback_context",
            None,
            None,
            6,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-irq-irq-sleepable-helper-global-subprog-syscall-7d470f89.yaml",
            "global functions that may sleep are not allowed in non-sleepable context",
            "execution_context",
            None,
            None,
            5,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-test-dynptr-skb-small-buff-cgroup-skb-egress-4f498dbd.yaml",
            "arg#2 arg#3 memory, len pair leads to invalid memory access",
            "buffer_length_pair",
            "R3",
            "R4",
            17,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-exceptions-fail-reject-set-exception-cb-bad-ret1-fentry-bpf-check-8124b586.yaml",
            "At program exit the register R0 has unknown scalar value should have been in [0, 0]",
            "exit_return_type",
            "R0",
            None,
            2,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d.yaml",
            "combined stack size of 2 calls is 544. Too large",
            "verifier_limits",
            None,
            None,
            56,
        ),
        (
            "case_study/cases/kernel_selftests/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b.yaml",
            "R1 must be referenced or trusted",
            "trusted_null_check",
            "R1",
            None,
            7,
        ),
    ]

    for case_path, error_line, expected_kind, expected_base, expected_index, reject_site in cases:
        _, parsed, result = _analyze_case(case_path, error_line=error_line)
        assert parsed.instructions
        assert result.obligation is not None
        assert result.obligation.kind == expected_kind
        assert result.obligation.base_reg == expected_base
        assert result.obligation.index_reg == expected_index
        assert result.reject_site == reject_site


def test_analyze_proof_real_trusted_null_scalar_zero_is_never_established() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-null-tp-btf-cgroup-mkdir-2a562fb3.yaml",
        error_line="Possibly NULL pointer passed to trusted arg0",
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "trusted_null_check"
    assert result.obligation.base_reg == "R1"
    assert result.proof_status == "established_then_lost"
    assert result.loss_site == 0
    assert result.reject_site == 1


def test_analyze_proof_real_env_mismatch_helper_unavailable_stays_unknown() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/github_issues/github-aya-rs-aya-1233.yaml",
        block_index=0,
    )

    assert len(payload["verifier_log"]["blocks"]) == 2
    assert parsed.has_btf_annotations is True
    assert parsed.error_line is None
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 8


def test_analyze_proof_real_env_mismatch_unknown_func_returns_unknown() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/github_issues/github-aya-rs-aya-864.yaml",
        block_index=0,
        error_line="unknown func bpf_get_current_pid_tgid#14",
    )

    assert parsed.instructions
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 1


def test_analyze_proof_real_verifier_limit_async_stack_returns_unknown() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda.yaml",
        error_line="combined stack size of 2 calls is",
    )

    assert payload["selftest"]["function"] == "async_call_root_check"
    assert parsed.has_btf_annotations is True
    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "verifier_limits"
    assert result.proof_status == "unknown"
    assert result.reject_site == 54


def test_analyze_proof_real_verifier_limit_large_state_budget_returns_unknown() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/github_issues/github-cilium-cilium-41412.yaml",
        error_line=(
            "processed 496185 insns (limit 1000000) max_states_per_insn 4 "
            "total_states 6230 peak_states 6230 mark_read 3871"
        ),
    )

    assert parsed.instructions
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 1738


def test_analyze_proof_real_env_mismatch_alignment_returns_unknown() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/stackoverflow/stackoverflow-76441958.yaml",
        block_index=0,
    )

    assert parsed.has_btf_annotations is True
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.reject_site == 15


def test_analyze_proof_real_verifier_bug_kernel_oops_returns_unknown() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/github_issues/github-cilium-cilium-44216.yaml",
        block_index=0,
    )

    assert parsed.instructions == []
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site is None


def test_analyze_proof_empty_trace_returns_unknown_without_crashing() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/stackoverflow/stackoverflow-56872436.yaml",
        block_index=0,
    )

    assert parsed.instructions == []
    assert parsed.has_btf_annotations is False
    assert result.obligation is None
    assert result.proof_status == "unknown"
    assert result.reject_site is None


def test_analyze_proof_real_helper_arg_missing_post_state_stays_never_established() -> None:
    payload, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9.yaml",
        error_line="arg#0 expected pointer to stack or const struct bpf_dynptr",
    )

    assert payload["case_id"] == "kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9"
    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "helper_arg"
    assert result.obligation.base_reg == "R1"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.transition is None
    assert result.reject_site == 0


def test_analyze_proof_real_map_value_hoisted_scalar_guard_tracks_loss() -> None:
    _, parsed, result = _analyze_case("case_study/cases/stackoverflow/stackoverflow-74178703.yaml")

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "map_value_access"
    assert result.obligation.base_reg == "R3"
    assert result.proof_status == "established_then_lost"
    assert result.establish_site is not None
    assert result.loss_site is not None
    assert result.loss_site < result.reject_site
    assert result.reject_site == 195
    assert result.transition is not None
    assert result.transition.atom_id == "range_at_least"


def test_analyze_proof_real_subprog_memory_access_without_caller_context_returns_unknown() -> None:
    _, parsed, result = _analyze_case("case_study/cases/stackoverflow/stackoverflow-76160985.yaml")

    assert parsed.validated_functions == [1]
    assert parsed.caller_transfer_sites == []
    assert result.obligation is not None
    assert result.obligation.kind == "memory_access"
    assert result.proof_status == "unknown"
    assert result.status_reason is not None
    assert "caller-side proof context" in result.status_reason
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 195


def test_analyze_proof_real_github_aya_458_null_check_never_established() -> None:
    _, parsed, result = _analyze_case("case_study/cases/github_issues/github-aya-rs-aya-458.yaml")

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "null_check"
    assert result.obligation.base_reg == "R0"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 293


def test_analyze_proof_real_github_cilium_41522_packet_access_never_established() -> None:
    _, parsed, result = _analyze_case("case_study/cases/github_issues/github-cilium-cilium-41522.yaml")

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "packet_access"
    assert result.obligation.base_reg == "R4"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 945


def test_analyze_proof_real_dynptr_map_value_memory_access_never_established() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84.yaml"
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "memory_access"
    assert result.obligation.base_reg == "R0"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 28


def test_analyze_proof_real_dynptr_partial_slot_invalidation_tracks_stack_loss() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-dynptr-partial-slot-invalidate-tc-8f5ee7c7.yaml"
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "stack_access"
    assert result.obligation.base_reg == "R10"
    assert result.proof_status == "established_then_lost"
    assert result.establish_site == 25
    assert result.loss_site == 25
    assert result.reject_site == 25
    assert result.transition is not None


def test_analyze_proof_real_dynptr_slice_var_len_map_value_never_established() -> None:
    _, parsed, result = _analyze_case(
        "case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-dynptr-slice-var-len2-tc-673ab9e7.yaml"
    )

    assert parsed.instructions
    assert result.obligation is not None
    assert result.obligation.kind == "map_value_access"
    assert result.obligation.base_reg == "R1"
    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.reject_site == 10
