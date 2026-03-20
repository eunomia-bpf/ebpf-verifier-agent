"""Tests for the opcode-driven safety condition inference (interface/extractor/engine/opcode_safety.py).

Verifies:
1. Each opcode class maps to the correct SafetyDomain.
2. SafetyCondition.is_satisfied / evaluate_condition works correctly with synthetic register states.
3. The reference case (stackoverflow-70750259) produces the correct violated condition.
4. End-to-end pipeline still works with opcode-driven analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers: minimal RegisterState stub for tests
# ---------------------------------------------------------------------------

@dataclass
class MockReg:
    """Minimal RegisterState mock for opcode_safety tests."""
    type: str
    off: int | None = None
    range: int | None = None
    umin: int | None = None
    umax: int | None = None
    smin: int | None = None
    smax: int | None = None
    id: int | None = None
    var_off: str | None = None


@dataclass
class MockInsn:
    """Minimal TracedInstruction mock."""
    bytecode: str
    pre_state: dict
    post_state: dict
    is_error: bool = True
    error_text: str | None = None
    insn_idx: int = 0
    source_line: str | None = None
    backtrack: Any = None
    opcode_hex: str | None = None


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


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from interface.extractor.engine.opcode_safety import (
    OpcodeClass,
    OpcodeConditionPredicate,
    SafetyCondition,
    SafetyDomain,
    decode_opcode,
    derive_safety_conditions,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
    _extract_regs_from_bytecode,
)


# ---------------------------------------------------------------------------
# Tests: decode_opcode
# ---------------------------------------------------------------------------

class TestDecodeOpcode:
    """Test opcode byte decoding into OpcodeInfo."""

    def test_ldx_byte(self):
        """0x71 = LDX byte access."""
        info = decode_opcode("71", "r6 = *(u8 *)(r0 +2)")
        assert info.opclass == OpcodeClass.LDX
        assert info.is_memory_access is True
        assert info.is_call is False
        assert info.is_exit is False
        assert info.is_alu is False
        assert info.access_size == 1  # u8 = 1 byte
        assert info.src_reg == "R0"
        assert info.dst_reg == "R6"

    def test_ldx_word(self):
        """0x61 = LDX 32-bit word."""
        info = decode_opcode("61", "r3 = *(u32 *)(r5 +4)")
        assert info.opclass == OpcodeClass.LDX
        assert info.access_size == 4
        assert info.src_reg == "R5"
        assert info.dst_reg == "R3"

    def test_ldx_dword(self):
        """0x79 = LDX 64-bit."""
        info = decode_opcode("79", "r2 = *(u64 *)(r1 +0)")
        assert info.opclass == OpcodeClass.LDX
        assert info.access_size == 8
        assert info.src_reg == "R1"
        assert info.dst_reg == "R2"

    def test_stx_byte(self):
        """0x73 = STX byte store."""
        info = decode_opcode("73", "*(u8 *)(r10 -1) = r3")
        assert info.opclass == OpcodeClass.STX
        assert info.is_memory_access is True
        assert info.access_size == 1
        assert info.dst_reg == "R10"
        assert info.src_reg == "R3"

    def test_st_word(self):
        """0x62 = ST immediate word store."""
        info = decode_opcode("62", "*(u32 *)(r10 -4) = 0")
        assert info.opclass == OpcodeClass.ST
        assert info.is_memory_access is True
        assert info.access_size == 4
        assert info.dst_reg == "R10"

    def test_alu64(self):
        """0x0f = ALU64 ADD."""
        info = decode_opcode("0f", "r5 += r0")
        assert info.opclass == OpcodeClass.ALU64
        assert info.is_alu is True
        assert info.is_memory_access is False
        assert info.dst_reg == "R5"
        assert info.src_reg == "R0"

    def test_alu_or(self):
        """0x4f = ALU64 OR."""
        info = decode_opcode("4f", "r0 |= r6")
        assert info.opclass == OpcodeClass.ALU64
        assert info.is_alu is True
        assert info.dst_reg == "R0"
        assert info.src_reg == "R6"

    def test_call(self):
        """0x85 = CALL."""
        info = decode_opcode("85", "call bpf_map_lookup_elem#1")
        assert info.is_call is True
        assert info.is_exit is False
        assert info.is_alu is False
        assert info.is_memory_access is False
        assert info.helper_id == 1

    def test_exit(self):
        """0x95 = EXIT."""
        info = decode_opcode("95", "exit")
        assert info.is_exit is True
        assert info.is_call is False

    def test_jmp_conditional(self):
        """0x25 = JMP32 conditional."""
        info = decode_opcode("25", "if r3 > 0xfb goto pc+3")
        assert info.is_branch is True
        assert info.is_call is False
        assert info.is_exit is False


# ---------------------------------------------------------------------------
# Tests: derive_safety_conditions
# ---------------------------------------------------------------------------

class TestDeriveSafetyConditions:
    """Test that opcode class maps to correct safety conditions."""

    def test_ldx_conditions(self):
        info = decode_opcode("71", "r6 = *(u8 *)(r0 +2)")
        conditions = derive_safety_conditions(info)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.POINTER_TYPE in domains
        assert SafetyDomain.NULL_SAFETY in domains
        assert SafetyDomain.MEMORY_BOUNDS in domains

    def test_ldx_critical_register_is_src(self):
        """For LDX, the base pointer is src_reg (R0), not dst_reg (R6)."""
        info = decode_opcode("71", "r6 = *(u8 *)(r0 +2)")
        conditions = derive_safety_conditions(info)
        ptr_conditions = [c for c in conditions if c.domain == SafetyDomain.POINTER_TYPE]
        assert ptr_conditions
        assert all(c.critical_register == "R0" for c in ptr_conditions)

    def test_stx_conditions(self):
        info = decode_opcode("7b", "*(u64 *)(r10 -8) = r1")
        conditions = derive_safety_conditions(info)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.POINTER_TYPE in domains
        assert SafetyDomain.NULL_SAFETY in domains
        assert SafetyDomain.MEMORY_BOUNDS in domains
        assert SafetyDomain.WRITE_PERMISSION in domains

    def test_stx_critical_register_is_dst(self):
        """For STX, the base pointer is dst_reg."""
        info = decode_opcode("7b", "*(u64 *)(r10 -8) = r1")
        conditions = derive_safety_conditions(info)
        ptr_conditions = [c for c in conditions if c.domain == SafetyDomain.POINTER_TYPE]
        assert ptr_conditions
        assert all(c.critical_register == "R10" for c in ptr_conditions)

    def test_alu_conditions(self):
        """ALU instruction produces ARITHMETIC_LEGALITY and optionally SCALAR_BOUND."""
        info = decode_opcode("0f", "r5 += r0")
        conditions = derive_safety_conditions(info)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.ARITHMETIC_LEGALITY in domains
        assert SafetyDomain.SCALAR_BOUND in domains

    def test_alu_no_src_no_scalar_bound(self):
        """ALU immediate (no src register) should not produce SCALAR_BOUND."""
        info = decode_opcode("07", "r2 += 1")
        conditions = derive_safety_conditions(info)
        # With immediate, src_reg is None — no SCALAR_BOUND
        scalar_conds = [c for c in conditions if c.domain == SafetyDomain.SCALAR_BOUND]
        assert len(scalar_conds) == 0

    def test_call_conditions(self):
        info = decode_opcode("85", "call bpf_map_lookup_elem")
        conditions = derive_safety_conditions(info)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.ARG_CONTRACT in domains
        # Helper-specific signature should expose only the real arguments.
        regs = {c.critical_register for c in conditions if c.domain == SafetyDomain.ARG_CONTRACT}
        assert regs == {"R1", "R2"}

    def test_zero_arg_helper_has_no_arg_conditions(self):
        info = decode_opcode("85", "call bpf_get_current_pid_tgid#14")
        conditions = derive_safety_conditions(info)
        assert conditions == []

    def test_exit_conditions(self):
        info = decode_opcode("95", "exit")
        conditions = derive_safety_conditions(info)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.REFERENCE_BALANCE in domains
        assert SafetyDomain.SCALAR_BOUND in domains

    def test_branch_no_conditions(self):
        """Conditional branches have no safety conditions."""
        info = decode_opcode("25", "if r3 > 0xfb goto pc+3")
        conditions = derive_safety_conditions(info)
        assert len(conditions) == 0


# ---------------------------------------------------------------------------
# Tests: evaluate_condition
# ---------------------------------------------------------------------------

class TestEvaluateCondition:
    """Test SafetyCondition evaluation against register states."""

    def test_pointer_type_satisfied(self):
        cond = SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R0",
            required_property="must be pointer",
        )
        state = {"R0": MockReg(type="pkt", off=0, range=10)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_pointer_type_violated_scalar(self):
        cond = SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R0",
            required_property="must be pointer",
        )
        state = {"R0": MockReg(type="inv")}
        assert evaluate_condition(cond, state) == "violated"

    def test_pointer_type_unknown_missing(self):
        cond = SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R0",
            required_property="must be pointer",
        )
        state = {}
        assert evaluate_condition(cond, state) == "unknown"

    def test_null_safety_satisfied(self):
        cond = SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register="R3",
            required_property="must not be null",
        )
        state = {"R3": MockReg(type="map_value", off=0, range=4)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_null_safety_violated_or_null(self):
        cond = SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register="R3",
            required_property="must not be null",
        )
        state = {"R3": MockReg(type="map_value_or_null")}
        assert evaluate_condition(cond, state) == "violated"

    def test_null_safety_violated_ptr_or_null(self):
        cond = SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register="R1",
            required_property="must not be null",
        )
        state = {"R1": MockReg(type="ptr_or_null_")}
        assert evaluate_condition(cond, state) == "violated"

    def test_memory_bounds_satisfied(self):
        cond = SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register="R0",
            required_property="off + 1 <= range",
            access_size=1,
        )
        # off=0, range=6: 0 + 1 <= 6, satisfied
        state = {"R0": MockReg(type="pkt", off=0, range=6)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_memory_bounds_violated_zero_range(self):
        cond = SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register="R0",
            required_property="off + 4 <= range",
            access_size=4,
        )
        state = {"R0": MockReg(type="pkt", off=0, range=0)}
        assert evaluate_condition(cond, state) == "violated"

    def test_memory_bounds_violated_overflow(self):
        cond = SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register="R0",
            required_property="off + 4 <= range",
            access_size=4,
        )
        # off=5, range=6: 5 + 4 = 9 > 6
        state = {"R0": MockReg(type="pkt", off=5, range=6)}
        assert evaluate_condition(cond, state) == "violated"

    def test_scalar_bound_satisfied(self):
        cond = SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="must be bounded",
        )
        state = {"R0": MockReg(type="inv", umax=255)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_scalar_bound_violated_unbounded(self):
        cond = SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="must be bounded",
        )
        # umax=None means completely unbounded
        state = {"R0": MockReg(type="inv")}
        assert evaluate_condition(cond, state) == "violated"

    def test_scalar_bound_violated_too_wide(self):
        cond = SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="must be bounded",
        )
        # umax >= 2^32 is "too wide"
        state = {"R0": MockReg(type="inv", umax=2**32)}
        assert evaluate_condition(cond, state) == "violated"

    def test_arithmetic_legality_scalar(self):
        """Scalar-scalar arithmetic is always legal."""
        cond = SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register="R5",
            required_property="arithmetic must be legal",
        )
        state = {"R5": MockReg(type="inv", umax=100)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_arithmetic_legality_pkt_pointer(self):
        """pkt pointer arithmetic is legal."""
        cond = SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register="R5",
            required_property="arithmetic must be legal",
        )
        state = {"R5": MockReg(type="pkt", off=0, range=10)}
        assert evaluate_condition(cond, state) == "satisfied"

    def test_arithmetic_legality_ctx_prohibited(self):
        """ctx pointer arithmetic is prohibited."""
        cond = SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register="R1",
            required_property="arithmetic must be legal",
        )
        state = {"R1": MockReg(type="ctx")}
        assert evaluate_condition(cond, state) == "violated"


# ---------------------------------------------------------------------------
# Tests: infer_conditions_from_error_insn (opcode-hex-driven)
# ---------------------------------------------------------------------------

class TestInferConditionsFromErrorInsn:
    """Test condition inference from explicit opcode bytes."""

    def test_ldx_from_opcode(self):
        insn = MockInsn(
            bytecode="r6 = *(u8 *)(r0 +2)",
            pre_state={},
            post_state={},
            opcode_hex="71",
        )
        conditions = infer_conditions_from_error_insn(insn)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.POINTER_TYPE in domains
        assert SafetyDomain.NULL_SAFETY in domains
        assert SafetyDomain.MEMORY_BOUNDS in domains

    def test_stx_from_opcode(self):
        insn = MockInsn(
            bytecode="*(u64 *)(r10 -8) = r1",
            pre_state={},
            post_state={},
            opcode_hex="7b",
        )
        conditions = infer_conditions_from_error_insn(insn)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.POINTER_TYPE in domains
        assert SafetyDomain.MEMORY_BOUNDS in domains

    def test_alu_add_from_opcode(self):
        insn = MockInsn(
            bytecode="r5 += r0",
            pre_state={
                "R5": MockReg(type="pkt", off=0, range=10),
                "R0": MockReg(type="inv"),  # unbounded scalar
            },
            post_state={},
            opcode_hex="0f",
        )
        conditions = infer_conditions_from_error_insn(insn)
        # Should have SCALAR_BOUND for R0 (and ARITHMETIC_LEGALITY for R5 which is a pointer)
        scalar_conds = [c for c in conditions if c.domain == SafetyDomain.SCALAR_BOUND]
        assert scalar_conds
        assert any(c.critical_register == "R0" for c in scalar_conds)

    def test_alu_refinement_drops_arith_legality_for_scalar(self):
        """For ALU when dst is scalar, ARITHMETIC_LEGALITY is dropped in refinement."""
        insn = MockInsn(
            bytecode="r0 |= r6",
            pre_state={
                "R0": MockReg(type="inv", umax=65280),  # scalar
                "R6": MockReg(type="inv", umax=255),
            },
            post_state={},
            opcode_hex="4f",
        )
        conditions = infer_conditions_from_error_insn(insn)
        # R0 is scalar: ARITHMETIC_LEGALITY should be dropped
        arith_conds = [c for c in conditions if c.domain == SafetyDomain.ARITHMETIC_LEGALITY]
        assert len(arith_conds) == 0

    def test_call_from_opcode(self):
        insn = MockInsn(
            bytecode="call bpf_map_lookup_elem",
            pre_state={},
            post_state={},
            opcode_hex="85",
        )
        conditions = infer_conditions_from_error_insn(insn)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.ARG_CONTRACT in domains

    def test_exit_from_opcode(self):
        insn = MockInsn(
            bytecode="exit",
            pre_state={},
            post_state={},
            opcode_hex="95",
        )
        conditions = infer_conditions_from_error_insn(insn)
        domains = {c.domain for c in conditions}
        assert SafetyDomain.REFERENCE_BALANCE in domains

    def test_branch_no_conditions(self):
        insn = MockInsn(
            bytecode="if r3 > 0xfb goto pc+3",
            pre_state={},
            post_state={},
            opcode_hex="25",
        )
        conditions = infer_conditions_from_error_insn(insn)
        assert len(conditions) == 0

    def test_empty_bytecode_returns_empty(self):
        insn = MockInsn(
            bytecode="",
            pre_state={},
            post_state={},
        )
        conditions = infer_conditions_from_error_insn(insn)
        assert len(conditions) == 0


# ---------------------------------------------------------------------------
# Tests: find_violated_condition
# ---------------------------------------------------------------------------

class TestFindViolatedCondition:
    """Test violated condition identification at the error instruction."""

    def test_finds_scalar_bound_violated(self):
        """On r5 += r0 where R0 is unbounded, SCALAR_BOUND on R0 should be violated."""
        insn = MockInsn(
            bytecode="r5 += r0",
            pre_state={
                "R5": MockReg(type="pkt", off=0, range=10),
                "R0": MockReg(type="inv"),  # unbounded
            },
            post_state={},
            opcode_hex="0f",
        )
        conditions = infer_conditions_from_error_insn(insn)
        violated = find_violated_condition(insn, conditions)
        assert violated is not None
        assert violated.domain == SafetyDomain.SCALAR_BOUND
        assert violated.critical_register == "R0"

    def test_finds_null_safety_violated(self):
        """On LDX where src is ptr_or_null, NULL_SAFETY should be violated."""
        insn = MockInsn(
            bytecode="r3 = *(u64 *)(r1 +0)",
            pre_state={
                "R1": MockReg(type="map_value_or_null"),
            },
            post_state={},
            opcode_hex="79",
        )
        conditions = infer_conditions_from_error_insn(insn)
        violated = find_violated_condition(insn, conditions)
        assert violated is not None
        # Either NULL_SAFETY or POINTER_TYPE (ptr_or_null can be caught by either)
        assert violated.domain in {SafetyDomain.NULL_SAFETY, SafetyDomain.POINTER_TYPE}

    def test_returns_first_when_no_violation(self):
        """When all conditions are satisfied/unknown, return first condition as fallback."""
        insn = MockInsn(
            bytecode="r3 = *(u64 *)(r1 +0)",
            pre_state={
                "R1": MockReg(type="map_value", off=0, range=8),
            },
            post_state={},
            opcode_hex="79",
        )
        conditions = infer_conditions_from_error_insn(insn)
        violated = find_violated_condition(insn, conditions)
        # Since all conditions may be satisfied, it falls back to conditions[0]
        assert violated is not None
        assert violated == conditions[0]

    def test_empty_conditions_returns_none(self):
        """When no conditions, find_violated_condition returns None."""
        insn = MockInsn(
            bytecode="if r3 > 5 goto pc+1",  # branch — no conditions
            pre_state={},
            post_state={},
            opcode_hex="2d",
        )
        conditions = infer_conditions_from_error_insn(insn)
        violated = find_violated_condition(insn, conditions)
        assert violated is None


# ---------------------------------------------------------------------------
# Tests: OpcodeConditionPredicate (Predicate adapter)
# ---------------------------------------------------------------------------

class TestOpcodeConditionPredicate:
    """Test the Predicate adapter for SafetyCondition."""

    def test_evaluate_delegates_to_evaluate_condition(self):
        cond = SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="must be bounded",
        )
        pred = OpcodeConditionPredicate(cond)
        state = {"R0": MockReg(type="inv", umax=255)}
        assert pred.evaluate(state) == "satisfied"

    def test_target_regs_is_critical_register(self):
        cond = SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R3",
            required_property="must be pointer",
        )
        pred = OpcodeConditionPredicate(cond)
        assert pred.target_regs == ["R3"]

    def test_describe_violation_includes_details(self):
        cond = SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="must be bounded",
        )
        pred = OpcodeConditionPredicate(cond)
        state = {"R0": MockReg(type="inv")}  # unbounded
        desc = pred.describe_violation(state)
        assert "scalar_bound" in desc
        assert "R0" in desc

    def test_describe_violation_missing_register(self):
        cond = SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R5",
            required_property="must be pointer",
        )
        pred = OpcodeConditionPredicate(cond)
        desc = pred.describe_violation({})  # empty state
        assert "R5" in desc
        assert "not in state" in desc.lower() or "pointer_type" in desc.lower()


# ---------------------------------------------------------------------------
# Tests: Reference case (stackoverflow-70750259)
# ---------------------------------------------------------------------------

class TestReferenceCase:
    """Verify opcode analysis produces correct lifecycle for the reference case."""

    def setup_method(self):
        from interface.extractor.trace_parser import parse_trace
        log = _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
        self.trace = parse_trace(log)

    def test_error_instruction_is_alu_add(self):
        """The error instruction should be r5 += r0 (ALU pointer arithmetic)."""
        error_insns = [i for i in self.trace.instructions if i.is_error]
        assert error_insns, "Should have at least one error instruction"
        # First error should be the r5 += r0 at insn 24
        first_error = error_insns[0]
        assert "r5 += r0" in first_error.bytecode or first_error.insn_idx == 24

    def test_opcode_analysis_finds_scalar_bound_violation(self):
        """The violated condition should be SCALAR_BOUND on R0."""
        error_insns = [i for i in self.trace.instructions if i.is_error]
        assert error_insns
        first_error = error_insns[0]

        conditions = infer_conditions_from_error_insn(first_error)
        assert conditions, "Should derive conditions from ALU instruction"

        violated = find_violated_condition(first_error, conditions)
        assert violated is not None
        assert violated.domain == SafetyDomain.SCALAR_BOUND
        assert violated.critical_register == "R0"

    def test_pipeline_avoids_vacuous_establishment(self):
        """End-to-end: the pipeline should not synthesize establishment from gap=0 at trace start."""
        from interface.extractor.rust_diagnostic import generate_diagnostic
        log = _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
        output = generate_diagnostic(log)

        assert output.json_data["metadata"]["proof_status"] == "never_established"
        assert output.json_data["failure_class"] == "lowering_artifact"


# ---------------------------------------------------------------------------
# Tests: _extract_regs_from_bytecode
# ---------------------------------------------------------------------------

class TestExtractRegsFromBytecode:
    """Test register extraction from bytecode text."""

    def test_ldx(self):
        src, dst = _extract_regs_from_bytecode("r6 = *(u8 *)(r0 +2)")
        assert src == "R0"
        assert dst == "R6"

    def test_stx(self):
        src, dst = _extract_regs_from_bytecode("*(u64 *)(r10 -8) = r1")
        assert src == "R1"
        assert dst == "R10"

    def test_alu_add(self):
        src, dst = _extract_regs_from_bytecode("r5 += r0")
        assert dst == "R5"
        assert src == "R0"

    def test_alu_or(self):
        src, dst = _extract_regs_from_bytecode("r0 |= r6")
        assert dst == "R0"
        assert src == "R6"

    def test_alu_immediate(self):
        src, dst = _extract_regs_from_bytecode("r2 += 1")
        assert dst == "R2"
        assert src is None  # No src register for immediate

    def test_w_register(self):
        """32-bit registers (w0) should normalize to R0."""
        src, dst = _extract_regs_from_bytecode("w0 |= w6")
        assert dst == "R0"
        assert src == "R6"
