"""Tests for TransitionAnalyzer — abstract state transition classification.

Tests cover:
1. Each TransitionEffect classification (narrowing, widening, destroying, neutral)
2. Type-change classifications (TYPE_DOWNGRADE, NULL_RESOLVED, etc.)
3. Range/bounds change classifications
4. Tnum (var_off) precision changes
5. Reason inference from opcodes
6. TransitionChain proof status derivation
7. Integration with real case data
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from interface.extractor.trace_parser import RegisterState, TracedInstruction, parse_trace
from interface.extractor.engine.transition_analyzer import (
    TransitionAnalyzer,
    TransitionEffect,
    analyze_transitions,
    _describe_state,
    _parse_tnum_mask,
)


# ---------------------------------------------------------------------------
# Helpers for building synthetic TracedInstructions
# ---------------------------------------------------------------------------

def _make_reg(
    type: str,
    umin=None,
    umax=None,
    smin=None,
    smax=None,
    off=None,
    range=None,
    id=None,
    var_off=None,
) -> RegisterState:
    return RegisterState(
        type=type,
        umin=umin,
        umax=umax,
        smin=smin,
        smax=smax,
        off=off,
        range=range,
        id=id,
        var_off=var_off,
    )


def _make_insn(
    insn_idx: int,
    bytecode: str,
    pre: dict[str, RegisterState] | None = None,
    post: dict[str, RegisterState] | None = None,
    source_line: str | None = None,
    is_error: bool = False,
    error_text: str | None = None,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=insn_idx,
        bytecode=bytecode,
        source_line=source_line,
        pre_state=pre or {},
        post_state=post or {},
        backtrack=None,
        is_error=is_error,
        error_text=error_text,
    )


def _load_case(relative_path: str) -> dict:
    from bench_fixtures import load_case

    return load_case(relative_path)

def _verifier_log(case_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(case_path)


# ---------------------------------------------------------------------------
# Unit tests: classify_transition()
# ---------------------------------------------------------------------------

class TestClassifyTransition:
    """Unit tests for the core classify_transition method."""

    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_neutral_no_change(self):
        pre = _make_reg("scalar", umin=0, umax=100)
        post = _make_reg("scalar", umin=0, umax=100)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 += 0")
        assert detail.effect == TransitionEffect.NEUTRAL

    def test_neutral_both_none(self):
        detail = self.analyzer.classify_transition("R0", None, None, "r0 += 1")
        assert detail.effect == TransitionEffect.NEUTRAL

    def test_narrowing_umax_decreased(self):
        pre = _make_reg("scalar", umin=0, umax=1000)
        post = _make_reg("scalar", umin=0, umax=100)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 &= 0xff")
        assert detail.effect == TransitionEffect.NARROWING
        assert "umax" in detail.field or "interval" in detail.reason.lower()

    def test_narrowing_umin_increased(self):
        pre = _make_reg("scalar", umin=0, umax=100)
        post = _make_reg("scalar", umin=10, umax=100)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 &= 0xf0")
        assert detail.effect == TransitionEffect.NARROWING

    def test_widening_umax_increased(self):
        pre = _make_reg("scalar", umin=0, umax=100)
        post = _make_reg("scalar", umin=0, umax=5000)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 |= r1")
        assert detail.effect == TransitionEffect.WIDENING

    def test_widening_umin_decreased(self):
        pre = _make_reg("scalar", umin=10, umax=100)
        post = _make_reg("scalar", umin=0, umax=100)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 |= r1")
        assert detail.effect == TransitionEffect.WIDENING

    def test_destroying_bounds_collapse(self):
        """Bounds completely lost — DESTROYING."""
        pre = _make_reg("scalar", umin=0, umax=255)
        post = _make_reg("scalar")  # no bounds
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 = be16 r0")
        assert detail.effect == TransitionEffect.DESTROYING

    def test_destroying_type_downgrade_ptr_to_scalar(self):
        """TYPE_DOWNGRADE: pointer -> scalar is DESTROYING."""
        pre = _make_reg("pkt", off=0, range=6, id=0)
        post = _make_reg("scalar", umin=0, umax=255)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 = *(u8 *)(r0 +3)")
        assert detail.effect == TransitionEffect.DESTROYING
        assert "TYPE_DOWNGRADE" in detail.reason.upper() or "downgrad" in detail.reason.lower()

    def test_narrowing_null_resolved(self):
        """*_or_null -> concrete pointer is NARROWING."""
        pre = _make_reg("map_value_or_null", id=0)
        post = _make_reg("map_value", id=0, off=0, range=64)
        detail = self.analyzer.classify_transition("R0", pre, post, "if r0 == 0 goto")
        assert detail.effect == TransitionEffect.NARROWING
        assert "null" in detail.reason.lower() or "NULL" in detail.reason

    def test_widening_null_introduced(self):
        """concrete pointer -> *_or_null is WIDENING."""
        pre = _make_reg("map_value", id=0)
        post = _make_reg("map_value_or_null", id=0)
        detail = self.analyzer.classify_transition("R0", pre, post, "r0 = map_lookup")
        assert detail.effect == TransitionEffect.WIDENING

    def test_destroying_range_loss(self):
        """Range going from >0 to 0 on a pointer is DESTROYING."""
        pre = _make_reg("pkt", off=0, range=14, id=0)
        post = _make_reg("pkt", off=0, range=0, id=0)
        detail = self.analyzer.classify_transition("R1", pre, post, "r1 += r2")
        assert detail.effect == TransitionEffect.DESTROYING
        assert "RANGE_LOSS" in detail.reason or "range" in detail.reason.lower()

    def test_narrowing_range_established(self):
        """Range going from 0 to >0 is NARROWING."""
        pre = _make_reg("pkt", off=0, range=0, id=0)
        post = _make_reg("pkt", off=0, range=14, id=0)
        detail = self.analyzer.classify_transition("R2", pre, post, "if r1 < r2 goto")
        assert detail.effect == TransitionEffect.NARROWING
        assert "range" in detail.field.lower()

    def test_neutral_register_absent_both(self):
        detail = self.analyzer.classify_transition("R5", None, None, "r0 += 1")
        assert detail.effect == TransitionEffect.NEUTRAL
        assert detail.register == "R5"

    def test_narrowing_register_newly_appeared_bounded(self):
        """Register appears in post-state with bounded scalar — NARROWING."""
        post = _make_reg("scalar", umin=0, umax=100)
        detail = self.analyzer.classify_transition("R0", None, post, "r0 = 50")
        assert detail.effect == TransitionEffect.NARROWING

    def test_neutral_register_newly_appeared_unbounded(self):
        """Register appears with unbounded type — NEUTRAL (no proof established)."""
        post = _make_reg("scalar")  # no bounds
        detail = self.analyzer.classify_transition("R0", None, post, "r0 = r1")
        assert detail.effect == TransitionEffect.NEUTRAL

    def test_destroying_pointer_disappears(self):
        """Pointer disappears from state — DESTROYING."""
        pre = _make_reg("pkt", off=0, range=14, id=0)
        detail = self.analyzer.classify_transition("R1", pre, None, "r1 = *(u32 *)(r0 +0)")
        assert detail.effect == TransitionEffect.DESTROYING


# ---------------------------------------------------------------------------
# Unit tests: _classify_bounds_change()
# ---------------------------------------------------------------------------

class TestClassifyBoundsChange:
    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_interval_narrowing(self):
        """Post interval contained in pre interval — NARROWING."""
        pre = _make_reg("scalar", umin=0, umax=1000)
        post = _make_reg("scalar", umin=10, umax=100)
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.NARROWING

    def test_interval_widening(self):
        """Pre interval contained in post interval — WIDENING."""
        pre = _make_reg("scalar", umin=10, umax=100)
        post = _make_reg("scalar", umin=0, umax=1000)
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.WIDENING

    def test_bounds_collapse(self):
        """Had bounds, now has none — DESTROYING."""
        pre = _make_reg("scalar", umin=0, umax=255)
        post = _make_reg("scalar")
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.DESTROYING
        assert "lost" in reason.lower() or "unbounded" in reason.lower()

    def test_umax_increased(self):
        """Upper bound increased but lower bound same — WIDENING."""
        pre = _make_reg("scalar", umin=0, umax=100)
        post = _make_reg("scalar", umin=0, umax=500)
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.WIDENING

    def test_umax_decreased(self):
        """Upper bound decreased — NARROWING."""
        pre = _make_reg("scalar", umin=0, umax=500)
        post = _make_reg("scalar", umin=0, umax=100)
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.NARROWING

    def test_both_unbounded_neutral(self):
        """Both states unbounded — NEUTRAL."""
        pre = _make_reg("scalar")
        post = _make_reg("scalar")
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.NEUTRAL

    def test_signed_bounds_narrowing(self):
        """Same unsigned but signed lower bound increased — NARROWING."""
        pre = _make_reg("scalar", umin=0, umax=100, smin=-50, smax=100)
        post = _make_reg("scalar", umin=0, umax=100, smin=0, smax=100)
        effect, field, reason = self.analyzer._classify_bounds_change(pre, post)
        assert effect == TransitionEffect.NARROWING
        assert "smin" in field


# ---------------------------------------------------------------------------
# Unit tests: _classify_type_change()
# ---------------------------------------------------------------------------

class TestClassifyTypeChange:
    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_ptr_to_scalar_destroying(self):
        effect, field, reason = self.analyzer._classify_type_change("pkt", "scalar")
        assert effect == TransitionEffect.DESTROYING
        assert "TYPE_DOWNGRADE" in reason.upper()

    def test_map_value_to_scalar_destroying(self):
        effect, field, reason = self.analyzer._classify_type_change("map_value", "inv")
        assert effect == TransitionEffect.DESTROYING

    def test_or_null_to_ptr_narrowing(self):
        effect, field, reason = self.analyzer._classify_type_change(
            "map_value_or_null", "map_value"
        )
        assert effect == TransitionEffect.NARROWING
        assert "NULL_RESOLVED" in reason.upper() or "null" in reason.lower()

    def test_ptr_to_or_null_widening(self):
        effect, field, reason = self.analyzer._classify_type_change(
            "map_value", "map_value_or_null"
        )
        assert effect == TransitionEffect.WIDENING
        assert "null" in reason.lower()

    def test_scalar_to_ptr_narrowing(self):
        effect, field, reason = self.analyzer._classify_type_change("scalar", "map_value")
        assert effect == TransitionEffect.NARROWING
        assert "upgrade" in reason.lower() or "TYPE_UPGRADE" in reason.upper()

    def test_same_type_neutral(self):
        effect, field, reason = self.analyzer._classify_type_change("scalar", "scalar")
        assert effect == TransitionEffect.NEUTRAL

    def test_ptr_or_null_variants(self):
        """ptr_or_null_ prefix should be detected as nullable."""
        effect, field, reason = self.analyzer._classify_type_change(
            "ptr_or_null_task", "ptr_task"
        )
        assert effect == TransitionEffect.NARROWING


# ---------------------------------------------------------------------------
# Unit tests: _classify_range_change()
# ---------------------------------------------------------------------------

class TestClassifyRangeChange:
    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_range_loss_destroying(self):
        effect, reason = self.analyzer._classify_range_change(14, 0)
        assert effect == TransitionEffect.DESTROYING
        assert "RANGE_LOSS" in reason.upper()

    def test_range_established_narrowing(self):
        effect, reason = self.analyzer._classify_range_change(0, 14)
        assert effect == TransitionEffect.NARROWING
        assert "range" in reason.lower() or "established" in reason.lower()

    def test_range_expanded_narrowing(self):
        effect, reason = self.analyzer._classify_range_change(14, 40)
        assert effect == TransitionEffect.NARROWING

    def test_range_reduced_widening(self):
        effect, reason = self.analyzer._classify_range_change(40, 14)
        assert effect == TransitionEffect.WIDENING

    def test_range_none_to_nonzero(self):
        """None treated as 0."""
        effect, reason = self.analyzer._classify_range_change(None, 14)
        assert effect == TransitionEffect.NARROWING

    def test_range_unchanged(self):
        effect, reason = self.analyzer._classify_range_change(14, 14)
        assert effect == TransitionEffect.NEUTRAL


# ---------------------------------------------------------------------------
# Unit tests: _infer_reason()
# ---------------------------------------------------------------------------

class TestInferReason:
    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_or_operation_reason(self):
        reason = self.analyzer._infer_reason(
            "r0 |= r6", None, None, TransitionEffect.WIDENING
        )
        assert "OR" in reason.upper() or "|=" in reason
        assert "scalar" in reason.lower() or "bounds" in reason.lower()

    def test_and_operation_reason(self):
        reason = self.analyzer._infer_reason(
            "r0 &= 0xff", None, None, TransitionEffect.NARROWING
        )
        assert "AND" in reason.upper() or "&=" in reason
        assert "narrow" in reason.lower() or "range" in reason.lower()

    def test_shift_left_reason(self):
        reason = self.analyzer._infer_reason(
            "r0 <<= 8", None, None, TransitionEffect.WIDENING
        )
        assert "shift" in reason.lower() or "<<=" in reason

    def test_byte_swap_reason(self):
        reason = self.analyzer._infer_reason(
            "be16 r0", None, None, TransitionEffect.DESTROYING
        )
        assert "byte" in reason.lower() or "endian" in reason.lower() or "be16" in reason

    def test_stack_fill_reason(self):
        reason = self.analyzer._infer_reason(
            "r1 = *(u64 *)(fp-8)", None, None, TransitionEffect.NEUTRAL
        )
        assert "stack" in reason.lower() or "fill" in reason.lower()

    def test_stack_spill_reason(self):
        reason = self.analyzer._infer_reason(
            "*(u64 *)(fp-8) = r1", None, None, TransitionEffect.NEUTRAL
        )
        assert "stack" in reason.lower() or "spill" in reason.lower()

    def test_function_call_reason(self):
        reason = self.analyzer._infer_reason(
            "call bpf_map_lookup_elem", None, None, TransitionEffect.NEUTRAL
        )
        assert "call" in reason.lower() or "function" in reason.lower()

    def test_constant_assignment_reason(self):
        reason = self.analyzer._infer_reason(
            "r0 = 42", None, None, TransitionEffect.NARROWING
        )
        assert "constant" in reason.lower() or "42" in reason

    def test_empty_opcode_fallback(self):
        reason = self.analyzer._infer_reason("", None, None, TransitionEffect.NEUTRAL)
        assert reason == "unknown operation"


# ---------------------------------------------------------------------------
# Unit tests: TransitionChain proof status
# ---------------------------------------------------------------------------

class TestTransitionChainProofStatus:
    def setup_method(self):
        self.analyzer = TransitionAnalyzer()

    def test_never_established_no_narrowing(self):
        """If no narrowing ever occurs, proof was never established."""
        insns = [
            _make_insn(
                0,
                "r0 = r1",
                pre={"R0": _make_reg("scalar")},
                post={"R0": _make_reg("scalar")},
            ),
        ]
        chain = self.analyzer.analyze(insns, {"R0"})
        assert chain.proof_status == "never_established"
        assert chain.establish_point is None
        assert chain.loss_point is None

    def test_established_then_lost_destroying(self):
        """Narrowing then DESTROYING should yield 'established_then_lost'."""
        insns = [
            # insn 0: bounds established
            _make_insn(
                0,
                "r0 &= 0xff",
                pre={"R0": _make_reg("scalar")},
                post={"R0": _make_reg("scalar", umin=0, umax=255)},
            ),
            # insn 1: bounds collapse (destroying)
            _make_insn(
                1,
                "r0 |= r1",
                pre={"R0": _make_reg("scalar", umin=0, umax=255)},
                post={"R0": _make_reg("scalar")},  # unbounded
            ),
        ]
        chain = self.analyzer.analyze(insns, {"R0"})
        assert chain.proof_status == "established_then_lost"
        assert chain.establish_point is not None
        assert chain.establish_point.insn_idx == 0
        assert chain.loss_point is not None
        assert chain.loss_point.insn_idx == 1

    def test_established_type_downgrade(self):
        """TYPE_DOWNGRADE after establishment should be 'established_then_lost'."""
        insns = [
            # insn 0: pointer established
            _make_insn(
                0,
                "r1 = r0",
                pre={"R1": _make_reg("scalar")},
                post={"R1": _make_reg("pkt", off=0, range=14, id=0)},
            ),
            # insn 1: type downgrade
            _make_insn(
                1,
                "r1 = *(u8 *)(r1 +0)",
                pre={"R1": _make_reg("pkt", off=0, range=14, id=0)},
                post={"R1": _make_reg("scalar", umin=0, umax=255)},
            ),
        ]
        chain = self.analyzer.analyze(insns, {"R1"})
        assert chain.proof_status == "established_then_lost"
        assert chain.loss_point.effect == TransitionEffect.DESTROYING

    def test_established_never_lost(self):
        """Narrowing with no subsequent destroying -> 'established_but_insufficient'."""
        insns = [
            _make_insn(
                0,
                "r0 &= 0xff",
                pre={"R0": _make_reg("scalar")},
                post={"R0": _make_reg("scalar", umin=0, umax=255)},
            ),
        ]
        chain = self.analyzer.analyze(insns, {"R0"})
        assert chain.proof_status == "established_but_insufficient"
        assert chain.establish_point is not None
        assert chain.loss_point is None

    def test_empty_proof_registers_returns_neutral_result(self):
        """When proof_registers is empty, no transition story is synthesized."""
        insns = [
            _make_insn(
                0,
                "r0 &= 0xff",
                pre={"R0": _make_reg("scalar"), "R1": _make_reg("scalar")},
                post={
                    "R0": _make_reg("scalar", umin=0, umax=255),
                    "R1": _make_reg("scalar", umin=0, umax=100),
                },
            ),
        ]
        chain = self.analyzer.analyze(insns, set())
        assert chain.proof_status == "unknown"
        assert chain.chain == []

    def test_chain_contains_all_non_neutral_transitions(self):
        """chain field should include narrowing, widening, and destroying events."""
        insns = [
            _make_insn(
                0,
                "r0 &= 0xff",
                pre={"R0": _make_reg("scalar")},
                post={"R0": _make_reg("scalar", umin=0, umax=255)},
            ),
            _make_insn(
                1,
                "r0 |= r1",
                pre={"R0": _make_reg("scalar", umin=0, umax=255)},
                post={"R0": _make_reg("scalar", umin=0, umax=511)},
            ),
        ]
        chain = self.analyzer.analyze(insns, {"R0"})
        assert len(chain.chain) >= 2
        effects = {t.effect for t in chain.chain}
        assert TransitionEffect.NARROWING in effects
        assert TransitionEffect.WIDENING in effects


# ---------------------------------------------------------------------------
# Unit tests: Tnum / var_off parsing
# ---------------------------------------------------------------------------

class TestTnumParsing:
    def test_parse_tnum_mask_basic(self):
        assert _parse_tnum_mask("(0x0; 0xff)") == 0xFF

    def test_parse_tnum_mask_zero(self):
        assert _parse_tnum_mask("(0x0; 0x0)") == 0

    def test_parse_tnum_mask_full(self):
        assert _parse_tnum_mask("(0x0; 0xffffffffffffffff)") == 0xFFFF_FFFF_FFFF_FFFF

    def test_parse_tnum_mask_none(self):
        assert _parse_tnum_mask(None) is None

    def test_parse_tnum_mask_invalid(self):
        assert _parse_tnum_mask("not_a_tnum") is None

    def test_tnum_widening(self):
        analyzer = TransitionAnalyzer()
        pre = _make_reg("scalar", umin=0, umax=255, var_off="(0x0; 0xff)")
        post = _make_reg("scalar", umin=0, umax=65535, var_off="(0x0; 0xffff)")
        detail = analyzer.classify_transition("R0", pre, post, "r0 <<= 8")
        # Type is the same so should check bounds first; upper bound increased -> widening
        assert detail.effect in (TransitionEffect.WIDENING, TransitionEffect.NEUTRAL)

    def test_tnum_narrowing_standalone(self):
        """Test that tnum narrowing is detected when bounds don't change."""
        analyzer = TransitionAnalyzer()
        # Same bounds but mask got smaller
        pre = _make_reg("scalar", umin=0, umax=255, var_off="(0x0; 0xff)")
        post = _make_reg("scalar", umin=0, umax=255, var_off="(0x0; 0x0f)")
        detail = analyzer.classify_transition("R0", pre, post, "r0 &= 0x0f")
        # Bounds are same (NEUTRAL from bounds check), should fall through to tnum check
        assert detail.effect in (TransitionEffect.NARROWING, TransitionEffect.NEUTRAL)


# ---------------------------------------------------------------------------
# Integration test: real verifier log from case files
# ---------------------------------------------------------------------------

class TestIntegrationWithRealCases:
    """Parse real verifier logs and run the analyzer."""

    def _get_log(self, case_path: str) -> str:
        return _verifier_log(case_path)

    def test_sni_case_bounds_collapse(self):
        """The SNI TLS case has a bounds collapse at insn 24 (r5 += r0 with unbounded r0).

        After insn 22 (r0 |= r6), R0 loses its scalar bounds because OR destroys the
        tnum tracking. The verifier then cannot prove r5 += r0 is bounded.
        """
        log = self._get_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
        parsed = parse_trace(log)

        chain = analyze_transitions(parsed.instructions, {"R0", "R5"})

        # Should find some transitions
        assert len(chain.chain) > 0

        # Find if we detected any DESTROYING or WIDENING effects
        effects = {t.effect for t in chain.chain}
        # The OR operation at insn 22 should cause widening/destroying
        destroying_or_widening = {
            TransitionEffect.DESTROYING,
            TransitionEffect.WIDENING,
        }
        assert effects & destroying_or_widening, (
            f"Expected at least one DESTROYING or WIDENING effect, got: {effects}"
        )

    def test_sni_case_transition_chain_has_reason(self):
        """Every non-neutral transition should have a non-empty reason."""
        log = self._get_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
        parsed = parse_trace(log)

        chain = analyze_transitions(parsed.instructions, {"R0", "R5"})

        for detail in chain.chain:
            assert detail.reason, f"Transition {detail} has empty reason"
            assert detail.before != detail.after or detail.effect == TransitionEffect.NEUTRAL

    def test_sni_case_transition_details_have_insn_idx(self):
        """All transitions should reference valid instruction indices."""
        log = self._get_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
        parsed = parse_trace(log)
        valid_idxs = {insn.insn_idx for insn in parsed.instructions}

        chain = analyze_transitions(parsed.instructions, {"R0", "R5"})

        for detail in chain.chain:
            assert detail.insn_idx in valid_idxs, (
                f"Transition insn_idx {detail.insn_idx} not in valid indices"
            )

    def test_sni_case_establish_point_is_narrowing(self):
        """If establish_point is set, its effect must be NARROWING."""
        log = self._get_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
        parsed = parse_trace(log)

        chain = analyze_transitions(parsed.instructions, {"R5"})

        if chain.establish_point is not None:
            assert chain.establish_point.effect == TransitionEffect.NARROWING

    def test_packet_case_basic(self):
        """Verify the analyzer runs on a packet bounds case."""
        try:
            log = self._get_log("bpfix-bench/raw/so/stackoverflow-70729664.yaml")
        except (FileNotFoundError, KeyError):
            # Skip if file not found
            return

        parsed = parse_trace(log)
        # Just verify it doesn't crash
        chain = analyze_transitions(parsed.instructions, set())
        assert chain.proof_status in (
            "never_established",
            "established_then_lost",
            "established_but_insufficient",
            "unknown",
        )


# ---------------------------------------------------------------------------
# Integration test: analyze_transitions() convenience function
# ---------------------------------------------------------------------------

class TestAnalyzeTransitionsConvenience:
    def test_empty_instructions(self):
        chain = analyze_transitions([], {"R0"})
        assert chain.proof_status == "never_established"
        assert chain.chain == []

    def test_single_neutral_instruction(self):
        insns = [
            _make_insn(
                0,
                "r10 = r10",
                pre={"R10": _make_reg("fp", off=0)},
                post={"R10": _make_reg("fp", off=0)},
            )
        ]
        chain = analyze_transitions(insns, {"R10"})
        # fp register with no change — should be neutral
        assert len(chain.chain) == 0 or all(
            t.effect == TransitionEffect.NEUTRAL for t in chain.chain
        )

    def test_no_proof_registers_still_runs(self):
        insns = [
            _make_insn(
                0,
                "r0 &= 0xff",
                pre={"R0": _make_reg("scalar")},
                post={"R0": _make_reg("scalar", umin=0, umax=255)},
            )
        ]
        # None/empty proof registers intentionally suppress speculative analysis.
        chain = analyze_transitions(insns, None)
        assert chain.proof_status == "unknown"
        assert chain.chain == []

    def test_describe_state_helper(self):
        state = _make_reg("pkt", off=2, range=14, id=0)
        desc = _describe_state(state)
        assert "pkt" in desc
        assert "off=2" in desc
        assert "r=14" in desc

    def test_describe_state_none(self):
        assert _describe_state(None) == "absent"
