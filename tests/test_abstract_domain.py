"""Tests for interface/extractor/abstract_domain.py

Covers:
  - ScalarBounds construction and interval arithmetic
  - PointerState construction
  - Parsing from verifier state strings (parse_scalar_bounds, parse_pointer_state)
  - Parsing from existing RegisterState dataclass objects
  - Predicate evaluators with known good/bad states
  - Edge cases: missing fields, partial state, unknown values

NOTE: tnum_add/tnum_and/tnum_or/tnum_lshift are arithmetic helpers not called
directly in the pipeline (only referenced as formal spec strings in
obligation_catalog_formal.py). Tests for those dead-code paths are omitted.
The tnum_upper_bound/lower_bound/is_const/contains helpers are exercised
indirectly through the ScalarBounds high-level methods tested here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from interface.extractor.abstract_domain import (
    S64_MAX,
    S64_MIN,
    U64_MAX,
    PointerState,
    ScalarBounds,
    eval_atom_abstract,
    eval_map_value_access,
    eval_null_check,
    eval_packet_access,
    eval_scalar_in_range,
    eval_scalar_non_negative,
    eval_scalar_upper_bound,
    eval_stack_access,
    eval_tnum_bits,
    eval_type_match,
    parse_pointer_state,
    parse_scalar_bounds,
    pointer_state_from_register_state,
    scalar_bounds_from_register_state,
)
from interface.extractor.trace_parser import RegisterState

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_case(relative_path: str) -> dict:
    path = ROOT / relative_path
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _block(case_path: str, index: int) -> str:
    payload = _load_case(case_path)
    return payload["verifier_log"]["blocks"][index]


def _reg(type_: str, **kwargs):
    """Convenience factory for RegisterState."""
    return RegisterState(type=type_, **kwargs)


# ===========================================================================
# ScalarBounds — construction and basic methods
# ===========================================================================


class TestScalarBoundsDefaults:
    def test_defaults_cover_full_range(self):
        sb = ScalarBounds()
        assert sb.umin == 0
        assert sb.umax == U64_MAX
        assert sb.smin == S64_MIN
        assert sb.smax == S64_MAX
        assert sb.var_off_value == 0
        assert sb.var_off_mask == U64_MAX

    def test_default_not_bounded(self):
        sb = ScalarBounds()
        assert not sb.is_bounded()

    def test_not_const(self):
        sb = ScalarBounds()
        assert not sb.is_const()


class TestScalarBoundsBounded:
    def test_umax_bound(self):
        sb = ScalarBounds(umin=0, umax=255, smin=0, smax=255)
        assert sb.is_bounded()

    def test_umin_bound(self):
        sb = ScalarBounds(umin=10, umax=U64_MAX, smin=S64_MIN, smax=S64_MAX)
        assert sb.is_bounded()

    def test_const(self):
        sb = ScalarBounds(umin=42, umax=42, smin=42, smax=42,
                          var_off_value=42, var_off_mask=0)
        assert sb.is_const()
        assert sb.is_bounded()

    def test_zero_const(self):
        sb = ScalarBounds(umin=0, umax=0, smin=0, smax=0,
                          var_off_value=0, var_off_mask=0)
        assert sb.is_const()

    def test_tnum_only_bounded(self):
        # var_off=(0x0; 0xff) means low byte unknown — tnum constrains even when
        # interval bounds are still at defaults (e.g., before verifier propagates umax).
        # A scalar like `r0 &= 0xff` will have var_off_mask=0xff < U64_MAX → bounded.
        sb = ScalarBounds(umin=0, umax=U64_MAX, smin=S64_MIN, smax=S64_MAX,
                          var_off_value=0, var_off_mask=0xFF)
        assert sb.is_bounded()

    def test_fully_unknown_tnum_not_bounded(self):
        # var_off_mask=U64_MAX (all bits unknown) adds no constraint.
        sb = ScalarBounds(umin=0, umax=U64_MAX, smin=S64_MIN, smax=S64_MAX,
                          var_off_value=0, var_off_mask=U64_MAX)
        assert not sb.is_bounded()


class TestScalarBoundsContains:
    def test_contains_within(self):
        sb = ScalarBounds(umin=0, umax=255, var_off_value=0, var_off_mask=0xFF)
        # 0..255 with var_off all bits unknown -> any byte value possible
        assert sb.contains(0)
        assert sb.contains(128)
        assert sb.contains(255)

    def test_contains_outside_interval(self):
        sb = ScalarBounds(umin=0, umax=100, var_off_value=0, var_off_mask=0xFF)
        assert not sb.contains(101)

    def test_contains_tnum_filtered(self):
        # var_off=(0x0; 0x0) means constant 0 — only 0 is valid
        sb = ScalarBounds(umin=0, umax=255, var_off_value=0, var_off_mask=0)
        assert sb.contains(0)
        assert not sb.contains(1)
        assert not sb.contains(255)

    def test_contains_aligned_only(self):
        # var_off=(0x0; 0xFE) means bit 0 is known zero -> only even values
        sb = ScalarBounds(umin=0, umax=255, var_off_value=0, var_off_mask=0xFE)
        assert sb.contains(0)
        assert sb.contains(2)
        assert sb.contains(254)
        assert not sb.contains(1)
        assert not sb.contains(3)


class TestScalarBoundsUpperLower:
    def test_upper_bound_uses_tnum(self):
        # umax=1000 but tnum says only low byte unknown -> upper bound is 0xFF
        sb = ScalarBounds(umin=0, umax=1000,
                          var_off_value=0, var_off_mask=0xFF)
        assert sb.upper_bound() == min(1000, 0xFF)

    def test_upper_bound_uses_umax_when_tnum_looser(self):
        # tnum fully unknown but umax=50
        sb = ScalarBounds(umin=0, umax=50, var_off_value=0, var_off_mask=U64_MAX)
        assert sb.upper_bound() == 50  # umax is tighter

    def test_lower_bound_uses_umin(self):
        # tnum lower bound = var_off_value (unknown bits -> 0)
        # umin=10, var_off_value=0 -> max(10, 0) = 10
        sb = ScalarBounds(umin=10, umax=200,
                          var_off_value=0, var_off_mask=0xFF)
        assert sb.lower_bound() == 10

    def test_lower_bound_uses_tnum_when_tighter(self):
        # umin=0, var_off_value=0x10 (bit 4 known set) -> lb=16
        sb = ScalarBounds(umin=0, umax=255,
                          var_off_value=0x10, var_off_mask=0x0F)
        # tnum lower bound = var_off_value = 0x10 = 16
        assert sb.lower_bound() == max(0, 0x10)

    def test_signed_bounds(self):
        sb = ScalarBounds(smin=-100, smax=50)
        assert sb.signed_lower_bound() == -100
        assert sb.signed_upper_bound() == 50


# ===========================================================================
# PointerState — construction and basic methods
# ===========================================================================


class TestPointerState:
    def test_is_packet(self):
        ps = PointerState(type="pkt", off=14, range=34)
        assert ps.is_packet()
        assert not ps.is_map_value()
        assert not ps.is_null_possible()

    def test_is_map_value(self):
        ps = PointerState(type="map_value", off=0, ks=4, vs=8)
        assert ps.is_map_value()
        assert not ps.is_packet()

    def test_is_null_possible(self):
        ps = PointerState(type="map_value_or_null")
        assert ps.is_null_possible()

    def test_is_stack(self):
        ps = PointerState(type="fp", off=-8)
        assert ps.is_stack()

    def test_is_ctx(self):
        ps = PointerState(type="ctx")
        assert ps.is_ctx()


# ===========================================================================
# Parsing from verifier state strings
# ===========================================================================


class TestParseScalarBounds:
    """Test parse_scalar_bounds() with real verifier state strings."""

    def test_inv_with_umax_and_var_off(self):
        # R1=inv(id=0,umax_value=255,var_off=(0x0; 0xff))
        sb = parse_scalar_bounds("inv(id=0,umax_value=255,var_off=(0x0; 0xff))")
        assert sb is not None
        assert sb.umax == 255
        assert sb.umin == 0
        assert sb.var_off_value == 0
        assert sb.var_off_mask == 0xFF

    def test_inv_constant_zero(self):
        # inv0
        sb = parse_scalar_bounds("inv0")
        assert sb is not None
        assert sb.umin == 0
        assert sb.umax == 0
        assert sb.is_const()

    def test_inv_constant_nonzero(self):
        # inv42
        sb = parse_scalar_bounds("inv42")
        assert sb is not None
        assert sb.umin == 42
        assert sb.umax == 42
        assert sb.is_const()

    def test_inv_constant_hex(self):
        sb = parse_scalar_bounds("inv0x10")
        assert sb is not None
        assert sb.umin == 16
        assert sb.umax == 16

    def test_invP(self):
        # invP is a "precise" variant of inv
        sb = parse_scalar_bounds("invP(id=0,umax_value=65535,var_off=(0x0; 0xffff))")
        assert sb is not None
        assert sb.umax == 65535
        assert sb.var_off_mask == 0xFFFF

    def test_inv_large_umax(self):
        # R1_r=inv(id=0,umax_value=4294967295,...) from real log
        sb = parse_scalar_bounds(
            "inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff))"
        )
        assert sb is not None
        assert sb.umax == 4294967295
        assert sb.var_off_mask == 0xFFFFFFFF

    def test_scalar_bare(self):
        # "scalar" with no parens -> fully unknown
        sb = parse_scalar_bounds("scalar")
        assert sb is not None
        assert sb.umax == U64_MAX
        assert not sb.is_bounded()

    def test_pointer_type_returns_none(self):
        # Pointer types must not parse as scalar
        assert parse_scalar_bounds("pkt(id=0,off=14,r=34,imm=0)") is None
        assert parse_scalar_bounds("map_value(id=0,off=0,ks=4,vs=8,imm=0)") is None
        assert parse_scalar_bounds("ctx(id=0,off=0,imm=0)") is None
        assert parse_scalar_bounds("fp-8") is None

    def test_inv_with_tnum_left_shift(self):
        # var_off=(0x0; 0xff00) after left shift by 8
        sb = parse_scalar_bounds("inv(id=0,umax_value=65280,var_off=(0x0; 0xff00))")
        assert sb is not None
        assert sb.umax == 65280
        assert sb.var_off_mask == 0xFF00


class TestParsePointerState:
    """Test parse_pointer_state() with real verifier state strings."""

    def test_pkt_pointer(self):
        # R0=pkt(id=0,off=14,r=34,imm=0)
        ps = parse_pointer_state("pkt(id=0,off=14,r=34,imm=0)")
        assert ps is not None
        assert ps.type == "pkt"
        assert ps.off == 14
        assert ps.range == 34
        assert ps.id == 0

    def test_pkt_with_scalar_fields(self):
        # pkt with umin_value/umax_value from real log
        ps = parse_pointer_state(
            "pkt(id=65,off=37,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff))"
        )
        assert ps is not None
        assert ps.type == "pkt"
        assert ps.off == 37
        assert ps.range == 55

    def test_pkt_end(self):
        ps = parse_pointer_state("pkt_end(id=0,off=0,imm=0)")
        assert ps is not None
        assert ps.type == "pkt_end"
        assert ps.off == 0

    def test_map_value(self):
        # R2=map_value(off=0,ks=4,vs=8,imm=0)
        ps = parse_pointer_state("map_value(id=0,off=0,ks=4,vs=8,imm=0)")
        assert ps is not None
        assert ps.type == "map_value"
        assert ps.off == 0
        assert ps.ks == 4
        assert ps.vs == 8

    def test_ctx(self):
        ps = parse_pointer_state("ctx(id=0,off=0,imm=0)")
        assert ps is not None
        assert ps.type == "ctx"

    def test_fp_shorthand(self):
        ps = parse_pointer_state("fp-8")
        assert ps is not None
        assert ps.type == "fp"
        assert ps.off == -8

    def test_scalar_returns_none(self):
        assert parse_pointer_state("inv(id=0,umax_value=255,var_off=(0x0; 0xff))") is None
        assert parse_pointer_state("inv0") is None

    def test_map_value_or_null(self):
        ps = parse_pointer_state("map_value_or_null(id=0,off=0,ks=4,vs=8,imm=0)")
        assert ps is not None
        assert ps.is_null_possible()


# ===========================================================================
# Parsing from RegisterState objects
# ===========================================================================


class TestFromRegisterState:
    def test_scalar_bounds_full_fields(self):
        reg = _reg("inv", umin=0, umax=255, smin=0, smax=255,
                   var_off="(0x0; 0xff)")
        sb = scalar_bounds_from_register_state(reg)
        assert sb.umax == 255
        assert sb.umin == 0
        assert sb.var_off_mask == 0xFF

    def test_scalar_bounds_partial_fields(self):
        reg = _reg("inv", umax=1000)
        sb = scalar_bounds_from_register_state(reg)
        assert sb.umax == 1000
        assert sb.umin == 0  # default

    def test_scalar_bounds_no_var_off(self):
        reg = _reg("inv", umin=10, umax=20)
        sb = scalar_bounds_from_register_state(reg)
        # var_off not set -> stays fully unknown
        assert sb.var_off_mask == U64_MAX

    def test_pointer_state_pkt(self):
        reg = _reg("pkt", off=14, range=34, id=0)
        ps = pointer_state_from_register_state(reg)
        assert ps.type == "pkt"
        assert ps.off == 14
        assert ps.range == 34
        assert ps.id == 0

    def test_pointer_state_defaults(self):
        reg = _reg("pkt")
        ps = pointer_state_from_register_state(reg)
        assert ps.off == 0
        assert ps.range == 0

    def test_pointer_state_negative_off(self):
        reg = _reg("fp", off=-8)
        ps = pointer_state_from_register_state(reg)
        assert ps.off == -8



# ===========================================================================
# Predicate evaluators
# ===========================================================================


class TestEvalPacketAccess:
    def test_satisfied_fixed_access(self):
        # pkt(off=14, r=34) + access_size=4: 14+4=18 <= 34 -> satisfied
        ptr = PointerState(type="pkt", off=14, range=34)
        result = eval_packet_access(ptr, None, 4)
        assert result == "satisfied"

    def test_violated_fixed_access(self):
        # pkt(off=30, r=34) + access_size=8: 30+8=38 > 34 -> violated
        ptr = PointerState(type="pkt", off=30, range=34)
        result = eval_packet_access(ptr, None, 8)
        assert result == "violated"

    def test_satisfied_with_index(self):
        # pkt(off=14, r=40), index=[0,10], size=4: worst=14+10+4=28 <= 40
        ptr = PointerState(type="pkt", off=14, range=40)
        idx = ScalarBounds(umin=0, umax=10, var_off_value=0, var_off_mask=0xF)
        result = eval_packet_access(ptr, idx, 4)
        assert result == "satisfied"

    def test_violated_with_index(self):
        # pkt(off=14, r=34), index=[5,255], size=1: best=14+5+1=20>34? No.
        # worst=14+255+1=270 > 34, best=14+5+1=20 <= 34 -> unknown
        ptr = PointerState(type="pkt", off=14, range=34)
        idx = ScalarBounds(umin=5, umax=255, var_off_value=0, var_off_mask=0xFF)
        result = eval_packet_access(ptr, idx, 1)
        assert result == "unknown"

    def test_definitely_violated_with_large_index(self):
        # pkt(off=14, r=34), index=[100,255], size=1: best=14+100+1=115>34
        ptr = PointerState(type="pkt", off=14, range=34)
        idx = ScalarBounds(umin=100, umax=255)
        result = eval_packet_access(ptr, idx, 1)
        assert result == "violated"

    def test_zero_range_always_violated(self):
        ptr = PointerState(type="pkt", off=0, range=0)
        result = eval_packet_access(ptr, None, 1)
        assert result == "violated"

    def test_exactly_at_boundary(self):
        # off=30, size=4, range=34: 30+4=34 == 34 -> satisfied
        ptr = PointerState(type="pkt", off=30, range=34)
        result = eval_packet_access(ptr, None, 4)
        assert result == "satisfied"

    def test_one_past_boundary(self):
        # off=31, size=4, range=34: 31+4=35 > 34 -> violated
        ptr = PointerState(type="pkt", off=31, range=34)
        result = eval_packet_access(ptr, None, 4)
        assert result == "violated"


class TestEvalNullCheck:
    def test_non_null_satisfied(self):
        ps = PointerState(type="map_value")
        assert eval_null_check(ps) == "satisfied"

    def test_or_null_violated(self):
        ps = PointerState(type="map_value_or_null")
        assert eval_null_check(ps) == "violated"

    def test_ptr_or_null_violated(self):
        ps = PointerState(type="ptr_or_null")
        assert eval_null_check(ps) == "violated"

    def test_pkt_non_null(self):
        ps = PointerState(type="pkt")
        assert eval_null_check(ps) == "satisfied"


class TestEvalScalarInRange:
    def test_fully_within(self):
        sb = ScalarBounds(umin=0, umax=100)
        assert eval_scalar_in_range(sb, 0, 255) == "satisfied"

    def test_fully_outside(self):
        sb = ScalarBounds(umin=300, umax=400)
        assert eval_scalar_in_range(sb, 0, 255) == "violated"

    def test_partial_overlap(self):
        sb = ScalarBounds(umin=200, umax=300)
        assert eval_scalar_in_range(sb, 0, 255) == "unknown"

    def test_exact_match(self):
        sb = ScalarBounds(umin=42, umax=42)
        assert eval_scalar_in_range(sb, 42, 42) == "satisfied"


class TestEvalScalarNonNegative:
    def test_all_positive(self):
        sb = ScalarBounds(umin=0, umax=255, smin=0, smax=255)
        assert eval_scalar_non_negative(sb) == "satisfied"

    def test_all_negative(self):
        sb = ScalarBounds(smin=-100, smax=-1)
        assert eval_scalar_non_negative(sb) == "violated"

    def test_straddles_zero(self):
        sb = ScalarBounds(smin=-50, smax=50)
        assert eval_scalar_non_negative(sb) == "unknown"

    def test_zero_is_non_negative(self):
        sb = ScalarBounds(umin=0, umax=0, smin=0, smax=0)
        assert eval_scalar_non_negative(sb) == "satisfied"


class TestEvalScalarUpperBound:
    def test_within(self):
        sb = ScalarBounds(umin=0, umax=100, var_off_value=0, var_off_mask=0x7F)
        # tnum upper bound = 0x7F = 127, umax = 100, min(100, 127) = 100 <= 200
        assert eval_scalar_upper_bound(sb, 200) == "satisfied"

    def test_tnum_tightens(self):
        # umax = 1000 but tnum says only low byte -> upper = min(1000, 255) = 255
        sb = ScalarBounds(umin=0, umax=1000, var_off_value=0, var_off_mask=0xFF)
        assert eval_scalar_upper_bound(sb, 255) == "satisfied"

    def test_violated_when_lb_exceeds_limit(self):
        sb = ScalarBounds(umin=300, umax=400)
        assert eval_scalar_upper_bound(sb, 255) == "violated"

    def test_unknown_when_partially_overlapping(self):
        # lb = 0, ub = 300 with limit 255 -> partial overlap
        sb = ScalarBounds(umin=0, umax=300, var_off_value=0, var_off_mask=U64_MAX)
        assert eval_scalar_upper_bound(sb, 255) == "unknown"


class TestEvalMapValueAccess:
    def test_satisfied_fixed_offset(self):
        ptr = PointerState(type="map_value", off=0, vs=8)
        result = eval_map_value_access(ptr, None, 4, map_value_size=8)
        assert result == "satisfied"

    def test_violated_fixed_offset(self):
        ptr = PointerState(type="map_value", off=4, vs=8)
        result = eval_map_value_access(ptr, None, 8, map_value_size=8)
        assert result == "violated"

    def test_with_variable_index_unknown(self):
        # off=0, index=[0,10], size=4, map_vs=8
        # worst case: 0 + 10 + 4 = 14 > 8 (exceeds)
        # best case:  0 + 0  + 4 = 4 <= 8 (within)
        # -> unknown (ambiguous depending on concrete index value)
        ptr = PointerState(type="map_value", off=0, vs=8)
        idx = ScalarBounds(umin=0, umax=10)
        result = eval_map_value_access(ptr, idx, 4, map_value_size=8)
        assert result == "unknown"

    def test_with_variable_index_definitely_violated(self):
        # off=0, index=[5,10], size=4, map_vs=8
        # worst case: 0 + 10 + 4 = 14 > 8
        # best case:  0 + 5  + 4 = 9  > 8 -> definitely violated
        ptr = PointerState(type="map_value", off=0, vs=8)
        idx = ScalarBounds(umin=5, umax=10)
        result = eval_map_value_access(ptr, idx, 4, map_value_size=8)
        assert result == "violated"

    def test_unknown_without_size(self):
        ptr = PointerState(type="map_value", off=0, vs=0, range=0)
        result = eval_map_value_access(ptr, None, 4, map_value_size=0)
        assert result == "unknown"


class TestEvalStackAccess:
    def test_within_frame(self):
        assert eval_stack_access(-8, 8) == "satisfied"

    def test_at_frame_limit(self):
        # fp-512 is the lowest valid byte; accessing 1 byte there:
        # off=-512 >= -512 AND -512+1=-511 <= 0 -> satisfied
        assert eval_stack_access(-512, 1, frame_size=512) == "satisfied"

    def test_exceeded_frame_low(self):
        # fp-513 is one byte below the frame bottom
        assert eval_stack_access(-513, 1, frame_size=512) == "violated"

    def test_exceeded_frame_size(self):
        # fp-512, size=8: -512+8=-504 <= 0, but abs(-512)=512 ok; access valid
        # Actually -512+8=-504 <= 0 AND -512 >= -512, so satisfied
        # But -505+8=-497 ok too
        # Let's pick one that clearly violates: fp-512, size=513
        # -512 >= -512 ok, but -512+513=1 > 0 -> violated
        assert eval_stack_access(-512, 513, frame_size=512) == "violated"

    def test_small_access(self):
        assert eval_stack_access(-4, 4) == "satisfied"


class TestEvalTypeMatch:
    def test_exact_match(self):
        ps = PointerState(type="pkt")
        assert eval_type_match(ps, ["pkt"]) == "satisfied"

    def test_prefix_match(self):
        ps = PointerState(type="map_value_or_null")
        assert eval_type_match(ps, ["map_value"]) == "satisfied"

    def test_no_match(self):
        ps = PointerState(type="pkt")
        assert eval_type_match(ps, ["map_value", "ctx"]) == "violated"

    def test_multiple_expected_any_match(self):
        ps = PointerState(type="ctx")
        assert eval_type_match(ps, ["pkt", "ctx", "fp"]) == "satisfied"


class TestEvalTnumBits:
    def test_fully_unknown_always_compatible(self):
        # scalar fully unknown is compatible with anything
        sb = ScalarBounds(var_off_value=0, var_off_mask=U64_MAX)
        result = eval_tnum_bits(sb, 0, 0)
        assert result == "satisfied"

    def test_constant_matches_required(self):
        # scalar known = 42 (mask=0), required = (42, 0) -> satisfied
        sb = ScalarBounds(var_off_value=42, var_off_mask=0)
        result = eval_tnum_bits(sb, 42, 0)
        assert result == "satisfied"

    def test_constant_mismatches_required(self):
        # scalar known = 42, required = (43, 0)
        sb = ScalarBounds(var_off_value=42, var_off_mask=0)
        result = eval_tnum_bits(sb, 43, 0)
        assert result == "violated"

    def test_aligned_requirement(self):
        # scalar has bit 0 known = 0 (even), required alignment: bit 0 = 0
        sb = ScalarBounds(var_off_value=0, var_off_mask=0xFE)  # bit 0 known = 0
        result = eval_tnum_bits(sb, 0, 0xFE)  # require same: bit 0 = 0
        assert result == "satisfied"


# ===========================================================================
# eval_atom_abstract — high-level interface
# ===========================================================================


class TestEvalAtomAbstract:
    def test_range_at_least_satisfied(self):
        # pkt at off=14, range=34, checking access of 4 bytes from off=0 -> require 18
        reg = _reg("pkt", off=14, range=34)
        result, witness = eval_atom_abstract(
            "range_at_least",
            "ptr.off + 4 <= ptr.range",
            reg,
        )
        # off=14, limit extracted=4, check 14+4=18 <= 34 -> satisfied
        assert result == "satisfied"
        assert "range=34" in witness

    def test_range_at_least_violated(self):
        reg = _reg("pkt", off=30, range=34)
        result, _ = eval_atom_abstract(
            "range_at_least",
            "ptr.off + 8 <= ptr.range",
            reg,
        )
        # 30+8=38 > 34
        assert result == "violated"

    def test_base_is_pkt_satisfied(self):
        reg = _reg("pkt", off=0, range=20)
        result, witness = eval_atom_abstract("base_is_pkt", "", reg)
        assert result == "satisfied"
        assert "pkt" in witness

    def test_base_is_pkt_violated(self):
        reg = _reg("map_value", off=0, range=8)
        result, _ = eval_atom_abstract("base_is_pkt", "", reg)
        assert result == "violated"

    def test_non_null_satisfied(self):
        reg = _reg("map_value", off=0)
        result, _ = eval_atom_abstract("non_null", "", reg)
        assert result == "satisfied"

    def test_non_null_violated(self):
        reg = _reg("map_value_or_null", off=0)
        result, _ = eval_atom_abstract("non_null", "", reg)
        assert result == "violated"

    def test_offset_non_negative_satisfied(self):
        reg = _reg("inv", umin=0, umax=255, smin=0, smax=255)
        result, _ = eval_atom_abstract("offset_non_negative", "", reg)
        assert result == "satisfied"

    def test_offset_non_negative_violated(self):
        reg = _reg("inv", smin=-100, smax=-1)
        result, _ = eval_atom_abstract("offset_non_negative", "", reg)
        assert result == "violated"

    def test_offset_bounded_satisfied(self):
        reg = _reg("inv", umin=0, umax=100, var_off="(0x0; 0x7f)")
        result, _ = eval_atom_abstract(
            "offset_bounded", "index <= 255", reg
        )
        assert result == "satisfied"

    def test_scalar_bounds_known_tnum_only_satisfied(self):
        # Scalar bounded only via tnum: umax is still at default but
        # var_off=(0x0; 0xff) means only low-byte values are possible.
        # is_bounded() should detect this via var_off_mask < U64_MAX.
        reg = _reg("inv", var_off="(0x0; 0xff)")
        result, _ = eval_atom_abstract("scalar_bounds_known", "", reg)
        assert result == "satisfied"

    def test_scalar_bounds_known_satisfied(self):
        reg = _reg("inv", umin=0, umax=255)
        result, _ = eval_atom_abstract("scalar_bounds_known", "", reg)
        assert result == "satisfied"

    def test_scalar_bounds_known_violated(self):
        # Fully unbounded scalar
        reg = _reg("inv")
        # No bounds set -> not bounded
        result, _ = eval_atom_abstract("scalar_bounds_known", "", reg)
        assert result == "violated"

    def test_type_matches_satisfied(self):
        reg = _reg("map_value", off=0)
        result, _ = eval_atom_abstract(
            "type_matches", "type matches map_value", reg
        )
        assert result == "satisfied"

    def test_type_matches_violated(self):
        reg = _reg("pkt", off=0)
        result, _ = eval_atom_abstract(
            "type_matches", "type matches map_value", reg
        )
        assert result == "violated"

    def test_unknown_atom_returns_unknown(self):
        reg = _reg("inv", umax=10)
        result, witness = eval_atom_abstract("nonexistent_atom", "", reg)
        assert result == "unknown"
        assert "unsupported" in witness


# ===========================================================================
# Integration: parse from real verifier log lines
# ===========================================================================


class TestRealVerifierLogs:
    """Verify parsing against states extracted from actual case corpus."""

    # From stackoverflow-70750259: pkt pointer with full bounds
    # R5_w=pkt(id=0,off=6,r=6,imm=0)
    def test_real_pkt_state(self):
        ps = parse_pointer_state("pkt(id=0,off=6,r=6,imm=0)")
        assert ps is not None
        assert ps.type == "pkt"
        assert ps.off == 6
        assert ps.range == 6

    # R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff))
    def test_real_inv_with_var_off(self):
        sb = parse_scalar_bounds("inv(id=0,umax_value=255,var_off=(0x0; 0xff))")
        assert sb is not None
        assert sb.umax == 255
        assert sb.upper_bound() == min(255, 0xFF)  # = 255
        assert sb.lower_bound() == 0

    # R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00)) after << 8
    def test_real_inv_after_shift(self):
        sb = parse_scalar_bounds(
            "inv(id=0,umax_value=65280,var_off=(0x0; 0xff00))"
        )
        assert sb is not None
        assert sb.umax == 65280
        assert sb.var_off_mask == 0xFF00
        # Upper bound: min(65280, 0xff00) = min(65280, 65280) = 65280
        assert sb.upper_bound() == 65280

    # From stackoverflow-70729664: pkt with scalar fields
    # R2_w=pkt(id=65,off=37,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff))
    def test_real_pkt_with_large_var_range(self):
        ps = parse_pointer_state(
            "pkt(id=65,off=37,r=55,umin_value=20,umax_value=8316,"
            "var_off=(0x0; 0xffffffff))"
        )
        assert ps is not None
        assert ps.type == "pkt"
        assert ps.off == 37
        assert ps.range == 55
        # Packet access: off=37, size=1 -> 37+1=38 <= 55 -> satisfied
        result = eval_packet_access(ps, None, 1)
        assert result == "satisfied"

    # map_value with vs field
    # R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) from the same case
    def test_real_map_value_small_vs(self):
        ps = parse_pointer_state("map_value(id=0,off=0,ks=4,vs=2,imm=0)")
        assert ps is not None
        assert ps.vs == 2
        # Access of 2 bytes at off=0 -> ok
        result = eval_map_value_access(ps, None, 2, map_value_size=2)
        assert result == "satisfied"
        # Access of 4 bytes at off=0 -> violated
        result = eval_map_value_access(ps, None, 4, map_value_size=2)
        assert result == "violated"

    # inv4 constant (e.g. inv17179869184 = 0x400000000)
    def test_real_large_constant(self):
        sb = parse_scalar_bounds("inv17179869184")
        assert sb is not None
        assert sb.umin == 17179869184
        assert sb.umax == 17179869184
        assert sb.is_const()

    def test_from_register_state_full_round_trip(self):
        """Parse a real state line, convert via RegisterState, check bounds."""
        # Simulate what trace_parser produces for:
        # R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff))
        reg = RegisterState(
            type="inv",
            id=0,
            umin=None,
            umax=255,
            smin=None,
            smax=None,
            var_off="(0x0; 0xff)",
        )
        sb = scalar_bounds_from_register_state(reg)
        assert sb.umax == 255
        assert sb.var_off_mask == 0xFF
        assert sb.upper_bound() == 255
        # Check containment
        assert sb.contains(0)
        assert sb.contains(255)
        assert not sb.contains(256)

    def test_eval_packet_access_from_real_case(self):
        """End-to-end: pkt(off=6,r=6) + 0 bytes access should be at boundary."""
        reg = RegisterState(type="pkt", off=6, range=6)
        ps = pointer_state_from_register_state(reg)
        # Access 1 byte at off=6, range=6: 6+1=7 > 6 -> violated
        result = eval_packet_access(ps, None, 1)
        assert result == "violated"
        # Access exactly within range: size=0 -> treated as 1
        result = eval_packet_access(ps, None, 0)
        assert result == "violated"
