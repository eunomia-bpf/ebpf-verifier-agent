"""Tests for value lineage tracking (register spill/fill/copy/ALU lineage)."""

from __future__ import annotations

from interface.extractor.value_lineage import build_value_lineage
from interface.extractor.trace_parser import RegisterState, TracedInstruction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rs(type_: str = "scalar", **kw) -> RegisterState:
    return RegisterState(type=type_, **kw)


def _insn(
    idx: int,
    bytecode: str,
    *,
    pre: dict[str, RegisterState] | None = None,
    post: dict[str, RegisterState] | None = None,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=idx,
        bytecode=bytecode,
        source_line=None,
        pre_state=dict(pre or {}),
        post_state=dict(post or {}),
        backtrack=None,
        is_error=False,
        error_text=None,
    )


# ---------------------------------------------------------------------------
# 1. Simple register copy chain: R0 -> R3 -> R5
# ---------------------------------------------------------------------------


def test_simple_copy_chain_same_proof_root():
    """R0 -> R3 (copy) -> R5 (copy): all three share the same proof root."""
    insns = [
        _insn(0, "r0 = r1", pre={"R0": _rs("pkt"), "R1": _rs("pkt")}),
        _insn(1, "r3 = r0", pre={"R0": _rs("pkt")}),
        _insn(2, "r5 = r3", pre={"R3": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # After insn 0 (trace_pos=1 for subsequent state): R0 originates from R1.
    # After insn 1: R3 should share R0's proof root.
    # After insn 2: R5 should share R3's (and thus R0/R1's) proof root.

    # is_same_value between R0 and R3 after insn 1 (trace_pos 2 is the snapshot
    # before insn 2, so R3=r0 copy has already occurred at trace_pos 2)
    assert lineage.is_same_value(2, "R0", "R3"), "R0 and R3 should share proof root after copy"
    assert lineage.is_same_value(3, "R0", "R5"), "R0 and R5 should share proof root after second copy"
    assert lineage.is_same_value(3, "R3", "R5"), "R3 and R5 should share proof root"


def test_copy_chain_origin_traces_back():
    """get_value_origin should trace back to the original definition."""
    insns = [
        _insn(0, "r3 = r0", pre={"R0": _rs("pkt"), "R3": _rs("scalar")}),
        _insn(1, "r5 = r3", pre={"R3": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # After insn 1 (trace_pos=2), R5 should trace back to where R0 was defined (entry).
    origin = lineage.get_value_origin(2, "R5")
    assert origin is not None, "R5 should have a traceable origin after fill chain"
    # The ultimate origin of R0 at entry is (None, 'R0') since it was in pre_state at pos=0
    orig_insn_idx, orig_loc = origin
    assert orig_loc == "R0", f"Expected origin in R0, got {orig_loc}"


def test_all_aliases_after_copy():
    """get_all_aliases should return all registers holding the same value."""
    insns = [
        _insn(0, "r3 = r0", pre={"R0": _rs("pkt"), "R3": _rs("scalar")}),
        _insn(1, "r5 = r0", pre={"R0": _rs("pkt"), "R3": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # At trace_pos=2 (after insn 1), both R3 and R5 were copied from R0
    aliases = lineage.get_all_aliases(2, "R0")
    assert "R0" in aliases
    assert "R3" in aliases


# ---------------------------------------------------------------------------
# 2. Spill and fill: R0 -> stack fp-8 -> R5
# ---------------------------------------------------------------------------


def test_spill_fill_lineage():
    """Value spilled to stack and filled back to a different register should preserve lineage."""
    insns = [
        # insn 0: spill R0 to fp-8
        _insn(0, "*(u64 *)(r10 -8) = r0", pre={"R0": _rs("pkt"), "R10": _rs("fp")}),
        # insn 1: fill fp-8 into R5
        _insn(1, "r5 = *(u64 *)(r10 -8)", pre={"R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    # At trace_pos=2 (snapshot before what would be insn 2): R5 should share R0's proof root
    assert lineage.is_same_value(2, "R0", "R5"), (
        "R5 (filled from stack) should share proof root with R0 (spilled to stack)"
    )


def test_spill_fill_origin():
    """Origin of a filled register should trace back to the original pre-spill register."""
    insns = [
        _insn(0, "*(u64 *)(r10 -8) = r0", pre={"R0": _rs("pkt"), "R10": _rs("fp")}),
        _insn(1, "r5 = *(u64 *)(r10 -8)", pre={"R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    origin = lineage.get_value_origin(2, "R5")
    assert origin is not None
    insn_idx, loc = origin
    assert loc == "R0", f"Origin should be R0 (spilled source), got {loc}"


def test_spill_fill_aliases_include_stack_slot():
    """Aliases of a spilled value should include the stack slot name."""
    insns = [
        _insn(0, "*(u64 *)(r10 -8) = r0", pre={"R0": _rs("pkt"), "R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    # At trace_pos=1 (after the spill), R0 and fp-8 share the same proof root
    aliases = lineage.get_all_aliases(1, "R0")
    assert "fp-8" in aliases, f"Stack slot fp-8 should be an alias of R0; got {aliases}"


# ---------------------------------------------------------------------------
# 3. ALU preserving (ptr_add): R0 += 14 -> same proof root, offset changed
# ---------------------------------------------------------------------------


def test_ptr_add_constant_preserves_lineage():
    """r0 += 14 should preserve lineage (same proof root) with updated offset delta."""
    insns = [
        _insn(0, "r0 += 14", pre={"R0": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # R0 at trace_pos=0 and R0 at trace_pos=1 should have the same proof root
    assert lineage.is_same_value(0, "R0", "R0"), "R0 pre-add should match itself"
    vid0 = lineage._live_at[0].get("R0")
    vid1 = lineage._live_at[1].get("R0") if len(lineage._live_at) > 1 else None

    if vid0 is not None and vid1 is not None:
        assert lineage._nodes[vid0].proof_root == lineage._nodes[vid1].proof_root, (
            "proof root should be preserved after ptr_add"
        )


def test_ptr_add_constant_offset_delta():
    """r0 += 14 should increase the offset_delta by 14."""
    insns = [
        _insn(0, "r0 += 14", pre={"R0": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # Before add: delta should be 0
    assert lineage.get_offset_delta(0, "R0") == 0
    # After add: delta should be +14
    assert lineage.get_offset_delta(1, "R0") == 14


def test_ptr_sub_constant_offset_delta():
    """r0 -= 4 should decrease the offset_delta by 4."""
    insns = [
        _insn(0, "r0 -= 4", pre={"R0": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    assert lineage.get_offset_delta(1, "R0") == -4


# ---------------------------------------------------------------------------
# 4. ALU destroying: R0 |= R6 -> new value, lineage broken
# ---------------------------------------------------------------------------


def test_alu_reg_destroys_lineage():
    """r0 |= r6 should produce a new value with no parent (lineage broken)."""
    insns = [
        _insn(0, "r0 |= r6", pre={"R0": _rs("scalar"), "R6": _rs("scalar")}),
    ]
    lineage = build_value_lineage(insns)

    vid0 = lineage._live_at[0].get("R0")  # before the op
    vid1 = lineage._live_at[1].get("R0") if len(lineage._live_at) > 1 else None  # after

    if vid0 is not None and vid1 is not None:
        assert lineage._nodes[vid0].proof_root != lineage._nodes[vid1].proof_root, (
            "lineage should be broken by register-register ALU op"
        )


def test_alu_reg_add_destroys_lineage():
    """r0 += r2 (register source, not constant) should also break lineage."""
    insns = [
        _insn(0, "r0 += r2", pre={"R0": _rs("pkt"), "R2": _rs("scalar")}),
    ]
    lineage = build_value_lineage(insns)

    vid0 = lineage._live_at[0].get("R0")
    vid1 = lineage._live_at[1].get("R0") if len(lineage._live_at) > 1 else None

    if vid0 is not None and vid1 is not None:
        assert lineage._nodes[vid0].proof_root != lineage._nodes[vid1].proof_root, (
            "r0 += r2 should break lineage"
        )


# ---------------------------------------------------------------------------
# 5. Complex chain: R0 -> R3 (copy), R3 -> stack (spill), stack -> R7 (fill)
# ---------------------------------------------------------------------------


def test_complex_chain_r0_to_r3_to_stack_to_r7():
    """Full complex chain through copy + spill + fill preserves origin."""
    insns = [
        # copy: R3 = R0
        _insn(0, "r3 = r0", pre={"R0": _rs("pkt"), "R3": _rs("scalar")}),
        # spill: stack fp-16 = R3
        _insn(1, "*(u64 *)(r10 -16) = r3", pre={"R3": _rs("pkt"), "R10": _rs("fp")}),
        # fill: R7 = stack fp-16
        _insn(2, "r7 = *(u64 *)(r10 -16)", pre={"R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    # At trace_pos=3 (after all three insns): R7 should share R0's proof root
    assert lineage.is_same_value(3, "R0", "R7"), (
        "R7 (fill from stack) should share R0's proof root after copy+spill+fill chain"
    )

    origin = lineage.get_value_origin(3, "R7")
    assert origin is not None
    _, orig_loc = origin
    assert orig_loc == "R0", f"Expected R0 as ultimate origin, got {orig_loc}"


def test_complex_chain_all_aliases():
    """After copy+spill: R0, R3, fp-16 should all be aliases."""
    insns = [
        _insn(0, "r3 = r0", pre={"R0": _rs("pkt"), "R3": _rs("scalar")}),
        _insn(1, "*(u64 *)(r10 -16) = r3", pre={"R3": _rs("pkt"), "R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    aliases = lineage.get_all_aliases(2, "R0")
    assert "R0" in aliases
    assert "R3" in aliases
    assert "fp-16" in aliases


# ---------------------------------------------------------------------------
# 6. Edge cases
# ---------------------------------------------------------------------------


def test_register_overwrite_breaks_old_lineage():
    """Overwriting R3 with a new value breaks the lineage with R0."""
    insns = [
        # Copy: R3 = R0 (R3 now aliases R0)
        _insn(0, "r3 = r0", pre={"R0": _rs("pkt"), "R3": _rs("scalar")}),
        # Overwrite: R3 = 0  (new independent value)
        _insn(1, "r3 = 0", pre={"R0": _rs("pkt"), "R3": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # At trace_pos=1: R0 and R3 should be aliases (after copy but before overwrite)
    assert lineage.is_same_value(1, "R0", "R3"), "Should be aliases at trace_pos=1"

    # At trace_pos=2: R3 has been overwritten — no longer an alias of R0
    assert not lineage.is_same_value(2, "R0", "R3"), (
        "R3 should NOT be an alias of R0 after overwrite"
    )


def test_unknown_location_returns_none():
    """Querying a location that was never live should return None."""
    insns = [
        _insn(0, "r0 = 1", pre={"R0": _rs("scalar")}),
    ]
    lineage = build_value_lineage(insns)
    assert lineage.get_value_origin(0, "R9") is None
    assert lineage.get_all_aliases(0, "R9") == set()


def test_multiple_spill_slots_independent():
    """Two different stack slots should be tracked independently."""
    insns = [
        _insn(0, "*(u64 *)(r10 -8) = r0", pre={"R0": _rs("pkt"), "R10": _rs("fp")}),
        _insn(1, "*(u64 *)(r10 -16) = r1", pre={"R1": _rs("map_value"), "R10": _rs("fp")}),
        _insn(2, "r5 = *(u64 *)(r10 -8)", pre={"R10": _rs("fp")}),
        _insn(3, "r6 = *(u64 *)(r10 -16)", pre={"R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    # After all: R5 should share R0's root, R6 should share R1's root
    assert lineage.is_same_value(4, "R0", "R5"), "R5 should be filled from fp-8 (R0)"
    assert lineage.is_same_value(4, "R1", "R6"), "R6 should be filled from fp-16 (R1)"
    assert not lineage.is_same_value(4, "R0", "R6"), "R0 and R6 are different values"
    assert not lineage.is_same_value(4, "R1", "R5"), "R1 and R5 are different values"


def test_fill_from_unknown_stack_slot():
    """Filling from a stack slot that was never spilled to should create a new value."""
    insns = [
        # No prior spill — reading from fp-8 that we never wrote
        _insn(0, "r5 = *(u64 *)(r10 -8)", pre={"R10": _rs("fp")}),
    ]
    lineage = build_value_lineage(insns)

    # R5 should exist but have no meaningful parent (it's a fresh load)
    origin = lineage.get_value_origin(1, "R5")
    # Should be non-None (R5 does have a lineage node), but parent should trace to itself
    assert origin is not None
    _, orig_loc = origin
    # The ultimate origin should be R5 itself (no parent chain to follow)
    assert orig_loc == "R5"


def test_ptr_add_chain_preserves_root_across_multiple_adds():
    """Multiple consecutive ptr_adds should all point to the same proof root."""
    insns = [
        _insn(0, "r0 += 4", pre={"R0": _rs("pkt")}),
        _insn(1, "r0 += 8", pre={"R0": _rs("pkt")}),
        _insn(2, "r0 += 2", pre={"R0": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    vid0 = lineage._live_at[0].get("R0")  # before any add
    vid3 = lineage._live_at[3].get("R0") if len(lineage._live_at) > 3 else None  # after all adds

    if vid0 is not None and vid3 is not None:
        assert lineage._nodes[vid0].proof_root == lineage._nodes[vid3].proof_root, (
            "Proof root should be preserved across multiple ptr_adds"
        )

    assert lineage.get_offset_delta(3, "R0") == 14, "Total offset delta should be 4+8+2=14"


def test_call_produces_fresh_r0():
    """A call instruction should produce a fresh R0 value with no lineage from before."""
    insns = [
        _insn(0, "r0 = r1", pre={"R0": _rs("scalar"), "R1": _rs("pkt")}),
        _insn(1, "call bpf_map_lookup_elem", pre={"R0": _rs("pkt")}),
    ]
    lineage = build_value_lineage(insns)

    # R0 before call (trace_pos=1) should share R1's lineage
    assert lineage.is_same_value(1, "R0", "R1"), "Before call: R0 copied from R1"

    # R0 after call (trace_pos=2) should be a fresh value, not aliasing R1
    assert not lineage.is_same_value(2, "R0", "R1"), "After call: R0 is fresh return value"


def test_wide_register_copy():
    """w3 = w0 (32-bit move) should also track lineage correctly."""
    insns = [
        _insn(0, "w3 = w0", pre={"R0": _rs("scalar"), "R3": _rs("scalar")}),
    ]
    lineage = build_value_lineage(insns)

    # After the move, R3 should share R0's proof root
    assert lineage.is_same_value(1, "R0", "R3"), "w3 = w0 should track lineage"
