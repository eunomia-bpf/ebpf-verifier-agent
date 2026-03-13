"""Abstract domain types and interval arithmetic for eBPF verifier predicate evaluation.

Mirrors the verifier's scalar abstract domain:
  - tnum (tracked number): value/mask pairs for bitwise precision
  - Scalar bounds: [umin, umax] x [smin, smax]
  - Pointer fields: type, off, range, id, ref_obj_id

This module is designed to be used by obligation_inference.py predicate evaluators
but is kept self-contained so it can be wired in incrementally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .trace_parser_parts._impl import RegisterState

# ---------------------------------------------------------------------------
# Constants matching the kernel's 64-bit unsigned / signed ranges
# ---------------------------------------------------------------------------

U64_MAX: int = (1 << 64) - 1
S64_MAX: int = (1 << 63) - 1
S64_MIN: int = -(1 << 63)

# Regex to parse tnum written as "(0xVALUE; 0xMASK)" in verifier output.
# The verifier uses hex for both fields separated by "; ".
# Examples:
#   (0x0; 0xff)        -> value=0, mask=0xff   (low byte unknown)
#   (0x0; 0xff00)      -> value=0, mask=0xff00
#   (0x14; 0x0)        -> value=20, mask=0       (constant 20)
_TNUM_RE = re.compile(
    r"\(\s*(?P<value>0x[0-9a-fA-F]+|\d+)\s*;\s*(?P<mask>0x[0-9a-fA-F]+|\d+)\s*\)"
)

# Regex to parse var_off or attr attributes like "off=14", "r=34", etc.
_ATTR_RE = re.compile(r"(?P<key>[a-zA-Z0-9_]+)=(?P<value>\([^)]*\)|[^,]+)")


# ---------------------------------------------------------------------------
# tnum helpers
# ---------------------------------------------------------------------------


def _parse_tnum(text: str) -> tuple[int, int] | None:
    """Parse a tnum string '(0xVALUE; 0xMASK)' into (value, mask).

    Returns None if the string does not match the expected format.
    """
    m = _TNUM_RE.search(text.strip())
    if m is None:
        return None
    try:
        value = int(m.group("value"), 0)
        mask = int(m.group("mask"), 0)
        return value, mask
    except ValueError:
        return None


def tnum_upper_bound(value: int, mask: int) -> int:
    """Conservative upper bound of a tnum: value | mask (all unknown bits set)."""
    return (value | mask) & U64_MAX


def tnum_lower_bound(value: int, mask: int) -> int:
    """Conservative lower bound of a tnum: value (unknown bits cleared to 0)."""
    return value & U64_MAX


def tnum_is_const(value: int, mask: int) -> bool:
    """True if tnum represents a single concrete value (no unknown bits)."""
    return (mask & U64_MAX) == 0


def tnum_contains(value: int, mask: int, concrete: int) -> bool:
    """True if the concrete value is possible given the tnum constraints.

    A concrete integer c is consistent with (value, mask) iff:
      (c & ~mask) == (value & ~mask)
    i.e. all known bits match.
    """
    known_bits = ~mask & U64_MAX
    return (concrete & known_bits) == (value & known_bits)


# ---------------------------------------------------------------------------
# ScalarBounds
# ---------------------------------------------------------------------------


@dataclass
class ScalarBounds:
    """Mirrors the verifier's scalar tracking for a single register.

    Fields:
        umin, umax   -- unsigned 64-bit interval
        smin, smax   -- signed 64-bit interval
        var_off_value, var_off_mask -- tnum for variable offset component
            mask bit = 1 means "unknown bit", mask bit = 0 means "known bit"
            so the concrete value has:  (concrete & ~mask) == (value & ~mask)
    """

    umin: int = 0
    umax: int = U64_MAX
    smin: int = S64_MIN
    smax: int = S64_MAX
    var_off_value: int = 0
    var_off_mask: int = U64_MAX  # fully unknown by default

    def is_bounded(self) -> bool:
        """True if bounds are non-trivial (not the full 64-bit range).

        A scalar is "bounded" if at least one of the four interval endpoints
        is tighter than the worst-case default, OR if the tnum (var_off)
        constrains the value (some bits are known, restricting the upper bound).

        The tnum check catches cases like `r0 &= 0xff` where the verifier
        tracks var_off=(0x0; 0xff) but the interval umax may still be U64_MAX
        if the bounds haven't been tightened yet in the log.
        """
        return (
            self.umax < U64_MAX
            or self.umin > 0
            or self.smin > S64_MIN
            or self.smax < S64_MAX
            or self.var_off_mask < U64_MAX  # tnum has some known bits
        )

    def is_const(self) -> bool:
        """True if the scalar is a compile-time constant (umin == umax)."""
        return self.umin == self.umax

    def contains(self, concrete: int) -> bool:
        """True if *concrete* is within the unsigned interval AND consistent with tnum.

        Both checks must pass.
        """
        in_interval = self.umin <= concrete <= self.umax
        tnum_ok = tnum_contains(self.var_off_value, self.var_off_mask, concrete)
        return in_interval and tnum_ok

    def upper_bound(self) -> int:
        """Conservative upper bound: min(umax, tnum upper bound).

        Intersection of the two abstract domains cannot be larger than either.
        """
        tnum_ub = tnum_upper_bound(self.var_off_value, self.var_off_mask)
        return min(self.umax, tnum_ub)

    def lower_bound(self) -> int:
        """Conservative lower bound: max(umin, tnum lower bound)."""
        tnum_lb = tnum_lower_bound(self.var_off_value, self.var_off_mask)
        return max(self.umin, tnum_lb)

    def signed_upper_bound(self) -> int:
        """Conservative upper bound using the signed interval."""
        return self.smax

    def signed_lower_bound(self) -> int:
        """Conservative lower bound using the signed interval."""
        return self.smin


# ---------------------------------------------------------------------------
# PointerState
# ---------------------------------------------------------------------------


@dataclass
class PointerState:
    """Mirrors verifier's pointer abstract state for a single register.

    Fields:
        type          -- verifier type string, e.g. "pkt", "map_value", "ctx", "fp"
        off           -- fixed (constant) byte offset from the base pointer
        range         -- accessible byte range past the fixed offset (for pkt pointers)
        id            -- provenance ID (shared across aliased pointers)
        ref_obj_id    -- reference object ID (for kptr / resource tracking)
        ks            -- map key size (map_value pointers)
        vs            -- map value size (map_value pointers)
    """

    type: str = "unknown"
    off: int = 0
    range: int = 0
    id: int = 0
    ref_obj_id: int = 0
    ks: int = 0
    vs: int = 0

    def is_null_possible(self) -> bool:
        """True if pointer type admits NULL (i.e. contains '_or_null')."""
        return "_or_null" in self.type

    def is_packet(self) -> bool:
        return self.type in ("pkt", "pkt_meta")

    def is_map_value(self) -> bool:
        return "map_value" in self.type

    def is_stack(self) -> bool:
        return self.type in ("fp",)

    def is_ctx(self) -> bool:
        return "ctx" in self.type


# ---------------------------------------------------------------------------
# Parsing from verifier state strings
# ---------------------------------------------------------------------------


def _parse_int_safe(text: str | None) -> int | None:
    """Parse a hex or decimal integer string, returning None on failure."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _parse_attrs(attrs_text: str) -> dict[str, str]:
    """Parse 'key=value' pairs from the inside of a verifier type annotation.

    Handles tnum values like 'var_off=(0x0; 0xff)' correctly by treating
    parenthesised groups as atomic values.
    """
    result: dict[str, str] = {}
    for m in _ATTR_RE.finditer(attrs_text):
        result[m.group("key")] = m.group("value").strip()
    return result


def parse_scalar_bounds(value: str) -> ScalarBounds | None:
    """Parse a verifier register state string into ScalarBounds.

    Accepts the right-hand side of an 'Rn=' annotation, for example:
      "inv(id=0,umax_value=255,var_off=(0x0; 0xff))"
      "invP(id=0,umax_value=65535,var_off=(0x0; 0xffff))"
      "inv0"        (constant zero)
      "inv42"       (constant 42)
      "scalar"      (fully unknown)

    Returns None if the value does not describe a scalar-like type.
    """
    text = value.strip()

    # Reject obvious pointer types early so callers need not check.
    type_prefix_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)", text)
    if type_prefix_match:
        type_name = type_prefix_match.group(1).lower()
        _POINTER_PREFIXES = (
            "pkt", "map_value", "map_ptr", "ctx", "fp", "ptr",
            "mem", "sock", "sk_", "btf_", "percpu", "dynptr", "iter",
            "ringbuf", "timer", "kptr",
        )
        # Only reject if it's clearly a pointer type (not inv/scalar)
        if not type_name.startswith(("inv", "scalar")) and any(
            type_name.startswith(p) for p in _POINTER_PREFIXES
        ):
            return None

    sb = ScalarBounds()

    # ---------- constant shorthand: inv0, inv42, inv-3 ----------
    const_match = re.match(r"^(?:invP?|scalar)(-?(?:0x[0-9a-fA-F]+|\d+))$", text)
    if const_match:
        const_val = _parse_int_safe(const_match.group(1))
        if const_val is not None:
            # Treat as unsigned if non-negative, otherwise handle wrap-around.
            uval = const_val & U64_MAX
            sb.umin = uval
            sb.umax = uval
            # Signed interpretation
            sval = const_val if const_val >= S64_MIN else const_val
            sb.smin = sval
            sb.smax = sval
            # tnum: known constant
            sb.var_off_value = uval
            sb.var_off_mask = 0
            return sb

    # ---------- parenthesised attribute form: inv(...) ----------
    paren_match = re.match(
        r"^(?:invP?|scalar[0-9]*)(?:\((?P<attrs>.*)\))?$", text, re.IGNORECASE
    )
    if not paren_match:
        # Bare "scalar" with no parens is fully unknown — use defaults.
        if re.match(r"^scalar$", text, re.IGNORECASE):
            return sb  # full-range defaults
        return None

    attrs_text = paren_match.group("attrs") or ""
    attrs = _parse_attrs(attrs_text)

    # Map verifier attribute names to our fields.
    _UMIN_KEYS = ("umin_value", "umin", "u32_min_value")
    _UMAX_KEYS = ("umax_value", "umax", "u32_max_value")
    _SMIN_KEYS = ("smin_value", "smin", "s32_min_value")
    _SMAX_KEYS = ("smax_value", "smax", "s32_max_value")

    for key in _UMIN_KEYS:
        if key in attrs:
            v = _parse_int_safe(attrs[key])
            if v is not None:
                sb.umin = max(0, v)
            break

    for key in _UMAX_KEYS:
        if key in attrs:
            v = _parse_int_safe(attrs[key])
            if v is not None:
                sb.umax = v & U64_MAX
            break

    for key in _SMIN_KEYS:
        if key in attrs:
            v = _parse_int_safe(attrs[key])
            if v is not None:
                sb.smin = v
            break

    for key in _SMAX_KEYS:
        if key in attrs:
            v = _parse_int_safe(attrs[key])
            if v is not None:
                sb.smax = v
            break

    if "var_off" in attrs:
        parsed = _parse_tnum(attrs["var_off"])
        if parsed is not None:
            sb.var_off_value, sb.var_off_mask = parsed
        # If parsing fails, keep fully-unknown defaults.

    return sb


def parse_pointer_state(value: str) -> PointerState | None:
    """Parse a verifier register state string into PointerState.

    Accepts the right-hand side of an 'Rn=' annotation, for example:
      "pkt(id=0,off=14,r=34,imm=0)"
      "pkt_end(id=0,off=0,imm=0)"
      "map_value(id=0,off=0,ks=4,vs=8,imm=0)"
      "ctx(id=0,off=0,imm=0)"
      "fp-8"          (stack slot at offset -8)

    Returns None if the value does not describe a pointer-like type.
    """
    text = value.strip()

    # fp-N shorthand (stack frame pointer)
    fp_match = re.match(r"^fp(?P<off>-?\d+)$", text)
    if fp_match:
        return PointerState(type="fp", off=int(fp_match.group("off")))

    # Reject scalar-like types
    scalar_match = re.match(r"^(?:invP?|scalar)", text, re.IGNORECASE)
    if scalar_match:
        return None

    # Must be type(attrs) form
    paren_match = re.match(
        r"^(?P<type>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<attrs>.*)\)$", text
    )
    if not paren_match:
        return None

    ps = PointerState(type=paren_match.group("type"))
    attrs = _parse_attrs(paren_match.group("attrs"))

    if "id" in attrs:
        ps.id = _parse_int_safe(attrs["id"]) or 0
    if "off" in attrs:
        ps.off = _parse_int_safe(attrs["off"]) or 0
    if "r" in attrs:
        ps.range = _parse_int_safe(attrs["r"]) or 0
    if "ref_obj_id" in attrs:
        ps.ref_obj_id = _parse_int_safe(attrs["ref_obj_id"]) or 0
    if "ks" in attrs:
        ps.ks = _parse_int_safe(attrs["ks"]) or 0
    if "vs" in attrs:
        ps.vs = _parse_int_safe(attrs["vs"]) or 0

    return ps


def scalar_bounds_from_register_state(reg: "RegisterState") -> ScalarBounds:
    """Construct a ScalarBounds from an existing RegisterState dataclass.

    The RegisterState already has umin/umax/smin/smax as parsed integers
    and var_off as a raw string like '(0x0; 0xff)'.  This function builds
    the full ScalarBounds, applying sensible defaults for missing fields.
    """
    sb = ScalarBounds()

    if reg.umin is not None:
        sb.umin = max(0, reg.umin)
    if reg.umax is not None:
        sb.umax = reg.umax & U64_MAX
    if reg.smin is not None:
        sb.smin = reg.smin
    if reg.smax is not None:
        sb.smax = reg.smax

    if reg.var_off is not None:
        parsed = _parse_tnum(reg.var_off)
        if parsed is not None:
            sb.var_off_value, sb.var_off_mask = parsed

    return sb


def pointer_state_from_register_state(reg: "RegisterState") -> PointerState:
    """Construct a PointerState from an existing RegisterState dataclass."""
    ps = PointerState(type=reg.type)
    if reg.off is not None:
        ps.off = reg.off
    if reg.range is not None:
        ps.range = reg.range
    if reg.id is not None:
        ps.id = reg.id
    return ps


# ---------------------------------------------------------------------------
# Predicate evaluators using the full abstract domain
# ---------------------------------------------------------------------------


def eval_packet_access(
    ptr: PointerState,
    index: ScalarBounds | None,
    access_size: int,
) -> str:
    """Evaluate whether a packet pointer access stays within the proven range.

    The verifier requires:
        ptr.off + index_upper_bound + access_size <= ptr.range

    Parameters
    ----------
    ptr         : PointerState for the base pointer register
    index       : ScalarBounds for the index/offset scalar register, or None
                  if there is no variable index (pure fixed-offset access)
    access_size : number of bytes being accessed

    Returns
    -------
    "satisfied" -- definitely within range (even in the worst case)
    "violated"  -- definitely out of range (even in the best case)
    "unknown"   -- ambiguous; depends on concrete runtime value
    """
    if access_size <= 0:
        access_size = 1  # conservative: at least 1 byte

    idx_ub = index.upper_bound() if index is not None else 0
    idx_lb = index.lower_bound() if index is not None else 0

    worst_case = ptr.off + idx_ub + access_size
    best_case = ptr.off + idx_lb + access_size

    if worst_case <= ptr.range:
        return "satisfied"
    if best_case > ptr.range:
        return "violated"
    return "unknown"


def eval_null_check(ptr: PointerState) -> str:
    """Evaluate whether a pointer is guaranteed non-null.

    The verifier tracks 'X_or_null' types for pointers that might be NULL.

    Returns "violated" if null is possible, "satisfied" otherwise.
    """
    if ptr.is_null_possible():
        return "violated"
    return "satisfied"


def eval_scalar_in_range(scalar: ScalarBounds, low: int, high: int) -> str:
    """Evaluate whether scalar value is guaranteed within [low, high].

    Uses the unsigned interval for the comparison.

    Returns
    -------
    "satisfied" -- scalar.umin >= low AND scalar.umax <= high
    "violated"  -- scalar.umin > high OR scalar.umax < low (disjoint)
    "unknown"   -- intervals overlap but not fully contained
    """
    if scalar.umin >= low and scalar.umax <= high:
        return "satisfied"
    if scalar.umin > high or scalar.umax < low:
        return "violated"
    return "unknown"


def eval_scalar_non_negative(scalar: ScalarBounds) -> str:
    """Evaluate whether the scalar is guaranteed non-negative (signed >= 0).

    Uses the signed lower bound for conservative analysis.
    """
    signed_lb = scalar.signed_lower_bound()
    if signed_lb >= 0:
        return "satisfied"
    if scalar.smax < 0:
        return "violated"
    return "unknown"


def eval_scalar_upper_bound(scalar: ScalarBounds, limit: int) -> str:
    """Evaluate whether scalar is guaranteed <= limit.

    Uses conservative (worst-case) upper bound: min(umax, tnum upper bound).
    """
    ub = scalar.upper_bound()
    if ub <= limit:
        return "satisfied"
    lb = scalar.lower_bound()
    if lb > limit:
        return "violated"
    return "unknown"


def eval_type_match(ptr: PointerState, expected_types: list[str]) -> str:
    """Evaluate whether the pointer type matches one of the expected types.

    Matching is prefix-based to handle subtypes (e.g. 'map_value' matches
    'map_value_or_null').
    """
    actual = ptr.type.lower()
    for expected in expected_types:
        exp = expected.lower()
        if actual == exp:
            return "satisfied"
        if actual.startswith(exp):
            return "satisfied"
        if exp.endswith("_") and actual.startswith(exp):
            return "satisfied"
    return "violated"


def eval_map_value_access(
    ptr: PointerState,
    index: ScalarBounds | None,
    access_size: int,
    map_value_size: int,
) -> str:
    """Evaluate whether a map_value access stays within the map value size.

    ptr.off + index_upper_bound + access_size <= map_value_size

    Parameters
    ----------
    ptr            : PointerState for the map_value base pointer
    index          : optional variable index scalar
    access_size    : bytes being accessed
    map_value_size : vs field from the map_value pointer (total value size)
    """
    if access_size <= 0:
        access_size = 1

    idx_ub = index.upper_bound() if index is not None else 0
    idx_lb = index.lower_bound() if index is not None else 0

    limit = map_value_size if map_value_size > 0 else ptr.range

    worst_case = ptr.off + idx_ub + access_size
    best_case = ptr.off + idx_lb + access_size

    if limit > 0:
        if worst_case <= limit:
            return "satisfied"
        if best_case > limit:
            return "violated"
        return "unknown"

    # No size information available -- fallback to range field
    if ptr.range > 0:
        if worst_case <= ptr.range:
            return "satisfied"
        if best_case > ptr.range:
            return "violated"
        return "unknown"

    return "unknown"


def eval_stack_access(
    off: int,
    access_size: int,
    frame_size: int = 512,
) -> str:
    """Evaluate whether a stack access is within the frame.

    Stack accesses use negative offsets from fp (frame pointer).  The eBPF
    stack spans [fp - frame_size .. fp - 1], so a valid access of *access_size*
    bytes starting at *off* requires:

        off >= -frame_size          (start is within the frame)
        off + access_size <= 0      (access ends before the frame pointer)

    Both conditions must hold.
    """
    if access_size <= 0:
        access_size = 1
    if off >= -frame_size and (off + access_size) <= 0:
        return "satisfied"
    return "violated"


def eval_tnum_bits(scalar: ScalarBounds, required_value: int, required_mask: int) -> str:
    """Evaluate tnum compatibility: does scalar include values matching (required_value, required_mask)?

    The verifier sometimes imposes tnum constraints (e.g. alignment).
    A tnum (value, mask) is compatible with a required tnum (rv, rm) iff
    the intersection is non-empty:
        (scalar.var_off_value & ~required_mask) == (required_value & ~required_mask)
    when we only look at bits known in BOTH tnums.
    """
    # Bits that are known in BOTH tnums
    both_known = ~scalar.var_off_mask & ~required_mask & U64_MAX
    if both_known == 0:
        # No bits constrained by both — always compatible
        return "satisfied"
    if (scalar.var_off_value & both_known) == (required_value & both_known):
        return "satisfied"
    return "violated"


# ---------------------------------------------------------------------------
# High-level: evaluate predicate atom using full abstract domain
# ---------------------------------------------------------------------------


def eval_atom_abstract(
    atom_id: str,
    expression: str,
    reg: "RegisterState",
) -> tuple[str, str]:
    """Evaluate a predicate atom against a RegisterState using the full abstract domain.

    This is intended as a drop-in replacement for the simple comparison in
    _eval_atom_on_state() inside obligation_inference.py.  It returns the same
    (result, witness) pair.

    Parameters
    ----------
    atom_id    : e.g. "range_at_least", "non_null", "offset_bounded"
    expression : the atom's expression string (may contain limit values)
    reg        : RegisterState from the trace parser

    Returns
    -------
    (result, witness) where result in {"satisfied", "violated", "unknown"}
    """
    if atom_id == "range_at_least":
        ptr = pointer_state_from_register_state(reg)
        # Extract required extent from expression (e.g. "ptr.off + N <= ptr.range")
        limit = _extract_trailing_int_from_expr(expression)
        if limit is None:
            return "unknown", f"range_at_least: cannot parse limit from {expression!r}"
        if ptr.off + limit <= ptr.range:
            return "satisfied", f"off={ptr.off}, required={limit}, range={ptr.range}"
        return "violated", f"off={ptr.off}, required={limit}, range={ptr.range}"

    if atom_id == "base_is_pkt":
        ptr = pointer_state_from_register_state(reg)
        result = "satisfied" if ptr.is_packet() else "violated"
        return result, f"type={ptr.type}"

    if atom_id == "non_null":
        ptr = pointer_state_from_register_state(reg)
        result = eval_null_check(ptr)
        return result, f"type={ptr.type}"

    if atom_id == "offset_non_negative":
        sb = scalar_bounds_from_register_state(reg)
        result = eval_scalar_non_negative(sb)
        return result, f"smin={sb.smin}, smax={sb.smax}"

    if atom_id == "offset_bounded":
        sb = scalar_bounds_from_register_state(reg)
        limit = _extract_trailing_int_from_expr(expression)
        if limit is None:
            return "violated" if sb.umax == U64_MAX else "unknown", f"umax={sb.umax}"
        result = eval_scalar_upper_bound(sb, limit)
        return result, f"umax={sb.umax}, tnum_ub={sb.upper_bound()}, limit={limit}"

    if atom_id == "scalar_bounds_known":
        sb = scalar_bounds_from_register_state(reg)
        result = "satisfied" if sb.is_bounded() else "violated"
        tnum_ub = tnum_upper_bound(sb.var_off_value, sb.var_off_mask)
        return result, f"umin={sb.umin}, umax={sb.umax}, tnum_ub={tnum_ub}, var_off_mask={hex(sb.var_off_mask)}"

    if atom_id == "type_matches":
        ptr = pointer_state_from_register_state(reg)
        expected = _parse_expected_types_from_expr(expression)
        result = eval_type_match(ptr, expected)
        return result, f"type={ptr.type}, expected={expected}"

    if atom_id == "type_is_pointer":
        ptr = pointer_state_from_register_state(reg)
        from .shared_utils import is_pointer_type_name
        result = "satisfied" if is_pointer_type_name(ptr.type) else "violated"
        return result, f"type={ptr.type}"

    return "unknown", f"{atom_id}: unsupported in abstract domain evaluator"


# ---------------------------------------------------------------------------
# tnum arithmetic helpers (for completeness)
# ---------------------------------------------------------------------------


def tnum_add(lv: int, lm: int, rv: int, rm: int) -> tuple[int, int]:
    """Compute tnum addition: (lv, lm) + (rv, rm).

    Mirrors the kernel implementation in lib/tnum.c::tnum_add():
        sm = a.mask + b.mask
        sv = a.value + b.value
        sigma = sm + sv
        chi = sigma ^ sv
        mu = chi | a.mask | b.mask
        return TNUM(sv & ~mu, mu)
    """
    sm = (lm + rm) & U64_MAX
    sv = (lv + rv) & U64_MAX
    sigma = (sm + sv) & U64_MAX
    chi = (sigma ^ sv) & U64_MAX
    mu = (chi | lm | rm) & U64_MAX
    return (sv & (~mu & U64_MAX)) & U64_MAX, mu & U64_MAX


def tnum_and(lv: int, lm: int, rv: int, rm: int) -> tuple[int, int]:
    """Compute tnum bitwise AND."""
    alpha = (lv | lm) & U64_MAX
    beta = (rv | rm) & U64_MAX
    v = (lv & rv) & U64_MAX
    m = ((alpha & beta) ^ v) & U64_MAX
    return v, m


def tnum_or(lv: int, lm: int, rv: int, rm: int) -> tuple[int, int]:
    """Compute tnum bitwise OR."""
    v = (lv | rv) & U64_MAX
    m = (lm | rm) & U64_MAX
    return v, m


def tnum_lshift(value: int, mask: int, shift: int) -> tuple[int, int]:
    """Compute tnum left shift by a constant."""
    v = (value << shift) & U64_MAX
    m = (mask << shift) & U64_MAX
    return v, m


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_trailing_int_from_expr(expression: str) -> int | None:
    """Extract the last integer literal from an expression string."""
    matches = re.findall(r"(-?(?:0x[0-9a-fA-F]+|\d+))", expression)
    if not matches:
        return None
    return _parse_int_safe(matches[-1])


def _parse_expected_types_from_expr(expression: str) -> list[str]:
    """Parse expected type names from a 'type_matches X, Y' expression."""
    if "matches" not in expression:
        return []
    _, _, rhs = expression.partition("matches")
    return [p.strip().lower() for p in rhs.split(",") if p.strip()]
