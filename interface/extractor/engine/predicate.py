"""Declarative predicates with interval arithmetic for eBPF verifier proof monitoring.

Predicates evaluate register states and determine whether a safety property
(proof obligation) is satisfied, violated, or unknown at a given point.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


class Predicate(ABC):
    """Abstract base class for verifier proof predicates."""

    @abstractmethod
    def evaluate(self, state: dict, insn: Any = None) -> str:
        """Evaluate the predicate against a register state snapshot.

        Args:
            state: dict mapping register names (e.g., 'R0') to RegisterState.
            insn: Optional TracedInstruction for context.

        Returns:
            'satisfied', 'violated', or 'unknown'
        """

    @abstractmethod
    def describe_violation(self, state: dict, insn: Any = None) -> str:
        """Human-readable explanation of why the predicate is violated."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


@dataclass
class IntervalContainment(Predicate):
    """Check that a register's offset/range is within bounds.

    Specifically: [reg.off, reg.off + reg.range] ⊆ [0, max_range]
    Used for packet/map access bounds checking.

    The 'target_regs' are the registers to check (e.g., ['R2', 'R3']).
    If 'max_range' is None, we check that the register has a finite range at all.
    """

    target_regs: list[str]
    max_range: int | None = None
    field_name: str = "range"  # which field to check: 'range', 'umax', 'smax'

    def evaluate(self, state: dict, insn: Any = None) -> str:
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is None:
                continue

            # Check if register has packet/pointer type
            reg_type = getattr(reg, "type", "")
            if not reg_type:
                continue

            # Evaluate interval containment
            off = getattr(reg, "off", None)
            rng = getattr(reg, "range", None)
            umax = getattr(reg, "umax", None)

            if self.field_name == "range" and rng is not None:
                if rng == 0:
                    return "unknown"  # no range tracked yet
                if self.max_range is not None and rng > self.max_range:
                    return "violated"
                if off is not None and off < 0:
                    return "violated"
                # Range is known and finite — check it's not unbounded
                if rng < (1 << 32):  # reasonable bound
                    return "satisfied"
                return "violated"

            elif self.field_name == "umax" and umax is not None:
                if self.max_range is not None and umax > self.max_range:
                    return "violated"
                if umax < (1 << 32):
                    return "satisfied"
                return "violated"

        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                off = getattr(reg, "off", "?")
                rng = getattr(reg, "range", "?")
                parts.append(f"{reg_name}: off={off}, range={rng}")
        regs_desc = "; ".join(parts) if parts else "unknown registers"
        return f"IntervalContainment violated: {regs_desc} (max_range={self.max_range})"


@dataclass
class TypeMembership(Predicate):
    """Check that a register's type is in an allowed set.

    Used for null checks (ptr_or_null -> ptr) and type checks.
    """

    target_regs: list[str]
    allowed_types: set[str]
    forbidden_types: set[str] | None = None

    def evaluate(self, state: dict, insn: Any = None) -> str:
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is None:
                continue

            reg_type = getattr(reg, "type", "")
            if not reg_type:
                return "unknown"

            # Check if type matches any allowed type (prefix match)
            type_lower = reg_type.lower()
            for allowed in self.allowed_types:
                if allowed.lower() in type_lower or type_lower.startswith(allowed.lower()):
                    # Also check it's not in forbidden
                    if self.forbidden_types:
                        for forbidden in self.forbidden_types:
                            if forbidden.lower() in type_lower:
                                return "violated"
                    return "satisfied"

            # Check forbidden types explicitly
            if self.forbidden_types:
                for forbidden in self.forbidden_types:
                    if forbidden.lower() in type_lower:
                        return "violated"

            # Type doesn't match allowed — check if it's scalar (which is often the problem)
            if "scalar" in type_lower:
                return "violated"

            return "unknown"

        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                parts.append(f"{reg_name}={getattr(reg, 'type', '?')}")
        regs_desc = ", ".join(parts) if parts else "unknown"
        return (
            f"TypeMembership violated: {regs_desc} not in {self.allowed_types}"
        )


@dataclass
class ScalarBound(Predicate):
    """Check scalar bound constraints.

    Used for: umax <= limit, smin >= 0, etc.
    Typically checks that a loop counter or offset is within bounds.
    """

    target_regs: list[str]
    umax_limit: int | None = None   # umax must be <= this
    smin_floor: int | None = None   # smin must be >= this
    check_non_negative: bool = False  # smin >= 0

    def evaluate(self, state: dict, insn: Any = None) -> str:
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is None:
                continue

            reg_type = getattr(reg, "type", "")
            if not reg_type:
                return "unknown"

            # Only meaningful for scalars
            # eBPF verifier uses "inv" (invalid pointer) to mean scalar
            type_lower = reg_type.lower()
            is_scalar = (
                "scalar" in type_lower
                or "int" in type_lower
                or type_lower.startswith("inv")
                or type_lower == "unknown"
            )
            if not is_scalar:
                return "unknown"

            umax = getattr(reg, "umax", None)
            smin = getattr(reg, "smin", None)

            if self.umax_limit is not None:
                if umax is None:
                    # Unbounded scalar — violated if we require a bound
                    return "violated"
                if umax > self.umax_limit:
                    return "violated"
                return "satisfied"

            if self.smin_floor is not None and smin is not None:
                if smin < self.smin_floor:
                    return "violated"
                return "satisfied"

            if self.check_non_negative and smin is not None:
                if smin < 0:
                    return "violated"
                return "satisfied"

        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                umax = getattr(reg, "umax", "?")
                smin = getattr(reg, "smin", "?")
                parts.append(f"{reg_name}: umax={umax}, smin={smin}")
        regs_desc = "; ".join(parts) if parts else "unknown"
        return (
            f"ScalarBound violated: {regs_desc} "
            f"(umax_limit={self.umax_limit}, smin_floor={self.smin_floor})"
        )


@dataclass
class NullCheckPredicate(Predicate):
    """Check that a register is not null (ptr_or_null was narrowed to ptr).

    This is the most common eBPF lowering artifact — after a null check,
    the verifier knows the pointer is non-null, but compiler lowering can
    lose that information across a stack spill/fill.
    """

    target_regs: list[str]

    def evaluate(self, state: dict, insn: Any = None) -> str:
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is None:
                continue

            reg_type = getattr(reg, "type", "")
            if not reg_type:
                return "unknown"

            type_lower = reg_type.lower()

            # ptr_or_null means null check NOT yet done
            if "ptr_or_null" in type_lower or "or_null" in type_lower:
                return "violated"

            # scalar means completely lost pointer type
            if type_lower == "scalar" or type_lower.startswith("scalar("):
                return "violated"

            # Any legitimate pointer type (ptr_, map_value, packet, etc.)
            if (
                "ptr" in type_lower
                or "map_value" in type_lower
                or "packet" in type_lower
                or "ctx" in type_lower
                or "bpf_" in type_lower
            ):
                if "or_null" not in type_lower:
                    return "satisfied"

        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                parts.append(f"{reg_name}={getattr(reg, 'type', '?')}")
        regs_desc = ", ".join(parts) if parts else "unknown"
        return f"NullCheck violated: {regs_desc} is null or ptr_or_null"


@dataclass
class PacketAccessPredicate(Predicate):
    """Check that packet data access is within bounds.

    Specifically: the register used for packet access must have type 'pkt'
    (or similar) and off+size <= range.
    """

    target_regs: list[str]
    access_size: int | None = None  # bytes being accessed

    def evaluate(self, state: dict, insn: Any = None) -> str:
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is None:
                continue

            reg_type = getattr(reg, "type", "")
            type_lower = reg_type.lower()

            # Must be a packet-type register
            is_pkt = (
                "pkt" in type_lower
                or "packet" in type_lower
                or "ctx" in type_lower
            )
            if not is_pkt:
                if "scalar" in type_lower:
                    return "violated"
                return "unknown"

            off = getattr(reg, "off", None) or 0
            rng = getattr(reg, "range", None)

            if rng is None:
                return "unknown"

            if rng == 0:
                return "violated"

            # In the eBPF verifier, 'range' (r=N in register state) is the
            # number of bytes from pkt_start that have been verified accessible.
            # 'off' is the absolute offset from pkt_start.
            # Access at off with size bytes requires: off + size <= range.
            size = self.access_size or 1
            if off is None:
                # No offset info — just check range is non-zero
                return "satisfied" if rng > 0 else "violated"
            if off + size <= rng:
                return "satisfied"
            return "violated"

        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                off = getattr(reg, "off", "?")
                rng = getattr(reg, "range", "?")
                parts.append(f"{reg_name}: off={off}, range={rng}")
        regs_desc = "; ".join(parts) if parts else "unknown"
        return f"PacketAccess violated: {regs_desc} (access_size={self.access_size})"


@dataclass
class CompositeAllPredicate(Predicate):
    """A predicate that is satisfied only when ALL sub-predicates are satisfied."""

    predicates: list[Predicate]

    def evaluate(self, state: dict, insn: Any = None) -> str:
        results = [p.evaluate(state, insn) for p in self.predicates]
        if all(r == "satisfied" for r in results):
            return "satisfied"
        if any(r == "violated" for r in results):
            return "violated"
        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        violations = [
            p.describe_violation(state, insn)
            for p in self.predicates
            if p.evaluate(state, insn) == "violated"
        ]
        return "; ".join(violations) if violations else "CompositeAll violation"


@dataclass
class ClassificationOnlyPredicate(Predicate):
    """A predicate for errors that can be classified but have no meaningful
    register-level safety property to check via abstract state analysis.

    This applies to meta-errors (verifier limits, JIT restrictions, environment
    mismatches, IRQ/lock discipline violations) where the verifier already
    provides the definitive diagnosis and no lifecycle analysis is needed.

    evaluate() always returns 'unknown' because the error is not a register
    safety property violation — it's a structural/environmental constraint.
    """

    error_id: str
    taxonomy_class: str
    description: str

    def evaluate(self, state: dict, insn: Any = None) -> str:
        # Classification-only predicates cannot be evaluated against register state.
        # The verifier's own error message is the complete diagnosis.
        return "unknown"

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        return (
            f"ClassificationOnly[{self.error_id}]: {self.description} "
            f"(taxonomy={self.taxonomy_class}; no register-level predicate applies)"
        )


@dataclass
class PacketArithScalarBound(ScalarBound):
    """Scalar bound predicate for math-between-pkt-pointer errors.

    Like ScalarBound, but classified as a packet_access obligation.
    Used when a scalar register is being added to a packet pointer but
    the scalar is unbounded (e.g., 'math between pkt pointer and register
    with unbounded min value is not allowed').
    """

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        parts = []
        for reg_name in self.target_regs:
            reg = state.get(reg_name)
            if reg is not None:
                umax = getattr(reg, "umax", "?")
                smin = getattr(reg, "smin", "?")
                parts.append(f"{reg_name}: umax={umax}, smin={smin}")
        regs_desc = "; ".join(parts) if parts else "unknown"
        return (
            f"PacketArith violated: {regs_desc} is unbounded "
            f"(cannot add unbounded scalar to pkt pointer)"
        )
