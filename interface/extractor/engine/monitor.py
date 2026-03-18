"""Generic trace monitor for proof obligation evaluation.

Evaluates a predicate's verification gap at each traced instruction to find
where a safety property was materially established, then where it was lost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MonitorResult:
    """Result of monitoring a predicate over a trace."""

    proof_status: str
    """
    - 'never_established': predicate never reached gap=0 after a positive gap
    - 'established_then_lost': predicate reached gap=0, then later regressed
    - 'established_but_insufficient': predicate reached gap=0 but error still occurred
    - 'unknown': could not determine (e.g., no instructions, no predicate)
    """

    establish_site: int | None
    """Instruction index where the gap first transitioned from >0 to 0."""

    loss_site: int | None
    """Instruction index where the gap transitioned from 0 to >0."""

    loss_reason: str | None
    """Human-readable description of why P was violated at loss_site."""

    last_satisfied_insn: int | None = None
    """Last instruction index where predicate was still satisfied."""

    error_insn: int | None = None
    """Instruction index of the verifier error (if any)."""


class TraceMonitor:
    """Evaluate a predicate over a sequence of TracedInstructions."""

    def monitor(self, predicate, traced_insns) -> MonitorResult:
        """Evaluate a predicate's verification gap at each instruction.

        Establishment is recorded only when the gap transitions from positive
        to zero. Vacuous satisfaction (gap already zero at the start) does not
        count as proof establishment.

        Args:
            predicate: A Predicate-like object with compute_gap(state) and
                       describe_violation(state) methods.
            traced_insns: Iterable of TracedInstruction objects.

        Returns:
            MonitorResult describing the proof status.
        """
        if predicate is None:
            return MonitorResult(
                proof_status="unknown",
                establish_site=None,
                loss_site=None,
                loss_reason="No predicate provided",
            )

        instructions = list(traced_insns)
        if not instructions:
            return MonitorResult(
                proof_status="unknown",
                establish_site=None,
                loss_site=None,
                loss_reason="No instructions in trace",
            )

        establish_site: int | None = None
        last_satisfied_insn: int | None = None
        loss_site: int | None = None
        loss_reason: str | None = None
        error_insn: int | None = None
        previous_gap: int | None = None
        proof_active = False

        for insn in instructions:
            if insn.is_error and error_insn is None:
                error_insn = insn.insn_idx

            # Evaluate predicate against the post-state first, fall back to pre-state
            # Post-state reflects what the verifier knows after this instruction
            state_to_check = insn.post_state or insn.pre_state

            if not state_to_check:
                if insn.is_error:
                    break
                continue

            gap = predicate.compute_gap(state_to_check, insn)
            if gap is None:
                if insn.is_error:
                    break
                continue

            if previous_gap is not None and previous_gap > 0 and gap == 0:
                if establish_site is None:
                    establish_site = insn.insn_idx
                proof_active = True
                loss_site = None
                loss_reason = None

            elif previous_gap is not None and previous_gap == 0 and gap > 0:
                if loss_site is None:
                    loss_site = insn.insn_idx
                    loss_reason = predicate.describe_violation(state_to_check, insn)
                proof_active = False

            if gap == 0 and proof_active:
                last_satisfied_insn = insn.insn_idx

            previous_gap = gap

            if insn.is_error:
                break

        # Classify the proof status
        if establish_site is None:
            proof_status = "never_established"
        elif loss_site is not None:
            proof_status = "established_then_lost"
        elif error_insn is not None:
            # Predicate was established but there's still an error —
            # possibly a different safety property failed
            proof_status = "established_but_insufficient"
        else:
            # No error and predicate was satisfied — unusual but possible
            proof_status = "established_but_insufficient"

        return MonitorResult(
            proof_status=proof_status,
            establish_site=establish_site,
            loss_site=loss_site,
            loss_reason=loss_reason,
            last_satisfied_insn=last_satisfied_insn,
            error_insn=error_insn,
        )
