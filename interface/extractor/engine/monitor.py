"""Generic trace monitor for proof obligation evaluation.

Evaluates a predicate at each traced instruction's register state to find
where a safety property was established, then where it was lost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MonitorResult:
    """Result of monitoring a predicate over a trace."""

    proof_status: str
    """
    - 'never_established': predicate never reached 'satisfied'
    - 'established_then_lost': predicate was satisfied then violated
    - 'established_but_insufficient': predicate was satisfied but error still occurred
    - 'unknown': could not determine (e.g., no instructions, no predicate)
    """

    establish_site: int | None
    """Instruction index where predicate was first satisfied."""

    loss_site: int | None
    """Instruction index where predicate flipped to 'violated' after being satisfied."""

    loss_reason: str | None
    """Human-readable description of why P was violated at loss_site."""

    last_satisfied_insn: int | None = None
    """Last instruction index where predicate was still satisfied."""

    error_insn: int | None = None
    """Instruction index of the verifier error (if any)."""


class TraceMonitor:
    """Evaluate a predicate over a sequence of TracedInstructions."""

    def monitor(self, predicate, traced_insns) -> MonitorResult:
        """Evaluate predicate at each instruction's register state.

        Finds the last instruction where P=satisfied, then the first after
        where P=violated.

        Args:
            predicate: A Predicate object with an evaluate(state) method.
                       evaluate() returns 'satisfied', 'violated', or 'unknown'.
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

        for insn in instructions:
            if insn.is_error and error_insn is None:
                error_insn = insn.insn_idx

            # Evaluate predicate against the post-state first, fall back to pre-state
            # Post-state reflects what the verifier knows after this instruction
            state_to_check = insn.post_state or insn.pre_state

            if not state_to_check:
                continue

            result = predicate.evaluate(state_to_check, insn)

            if result == "satisfied":
                if establish_site is None:
                    establish_site = insn.insn_idx
                last_satisfied_insn = insn.insn_idx
                # If we had a loss_site but now it's satisfied again, clear it
                # (predicate re-established downstream of a conditional)
                if loss_site is not None:
                    loss_site = None
                    loss_reason = None

            elif result == "violated":
                if establish_site is not None and loss_site is None:
                    # We had a satisfied run, now it's violated — this is the loss point
                    loss_site = insn.insn_idx
                    loss_reason = predicate.describe_violation(state_to_check, insn)

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
