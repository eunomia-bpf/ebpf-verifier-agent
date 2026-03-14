"""Template-based repair synthesizer for eBPF verifier failures.

Generates concrete repair suggestions based on the proof-loss analysis
from the TraceMonitor. This is a pilot implementation focused on the most
common lowering artifact patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .monitor import MonitorResult
from .predicate import (
    IntervalContainment,
    NullCheckPredicate,
    PacketAccessPredicate,
    Predicate,
    ScalarBound,
    TypeMembership,
)


@dataclass
class RepairSuggestion:
    """A concrete repair suggestion."""

    repair_type: str
    """Type of repair: 'insert_null_check', 'insert_bounds_check',
    'insert_range_check', 'restrict_access', 'add_mask', etc."""

    description: str
    """Human-readable description of the repair."""

    code_patch: str | None
    """Suggested C code patch (may be None if we can only describe)."""

    confidence: str
    """'high', 'medium', 'low'"""

    proof_context: str | None = None
    """Context about the proof loss that motivated this repair."""


class RepairSynthesizer:
    """Synthesize repairs based on proof-loss analysis."""

    def synthesize(
        self,
        monitor_result: MonitorResult,
        predicate: Predicate | None,
        traced_insns,
        source_code: str,
    ) -> RepairSuggestion | None:
        """Generate a repair based on the proof-loss analysis.

        Args:
            monitor_result: Result from TraceMonitor.monitor().
            predicate: The predicate that was being monitored.
            traced_insns: The traced instructions (for context).
            source_code: The original buggy source code.

        Returns:
            A RepairSuggestion, or None if no repair can be synthesized.
        """
        if predicate is None:
            return None

        status = monitor_result.proof_status

        if status == "established_then_lost":
            return self._repair_lowering_artifact(monitor_result, predicate, traced_insns, source_code)
        elif status == "never_established":
            return self._repair_missing_check(monitor_result, predicate, source_code)
        elif status == "established_but_insufficient":
            return self._repair_insufficient(monitor_result, predicate, source_code)

        return None

    def _repair_lowering_artifact(
        self,
        result: MonitorResult,
        predicate: Predicate,
        traced_insns,
        source_code: str,
    ) -> RepairSuggestion | None:
        """Repair a lowering artifact: proof was established then lost.

        The fix is to re-assert the safety property at the point where it was lost.
        Common causes: stack spill/fill of pointer loses type info, conditional
        branch not taken, compiler re-orders operations.
        """
        loss_insn_idx = result.loss_site
        establish_insn_idx = result.establish_site

        # Find the loss instruction to understand context
        loss_insn = None
        establish_insn = None
        for insn in (traced_insns or []):
            if insn.insn_idx == loss_insn_idx:
                loss_insn = insn
            if insn.insn_idx == establish_insn_idx:
                establish_insn = insn

        proof_context = (
            f"Proof established at insn {establish_insn_idx}, "
            f"lost at insn {loss_insn_idx}: {result.loss_reason}"
        )

        if isinstance(predicate, NullCheckPredicate):
            return self._repair_lowering_null_check(
                result, predicate, loss_insn, source_code, proof_context
            )
        elif isinstance(predicate, (PacketAccessPredicate, IntervalContainment)):
            return self._repair_lowering_bounds(
                result, predicate, loss_insn, source_code, proof_context
            )
        elif isinstance(predicate, TypeMembership):
            return self._repair_lowering_type(
                result, predicate, loss_insn, source_code, proof_context
            )
        elif isinstance(predicate, ScalarBound):
            return self._repair_lowering_scalar(
                result, predicate, loss_insn, source_code, proof_context
            )

        # Generic fallback
        return RepairSuggestion(
            repair_type="generic_lowering_fix",
            description=(
                f"Proof was established at instruction {establish_insn_idx} "
                f"but lost at instruction {loss_insn_idx}. "
                "This is likely a compiler lowering artifact. "
                "Consider adding an explicit bounds check or type assertion "
                "at the point of failure."
            ),
            code_patch=None,
            confidence="low",
            proof_context=proof_context,
        )

    def _repair_missing_check(
        self,
        result: MonitorResult,
        predicate: Predicate,
        source_code: str,
    ) -> RepairSuggestion | None:
        """Repair a source bug: the safety property was never established.

        The fix is to insert the missing check before the first use.
        """
        if isinstance(predicate, NullCheckPredicate):
            target_regs = predicate.target_regs
            reg_desc = " / ".join(target_regs[:2])
            # Find a variable that might correspond to the error register
            var_name = self._guess_variable_name(source_code, target_regs)
            patch = f"if (!{var_name})\n    return -EINVAL;  /* NULL check added by OBLIGE */\n"
            return RepairSuggestion(
                repair_type="insert_null_check",
                description=(
                    f"Register {reg_desc} is never confirmed non-null. "
                    "Add a null check before using this pointer."
                ),
                code_patch=patch,
                confidence="medium",
                proof_context="Proof never established: missing null check",
            )

        elif isinstance(predicate, PacketAccessPredicate):
            patch = (
                "if (data + sizeof(*hdr) > data_end)\n"
                "    return XDP_DROP;  /* bounds check added by OBLIGE */\n"
            )
            return RepairSuggestion(
                repair_type="insert_bounds_check",
                description=(
                    "Packet access without bounds check. "
                    "Add: if (data + SIZE > data_end) return XDP_DROP;"
                ),
                code_patch=patch,
                confidence="medium",
                proof_context="Proof never established: missing packet bounds check",
            )

        elif isinstance(predicate, IntervalContainment):
            patch = (
                "if (off + size > map_value_size)\n"
                "    return -E2BIG;  /* bounds check added by OBLIGE */\n"
            )
            return RepairSuggestion(
                repair_type="insert_bounds_check",
                description=(
                    "Map value access without bounds check. "
                    "Ensure the access offset and size are within the map value."
                ),
                code_patch=patch,
                confidence="medium",
                proof_context="Proof never established: missing bounds check",
            )

        elif isinstance(predicate, ScalarBound):
            limit = predicate.umax_limit or "MAX"
            patch = (
                f"if (idx >= {limit})\n"
                f"    return -ERANGE;  /* bound check added by OBLIGE */\n"
            )
            return RepairSuggestion(
                repair_type="insert_range_check",
                description=f"Scalar value exceeds {limit}. Add range check.",
                code_patch=patch,
                confidence="medium",
                proof_context="Proof never established: missing scalar bound check",
            )

        return None

    def _repair_insufficient(
        self,
        result: MonitorResult,
        predicate: Predicate,
        source_code: str,
    ) -> RepairSuggestion | None:
        """Repair established-but-insufficient: the right check exists but
        there's another issue (e.g., different register or different property).
        """
        return RepairSuggestion(
            repair_type="refine_existing_check",
            description=(
                "The proof was established but another safety property failed. "
                "The existing checks may be incomplete or check the wrong register. "
                "Review the verifier trace to identify the second failing property."
            ),
            code_patch=None,
            confidence="low",
            proof_context=(
                f"Proof established at insn {result.establish_site} "
                f"but error at insn {result.error_insn}"
            ),
        )

    # --------------------------------------------------------------------------
    # Lowering-specific repair helpers
    # --------------------------------------------------------------------------

    def _repair_lowering_null_check(
        self,
        result: MonitorResult,
        predicate: NullCheckPredicate,
        loss_insn,
        source_code: str,
        proof_context: str,
    ) -> RepairSuggestion:
        """For null-check lowering artifacts: the pointer was checked but the
        verifier lost track of the null-check result (common after spill/fill).

        Fix: add an explicit null check or use __builtin_assume / barrier_var.
        """
        target_regs = predicate.target_regs
        reg_desc = " / ".join(target_regs[:2])

        # Try to find the variable name in source
        var_name = self._guess_variable_name(source_code, target_regs)

        # The standard fix for this is to re-check after the spill/fill
        patch = (
            f"/* OBLIGE: Re-assert null check after spill/fill */\n"
            f"if (!{var_name})\n"
            f"    return -EINVAL;\n"
        )

        # Also suggest barrier_var if available
        barrier_variant = (
            f"/* Alternative: use barrier_var to prevent optimization */\n"
            f"barrier_var({var_name});\n"
            f"if (!{var_name})\n"
            f"    return -EINVAL;\n"
        )

        return RepairSuggestion(
            repair_type="insert_null_check",
            description=(
                f"Pointer {reg_desc} had null-check result lost after "
                f"stack spill/fill at instruction {result.loss_site}. "
                f"Insert a re-check of variable '{var_name}' after the spill, "
                "or use barrier_var() to prevent the compiler from hoisting the check."
            ),
            code_patch=patch,
            confidence="high",
            proof_context=proof_context,
        )

    def _repair_lowering_bounds(
        self,
        result: MonitorResult,
        predicate: Predicate,
        loss_insn,
        source_code: str,
        proof_context: str,
    ) -> RepairSuggestion:
        """For bounds/interval lowering artifacts: the range check was done but
        lost (common when accessing packet data across function calls or loops).
        """
        is_packet = isinstance(predicate, PacketAccessPredicate)
        access_type = "packet" if is_packet else "map value"

        patch = (
            f"/* OBLIGE: Re-assert {access_type} bounds check */\n"
        )
        if is_packet:
            patch += (
                "if (data + offset > data_end)\n"
                "    return XDP_DROP;\n"
            )
        else:
            patch += (
                "if (offset + size > value_size)\n"
                "    return -ERANGE;\n"
            )

        return RepairSuggestion(
            repair_type="insert_bounds_check",
            description=(
                f"{access_type.capitalize()} bounds check was established "
                f"at instruction {result.establish_site} but lost at "
                f"instruction {result.loss_site}. "
                "Insert a redundant bounds check at the point of loss, "
                "or ensure the access is consolidated before the bounds check."
            ),
            code_patch=patch,
            confidence="high" if is_packet else "medium",
            proof_context=proof_context,
        )

    def _repair_lowering_type(
        self,
        result: MonitorResult,
        predicate: TypeMembership,
        loss_insn,
        source_code: str,
        proof_context: str,
    ) -> RepairSuggestion:
        """For type-membership lowering artifacts: the pointer type was known
        but got downgraded (common after passing through helpers or kfuncs).
        """
        allowed = " | ".join(sorted(predicate.allowed_types))
        target_regs = predicate.target_regs
        reg_desc = " / ".join(target_regs[:2])

        var_name = self._guess_variable_name(source_code, target_regs)

        patch = (
            f"/* OBLIGE: Re-assert type check — {reg_desc} must be {allowed} */\n"
            f"if (!{var_name})\n"
            f"    return -EINVAL;\n"
        )

        return RepairSuggestion(
            repair_type="insert_type_check",
            description=(
                f"Register {reg_desc} had type information lost at "
                f"instruction {result.loss_site}. "
                f"Expected type: {allowed}. "
                "This typically happens when a pointer passes through a helper "
                "call that does not preserve the verifier's type tracking. "
                "Re-check the pointer after the call."
            ),
            code_patch=patch,
            confidence="medium",
            proof_context=proof_context,
        )

    def _repair_lowering_scalar(
        self,
        result: MonitorResult,
        predicate: ScalarBound,
        loss_insn,
        source_code: str,
        proof_context: str,
    ) -> RepairSuggestion:
        """For scalar-bound lowering artifacts."""
        limit = predicate.umax_limit or predicate.smin_floor or "N"
        target_regs = predicate.target_regs
        reg_desc = " / ".join(target_regs[:2])

        patch = (
            f"/* OBLIGE: Re-assert scalar bound for {reg_desc} */\n"
            f"if (idx >= {limit})\n"
            f"    return -ERANGE;\n"
        )

        return RepairSuggestion(
            repair_type="insert_range_check",
            description=(
                f"Scalar bound for {reg_desc} was established at "
                f"instruction {result.establish_site} but lost at "
                f"instruction {result.loss_site}. "
                f"Add a range check (value < {limit}) at the loss point."
            ),
            code_patch=patch,
            confidence="medium",
            proof_context=proof_context,
        )

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    def _guess_variable_name(self, source_code: str, target_regs: list[str]) -> str:
        """Try to guess a variable name from source code.

        Looks for pointer variable declarations near the error.
        Falls back to a generic name.
        """
        if not source_code:
            return "ptr"

        # Look for pointer declarations
        ptr_decl_re = re.compile(
            r'\b(\w+)\s*=\s*(?:bpf_map_lookup_elem|bpf_cpumask_create|bpf_ringbuf_reserve|'
            r'bpf_dynptr_data|bpf_task_acquire|bpf_get_current_task|bpf_obj_new)',
            re.IGNORECASE,
        )
        match = ptr_decl_re.search(source_code)
        if match:
            return match.group(1)

        # Look for struct pointer declarations
        struct_ptr_re = re.compile(
            r'struct\s+\w+\s*\*\s*(\w+)\s*;',
            re.IGNORECASE,
        )
        match = struct_ptr_re.search(source_code)
        if match:
            return match.group(1)

        # Look for simple pointer declarations
        ptr_decl2_re = re.compile(
            r'\b(?:void|int|char|__u8|__u16|__u32|__u64|u8|u16|u32|u64)\s*\*\s*(\w+)',
            re.IGNORECASE,
        )
        match = ptr_decl2_re.search(source_code)
        if match:
            return match.group(1)

        return "ptr"
