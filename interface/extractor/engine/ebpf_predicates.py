"""Map eBPF verifier error messages to proof predicates.

Given a verifier error message (and optionally some register state context),
infer what safety property was being checked and return an appropriate Predicate.
"""

from __future__ import annotations

import re

from .predicate import (
    ClassificationOnlyPredicate,
    CompositeAllPredicate,
    IntervalContainment,
    NullCheckPredicate,
    PacketAccessPredicate,
    PacketArithScalarBound,
    Predicate,
    ScalarBound,
    TypeMembership,
)

# ---------------------------------------------------------------------------
# Error message patterns -> predicate factories
# ---------------------------------------------------------------------------

_PACKET_ACCESS_RE = re.compile(
    r"invalid access to packet",
    re.IGNORECASE,
)
_MAP_VALUE_ACCESS_RE = re.compile(
    r"invalid access to map value",
    re.IGNORECASE,
)
_INVALID_MEM_ACCESS_RE = re.compile(
    r"invalid mem access '([^']+)'",
    re.IGNORECASE,
)
_OFFSET_OUTSIDE_RE = re.compile(
    r"offset is outside of the packet",
    re.IGNORECASE,
)
_UNBOUNDED_RE = re.compile(
    r"unbounded memory access",
    re.IGNORECASE,
)
_NULL_ACCESS_RE = re.compile(
    r"R(\d+) invalid mem access 'scalar'",
    re.IGNORECASE,
)
_PTR_NULL_ACCESS_RE = re.compile(
    r"R(\d+) invalid mem access 'ptr_or_null_",
    re.IGNORECASE,
)
_TYPE_MISMATCH_RE = re.compile(
    r"type=(\S+)\s+expected=(.+)",
    re.IGNORECASE,
)
_SCALAR_ARITH_RE = re.compile(
    r"math between (\S+) pointer and (\S+) is not allowed",
    re.IGNORECASE,
)
_LOOP_NOT_BOUNDED_RE = re.compile(
    r"loop is not bounded",
    re.IGNORECASE,
)
_COMPLEXITY_LIMIT_RE = re.compile(
    r"complexity limit",
    re.IGNORECASE,
)
_BACK_EDGE_RE = re.compile(
    r"back-edge",
    re.IGNORECASE,
)
_TRUSTED_RE = re.compile(
    r"expected trusted",
    re.IGNORECASE,
)
_UNRELEASED_RE = re.compile(
    r"unreleased reference|unacquired reference",
    re.IGNORECASE,
)
_ARG_TYPE_RE = re.compile(
    r"arg#\d+\s+(type\s+)?(\S+)\s+expected",
    re.IGNORECASE,
)
_LEADS_TO_INVALID_RE = re.compile(
    r"leads to invalid memory access",
    re.IGNORECASE,
)
_POINTER_ARITH_RE = re.compile(
    r"pointer arithmetic on (\S+) prohibited",
    re.IGNORECASE,
)
_MATH_BETWEEN_PKT_RE = re.compile(
    r"math between (?:pkt|packet|ctx) pointer and .+(?:unbounded|register)",
    re.IGNORECASE,
)
_POSSIBLY_NULL_RE = re.compile(
    r"(?:Possibly |)NULL pointer passed to (?:trusted|helper) arg(\d+)",
    re.IGNORECASE,
)
_UNRELEASED_REF_RE = re.compile(
    r"Unreleased reference id=\d+",
    re.IGNORECASE,
)
_UNACQUIRED_REF_RE = re.compile(
    r"unacquired reference id=\d+",
    re.IGNORECASE,
)
_MUST_BE_REFERENCED_RE = re.compile(
    r"must be referenced",
    re.IGNORECASE,
)
_REG_TYPE_EXPECTED_RE = re.compile(
    r"R\d+\s+type=(\S+)\s+expected=(.+)",
    re.IGNORECASE,
)
_CONTEXT_ACCESS_RE = re.compile(
    r"invalid bpf_context access",
    re.IGNORECASE,
)

# ── IRQ / locking / RCU discipline ─────────────────────────────────────────
_IRQ_INITIALIZED_RE = re.compile(
    r"expected (?:an )?initialized irq flag as arg#\d+",
    re.IGNORECASE,
)
_IRQ_UNINITIALIZED_RE = re.compile(
    r"expected uninitialized irq flag as arg#\d+",
    re.IGNORECASE,
)
_IRQ_NOT_ON_STACK_RE = re.compile(
    r"arg#\d+ doesn't point to an irq flag on stack",
    re.IGNORECASE,
)
_IRQ_OOO_RE = re.compile(
    r"cannot restore irq state out of order",
    re.IGNORECASE,
)
_IRQ_EXIT_REGION_RE = re.compile(
    r"BPF_EXIT instruction.*cannot be used inside.*(?:irq|lock|rcu|bpf_local_irq)",
    re.IGNORECASE,
)
_LOCK_FUNCTION_CALL_RE = re.compile(
    r"function calls are not allowed while holding a lock",
    re.IGNORECASE,
)
_SLEEPABLE_CONTEXT_RE = re.compile(
    r"(?:global functions that may sleep are not allowed|"
    r"kernel func .* is sleepable within IRQ-disabled|"
    r"a non-sleepable BPF program context|"
    r"sleepable func .* in non-sleepable)",
    re.IGNORECASE,
)

# ── Reference / kref lifetime ───────────────────────────────────────────────
_BPF_EXIT_REFERENCE_LEAK_RE = re.compile(
    r"BPF_EXIT instruction.*would lead to reference leak",
    re.IGNORECASE,
)
_UNACQUIRED_REFERENCE_RE = re.compile(
    r"arg \d+ is an unacquired reference",
    re.IGNORECASE,
)
_RELEASE_EXPECTS_RE = re.compile(
    r"release kernel function .* expects refcounted",
    re.IGNORECASE,
)

# ── Dynptr protocol ──────────────────────────────────────────────────────────
_DYNPTR_EXPECTED_INIT_RE = re.compile(
    r"Expected an initialized dynptr as arg #\d+",
    re.IGNORECASE,
)
_DYNPTR_EXPECTED_UNINIT_RE = re.compile(
    r"(?:Dynptr has to be an uninitialized dynptr|"
    r"expected uninitialized dynptr)",
    re.IGNORECASE,
)
_DYNPTR_OVERWRITE_RE = re.compile(
    r"cannot overwrite referenced dynptr",
    re.IGNORECASE,
)
_DYNPTR_POTENTIAL_WRITE_RE = re.compile(
    r"potential write to dynptr at off=",
    re.IGNORECASE,
)
_DYNPTR_OFFSET_RE = re.compile(
    r"cannot pass in dynptr at an offset",
    re.IGNORECASE,
)
_DYNPTR_EXPECTED_TYPE_RE = re.compile(
    r"Expected a dynptr of type .* as arg #\d+",
    re.IGNORECASE,
)
_DYNPTR_CONST_STRUCT_RE = re.compile(
    r"arg#\d+ expected pointer to stack or const struct bpf_dynptr",
    re.IGNORECASE,
)
_DYNPTR_FP_RE = re.compile(
    r"Unsupported reg type fp for bpf_dynptr_from_mem",
    re.IGNORECASE,
)

# ── Iterator protocol ────────────────────────────────────────────────────────
_ITER_EXPECTED_INIT_RE = re.compile(
    r"expected (?:an )?initialized iter_\w+ as arg #\d+",
    re.IGNORECASE,
)
_ITER_EXPECTED_UNINIT_RE = re.compile(
    r"expected uninitialized iter_\w+ as arg #\d+",
    re.IGNORECASE,
)
_ITER_ON_STACK_RE = re.compile(
    r"arg#\d+ expected pointer to an iterator on stack",
    re.IGNORECASE,
)

# ── Stack access ─────────────────────────────────────────────────────────────
_STACK_READ_RE = re.compile(
    r"invalid (?:indirect )?read from stack",
    re.IGNORECASE,
)
_STACK_MISALIGN_RE = re.compile(
    r"misaligned stack access off",
    re.IGNORECASE,
)

# ── Generic memory access ────────────────────────────────────────────────────
_MEMORY_ACCESS_RE = re.compile(
    r"invalid access to memory, mem_size=\d+ off=-?\d+ size=\d+",
    re.IGNORECASE,
)

# ── Env / JIT / helper availability ─────────────────────────────────────────
_JIT_KFUNC_RE = re.compile(
    r"JIT does not support calling kfunc",
    re.IGNORECASE,
)
_CALLING_KFUNC_NOT_ALLOWED_RE = re.compile(
    r"calling kernel function .* is not allowed",
    re.IGNORECASE,
)
_EXCEPTION_CB_RE = re.compile(
    r"(?:insn \d+ )?cannot call exception cb directly",
    re.IGNORECASE,
)
_MULTIPLE_EXCEPTION_CB_RE = re.compile(
    r"multiple exception callback tags",
    re.IGNORECASE,
)
_ATTACH_UNSUPPORTED_RE = re.compile(
    r"attach to unsupported member",
    re.IGNORECASE,
)
_HELPER_NOT_ALLOWED_RE = re.compile(
    r"helper call is not allowed|program of this type cannot use helper",
    re.IGNORECASE,
)
_UNKNOWN_FUNC_RE = re.compile(
    r"unknown func",
    re.IGNORECASE,
)
_GLOBAL_FUNC_NO_SCALAR_RE = re.compile(
    r"Global function .* doesn't return scalar",
    re.IGNORECASE,
)
_GLOBAL_FUNC_SLEEPABLE_RE = re.compile(
    r"global functions that may sleep are not allowed",
    re.IGNORECASE,
)
_CANNOT_CALL_FROM_CALLBACK_RE = re.compile(
    r"cannot be called from callback",
    re.IGNORECASE,
)

# ── Verifier limits ──────────────────────────────────────────────────────────
_COMBINED_STACK_RE = re.compile(
    r"combined stack size of \d+ calls is \d+\. Too large",
    re.IGNORECASE,
)
_STACK_DEPTH_EXCEEDS_RE = re.compile(
    r"stack depth \d+ exceeds",
    re.IGNORECASE,
)
_TOO_MANY_STATES_RE = re.compile(
    r"too many states",
    re.IGNORECASE,
)
_JUMPS_TOO_COMPLEX_RE = re.compile(
    r"The sequence of .* jumps is too complex",
    re.IGNORECASE,
)
_BPF_PROG_TOO_LARGE_RE = re.compile(
    r"BPF program is too large",
    re.IGNORECASE,
)

# ── Return value / register contract ────────────────────────────────────────
_AT_EXIT_RE = re.compile(
    r"At program exit the register R\d+ has",
    re.IGNORECASE,
)
_RCU_POINTER_RE = re.compile(
    r"R\d+ must be a rcu pointer",
    re.IGNORECASE,
)
_PTR_COMPARISON_RE = re.compile(
    r"R\d+ pointer comparison prohibited",
    re.IGNORECASE,
)
_NOT_READ_OK_RE = re.compile(
    r"R\d+ !read_ok",
    re.IGNORECASE,
)
_ZERO_SIZED_READ_RE = re.compile(
    r"R\d+ invalid zero-sized read",
    re.IGNORECASE,
)

# ── BTF metadata errors ──────────────────────────────────────────────────────
_BTF_UNKNOWN_SIZE_RE = re.compile(
    r"reference type\('UNKNOWN '\) size cannot be determined",
    re.IGNORECASE,
)
_BTF_INVALID_ID_RE = re.compile(
    r"invalid btf[_ ]id",
    re.IGNORECASE,
)
_BTF_MISSING_RE = re.compile(
    r"missing btf func_info|failed to find kernel BTF type ID",
    re.IGNORECASE,
)
_INVALID_BTF_NAME_RE = re.compile(
    r"\[\d+\]\s+.*\s+Invalid name",
    re.IGNORECASE,
)

# ── Specific type mismatch patterns ─────────────────────────────────────────
_ARG_POINTER_TYPE_MUST_RE = re.compile(
    r"arg#\d+ pointer type .+ must point",
    re.IGNORECASE,
)
_KFUNC_ARG_TYPE_MISMATCH_RE = re.compile(
    r"kernel function \S+ args#\d+ expected pointer to",
    re.IGNORECASE,
)
_REG_TYPE_FP_EXPECTED_RE = re.compile(
    r"R\d+\s+type=(?:ctx|inv|map_value|scalar|fp)\s+expected=fp",
    re.IGNORECASE,
)
_REG_TYPE_MAP_PTR_RE = re.compile(
    r"R\d+\s+type=(?:inv|map_value)\s+expected=map_ptr",
    re.IGNORECASE,
)
_PERCPU_PTR_RE = re.compile(
    r"type=scalar expected=percpu_ptr_",
    re.IGNORECASE,
)
_WRITE_RDONLY_RE = re.compile(
    r"cannot write into rdonly_mem|the prog does not allow writes to packet data",
    re.IGNORECASE,
)
_ONLY_READ_ARRAY_RE = re.compile(
    r"only read from bpf_array is supported",
    re.IGNORECASE,
)
_NO_VALID_KPTR_RE = re.compile(
    r"R\d+ has no valid kptr",
    re.IGNORECASE,
)
_MUST_BE_KNOWN_CONSTANT_RE = re.compile(
    r"(?:R\d+ )?must be a known constant",
    re.IGNORECASE,
)
_MEM_LEN_PAIR_RE = re.compile(
    r"arg#\d+\s+arg#\d+\s+memory,\s+len pair leads to invalid memory access",
    re.IGNORECASE,
)
_CALLER_INVALID_ARGS_RE = re.compile(
    r"Caller passes invalid args into func",
    re.IGNORECASE,
)


def _extract_register_from_error(error_msg: str) -> list[str]:
    """Extract referenced register names from an error message."""
    regs = re.findall(r'\bR(\d+)\b', error_msg)
    return [f"R{n}" for n in regs] if regs else ["R0", "R1", "R2"]


def _infer_target_regs(error_msg: str, register_states: dict) -> list[str]:
    """Determine which registers are most relevant to the error."""
    mentioned = _extract_register_from_error(error_msg)
    if mentioned:
        return mentioned[:3]  # Use up to 3 mentioned registers
    # Fall back to all registers in state
    return [k for k in register_states if k.startswith("R")][:4]


def infer_predicate(error_msg: str, register_states: dict) -> Predicate | None:
    """From a verifier error message, determine what safety property was being checked.

    Args:
        error_msg: The verifier error message (e.g., "invalid access to packet").
        register_states: Dict of register name -> RegisterState at the error point.
                         May be empty if not available.

    Returns:
        A Predicate instance, or None if the error cannot be mapped to a predicate.
    """
    if not error_msg:
        return None

    msg = error_msg.strip()
    target_regs = _infer_target_regs(msg, register_states)

    # ── Packet access ──────────────────────────────────────────────────────────
    if _PACKET_ACCESS_RE.search(msg) or _OFFSET_OUTSIDE_RE.search(msg):
        return PacketAccessPredicate(
            target_regs=target_regs,
            access_size=None,  # unknown
        )

    # ── Math between pkt pointer and unbounded register ─────────────────────────
    # e.g., "math between pkt pointer and register with unbounded min value is not allowed"
    if _MATH_BETWEEN_PKT_RE.search(msg):
        # The scalar register being added to the pkt pointer must be bounded.
        # Find the non-pkt registers (the scalar), and check them with ScalarBound.
        # Use a PacketArithScalarBound predicate so obligation maps to "packet_access".
        scalar_regs = [
            r for r in target_regs
            if r in register_states
            and hasattr(register_states.get(r), "type")
            and "pkt" not in getattr(register_states.get(r), "type", "").lower()
        ] or target_regs
        return PacketArithScalarBound(
            target_regs=scalar_regs,
            umax_limit=(1 << 31) - 1,  # must be a bounded scalar
        )

    # ── Map value access ────────────────────────────────────────────────────────
    if _MAP_VALUE_ACCESS_RE.search(msg):
        return IntervalContainment(
            target_regs=target_regs,
            max_range=None,
            field_name="range",
        )

    # ── "invalid mem access 'scalar'" — null/type dereference ──────────────────
    null_match = _NULL_ACCESS_RE.search(msg)
    if null_match:
        reg_n = null_match.group(1)
        return NullCheckPredicate(target_regs=[f"R{reg_n}"])

    ptr_null_match = _PTR_NULL_ACCESS_RE.search(msg)
    if ptr_null_match:
        reg_n = ptr_null_match.group(1)
        return NullCheckPredicate(target_regs=[f"R{reg_n}"])

    # ── Generic invalid mem access ──────────────────────────────────────────────
    mem_match = _INVALID_MEM_ACCESS_RE.search(msg)
    if mem_match:
        bad_type = mem_match.group(1).lower()
        if "scalar" in bad_type:
            # Dereferencing a scalar — need a pointer type
            return TypeMembership(
                target_regs=target_regs,
                allowed_types={"ptr", "map_value", "pkt", "ctx", "bpf_"},
                forbidden_types={"scalar"},
            )
        if "ptr_or_null" in bad_type or "mem_or_null" in bad_type or "or_null" in bad_type:
            # Null pointer dereference — need a non-null pointer
            return NullCheckPredicate(target_regs=target_regs)
        # Generic type check
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr", "map_value", "pkt", "ctx"},
            forbidden_types={"scalar"},
        )

    # ── Unbounded memory access ─────────────────────────────────────────────────
    if _UNBOUNDED_RE.search(msg):
        return ScalarBound(
            target_regs=target_regs,
            umax_limit=0xFFFF,  # reasonable upper bound for memory access
        )

    # ── Type mismatch ───────────────────────────────────────────────────────────
    type_match = _TYPE_MISMATCH_RE.search(msg)
    if type_match:
        expected = type_match.group(2).strip().split()
        return TypeMembership(
            target_regs=target_regs,
            allowed_types=set(expected),
        )

    # ── Leads to invalid memory access (kfunc/helper arg check) ────────────────
    if _LEADS_TO_INVALID_RE.search(msg):
        # The argument being passed is likely a pointer that lost its type
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr", "map_value", "pkt", "trusted", "bpf_"},
            forbidden_types={"scalar", "ptr_or_null"},
        )

    # ── "Possibly NULL pointer passed to trusted argN" ──────────────────────────
    possibly_null_match = _POSSIBLY_NULL_RE.search(msg)
    if possibly_null_match:
        # The argument passed to a kfunc must not be null
        return NullCheckPredicate(target_regs=target_regs or ["R1", "R2", "R3"])

    # ── Unreleased reference ────────────────────────────────────────────────────
    if _UNRELEASED_REF_RE.search(msg) or _UNACQUIRED_REF_RE.search(msg) or _MUST_BE_REFERENCED_RE.search(msg):
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr_bpf_", "bpf_", "trusted", "ptr_"},
        )

    # ── R<n> type=X expected=Y ──────────────────────────────────────────────────
    reg_type_match = _REG_TYPE_EXPECTED_RE.search(msg)
    if reg_type_match:
        expected_types = reg_type_match.group(2).strip().split("|")
        return TypeMembership(
            target_regs=target_regs,
            allowed_types=set(t.strip() for t in expected_types),
        )

    # ── Invalid bpf_context access ──────────────────────────────────────────────
    if _CONTEXT_ACCESS_RE.search(msg):
        return IntervalContainment(
            target_regs=target_regs,
            max_range=None,
            field_name="off",
        )

    # ── Trusted pointer requirements ────────────────────────────────────────────
    if _TRUSTED_RE.search(msg):
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"trusted", "ptr_bpf_", "ptr_or_null_"},
        )

    # ── Pointer arithmetic prohibited ───────────────────────────────────────────
    ptr_arith_match = _POINTER_ARITH_RE.search(msg)
    if ptr_arith_match:
        ptr_type = ptr_arith_match.group(1)
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"scalar"},  # arithmetic only valid on scalars
            forbidden_types={ptr_type},
        )

    # ── Loop / complexity limits ────────────────────────────────────────────────
    if _LOOP_NOT_BOUNDED_RE.search(msg) or _COMPLEXITY_LIMIT_RE.search(msg) or _BACK_EDGE_RE.search(msg):
        return ScalarBound(
            target_regs=target_regs,
            umax_limit=1000000,  # complexity proxy
        )

    # ── Unreleased reference ────────────────────────────────────────────────────
    if _UNRELEASED_RE.search(msg):
        # Reference must be released — this is a resource management predicate
        # Map to TypeMembership checking for reference-type register
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr_bpf_", "bpf_", "trusted"},
        )

    # ── IRQ flag protocol ───────────────────────────────────────────────────────
    if _IRQ_INITIALIZED_RE.search(msg):
        # arg must be an initialized irq_flag type on the stack
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"irq_flag", "fp"},
        )

    if _IRQ_UNINITIALIZED_RE.search(msg):
        # arg must be an uninitialized irq_flag slot (write-before-read)
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"fp"},
            forbidden_types={"irq_flag"},
        )

    if _IRQ_NOT_ON_STACK_RE.search(msg):
        # The argument must be a frame pointer (on-stack address)
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"fp"},
            forbidden_types={"scalar", "ptr"},
        )

    if _IRQ_OOO_RE.search(msg):
        # IRQ save/restore ordering is tracked at the structural level.
        # No register safety predicate; this is a control-flow discipline error.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E020",
            taxonomy_class="source_bug",
            description="IRQ state restore order violation — must match LIFO acquire order",
        )

    if _IRQ_EXIT_REGION_RE.search(msg):
        # Cannot exit program while in an IRQ-disabled or lock-held region.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E013",
            taxonomy_class="source_bug",
            description="BPF_EXIT inside IRQ/lock region — must release before exit",
        )

    if _LOCK_FUNCTION_CALL_RE.search(msg):
        # Function calls disallowed while holding a lock (kfunc/spinlock discipline).
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E013",
            taxonomy_class="source_bug",
            description="Function call inside lock-held critical section",
        )

    if _SLEEPABLE_CONTEXT_RE.search(msg):
        # Sleepable function called in non-sleepable context (IRQ, softirq, etc.)
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Sleepable function/program in non-sleepable execution context",
        )

    # ── Reference / kref lifetime errors ────────────────────────────────────────
    if _BPF_EXIT_REFERENCE_LEAK_RE.search(msg):
        # A kref/reference was acquired but not released before program exit.
        return TypeMembership(
            target_regs=target_regs or ["R0"],
            allowed_types={"ptr_bpf_", "bpf_", "trusted", "ptr_"},
        )

    if _UNACQUIRED_REFERENCE_RE.search(msg):
        # Releasing a reference that was never acquired.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr_bpf_", "bpf_", "trusted", "ptr_"},
            forbidden_types={"scalar"},
        )

    if _RELEASE_EXPECTS_RE.search(msg):
        # Release function expects a refcounted PTR_TO_BTF_ID.
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"ptr_bpf_", "trusted_ptr_", "rcu_ptr_"},
            forbidden_types={"scalar", "fp"},
        )

    # ── Dynptr protocol errors ───────────────────────────────────────────────────
    if _DYNPTR_EXPECTED_INIT_RE.search(msg):
        # Dynptr argument must already be initialized.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"dynptr", "fp"},
        )

    if _DYNPTR_EXPECTED_UNINIT_RE.search(msg):
        # Dynptr must be uninitialized before bpf_dynptr_from_* call.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"fp"},
            forbidden_types={"dynptr"},
        )

    if _DYNPTR_OVERWRITE_RE.search(msg):
        # Cannot overwrite a referenced (initialized) dynptr slot.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"fp"},
            forbidden_types={"dynptr"},
        )

    if _DYNPTR_POTENTIAL_WRITE_RE.search(msg):
        # Write into a dynptr slot at a fixed offset is disallowed.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E019",
            taxonomy_class="source_bug",
            description="Potential write to dynptr storage slot at fixed offset",
        )

    if _DYNPTR_OFFSET_RE.search(msg):
        # Dynptr must be passed at offset 0 (constant).
        return IntervalContainment(
            target_regs=target_regs,
            max_range=0,
            field_name="off",
        )

    if _DYNPTR_EXPECTED_TYPE_RE.search(msg):
        # Dynptr type mismatch (e.g., skb dynptr passed where ringbuf expected).
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"dynptr", "ringbuf_mem", "mem"},
        )

    if _DYNPTR_CONST_STRUCT_RE.search(msg):
        # arg must be a stack pointer to a bpf_dynptr struct.
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"fp"},
            forbidden_types={"scalar", "map_value"},
        )

    if _DYNPTR_FP_RE.search(msg):
        # bpf_dynptr_from_mem data arg cannot be a frame pointer.
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            forbidden_types={"fp"},
            allowed_types={"map_value", "mem", "pkt"},
        )

    # ── Iterator protocol errors ─────────────────────────────────────────────────
    if _ITER_EXPECTED_INIT_RE.search(msg):
        # Iterator must be initialized before use.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"iter", "fp"},
        )

    if _ITER_EXPECTED_UNINIT_RE.search(msg):
        # Iterator must be uninitialized for bpf_iter_new.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"fp"},
            forbidden_types={"iter"},
        )

    if _ITER_ON_STACK_RE.search(msg):
        # Iterator argument must be a stack address.
        return TypeMembership(
            target_regs=target_regs or ["R1"],
            allowed_types={"fp"},
            forbidden_types={"scalar", "map_value", "ptr"},
        )

    # ── Stack access errors ──────────────────────────────────────────────────────
    if _STACK_READ_RE.search(msg):
        # Reading from uninitialized stack memory.
        return ScalarBound(
            target_regs=target_regs,
            check_non_negative=False,
            umax_limit=512,  # max BPF stack size
        )

    if _STACK_MISALIGN_RE.search(msg):
        # Misaligned stack slot access.
        return IntervalContainment(
            target_regs=target_regs,
            max_range=512,
            field_name="off",
        )

    # ── Generic memory access bounds ─────────────────────────────────────────────
    if _MEMORY_ACCESS_RE.search(msg):
        # Access to memory (dynptr slice, etc.) out of bounds.
        return IntervalContainment(
            target_regs=target_regs,
            max_range=None,
            field_name="range",
        )

    # ── Memory/len pair leading to invalid access ────────────────────────────────
    if _MEM_LEN_PAIR_RE.search(msg):
        # Helper argument: memory+length pair out of bounds.
        return IntervalContainment(
            target_regs=target_regs,
            max_range=None,
            field_name="umax",
        )

    # ── Caller passes invalid args into global func ──────────────────────────────
    if _CALLER_INVALID_ARGS_RE.search(msg):
        # Global function argument type mismatch — treat as generic type error.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"fp", "map_value", "pkt", "ptr", "trusted"},
        )

    # ── Environment / JIT / helper availability ──────────────────────────────────
    if _JIT_KFUNC_RE.search(msg):
        # JIT backend does not support this kfunc (e.g., bpf_throw).
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E009",
            taxonomy_class="env_mismatch",
            description="JIT does not support the requested kfunc — architecture or kernel version mismatch",
        )

    if _CALLING_KFUNC_NOT_ALLOWED_RE.search(msg):
        # Kfunc not allowed in this program type or context.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Kfunc call not permitted in the current program type or execution context",
        )

    if _EXCEPTION_CB_RE.search(msg):
        # Cannot call exception callback directly from BPF code.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Exception callback cannot be called directly from BPF programs",
        )

    if _MULTIPLE_EXCEPTION_CB_RE.search(msg):
        # Multiple exception callback tags on a single subprogram.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Multiple exception callback tags defined for the same subprogram",
        )

    if _ATTACH_UNSUPPORTED_RE.search(msg):
        # Attach target is not a supported struct-ops member.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Attach target is not a supported struct_ops member",
        )

    if _HELPER_NOT_ALLOWED_RE.search(msg):
        # Helper not allowed in this program type.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E009",
            taxonomy_class="env_mismatch",
            description="BPF helper not available in the current program type",
        )

    if _UNKNOWN_FUNC_RE.search(msg):
        # Unknown helper function ID.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E009",
            taxonomy_class="env_mismatch",
            description="Unknown BPF helper function",
        )

    if _GLOBAL_FUNC_NO_SCALAR_RE.search(msg):
        # Global function return type must be scalar.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Global function must return a scalar value",
        )

    if _CANNOT_CALL_FROM_CALLBACK_RE.search(msg):
        # Calling restricted function from a callback subprogram.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E016",
            taxonomy_class="env_mismatch",
            description="Function cannot be called from a callback subprogram",
        )

    # ── Verifier limits (no safety predicate — structural) ────────────────────────
    if _COMBINED_STACK_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E018",
            taxonomy_class="verifier_limit",
            description="Combined call stack size exceeds 512-byte limit",
        )

    if _STACK_DEPTH_EXCEEDS_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E018",
            taxonomy_class="verifier_limit",
            description="Function stack depth exceeds BPF limit",
        )

    if _TOO_MANY_STATES_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E007",
            taxonomy_class="verifier_limit",
            description="Too many verifier states; program control flow is too complex",
        )

    if _JUMPS_TOO_COMPLEX_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E007",
            taxonomy_class="verifier_limit",
            description="Sequence of jumps is too complex for the verifier to analyze",
        )

    if _BPF_PROG_TOO_LARGE_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E018",
            taxonomy_class="verifier_limit",
            description="BPF program instruction count exceeds the limit",
        )

    # ── Return value / register contract ────────────────────────────────────────
    if _AT_EXIT_RE.search(msg):
        # Program exit register has wrong value (e.g., R0 not in [0,0]).
        reg_match = re.search(r"R(\d+)", msg)
        regs = [f"R{reg_match.group(1)}"] if reg_match else target_regs
        return ScalarBound(
            target_regs=regs,
            umax_limit=1,  # typically R0 must be 0 at exit for some prog types
        )

    if _RCU_POINTER_RE.search(msg):
        # Register must be an RCU pointer type.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"rcu_ptr_", "trusted_ptr_"},
            forbidden_types={"scalar", "ptr_or_null"},
        )

    if _PTR_COMPARISON_RE.search(msg):
        # Pointer comparison is prohibited.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"scalar"},
            forbidden_types={"ptr", "map_value", "pkt"},
        )

    if _NOT_READ_OK_RE.search(msg):
        # Register is not readable in this context (uninitialized).
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"scalar", "ptr", "map_value"},
        )

    if _ZERO_SIZED_READ_RE.search(msg):
        # Zero-sized read is invalid.
        return ScalarBound(
            target_regs=target_regs,
            umax_limit=0,  # access size must be > 0
        )

    # ── BTF metadata errors ──────────────────────────────────────────────────────
    if _BTF_UNKNOWN_SIZE_RE.search(msg):
        # BTF type has UNKNOWN size — this is a metadata/toolchain issue.
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E021",
            taxonomy_class="env_mismatch",
            description="BTF reference type has UNKNOWN size — regenerate BTF artifacts",
        )

    if _BTF_INVALID_ID_RE.search(msg) or _BTF_MISSING_RE.search(msg) or _INVALID_BTF_NAME_RE.search(msg):
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E021",
            taxonomy_class="env_mismatch",
            description="BTF metadata is invalid or missing — check BTF artifacts and kernel version",
        )

    # ── Specific type/pointer mismatch patterns ──────────────────────────────────
    if _ARG_POINTER_TYPE_MUST_RE.search(msg):
        # arg#N pointer type X must point to Y
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"ptr", "trusted_ptr_", "fp"},
            forbidden_types={"scalar", "fp"},
        )

    if _KFUNC_ARG_TYPE_MISMATCH_RE.search(msg):
        # kernel function X args#N expected pointer to STRUCT Y
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"trusted_ptr_", "ptr_bpf_", "rcu_ptr_"},
            forbidden_types={"scalar"},
        )

    if _REG_TYPE_FP_EXPECTED_RE.search(msg):
        # Register type mismatch: expected frame pointer.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"fp"},
            forbidden_types={"scalar", "ctx", "map_value"},
        )

    if _REG_TYPE_MAP_PTR_RE.search(msg):
        # Register type mismatch: expected map_ptr.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"map_ptr"},
            forbidden_types={"scalar", "map_value", "inv"},
        )

    if _PERCPU_PTR_RE.search(msg):
        # Register should be percpu_ptr_ type, not scalar.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"percpu_ptr_"},
            forbidden_types={"scalar"},
        )

    if _WRITE_RDONLY_RE.search(msg):
        # Attempt to write to read-only memory (rdonly_mem or packet data).
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E019",
            taxonomy_class="source_bug",
            description="Write to read-only memory region (rdonly_mem or packet data)",
        )

    if _ONLY_READ_ARRAY_RE.search(msg):
        # Only read access to bpf_array is supported (mutable globals unsupported).
        return ClassificationOnlyPredicate(
            error_id="OBLIGE-E022",
            taxonomy_class="env_mismatch",
            description="Mutable bpf_array access unsupported in this environment",
        )

    if _NO_VALID_KPTR_RE.search(msg):
        # Register has no valid kptr — kptr_xchg requires a kptr-type field.
        return TypeMembership(
            target_regs=target_regs,
            allowed_types={"kptr", "ptr_bpf_", "trusted_ptr_"},
            forbidden_types={"scalar", "map_value"},
        )

    if _MUST_BE_KNOWN_CONSTANT_RE.search(msg):
        # A register value must be a compile-time constant (e.g., flags arg).
        return ScalarBound(
            target_regs=target_regs,
            umax_limit=(1 << 32) - 1,
        )

    return None


def _is_non_error_line(line: str) -> bool:
    """Return True if a line is clearly NOT a verifier error message.

    The log_parser sometimes picks up the final 'processed N insns' accounting
    line or a register-state dump line as the error_line. Detect these so the
    caller can fall back to scanning raw_log for the real error.
    """
    s = line.strip()
    if not s:
        return True
    if s.startswith("processed ") and "insns" in s:
        return True
    # Register state dumps: "R6=fp-8 R7=fp-24 ...", "R10=fp0 fp-8=ffffffff ..."
    if re.match(r"R\d+[_=]", s) and ("=" in s):
        return True
    # Instruction trace lines: "18: (63) ..." or "1: R1_w=..."
    if re.match(r"\d+:\s", s):
        return True
    return False


def _extract_error_from_raw_log(raw_log: str) -> str:
    """Scan raw_log in reverse and return the first line that looks like a real error.

    This is a fallback for when the log_parser's error_line field is set to a
    non-error line (e.g., 'processed N insns ...' or a register state dump).
    """
    skip_prefixes = (";", "fp", "0:")
    for line in reversed(raw_log.splitlines()):
        line = line.strip()
        if not line:
            continue
        if _is_non_error_line(line):
            continue
        if any(line.startswith(p) for p in skip_prefixes):
            continue
        return line
    return ""


def infer_predicate_from_trace(parsed_log, parsed_trace=None) -> Predicate | None:
    """Higher-level helper: infer a predicate from a ParsedLog and optionally a ParsedTrace.

    Uses the error message from the log and the register states at the error instruction.
    When the log_parser's error_line field is a non-error line (e.g., the final
    'processed N insns ...' accounting line), falls back to scanning raw_log for
    the actual error message.
    """
    if parsed_log is None:
        return None

    # Get error message
    error_msg = ""
    if hasattr(parsed_log, "error_line"):
        error_msg = parsed_log.error_line or ""
    elif isinstance(parsed_log, dict):
        error_msg = parsed_log.get("error_line", "") or parsed_log.get("error_message", "")

    # If error_line looks like a non-error line, try to extract the real error
    # from raw_log so we can still match a predicate.
    if _is_non_error_line(error_msg):
        raw_log = ""
        if hasattr(parsed_log, "raw_log"):
            raw_log = parsed_log.raw_log or ""
        elif isinstance(parsed_log, dict):
            raw_log = parsed_log.get("raw_log", "")
        if raw_log:
            error_msg = _extract_error_from_raw_log(raw_log) or error_msg

    # Get register states at error point
    register_states: dict = {}
    if parsed_trace is not None and hasattr(parsed_trace, "instructions"):
        # Find the error instruction and get its state
        for insn in parsed_trace.instructions:
            if insn.is_error:
                register_states = insn.pre_state or insn.post_state or {}
                break
        # Fallback: use last instruction's state
        if not register_states and parsed_trace.instructions:
            last = parsed_trace.instructions[-1]
            register_states = last.post_state or last.pre_state or {}

    return infer_predicate(error_msg, register_states)
