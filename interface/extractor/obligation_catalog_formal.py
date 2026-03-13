"""Formal obligation catalog derived from Linux kernel BPF verifier source.

Each FormalObligation is extracted directly from the check_* functions in
kernel/bpf/verifier.c (v6.8+).  The precondition expressions use the field
names that appear in bpf_reg_state and are observable in LOG_LEVEL2 output.

Source file analysed: kernel/bpf/verifier.c (26,199 lines)

Field name conventions (matching bpf_reg_state):
  reg.type        — enum bpf_reg_type, e.g. PTR_TO_PACKET, SCALAR_VALUE, NOT_INIT
  reg.smin_value  — signed 64-bit minimum
  reg.smax_value  — signed 64-bit maximum
  reg.umin_value  — unsigned 64-bit minimum
  reg.umax_value  — unsigned 64-bit maximum
  reg.off         — fixed accumulated offset (s32), part of pointer representation
  reg.range       — proven packet range (u32); only valid on PTR_TO_PACKET*
  reg.var_off     — tnum (value + mask) encoding variable part of offset
  reg.ref_obj_id  — reference tracking ID (non-zero means acquired reference)
  reg.btf_id      — BTF type ID for PTR_TO_BTF_ID registers
  access_size     — width of the memory access (1/2/4/8 bytes, from instruction)
  access_off      — fixed offset in the instruction encoding
  access_type     — BPF_READ or BPF_WRITE

BPF_MAX_VAR_OFF  = 0x7fffffff   (max variable offset magnitude)
BPF_MAX_VAR_SIZ  = 0x7fff8000   (max size arg to helpers)
MAX_BPF_STACK    = 512           (bytes; stack grows from 0 downward to -512)
NET_IP_ALIGN     = 2             (packet alignment offset for alignment check)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Core dataclass
# ---------------------------------------------------------------------------

@dataclass
class FormalObligation:
    """A proof obligation extracted from the Linux BPF verifier source.

    Attributes
    ----------
    family:
        Obligation family name (matches OBLIGATION_FAMILIES keys in
        obligation_inference.py).
    precondition:
        Formal string expression for the obligation.  Python-style boolean
        expression; field names follow bpf_reg_state conventions.
    fields_needed:
        List of bpf_reg_state fields the precondition depends on.
    error_patterns:
        Regex patterns (uncompiled) matching the verifier verbose() strings
        that are emitted when this obligation is violated.
    verifier_function:
        The check_* function in verifier.c that enforces this obligation.
    verifier_line:
        Approximate line number in verifier.c (kernel v6.8+).
    evaluable:
        True  — can be fully evaluated from LOG_LEVEL2 trace data alone.
        False — requires information not in the trace (e.g. map metadata).
    evaluable_note:
        Explanation of why the obligation is only partially or not evaluable.
    source_condition:
        The verbatim C condition from verifier.c that guards the rejection.
    """

    family: str
    precondition: str
    fields_needed: list[str]
    error_patterns: list[str]
    verifier_function: str
    verifier_line: int
    evaluable: bool
    evaluable_note: str = ""
    source_condition: str = ""


# ---------------------------------------------------------------------------
# Compiled catalog
# ---------------------------------------------------------------------------

FORMAL_OBLIGATIONS: list[FormalObligation] = [

    # -----------------------------------------------------------------------
    # 1. packet_access — check_packet_access
    # -----------------------------------------------------------------------

    FormalObligation(
        family="packet_access",
        precondition="reg.smin_value >= 0",
        fields_needed=["smin_value"],
        error_patterns=[
            r"R\d+ min value is negative, either use unsigned index or do a if \(index >=0\) check\.",
        ],
        verifier_function="check_packet_access",
        verifier_line=6338,
        evaluable=True,
        source_condition="if (reg->smin_value < 0)",
    ),

    FormalObligation(
        family="packet_access",
        precondition=(
            "reg.range >= 0 "
            "AND (access_off + reg.off) >= 0 "
            "AND (access_off + reg.off + access_size) <= reg.range"
        ),
        fields_needed=["range", "off"],
        error_patterns=[
            r"R\d+ offset is outside of the packet",
            r"invalid access to packet, off=\S+ size=\S+",
        ],
        verifier_function="check_packet_access",
        verifier_line=6344,
        evaluable=True,
        evaluable_note=(
            "reg.range is printed as r=N in packet register state "
            "(e.g. R3(id=0,off=0,r=32)). access_off comes from instruction encoding."
        ),
        source_condition=(
            "err = reg->range < 0 ? -EINVAL : "
            "__check_mem_access(env, regno, off, size, reg->range, zero_size_allowed);"
        ),
    ),

    # -----------------------------------------------------------------------
    # 2. map_value_bounds — check_mem_region_access + check_map_access_type
    # -----------------------------------------------------------------------

    FormalObligation(
        family="map_value_access",
        precondition=(
            "reg.smin_value >= 0 "
            "OR (access_off + reg.smin_value == (s32)(access_off + reg.smin_value) "
            "    AND access_off + reg.smin_value >= 0)"
        ),
        fields_needed=["smin_value"],
        error_patterns=[
            r"R\d+ min value is negative, either use unsigned index or do a if \(index >=0\) check\.",
        ],
        verifier_function="check_mem_region_access",
        verifier_line=5888,
        evaluable=True,
        source_condition=(
            "if (reg->smin_value < 0 && "
            "(reg->smin_value == S64_MIN || "
            " (off + reg->smin_value != (s64)(s32)(off + reg->smin_value)) || "
            "  reg->smin_value + off < 0))"
        ),
    ),

    FormalObligation(
        family="map_value_access",
        precondition="reg.umax_value < 0x7fffffff",  # BPF_MAX_VAR_OFF
        fields_needed=["umax_value"],
        error_patterns=[
            r"R\d+ unbounded memory access, make sure to bounds check any such access",
        ],
        verifier_function="check_mem_region_access",
        verifier_line=5908,
        evaluable=True,
        source_condition="if (reg->umax_value >= BPF_MAX_VAR_OFF)",
    ),

    FormalObligation(
        family="map_value_access",
        precondition=(
            "reg.smin_value + access_off >= 0 "
            "AND reg.smin_value + access_off + access_size <= map.value_size"
        ),
        fields_needed=["smin_value"],
        error_patterns=[
            r"R\d+ min value is outside of the allowed memory range",
            r"invalid access to map value, value_size=\d+ off=\S+ size=\S+",
        ],
        verifier_function="__check_mem_access",
        verifier_line=5840,
        evaluable=False,
        evaluable_note=(
            "map.value_size is NOT printed in the LOG_LEVEL2 trace; "
            "it appears in the error message text. Can be recovered by "
            "parsing 'value_size=%d' from the error message."
        ),
        source_condition=(
            "if (off >= 0 && size_ok && (u64)off + size <= mem_size) return 0;"
            "  /* else emit error */"
        ),
    ),

    FormalObligation(
        family="map_value_access",
        precondition=(
            "reg.umax_value + access_off + access_size <= map.value_size"
        ),
        fields_needed=["umax_value"],
        error_patterns=[
            r"R\d+ max value is outside of the allowed memory range",
        ],
        verifier_function="check_mem_region_access",
        verifier_line=5913,
        evaluable=False,
        evaluable_note="map.value_size not in trace; recoverable from error message.",
        source_condition=(
            "err = __check_mem_access(env, regno, reg->umax_value + off, size, "
            "mem_size, zero_size_allowed);"
        ),
    ),

    FormalObligation(
        family="map_value_access",
        precondition="access_type == BPF_READ OR map has BPF_MAP_CAN_WRITE capability",
        fields_needed=[],
        error_patterns=[
            r"write into map forbidden, value_size=\d+ off=\S+ size=\S+",
            r"read from map forbidden, value_size=\d+ off=\S+ size=\S+",
        ],
        verifier_function="check_map_access_type",
        verifier_line=5817,
        evaluable=False,
        evaluable_note="Map capability flags are not printed in the trace.",
        source_condition="if (type == BPF_WRITE && !(cap & BPF_MAP_CAN_WRITE))",
    ),

    # -----------------------------------------------------------------------
    # 3. null_check / register_initialized — __check_reg_arg
    # -----------------------------------------------------------------------

    FormalObligation(
        family="null_check",
        precondition="reg.type != NOT_INIT",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ !read_ok",
        ],
        verifier_function="__check_reg_arg",
        verifier_line=3941,
        evaluable=True,
        source_condition="if (reg->type == NOT_INIT)",
    ),

    FormalObligation(
        family="null_check",
        precondition="regno != BPF_REG_FP (R10) when used as write destination",
        fields_needed=[],
        error_patterns=[
            r"frame pointer is read only",
        ],
        verifier_function="__check_reg_arg",
        verifier_line=3955,
        evaluable=True,
        evaluable_note="Determined from instruction bytecode destination register.",
        source_condition="if (regno == BPF_REG_FP) { verbose(env, \"frame pointer is read only\"); }",
    ),

    # -----------------------------------------------------------------------
    # 4. stack_access — check_stack_access_within_bounds
    # -----------------------------------------------------------------------

    FormalObligation(
        family="stack_access",
        precondition=(
            "reg.smax_value < 0x7fffffff "   # BPF_MAX_VAR_OFF
            "AND reg.smin_value > -0x7fffffff"
        ),
        fields_needed=["smax_value", "smin_value"],
        error_patterns=[
            r"invalid unbounded variable-offset(?:\s+\w+)*\s+stack R\d+",
        ],
        verifier_function="check_stack_access_within_bounds",
        verifier_line=7625,
        evaluable=True,
        source_condition=(
            "if (reg->smax_value >= BPF_MAX_VAR_OFF || "
            "    reg->smin_value <= -BPF_MAX_VAR_OFF)"
        ),
    ),

    FormalObligation(
        family="stack_access",
        precondition=(
            "# Constant-offset case:\n"
            "min_off = reg.var_off.value + access_off\n"
            "max_off = min_off + access_size\n"
            "REQUIRE: min_off >= -512 AND max_off <= 0"
        ),
        fields_needed=["var_off"],
        error_patterns=[
            r"invalid(?:\s+\w+)*\s+stack R\d+ off=\S+ size=\S+",
        ],
        verifier_function="check_stack_access_within_bounds",
        verifier_line=7644,
        evaluable=True,
        evaluable_note=(
            "var_off is printed as (value; mask). When constant, "
            "var_off.value + access_off must be in [-512, 0)."
        ),
        source_condition=(
            "min_off = (s64)reg->var_off.value + off; "
            "max_off = min_off + access_size; "
            "check_stack_slot_within_bounds(min_off); "
            "if (max_off > 0) err = -EINVAL;"
        ),
    ),

    FormalObligation(
        family="stack_access",
        precondition=(
            "# Variable-offset case:\n"
            "min_off = reg.smin_value + access_off\n"
            "max_off = reg.smax_value + access_off + access_size\n"
            "REQUIRE: min_off >= -512 AND max_off <= 0"
        ),
        fields_needed=["smin_value", "smax_value", "var_off"],
        error_patterns=[
            r"invalid variable-offset(?:\s+\w+)*\s+stack R\d+ var_off=.+? off=\S+ size=\S+",
        ],
        verifier_function="check_stack_access_within_bounds",
        verifier_line=7644,
        evaluable=True,
        source_condition=(
            "min_off = reg->smin_value + off; "
            "max_off = reg->smax_value + off + access_size;"
        ),
    ),

    # -----------------------------------------------------------------------
    # 5. helper_arg_type / type_safety — check_reg_type, check_func_arg
    # -----------------------------------------------------------------------

    FormalObligation(
        family="helper_arg",
        precondition=(
            "reg.type (with flags masked per arg_type) IN compatible_reg_types[base_type(arg_type)]"
        ),
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ type=\S+ expected=\S+",
        ],
        verifier_function="check_reg_type",
        verifier_line=9463,
        evaluable=True,
        evaluable_note=(
            "Both actual type and expected type(s) are printed in the error message. "
            "The full compatible_reg_types table is in verifier.c and depends on "
            "arg_type which requires knowing the helper's prototype."
        ),
        source_condition=(
            "for (i ...) { if (type == compatible->types[i]) goto found; } "
            "verbose(env, \"R%d type=%s expected=%s\", ...);"
        ),
    ),

    FormalObligation(
        family="trusted_null_check",
        precondition=(
            "NOT (type_may_be_null(reg.type) "
            "     AND NOT type_may_be_null(arg_type))"
        ),
        fields_needed=["type"],
        error_patterns=[
            r"Possibly NULL pointer passed to helper arg\d+",
            r"Possibly NULL pointer passed to trusted arg\d+",
        ],
        verifier_function="check_reg_type",
        verifier_line=9508,
        evaluable=True,
        evaluable_note=(
            "type_may_be_null() checks for PTR_MAYBE_NULL flag in reg->type. "
            "This flag is included in the printed type string."
        ),
        source_condition=(
            "if (type_may_be_null(reg->type) && "
            "    (!type_may_be_null(arg_type) || arg_type_is_release(arg_type)))"
        ),
    ),

    FormalObligation(
        family="helper_arg",
        precondition=(
            "btf_struct_ids_match(reg.btf, reg.btf_id, reg.off, btf_vmlinux, arg_btf_id)"
        ),
        fields_needed=["btf_id", "off"],
        error_patterns=[
            r"R\d+ is of type \S+ but \S+ is expected",
        ],
        verifier_function="check_reg_type",
        verifier_line=9533,
        evaluable=False,
        evaluable_note=(
            "BTF type match requires the kernel BTF database. The actual and "
            "expected type names are printed in the error message. Exact BTF IDs "
            "are not printed in the trace."
        ),
        source_condition=(
            "if (!btf_struct_ids_match(&env->log, reg->btf, reg->btf_id, reg->off, "
            "                          btf_vmlinux, *arg_btf_id, strict_type_match))"
        ),
    ),

    FormalObligation(
        family="helper_arg",
        precondition="reg.type == SCALAR_VALUE (no pointer leak into helper)",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ leaks addr into helper function",
        ],
        verifier_function="check_func_arg",
        verifier_line=9860,
        evaluable=True,
        source_condition="if (is_pointer_value(env, regno)) { verbose(...\"leaks addr into helper\"); }",
    ),

    FormalObligation(
        family="helper_arg",
        precondition="reg.ref_obj_id != 0 when arg is a release-type argument",
        fields_needed=["ref_obj_id"],
        error_patterns=[
            r"R\d+ must be referenced when passed to release function",
        ],
        verifier_function="check_func_arg",
        verifier_line=9920,
        evaluable=True,
        evaluable_note="ref_obj_id is printed when non-zero in register state.",
        source_condition="} else if (!reg->ref_obj_id && !register_is_null(reg)) {",
    ),

    # -----------------------------------------------------------------------
    # 6. scalar_bounds — check_alu_op, adjust_reg_min_max_vals
    # -----------------------------------------------------------------------

    FormalObligation(
        family="scalar_bounds",
        precondition="0 <= shift_imm < operand_size_bits (32 for ALU32, 64 for ALU64)",
        fields_needed=[],
        error_patterns=[
            r"invalid shift \d+",
        ],
        verifier_function="check_alu_op",
        verifier_line=16559,
        evaluable=True,
        evaluable_note="Shift amount comes from instruction immediate, visible in bytecode.",
        source_condition="if (insn->imm < 0 || insn->imm >= size)",
    ),

    FormalObligation(
        family="scalar_bounds",
        precondition="imm != 0 when opcode is BPF_DIV or BPF_MOD with BPF_K source",
        fields_needed=[],
        error_patterns=[
            r"div by zero",
        ],
        verifier_function="check_alu_op",
        verifier_line=16549,
        evaluable=True,
        source_condition=(
            "if ((opcode == BPF_MOD || opcode == BPF_DIV) && "
            "    BPF_SRC(insn->code) == BPF_K && insn->imm == 0)"
        ),
    ),

    FormalObligation(
        family="scalar_bounds",
        precondition="reg.type == SCALAR_VALUE (not a pointer) for NEG/END operations",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ pointer arithmetic prohibited",
        ],
        verifier_function="check_alu_op",
        verifier_line=16361,
        evaluable=True,
        source_condition="if (is_pointer_value(env, insn->dst_reg))",
    ),

    FormalObligation(
        family="scalar_bounds",
        precondition=(
            "NOT (ptr_reg.type & PTR_MAYBE_NULL) "
            "— pointer arithmetic requires null-checked pointer"
        ),
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ pointer arithmetic on \S+ prohibited, null-check it first",
        ],
        verifier_function="adjust_reg_min_max_vals",
        verifier_line=14883,
        evaluable=True,
        source_condition="if (ptr_reg->type & PTR_MAYBE_NULL)",
    ),

    FormalObligation(
        family="scalar_bounds",
        precondition=(
            "ptr_reg.type IN {PTR_TO_CTX, PTR_TO_MAP_VALUE, PTR_TO_MAP_KEY, "
            "PTR_TO_STACK, PTR_TO_PACKET, PTR_TO_PACKET_META, PTR_TO_TP_BUFFER, "
            "PTR_TO_BTF_ID, PTR_TO_MEM, PTR_TO_BUF, PTR_TO_FUNC, "
            "CONST_PTR_TO_DYNPTR, PTR_TO_FLOW_KEYS (constant offset only)}"
        ),
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ pointer arithmetic on \S+ prohibited$",
        ],
        verifier_function="adjust_reg_min_max_vals",
        verifier_line=14920,
        evaluable=True,
        source_condition="default: verbose(env, \"R%d pointer arithmetic on %s prohibited\", ...);",
    ),

    FormalObligation(
        family="scalar_bounds",
        precondition="src_reg.type == SCALAR_VALUE when sign-extending via BPF_MOV",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ sign-extension part of pointer",
            r"R\d+ partial copy of pointer",
        ],
        verifier_function="check_alu_op",
        verifier_line=16444,
        evaluable=True,
        source_condition="if (is_pointer_value(env, insn->src_reg))",
    ),

    # -----------------------------------------------------------------------
    # 7. reference_release — check_reference_leak
    # -----------------------------------------------------------------------

    FormalObligation(
        family="unreleased_reference",
        precondition=(
            "ALL registers with ref_obj_id != 0 and type REF_TYPE_PTR "
            "must have been released before program exit"
        ),
        fields_needed=["ref_obj_id"],
        error_patterns=[
            r"Unreleased reference id=\d+ alloc_insn=\d+",
            r"\S+ would lead to reference leak",
        ],
        verifier_function="check_reference_leak",
        verifier_line=11447,
        evaluable=False,
        evaluable_note=(
            "The state->acquired_refs array is not printed in LOG_LEVEL2 output. "
            "However, the error message reports the ref_obj_id and acquisition insn. "
            "ref_obj_id is printed on individual registers when non-zero."
        ),
        source_condition=(
            "for (i = 0; i < state->acquired_refs; i++) { "
            "  if (state->refs[i].type != REF_TYPE_PTR) continue; "
            "  verbose(env, \"Unreleased reference id=%d alloc_insn=%d\", ...); }"
        ),
    ),

    # -----------------------------------------------------------------------
    # 8. context_access — check_ctx_access
    # -----------------------------------------------------------------------

    FormalObligation(
        family="execution_context",
        precondition=(
            "off and size must correspond to a valid field of the program's "
            "context struct as determined by env->ops->is_valid_access"
        ),
        fields_needed=["off"],
        error_patterns=[
            r"invalid bpf_context access off=\S+ size=\S+",
        ],
        verifier_function="check_ctx_access",
        verifier_line=6394,
        evaluable=False,
        evaluable_note=(
            "Valid context fields depend on the BPF program type "
            "(env->ops->is_valid_access callback) and the ctx struct definition. "
            "The offset is visible from the instruction encoding + reg->off. "
            "Validity requires program-type-specific knowledge not in the trace."
        ),
        source_condition=(
            "if (!(env->ops->is_valid_access && "
            "      env->ops->is_valid_access(off, size, t, env->prog, info))) "
            "{ verbose(env, \"invalid bpf_context access\"); }"
        ),
    ),

    FormalObligation(
        family="execution_context",
        precondition="context pointer has not been modified (reg.off == 0, var_off == 0)",
        fields_needed=["off", "var_off"],
        error_patterns=[
            r"dereference of modified \S+ ptr R\d+ off=\S+ disallowed",
            r"negative offset \S+ ptr R\d+ off=\S+ disallowed",
            r"variable \S+ access var_off=\S+ disallowed",
        ],
        verifier_function="__check_ptr_off_reg",
        verifier_line=5932,
        evaluable=True,
        source_condition=(
            "if (reg->off < 0) { verbose(...\"negative offset\"); } "
            "if (!fixed_off_ok && reg->off) { verbose(...\"dereference of modified\"); } "
            "if (!tnum_is_const(reg->var_off) || reg->var_off.value) { verbose(...\"variable access\"); }"
        ),
    ),

    # -----------------------------------------------------------------------
    # 9. alignment — check_pkt_ptr_alignment, check_generic_ptr_alignment
    # -----------------------------------------------------------------------

    FormalObligation(
        family="packet_access",
        precondition=(
            "size == 1 "
            "OR NOT strict_alignment "
            "OR tnum_is_aligned(tnum_add(reg.var_off, tnum_const(2 + reg.off + access_off)), size)"
            "\n# i.e.: (NET_IP_ALIGN=2 + reg.var_off + reg.off + access_off) % size == 0"
        ),
        fields_needed=["var_off", "off"],
        error_patterns=[
            r"misaligned packet access off \d+\+\S+\+\d+\+\d+ size \d+",
        ],
        verifier_function="check_pkt_ptr_alignment",
        verifier_line=6580,
        evaluable=True,
        evaluable_note=(
            "var_off is printed as (value; mask). "
            "tnum_is_aligned(t, size) is True iff t.mask & (size-1) == 0 and t.value & (size-1) == 0. "
            "ip_align=2 is the NET_IP_ALIGN constant (hardcoded in verifier)."
        ),
        source_condition=(
            "reg_off = tnum_add(reg->var_off, tnum_const(ip_align + reg->off + off)); "
            "if (!tnum_is_aligned(reg_off, size)) { verbose(env, \"misaligned packet access\"); }"
        ),
    ),

    FormalObligation(
        family="memory_access",
        precondition=(
            "size == 1 "
            "OR NOT strict_alignment "
            "OR tnum_is_aligned(tnum_add(reg.var_off, tnum_const(reg.off + access_off)), size)"
            "\n# i.e.: (reg.var_off + reg.off + access_off) % size == 0"
        ),
        fields_needed=["var_off", "off"],
        error_patterns=[
            r"misaligned \S*access off \S+\+\d+\+\d+ size \d+",
        ],
        verifier_function="check_generic_ptr_alignment",
        verifier_line=6605,
        evaluable=True,
        source_condition=(
            "reg_off = tnum_add(reg->var_off, tnum_const(reg->off + off)); "
            "if (!tnum_is_aligned(reg_off, size)) { verbose(env, \"misaligned %saccess\"); }"
        ),
    ),

    # -----------------------------------------------------------------------
    # 10. memory_access (PTR_TO_MEM) — check_mem_access
    # -----------------------------------------------------------------------

    FormalObligation(
        family="memory_access",
        precondition="NOT type_may_be_null(reg.type)",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ invalid mem access '\S+'",
        ],
        verifier_function="check_mem_access",
        verifier_line=7769,
        evaluable=True,
        evaluable_note=(
            "type_may_be_null checks for PTR_MAYBE_NULL flag in reg->type. "
            "The type name printed includes this qualifier when set."
        ),
        source_condition="if (type_may_be_null(reg->type)) { verbose(env, \"R%d invalid mem access\"); }",
    ),

    FormalObligation(
        family="memory_access",
        precondition="access_type == BPF_READ OR NOT type_is_rdonly_mem(reg.type)",
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ cannot write into \S+",
        ],
        verifier_function="check_mem_access",
        verifier_line=7775,
        evaluable=True,
        evaluable_note=(
            "type_is_rdonly_mem checks for MEM_RDONLY flag. "
            "The type string includes RDONLY qualifier when printed."
        ),
        source_condition="if (t == BPF_WRITE && rdonly_mem) { verbose(env, \"R%d cannot write into\"); }",
    ),

    FormalObligation(
        family="memory_access",
        precondition=(
            "value_reg.type == SCALAR_VALUE "
            "(pointer values cannot be stored into map/mem/ctx/packet)"
        ),
        fields_needed=["type"],
        error_patterns=[
            r"R\d+ leaks addr into map",
            r"R\d+ leaks addr into mem",
            r"R\d+ leaks addr into ctx",
            r"R\d+ leaks addr into packet",
            r"R\d+ leaks addr into flow keys",
            r"R\d+ leaks addr as return value",
        ],
        verifier_function="check_mem_access",
        verifier_line=7718,
        evaluable=True,
        source_condition=(
            "if (t == BPF_WRITE && value_regno >= 0 && is_pointer_value(env, value_regno)) "
            "{ verbose(env, \"R%d leaks addr into ...\"); }"
        ),
    ),

    FormalObligation(
        family="memory_access",
        precondition="access_type == BPF_READ when reg.type == PTR_TO_MAP_KEY",
        fields_needed=["type"],
        error_patterns=[
            r"write to change key R\d+ not allowed",
        ],
        verifier_function="check_mem_access",
        verifier_line=7702,
        evaluable=True,
        source_condition=(
            "if (reg->type == PTR_TO_MAP_KEY) { "
            "  if (t == BPF_WRITE) { verbose(env, \"write to change key R%d not allowed\"); } }"
        ),
    ),

    # -----------------------------------------------------------------------
    # 11. Size argument to helpers
    # -----------------------------------------------------------------------

    FormalObligation(
        family="helper_arg",
        precondition="reg.smin_value >= 0 (size register must be non-negative)",
        fields_needed=["smin_value"],
        error_patterns=[
            r"R\d+ min value is negative, either use unsigned or 'var &= const'",
        ],
        verifier_function="check_mem_size",
        verifier_line=8453,
        evaluable=True,
        source_condition="if (reg->smin_value < 0)",
    ),

    FormalObligation(
        family="helper_arg",
        precondition="reg.umin_value > 0 (zero-size access not allowed for this helper)",
        fields_needed=["umin_value", "umax_value"],
        error_patterns=[
            r"R\d+ invalid zero-sized read: u64=\[\S+,\S+\]",
        ],
        verifier_function="check_mem_size",
        verifier_line=8459,
        evaluable=True,
        source_condition="if (reg->umin_value == 0 && !zero_size_allowed)",
    ),

    FormalObligation(
        family="helper_arg",
        precondition="reg.umax_value < 0x7fff8000 (BPF_MAX_VAR_SIZ)",
        fields_needed=["umax_value"],
        error_patterns=[
            r"R\d+ unbounded memory access, use 'var &= const' or 'if \(var < const\)'",
        ],
        verifier_function="check_mem_size",
        verifier_line=8465,
        evaluable=True,
        source_condition="if (reg->umax_value >= BPF_MAX_VAR_SIZ)",
    ),

]


# ---------------------------------------------------------------------------
# Index structures for quick lookup
# ---------------------------------------------------------------------------

def _build_error_pattern_index(
    obligations: list[FormalObligation],
) -> list[tuple[re.Pattern[str], FormalObligation]]:
    """Return a list of (compiled_regex, obligation) pairs for error matching."""
    index: list[tuple[re.Pattern[str], FormalObligation]] = []
    for ob in obligations:
        for pattern in ob.error_patterns:
            index.append((re.compile(pattern), ob))
    return index


def _build_family_index(
    obligations: list[FormalObligation],
) -> dict[str, list[FormalObligation]]:
    index: dict[str, list[FormalObligation]] = {}
    for ob in obligations:
        index.setdefault(ob.family, []).append(ob)
    return index


# Pre-built indices (initialised at import time)
ERROR_PATTERN_INDEX: list[tuple[re.Pattern[str], FormalObligation]] = (
    _build_error_pattern_index(FORMAL_OBLIGATIONS)
)
FAMILY_INDEX: dict[str, list[FormalObligation]] = (
    _build_family_index(FORMAL_OBLIGATIONS)
)


def match_error_message(error_msg: str) -> list[FormalObligation]:
    """Return all FormalObligations whose error_patterns match *error_msg*.

    The match is case-sensitive and uses re.search (substring match).
    Returns obligations in definition order.
    """
    results: list[FormalObligation] = []
    seen_ids: set[int] = set()
    for pattern, ob in ERROR_PATTERN_INDEX:
        if pattern.search(error_msg) and id(ob) not in seen_ids:
            results.append(ob)
            seen_ids.add(id(ob))
    return results


def obligations_for_family(family: str) -> list[FormalObligation]:
    """Return all obligations in a given family."""
    return FAMILY_INDEX.get(family, [])


def evaluable_obligations() -> list[FormalObligation]:
    """Return only obligations fully evaluable from LOG_LEVEL2 trace data."""
    return [ob for ob in FORMAL_OBLIGATIONS if ob.evaluable]


def partial_obligations() -> list[FormalObligation]:
    """Return obligations that are partially or not evaluable from trace."""
    return [ob for ob in FORMAL_OBLIGATIONS if not ob.evaluable]


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------

def summarize() -> str:
    """Return a human-readable summary of the catalog."""
    families = sorted(FAMILY_INDEX.keys())
    total = len(FORMAL_OBLIGATIONS)
    ev = sum(1 for o in FORMAL_OBLIGATIONS if o.evaluable)
    lines = [
        f"FormalObligation catalog: {total} obligations across {len(families)} families",
        f"  Evaluable from LOG_LEVEL2 trace: {ev}/{total}",
        "",
        "Families:",
    ]
    for fam in families:
        obs = FAMILY_INDEX[fam]
        ev_fam = sum(1 for o in obs if o.evaluable)
        lines.append(f"  {fam}: {len(obs)} obligations ({ev_fam} evaluable)")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summarize())
    print()
    # Demo: match an error message
    test_msg = "R3 min value is negative, either use unsigned index or do a if (index >=0) check."
    matches = match_error_message(test_msg)
    print(f"Matches for: {test_msg!r}")
    for m in matches:
        print(f"  family={m.family!r}  precondition={m.precondition!r}")
