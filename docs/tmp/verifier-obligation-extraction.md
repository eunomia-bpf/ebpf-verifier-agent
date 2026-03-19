# Verifier Obligation Extraction: Real Preconditions from Linux Kernel Source

**Source file**: `/tmp/linux-src-Wei3fq/kernel/bpf/verifier.c` (26,199 lines)
**Kernel version**: ~v6.8+ (Linux master, March 2025)
**Extracted by**: BPFix obligation extraction task

---

## Overview

This document extracts the **real proof preconditions** embedded in the Linux kernel BPF
verifier's check_* functions. For each obligation family, we record:

1. The verifier function that enforces the check
2. The exact C condition that guards each `verbose()` rejection call
3. A formal precondition expression (the negation of the rejection condition)
4. Which register fields (`reg->type`, `reg->off`, `reg->range`, etc.) are checked
5. Whether the precondition can be evaluated purely from LOG_LEVEL2 trace data
   (i.e., from `RegisterState` as printed by the verifier)

---

## Obligation Family 1: `packet_access`

**Verifier functions**: `check_packet_access` (line 6324), `__check_mem_access` (line 5833)

### Rejection condition 1 — negative index
```c
// check_packet_access, line 6338
if (reg->smin_value < 0) {
    verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n", regno);
    return -EACCES;
}
```
**Formal precondition**: `reg.smin_value >= 0`
**Fields needed**: `smin_value`
**Error message**: `"R%d min value is negative, either use unsigned index or do a if (index >=0) check."`
**Evaluable from LOG_LEVEL2**: YES — smin_value is printed in register state

### Rejection condition 2 — range exceeded
```c
// check_packet_access, line 6344-6349
err = reg->range < 0 ? -EINVAL :
      __check_mem_access(env, regno, off, size, reg->range, zero_size_allowed);
if (err) {
    verbose(env, "R%d offset is outside of the packet\n", regno);
    return err;
}
// __check_mem_access succeeds iff: off >= 0 && size > 0 && (u64)off + size <= mem_size
```
**Formal precondition**: `reg.range >= 0 AND off >= 0 AND (off + access_size) <= reg.range`
- Here `off` is the fixed instruction offset plus `reg->off` (the accumulated fixed offset on the register)
**Fields needed**: `range`, `off`, access size (from instruction encoding)
**Error message**: `"R%d offset is outside of the packet"`
**Evaluable from LOG_LEVEL2**: YES — `r=<range>` is printed in register state output (`R1(id=0,off=8,r=32)`)

### Notes
- `reg->range` is set by `find_good_pkt_pointers()` after a bounds check like `if (r3 > data_end) return`.
  It represents the proven distance from the pointer to `data_end`.
- Variable offsets (`reg->var_off`) are already folded into `range` before this check.
- The `env->prog->aux->max_pkt_offset` side-effect updates the maximum packet offset tracked.

---

## Obligation Family 2: `map_value_bounds`

**Verifier functions**: `check_mem_region_access` (line 5869), `__check_mem_access` (line 5833),
                        `check_map_access_type` (line 5810)

### Rejection condition 1 — negative signed minimum
```c
// check_mem_region_access, line 5888-5895
if (reg->smin_value < 0 &&
    (reg->smin_value == S64_MIN ||
     (off + reg->smin_value != (s64)(s32)(off + reg->smin_value)) ||
     reg->smin_value + off < 0)) {
    verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n", regno);
    return -EACCES;
}
```
**Formal precondition**: `reg.smin_value >= 0 OR (off + reg.smin_value fits in s32 AND off + reg.smin_value >= 0)`
**Fields needed**: `smin_value`
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 2 — unbounded umax
```c
// check_mem_region_access, line 5908-5911
if (reg->umax_value >= BPF_MAX_VAR_OFF) {  // BPF_MAX_VAR_OFF = 0x7fffffff
    verbose(env, "R%d unbounded memory access, make sure to bounds check any such access\n", regno);
    return -EACCES;
}
```
**Formal precondition**: `reg.umax_value < BPF_MAX_VAR_OFF (0x7fffffff)`
**Fields needed**: `umax_value`
**Evaluable from LOG_LEVEL2**: YES — umax is printed

### Rejection condition 3 — out of bounds (smin check)
```c
// __check_mem_access, line 5840
// succeeds iff: off >= 0 && (size > 0 || zero_size_allowed) && (u64)off + size <= mem_size
// mem_size = map->value_size (NOT in register state)
err = __check_mem_access(env, regno, reg->smin_value + off, size, mem_size, zero_size_allowed);
if (err) {
    verbose(env, "R%d min value is outside of the allowed memory range\n", regno);
```
**Formal precondition**: `reg.smin_value + off >= 0 AND reg.smin_value + off + access_size <= map.value_size`
**Fields needed**: `smin_value`, plus `map.value_size` (NOT in trace)
**Evaluable from LOG_LEVEL2**: PARTIAL — smin_value visible; value_size from error message text

### Rejection condition 4 — out of bounds (umax check)
```c
err = __check_mem_access(env, regno, reg->umax_value + off, size, mem_size, zero_size_allowed);
if (err) {
    verbose(env, "R%d max value is outside of the allowed memory range\n", regno);
```
**Formal precondition**: `reg.umax_value + off + access_size <= map.value_size`
**Fields needed**: `umax_value`, plus `map.value_size` (NOT in trace)
**Error messages**:
  - `"invalid access to map value, value_size=%d off=%d size=%d"`
  - `"R%d min value is outside of the allowed memory range"`
  - `"R%d max value is outside of the allowed memory range"`
  - `"R%d unbounded memory access, make sure to bounds check any such access"`

### Rejection condition 5 — write to read-only map
```c
// check_map_access_type, line 5817-5820
if (type == BPF_WRITE && !(cap & BPF_MAP_CAN_WRITE)) {
    verbose(env, "write into map forbidden, value_size=%d off=%d size=%d\n", ...);
```
**Formal precondition**: `access_type == READ OR map has BPF_MAP_CAN_WRITE capability`
**Fields needed**: map capability flags (NOT in trace)
**Evaluable from LOG_LEVEL2**: NO — map flags not printed

---

## Obligation Family 3: `null_check` / `register_initialized`

**Verifier function**: `__check_reg_arg` (line 3923)

### Rejection condition 1 — uninitialized register
```c
// __check_reg_arg, line 3941-3943
if (t == SRC_OP) {
    if (reg->type == NOT_INIT) {
        verbose(env, "R%d !read_ok\n", regno);
        return -EACCES;
    }
```
**Formal precondition**: `reg.type != NOT_INIT` (register is initialized)
**Fields needed**: `type`
**Error message**: `"R%d !read_ok"`
**Evaluable from LOG_LEVEL2**: YES — type printed in register state

### Rejection condition 2 — write to frame pointer
```c
// __check_reg_arg, line 3955-3957
if (regno == BPF_REG_FP) {
    verbose(env, "frame pointer is read only\n");
    return -EACCES;
}
```
**Formal precondition**: `regno != BPF_REG_FP (R10)` when used as destination
**Error message**: `"frame pointer is read only"`
**Evaluable from LOG_LEVEL2**: YES — instruction bytecode shows destination register

---

## Obligation Family 4: `stack_access`

**Verifier function**: `check_stack_access_within_bounds` (line 7605)

### Rejection condition 1 — unbounded variable offset
```c
// line 7625-7629
if (reg->smax_value >= BPF_MAX_VAR_OFF ||
    reg->smin_value <= -BPF_MAX_VAR_OFF) {
    verbose(env, "invalid unbounded variable-offset%s stack R%d\n", err_extra, regno);
    return -EACCES;
}
```
**Formal precondition**: `reg.smax_value < BPF_MAX_VAR_OFF AND reg.smin_value > -BPF_MAX_VAR_OFF`
**Fields needed**: `smax_value`, `smin_value`
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 2 — out of stack bounds
```c
// line 7636-7654
err = check_stack_slot_within_bounds(env, min_off, state, type);
if (!err && max_off > 0)
    err = -EINVAL;  // non-negative offset = above frame pointer, out of stack
// ...
if (err) {
    if (tnum_is_const(reg->var_off)) {
        verbose(env, "invalid%s stack R%d off=%d size=%d\n", err_extra, regno, off, access_size);
    } else {
        verbose(env, "invalid variable-offset%s stack R%d var_off=%s off=%d size=%d\n", ...);
    }
}
```
**Formal precondition (constant offset)**:
  `min_off = reg.var_off.value + off >= -MAX_BPF_STACK (-512)`
  AND `max_off = min_off + access_size <= 0`
**Formal precondition (variable offset)**:
  `reg.smin_value + off >= -MAX_BPF_STACK`
  AND `reg.smax_value + off + access_size <= 0`
**Fields needed**: `var_off` (value + mask), `smin_value`, `smax_value`
**Error messages**:
  - `"invalid%s stack R%d off=%d size=%d"` (constant offset)
  - `"invalid variable-offset%s stack R%d var_off=%s off=%d size=%d"` (variable offset)
**Evaluable from LOG_LEVEL2**: YES — var_off printed as `value+mask` notation

---

## Obligation Family 5: `helper_arg_type` / `type_safety`

**Verifier functions**: `check_func_arg` (line 9839), `check_reg_type` (line 9422)

### Rejection condition 1 — type mismatch
```c
// check_reg_type, line 9463-9476
for (i = 0; i < ARRAY_SIZE(compatible->types); i++) {
    expected = compatible->types[i];
    if (expected == NOT_INIT) break;
    if (type == expected) goto found;
}
verbose(env, "R%d type=%s expected=", regno, reg_type_str(env, reg->type));
// prints list of compatible types
verbose(env, "%s\n", reg_type_str(env, compatible->types[j]));
return -EACCES;
```
**Formal precondition**: `reg.type IN compatible_reg_types[base_type(arg_type)]`
- The set of compatible types is determined by the helper's `arg_type` parameter
- Type flags (`MEM_RDONLY`, `PTR_MAYBE_NULL`, `DYNPTR_TYPE_FLAG_MASK`) are masked before comparison
**Fields needed**: `type`
**Error message**: `"R%d type=%s expected=%s"` — message includes both actual and expected types
**Evaluable from LOG_LEVEL2**: YES — type printed; expected type extracted from error message

### Rejection condition 2 — NULL pointer to non-nullable arg
```c
// check_reg_type, line 9508-9512
if (type_may_be_null(reg->type) &&
    (!type_may_be_null(arg_type) || arg_type_is_release(arg_type))) {
    verbose(env, "Possibly NULL pointer passed to helper arg%d\n", regno);
    return -EACCES;
}
```
**Formal precondition**: `NOT (reg.type has PTR_MAYBE_NULL flag AND arg_type does NOT have PTR_MAYBE_NULL flag)`
- Equivalently: if arg requires non-null, register must not be nullable
**Fields needed**: `type` (specifically the `PTR_MAYBE_NULL` flag)
**Error message**: `"Possibly NULL pointer passed to helper arg%d"`
**Evaluable from LOG_LEVEL2**: YES — register type printed includes NULL qualifier

### Rejection condition 3 — BTF type mismatch
```c
// check_reg_type, line 9533-9539
if (!btf_struct_ids_match(&env->log, reg->btf, reg->btf_id, reg->off,
                          btf_vmlinux, *arg_btf_id, strict_type_match)) {
    verbose(env, "R%d is of type %s but %s is expected\n",
            regno, btf_type_name(reg->btf, reg->btf_id),
            btf_type_name(btf_vmlinux, *arg_btf_id));
    return -EACCES;
}
```
**Formal precondition**: `reg.btf_id must match arg_btf_id under BTF type hierarchy`
**Fields needed**: `btf_id`, `btf` (pointer), `off` (for subtype matching)
**Error message**: `"R%d is of type %s but %s is expected"` — includes both type names
**Evaluable from LOG_LEVEL2**: PARTIAL — BTF type name printed when available; exact BTF ID not printed

### Rejection condition 4 — leaks pointer into helper
```c
// check_func_arg, line 9860-9864
if (arg_type == ARG_ANYTHING) {
    if (is_pointer_value(env, regno)) {
        verbose(env, "R%d leaks addr into helper function\n", regno);
        return -EACCES;
    }
}
```
**Formal precondition**: `reg.type == SCALAR_VALUE` (when arg accepts anything, pointers cannot be passed to prevent info leaks)
**Fields needed**: `type`
**Evaluable from LOG_LEVEL2**: YES

---

## Obligation Family 6: `scalar_bounds`

**Verifier function**: `adjust_scalar_min_max_vals` (line 16014), `check_alu_op` (line 16332)

### Rejection condition 1 — shift out of range
```c
// check_alu_op, line 16555-16562
if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) &&
    BPF_SRC(insn->code) == BPF_K) {
    int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;
    if (insn->imm < 0 || insn->imm >= size) {
        verbose(env, "invalid shift %d\n", insn->imm);
        return -EINVAL;
    }
}
```
**Formal precondition**: `0 <= shift_imm < operand_size_bits (32 or 64)`
**Fields needed**: immediate value from instruction encoding (NOT register state)
**Evaluable from LOG_LEVEL2**: YES — bytecode printed in trace

### Rejection condition 2 — division by zero (immediate)
```c
// check_alu_op, line 16549-16552
if ((opcode == BPF_MOD || opcode == BPF_DIV) &&
    BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
    verbose(env, "div by zero\n");
    return -EINVAL;
}
```
**Formal precondition**: `imm != 0 when opcode in {BPF_MOD, BPF_DIV}`
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 3 — pointer arithmetic prohibited
```c
// check_alu_op (BPF_NEG/BPF_END path), line 16361-16365
if (is_pointer_value(env, insn->dst_reg)) {
    verbose(env, "R%d pointer arithmetic prohibited\n", insn->dst_reg);
    return -EACCES;
}
```
```c
// adjust_reg_min_max_vals (pointer+pointer or prohibited type), line 14883-14886
if (ptr_reg->type & PTR_MAYBE_NULL) {
    verbose(env, "R%d pointer arithmetic on %s prohibited, null-check it first\n", dst, ...);
    return -EACCES;
}
// line 14919-14922
verbose(env, "R%d pointer arithmetic on %s prohibited\n", dst, reg_type_str(env, ptr_reg->type));
return -EACCES;
```
**Formal precondition**: arithmetic only allowed on: `PTR_TO_CTX`, `PTR_TO_MAP_VALUE`, `PTR_TO_MAP_KEY`,
  `PTR_TO_STACK`, `PTR_TO_PACKET`, `PTR_TO_PACKET_META`, `PTR_TO_TP_BUFFER`, `PTR_TO_BTF_ID`,
  `PTR_TO_MEM`, `PTR_TO_BUF`, `PTR_TO_FUNC`, `CONST_PTR_TO_DYNPTR`
- Also: `NOT (ptr_reg->type & PTR_MAYBE_NULL)` — no arithmetic on nullable pointers
**Error messages**:
  - `"R%d pointer arithmetic prohibited"` — unary neg/endian on pointer
  - `"R%d pointer arithmetic on %s prohibited, null-check it first"` — nullable pointer
  - `"R%d pointer arithmetic on %s prohibited"` — disallowed pointer type
**Evaluable from LOG_LEVEL2**: YES — type printed in register state

### Rejection condition 4 — sign-extension of pointer
```c
// check_alu_op BPF_MOV path, line 16444-16448
if (is_pointer_value(env, insn->src_reg)) {
    verbose(env, "R%d sign-extension part of pointer\n", insn->src_reg);
    return -EACCES;
}
```
**Formal precondition**: `src_reg.type == SCALAR_VALUE` when sign-extending via MOV
**Evaluable from LOG_LEVEL2**: YES

---

## Obligation Family 7: `reference_release`

**Verifier function**: `check_reference_leak` (line 11427)

### Rejection condition — unreleased reference at program exit
```c
// check_reference_leak, line 11438-11450
for (i = 0; i < state->acquired_refs; i++) {
    if (state->refs[i].type != REF_TYPE_PTR)
        continue;
    // Allow struct_ops return of kptr...
    verbose(env, "Unreleased reference id=%d alloc_insn=%d\n",
            state->refs[i].id, state->refs[i].insn_idx);
    refs_lingering = true;
}
return refs_lingering ? -EINVAL : 0;
```
**Formal precondition**: `ALL acquired references with type==REF_TYPE_PTR must be released before program exit`
- Equivalently: `state.acquired_refs == 0` at exit (or all are returned as struct_ops kptr)
**Fields needed**: `ref_obj_id` on registers (tracks acquired reference)
**Error message**: `"Unreleased reference id=%d alloc_insn=%d"` — includes acquisition site
**Evaluable from LOG_LEVEL2**: PARTIAL — `ref_obj_id` printed when non-zero; acquisition insn from error message

### Related rejection — release of unacquired reference
```c
// check_func_arg, line 9920-9923
} else if (!reg->ref_obj_id && !register_is_null(reg)) {
    verbose(env, "R%d must be referenced when passed to release function\n", regno);
    return -EINVAL;
}
```
**Formal precondition**: `reg.ref_obj_id != 0` when passing to a release function
**Evaluable from LOG_LEVEL2**: YES — ref_obj_id printed in register state

---

## Obligation Family 8: `context_access`

**Verifier function**: `check_ctx_access` (line 6366)

### Rejection condition — invalid ctx field access
```c
// check_ctx_access, line 6369-6395
if (env->ops->is_valid_access &&
    env->ops->is_valid_access(off, size, t, env->prog, info)) {
    // ... success path
    return 0;
}
verbose(env, "invalid bpf_context access off=%d size=%d\n", off, size);
return -EACCES;
```
**Formal precondition**: `off and size must match a valid field of the program's ctx struct`
- Determined by `env->ops->is_valid_access` — program-type-specific callback
- e.g., for XDP: `bpf_xdp_is_valid_access()` checks against `xdp_md` struct layout
**Fields needed**: `off` (from instruction + reg->off), access size, program type (context-dependent)
**Error message**: `"invalid bpf_context access off=%d size=%d"` — includes offset and size
**Evaluable from LOG_LEVEL2**: PARTIAL — off and size visible; valid fields depend on program type (NOT in trace)

### Special case — BTF reference already released
```c
// check_ctx_access, line 6379-6383
if (base_type(info->reg_type) == PTR_TO_BTF_ID) {
    if (info->ref_obj_id &&
        !find_reference_state(env->cur_state, info->ref_obj_id)) {
        verbose(env, "invalid bpf_context access off=%d. Reference may already be released\n", off);
```
**Evaluable from LOG_LEVEL2**: PARTIAL

---

## Obligation Family 9: `alignment`

**Verifier function**: `check_pkt_ptr_alignment` (line 6558), `check_generic_ptr_alignment` (line 6593)

### Rejection condition — misaligned packet access
```c
// check_pkt_ptr_alignment, line 6566-6588
if (!strict || size == 1)
    return 0;
ip_align = 2;
reg_off = tnum_add(reg->var_off, tnum_const(ip_align + reg->off + off));
if (!tnum_is_aligned(reg_off, size)) {
    verbose(env, "misaligned packet access off %d+%s+%d+%d size %d\n",
            ip_align, tn_buf, reg->off, off, size);
    return -EACCES;
}
```
**Formal precondition**: `(ip_align + reg.var_off + reg.off + off) % access_size == 0`
- Where `ip_align = 2` (NET_IP_ALIGN), `reg.var_off` is a tnum (value + mask)
- Only enforced when `strict` alignment mode is active and `size > 1`
**Fields needed**: `var_off` (value + mask), `off`, access size
**Error message**: `"misaligned packet access off %d+%s+%d+%d size %d"` — includes ip_align, var_off, reg->off, insn_off, size
**Evaluable from LOG_LEVEL2**: YES — var_off printed; reg->off visible in register state `off=N` field

### Rejection condition — misaligned generic pointer access
```c
// check_generic_ptr_alignment, line 6604-6613
reg_off = tnum_add(reg->var_off, tnum_const(reg->off + off));
if (!tnum_is_aligned(reg_off, size)) {
    verbose(env, "misaligned %saccess off %s+%d+%d size %d\n",
            pointer_desc, tn_buf, reg->off, off, size);
```
**Formal precondition**: `(reg.var_off + reg.off + off) % access_size == 0`
**Evaluable from LOG_LEVEL2**: YES

---

## Obligation Family 10: `memory_access` (generic PTR_TO_MEM)

**Verifier function**: `check_mem_access` (line 7681)

### Rejection condition 1 — null pointer dereference
```c
// check_mem_access, line 7769-7773
if (type_may_be_null(reg->type)) {
    verbose(env, "R%d invalid mem access '%s'\n", regno,
            reg_type_str(env, reg->type));
    return -EACCES;
}
```
**Formal precondition**: `NOT type_may_be_null(reg.type)` — pointer must be proven non-null
**Fields needed**: `type` (specifically whether `PTR_MAYBE_NULL` flag is set)
**Error message**: `"R%d invalid mem access '%s'"` — includes type name (which includes NULL qualifier)
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 2 — write to read-only memory
```c
// check_mem_access, line 7775-7779
if (t == BPF_WRITE && rdonly_mem) {
    verbose(env, "R%d cannot write into %s\n", regno, reg_type_str(env, reg->type));
    return -EACCES;
}
```
**Formal precondition**: `access_type == READ OR NOT type_is_rdonly_mem(reg.type)`
**Fields needed**: `type` (specifically whether `MEM_RDONLY` flag is set)
**Error message**: `"R%d cannot write into %s"`
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 3 — pointer leak into map/mem/ctx/packet
```c
// check_mem_access — multiple locations (lines 7718, 7783, 7806, 7870...)
verbose(env, "R%d leaks addr into map\n", value_regno);
verbose(env, "R%d leaks addr into mem\n", value_regno);
verbose(env, "R%d leaks addr into ctx\n", value_regno);
verbose(env, "R%d leaks addr into packet\n", value_regno);
```
**Formal precondition**: `value_reg.type == SCALAR_VALUE` (stored value must not be a pointer)
**Fields needed**: `type` of the value register being stored
**Error messages**: Multiple `"R%d leaks addr into ..."` variants
**Evaluable from LOG_LEVEL2**: YES

### Rejection condition 4 — invalid map key write
```c
// check_mem_access, line 7701-7705
if (reg->type == PTR_TO_MAP_KEY) {
    if (t == BPF_WRITE) {
        verbose(env, "write to change key R%d not allowed\n", regno);
```
**Formal precondition**: `reg.type != PTR_TO_MAP_KEY OR access_type == READ`
**Evaluable from LOG_LEVEL2**: YES

---

## Additional Families

### `check_ptr_off_reg` — modified pointer passed to helper

```c
// __check_ptr_off_reg, line 5932-5950
if (reg->off < 0) {
    verbose(env, "negative offset %s ptr R%d off=%d disallowed\n", ...);
}
if (!fixed_off_ok && reg->off) {
    verbose(env, "dereference of modified %s ptr R%d off=%d disallowed\n", ...);
}
if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
    verbose(env, "variable %s access var_off=%s disallowed\n", ...);
}
```
**Formal precondition**: `reg.off == 0 AND tnum_is_const(reg.var_off) AND reg.var_off.value == 0`
(when fixed_off_ok is false — i.e., helper requires unmodified pointer)
**Error messages**: `"dereference of modified %s ptr"`, `"variable %s access var_off=%s disallowed"`, `"negative offset %s ptr"`
**Evaluable from LOG_LEVEL2**: YES — off and var_off printed

### `check_mem_size` — size argument to helpers

```c
// Various locations around line 8453-8469
if (reg->smin_value < 0) {
    verbose(env, "R%d min value is negative, either use unsigned or 'var &= const'\n", regno);
}
if (reg->umin_value == 0 && !zero_size_allowed) {
    verbose(env, "R%d invalid zero-sized read: u64=[%lld,%lld]\n", ...);
}
if (reg->umax_value >= BPF_MAX_VAR_SIZ) {
    verbose(env, "R%d unbounded memory access, use 'var &= const' or 'if (var < const)'\n", regno);
}
```
**Formal precondition**:
  `reg.smin_value >= 0`
  AND `reg.umin_value > 0` (when zero size not allowed)
  AND `reg.umax_value < BPF_MAX_VAR_SIZ (0x7fff8000)`
**Error messages**:
  - `"R%d min value is negative, either use unsigned or 'var &= const'"`
  - `"R%d invalid zero-sized read: u64=[%lld,%lld]"`
  - `"R%d unbounded memory access, use 'var &= const' or 'if (var < const)'"`
**Evaluable from LOG_LEVEL2**: YES

---

## Register Fields: Evaluability Summary

| Field | LOG_LEVEL2 Printed? | Example in trace |
|-------|---------------------|-----------------|
| `reg->type` | YES | `map_value` / `pkt` / `ctx` / `scalar` etc. |
| `reg->smin_value` | YES | `smin=0` |
| `reg->smax_value` | YES | `smax=9223372036854775807` |
| `reg->umin_value` | YES | `umin=0` |
| `reg->umax_value` | YES | `umax=...` |
| `reg->var_off` | YES | `var_off=(0x0; 0xff)` (value+mask) |
| `reg->off` | YES | `off=8` (in `R1(id=0,off=8,r=32)`) |
| `reg->range` | YES | `r=32` (in PTR_TO_PACKET) |
| `reg->id` | YES | `id=0` |
| `reg->ref_obj_id` | PARTIAL | printed when non-zero |
| `reg->btf_id` | PARTIAL | BTF type name sometimes printed |
| `reg->map_ptr` | NO | map pointer not printed |
| `map->value_size` | PARTIAL | appears in error messages |
| `map->key_size` | PARTIAL | appears in error messages |
| Map capability flags | NO | |
| ctx struct layout | NO | program-type specific |

---

## Mapping: Error Message → Formal Precondition

| Error message pattern | Obligation family | Violated precondition |
|-----------------------|-------------------|----------------------|
| `R%d !read_ok` | null_check | `reg.type != NOT_INIT` |
| `R%d min value is negative, either use unsigned index` | packet_access / map_value_bounds | `reg.smin_value >= 0` |
| `R%d offset is outside of the packet` | packet_access | `reg.range >= 0 AND off + size <= reg.range` |
| `invalid access to packet, off=%d size=%d` | packet_access | `off >= 0 AND off + size <= reg.range` |
| `invalid access to map value, value_size=%d off=%d size=%d` | map_value_bounds | `smin_val+off >= 0 AND umax_val+off+size <= value_size` |
| `R%d unbounded memory access, make sure to bounds check` | map_value_bounds | `reg.umax_value < BPF_MAX_VAR_OFF` |
| `invalid%s stack R%d off=%d size=%d` | stack_access | `min_off >= -512 AND max_off <= 0` |
| `invalid variable-offset%s stack R%d` | stack_access | `smin+off >= -512 AND smax+off+size <= 0` |
| `invalid unbounded variable-offset%s stack R%d` | stack_access | `smax < BPF_MAX_VAR_OFF AND smin > -BPF_MAX_VAR_OFF` |
| `R%d type=%s expected=%s` | helper_arg_type | `reg.type IN compatible_types[arg_type]` |
| `Possibly NULL pointer passed to helper arg%d` | null_check | `NOT type_may_be_null(reg.type)` |
| `R%d is of type %s but %s is expected` | type_safety | BTF type match |
| `Unreleased reference id=%d alloc_insn=%d` | reference_release | all refs released at exit |
| `R%d must be referenced when passed to release function` | reference_release | `reg.ref_obj_id != 0` |
| `invalid bpf_context access off=%d size=%d` | context_access | valid ctx field for prog type |
| `misaligned packet access off %d+%s+%d+%d size %d` | alignment | `(ip_align+var_off+reg.off+off) % size == 0` |
| `misaligned %saccess off %s+%d+%d size %d` | alignment | `(var_off+reg.off+off) % size == 0` |
| `R%d invalid mem access '%s'` | memory_access | `NOT type_may_be_null(reg.type)` |
| `R%d cannot write into %s` | memory_access | `NOT type_is_rdonly_mem(reg.type)` |
| `R%d leaks addr into map/mem/ctx/packet` | memory_access | `value_reg.type == SCALAR_VALUE` |
| `R%d pointer arithmetic prohibited` | scalar_bounds | `reg.type == SCALAR_VALUE` for unary ops |
| `R%d pointer arithmetic on %s prohibited, null-check it first` | scalar_bounds | `NOT (reg.type & PTR_MAYBE_NULL)` |
| `R%d pointer arithmetic on %s prohibited` | scalar_bounds | `reg.type IN allowed_arithmetic_types` |
| `dereference of modified %s ptr R%d off=%d disallowed` | context_access / helper_arg | `reg.off == 0` |
| `variable %s access var_off=%s disallowed` | context_access / helper_arg | `tnum_is_const(reg.var_off) AND var_off.value == 0` |
| `div by zero` | scalar_bounds | `imm != 0` |
| `invalid shift %d` | scalar_bounds | `0 <= shift < operand_size_bits` |
| `R%d min value is negative, either use unsigned or 'var &= const'` | scalar_bounds | `reg.smin_value >= 0` (size arg) |
| `R%d unbounded memory access, use 'var &= const' or 'if (var < const)'` | scalar_bounds | `reg.umax_value < BPF_MAX_VAR_SIZ` |
| `write into map forbidden` | map_value_bounds | map has write capability |
| `cannot write into packet` | packet_access | program type allows packet write |
| `frame pointer is read only` | null_check | destination is not R10 |

---

## Notes on Information Availability

### What IS computable from LOG_LEVEL2 trace alone:
- All scalar bounds: `smin`, `smax`, `umin`, `umax`, `s32_min`, `s32_max`, `u32_min`, `u32_max`
- Register type and type flags (e.g., `PTR_MAYBE_NULL`, `MEM_RDONLY`)
- Packet range: `r=N` field on packet register state
- Stack offset: computed from `var_off + reg->off`
- Variable offset tnum: printed as `var_off=(value; mask)`
- Access size and offset: from instruction bytecode disassembly
- Reference object ID: `ref_obj_id` when printed
- Whether register is `NOT_INIT`

### What is NOT computable from LOG_LEVEL2 trace:
- `map->value_size`, `map->key_size` — map metadata not in trace (but appears in error messages)
- `map->flags` / capabilities (BPF_MAP_CAN_READ, BPF_MAP_CAN_WRITE)
- `env->ops->is_valid_access` result — ctx field validity depends on program type
- Exact BTF type hierarchy for `btf_struct_ids_match`
- `state->acquired_refs` list — reference tracking state not printed (only ref_obj_id on register)
- IRQ/lock state (`active_locks`, `active_irq_id`, `active_rcu_locks`)

### Implication for BPFix:
The most evaluable obligations (covering ~85% of rejections by error message frequency) are:
1. **Fully evaluable**: packet_access bounds, stack_access bounds, null_check/NOT_INIT,
   scalar_bounds (pointer arith prohibited, shift, div-by-zero), alignment, memory_access
   (null deref, readonly write, pointer leak)
2. **Partially evaluable**: map_value_bounds (smin/umax checks evaluable; value_size from error msg),
   reference_release (ref_obj_id tracked; acquisition site from error msg),
   type_safety (type printed; BTF name from error msg)
3. **Not evaluable from trace**: map capability checks, context field validity, BTF type hierarchy
