# Mainline `verifier.c` Semantic Choke-Point Analysis

Snapshot basis:

- Upstream source: `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/verifier.c`
- `HEAD` at fetch time (`2026-03-11`): `b29fb8829bff243512bb8c8908fd39406f9fd4c3`
- Local weighting source for impact ranking: `docs/tmp/taxonomy-coverage-report.md`

Scope and conventions:

- I scanned **90** top-level `check_*` definitions in upstream `kernel/bpf/verifier.c`.
- Surface split: **78 `int`**, **11 `bool`**, **1 `void`**.
- Main inventory below covers the **77 errno-returning or errno-propagating `check_*` validators** that participate directly in rejection. A short appendix covers non-errno helper predicates.
- `verbose()` counts are **direct calls inside the named function body**, not delegated helper calls.
- `E00x?` means “nearest current BPFix fit, but not a clean catalog hit.” `-` means uncatalogued under the current `E001-E018` catalog.

Impact weighting used later comes from the current benchmark coverage report:

- Highest-count IDs are `E011` 38, `E005` 23, `E012` 22, `E013` 19, `E001` 18, `E004` 17, `E016` 12, `E014` 10, `E003` 9, `E002` 8, `E015` 8.
- That makes type discipline, scalar-range proof, dynptr/iterator protocol, execution-context discipline, packet bounds, and reference lifetime the highest-value instrument-first regions.

## Full Inventory

### Register, Stack, Memory, and Access Validators

| Function | Lines | What it checks | Failure reporting | BPFix IDs | Taxonomy class(es) | `verbose()` |
| --- | ---: | --- | --- | --- | --- | ---: |
| `check_reg_arg` | 3966-3973 | Source/destination register usability via `__check_reg_arg()` | No direct log; delegates to `R%d is invalid`, `R%d !read_ok`, `frame pointer is read only` | `-` | `source_bug` | 0 |
| `check_stack_write_fixed_off` | 5226-5351 | Fixed-offset stack writes, spill layout, caller-frame spill restrictions | `attempt to corrupt spilled pointer on stack`; `invalid size of register spill`; `cannot spill pointers ... into stack frame of the caller` | `E006?`, `E012?` | `source_bug`, `lowering_artifact` | 3 |
| `check_stack_write_var_off` | 5372-5480 | Conservative variable-offset stack writes that avoid clobbering hidden pointer facts | `spilled ptr in range of var-offset stack write`; `uninit stack in range of var-offset write prohibited for !root` | `E003?`, `E006?`, `E012?` | `source_bug`, `lowering_artifact` | 2 |
| `check_stack_read_fixed_off` | 5530-5667 | Fixed-offset stack reads/fills, spill restoration, and pointer leak checks | `invalid size of register fill`; `invalid read from stack off ...`; `leaking pointer from stack off ...` | `E003`, `E006?` | `source_bug`, `lowering_artifact` | 4 |
| `check_stack_read_var_off` | 5698-5719 | Variable-offset stack reads via initialized-range validation | No direct log; delegates to `check_stack_range_initialized()` | `E003`, `E012?`, `E014?` | `source_bug` | 0 |
| `check_stack_read` | 5730-5774 | Dispatches stack reads and rejects helper-facing variable stack pointers | `variable offset stack pointer cannot be passed into helper function` | `E003`, `E006?` | `source_bug` | 1 |
| `check_stack_write` | 5787-5808 | Wrapper dispatch for fixed/variable stack writes | No direct log; delegates to `check_stack_write_fixed_off()` and `check_stack_write_var_off()` | `E003?`, `E006?`, `E012?` | `source_bug` | 0 |
| `check_map_access_type` | 5810-5830 | Map read/write capability flags (`BPF_F_RDONLY_PROG`, write-only maps) | `write into map forbidden`; `read from map forbidden` | `-` | `env_mismatch`, `source_bug` | 2 |
| `check_mem_region_access` | 5869-5922 | Scalar range proof for generic variable-offset memory regions | `min value is negative`; `min value is outside of the allowed memory range`; `unbounded memory access` | `E005`, `E017?` | `lowering_artifact`, `source_bug` | 4 |
| `check_ptr_off_reg` | 5956-5960 | Requires structured pointers to be unmodified/constant before dereference or helper use | No direct log; delegates to `negative offset ... ptr`; `dereference of modified ... ptr disallowed`; `variable ... access ... disallowed` | `E006?` | `source_bug`, `lowering_artifact` | 0 |
| `check_map_kptr_access` | 6137-6199 | kptr/uptr map-field access protocol, store restrictions, load/store mode discipline | `kptr in map can only be accessed using BPF_MEM`; `store to referenced kptr disallowed`; `store to uptr disallowed` | `E004?`, `E013?` | `source_bug` | 5 |
| `check_map_access` | 6214-6278 | Special-field map value access rules, helper-indirect access bans, alignment and size | `... cannot be accessed indirectly by helper`; `... access cannot have variable offset`; `... access misaligned ...` | `E017`, `E005?` | `source_bug`, `lowering_artifact` | 5 |
| `check_packet_access` | 6324-6363 | Packet bounds proof for direct packet access | `min value is negative`; `invalid access to packet`; `R%d offset is outside of the packet` | `E001`, `E005` | `source_bug`, `lowering_artifact` | 2 |
| `check_ctx_access` | 6366-6396 | Fixed-offset context-field access and reference-liveness-sensitive ctx reads | `invalid bpf_context access ... Reference may already be released`; `invalid bpf_context access ... size=...` | `E004?` | `source_bug` | 2 |
| `check_flow_keys_access` | 6398-6408 | Bounds checks on `struct bpf_flow_keys` access | `invalid access to flow keys` | `-` | `source_bug` | 1 |
| `check_sock_access` | 6410-6452 | Socket, sock-common, tcp, and xdp-sock field access validity | `min value is negative`; `R%d invalid ... access off=... size=...` | `E005?` | `source_bug`, `lowering_artifact` | 2 |
| `check_pkt_ptr_alignment` | 6558-6591 | NET_IP_ALIGN-aware packet alignment | `misaligned packet access ...` | `E001?` | `source_bug` | 1 |
| `check_generic_ptr_alignment` | 6593-6615 | Alignment checks for map/ctx/stack/sock/BTF/etc. pointers | `misaligned ... access ...` | `E017?` | `source_bug` | 1 |
| `check_ptr_alignment` | 6617-6672 | Wrapper dispatch for packet/generic/stack alignment checks | No direct log; delegates to `check_pkt_ptr_alignment()`, `check_generic_ptr_alignment()`, and fixed stack read/write validators | `E001?`, `E003?`, `E017?` | `source_bug` | 0 |
| `check_max_stack_depth_subprog` | 6719-6878 | Per-subprog stack depth, combined call-stack size, callback/exception stack limits | `tail_calls are not allowed when call stack ... Too large`; `stack size of subprog ... Too large`; `combined stack size ... Too large`; `the call stack ... is too deep` | `E018`, `E016?` | `verifier_limit`, `source_bug` | 7 |
| `check_max_stack_depth` | 6880-6922 | Wrapper over `check_max_stack_depth_subprog()` | No direct log; delegates to `check_max_stack_depth_subprog()` | `E018` | `verifier_limit` | 0 |
| `check_tp_buffer_access` | 6961-6975 | Tracepoint buffer pointer offset validation | No direct log; delegates to `invalid tracepoint buffer access` and `invalid variable buffer offset` via `__check_buffer_access()` | `-` | `source_bug` | 0 |
| `check_buffer_access` | 6977-6994 | Generic rdonly/rdwr buffer pointer offset validation | No direct log; delegates to `invalid rdonly/rdwr buffer access` and `invalid variable buffer offset` | `-` | `source_bug` | 0 |
| `check_ptr_to_btf_access` | 7358-7509 | `PTR_TO_BTF_ID` struct access under capability, GPL, trust, offset, and memory-domain rules | `access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN`; `Cannot access kernel 'struct ...' from non-GPL compatible program`; `invalid negative access` | `E009`, `E006?`, `E013?` | `env_mismatch`, `source_bug` | 7 |
| `check_ptr_to_map_access` | 7511-7575 | `CONST_PTR_TO_MAP` BTF-based struct access, map-type support, capability checks | `map_ptr access not supported without CONFIG_DEBUG_INFO_BTF`; `map_ptr access not supported for map type ...`; `only read from ... is supported` | `E009` | `env_mismatch` | 5 |
| `check_stack_slot_within_bounds` | 7583-7598 | Primitive stack-slot boundary check used by broader stack validators | No direct log; returns `-EACCES` to callers | `E003?`, `E012?`, `E014?` | `source_bug` | 0 |
| `check_stack_access_within_bounds` | 7605-7662 | Fixed/variable-offset stack window bounds | `invalid unbounded variable-offset ... stack`; `invalid ... stack R%d off=... size=...`; `invalid variable-offset ... stack R%d var_off=...` | `E003`, `E005?` | `source_bug`, `lowering_artifact` | 3 |
| `check_mem_access` | 7681-7946 | Top-level typed memory-access dispatcher for map/mem/ctx/stack/packet/sock/buffer/BTF | `R%d invalid mem access '%s'`; `R%d leaks addr into ...`; `cannot write into packet`; `write to change key ... not allowed` | `E001`, `E002`, `E003`, `E005`, `E011`, `E017` | `source_bug`, `lowering_artifact` | 13 |
| `check_load_mem` | 7951-7982 | Memory-load instruction wrapper around register and typed-memory checks | No direct log; delegates to `check_mem_access()` and `check_reg_arg()` | `E001`, `E002`, `E003`, `E011`, `E017` | `source_bug` | 0 |
| `check_store_reg` | 7984-8010 | Memory-store instruction wrapper around register and typed-memory checks | No direct log; delegates to `check_mem_access()` and `check_reg_arg()` | `E001`, `E011`, `E017` | `source_bug` | 0 |
| `check_atomic_rmw` | 8012-8099 | Atomic RMW/CMPXCHG operand size checks and target pointer-type validation | `invalid atomic operand size`; `R%d leaks addr into mem`; `BPF_ATOMIC stores into R%d %s is not allowed` | `E011?`, `E017?` | `source_bug` | 4 |
| `check_atomic_load` | 8101-8118 | Atomic load-acquire target type restrictions | `BPF_ATOMIC loads from R%d %s is not allowed` | `E011?` | `source_bug` | 1 |
| `check_atomic_store` | 8120-8137 | Atomic store-release target type restrictions | `BPF_ATOMIC stores into R%d %s is not allowed` | `E011?` | `source_bug` | 1 |
| `check_atomic` | 8139-8172 | Unsupported atomic opcode and arch-specific acquire/release restrictions | `64-bit load-acquires are only supported on 64-bit arches`; `64-bit store-releases are only supported on 64-bit arches`; `BPF_ATOMIC uses invalid atomic opcode` | `E009?` | `source_bug`, `env_mismatch` | 3 |
| `check_stack_range_initialized` | 8184-8328 | Helper/indirect stack region initialization plus dynptr-safe stack-range checks | `invalid zero-sized read`; `variable offset stack access prohibited for !root`; `potential write to dynptr at off=... disallowed`; `invalid read from stack ...` | `E003`, `E005`, `E012`, `E014` | `source_bug`, `lowering_artifact` | 6 |
| `check_helper_mem_access` | 8330-8419 | Helper-memory argument validation by pointee type and access mode | `R%d cannot write into %s`; `R%d type=%s expected=%s`; plus delegated packet/map/stack/BTF/buffer stems | `E001`, `E003`, `E005`, `E011`, `E017` | `source_bug`, `lowering_artifact` | 5 |
| `check_mem_size_reg` | 8427-8475 | Helper length/scalar bounds proof for memory pairs | `min value is negative, either use unsigned or 'var &= const'`; `invalid zero-sized read`; `unbounded memory access ...` | `E005` | `lowering_artifact` | 3 |
| `check_mem_reg` | 8477-8503 | Wrapper for helper memory-region validation | No direct log; delegates to `check_helper_mem_access()` | `E001`, `E005`, `E011`, `E017` | `source_bug`, `lowering_artifact` | 0 |
| `check_kfunc_mem_size_reg` | 8505-8530 | Wrapper applying helper-style length validation to kfunc memory-size args | No direct log; delegates to `check_mem_size_reg()` | `E005` | `lowering_artifact` | 0 |
| `check_map_field_pointer` | 8677-8729 | Ensures a helper/kfunc arg points exactly at a BTF-described timer/task-work/workqueue field in a map value | `doesn't have constant offset`; `map '...' has to have BTF`; `map '...' has no valid ...`; `off ... doesn't point to 'struct ...'` | `E009?`, `E013?` | `source_bug`, `env_mismatch` | 4 |

### Helper, Kfunc, and Call-Interface Validators

| Function | Lines | What it checks | Failure reporting | BPFix IDs | Taxonomy class(es) | `verbose()` |
| --- | ---: | --- | --- | --- | --- | ---: |
| `check_reg_type` | 9422-9567 | Canonical register-type matcher for helper/kfunc args and nullable/trusted pointer expectations | `R%d type=%s expected=...`; nullable/trusted-pointer mismatch strings | `E002`, `E011`, `E015` | `source_bug` | 8 |
| `check_func_arg_reg_off` | 9586-9655 | Allowed fixed/variable offsets for helper/kfunc args, especially release/trusted args | `R%d must have zero offset when passed to release func or trusted arg to kfunc`; plus delegated ptr-offset stems | `E004?`, `E011`, `E015` | `source_bug` | 1 |
| `check_reg_const_str` | 9723-9774 | Const-string args must come from readonly, directly addressable, NUL-terminated map values | `... cannot be used as const string`; `does not point to a readonly map`; `string is not zero-terminated` | `E009?` | `source_bug` | 6 |
| `check_func_arg` | 9839-10107 | Per-helper arg typing, memory, reference, dynptr, timer, packet, and const-string validation | `R%d leaks addr into helper function`; `helper access to the packet is not allowed`; `arg %d is an unacquired reference` | `E001`, `E002`, `E004`, `E011`, `E012`, `E015`, `E017` | `source_bug` | 10 |
| `check_map_func_compatibility` | 10153-10404 | Helper/map-type compatibility and tail-call-vs-bpf-to-bpf restrictions | `mixing of tail_calls and bpf-to-bpf calls is not supported`; `cannot pass map_type ... into func ...` | `E009`, `E016` | `env_mismatch` | 2 |
| `check_func_proto` | 10496-10502 | Sanity-checks helper prototype metadata before use | No direct log; caller reports `incorrect func proto ...` | `E010` | `verifier_bug` | 0 |
| `check_func_call` | 10864-10944 | BPF-to-BPF/global call context, sleepability, and caller/callee BTF arg matching | `global function calls are not allowed while holding a lock`; `global functions that may sleep are not allowed ...`; `Caller passes invalid args into func#...` | `E013`, `E016` | `source_bug`, `env_mismatch` | 6 |
| `check_reference_leak` | 11427-11452 | Exit-path unreleased reference detection | `Unreleased reference id=... alloc_insn=...` | `E004` | `source_bug` | 1 |
| `check_resource_leak` | 11454-11485 | Tail-call / exceptional exit with active ref, lock, IRQ, RCU, or preempt state | `... cannot be used inside ... region`; `... would lead to reference leak` | `E004`, `E013` | `source_bug` | 5 |
| `check_bpf_snprintf_call` | 11487-11523 | `bpf_snprintf()` format and backing-map value validation | `failed to retrieve map value address`; `Invalid format string` | `E009?` | `source_bug` | 2 |
| `check_get_func_ip` | 11525-11544 | `bpf_get_func_ip()` availability by program type/attach mode | `supported only for fentry/fexit/fmod_ret programs`; `not supported for program type ...` | `E009`, `E016` | `env_mismatch` | 2 |
| `check_helper_call` | 11618-12152 | Top-level helper-call gate: availability, GPL, sleepability, args, ref release, special helpers, return typing | `program of this type cannot use helper ...`; `helper call is not allowed ...`; `helper call might sleep ...`; `reference has not been acquired before` | `E004`, `E009`, `E012`, `E013`, `E016`, `E017` | `env_mismatch`, `source_bug` | 18 |
| `check_reg_allocation_locked` | 12984-13011 | Graph/root object must reside in the same allocation as the held lock | `held lock and object are not in the same allocation` | `E013` | `source_bug` | 1 |
| `check_kfunc_args` | 13333-13878 | Top-level kfunc arg typing, nullability, ref/ownership, dynptr, iterator, graph, IRQ, and const-string validation | `Possibly NULL pointer passed to trusted arg...`; `R%d must be referenced or trusted`; `css_task_iter is only allowed ...`; `release kernel function ... expects refcounted PTR_TO_BTF_ID` | `E004`, `E011`, `E012`, `E013`, `E014`, `E015`, `E016` | `source_bug`, `env_mismatch` | 43 |
| `check_special_kfunc` | 13911-14084 | Special kfunc protocol and return shaping (`obj_new`, `refcount_acquire`, `rdonly_cast`, `dynptr_slice`, etc.) | `... requires prog BTF`; `type ID argument must be of a struct`; `Unknown type ID ...`; `the prog does not allow writes to packet data` | `E009`, `E012`, `E016` | `env_mismatch`, `source_bug` | 9 |
| `check_kfunc_call` | 14088-14481 | Top-level kfunc gate: availability, sleepability, RCU/preempt/IRQ discipline, release/acquire handling, return typing | `calling kernel function ... is not allowed`; `program must be sleepable to call sleepable kfunc ...`; `requires RCU critical section protection`; `reference has not been acquired before` | `E004`, `E009`, `E012`, `E013`, `E014`, `E015`, `E016` | `source_bug`, `env_mismatch` | 22 |
| `check_return_code` | 17901-18099 | Exit-path return register type/range/lifetime rules for programs and subprograms | `R%d leaks addr as return value`; `At subprogram exit ... not a scalar value`; `... register R%d is not a known value` | `E004`, `E011`, `E013` | `source_bug` | 4 |

### Instruction, CFG, BTF, and Attach Validators

| Function | Lines | What it checks | Failure reporting | BPFix IDs | Taxonomy class(es) | `verbose()` |
| --- | ---: | --- | --- | --- | --- | ---: |
| `check_subprogs` | 3679-3733 | Early subprogram partitioning and jump-target sanity across subprog boundaries | `jump out of range from insn ...`; `last insn is not an exit or jmp` | `-` | `source_bug` | 2 |
| `check_stack_access_for_ptr_arithmetic` | 14780-14802 | Non-root stack pointer arithmetic must stay constant and in range | `variable stack access prohibited for !root`; `stack pointer arithmetic goes out of range ...` | `E005?` | `source_bug`, `lowering_artifact` | 2 |
| `check_alu_op` | 16332-16573 | ALU/MOV encoding validation plus unsafe pointer/scalar arithmetic rejection | `BPF_NEG/BPF_END/BPF_MOV/BPF_ALU uses reserved fields`; `pointer arithmetic prohibited`; `partial copy of pointer`; `invalid shift` | `E005`, `E006?`, `E011` | `source_bug`, `lowering_artifact` | 15 |
| `check_cond_jmp_op` | 17449-17704 | Conditional-jump encoding validation and unsupported pointer-comparison rejection | `invalid BPF_JMP/JMP32 opcode`; `invalid may_goto imm`; `BPF_JMP/JMP32 uses reserved fields`; `pointer comparison prohibited` | `E011?` | `source_bug` | 6 |
| `check_ld_imm` | 17707-17802 | `LD_IMM64` encoding, pseudo-func, and pseudo-BTF load validation | `invalid BPF_LD_IMM insn`; `BPF_LD_IMM64 uses reserved fields`; `missing btf func_info`; `callback function not static` | `E009?` | `env_mismatch`, `source_bug` | 4 |
| `check_ld_abs` | 17831-17899 | `LD_ABS/IND` program-type restrictions, reserved-field checks, skb-context expectations, and leak safety | `BPF_LD_[ABS/IND] instructions not allowed for this program type`; `uses reserved fields`; `R6 != pointer to skb` | `E001?`, `E004?`, `E009` | `env_mismatch`, `source_bug` | 3 |
| `check_cfg` | 18918-19004 | Reachability and CFG-edge sanity; loop/back-edge rejection is delegated to `visit_insn()` | Direct: `unreachable insn`; `jump into the middle of ldimm64`; delegated: `back-edge from insn`, jump-table shape errors | `E008`, `E018` | `source_bug`, `verifier_limit` | 2 |
| `check_abnormal_return` | 19057-19072 | Rejects subprogs using `LD_ABS`/`tail_call` without BTF func metadata | `LD_ABS is not allowed in subprogs without BTF`; `tail_call is not allowed in subprogs without BTF` | `E009` | `env_mismatch` | 2 |
| `check_btf_func_early` | 19078-19178 | Early `func_info` record-size, ordering, and type-id validation | `invalid func info rec size`; `nonzero tailing record in func info`; `nonzero insn_off ... first func info record` | `E009?` | `env_mismatch` | 5 |
| `check_btf_func` | 19180-19254 | Matches `func_info` to subprog layout and enforces return-type restrictions for `LD_ABS`/`tail_call` subprogs | `number of funcs in func_info doesn't match number of subprogs`; `func_info BTF section doesn't match subprog layout ...`; `LD_ABS is only allowed ...` | `E009?` | `env_mismatch` | 4 |
| `check_btf_line` | 19272-19395 | `line_info` ordering, bounds, string references, and per-function coverage | `nonzero tailing record in line_info`; `Invalid line_info[].insn_off`; `missing bpf_line_info ...` | `E009?` | `env_mismatch` | 6 |
| `check_core_relo` | 19400-19467 | CO-RE relocation record validation and application | `nonzero tailing record in core_relo`; `Invalid core_relo[].insn_off` | `E009?` | `env_mismatch` | 2 |
| `check_btf_info_early` | 19469-19495 | Wrapper: non-kernel BTF fd plus early `func_info` checks | No direct log; delegates to `check_abnormal_return()` and `check_btf_func_early()` | `E009?` | `env_mismatch` | 0 |
| `check_btf_info` | 19497-19522 | Wrapper: full BTF `func_info`/`line_info`/CO-RE validation | No direct log; delegates to `check_btf_func()`, `check_btf_line()`, and `check_core_relo()` | `E009?` | `env_mismatch` | 0 |
| `check_indirect_jump` | 20976-21030 | `gotox`/indirect-jump target must be `PTR_TO_INSN` and resolve into an insn-array jump table | `R%d has type %s, expected PTR_TO_INSN`; `register R%d doesn't point to any offset in map ...` | `E009?`, `E011?` | `source_bug`, `env_mismatch` | 2 |
| `check_pseudo_btf_id` | 21530-21561 | Pseudo-BTF `ldimm64` resolution to kernel/module symbols and BTF objects | `invalid module BTF object FD specified`; `kernel is missing BTF ...`; delegated invalid-btf-id/symbol-resolution errors | `E009` | `env_mismatch` | 2 |
| `check_map_prog_compatibility` | 21583-21686 | Map/program feature compatibility: offload consistency, sleepable-map limits, arena prerequisites, tracing/map feature bans | `tracing progs cannot use ...`; `socket filter progs cannot use bpf_spin_lock yet`; `Sleepable programs can only use ...`; `CAP_BPF and CAP_PERFMON are required to use arena` | `E009`, `E016`, `E013?` | `env_mismatch`, `source_bug` | 13 |
| `check_struct_ops_btf_id` | 24773-24881 | `struct_ops` target/member validation, GPL/JIT/private-stack constraints, ref-arg tail-call rule | `struct ops programs must have a GPL compatible license`; `attach_btf_id ... is not a supported struct`; `Private stack not supported by jit` | `E009`, `E016` | `env_mismatch` | 9 |
| `check_attach_modify_return` | 24884-24891 | Predicate gate for modifiable return-code targets | No direct log; user-visible attach failure appears later as `%s() is not modifiable` | `E016` | `env_mismatch` | 0 |
| `check_attach_btf_id` | 25317-25406 | Top-level attach-target, sleepable, denylist, and trampoline setup gate | `Syscall programs can only be sleepable`; `Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and struct_ops programs can be sleepable`; `Attaching tracing programs to function ... is rejected` | `E009`, `E016` | `env_mismatch` | 4 |

## Auxiliary Non-Errno `check_*` Helpers

These are not part of the main errno-returning rejection table, but they matter for obligation extraction because some own canonical `verbose()` text or are called immediately before a rejecting return.

| Function | Return type | Role | Notes |
| --- | --- | --- | --- |
| `check_fastcall_stack_contract` | `void` | Fastcall stack-shape bookkeeping | No direct rejection surface |
| `check_raw_mode_ok` | `bool` | Helper proto raw-memory mode sanity | Consumed by `check_func_proto()` |
| `check_args_pair_invalid` | `bool` | Helper proto buf/len pairing predicate | Consumed by `check_arg_pair_ok()` |
| `check_arg_pair_ok` | `bool` | Helper proto buf/len pairing sanity | Consumed by `check_func_proto()` |
| `check_btf_id_ok` | `bool` | Helper proto BTF-id metadata sanity | Consumed by `check_func_proto()` |
| `check_mem_arg_rw_flag_ok` | `bool` | Helper proto read/write flag sanity | Consumed by `check_func_proto()` |
| `check_kfunc_is_graph_root_api` | `bool` | Graph-root kfunc classifier | Emits only verifier-internal-error diagnostics |
| `check_kfunc_is_graph_node_api` | `bool` | Graph-node kfunc classifier | Emits only verifier-internal-error diagnostics |
| `check_css_task_iter_allowlist` | `bool` | Program-type allowlist for `css_task_iter` | Used by `check_kfunc_args()` |
| `check_reg_sane_offset` | `bool` | Canonical pointer-offset sanity helper for ALU paths | Owns the classic `unbounded min value` / `pointer ... out of bounds` `E005` stems |
| `check_ids` | `bool` | State-equivalence ID mapping helper | No user-facing `verbose()` |
| `check_scalar_ids` | `bool` | Scalar-ID equivalence helper | No user-facing `verbose()` |
| `check_non_sleepable_error_inject` | `int` (`0/1`) | Sleepability allowlist predicate for tracing attach | User-visible failure is logged elsewhere |

## BPFix Error-ID Crosswalk

This is the practical “which source check owns which catalog bucket?” summary.

| Error ID | Main `check_*` choke points |
| --- | --- |
| `E001` | `check_packet_access`, `check_mem_access`, `check_helper_mem_access`, `check_func_arg` |
| `E002` | `check_reg_type`, `check_mem_access`, `check_func_arg` |
| `E003` | `check_stack_range_initialized`, `check_stack_read_fixed_off`, `check_stack_read_var_off`, `check_stack_access_within_bounds` |
| `E004` | `check_reference_leak`, `check_resource_leak`, `check_helper_call`, `check_kfunc_call`, `check_return_code` |
| `E005` | `check_mem_region_access`, `check_mem_size_reg`, `check_alu_op`, helper `check_reg_sane_offset` |
| `E006` | `check_ptr_off_reg`, `check_stack_write_fixed_off`, `check_stack_read_fixed_off`, `check_alu_op` |
| `E007` | `check_cfg` (nearest current owner for state-explosion/control-shape rejection) |
| `E008` | `check_cfg` plus delegated `visit_insn()` back-edge logs |
| `E009` | `check_helper_call`, `check_get_func_ip`, `check_pseudo_btf_id`, `check_map_func_compatibility`, `check_attach_btf_id`, BTF metadata checks |
| `E010` | `check_func_proto` and a few verifier-internal helper predicates (`check_kfunc_is_graph_*_api`) |
| `E011` | `check_reg_type`, `check_mem_access`, `check_alu_op`, `check_kfunc_args`, `check_return_code` |
| `E012` | `check_stack_range_initialized`, `check_func_arg`, `check_helper_call`, `check_kfunc_args`, `check_special_kfunc` |
| `E013` | `check_resource_leak`, `check_func_call`, `check_kfunc_args`, `check_kfunc_call`, `check_return_code`, `check_map_field_pointer` |
| `E014` | `check_kfunc_args`, `check_stack_range_initialized` |
| `E015` | `check_reg_type`, `check_func_arg`, `check_kfunc_args`, `check_func_arg_reg_off` |
| `E016` | `check_helper_call`, `check_kfunc_call`, `check_map_prog_compatibility`, `check_attach_btf_id`, `check_func_call` |
| `E017` | `check_map_access`, `check_mem_access`, `check_helper_mem_access`, `check_mem_region_access` |
| `E018` | `check_max_stack_depth_subprog`, `check_max_stack_depth`, `check_cfg` |

## `verbose()` Distribution Across the File

File-wide direct-call statistics:

- Total top-level functions in `verifier.c`: **683**
- Top-level functions with at least one direct `verbose()`: **145**
- Total direct `verbose()` call sites across all top-level functions: **547**
- Direct `verbose()` calls inside `check_*` functions: **328 / 547 = 60.0%**
- `check_*` functions with at least one direct `verbose()`: **63 / 90**
- `check_*` bucket distribution:
  - `0` calls: **27**
  - `1-2` calls: **26**
  - `3-5` calls: **20**
  - `6-10` calls: **11**
  - `11+` calls: **6**
- Concentration:
  - Top 5 `check_*` functions account for **111 / 328 = 33.8%**
  - Top 10 account for **160 / 328 = 48.8%**
  - Top 15 account for **192 / 328 = 58.5%**

Top direct `verbose()` emitters in the `check_*` surface:

| Rank | Function | Direct `verbose()` calls | Why it matters |
| ---: | --- | ---: | --- |
| 1 | `check_kfunc_args` | 43 | Densest kfunc arg/type/dynptr/iterator discipline surface |
| 2 | `check_kfunc_call` | 22 | Kfunc availability plus execution-context and lifetime surface |
| 3 | `check_helper_call` | 18 | Helper availability, context, protocol, and return shaping |
| 4 | `check_alu_op` | 15 | Pointer arithmetic and scalar-proof collapse |
| 5 | `check_map_prog_compatibility` | 13 | Program/map feature mismatch cluster |
| 6 | `check_mem_access` | 13 | Central dereference gate for packet/map/stack/ctx/BTF |
| 7 | `check_func_arg` | 10 | Helper arg typing/nullability/ref protocol |
| 8 | `check_special_kfunc` | 9 | `obj_new`, dynptr slice, `rdonly_cast`, etc. |
| 9 | `check_struct_ops_btf_id` | 9 | `struct_ops` environment/attach constraints |
| 10 | `check_reg_type` | 8 | Canonical type/nullability mismatch gate |

Interpretation:

- The **call interface layer** (`check_helper_call`, `check_kfunc_args`, `check_kfunc_call`, `check_func_arg`) and the **typed memory layer** (`check_mem_access`, `check_reg_type`, `check_alu_op`) dominate the observable rejection text.
- Several semantically important chokepoints have **zero direct `verbose()`** because they delegate logging to helper functions:
  - `check_reg_arg` -> `__check_reg_arg()`
  - `check_ptr_off_reg` -> `__check_ptr_off_reg()`
  - `check_tp_buffer_access` / `check_buffer_access` -> `__check_buffer_access()`
  - `check_cfg` -> `visit_insn()` for back-edge and malformed-jump logs
  - `check_attach_btf_id` -> `bpf_check_attach_target()` for many attach-target diagnostics

## Highest-Impact Semantic Choke Points

Ranked by a mix of:

- coverage of high-frequency BPFix IDs from `docs/tmp/taxonomy-coverage-report.md`
- centrality in the verifier call graph
- density and specificity of user-visible `verbose()` diagnostics

| Rank | Check point | Why it is high impact |
| ---: | --- | --- |
| 1 | `check_kfunc_args` | Covers the densest current cluster: `E011` 38, `E012` 22, `E013` 19, `E014` 10, `E015` 8, plus kfunc-specific `E016` context failures. |
| 2 | `check_helper_call` | Top helper gate for `E009`/`E016`, and it delegates into `E004`, `E012`, and `E017` through helper-arg checking. |
| 3 | `check_mem_access` | Central dereference choke point for `E001`, `E002`, `E003`, `E011`, and `E017`; most real-world invalid-mem-access strings pass through here. |
| 4 | `check_reg_type` | Canonical type/nullability mismatch owner for `E002`, `E011`, and `E015`. |
| 5 | `check_kfunc_call` | Owns kfunc availability, sleepability, RCU/preempt/IRQ discipline, and reference-release protocol: `E004`, `E013`, `E016`. |
| 6 | `check_alu_op` | Main arithmetic choke point for `E005` and part of `E011`/`E006`; pair it with helper `check_reg_sane_offset`. |
| 7 | `check_func_arg` | Helper-arg sub-choke point for `E002`, `E004`, `E012`, `E015`, and delegated packet/map access obligations. |
| 8 | `check_stack_range_initialized` | Owns stack-init, dynptr-stack, and iterator-stack proof failures: `E003`, `E012`, `E014`. |
| 9 | `check_packet_access` | Canonical packet-bounds proof gate for `E001`, with `E005` overlap when scalar range proof collapses. |
| 10 | `check_resource_leak` | Strong owner for `E004` and `E013` lock/IRQ/RCU scope failures on exceptional or tail-call exits. |
| 11 | `check_mem_size_reg` | High-value `E005` length-proof choke point for helper/kfunc memory pairs. |
| 12 | `check_return_code` | Exit-path owner for `E004`, `E011`, and `E013` when invalid pointers or unresolved refs reach return. |
| 13 | `check_map_prog_compatibility` | High-leverage env/feature surface for `E009` and `E016`, especially modern map features (`spin_lock`, arena, tracing limits). |
| 14 | `check_attach_btf_id` | Main tracing/LSM/ext attach gate for `E009` and `E016`; good leverage for environment-aware obligation extraction. |
| 15 | `check_cfg` and `check_max_stack_depth_subprog` | Lower-frequency in the current catalog, but they uniquely own `E008`/`E018` style control-shape and stack-budget failures. |

## Recommendations: Instrument First

1. Instrument the **typed memory front door** first:
   - `check_mem_access`
   - `check_reg_type`
   - `check_func_arg`
   - `check_packet_access`
   - `check_stack_range_initialized`
   These jointly cover the highest-volume source-bug families: `E001`, `E002`, `E003`, `E011`, `E012`, `E015`, and `E017`.

2. Instrument the **call interface front door** next:
   - `check_helper_call`
   - `check_kfunc_args`
   - `check_kfunc_call`
   - `check_resource_leak`
   - `check_return_code`
   This cluster owns most modern helper/kfunc/context/lifetime failures: `E004`, `E012`, `E013`, `E016`.

3. Add the **scalar-proof / lowering** layer immediately after:
   - `check_alu_op`
   - `check_mem_size_reg`
   - helper `check_reg_sane_offset`
   These are the most direct extraction sites for `E005` and part of `E006`.

4. For environment-sensitive failures, instrument:
   - `check_attach_btf_id`
   - `check_map_prog_compatibility`
   - `check_pseudo_btf_id`
   - `check_struct_ops_btf_id`
   This is the cleanest surface for `E009` and a large subset of `E016`.

5. For verifier-limit / proof-shape tracking, instrument:
   - `check_max_stack_depth_subprog`
   - `check_cfg`
   - helper `visit_insn()`
   `visit_insn()` is required if you want the canonical `back-edge` / malformed-jump text, because `check_cfg()` itself only logs the final reachability errors directly.

6. Do not instrument only the top-level `check_*` wrappers where `verbose()` count is zero. Pair them with the helper that actually owns the message text:
   - `check_reg_arg` + `__check_reg_arg()`
   - `check_ptr_off_reg` + `__check_ptr_off_reg()`
   - `check_tp_buffer_access` / `check_buffer_access` + `__check_buffer_access()`
   - `check_attach_btf_id` + `bpf_check_attach_target()`

Bottom line:

- If BPFix wants the best first-pass obligation extraction yield, the highest-value semantic cut is **memory/type/call protocol** rather than CFG or metadata.
- If BPFix wants the best first-pass environment diagnosis yield, the highest-value cut is **attach + helper/kfunc availability + map/prog compatibility**.
- If BPFix wants faithful message-to-obligation attribution, it should capture both the **top-level rejecting `check_*`** and the **non-`check_*` helper that actually emits the canonical string**.
