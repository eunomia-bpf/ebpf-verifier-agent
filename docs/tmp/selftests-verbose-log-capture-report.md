# Kernel Selftests Verbose Log Capture Report

Run date: 2026-03-11

## Scope

- Case directories scanned: /home/yunwei37/workspace/ebpf-verifier-agent/case_study/cases/kernel_selftests, /home/yunwei37/workspace/ebpf-verifier-agent/case_study/cases/kernel_selftests.pre_unique_ids_20260311T0903
- YAML case files present on disk: 400
- YAML case files with usable selftest metadata: 385
- Unique selftest program targets: 222
- Unique selftest source files referenced by processed targets: 22
- Programs were loaded one at a time with a custom libbpf helper using per-program verifier log level 2.
- No bpffs pins were created during load attempts; helper processes exited after each load.

## Results

- Compile files attempted: 22
- Compile files succeeded: 18
- Compile files failed: 4
- Program loads attempted: 213
- Program loads succeeded: 1
- Program loads rejected or failed: 212
- Programs with non-empty verifier logs captured: 175
- Rejected programs with verifier logs captured: 174
- YAML case files with `verifier_log` after this run: 321
- YAML case files updated with `verifier_log` in this run: 159

## Compilation Failures

- 1 file(s): `missing source file: /tmp/ebpf-eval-repos/linux/tools/testing/selftests/bpf/progs/cgroup_read_xattr.c`
- 1 file(s): `missing source file: /tmp/ebpf-eval-repos/linux/tools/testing/selftests/bpf/progs/file_reader_fail.c`
- 1 file(s): `missing source file: /tmp/ebpf-eval-repos/linux/tools/testing/selftests/bpf/progs/kfunc_implicit_args.c`
- 1 file(s): `missing source file: /tmp/ebpf-eval-repos/linux/tools/testing/selftests/bpf/progs/mem_rdonly_untrusted.c`

## Sample Verifier Logs

### `async_call_root_check` from `tools/testing/selftests/bpf/progs/async_stack_depth.c`

- Section: `tc`
- Error: `Permission denied`

```text
func#0 @0
func#1 @55
func#2 @104
Live regs before insn:
  0: .......... (b4) w6 = 0
  1: ......6... (73) *(u8 *)(r10 -1) = r6
  2: ......6... (b7) r1 = 0
  3: .1....6... (7b) *(u64 *)(r10 -16) = r1
  4: .1....6... (7b) *(u64 *)(r10 -24) = r1
  5: .1....6... (7b) *(u64 *)(r10 -32) = r1
  6: .1....6... (7b) *(u64 *)(r10 -40) = r1
  7: .1....6... (7b) *(u64 *)(r10 -48) = r1
  8: .1....6... (7b) *(u64 *)(r10 -56) = r1
  9: .1....6... (7b) *(u64 *)(r10 -64) = r1
 10: .1....6... (7b) *(u64 *)(r10 -72) = r1
 11: .1....6... (7b) *(u64 *)(r10 -80) = r1
 12: .1....6... (7b) *(u64 *)(r10 -88) = r1
 13: .1....6... (7b) *(u64 *)(r10 -96) = r1
 14: .1....6... (7b) *(u64 *)(r10 -104) = r1
 15: .1....6... (7b) *(u64 *)(r10 -112) = r1
 16: .1....6... (7b) *(u64 *)(r10 -120) = r1
 17: .1....6... (7b) *(u64 *)(r10 -128) = r1
 18: .1....6... (7b) *(u64 *)(r10 -136) = r1
 19: .1....6... (7b) *(u64 *)(r10 -144) = r1
 20: .1....6... (7b) *(u64 *)(r10 -152) = r1
 21: .1....6... (7b) *(u64 *)(r10 -160) = r1
 22: .1....6... (7b) *(u64 *)(r10 -168) = r1
 23: .1....6... (7b) *(u64 *)(r10 -176) = r1
 24: .1....6... (7b) *(u64 *)(r10 -184) = r1
 25: .1....6... (7b) *(u64 *)(r10 -192) = r1
 26: .1....6... (7b) *(u64 *)(r10 -200) = r1
 27: .1....6... (7b) *(u64 *)(r10 -208) = r1
 28: .1....6... (7b) *(u64 *)(r10 -216) = r1
 29: .1....6... (7b) *(u64 *)(r10 -224) = r1
 30: .1....6... (7b) *(u64 *)(r10 -232) = r1
 31: .1....6... (7b) *(u64 *)(r10 -240) = r1
 32: .1....6... (7b) *(u64 *)(r10 -248) = r1
 33: .1....6... (7b) *(u64 *)(r10 -256) = r1
 34: ......6... (73) *(u8 *)(r10 -2) = r6
 35: ......6... (6b) *(u16 *)(r10 -4) = r6
 36: ......6... (63) *(u32 *)(r10 -8) = r6
 37: ......6... (63) *(u32 *)(r10 -260) = r6
 38: ......6... (bf) r2 = r10
 39: ..2...6... (07) r2 += -260
 40: ..2...6... (18) r1 = 0xffff8d47e6e90800
 42: .12...6... (85) call bpf_map_lookup_elem#1
 43: 0.....6... (15) if r0 == 0x0 goto pc+9
 44: 0......... (bf) r1 = r0
 45: .1........ (18) r2 = 0x9
 47: .12....... (85) call bpf_timer_set_callback#170
 48: 0......... (bf) r6 = r0
 49: ......6... (71) r1 = *(u8 *)(r10 -1)
 50: .1....6... (64) w1 <<= 24
 51: .1....6... (c4) w1 s>>= 24
 52: .1....6... (0c) w6 += w1
 53: ......6... (bc) w0 = w6
 54: 0......... (95) exit
 55: ...345.... (b7) r1 = 0
 56: .1.345.... (7b) *(u64 *)(r10 -256) = r1
 57: .1.345.... (7b) *(u64 *)(r10 -248) = r1
```

### `pseudo_call_check` from `tools/testing/selftests/bpf/progs/async_stack_depth.c`

- Section: `tc`
- Error: `Permission denied`

```text
func#0 @0
func#1 @57
Live regs before insn:
  0: .......... (b4) w6 = 0
  1: ......6... (73) *(u8 *)(r10 -1) = r6
  2: ......6... (b7) r1 = 0
  3: .1....6... (7b) *(u64 *)(r10 -16) = r1
  4: .1....6... (7b) *(u64 *)(r10 -24) = r1
  5: .1....6... (7b) *(u64 *)(r10 -32) = r1
  6: .1....6... (7b) *(u64 *)(r10 -40) = r1
  7: .1....6... (7b) *(u64 *)(r10 -48) = r1
  8: .1....6... (7b) *(u64 *)(r10 -56) = r1
  9: .1....6... (7b) *(u64 *)(r10 -64) = r1
 10: .1....6... (7b) *(u64 *)(r10 -72) = r1
 11: .1....6... (7b) *(u64 *)(r10 -80) = r1
 12: .1....6... (7b) *(u64 *)(r10 -88) = r1
 13: .1....6... (7b) *(u64 *)(r10 -96) = r1
 14: .1....6... (7b) *(u64 *)(r10 -104) = r1
 15: .1....6... (7b) *(u64 *)(r10 -112) = r1
 16: .1....6... (7b) *(u64 *)(r10 -120) = r1
 17: .1....6... (7b) *(u64 *)(r10 -128) = r1
 18: .1....6... (7b) *(u64 *)(r10 -136) = r1
 19: .1....6... (7b) *(u64 *)(r10 -144) = r1
 20: .1....6... (7b) *(u64 *)(r10 -152) = r1
 21: .1....6... (7b) *(u64 *)(r10 -160) = r1
 22: .1....6... (7b) *(u64 *)(r10 -168) = r1
 23: .1....6... (7b) *(u64 *)(r10 -176) = r1
 24: .1....6... (7b) *(u64 *)(r10 -184) = r1
 25: .1....6... (7b) *(u64 *)(r10 -192) = r1
 26: .1....6... (7b) *(u64 *)(r10 -200) = r1
 27: .1....6... (7b) *(u64 *)(r10 -208) = r1
 28: .1....6... (7b) *(u64 *)(r10 -216) = r1
 29: .1....6... (7b) *(u64 *)(r10 -224) = r1
 30: .1....6... (7b) *(u64 *)(r10 -232) = r1
 31: .1....6... (7b) *(u64 *)(r10 -240) = r1
 32: .1....6... (7b) *(u64 *)(r10 -248) = r1
 33: .1....6... (7b) *(u64 *)(r10 -256) = r1
 34: ......6... (73) *(u8 *)(r10 -2) = r6
 35: ......6... (6b) *(u16 *)(r10 -4) = r6
 36: ......6... (63) *(u32 *)(r10 -8) = r6
 37: ......6... (63) *(u32 *)(r10 -260) = r6
 38: ......6... (bf) r2 = r10
 39: ..2...6... (07) r2 += -260
 40: ..2...6... (18) r1 = 0xffff8d481e690000
 42: .12...6... (85) call bpf_map_lookup_elem#1
 43: 0123456... (bf) r7 = r0
 44: .1234567.. (15) if r7 == 0x0 goto pc+10
 45: .12345.7.. (85) call pc+11
 46: .......7.. (bf) r1 = r7
 47: .1........ (18) r2 = 0x9
 49: .12....... (85) call bpf_timer_set_callback#170
 50: 0......... (bf) r6 = r0
 51: ......6... (71) r1 = *(u8 *)(r10 -1)
 52: .1....6... (64) w1 <<= 24
 53: .1....6... (c4) w1 s>>= 24
 54: .1....6... (0c) w6 += w1
 55: ......6... (bc) w0 = w6
 56: 0......... (95) exit
 57: .......... (b7) r1 = 0
 58: .1........ (7b) *(u64 *)(r10 -72) = r1
```

### `cgrp_kfunc_acquire_fp` from `tools/testing/selftests/bpf/progs/cgrp_kfunc_failure.c`

- Section: `tp_btf/cgroup_mkdir`
- Error: `Invalid argument`

```text
func#0 @0
Live regs before insn:
  0: .1........ (79) r1 = *(u64 *)(r1 +8)
  1: .1........ (7b) *(u64 *)(r10 -8) = r1
  2: .......... (bf) r1 = r10
  3: .1........ (07) r1 += -8
  4: .1........ (7b) *(u64 *)(r10 -16) = r1
  5: .......... (bf) r1 = r10
  6: .1........ (07) r1 += -16
  7: .1........ (85) call bpf_cgroup_acquire#71302
  8: 0......... (15) if r0 == 0x0 goto pc+2
  9: 0......... (bf) r1 = r0
 10: .1........ (85) call bpf_cgroup_release#71323
 11: .......... (b4) w0 = 0
 12: 0......... (95) exit
0: R1=ctx() R10=fp0
; int BPF_PROG(cgrp_kfunc_acquire_fp, struct cgroup *cgrp, const char *path) @ cgrp_kfunc_failure.c:68
0: (79) r1 = *(u64 *)(r1 +8)          ; R1_w=scalar()
1: (7b) *(u64 *)(r10 -8) = r1         ; R1_w=scalar(id=1) R10=fp0 fp-8_w=scalar(id=1)
2: (bf) r1 = r10                      ; R1_w=fp0 R10=fp0
;  @ cgrp_kfunc_failure.c:0
3: (07) r1 += -8                      ; R1_w=fp-8
; struct cgroup *acquired, *stack_cgrp = (struct cgroup *)&path; @ cgrp_kfunc_failure.c:70
4: (7b) *(u64 *)(r10 -16) = r1        ; R1_w=fp-8 R10=fp0 fp-16_w=fp-8
5: (bf) r1 = r10                      ; R1_w=fp0 R10=fp0
;  @ cgrp_kfunc_failure.c:0
6: (07) r1 += -16                     ; R1_w=fp-16
; acquired = bpf_cgroup_acquire((struct cgroup *)&stack_cgrp); @ cgrp_kfunc_failure.c:73
7: (85) call bpf_cgroup_acquire#71302
arg#0 pointer type STRUCT cgroup must point to scalar, or struct with scalar
processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

## Timing

- Started: 2026-03-11T20:58:06.548241+00:00
- Finished: 2026-03-11T20:58:29.637772+00:00
- Duration seconds: 23.1
