# Ground Truth Label Expansion Report

**Generated**: 2026-03-13

## Summary

| Source | Count |
| --- | ---: |
| Manual (existing 30-case study) | 30 |
| Kernel selftest auto-labeled | 189 |
| Stack Overflow auto-labeled | 58 |
| GitHub Issues auto-labeled | 15 |
| **Total** | **292** |

## Taxonomy Distribution

| Class | Count | Share |
| --- | ---: | ---: |
| `source_bug` | 193 | 66.1% |
| `env_mismatch` | 47 | 16.1% |
| `lowering_artifact` | 44 | 15.1% |
| `verifier_limit` | 6 | 2.1% |
| `verifier_bug` | 2 | 0.7% |

## Confidence Distribution

| Confidence | Count |
| --- | ---: |
| high | 219 |
| medium | 73 |

## Methodology

### Kernel Selftest Cases (confidence: high)

Kernel selftests are *intentionally failing* programs that test specific verifier checks.
Each case has `expected_verifier_messages` annotated with `__msg()`. The taxonomy is
deterministic from the error type:

1. If the case has an `error_id` field, map via the error catalog.
2. Otherwise, pattern-match the expected message strings against 50+ regex patterns
   covering all 23 OBLIGE error IDs.
3. Fall back to scanning the full `verifier_log` field.

### Stack Overflow and GitHub Issue Cases (confidence: medium)

Auto-labeling uses keyword matching on `fix_description`, `body_text`, and
`summary` fields:

- **source_bug**: bounds check, null check, initialize buffer, pointer guard, etc.
- **lowering_artifact**: volatile, barrier, inline, clang, compiler optimization, etc.
- **env_mismatch**: kernel version, not supported, helper not, program type, etc.
- **verifier_limit**: loop unroll, complexity, too many states, state explosion, etc.

If no keyword match, fall back to verifier log message pattern matching.

### Manual Labels (priority override)

The 30 existing manual labels always take priority over auto labels on any conflict.

## Sample Labeled Cases by Source

### Kernel Selftest Samples (first 10)

| Case ID | Taxonomy | Notes |
| --- | --- | --- |
| `kernel-selftest-cgroup-read-xattr-use-css-iter-sleepable-missing-rcu-lock-lsm-s-socket-connect-7dc81f79` | `source_bug` | msg_pattern:kernel func bpf_iter_css_new requires RCU critical section protectio |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-fp-tp-btf-cgroup-mkdir-7d3a90fe` | `source_bug` | msg_pattern:arg#0 pointer type STRUCT cgroup must point |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-no-null-check-tp-btf-cgroup-mkdir-6484ab95` | `source_bug` | msg_pattern:Possibly NULL pointer passed to trusted arg0 |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-null-tp-btf-cgroup-mkdir-2a562fb3` | `source_bug` | msg_pattern:Possibly NULL pointer passed to trusted arg0 |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-trusted-walked-tp-btf-cgroup-mkdir-6deeac84` | `source_bug` | log_pattern:func#0 @0
Live regs before insn:
  0: .1........ (79) r1 = *(u64 *)( |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unreleased-tp-btf-cgroup-mkdir-0f46d712` | `source_bug` | msg_pattern:Unreleased reference |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unsafe-kretprobe-kretprobe-cgroup-destroy-a01df7e0` | `env_mismatch` | msg_pattern:calling kernel function bpf_cgroup_acquire is not allowed |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-untrusted-tp-btf-cgroup-mkdir-2bcab89b` | `source_bug` | msg_pattern:Possibly NULL pointer passed to trusted arg0 |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b` | `source_bug` | msg_pattern:must be referenced or trusted |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-fp-tp-btf-cgroup-mkdir-2a0f9c99` | `source_bug` | msg_pattern:arg#0 pointer type STRUCT cgroup must point |

### Stack Overflow Samples (first 10)

| Case ID | Taxonomy | Notes |
| --- | --- | --- |
| `stackoverflow-47591176` | `lowering_artifact` | keyword:llvm |
| `stackoverflow-48267671` | `lowering_artifact` | keyword:llvm |
| `stackoverflow-53136145` | `source_bug` | log_msg:105: (bf) r4 = r0
106: (07) r4 += 8
107: (b7) r8 = 1
108: (2d) if r4 > r |
| `stackoverflow-56965789` | `lowering_artifact` | keyword:inline |
| `stackoverflow-60053570` | `lowering_artifact` | keyword:llvm |
| `stackoverflow-60506220` | `lowering_artifact` | keyword:clang |
| `stackoverflow-67402772` | `lowering_artifact` | keyword:clang |
| `stackoverflow-67441023` | `source_bug` | keyword:check_ld_abs()). As the comment says, these instructions implicitly expe |
| `stackoverflow-67679109` | `source_bug` | log_msg:> Compiling BPF
Attaching to uretprobe
bpf: Failed to load program: Perm |
| `stackoverflow-68752893` | `source_bug` | keyword:checks on your program in the Linux kernel ensures that no out-of-bound  |

### GitHub Issues Samples (all 15)

| Case ID | Taxonomy | Notes |
| --- | --- | --- |
| `github-aya-rs-aya-1002` | `env_mismatch` | keyword:not supported |
| `github-aya-rs-aya-1056` | `lowering_artifact` | log_msg:➜  IdeaProjects cargo generate https://github.com/aya-rs/aya-template
   |
| `github-aya-rs-aya-1207` | `source_bug` | log_msg:18: (85) call bpf_skb_load_bytes#26
R4 invalid zero-sized read: u64=[0,3 |
| `github-aya-rs-aya-1267` | `source_bug` | log_msg:hanshal101@lol:~/ebpf/rust/egmon$ sudo RUST_LOG=debug cargo run
   Compi |
| `github-aya-rs-aya-1490` | `env_mismatch` | log_msg:Error: BTF error: the BPF_BTF_LOAD syscall returned Invalid argument (os |
| `github-aya-rs-aya-407` | `env_mismatch` | keyword:only with u32/i32 for PerfEventArray, if this is a missing feature or so |
| `github-aya-rs-aya-440` | `env_mismatch` | keyword:helper access to the packet is not |
| `github-aya-rs-aya-458` | `source_bug` | log_msg:291: (85) call bpf_map_lookup_elem#1          ; R0_w=map_value_or_null(i |
| `github-aya-rs-aya-521` | `env_mismatch` | log_msg:5: (b7) r6 = 5                      ; R6_w=P5
876: (bf) r3 = r10         |
| `github-aya-rs-aya-808` | `env_mismatch` | log_msg:Error: the BPF_PROG_LOAD syscall failed. Verifier output: Validating wri |
| `github-aya-rs-aya-857` | `lowering_artifact` | keyword:LLVM |
| `github-aya-rs-aya-863` | `lowering_artifact` | log_msg:Error: the BPF_PROG_LOAD syscall failed. Verifier output: 0: (bf) r6 = r |
| `github-cilium-cilium-36936` | `env_mismatch` | keyword:Kernel Version |
| `github-cilium-cilium-37478` | `env_mismatch` | keyword:kernel version |
| `github-cilium-cilium-41522` | `env_mismatch` | keyword:Kernel Version |

## Output File

Labels saved to: `case_study/ground_truth_labels.yaml`

**Target achieved**: YES (292 >= 100 required)