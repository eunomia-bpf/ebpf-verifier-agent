# Taxonomy Coverage Analysis

Generated at: `2026-03-11T16:39:56+00:00`

## Coverage

- Total benchmark cases analyzed: **302**
- Catalog-matched cases: **263**
- Coverage rate: **87.1%**

### Coverage by Source

| Source | Cases | Matched | Coverage |
| --- | ---: | ---: | ---: |
| `github_issues` | 26 | 20 | 76.9% |
| `kernel_selftests` | 200 | 186 | 93.0% |
| `stackoverflow` | 76 | 57 | 75.0% |

## Distribution by Catalog Error ID

| Error ID | Count |
| --- | ---: |
| `OBLIGE-E001` | 18 |
| `OBLIGE-E002` | 8 |
| `OBLIGE-E003` | 9 |
| `OBLIGE-E004` | 17 |
| `OBLIGE-E005` | 23 |
| `OBLIGE-E006` | 0 |
| `OBLIGE-E007` | 1 |
| `OBLIGE-E008` | 1 |
| `OBLIGE-E009` | 3 |
| `OBLIGE-E010` | 1 |
| `OBLIGE-E011` | 38 |
| `OBLIGE-E012` | 22 |
| `OBLIGE-E013` | 19 |
| `OBLIGE-E014` | 10 |
| `OBLIGE-E015` | 9 |
| `OBLIGE-E016` | 21 |
| `OBLIGE-E017` | 1 |
| `OBLIGE-E018` | 3 |
| `OBLIGE-E019` | 13 |
| `OBLIGE-E020` | 9 |
| `OBLIGE-E021` | 2 |
| `OBLIGE-E022` | 1 |
| `OBLIGE-E023` | 34 |

## Distribution by Taxonomy Class

### Catalog-Matched Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 207 |
| `lowering_artifact` | 23 |
| `verifier_limit` | 5 |
| `env_mismatch` | 27 |
| `verifier_bug` | 1 |

### Heuristic Classification Across All Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 255 |
| `lowering_artifact` | 12 |
| `verifier_limit` | 5 |
| `env_mismatch` | 29 |
| `verifier_bug` | 1 |

## Top Unmatched Verifier Messages

| Rank | Message | Count | Sources | Sample Cases |
| ---: | --- | ---: | --- | --- |
| 1 | Invalid argument (os error 22) | 2 | github_issues:2 | `github-aya-rs-aya-1104`, `github-aya-rs-aya-546` |
| 2 | unbounded memory access | 2 | kernel_selftests:2 | `kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb`, `kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943` |
| 3 | 0: the BPF_PROG_LOAD syscall failed. Verifier output: fd 12 is not pointing to valid bpf_map | 1 | github_issues:1 | `github-aya-rs-aya-1324` |
| 4 | [30] UNION MaybeUninit<u8> size=1 vlen=2 Invalid name | 1 | github_issues:1 | `github-aya-rs-aya-1490` |
| 5 | At program exit the register R1 has smin=64 smax=64 | 1 | kernel_selftests:1 | `kernel-selftest-exceptions-assert-check-assert-with-return-fentry-bpf-check-ba50c498` |
| 6 | bpf_test.go:170: verifier error: load program: operation not supported: | 1 | github_issues:1 | `github-cilium-cilium-41412` |
| 7 | cgrp_kfunc_acquire_trusted_walked | 1 | kernel_selftests:1 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-trusted-walked-tp-btf-cgroup-mkdir-6deeac84` |
| 8 | fp-304=??mmmmmm fp-312=mmmmmmmm fp-320=mmmmmmmm fp-328=?mmmmmmm fp-336=mmmmmmmm fp-344= (truncated...) | 1 | stackoverflow:1 | `stackoverflow-68815540` |
| 9 | invalid bpf_context access off=92 size=4 | 1 | stackoverflow:1 | `stackoverflow-67402772` |
| 10 | leads to invalid memory access | 1 | kernel_selftests:1 | `kernel-selftest-cpumask-failure-test-populate-invalid-source-tp-btf-task-newtask-149c6ecc` |
| 11 | libbpf: failed to load BPF skeleton 'hello_bpf': -3 | 1 | stackoverflow:1 | `stackoverflow-77462271` |
| 12 | libbpf: failed to load object 'work/switch/switch.o' | 1 | stackoverflow:1 | `stackoverflow-78633443` |
| 13 | libbpf: load bpf program failed: Invalid argument | 1 | stackoverflow:1 | `stackoverflow-69192685` |
| 14 | memory, len pair leads to invalid memory access | 1 | kernel_selftests:1 | `kernel-selftest-dynptr-fail-test-dynptr-skb-small-buff-cgroup-skb-egress-4f498dbd` |
| 15 | Permission denied (os error 13) | 1 | github_issues:1 | `github-aya-rs-aya-857` |
| 16 | R0 unbounded memory access, make sure to bounds check any such access | 1 | stackoverflow:1 | `stackoverflow-71253472` |
| 17 | R1=ctx() R2=scalar(smin=umin=smin32=umin32=4096,smax=umax=smax32=umax32=8192,var_off=(0x0; 0x3fff)) | 1 | kernel_selftests:1 | `kernel-selftest-exceptions-assert-check-assert-range-u64-tc-832996f2` |
| 18 | R2 pointer arithmetic on PTR_TO_PACKET_END prohibited | 1 | stackoverflow:1 | `stackoverflow-60506220` |
| 19 | R3 pointer comparison prohibited | 1 | stackoverflow:1 | `stackoverflow-71351495` |
| 20 | section simple verbose | 1 | stackoverflow:1 | `stackoverflow-47591176` |

## Recommended Pattern Expansions to Existing IDs

These unmatched themes already look semantically close to existing catalog entries, so widening regex coverage is lower risk than introducing new IDs.


## Recommendations for New Error IDs

The current gap list mixes two kinds of misses: genuinely new semantic categories and messages that are likely pattern variants of existing catalog entries. The proposals below focus on the highest-frequency unmatched themes that recur across multiple cases.
