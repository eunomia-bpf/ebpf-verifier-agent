# Taxonomy Coverage Analysis

Generated at: `2026-03-11T16:27:56+00:00`

## Coverage

- Total benchmark cases analyzed: **302**
- Catalog-matched cases: **193**
- Coverage rate: **63.9%**

### Coverage by Source

| Source | Cases | Matched | Coverage |
| --- | ---: | ---: | ---: |
| `github_issues` | 26 | 12 | 46.2% |
| `kernel_selftests` | 200 | 139 | 69.5% |
| `stackoverflow` | 76 | 42 | 55.3% |

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
| `OBLIGE-E015` | 8 |
| `OBLIGE-E016` | 12 |
| `OBLIGE-E017` | 1 |
| `OBLIGE-E018` | 2 |

## Distribution by Taxonomy Class

### Catalog-Matched Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 150 |
| `lowering_artifact` | 23 |
| `verifier_limit` | 4 |
| `env_mismatch` | 15 |
| `verifier_bug` | 1 |

### Heuristic Classification Across All Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 261 |
| `lowering_artifact` | 12 |
| `verifier_limit` | 4 |
| `env_mismatch` | 24 |
| `verifier_bug` | 1 |

## Top Unmatched Verifier Messages

| Rank | Message | Count | Sources | Sample Cases |
| ---: | --- | ---: | --- | --- |
| 1 | expected an initialized | 4 | kernel_selftests:4 | `kernel-selftest-irq-irq-flag-overwrite-partial-tc-51152af8`, `kernel-selftest-irq-irq-flag-overwrite-tc-4c974993`, `kernel-selftest-irq-irq-restore-invalid-tc-e1f743bf`, `kernel-selftest-irq-irq-restore-iter-tc-501bf2c6` |
| 2 | arg 1 is an unacquired reference | 3 | kernel_selftests:3 | `kernel-selftest-dynptr-fail-release-twice-callback-raw-tp-bd7b2a60`, `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d`, `kernel-selftest-dynptr-fail-ringbuf-release-uninit-dynptr-raw-tp-a799622b` |
| 3 | misaligned stack access off 0+-31+0 size 8 | 3 | kernel_selftests:3 | `kernel-selftest-iters-iters-raw-tp-063123db`, `kernel-selftest-iters-iters-raw-tp-9292b545`, `kernel-selftest-iters-iters-raw-tp-bd99cf85` |
| 4 | must be referenced or trusted | 3 | kernel_selftests:3 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b`, `kernel-selftest-dynptr-fail-skb-invalid-ctx-fentry-fentry-skb-tx-error-17cea403`, `kernel-selftest-dynptr-fail-skb-invalid-ctx-fexit-fexit-skb-tx-error-ef42c043` |
| 5 | arg#0 doesn't point to an irq flag on stack | 2 | kernel_selftests:2 | `kernel-selftest-irq-irq-restore-bad-arg-tc-28a1cb48`, `kernel-selftest-irq-irq-save-bad-arg-tc-2e0fba3a` |
| 6 | arg#0 pointer type STRUCT cgroup must point | 2 | kernel_selftests:2 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-fp-tp-btf-cgroup-mkdir-7d3a90fe`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-fp-tp-btf-cgroup-mkdir-2a0f9c99` |
| 7 | cannot call exception cb directly | 2 | kernel_selftests:2 | `kernel-selftest-exceptions-fail-reject-exception-cb-call-global-func-tc-bd94f6f8`, `kernel-selftest-exceptions-fail-reject-exception-cb-call-static-func-tc-f3ceb9b7` |
| 8 | exception cb only supports single integer argument | 2 | kernel_selftests:2 | `kernel-selftest-exceptions-fail-reject-exception-cb-type-2-tc-45ccb6dc`, `kernel-selftest-exceptions-fail-reject-exception-cb-type-3-tc-62f713bd` |
| 9 | function calls are not allowed | 2 | kernel_selftests:2 | `kernel-selftest-irq-irq-wrong-kfunc-class-1-tc-05e98572`, `kernel-selftest-irq-irq-wrong-kfunc-class-2-tc-03b53958` |
| 10 | Invalid argument (os error 22) | 2 | github_issues:2 | `github-aya-rs-aya-1104`, `github-aya-rs-aya-546` |
| 11 | potential write to dynptr at off=-16 | 2 | kernel_selftests:2 | `kernel-selftest-dynptr-fail-dynptr-read-into-slot-raw-tp-5420cc35`, `kernel-selftest-dynptr-fail-uninit-write-into-slot-raw-tp-a80cb838` |
| 12 | R1 type=inv expected=map_ptr | 2 | github_issues:1, stackoverflow:1 | `stackoverflow-72606055`, `github-facebookincubator-katran-149` |
| 13 | R4 invalid zero-sized read: u64=[0,31] | 2 | github_issues:2 | `github-aya-rs-aya-1207`, `github-aya-rs-aya-1267` |
| 14 | R6 !read_ok | 2 | stackoverflow:2 | `stackoverflow-67441023`, `stackoverflow-75300106` |
| 15 | R{{[0-9]+}} cannot write into rdonly_mem | 2 | kernel_selftests:2 | `kernel-selftest-dynptr-fail-dynptr-fail-tc-db029308`, `kernel-selftest-dynptr-fail-dynptr-fail-tc-de3e751b` |
| 16 | unbounded memory access | 2 | kernel_selftests:2 | `kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb`, `kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943` |
| 17 | 0: the BPF_PROG_LOAD syscall failed. Verifier output: fd 12 is not pointing to valid bpf_map | 1 | github_issues:1 | `github-aya-rs-aya-1324` |
| 18 | [13] FUNC bpf_prog1 type_id=9 Invalid arg#1 | 1 | stackoverflow:1 | `stackoverflow-70392721` |
| 19 | [30] UNION MaybeUninit<u8> size=1 vlen=2 Invalid name | 1 | github_issues:1 | `github-aya-rs-aya-1490` |
| 20 | arg#0 expected pointer to stack or const struct bpf_dynptr | 1 | kernel_selftests:1 | `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` |

## Recommended Pattern Expansions to Existing IDs

These unmatched themes already look semantically close to existing catalog entries, so widening regex coverage is lower risk than introducing new IDs.


## Recommendations for New Error IDs

The current gap list mixes two kinds of misses: genuinely new semantic categories and messages that are likely pattern variants of existing catalog entries. The proposals below focus on the highest-frequency unmatched themes that recur across multiple cases.

### OBLIGE-E019 `dynptr_protocol_violation`

- Taxonomy class: `source_bug`
- Proposed title: Dynptr initialization, lifetime, or access protocol violated
- Supporting unmatched cases: 6
- Candidate regex patterns: `Expected an initialized dynptr as arg #\d+`, `cannot overwrite referenced dynptr`, `Expected a dynptr of type .* as arg #\d+`
- Example messages: `potential write to dynptr at off=-16`; `arg#0 expected pointer to stack or const struct bpf_dynptr`; `cannot pass in dynptr at an offset`
- Sources: kernel_selftests:6

### OBLIGE-E020 `execution_context_discipline_violation`

- Taxonomy class: `source_bug`
- Proposed title: Lock, IRQ, or RCU discipline violated on at least one control-flow path
- Supporting unmatched cases: 2
- Candidate regex patterns: `cannot restore irq state out of order`, `function calls are not allowed while holding a lock`, `BPF_EXIT instruction .* cannot be used inside .* region`
- Example messages: `arg#0 doesn't point to an irq flag on stack`
- Sources: kernel_selftests:2

### OBLIGE-E021 `btf_reference_metadata_missing`

- Taxonomy class: `env_mismatch`
- Proposed title: BTF or reference type metadata is insufficient for verifier type validation
- Supporting unmatched cases: 1
- Candidate regex patterns: `arg#\d+ reference type\('UNKNOWN '\) size cannot be determined`, `invalid btf[_ ]id`
- Example messages: `arg#0 reference type('UNKNOWN ') size cannot be determined: -22`
- Sources: github_issues:1

### OBLIGE-E022 `mutable_global_state_unsupported`

- Taxonomy class: `env_mismatch`
- Proposed title: Mutable global or static data access unsupported in the active BPF environment
- Supporting unmatched cases: 1
- Candidate regex patterns: `only read from bpf_array is supported`
- Example messages: `only read from bpf_array is supported`
- Sources: github_issues:1

### OBLIGE-E023 `scalar_pointer_dereference`

- Taxonomy class: `source_bug`
- Proposed title: Scalar value dereferenced where a tracked pointer proof is required
- Supporting unmatched cases: 1
- Candidate regex patterns: `R\d+ invalid mem access '(?:scalar|inv)'`, `R\d+ type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_`
- Example messages: `R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_`
- Sources: stackoverflow:1
