# Taxonomy Coverage Analysis

Generated at: `2026-03-11T16:17:02+00:00`

## Coverage

- Total benchmark cases analyzed: **302**
- Catalog-matched cases: **44**
- Coverage rate: **14.6%**

### Coverage by Source

| Source | Cases | Matched | Coverage |
| --- | ---: | ---: | ---: |
| `github_issues` | 26 | 10 | 38.5% |
| `kernel_selftests` | 200 | 11 | 5.5% |
| `stackoverflow` | 76 | 23 | 30.3% |

## Distribution by Catalog Error ID

| Error ID | Count |
| --- | ---: |
| `OBLIGE-E001` | 18 |
| `OBLIGE-E002` | 5 |
| `OBLIGE-E003` | 2 |
| `OBLIGE-E004` | 7 |
| `OBLIGE-E005` | 7 |
| `OBLIGE-E006` | 0 |
| `OBLIGE-E007` | 1 |
| `OBLIGE-E008` | 1 |
| `OBLIGE-E009` | 2 |
| `OBLIGE-E010` | 1 |

## Distribution by Taxonomy Class

### Catalog-Matched Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 32 |
| `lowering_artifact` | 7 |
| `verifier_limit` | 2 |
| `env_mismatch` | 2 |
| `verifier_bug` | 1 |

### Heuristic Classification Across All Cases

| Taxonomy Class | Count |
| --- | ---: |
| `source_bug` | 266 |
| `lowering_artifact` | 12 |
| `verifier_limit` | 4 |
| `env_mismatch` | 19 |
| `verifier_bug` | 1 |

## Top Unmatched Verifier Messages

| Rank | Message | Count | Sources | Sample Cases |
| ---: | --- | ---: | --- | --- |
| 1 | invalid mem access 'scalar' | 25 | kernel_selftests:25 | `kernel-selftest-dynptr-fail-clone-invalidate4-raw-tp-0dfbe587`, `kernel-selftest-dynptr-fail-clone-invalidate5-raw-tp-1e91d4af`, `kernel-selftest-dynptr-fail-clone-invalidate6-raw-tp-57de0291`, `kernel-selftest-dynptr-fail-clone-skb-packet-data-tc-109b5b9e`, `kernel-selftest-dynptr-fail-clone-skb-packet-meta-tc-c2ab5a7b` |
| 2 | Expected an initialized dynptr as arg #0 | 11 | kernel_selftests:11 | `kernel-selftest-dynptr-fail-clone-invalid1-raw-tp-b7206632`, `kernel-selftest-dynptr-fail-clone-invalidate1-raw-tp-6696ea02`, `kernel-selftest-dynptr-fail-clone-invalidate2-raw-tp-87d63d59`, `kernel-selftest-dynptr-fail-clone-invalidate3-raw-tp-819c4745`, `kernel-selftest-dynptr-fail-dynptr-adjust-invalid-raw-tp-6e40976e` |
| 3 | Unreleased reference | 9 | kernel_selftests:9 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unreleased-tp-btf-cgroup-mkdir-0f46d712`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0`, `kernel-selftest-cpumask-failure-test-alloc-no-release-tp-btf-task-newtask-7525df6a`, `kernel-selftest-cpumask-failure-test-insert-remove-no-release-tp-btf-task-newtask-24314756`, `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` |
| 4 | cannot overwrite referenced dynptr | 8 | kernel_selftests:8 | `kernel-selftest-dynptr-fail-clone-invalid2-xdp-08448ef8`, `kernel-selftest-dynptr-fail-dynptr-overwrite-ref-raw-tp-3fed55ba`, `kernel-selftest-dynptr-fail-dynptr-partial-slot-invalidate-tc-8f5ee7c7`, `kernel-selftest-dynptr-fail-dynptr-pruning-overwrite-tc-6e6ed521`, `kernel-selftest-dynptr-fail-dynptr-pruning-type-confusion-tc-28056c9b` |
| 5 | BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region | 7 | kernel_selftests:7 | `kernel-selftest-irq-irq-restore-missing-1-subprog-tc-d3ae4b66`, `kernel-selftest-irq-irq-restore-missing-2-subprog-tc-82732cca`, `kernel-selftest-irq-irq-restore-missing-2-tc-dbccea22`, `kernel-selftest-irq-irq-restore-missing-3-minus-2-subprog-tc-5c202e26`, `kernel-selftest-irq-irq-restore-missing-3-minus-2-tc-4087d3bc` |
| 6 | invalid access to map value, value_size=2048 off=0 size=0 | 7 | stackoverflow:7 | `stackoverflow-72560675`, `stackoverflow-74178703`, `stackoverflow-75515263`, `stackoverflow-76994829`, `stackoverflow-77713434` |
| 7 | invalid read from stack | 7 | kernel_selftests:7 | `kernel-selftest-dynptr-fail-add-dynptr-to-map1-raw-tp-2b5ac898`, `kernel-selftest-dynptr-fail-add-dynptr-to-map2-raw-tp-7a037daf`, `kernel-selftest-dynptr-fail-invalid-helper1-raw-tp-e765040b`, `kernel-selftest-dynptr-fail-invalid-read1-raw-tp-f61c0428`, `kernel-selftest-dynptr-fail-invalid-read3-raw-tp-99c4b958` |
| 8 | cannot restore irq state out of order | 6 | kernel_selftests:6 | `kernel-selftest-irq-irq-ooo-lock-cond-inv-tc-950f35d5`, `kernel-selftest-irq-irq-ooo-refs-array-tc-193001a6`, `kernel-selftest-irq-irq-restore-4-subprog-tc-f3feb6a1`, `kernel-selftest-irq-irq-restore-ooo-3-subprog-tc-b32ae1a0`, `kernel-selftest-irq-irq-restore-ooo-3-tc-e0b5e5ee` |
| 9 | expected an initialized iter_num as arg #0 | 6 | kernel_selftests:6 | `kernel-selftest-iters-state-safety-compromise-iter-w-direct-write-fail-raw-tp-12239df3`, `kernel-selftest-iters-state-safety-compromise-iter-w-helper-write-fail-raw-tp-50431478`, `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a`, `kernel-selftest-iters-state-safety-double-destroy-fail-raw-tp-224283ff`, `kernel-selftest-iters-state-safety-next-after-destroy-fail-raw-tp-28effd8b` |
| 10 | R2 invalid mem access 'inv' | 6 | stackoverflow:6 | `stackoverflow-53136145`, `stackoverflow-67679109`, `stackoverflow-71946593`, `stackoverflow-72074115`, `stackoverflow-75294010` |
| 11 | Possibly NULL pointer passed to trusted arg0 | 5 | kernel_selftests:5 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-no-null-check-tp-btf-cgroup-mkdir-6484ab95`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-null-tp-btf-cgroup-mkdir-2a562fb3`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-untrusted-tp-btf-cgroup-mkdir-2bcab89b`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-null-tp-btf-cgroup-mkdir-790c61df`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-untrusted-tp-btf-cgroup-mkdir-9eb3123d` |
| 12 | expected an initialized | 4 | kernel_selftests:4 | `kernel-selftest-irq-irq-flag-overwrite-partial-tc-51152af8`, `kernel-selftest-irq-irq-flag-overwrite-tc-4c974993`, `kernel-selftest-irq-irq-restore-invalid-tc-e1f743bf`, `kernel-selftest-irq-irq-restore-iter-tc-501bf2c6` |
| 13 | math between fp pointer and register with unbounded | 4 | kernel_selftests:4 | `kernel-selftest-iters-iters-raw-tp-579dfae3`, `kernel-selftest-iters-iters-raw-tp-80811bc0`, `kernel-selftest-iters-iters-raw-tp-d2273ce7`, `kernel-selftest-iters-iters-raw-tp-ea7ac3e5` |
| 14 | R0 min value is outside of the allowed memory range | 4 | kernel_selftests:1, stackoverflow:3 | `kernel-selftest-iters-looping-wrong-sized-read-fail-raw-tp-b975c554`, `stackoverflow-75515263`, `stackoverflow-76160985`, `stackoverflow-76994829` |
| 15 | value is outside of the allowed memory range | 4 | kernel_selftests:4 | `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-meta-tc-420f28c1`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49` |
| 16 | arg 1 is an unacquired reference | 3 | kernel_selftests:3 | `kernel-selftest-dynptr-fail-release-twice-callback-raw-tp-bd7b2a60`, `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d`, `kernel-selftest-dynptr-fail-ringbuf-release-uninit-dynptr-raw-tp-a799622b` |
| 17 | arg#0 expected pointer to an iterator on stack | 3 | kernel_selftests:3 | `kernel-selftest-iters-iter-destroy-bad-arg-raw-tp-0045e2f2`, `kernel-selftest-iters-iter-new-bad-arg-raw-tp-e25f0e76`, `kernel-selftest-iters-iter-next-bad-arg-raw-tp-30e866e3` |
| 18 | cannot be called from callback | 3 | kernel_selftests:3 | `kernel-selftest-exceptions-fail-reject-exception-throw-cb-diff-tc-d4026f8f`, `kernel-selftest-exceptions-fail-reject-exception-throw-cb-tc-ed9b506d`, `kernel-selftest-exceptions-fail-reject-with-cb-tc-eaccdce9` |
| 19 | function calls are not allowed while holding a lock | 3 | kernel_selftests:3 | `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8`, `kernel-selftest-exceptions-fail-reject-with-lock-tc-66db0d44`, `kernel-selftest-exceptions-fail-reject-with-rbtree-add-throw-tc-e943cfe2` |
| 20 | misaligned stack access off 0+-31+0 size 8 | 3 | kernel_selftests:3 | `kernel-selftest-iters-iters-raw-tp-063123db`, `kernel-selftest-iters-iters-raw-tp-9292b545`, `kernel-selftest-iters-iters-raw-tp-bd99cf85` |

## Recommended Pattern Expansions to Existing IDs

These unmatched themes already look semantically close to existing catalog entries, so widening regex coverage is lower risk than introducing new IDs.

### OBLIGE-E005

- Supporting unmatched cases: 11
- Why expand it: Broaden E005 to catch scalar-range failures currently phrased as allowed-memory-range violations.
- Candidate regex patterns: `math between .* pointer and register with unbounded.*`, `(?:R\d+ )?(?:min|max)? value is outside of the allowed memory range`
- Example messages: `math between fp pointer and register with unbounded`; `R0 min value is outside of the allowed memory range`; `R3 max value is outside of the allowed memory range`
- Sources: kernel_selftests:5, stackoverflow:6

### OBLIGE-E004

- Supporting unmatched cases: 10
- Why expand it: Expand E004 to match shorter `Unreleased reference` forms without an explicit `id=` suffix.
- Candidate regex patterns: `Unreleased reference(?: id=\d+)?`
- Example messages: `Unreleased reference`; `Unreleased reference id`
- Sources: kernel_selftests:10

### OBLIGE-E003

- Supporting unmatched cases: 7
- Why expand it: Expand E003 to cover both `invalid indirect read from stack` and the shorter `invalid read from stack` wording.
- Candidate regex patterns: `invalid (?:indirect )?read from stack`
- Example messages: `invalid read from stack`
- Sources: kernel_selftests:7

### OBLIGE-E002

- Supporting unmatched cases: 3
- Why expand it: Expand E002 to include nullable memory aliases beyond `map_value_or_null`.
- Candidate regex patterns: `invalid mem access 'map_value_or_null'`, `invalid mem access 'mem_or_null'`
- Example messages: `invalid mem access 'mem_or_null'`; `R1 invalid mem access 'mem_or_null'`
- Sources: kernel_selftests:2, stackoverflow:1

### OBLIGE-E009

- Supporting unmatched cases: 1
- Why expand it: Expand E009 to cover helper restrictions phrased in program-type-specific wording.
- Candidate regex patterns: `program of this type cannot use helper .*`, `helper call is not allowed`, `unknown func`
- Example messages: `program of this type cannot use helper bpf_probe_read#4`
- Sources: github_issues:1


## Recommendations for New Error IDs

The current gap list mixes two kinds of misses: genuinely new semantic categories and messages that are likely pattern variants of existing catalog entries. The proposals below focus on the highest-frequency unmatched themes that recur across multiple cases.

### OBLIGE-E011 `scalar_pointer_dereference`

- Taxonomy class: `source_bug`
- Proposed title: Scalar value dereferenced where a tracked pointer proof is required
- Supporting unmatched cases: 38
- Candidate regex patterns: `R\d+ invalid mem access '(?:scalar|inv)'`, `R\d+ type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_`
- Example messages: `invalid mem access 'scalar'`; `R2 invalid mem access 'inv'`; `R0 invalid mem access 'scalar'`
- Sources: kernel_selftests:27, stackoverflow:11

### OBLIGE-E012 `dynptr_protocol_violation`

- Taxonomy class: `source_bug`
- Proposed title: Dynptr initialization, lifetime, or access protocol violated
- Supporting unmatched cases: 31
- Candidate regex patterns: `Expected an initialized dynptr as arg #\d+`, `cannot overwrite referenced dynptr`, `Expected a dynptr of type .* as arg #\d+`
- Example messages: `Expected an initialized dynptr as arg #0`; `cannot overwrite referenced dynptr`; `cannot pass in dynptr at an offset=-8`
- Sources: kernel_selftests:31

### OBLIGE-E013 `execution_context_discipline_violation`

- Taxonomy class: `source_bug`
- Proposed title: Lock, IRQ, or RCU discipline violated on at least one control-flow path
- Supporting unmatched cases: 20
- Candidate regex patterns: `cannot restore irq state out of order`, `function calls are not allowed while holding a lock`, `BPF_EXIT instruction .* cannot be used inside .* region`
- Example messages: `BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region`; `cannot restore irq state out of order`; `function calls are not allowed while holding a lock`
- Sources: kernel_selftests:20

### OBLIGE-E014 `iterator_state_protocol_violation`

- Taxonomy class: `source_bug`
- Proposed title: Iterator state machine or stack-placement contract violated
- Supporting unmatched cases: 11
- Candidate regex patterns: `expected an initialized iter_num as arg #\d+`, `arg#\d+ expected pointer to an iterator on stack`
- Example messages: `expected an initialized iter_num as arg #0`; `arg#0 expected pointer to an iterator on stack`; `expected uninitialized iter_num as arg #0`
- Sources: kernel_selftests:11

### OBLIGE-E015 `trusted_arg_nullability`

- Taxonomy class: `source_bug`
- Proposed title: Trusted pointer argument may be NULL at call site
- Supporting unmatched cases: 8
- Candidate regex patterns: `Possibly NULL pointer passed to trusted arg\d+`, `NULL pointer passed to trusted arg\d+`
- Example messages: `Possibly NULL pointer passed to trusted arg0`; `NULL pointer passed to trusted arg0`
- Sources: kernel_selftests:8

### OBLIGE-E016 `helper_or_kfunc_context_restriction`

- Taxonomy class: `env_mismatch`
- Proposed title: Helper or kfunc is unavailable in the current program type or execution context
- Supporting unmatched cases: 7
- Candidate regex patterns: `program of this type cannot use helper .*`, `helper call is not allowed`, `cannot be called from callback(?: subprog)?`
- Example messages: `cannot be called from callback`; `cannot be called from callback subprog`; `global functions that may sleep are not allowed in non-sleepable context`
- Sources: kernel_selftests:7

### OBLIGE-E017 `map_value_bounds_violation`

- Taxonomy class: `source_bug`
- Proposed title: Map value access exceeds the verifier-proven bounds of the target object
- Supporting unmatched cases: 7
- Candidate regex patterns: `invalid access to map value, value_size=\d+ off=-?\d+ size=\d+`
- Example messages: `invalid access to map value, value_size=2048 off=0 size=0`
- Sources: stackoverflow:7

### OBLIGE-E018 `verifier_analysis_budget_limit`

- Taxonomy class: `verifier_limit`
- Proposed title: Verifier rejects the proof shape due to bounded analysis or complexity limits
- Supporting unmatched cases: 2
- Candidate regex patterns: `combined stack size .*`, `too many states`, `loop is not bounded`, `back-edge`
- Example messages: `combined stack size of 2 calls is`
- Sources: kernel_selftests:2
