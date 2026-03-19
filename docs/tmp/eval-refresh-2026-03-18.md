# Eval Refresh 2026-03-18

- Manifest: `case_study/eval_manifest.yaml`
- Batch results: `eval/results/batch_diagnostic_results.json`
- Latency results: `eval/results/latency_benchmark_v4.json`
- Baseline results: `eval/results/baseline_results.json`

## Manifest Stats

| Source | Total | Core | Noisy | Excluded |
| --- | ---: | ---: | ---: | ---: |
| `kernel_selftests` | 200 | 156 | 15 | 29 |
| `stackoverflow` | 76 | 43 | 22 | 11 |
| `github_issues` | 26 | 11 | 15 | 0 |

- Total logged cases: `302`
- Eligible: `262`
- Core: `210`
- Noisy: `52`
- Excluded: `40`

## Selftest Family Analysis

- Families with a terminal rejection line: `67`
- Ungrouped selftests with empty/no terminal message: `29`
- Core representatives retained across families: `85`

| Family (terminal rejection line) | Total | Core | Noisy | Excluded | Representatives |
| --- | ---: | ---: | ---: | ---: | --- |
| JIT does not support calling kfunc bpf_throw#73439 | 20 | 16 | 4 | 0 | `kernel-selftest-exceptions-fail-reject-async-callback-throw-tc-a86cf7b1`, `kernel-selftest-exceptions-fail-reject-with-cb-reference-tc-c99ec1a7` |
| BPF_EXIT instruction in main prog would lead to reference leak | 13 | 13 | 0 | 0 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0`, `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` |
| cannot overwrite referenced dynptr | 8 | 8 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-overwrite-ref-raw-tp-3fed55ba`, `kernel-selftest-dynptr-fail-dynptr-pruning-type-confusion-tc-28056c9b` |
| BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region | 7 | 7 | 0 | 0 | `kernel-selftest-irq-irq-restore-missing-3-minus-2-subprog-tc-5c202e26`, `kernel-selftest-irq-irq-restore-missing-3-subprog-tc-8592c5d7` |
| Possibly NULL pointer passed to trusted arg0 | 7 | 5 | 2 | 0 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-untrusted-tp-btf-cgroup-mkdir-2bcab89b`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-untrusted-tp-btf-cgroup-mkdir-9eb3123d` |
| Expected an initialized dynptr as arg #0 | 6 | 6 | 0 | 0 | `kernel-selftest-dynptr-fail-clone-invalid1-raw-tp-b7206632`, `kernel-selftest-dynptr-fail-invalid-write1-raw-tp-ba5ba8ca` |
| Expected an initialized dynptr as arg #2 | 6 | 6 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-helper2-raw-tp-34ba04aa`, `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` |
| R6 invalid mem access 'scalar' | 6 | 6 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725`, `kernel-selftest-iters-iter-err-too-permissive1-raw-tp-25649784` |
| R7 invalid mem access 'scalar' | 6 | 6 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-invalidate-slice-reinit-raw-tp-f5b71f50`, `kernel-selftest-dynptr-fail-skb-invalid-data-slice3-tc-a15c4322` |
| expected an initialized iter_num as arg #0 | 6 | 6 | 0 | 0 | `kernel-selftest-iters-state-safety-compromise-iter-w-helper-write-fail-raw-tp-50431478`, `kernel-selftest-iters-state-safety-double-destroy-fail-raw-tp-224283ff` |
| function calls are not allowed while holding a lock | 5 | 5 | 0 | 0 | `kernel-selftest-exceptions-fail-reject-with-rbtree-add-throw-tc-e943cfe2`, `kernel-selftest-irq-irq-wrong-kfunc-class-2-tc-03b53958` |
| R0 min value is outside of the allowed memory range | 4 | 4 | 0 | 0 | `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49` |
| R1 must be referenced or trusted | 4 | 4 | 0 | 0 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b`, `kernel-selftest-dynptr-fail-skb-invalid-ctx-fentry-fentry-skb-tx-error-17cea403` |
| R8 invalid mem access 'scalar' | 4 | 4 | 0 | 0 | `kernel-selftest-dynptr-fail-skb-invalid-data-slice1-tc-0b35a757`, `kernel-selftest-dynptr-fail-xdp-invalid-data-slice1-xdp-c0fa30d5` |
| expected an initialized irq flag as arg#0 | 4 | 4 | 0 | 0 | `kernel-selftest-irq-irq-flag-overwrite-tc-4c974993`, `kernel-selftest-irq-irq-restore-invalid-tc-e1f743bf` |
| arg 1 is an unacquired reference | 3 | 3 | 0 | 0 | `kernel-selftest-dynptr-fail-release-twice-callback-raw-tp-bd7b2a60`, `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` |
| arg#0 expected pointer to an iterator on stack | 3 | 1 | 2 | 0 | `kernel-selftest-iters-iter-new-bad-arg-raw-tp-e25f0e76` |
| Dynptr has to be an uninitialized dynptr | 2 | 2 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-var-off-overwrite-tc-ab0a2e71`, `kernel-selftest-dynptr-fail-invalid-offset-raw-tp-549f8135` |
| R0 invalid mem access 'mem_or_null' | 2 | 2 | 0 | 0 | `kernel-selftest-dynptr-fail-data-slice-missing-null-check1-raw-tp-af2be9c9`, `kernel-selftest-dynptr-fail-data-slice-missing-null-check2-raw-tp-8e533162` |
| a non-sleepable BPF program context | 2 | 2 | 0 | 0 | `kernel-selftest-irq-irq-sleepable-global-subprog-indirect-syscall-c96d09ca`, `kernel-selftest-irq-irq-sleepable-helper-global-subprog-syscall-7d470f89` |
| arg#0 doesn't point to an irq flag on stack | 2 | 0 | 2 | 0 | _None_ |
| arg#0 pointer type STRUCT cgroup must point to scalar, or struct with scalar | 2 | 2 | 0 | 0 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-fp-tp-btf-cgroup-mkdir-7d3a90fe`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-fp-tp-btf-cgroup-mkdir-2a0f9c99` |
| arg#2 arg#3 memory, len pair leads to invalid memory access | 2 | 2 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb`, `kernel-selftest-dynptr-fail-test-dynptr-skb-small-buff-cgroup-skb-egress-4f498dbd` |
| insn 3 cannot call exception cb directly | 2 | 2 | 0 | 0 | `kernel-selftest-exceptions-fail-reject-exception-cb-call-global-func-tc-bd94f6f8`, `kernel-selftest-exceptions-fail-reject-exception-cb-call-static-func-tc-f3ceb9b7` |
| invalid read from stack off -16+0 size 4 | 2 | 2 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-read1-raw-tp-f61c0428`, `kernel-selftest-dynptr-fail-invalid-read4-raw-tp-8a9b0872` |
| potential write to dynptr at off=-16 disallowed | 2 | 2 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-read-into-slot-raw-tp-5420cc35`, `kernel-selftest-dynptr-fail-uninit-write-into-slot-raw-tp-a80cb838` |
| At program exit the register R0 has unknown scalar value should have been in [0, 0] | 1 | 1 | 0 | 0 | `kernel-selftest-exceptions-fail-reject-set-exception-cb-bad-ret1-fentry-bpf-check-8124b586` |
| Caller passes invalid args into func#1 ('global_call_bpf_dynptr') | 1 | 0 | 1 | 0 | _None_ |
| Possibly NULL pointer passed to helper arg2 | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` |
| Possibly NULL pointer passed to trusted arg1 | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-global-mask-no-null-check-tp-btf-task-newtask-655f6c03` |
| R0 invalid mem access 'scalar' | 1 | 1 | 0 | 0 | `kernel-selftest-iters-looping-missing-null-check-fail-raw-tp-732d9857` |
| R1 has no valid kptr | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-invalid-nested-array-tp-btf-task-newtask-bd05d03f` |
| R1 must be a rcu pointer | 1 | 1 | 0 | 0 | `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-trusted-walked-tp-btf-cgroup-mkdir-6deeac84` |
| R1 type=mem expected=ringbuf_mem | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-ringbuf-invalid-api-raw-tp-87a443d6` |
| R1 type=scalar expected=fp | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` |
| R1 unbounded memory access, make sure to bounds check any such access | 1 | 1 | 0 | 0 | `kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943` |
| R2 must be a rcu pointer | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-global-mask-out-of-rcu-tp-btf-task-newtask-55a16b69` |
| R4 must be a known constant | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-slice-var-len2-tc-673ab9e7` |
| R4 type=map_value expected=fp, dynptr_ptr | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-global-raw-tp-e92dc79e` |
| R6 invalid mem access 'map_value_or_null' | 1 | 1 | 0 | 0 | `kernel-selftest-iters-iter-err-too-permissive2-raw-tp-177534f5` |
| R7 invalid mem access 'map_value_or_null' | 1 | 1 | 0 | 0 | `kernel-selftest-iters-iter-err-too-permissive3-raw-tp-969d109d` |
| Unsupported reg type fp for bpf_dynptr_from_mem data | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-dynptr-from-mem-invalid-api-raw-tp-1040be69` |
| arg#1 arg#2 memory, len pair leads to invalid memory access | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-populate-invalid-source-tp-btf-task-newtask-149c6ecc` |
| attach to unsupported member test_2 of struct bpf_dummy_ops | 1 | 0 | 1 | 0 | _None_ |
| calling kernel function bpf_cgroup_acquire is not allowed | 1 | 0 | 1 | 0 | _None_ |
| calling kernel function bpf_dynptr_from_skb is not allowed | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-skb-invalid-ctx-xdp-1a32a21f` |
| calling kernel function bpf_dynptr_from_xdp is not allowed | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-xdp-invalid-ctx-raw-tp-e886d43f` |
| cannot restore irq state out of order, expected id=2 acquired at insn_idx=10 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-ooo-lock-cond-inv-tc-950f35d5` |
| cannot restore irq state out of order, expected id=2 acquired at insn_idx=29 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-restore-4-subprog-tc-f3feb6a1` |
| cannot restore irq state out of order, expected id=2 acquired at insn_idx=7 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-restore-ooo-tc-84ede29d` |
| cannot restore irq state out of order, expected id=3 acquired at insn_idx=13 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-restore-ooo-3-tc-e0b5e5ee` |
| cannot restore irq state out of order, expected id=4 acquired at insn_idx=15 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-restore-ooo-3-subprog-tc-b32ae1a0` |
| cannot restore irq state out of order, expected id=5 acquired at insn_idx=16 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-ooo-refs-array-tc-193001a6` |
| combined stack size of 2 calls is 544. Too large | 1 | 1 | 0 | 0 | `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` |
| combined stack size of 2 calls is 576. Too large | 1 | 1 | 0 | 0 | `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` |
| expected uninitialized irq flag as arg#0 | 1 | 1 | 0 | 0 | `kernel-selftest-irq-irq-save-invalid-tc-86a07a3f` |
| expected uninitialized iter_num as arg #0 | 1 | 1 | 0 | 0 | `kernel-selftest-iters-state-safety-double-create-fail-raw-tp-11a53add` |
| invalid read from stack R1 off -24+0 size 16 | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-helper1-raw-tp-e765040b` |
| invalid read from stack R3 off -16+0 size 16 | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-add-dynptr-to-map1-raw-tp-2b5ac898` |
| invalid read from stack R3 off -24+8 size 24 | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-add-dynptr-to-map2-raw-tp-7a037daf` |
| invalid read from stack off -24+0 size 8 | 1 | 1 | 0 | 0 | `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` |
| invalid read from stack off -8+0 size 4 | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-read3-raw-tp-99c4b958` |
| kernel function bpf_cpumask_set_cpu args#1 expected pointer to STRUCT bpf_cpumask but R2 has a pointer to STRUCT cpumask | 1 | 1 | 0 | 0 | `kernel-selftest-cpumask-failure-test-mutate-cpumask-tp-btf-task-newtask-d7b7c258` |
| math between map_value pointer and register with unbounded min value is not allowed | 1 | 1 | 0 | 0 | `kernel-selftest-iters-iter-err-unsafe-c-loop-raw-tp-4b9ee52e` |
| multiple exception callback tags for main subprog | 1 | 0 | 1 | 0 | _None_ |
| release kernel function bpf_cgroup_release expects refcounted PTR_TO_BTF_ID | 1 | 0 | 1 | 0 | _None_ |
| the prog does not allow writes to packet data | 1 | 1 | 0 | 0 | `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196` |

## Batch Eval

- Generated at: `2026-03-19T03:30:14.096053+00:00`
- Eligible success rate: `262/262 (100.0%)`
- Eligible failures: `0`
- Skipped for short logs: `40`
- Average spans on successful eligible cases: `1.10`
- BTF file:line coverage on successful eligible cases: `172/262 (65.6%)`

### Proof Status

| Value | Count | Share |
| --- | ---: | ---: |
| `unknown` | 184 | (70.2%) |
| `never_established` | 66 | (25.2%) |
| `established_then_lost` | 11 | (4.2%) |
| `established_but_insufficient` | 1 | (0.4%) |

### Taxonomy

| Value | Count | Share |
| --- | ---: | ---: |
| `source_bug` | 212 | (80.9%) |
| `env_mismatch` | 27 | (10.3%) |
| `lowering_artifact` | 18 | (6.9%) |
| `verifier_limit` | 5 | (1.9%) |

## Latency

- Generated at: `2026-03-19T03:30:27.339066+00:00`
- Successful benchmarked cases: `262`

| Metric | ms |
| --- | ---: |
| min | 6.585 |
| median | 14.862 |
| mean | 13.997 |
| p95 | 19.573 |
| p99 | 30.564 |
| max | 57.479 |

- Pearson r(log lines, latency): `0.587`
- Slowest case: `github-aya-rs-aya-1062` at `57.479` ms

## Baseline vs BPFix

- Compared eligible cases: `262`
- Eligible cases with taxonomy labels: `255`
- Eligible cases with manual error IDs: `30`

| Metric | Regex baseline | BPFix |
| --- | ---: | ---: |
| Taxonomy accuracy on labeled eligible cases | 193/255 (75.7%) | 179/255 (70.2%) |
| Error ID accuracy on manual eligible cases | 24/30 (80.0%) | 23/30 (76.7%) |
| Average spans per eligible case | 0.00 | 1.10 |
| Multi-span outputs (>=2 spans) | 0/262 (0.0%) | 19/262 (7.3%) |
| Non-unknown proof status | 0/262 (0.0%) | 78/262 (29.8%) |

- The saved baseline `spans` metric follows the prescribed batch command and reads the top-level `spans` field.
- The regex baseline stores its rejected span under `metadata.proof_spans`, so the recorded `spans` count is `0` for all saved rows.
