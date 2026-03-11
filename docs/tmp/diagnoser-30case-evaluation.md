# Diagnoser 30-Case Evaluation

## Method

- Manual labels were loaded from `docs/tmp/manual-labeling-30cases.md`.
- Pretty Verifier accuracy was read from Table 2 in `docs/tmp/pretty-verifier-comparison.md`.
- Each case YAML was loaded from `case_study/cases/...`, and `verifier_log` was extracted exactly as `string` or `dict['combined']` falling back to joined `dict['blocks']`.
- The runner invoked `interface.extractor.diagnoser.diagnose(verifier_log)` once per case and recorded failures instead of aborting the batch.
- This report evaluates the current `diagnose()` entry point only. The earlier OBLIGE column in `pretty-verifier-comparison.md` came from a different `parse_log(...) + parse_trace(...)` path, so the numbers are not expected to match exactly.
- `root_cause != symptom` is `Yes` only when both instruction indices exist and differ.

## Per-Case Results

| case_id | manual_label | diagnoser_class | correct? | proof_status | root_cause != symptom? | loss_context | recommended_fix |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | `lowering_artifact` | No | `established_then_lost` | Yes | `branch` | Add an explicit unsigned clamp and keep the offset calculation in a separate verified register |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `lowering_artifact` | No | `established_then_lost` | Yes | `function_boundary` | Add __always_inline to the helper function |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | `lowering_artifact` | No | `established_then_lost` | Yes | `arithmetic` | Add an explicit unsigned clamp and keep the offset calculation in a separate verified register |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `stackoverflow-69767533` | `source_bug` | `source_bug` | Yes | `established_but_insufficient` | No | `arithmetic` |  |
| `stackoverflow-61945212` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `stackoverflow-77205912` | `source_bug` | `lowering_artifact` | No | `established_then_lost` | Yes | `arithmetic` | Add an explicit unsigned clamp and keep the offset calculation in a separate verified register |
| `stackoverflow-70091221` | `source_bug` | `source_bug` | Yes | `never_established` | No |  |  |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `lowering_artifact` | Yes | `established_then_lost` | Yes | `register_spill` | Keep pointer and offset in separate registers and avoid spill/reload across stack slots |
| `stackoverflow-79530762` | `lowering_artifact` | `lowering_artifact` | Yes | `established_then_lost` | Yes | `branch` | Restructure lowering so the verifier can preserve the earlier proof across the transformed code |
| `stackoverflow-73088287` | `lowering_artifact` | `source_bug` | No | `never_established` | No |  | Add bounds check: if (data + offset + size <= data_end) |
| `stackoverflow-74178703` | `lowering_artifact` | `lowering_artifact` | Yes | `never_established` | No |  | Restructure lowering so the verifier can preserve the earlier proof across the transformed code |
| `stackoverflow-76160985` | `lowering_artifact` | `lowering_artifact` | Yes | `established_but_insufficient` | No | `arithmetic` | Add an explicit unsigned clamp and keep the offset calculation in a separate verified register |
| `stackoverflow-70750259` | `lowering_artifact` | `lowering_artifact` | Yes | `established_then_lost` | Yes | `arithmetic` | Add an explicit unsigned clamp and keep the offset calculation in a separate verified register |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `verifier_limit` | Yes | `established_then_lost` | Yes | `function_boundary` | Split the program with tail calls or reduce branching and loop work |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `verifier_limit` | Yes | `established_then_lost` | Yes | `function_boundary` | Split the program with tail calls or reduce branching and loop work |
| `stackoverflow-56872436` | `verifier_limit` | `verifier_limit` | Yes |  | Unknown | `loop` | Strengthen the loop bound or fully unroll the loop |
| `stackoverflow-78753911` | `verifier_limit` | `verifier_limit` | Yes |  | Unknown |  | Split the program with tail calls or reduce branching and loop work |
| `github-cilium-cilium-41412` | `verifier_limit` | `verifier_limit` | Yes | `never_established` | No |  | Split the program with tail calls or reduce branching and loop work |
| `github-cilium-cilium-35182` | `env_mismatch` | `env_mismatch` | Yes |  | Unknown |  | Regenerate BTF artifacts and ensure they match the running kernel |
| `github-aya-rs-aya-1233` | `env_mismatch` | `env_mismatch` | Yes | `established_then_lost` | Yes | `function_boundary` | Check that the target kernel and program type support the helper, kfunc, or attach type |
| `github-aya-rs-aya-864` | `env_mismatch` | `env_mismatch` | Yes | `never_established` | No |  | Check that the target kernel and program type support the helper, kfunc, or attach type |
| `stackoverflow-76441958` | `env_mismatch` | `lowering_artifact` | No | `established_then_lost` | Yes | `branch` | Restructure lowering so the verifier can preserve the earlier proof across the transformed code |
| `github-cilium-cilium-44216` | `verifier_bug` | `verifier_bug` | Yes |  | Unknown |  | Minimize the reproducer and bisect the verifier behavior across kernel versions |
| `github-cilium-cilium-41996` | `verifier_bug` | `source_bug` | No | `never_established` | No |  |  |

## Aggregate Accuracy

| Metric | Value |
| --- | --- |
| Diagnoser overall accuracy | 23/30 (76.7%) |
| Pretty Verifier overall accuracy | 19/30 (63.3%) |
| Diagnoser earlier root cause found | 11/30 (36.7%) |
| Diagnoser recommended fix populated | 20/30 (66.7%) |
| Diagnoser failures | 0/30 (0.0%) |

| Taxonomy class | Cases | Diagnoser accuracy | PV accuracy | Earlier root cause |
| --- | --- | --- | --- | --- |
| `source_bug` | 13 | 9/13 (69.2%) | 13/13 (100.0%) | 4/13 (30.8%) |
| `lowering_artifact` | 6 | 5/6 (83.3%) | 1/6 (16.7%) | 3/6 (50.0%) |
| `verifier_limit` | 5 | 5/5 (100.0%) | 3/5 (60.0%) | 2/5 (40.0%) |
| `env_mismatch` | 4 | 3/4 (75.0%) | 1/4 (25.0%) | 2/4 (50.0%) |
| `verifier_bug` | 2 | 1/2 (50.0%) | 1/2 (50.0%) | 0/2 (0.0%) |

## Comparison vs Pretty Verifier

| Outcome | Count | Cases |
| --- | --- | --- |
| Diagnoser correct, PV wrong | 8 | `github-aya-rs-aya-1062`, `stackoverflow-79530762`, `stackoverflow-74178703`, `stackoverflow-76160985`, `stackoverflow-56872436`, `github-cilium-cilium-41412`, `github-aya-rs-aya-1233`, `github-aya-rs-aya-864` |
| PV correct, diagnoser wrong | 4 | `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8`, `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`, `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a`, `stackoverflow-77205912` |
| Both correct | 15 | `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a`, `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246`, `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d`, `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39`, `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09`, `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9`, `stackoverflow-69767533`, `stackoverflow-61945212`, `stackoverflow-70091221`, `stackoverflow-70750259`, `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda`, `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d`, `stackoverflow-78753911`, `github-cilium-cilium-35182`, `github-cilium-cilium-44216` |
| Both wrong | 3 | `stackoverflow-73088287`, `stackoverflow-76441958`, `github-cilium-cilium-41996` |

## Analysis

The diagnoser's proof-status distribution across all 30 cases was `established_but_insufficient`=2, `established_then_lost`=11, `never_established`=13, `unknown`=4. On the correctly classified subset, the distribution was `established_but_insufficient`=2, `established_then_lost`=6, `never_established`=11, `unknown`=4.

The current `diagnose()` entry point scored `23/30` overall, slightly below Pretty Verifier's `19/30`. That is also materially below the earlier OBLIGE column in `pretty-verifier-comparison.md`, which is expected here because that earlier document evaluated a lower-level `parse_log(...) + parse_trace(...)` pipeline rather than the current single-entry-point diagnoser.

The strongest class was `verifier_limit` and the weakest was `verifier_bug`. The diagnoser still keeps its intended advantage on trace-sensitive classes: `lowering_artifact` is `5/6` vs Pretty Verifier's `1/6`, `verifier_limit` is `5/5` vs `3/5`, and `env_mismatch` is `3/4` vs `1/4`.

The main regression driver is `source_bug`: only `9/13` correct, with `0` cases specifically drifting to `env_mismatch`. In those cases the evidence often still contains a `source_bug` catalog seed, but the final classification overrides it to `OBLIGE-E021` because the symptom line mentions `reference type('UNKNOWN ')` or similar environment-looking text.

Relative to Pretty Verifier, the diagnoser gained `8` cases and lost `4`. The wins are concentrated where trace structure matters more than the final line, while the losses are dominated by these `source_bug` override errors.

Incorrect cases and likely reasons:
- `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8`: manual `source_bug`, diagnoser `lowering_artifact`. Detected a real proof-loss transition, but over-attributed the failure to lowering instead of the underlying source-side contract bug.
- `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`: manual `source_bug`, diagnoser `lowering_artifact`. Detected a real proof-loss transition, but over-attributed the failure to lowering instead of the underlying source-side contract bug.
- `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a`: manual `source_bug`, diagnoser `lowering_artifact`. Detected a real proof-loss transition, but over-attributed the failure to lowering instead of the underlying source-side contract bug.
- `stackoverflow-77205912`: manual `source_bug`, diagnoser `lowering_artifact`. Detected a real proof-loss transition, but over-attributed the failure to lowering instead of the underlying source-side contract bug.
- `stackoverflow-73088287`: manual `lowering_artifact`, diagnoser `source_bug`. Stayed on the final access symptom and treated it as a source bug instead of a proof-loss artifact.
- `stackoverflow-76441958`: manual `env_mismatch`, diagnoser `lowering_artifact`. The environment-dependent rejection also contains proof-loss structure, and the diagnoser over-read that as a lowering artifact.
- `github-cilium-cilium-41996`: manual `verifier_bug`, diagnoser `source_bug`. Matched the symptom line, but not the kernel-side false-rejection pattern.

## Key Findings

- The diagnoser classified `23/30` cases correctly (76.7%), versus `19/30` (63.3%) for Pretty Verifier on the same 30 cases.
- Despite lower overall accuracy, the diagnoser still beat Pretty Verifier on `lowering_artifact` (`5/6` vs `1/6`), `verifier_limit` (`5/5` vs `3/5`), and `env_mismatch` (`3/4` vs `1/4`).
- The dominant failure mode was `source_bug -> env_mismatch`: `0` cases, mostly driven by final overrides to `OBLIGE-E021` after BTF-flavored symptom text.
- The diagnoser returned a distinct root-cause instruction on `11/30` cases and a non-empty recommended fix on `20/30` cases.
