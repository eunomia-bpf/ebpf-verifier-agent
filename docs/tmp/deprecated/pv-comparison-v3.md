# OBLIGE vs Pretty Verifier (PV), v3

Date: 2026-03-12

## Method

- Reused the exact 30-case benchmark from `docs/tmp/pv-comparison-v2.md` / `docs/tmp/manual-labeling-30cases.md` so the rerun stays comparable to v2.
- For StackOverflow and GitHub YAMLs with multiple `verifier_log.blocks`, selected the highest-scoring verbose block with the same `select_primary_log(...)` logic used in v2.
- OBLIGE was rerun on every case through `interface.extractor.rust_diagnostic.generate_diagnostic(log, catalog_path="taxonomy/error_catalog.yaml")`.
- PV is unchanged by construction: it is still simulated as one final verifier error line only, with one implied source location.
- `source locations` again counts unique `(path, line, snippet)` tuples from `json_data["metadata"]["proof_spans"]`; PV stays fixed at `1`.
- `root cause` and `actionability` were rescored against the same manual-label ground-truth fix notes. `root cause` means the output points to the real contract violation / missing proof, not just the final symptom. `actionability` means the output suggests a repair direction consistent with the accepted fix.
- `information density` is still `log_lines / diagnostic_lines`, so it remains a compression scalar rather than a usefulness score.
- Relative to v2, the current OBLIGE root/action scores changed on `10/30` cases: `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a`, `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d`, `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8`, `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`, `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09`, `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a`, `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9`, `stackoverflow-69767533`, `github-aya-rs-aya-1233`, `github-aya-rs-aya-864`.

## 30-Case Table

| Case | Class | Log lines | PV locs | OBLIGE locs | PV root | OBLIGE root | PV action | OBLIGE action | PV density | OBLIGE density |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | `source_bug` | 18 | 1 | 1 | Y | Y | Y | Y | 18.0x | 2.2x |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | 27 | 1 | 1 | Y | Y | N | Y | 27.0x | 1.6x |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | 38 | 1 | 1 | Y | Y | Y | Y | 38.0x | 2.9x |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | 44 | 1 | 3 | Y | Y | Y | Y | 44.0x | 2.8x |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | 46 | 1 | 1 | Y | Y | Y | Y | 46.0x | 5.1x |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | 102 | 1 | 3 | Y | Y | N | N | 102.0x | 6.4x |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | 41 | 1 | 1 | Y | Y | Y | Y | 41.0x | 4.6x |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | 24 | 1 | 1 | Y | Y | Y | Y | 24.0x | 2.7x |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `source_bug` | 16 | 1 | 1 | Y | Y | N | Y | 16.0x | 2.0x |
| `stackoverflow-69767533` | `source_bug` | 42 | 1 | 2 | Y | N | N | N | 42.0x | 3.2x |
| `stackoverflow-61945212` | `source_bug` | 13 | 1 | 1 | Y | Y | N | Y | 13.0x | 1.6x |
| `stackoverflow-77205912` | `source_bug` | 61 | 1 | 2 | N | N | N | N | 61.0x | 3.6x |
| `stackoverflow-70091221` | `source_bug` | 3 | 1 | 1 | Y | Y | Y | Y | 3.0x | 0.4x |
| `github-aya-rs-aya-1062` | `lowering_artifact` | 36 | 1 | 3 | Y | Y | Y | N | 36.0x | 2.1x |
| `stackoverflow-79530762` | `lowering_artifact` | 82 | 1 | 1 | N | Y | N | N | 82.0x | 4.8x |
| `stackoverflow-73088287` | `lowering_artifact` | 10 | 1 | 1 | N | N | N | N | 10.0x | 1.2x |
| `stackoverflow-74178703` | `lowering_artifact` | 23 | 1 | 1 | N | N | N | N | 23.0x | 2.6x |
| `stackoverflow-76160985` | `lowering_artifact` | 36 | 1 | 1 | N | N | N | N | 36.0x | 2.8x |
| `stackoverflow-70750259` | `lowering_artifact` | 22 | 1 | 2 | N | Y | N | Y | 22.0x | 1.3x |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | 513 | 1 | 2 | Y | Y | Y | Y | 513.0x | 32.1x |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | 408 | 1 | 2 | Y | Y | Y | Y | 408.0x | 24.0x |
| `stackoverflow-56872436` | `verifier_limit` | 6 | 1 | 1 | Y | Y | Y | Y | 6.0x | 0.9x |
| `stackoverflow-78753911` | `verifier_limit` | 2 | 1 | 1 | Y | Y | Y | Y | 2.0x | 0.3x |
| `github-cilium-cilium-41412` | `verifier_limit` | 25 | 1 | 1 | N | Y | N | Y | 25.0x | 2.8x |
| `github-cilium-cilium-35182` | `env_mismatch` | 5 | 1 | 1 | Y | Y | Y | Y | 5.0x | 0.7x |
| `github-aya-rs-aya-1233` | `env_mismatch` | 21 | 1 | 2 | Y | Y | Y | Y | 21.0x | 1.2x |
| `github-aya-rs-aya-864` | `env_mismatch` | 12 | 1 | 1 | Y | Y | N | Y | 12.0x | 1.5x |
| `stackoverflow-76441958` | `env_mismatch` | 25 | 1 | 1 | N | N | N | N | 25.0x | 1.5x |
| `github-cilium-cilium-44216` | `verifier_bug` | 45 | 1 | 1 | N | N | N | N | 45.0x | 7.5x |
| `github-cilium-cilium-41996` | `verifier_bug` | 2 | 1 | 1 | N | N | N | N | 2.0x | 0.3x |

## Summary Statistics

| Metric | PV | OBLIGE |
| --- | --- | --- |
| Mean source locations | 1.00 | 1.40 |
| Cases with >1 source location | 0/30 | 9/30 |
| Root cause identified | 20/30 | 22/30 |
| Actionable fix direction | 14/30 | 19/30 |
| Mean compression ratio (log lines / diagnostic lines) | 58.3x | 4.2x |
| Median compression ratio | 25.0x | 2.4x |

Per-class breakdown:

| Class | Cases | PV root | OBLIGE root | PV action | OBLIGE action |
| --- | --- | --- | --- | --- | --- |
| `source_bug` | 13 | 12/13 | 11/13 | 7/13 | 10/13 |
| `lowering_artifact` | 6 | 1/6 | 3/6 | 1/6 | 1/6 |
| `verifier_limit` | 5 | 4/5 | 5/5 | 4/5 | 5/5 |
| `env_mismatch` | 4 | 3/4 | 3/4 | 2/4 | 3/4 |
| `verifier_bug` | 2 | 0/2 | 0/2 | 0/2 | 0/2 |

- Root-cause comparison by case: OBLIGE better on `3` cases, worse on `1`, tied on `26`.
- Actionability comparison by case: OBLIGE better on `6` cases, worse on `1`, tied on `23`.

## What Changed vs V2

- The current pipeline substantially repairs the direct-contract / environment-mismatch regressions from v2. Destroying an uninitialized iterator, double-releasing a dynptr, calling a subprogram while holding a lock, passing a forged scalar where a stack pointer is required, and using a forbidden helper in `cgroup_skb` all now preserve the specific verifier contract instead of collapsing into generic `Regenerate BTF...` or verifier-limit advice.
- `github-aya-rs-aya-864` is another meaningful fix: OBLIGE now explicitly says the helper is unavailable in this classifier context and suggests reading the PID from context instead, which matches the issue fix.
- `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` improves only partially: OBLIGE now preserves the dynptr helper-argument contract (`Expected an initialized dynptr as arg #2`), so root-cause scoring improves, but the help text still overstates “initialize/create” instead of the exact-stack-slot repair.
- One source-bug regression remains: `stackoverflow-69767533` now surfaces `R1 type=ctx expected=fp` instead of the accepted `initialize tmp_buffer before bpf_probe_read` story, so its OBLIGE root/action score drops relative to v2.

## Honest Assessment

On this rerun, current OBLIGE now beats the PV one-line baseline overall on both metrics that matter here: root cause (`22/30` vs `20/30`) and actionability (`19/30` vs `14/30`). The gain comes almost entirely from the fixed source-bug and env-mismatch cases that used to collapse into generic BTF / verifier-limit text.

PV is still sufficient when the final verifier line already names the real defect. It remains competitive or better on cases like `stackoverflow-69767533`, where the current OBLIGE routing now latches onto the wrong early contract line instead of the accepted uninitialized-stack explanation.

The honest conclusion is narrower than “OBLIGE dominates PV everywhere.” The current pipeline now has a real overall advantage on this 30-case subset, but the win depends on preserving concrete verifier contracts. When OBLIGE routes to the wrong contract headline, PV can still be cleaner.
