# OBLIGE vs Pretty Verifier (PV), v2

Date: 2026-03-12

## Method

- Reused the original 30-case benchmark from `docs/tmp/manual-labeling-30cases.md` so the run stays comparable to the pre-integration comparison. This subset already includes the key lowering-artifact cases plus BTF-tagged selftests, verifier-limit cases, and environment mismatches.
- For StackOverflow and GitHub YAMLs with multiple `verifier_log.blocks`, selected the highest-scoring verbose block with the repo’s existing `select_primary_log(...)` logic.
- OBLIGE was run on every case through `interface.extractor.rust_diagnostic.generate_diagnostic(log, catalog_path="taxonomy/error_catalog.yaml")`.
- PV was simulated exactly as requested: one final verifier error line only, with one implied source location.
- `source locations` counts unique `(path, line, snippet)` entries from `json_data["metadata"]["proof_spans"]`; PV is fixed at `1` by construction.
- `root cause` and `actionability` were scored against the benchmark’s existing ground-truth fix notes. `root cause` means the output points to the missing proof / real contract violation, not just the final rejection symptom. `actionability` means the output suggests a repair direction consistent with the known fix.
- `information density` is `log_lines / diagnostic_lines`. This naturally favors PV because the PV baseline is a single line, so it should be read as a compression scalar, not a usefulness score.

## 30-Case Table

| Case | Class | Log lines | PV locs | OBLIGE locs | PV root | OBLIGE root | PV action | OBLIGE action | PV density | OBLIGE density |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | `source_bug` | 18 | 1 | 1 | Y | N | Y | N | 18.0x | 2.2x |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | 27 | 1 | 1 | Y | Y | N | Y | 27.0x | 1.6x |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | 38 | 1 | 1 | Y | N | Y | N | 38.0x | 2.9x |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | 44 | 1 | 3 | Y | N | Y | N | 44.0x | 2.8x |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | 46 | 1 | 1 | Y | Y | Y | Y | 46.0x | 5.1x |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | 102 | 1 | 1 | Y | N | N | N | 102.0x | 11.3x |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | 41 | 1 | 1 | Y | N | Y | N | 41.0x | 5.1x |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | 24 | 1 | 1 | Y | N | Y | N | 24.0x | 2.7x |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `source_bug` | 16 | 1 | 1 | Y | N | N | N | 16.0x | 1.8x |
| `stackoverflow-69767533` | `source_bug` | 42 | 1 | 2 | Y | Y | N | Y | 42.0x | 3.5x |
| `stackoverflow-61945212` | `source_bug` | 13 | 1 | 1 | Y | Y | N | Y | 13.0x | 1.6x |
| `stackoverflow-77205912` | `source_bug` | 61 | 1 | 2 | N | N | N | N | 61.0x | 3.6x |
| `stackoverflow-70091221` | `source_bug` | 3 | 1 | 1 | Y | Y | Y | Y | 3.0x | 0.4x |
| `github-aya-rs-aya-1062` | `lowering_artifact` | 36 | 1 | 3 | Y | Y | Y | N | 36.0x | 2.1x |
| `stackoverflow-79530762` | `lowering_artifact` | 82 | 1 | 1 | N | Y | N | N | 82.0x | 4.8x |
| `stackoverflow-73088287` | `lowering_artifact` | 10 | 1 | 1 | N | N | N | N | 10.0x | 1.2x |
| `stackoverflow-74178703` | `lowering_artifact` | 23 | 1 | 1 | N | N | N | N | 23.0x | 2.6x |
| `stackoverflow-76160985` | `lowering_artifact` | 36 | 1 | 1 | N | N | N | N | 36.0x | 4.0x |
| `stackoverflow-70750259` | `lowering_artifact` | 22 | 1 | 2 | N | Y | N | Y | 22.0x | 1.3x |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | 513 | 1 | 2 | Y | Y | Y | Y | 513.0x | 32.1x |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | 408 | 1 | 2 | Y | Y | Y | Y | 408.0x | 24.0x |
| `stackoverflow-56872436` | `verifier_limit` | 6 | 1 | 1 | Y | Y | Y | Y | 6.0x | 0.9x |
| `stackoverflow-78753911` | `verifier_limit` | 2 | 1 | 1 | Y | Y | Y | Y | 2.0x | 0.3x |
| `github-cilium-cilium-41412` | `verifier_limit` | 25 | 1 | 1 | N | Y | N | Y | 25.0x | 2.8x |
| `github-cilium-cilium-35182` | `env_mismatch` | 5 | 1 | 1 | Y | Y | Y | Y | 5.0x | 0.7x |
| `github-aya-rs-aya-1233` | `env_mismatch` | 21 | 1 | 2 | Y | N | Y | N | 21.0x | 1.2x |
| `github-aya-rs-aya-864` | `env_mismatch` | 12 | 1 | 1 | Y | N | N | N | 12.0x | 1.5x |
| `stackoverflow-76441958` | `env_mismatch` | 25 | 1 | 1 | N | N | N | N | 25.0x | 1.5x |
| `github-cilium-cilium-44216` | `verifier_bug` | 45 | 1 | 1 | N | N | N | N | 45.0x | 7.5x |
| `github-cilium-cilium-41996` | `verifier_bug` | 2 | 1 | 1 | N | N | N | N | 2.0x | 0.3x |

## Summary Statistics

| Metric | PV | OBLIGE |
| --- | --- | --- |
| Mean source locations | 1.00 | 1.33 |
| Cases with >1 source location | 0/30 | 8/30 |
| Root cause identified | 20/30 | 14/30 |
| Actionable fix direction | 14/30 | 12/30 |
| Mean compression ratio (log lines / diagnostic lines) | 58.3x | 4.4x |
| Median compression ratio | 25.0x | 2.4x |

Per-class breakdown:

| Class | Cases | PV root | OBLIGE root | PV action | OBLIGE action |
| --- | --- | --- | --- | --- | --- |
| `source_bug` | 13 | 12/13 | 5/13 | 7/13 | 5/13 |
| `lowering_artifact` | 6 | 1/6 | 3/6 | 1/6 | 1/6 |
| `verifier_limit` | 5 | 4/5 | 5/5 | 4/5 | 5/5 |
| `env_mismatch` | 4 | 3/4 | 1/4 | 2/4 | 1/4 |
| `verifier_bug` | 2 | 0/2 | 0/2 | 0/2 | 0/2 |

- Root-cause comparison by case: OBLIGE better on `3` cases, worse on `9`, tied on `18`.
- Actionability comparison by case: OBLIGE better on `5` cases, worse on `7`, tied on `18`.

## Key Examples Where OBLIGE Excels

- `stackoverflow-70750259` is still the cleanest lowering-artifact win. PV only surfaces `math between pkt pointer and register with unbounded min value is not allowed`. Current OBLIGE gives two source-correlated locations: the `ext_len` construction where the proof is lost, and the later packet-access rejection. The help text (`Add an explicit unsigned clamp and keep the offset calculation in a separate verified register`) matches the known fix direction.
- `stackoverflow-79530762` shows why multi-span proof tracking matters even when the final repair hint is imperfect. PV stops at `R4 offset is outside of the packet`. OBLIGE at least marks an earlier proof-loss transition before the packet write, which is closer to the real issue: the verifier lost equivalence between the checked pointer and the dereferenced pointer after lowering.
- `github-aya-rs-aya-1062` still demonstrates a real proof-story advantage. PV reports the signed-range symptom (`R2 min value is negative...`). OBLIGE shows an establish/loss/reject chain across three locations before `bpf_probe_read_user`, which is more informative for debugging the lowered bytecode. The caveat is that the current integrated help text regresses to a generic verifier-limit repair instead of the older signed-range-specific advice.
- On verifier-limit cases, OBLIGE now edges PV slightly: `5/5` root-cause and `5/5` actionability versus PV’s `4/5` and `4/5`. The biggest delta is `github-cilium-cilium-41412`, where PV collapses to `Error: failed to load object file`, while OBLIGE still classifies it as a verifier-limit case and suggests simplifying the program / call structure.

## Where PV Is Sufficient

- Simple contract violations remain PV’s best territory. `stackoverflow-61945212` (`R2 type=inv expected=fp`), `stackoverflow-70091221` (`R1 type=map_value expected=map_ptr`), and `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` (`Possibly NULL pointer passed to helper arg2`) are all cases where the final verifier line already names the missing proof or contract.
- On direct helper/program-type mismatches, the one-line baseline is often enough. `github-aya-rs-aya-1233` (`program of this type cannot use helper bpf_probe_read#4`) is more actionable than the current integrated OBLIGE output, which now drifts into a generic verifier-limit story.
- The same pattern shows up in several selftests: destroying an uninitialized iterator, double-releasing a dynptr, leaking an iterator across exits, or calling a subprogram while holding a lock. In the current pipeline, those cases often regress to generic `env_mismatch` / `Regenerate BTF artifacts...` advice, while the final verifier line is actually closer to the real fix.

## Honest Assessment

- The integrated pipeline clearly improves localization breadth: OBLIGE averages `1.33` source locations per case, reaches `>1` location on `8/30` cases, and is materially better on the lowering-artifact subset (`3/6` root-cause versus PV’s `1/6`).
- The integrated pipeline does **not** dominate PV on this benchmark overall. On the reused 30-case set, PV wins on straightforward source-bug and env-mismatch cases because the current OBLIGE routing frequently falls back to generic `env_mismatch` or `verifier_limit` repairs. The source-bug subset is the clearest regression: PV scores `12/13` on root cause and `7/13` on actionability, while OBLIGE scores `5/13` and `5/13`.
- Information density strongly favors PV by construction (`58.3x` mean compression versus `4.5x` for OBLIGE), but that number mostly reflects output length, not explanation quality. PV is denser because it is only one line.
- The net result is mixed: current OBLIGE is better when the verifier headline is only a symptom, but worse than the old pipeline on a noticeable set of direct-contract failures where the headline was already good enough.

## Conclusion

On the current integrated pipeline, OBLIGE still shows its intended advantage on rich lowering-artifact and verifier-limit logs: it can surface earlier proof-loss locations that a PV-style one-line baseline cannot. The strongest current example remains `stackoverflow-70750259`, and the verifier-limit subset also slightly improves.

But the rerun also exposes a regression that was not visible in the pre-integration comparison: several simple selftest and environment-mismatch cases now collapse into generic `env_mismatch` or `verifier_limit` diagnostics with weak repair text. So the honest takeaway is not “OBLIGE strictly beats PV everywhere.” It is: the current integrated pipeline is better for proof-loss localization, especially on lowering artifacts, but it still needs targeted fixes on direct contract violations before it can claim a clean end-to-end win over a line-only PV baseline.
