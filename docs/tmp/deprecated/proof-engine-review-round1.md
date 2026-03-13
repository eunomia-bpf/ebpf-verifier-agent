# Proof Engine Review Round 1

## Scope

Reviewed completely:

- `interface/extractor/proof_engine.py`
- `tests/test_proof_engine.py`
- `docs/tmp/novelty-gap-analysis.md`

Ran `analyze_proof()` on real corpus cases from `case_study/cases/` and converted the cases that now produce defensible results into passing regression tests.

## Code Review Findings

### Fixed in this round

1. Helper-call env mismatches were being mis-modeled as helper-arg proof failures.
   - Before: any failing `call` could fall through to `helper_arg`, even when the error was really “helper unavailable in this program type”.
   - Fix: helper obligations now require an actual arg/type/null clue in the error text before binding to `R1`.
   - Relevant code: `infer_formal_obligation()` at `proof_engine.py:370-400`, `_helper_arg_error_clue()` at `proof_engine.py:999-1001`.
   - Confirmed by `github-aya-rs-aya-1233`, which now returns `obligation=None`, `proof_status="unknown"` instead of a fabricated `helper_arg` loss.

2. Loss-site selection was not following the spec’s “last full predicate satisfied, then first loss” rule.
   - Before: `find_loss_transition()` picked the earliest atom-local `satisfied -> violated/unknown` transition, and `analyze_proof()` also let `establish_site` come from post-reject states.
   - Fix: transition detection now works on the full predicate timeline, restricted to points at or before the reject instruction; `establish_site` is also bounded to the same prefix.
   - Relevant code: `find_loss_transition()` at `proof_engine.py:462-521`, `analyze_proof()` at `proof_engine.py:627-657`.
   - This removes internally inconsistent states like “establish after reject” and makes `loss_site`/`transition` come from one consistent witness.

### Still incorrect or incomplete

1. Formal predicate tracking is real for the supported families, but still not fully semantic across redefinitions.
   - The engine now does obligation inference from opcode/state and evaluates atoms directly on trace states, which is materially closer to the design than the old heuristic lifecycle narration.
   - Remaining gap: tracking is still by register name, not by reaching register version. Reusing `R2`/`R7` for a different value can still look like “proof lost” instead of “new value never proved”.
   - Example: `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` still comes out `established_then_lost`, but semantically this is a source-side missing null proof at the failing call.

2. `infer_formal_obligation()` still has unsupported lowering families and some brittle fallbacks.
   - `packet_access`, `packet_ptr_add`, `map_value_access`, `null_check`, `helper_arg`, and `stack_access` are all implemented.
   - Missing/weak cases remain:
     - pointer-add obligations are only inferred when the failing destination still looks like a packet pointer (`proof_engine.py:335-368`)
     - generic “invalid access to memory” cases are unsupported
     - some multi-register equivalence / subprogram-boundary lowering artifacts still collapse to `unknown` or `never_established`
   - Concrete misses:
     - `stackoverflow-76160985`: `obligation=None`, `proof_status="unknown"` for a manual `lowering_artifact`
     - `stackoverflow-73088287`: `packet_access` inferred, but still `never_established` despite a manual `lowering_artifact`

3. `evaluate_obligation()` still under-models some atoms.
   - `range_at_least` ignores `state.off` and can let negative fixed offsets cancel access size in the arithmetic (`proof_engine.py:271-273`, `proof_engine.py:285-288`, `proof_engine.py:1021-1031`, `proof_engine.py:1068-1079`).
   - `null_check` is only `non_null`; once a register degrades to an incompatible non-null type, the atom still reports `satisfied` (`proof_engine.py:234-251`, `proof_engine.py:1033-1035`).

4. `backward_slice()` is still path-insensitive.
   - `_find_reaching_definition()` walks backward by instruction number only and ignores CFG reachability at joins (`proof_engine.py:524-588`, `proof_engine.py:1163-1173`).
   - `_find_guard_that_changed_atom()` is also a backward scan over all prior branches rather than a path-specific dependence query (`proof_engine.py:1176-1198`).
   - This is acceptable for bounded hints on short traces, but it is not yet a real CFG-aware backward slice.

5. Edge-case handling is mostly safe, but semantic confidence is limited when state is missing.
   - Empty/no-instruction traces: safe, returns `unknown`
   - Missing register state: `_eval_atom()` returns `unknown`
   - Missing error line: safe after the helper-inference fix, but obligation inference may legitimately fall back to `None`
   - Partial traces can still degrade to `unknown` in ways that are implementation-driven rather than semantic

### Performance

- `build_trace_ir()`: linear in trace length
- `evaluate_obligation()`: `O(n * atoms)`; fine for the current small atom sets
- `find_loss_transition()`: now linear in evaluated points plus a sort over timeline keys; still fine
- `backward_slice()`: bounded by depth 10, but each step does backward scans through the trace, so it is still effectively `O(n * slice_steps)`; acceptable today, not ideal for very large traces

## Per-case Test Results

These are the real cases now covered by `tests/test_proof_engine.py` after this round.

| Case | Manual class / subtype | Obligation | Proof status | Loss site | Result |
| --- | --- | --- | --- | --- | --- |
| `stackoverflow-70750259` | `lowering_artifact / signed-range widening` | `packet_ptr_add` | `established_then_lost` | `22` | Correct |
| `stackoverflow-70721661` | `source_bug / bounds` | `packet_access` | `never_established` | `None` | Correct |
| `stackoverflow-79530762` | `lowering_artifact / checked-vs-dereferenced pointer split` | `packet_access` | `established_then_lost` | `36` | Correct; this is also an old-system wrong-answer case |
| `kernel-selftest-iters-iter-err-too-permissive3-raw-tp-969d109d` | `source_bug / null` | `null_check` | `never_established` | `None` | Correct |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug / type` | `helper_arg` | `never_established` | `None` | Correct |
| `github-aya-rs-aya-1233` | `env_mismatch / helper unavailable` | `None` | `unknown` | `None` | Fixed in this round |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit / combined stack budget` | `None` | `unknown` | `None` | Correct |
| `stackoverflow-76441958` | `env_mismatch / ABI-alignment mismatch` | `None` | `unknown` | `None` | Correct |
| `stackoverflow-56872436` | `verifier_limit / loop-proof failure` | `None` | `unknown` | `None` | Correct; also covers empty-trace behavior |

Coverage requirements satisfied by the regression set:

- at least 2 `lowering_artifact`: `70750259`, `79530762`
- at least 2 `source_bug` subtypes: bounds, null, type
- at least 1 `env_mismatch`: `aya-1233`, `76441958`
- at least 1 `verifier_limit`: `async_call_root_check`, `56872436`
- at least 1 old-system wrong answer: `79530762`
- at least 1 rich-backtracking case: `70750259`
- at least 1 BTF-annotated case: multiple selftests and `aya-1233`

## Wrong Results Found During Corpus Runs

These were useful review cases, but I did not convert them into passing regression tests because they still expose unresolved model gaps.

| Case | Current output | Why it is wrong | What should change |
| --- | --- | --- | --- |
| `stackoverflow-73088287` | `packet_access`, `never_established` | Manual label is `lowering_artifact`; the failure is a checked-vs-dereferenced packet-pointer split that the current atom set does not reconstruct | Add register-version-aware pointer-equivalence tracking across the checked register and the dereferenced register |
| `stackoverflow-76160985` | `obligation=None`, `unknown` | Manual label is `lowering_artifact`; current obligation inference has no model for this `invalid access to memory` / subprogram-boundary family | Extend obligation inference beyond packet/map/null/helper/stack to cover generic memory and function-boundary proof transfer |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `null_check`, `established_then_lost` | Semantically this is a missing null proof on the failing value, but the engine treats an earlier unrelated non-null `R2` value as establishment | Make loss detection version-sensitive so earlier values in the same register do not count as proof establishment for the later failing value |

## What Was Fixed

- Stopped fabricating `helper_arg` obligations for helper-environment failures with no arg/type/null clue.
- Made transition detection use one consistent full-predicate witness bounded to the reject site.
- Prevented `establish_site` from being taken from post-reject trace states.
- Added 7 new real-case regression tests, bringing the total real-case coverage in `tests/test_proof_engine.py` to 9 cases.

## What Remains To Fix

- Register-version-aware proof tracking for helper/null cases with register reuse
- CFG-aware backward slicing instead of “nearest earlier def by line number”
- Better range semantics for pointer offsets (`state.off`, negative fixed offsets)
- Additional obligation families for generic memory failures and function-boundary lowering artifacts
- Better handling of multi-register equivalence losses in packet/map lowering cases like `73088287` and `74178703`

## Overall Assessment

This is now defensible as a narrow obligation-driven proof analysis engine, not just heuristic narration, for the obligation families it actually supports.

It now:

- infers obligations from the failing opcode/state for the core supported families
- evaluates machine-checkable atoms directly on trace states
- derives one internal loss witness from the predicate timeline
- slices backward from that witness instead of from unrelated generic transitions

It is still not fully defensible as a general “real proof analysis” implementation across the whole corpus. The main blockers are version-insensitive register tracking, path-insensitive slicing, weak range semantics, and missing obligation families for several important lowering-artifact patterns.
