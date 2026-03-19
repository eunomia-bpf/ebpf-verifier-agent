# Implementation Review 2026-03-18

Reviewed commits:

- `d41e162 eval: corpus manifest + selftest dedup + re-run batch/latency/baseline`
- `b0139a8 feat: implement proof-carrier-aware cross-analysis classification`
- `e191083 Add regex-based baseline diagnostic for evaluation`

## Findings

### 1. High: carrier monitoring is still register-bound, so same-alias proofs are lost when the carrier moves registers

Files:

- `interface/extractor/engine/opcode_safety.py:785-820`
- `interface/extractor/engine/monitor.py:77-97`
- `interface/extractor/engine/monitor.py:249-253`
- `interface/extractor/engine/monitor.py:304-311`

`discover_compatible_carriers()` correctly filters reject-site candidates by normalized `pointer_kind` and `provenance_id`. That part is good.

The problem is what happens after discovery. `CarrierBoundPredicate` binds the analysis to one concrete register (`target_regs -> [self.carrier.register]`) and `compute_gap()` returns `None` as soon as that register is absent or no longer matches the reject-site alias. `monitor_events()` then silently skips the instruction on `gap is None`.

That means cross-analysis is not actually monitoring a carrier equivalence class over time. It is monitoring "this exact reject-site register while it still happens to hold the same alias". If the proof is established on `R3`, then copied into `R5`, and the rejected use is on `R5`, earlier proof on the same `(pointer_kind, id)` is invisible unless `R3` also survives in the reject state and gets discovered there.

I reproduced this with a synthetic trace:

- establish packet bounds on `R3`
- copy `R3 -> R5`
- widen `R5`
- reject on `R5`

`classify_atom()` returns `source_bug`, because only `R5` is monitored and its lifecycle starts after the proof is already in place.

This is a real correctness hole relative to the design doc's "carrier class" story.

### 2. High: counterexample E is not actually fixed at the classifier level

Files:

- `interface/extractor/engine/monitor.py:255-287`
- `interface/extractor/pipeline.py:462-542`
- `tests/test_cross_analysis.py:149-174`

The monitor correctly refuses to count vacuous satisfaction as an establishment. The new test only checks that monitor-level behavior.

But the classifier still mishandles the important vacuous-loss case:

- first observed state already has `gap == 0`
- later instruction widens or otherwise loses the proof
- reject occurs after that loss

`monitor_events()` records a `loss` event even though no `establish` event was ever seen. `classify_atom()` ignores that pattern completely:

- `any_establish` stays false
- no `established_then_lost` path can trigger
- the function falls through to `source_bug`

So the theorem the design review objected to is still false in the implementation. The canonical example is still visible in the saved eval outputs:

- `stackoverflow-70750259`: published taxonomy `lowering_artifact`, proof status `never_established`, `cross_analysis_class = source_bug`

That is exactly the partial-trace/vacuous-establishment problem from the review.

### 3. High: cross-analysis is computed, but it does not drive the published taxonomy

Files:

- `interface/extractor/pipeline.py:112-163`
- `interface/extractor/pipeline.py:195-201`
- `interface/extractor/pipeline.py:319-326`
- `interface/extractor/pipeline.py:692-709`

`generate_diagnostic()` computes `cross_analysis_class` and per-atom metadata, but the final `taxonomy_class` still comes from `_derive_taxonomy_class()`, which ignores all cross-analysis outputs and uses the older rule:

- if `proof_status == established_then_lost` or `monitor_result.loss_site is not None` -> `lowering_artifact`
- else -> `source_bug`

So the integration is operationally clean in the sense that it did not break the existing pipeline, but it is not functionally integrated yet. The new analysis is side-band metadata only.

This matters for the eval discussion:

- the baseline-vs-BPFix taxonomy gap is not caused by cross-analysis producing too many `lowering_artifact` or `ambiguous` outputs
- the published taxonomy never consumes `cross_analysis_class`

I counted `26` eligible cases where saved `metadata.cross_analysis_class` disagrees with the reported taxonomy:

- `11` cases: published `lowering_artifact`, cross-analysis `source_bug`
- `8` cases: published `source_bug`, cross-analysis `ambiguous`
- `7` cases: published `lowering_artifact`, cross-analysis `ambiguous`

That is useful review metadata, but it is not actually steering user-visible behavior yet.

### 4. Medium: `classify_atom()` treats `reject_evaluation == "unknown"` as active evidence and can still emit `source_bug`

Files:

- `interface/extractor/pipeline.py:427-437`
- `interface/extractor/pipeline.py:534-552`

Only `reject_evaluation == "satisfied"` is treated as inactive. `unknown` falls into the normal path and can end as `source_bug` or `ambiguous`, even though the atom has not been shown to fail at the reject site.

This is not just theoretical. In the saved batch results, there are many active atoms with `reject_evaluation = unknown`; among labeled mismatches alone I counted `25` cases where at least one unknown-evaluated atom still participated in a wrong classification.

Representative wrong cases include:

- `github-aya-rs-aya-1056`
- `github-aya-rs-aya-1062`
- `kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb`
- `stackoverflow-74531552`

`unknown` should be treated much more conservatively, likely as an immediate `ambiguous` for that atom.

### 5. Medium: the parser still over-selects the `arg#0 reference type('UNKNOWN ')` preface and that explains several `env_mismatch` false positives

Files:

- `interface/extractor/log_parser.py:180-252`
- `case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84.yaml:52-84`
- `case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9.yaml:27-32`

`_select_error_line()` still picks the early BTF/reference-metadata line in several logs even when a more specific verifier rejection appears immediately after it. Because `_match_catalog()` searches the chosen error line first, this pushes the pipeline into `BPFIX-E021 -> env_mismatch`.

Concrete examples:

- `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`
  - early line: `arg#0 reference type('UNKNOWN ') size cannot be determined: -22`
  - later real reject: `R0 min value is outside of the allowed memory range`
  - BPFix output: `BPFIX-E021 / env_mismatch`
  - regex baseline: `BPFIX-E005 / lowering_artifact`

- `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9`
  - early line: `arg#0 reference type('UNKNOWN ') size cannot be determined: -22`
  - later real reject: `arg#0 expected pointer to stack or const struct bpf_dynptr`
  - BPFix output: `BPFIX-E021 / env_mismatch`
  - regex baseline: `BPFIX-E019 / source_bug`

I counted `13` labeled eligible cases where BPFix wrongly predicts `env_mismatch` and all `13` go through `BPFIX-E021`.

## Cross-analysis assessment

### Carrier discovery

`discover_compatible_carriers()` does correctly filter reject-site candidates by:

- normalized `pointer_kind`
- `provenance_id`

The unit tests for same-provenance / different-provenance / different-type are correct and sufficient for the reject-state filter itself.

The limitation is scope: discovery only sees carriers that are still present in `error_insn.pre_state`. Earlier same-alias carriers that died before reject are invisible, which is why register migration still breaks the intended semantics.

### Counterexamples from `design-review-2026-03-18.md`

My assessment:

- A: handled
  - The `(pointer_kind, provenance_id)` filter prevents unrelated proofs on other registers from being mistaken for the rejected carrier.
- B: mostly handled, but only by conservative dominance gating
  - `classify_atom()` marks non-dominating establish sites as `branch_local_establish -> ambiguous`.
  - This is the right conservative move, but it is not directly tested.
- C: partially handled
  - The new atomized schema inference is a real improvement over the old "pick one violated condition" path.
  - However, `reject_evaluation == unknown` still lets atoms become `source_bug`, so the implementation is not fully conservative on multi-obligation cases.
- D: conservatively handled
  - `slice_contains_back_edge()` forces `ambiguous` for loop-backed slices.
  - This matches the design review's recommendation to avoid confident taxonomy claims in loop-heavy cases.
- E: not handled end-to-end
  - Only the monitor behavior is tested.
  - The classifier and final taxonomy still mis-handle vacuous or partial-trace losses.

### Test coverage

`tests/test_cross_analysis.py` has the advertised 9 tests, but coverage is still thin around the hard cases.

Missing direct tests:

- branch-local establish / merge ambiguity (counterexample B)
- multi-atom mixed outcomes (counterexample C)
- loop-backed slice ambiguity at classifier level (counterexample D)
- vacuous-loss classification, not just vacuous monitor status (counterexample E)
- carrier migration across registers within one alias class
- `reject_evaluation == "unknown"` behavior
- pipeline-level assertion that published taxonomy actually uses, or intentionally does not use, cross-analysis

## Pipeline integration

The integration is clean in the narrow "no regression" sense:

- all existing tests pass
- cross-analysis metadata is attached without breaking the old rendering path

But it is incomplete as product behavior:

- the new classifier does not feed `taxonomy_class`
- the old `_derive_taxonomy_class()` heuristic still dominates outcomes
- metadata can now disagree with the headline classification

So I would call this safe but not finished.

## Regex baseline

### Is it fair?

As a taxonomy-only straw-man: yes.

- It is intentionally shallow.
- It only uses the final verifier-style error message plus catalog regexes and a small fallback taxonomy heuristic.
- It does not use trace structure, proof lifecycle, or source correlation.

That is a reasonable baseline for "how far can you get by parroting the verifier complaint?".

### Too weak or too strong?

It is weak as a diagnosis engine, but strong for the current taxonomy metric because the current label store is heavily surface-derived.

From `docs/tmp/eval-readiness-review-2026-03-18.md`:

- `145` eligible labels come from `msg_pattern`
- `48` from `keyword`
- `17` from `log_msg`
- at least `210 / 262` eligible labels are directly message-derived
- counting `log_pattern`, that rises to `225 / 262`

So the baseline is not "too strong" algorithmically. It is advantaged by the ground truth.

### Does the output schema match BPFix?

Mostly compatible for the batch eval harness, but not identical.

Matches:

- `diagnostic_version`
- `error_id`
- `failure_class`
- `message`
- `source_span`
- `missing_obligation`
- `evidence`
- `candidate_repairs`
- `metadata.proof_status`
- `metadata.proof_spans`

Differences:

- no top-level `taxonomy_class`
- no top-level `spans`
- no `observed_state` / `expected_state`
- the baseline's one pseudo-span lives only in `metadata.proof_spans`

So it is schema-compatible enough for the saved batch command, but not field-for-field identical.

## Eval refresh: why is BPFix below the regex baseline?

Short answer: partly a real problem, partly a label-bias problem.

### What cases does BPFix get wrong that baseline gets right?

On the `255` labeled eligible cases:

- both correct: `169`
- both wrong: `52`
- baseline-only correct: `24`
- BPFix-only correct: `10`

Dominant baseline-only win patterns:

- `10` cases: gold `source_bug`, BPFix `lowering_artifact`, baseline `source_bug`
- `9` cases: gold `lowering_artifact`, BPFix `source_bug`, baseline `lowering_artifact`
- `3` cases: gold `lowering_artifact`, BPFix `env_mismatch`, baseline `lowering_artifact`
- `1` case: gold `verifier_bug`, BPFix `source_bug`, baseline `verifier_bug`
- `1` case: gold `source_bug`, BPFix `env_mismatch`, baseline `source_bug`

So the main issue is still the `source_bug` / `lowering_artifact` boundary, with a secondary `env_mismatch` overcall problem from `BPFIX-E021`.

### Is the gap due to cross-analysis producing more `lowering_artifact` or `ambiguous`?

No, not in the reported taxonomy.

The published taxonomy does not consume `cross_analysis_class`. For the `24` baseline-only wins, the saved `cross_analysis_class` distribution was:

- `source_bug`: `12`
- `ambiguous`: `6`
- `None`: `6`
- `lowering_artifact`: `0`

So the current eval gap is not coming from the new cross-analysis path making the headline taxonomy more conservative. It comes from the older taxonomy path still being authoritative.

### Is the ground truth biased toward the regex baseline?

Yes, strongly, for the full `255`-case taxonomy metric.

The current label store is dominated by message-derived auto-labels, so a message-matching baseline is rewarded by construction.

But it is not only bias:

- manual subset accuracy is still `24/30` for the baseline vs `22/30` for BPFix

So there is a real BPFix taxonomy weakness on the stronger subset too, just smaller than the full `255`-case headline suggests.

### My conclusion on the eval gap

This should not be dismissed as "just bad labels", and it also should not be interpreted as "the regex baseline is a better diagnosis engine".

The evidence says:

1. The full `255`-case taxonomy metric is biased toward surface-message methods.
2. BPFix still has real taxonomy weaknesses on the stronger manual subset.
3. The biggest engineering issues are:
   - old taxonomy path ignoring cross-analysis
   - vacuous-loss / partial-trace handling
   - register-bound carrier monitoring
   - `BPFIX-E021` overcapture from parser error-line selection

## Test run

Command run:

```bash
python -m pytest tests/ -x -q
```

Result:

```text
387 passed, 5 skipped in 22.10s
```

