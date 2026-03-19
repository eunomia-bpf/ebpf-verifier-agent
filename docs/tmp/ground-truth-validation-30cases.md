# Ground Truth Validation: 30 Manually-Labeled Cases

**Date**: 2026-03-13
**Engine**: `generate_diagnostic()` from `interface.extractor.rust_diagnostic`
**Ground truth source**: `docs/tmp/manual-labeling-30cases.md`
**Output field compared**: `failure_class` in `json_data` (rendered by `_normalize_failure_class()`)

---

## Summary

| Metric | Value |
|---|---|
| Cases evaluated | 30/30 (no load errors) |
| **Agreement rate (new engine)** | **12/30 = 40.0%** |
| Agreement rate (heuristic classifier, from labeling doc) | 23/30 = 76.7% |
| Cohen's kappa (new engine) | ~0.17 (poor) |

**The new engine is dramatically worse than the heuristic classifier on taxonomy classification.** The primary failure mode is `_normalize_failure_class()` in the renderer, which overrides taxonomy to `lowering_artifact` whenever the TransitionAnalyzer reports `proof_status == "established_then_lost"` — regardless of what the Diagnoser correctly classified.

---

## Confusion Matrix (30 cases)

Ground truth rows × predicted columns:

| GT \ Predicted | `source_bug` | `lowering_artifact` | `verifier_limit` | `env_mismatch` | `verifier_bug` |
|---|---:|---:|---:|---:|---:|
| `source_bug` (13) | **5** | 7 | 0 | 1 | 0 |
| `lowering_artifact` (6) | 2 | **4** | 0 | 0 | 0 |
| `verifier_limit` (5) | 0 | 3 | **2** | 0 | 0 |
| `env_mismatch` (4) | 0 | 3 | 0 | **1** | 0 |
| `verifier_bug` (2) | 2 | 0 | 0 | 0 | **0** |

Diagonal (correct) = 5 + 4 + 2 + 1 + 0 = **12**

---

## Key Findings

### 1. source_bug misclassified as lowering_artifact: 7/13 (54%)

This is the most damaging failure. Seven cases that are true `source_bug` are predicted as `lowering_artifact` because the TransitionAnalyzer finds a transition sequence that looks like "established_then_lost" and `_normalize_failure_class()` unconditionally maps that to `lowering_artifact`. The Diagnoser (which correctly identifies the taxonomy from error patterns) is bypassed.

All 7 share the same root cause: `proof_status = "established_then_lost"` is detected by the TransitionAnalyzer, but the correct taxonomy is `source_bug` (the error is a real safety violation, not a compiler-lowering artifact).

### 2. GT lowering_artifact correctly predicted: 4/6 (67%)

- **Correct** (4): `github-aya-rs-aya-1062`, `stackoverflow-79530762`, `stackoverflow-76160985`, `stackoverflow-70750259`
- **Missed** (2): `stackoverflow-73088287`, `stackoverflow-74178703` — predicted as `source_bug` because neither the Diagnoser nor the TransitionAnalyzer detects the proof-then-loss pattern; both return `never_established`.

### 3. verifier_limit predicted as lowering_artifact: 3/5 (60%)

Three `verifier_limit` cases (`kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda`, `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d`, `github-cilium-cilium-41412`) are predicted as `lowering_artifact`. In each case the Diagnoser correctly identifies `verifier_limit` but the TransitionAnalyzer produces `established_then_lost` which overrides.

This is a specific bug documented in `pipeline.py` lines 368-382 as `is_verifier_limit` override logic — but it only applies to `ClassificationOnlyPredicate` cases and appears not to trigger correctly for these async-stack-depth selftests.

### 4. env_mismatch predicted as lowering_artifact: 3/4 (75%)

Three of four `env_mismatch` cases are overridden to `lowering_artifact`. For these cases (unavailable helper, architecture mismatch), the verifier log does show some bounded state transitions before the final rejection, which misleads the TransitionAnalyzer into reporting `established_then_lost`.

### 5. verifier_bug always wrong: 0/2 (0%)

Both `verifier_bug` cases (`github-cilium-cilium-44216`, `github-cilium-cilium-41996`) are predicted as `source_bug`. The Diagnoser returns `None` for `raw_taxonomy` on these (unrecognized pattern in the cilium logs), so the renderer defaults to `source_bug`.

---

## All 18 Disagreements

| Case ID (truncated) | GT | Predicted | Diagnoser class | proof_status | Root cause of error |
|---|---|---|---|---|---|
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | `source_bug` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; Diagnoser misclassifies (BPFIX-E021 → env_mismatch) |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; Diagnoser misclassifies dynptr double-release as E021 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; Diagnoser misclassifies lock-held call as E021 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | `lowering_artifact` | `source_bug` | `established_then_lost` | TransitionAnalyzer correctly finds `established_then_lost` but this is a null-check source bug, not lowering |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; Diagnoser misclassifies dynptr offset error as env |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; Diagnoser misclassifies iter leak as E021 |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `source_bug` | `env_mismatch` | `env_mismatch` | `never_established` | Diagnoser misclassifies dynptr reg-type mismatch as env_mismatch (E021) |
| `stackoverflow-69767533` | `source_bug` | `lowering_artifact` | `source_bug` | `established_then_lost` | TransitionAnalyzer incorrectly finds proof-then-loss in stack buffer uninitialized case |
| `stackoverflow-73088287` | `lowering_artifact` | `source_bug` | `source_bug` | `never_established` | Diagnoser correctly would need packet-bounds proof_loss detection; TA returns never_established |
| `stackoverflow-74178703` | `lowering_artifact` | `source_bug` | `source_bug` | `never_established` | Diagnoser returns source_bug; TA misses the loop-lowering proof loss |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `lowering_artifact` | `verifier_limit` | `established_then_lost` | TransitionAnalyzer override; verifier_limit guard in pipeline.py did not trigger |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `lowering_artifact` | `verifier_limit` | `established_then_lost` | Same — verifier_limit override guard not triggered for these cases |
| `github-cilium-cilium-41412` | `verifier_limit` | `lowering_artifact` | `None` | `established_then_lost` | Diagnoser returns None; TransitionAnalyzer override to lowering_artifact |
| `github-aya-rs-aya-1233` | `env_mismatch` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | TransitionAnalyzer override; correct env_mismatch from Diagnoser is discarded |
| `github-aya-rs-aya-864` | `env_mismatch` | `lowering_artifact` | `env_mismatch` | `established_then_lost` | Same — unavailable helper → established_then_lost false positive |
| `stackoverflow-76441958` | `env_mismatch` | `lowering_artifact` | `source_bug` | `established_then_lost` | Diagnoser misclassifies arch alignment as source_bug; TA overrides to lowering_artifact |
| `github-cilium-cilium-44216` | `verifier_bug` | `source_bug` | `None` | `unknown` | Diagnoser fails to match verifier_bug pattern; defaults to source_bug |
| `github-cilium-cilium-41996` | `verifier_bug` | `source_bug` | `None` | `never_established` | Diagnoser fails to match verifier_bug pattern; defaults to source_bug |

---

## Per-class Accuracy

| Class | Correct | Total | Accuracy |
|---|---:|---:|---:|
| `source_bug` | 5 | 13 | 38.5% |
| `lowering_artifact` | 4 | 6 | 66.7% |
| `verifier_limit` | 2 | 5 | 40.0% |
| `env_mismatch` | 1 | 4 | 25.0% |
| `verifier_bug` | 0 | 2 | 0.0% |
| **Overall** | **12** | **30** | **40.0%** |

---

## Root Cause Analysis

### Bug 1: `_normalize_failure_class()` unconditionally overrides to `lowering_artifact`

**File**: `interface/extractor/renderer.py`, lines 210–219

```python
def _normalize_failure_class(taxonomy_class: str, proof_status: str) -> str:
    if proof_status == "established_then_lost":
        return "lowering_artifact"  # ← BUG: overrides even for source_bug/verifier_limit/env_mismatch
    if taxonomy_class in VALID_FAILURE_CLASSES:
        return taxonomy_class
    return "source_bug"
```

This rule was correct for pure lowering artifacts, but the TransitionAnalyzer produces `established_then_lost` for many non-lowering-artifact cases (iterator state errors, stack depth limits, unavailable helpers). The Diagnoser's correct classification is silently overridden.

**Fix needed**: Only override to `lowering_artifact` when the Diagnoser also says `lowering_artifact` (or at most when `proof_status == "established_then_lost"` AND the Diagnoser has no conflicting classification). A `source_bug` or `verifier_limit` Diagnoser result should win over a TransitionAnalyzer `established_then_lost`.

### Bug 2: Diagnoser misclassifies several KS selftest errors as `env_mismatch` (BPFIX-E021)

The Diagnoser assigns `BPFIX-E021` (btf_reference_metadata_missing) to cases that should be `source_bug` because the error string `"reference type('UNKNOWN') size cannot be determined"` appears in logs for multiple different failure modes (not just BTF metadata issues). This affects: `a14b4d3a` (iter destroy), `3722429d` (dynptr double-release), `f038a1b8` (lock-held call), `2cc2b993` (dynptr offset), `65737a09` (iter leak).

### Bug 3: `verifier_limit` guard in pipeline.py not activated for non-ClassificationOnlyPredicate cases

The guard at `pipeline.py:368-382` only overrides to `never_established` for `ClassificationOnlyPredicate`. The async-stack-depth and cilium-41412 cases use a different predicate path, so the guard never fires and `verifier_limit` gets downgraded to `lowering_artifact`.

### Bug 4: `verifier_bug` cases not matched by Diagnoser

The cilium verifier-bug cases produce logs that the Diagnoser cannot match to any known error ID, so `raw_taxonomy` is `None`. The renderer then defaults to `source_bug` (line 219: `return "source_bug"`).

---

## Comparison: New Engine vs Heuristic Classifier

| | Heuristic | New Engine |
|---|---:|---:|
| Overall agreement | **23/30 (76.7%)** | 12/30 (40.0%) |
| `source_bug` accuracy | 13/13 (100%) | 5/13 (38.5%) |
| `lowering_artifact` accuracy | 2/6 (33%) | 4/6 (67%) |
| `verifier_limit` accuracy | 4/5 (80%) | 2/5 (40%) |
| `env_mismatch` accuracy | 3/4 (75%) | 1/4 (25%) |
| `verifier_bug` accuracy | 1/2 (50%) | 0/2 (0%) |

The new engine is better than the heuristic on `lowering_artifact` (67% vs 33%) because the `established_then_lost` proof_status correctly captures some real lowering artifacts — but this improvement comes at the cost of catastrophically misclassifying many other classes.

---

## Recommended Fixes (Priority Order)

1. **Critical**: Fix `_normalize_failure_class()` to use Diagnoser taxonomy when available and not `"unknown"`. The override should only apply when Diagnoser itself returns `"lowering_artifact"` OR when Diagnoser returns `"source_bug"` AND `proof_status == "established_then_lost"` (the overlap case requiring human review). Never override `verifier_limit`, `env_mismatch`, or `verifier_bug` based on proof_status alone.

2. **High**: Fix Diagnoser to not assign BPFIX-E021 to KS selftest cases that use iterators/dynptrs with the `"UNKNOWN"` reference type pattern. These are almost always `source_bug` (iterator misuse, dynptr contract violations).

3. **Medium**: Extend the `is_verifier_limit` guard in `pipeline.py` to also trigger when the Diagnoser's taxonomy_class (from `diagnosis`) is `"verifier_limit"`, not only when using `ClassificationOnlyPredicate`.

4. **Low**: Add `verifier_bug` detection patterns in the Diagnoser for the cilium-style `"verifier bug!"` log strings.
