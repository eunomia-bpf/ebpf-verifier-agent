# Proof Engine Review Round 3

## What Changed

1. Execution-order-aware proof timeline
   - Added `point_order` derived from the raw parsed trace so proof points are ordered by last observed execution order, not just numeric instruction index.
   - This fixes looped/repeated-instruction cases where the relevant guard appears at a higher instruction number than the final failing access.
   - `stackoverflow-74178703` now moves from a false source-bug style outcome to `map_value_access / established_then_lost`.

2. Missing call post-state no longer fabricates loss
   - The transition search now only ignores the failing instruction's post-state for call sites that do not actually have post-state data.
   - This preserves real fail-site losses like `stackoverflow-79530762` while eliminating the synthetic helper-call loss in the dynptr subprog case.
   - `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` now returns `helper_arg / never_established`.

3. Helper expected-type parsing is less permissive
   - Added textual expectation inference for helper errors such as `pointer to stack` / `dynptr`.
   - This prevents broad fallback expectations like `ctx` from incorrectly marking bad helper arguments as already established.

4. Subprogram-only memory failures now degrade to `unknown`
   - `ParsedTrace` now records validated function IDs and caller-transfer markers.
   - When a `memory_access` failure happens in a callee-only trace with no caller-side proof context visible, the engine returns `unknown` with a reason instead of fabricating `never_established` or `established_then_lost`.
   - `stackoverflow-76160985` now returns `memory_access / unknown` with reason `callee-only memory-access trace does not show caller-side proof context`.

## New Regression Coverage

Added 8 new real-case regression tests in `tests/test_proof_engine.py`:

### Requested fix cases

| Case | Expected output | Notes |
| --- | --- | --- |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `helper_arg`, `never_established`, reject `0` | Missing call post-state no longer becomes a synthetic loss |
| `stackoverflow-74178703` | `map_value_access`, `established_then_lost`, reject `195` | Hoisted scalar/index proof is now tracked across the looped trace order |
| `stackoverflow-76160985` | `memory_access`, `unknown`, reject `195` | Callee-only subprog trace now reports missing caller context instead of a fabricated proof verdict |

### 5 additional untested cases

| Case | Expected output | Notes |
| --- | --- | --- |
| `github-aya-rs-aya-458` | `null_check`, `never_established`, reject `293` | Real nullable-map-value dereference |
| `github-cilium-cilium-41522` | `packet_access`, `never_established`, reject `945` | Large real packet-range miss |
| `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84` | `memory_access`, `never_established`, reject `28` | Real dynptr map-value slice OOB |
| `kernel-selftest-dynptr-fail-dynptr-partial-slot-invalidate-tc-8f5ee7c7` | `stack_access`, `established_then_lost`, reject `25` | Real stack proof loss with no explicit `error_line` |
| `kernel-selftest-dynptr-fail-dynptr-slice-var-len2-tc-673ab9e7` | `map_value_access`, `never_established`, reject `10` | Real map-value width/range miss with inferred obligation |

Real-case regression coverage is now 25 cases.

## Batch Evaluation

Runner: `eval/batch_proof_engine_eval.py`  
Results JSON: `eval/results/batch_proof_engine_round3.json`

Scope:
- Reused `iter_case_files()` and `extract_verifier_log()` from `eval/batch_diagnostic_eval.py`
- Filtered to logs with at least 50 characters, matching the existing batch-eval convention
- Evaluated **241** cases with verifier logs

### Proof-engine summary

- Cases evaluated: **241**
- `obligation != None`: **102**
- Proof errors/crashes: **0**
- `proof_status` distribution:
  - `unknown`: **140**
  - `never_established`: **42**
  - `established_but_insufficient`: **35**
  - `established_then_lost`: **24**

### Comparison vs old diagnoser `proof_status`

- Diagnoser distribution:
  - `never_established`: **114**
  - `established_then_lost`: **97**
  - `unknown`: **22**
  - `established_but_insufficient`: **8**
- Exact status matches: **63 / 241**
- Mismatches: **178 / 241**

Largest mismatch buckets:

| Proof engine | Old diagnoser | Count | Main pattern |
| --- | --- | --- | --- |
| `unknown` | `never_established` | `61` | engine has no inferred obligation / intentionally defers |
| `unknown` | `established_then_lost` | `53` | diagnoser still over-reads trace structure where engine has no modeled obligation |
| `established_but_insufficient` | `never_established` | `22` | engine sees some establishment, but no defensible loss witness |
| `never_established` | `established_then_lost` | `14` | diagnoser remains more eager to claim proof loss |
| `established_but_insufficient` | `established_then_lost` | `13` | mostly helper/dynptr-style call cases |

Interpretation:

- The round-3 engine is more conservative than the old diagnoser.
- The main reason for disagreement is still obligation coverage: many diagnoser `established_then_lost` calls fall back to engine `unknown` because the engine refuses to classify without a modeled obligation.
- The new subprog rule intentionally increases `unknown` counts for callee-only `memory_access` traces.

## Remaining Gaps

1. Obligation coverage is still the dominant limiter.
   - 139 of 241 cases still land in `obligation=None` and therefore `unknown`.
   - Many dynptr/selftest cases remain outside the currently modeled families.

2. Helper-call classification is still conservative.
   - Several helper-arg cases now land in `established_but_insufficient` instead of the diagnoser's `established_then_lost`.
   - This is preferable to fabricating a loss, but it leaves useful signal on the table.

3. `stackoverflow-74178703` is improved but not yet ideal.
   - The engine now returns `established_then_lost`, which is the important classification fix.
   - The current loss site is the recomputed pointer path (`193`) rather than the ideal scalar guard site (`204`).

## Validation

- Mid-round full suite: `python -m pytest tests/ -v` → **73 passed**
- Final full suite after report updates should be rerun before close-out
