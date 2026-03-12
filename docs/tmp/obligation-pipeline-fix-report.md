# Obligation Pipeline Fix Report

## Summary

- Problem: obligation inference was materially better than rendered output coverage.
- Before fix: `metadata.obligation` rendered in `270/412` cases (`65.5%`).
- After fix: `metadata.obligation` renders in `397/412` cases (`96.4%`).
- Result: the pipeline gap is closed; remaining misses are upstream inference misses, not adapter/renderer drops.

## Root Causes

### 1. `_try_proof_engine()` only trusted `analyze_proof()`

`interface/extractor/proof_engine.py::analyze_proof()` only returns `result.obligation` when the formal proof analysis can recover a formalized obligation at the failing instruction. Its sibling `proof_engine.infer_obligation()` has broader fallback coverage (`392/412` cases), but `rust_diagnostic.py` was not using that broader path when `analyze_proof()` returned `obligation=None`.

Measured impact before the fix:

- `proof_engine.infer_obligation()` inferred obligations in `392/412` cases.
- `_try_proof_engine()` only propagated an obligation in `353/412` cases.
- `39` cases were lost here.

### 2. `_analyze_proof()` discarded valid engine obligations when proof status was ignored

`_should_ignore_engine_result()` intentionally ignores engine results with:

- `proof_status == "unknown"`
- only a synthesized `rejected` event
- a stronger diagnosis proof status already available

That behavior is valid for proof status/event selection, but the code also dropped the engine obligation at the same time. This created a second loss mode where the pipeline kept the diagnosis proof status but lost a still-valid obligation.

Measured impact before the fix:

- `97` cases had an engine obligation that was dropped after `_should_ignore_engine_result()`.

### 3. Specific helper contract refinement missed generic engine helper obligations

After preserving more engine obligations, helper-argument cases could carry a generic engine obligation like `R1.type matches ptr`. `_refine_obligation_with_specific_reject()` was too narrow and failed to replace that generic obligation with the more specific verifier contract text in some cases.

## Code Changes

### `interface/extractor/rust_diagnostic.py`

- Imported `proof_engine.infer_obligation()` as an explicit engine-side fallback.
- Added `_infer_obligation_from_engine(...)` to recover a `ProofObligation` directly from the proof engine’s higher-coverage inference path.
- Added `_engine_obligation_spec_to_proof_obligation(...)` so both analyzed and directly inferred engine obligations use the same conversion path.
- Updated `_try_proof_engine()` to:
  - keep using `analyze_proof()` for proof status/events
  - fall back to direct engine obligation inference when `result.obligation` is missing
  - only return `None` when both obligation inference and proof status are unavailable
- Updated `_analyze_proof()` to preserve `engine_result.obligation` even when `_should_ignore_engine_result()` rejects the engine proof status/events.
- Updated `generate_diagnostic()` to use engine obligation inference before falling back to the older catalog-based `_infer_obligation(...)`.
- Tightened `_refine_obligation_with_specific_reject()` so concrete helper contract text overrides generic engine `helper_arg` obligations.

### `tests/test_renderer.py`

Added regressions for both pipeline-gap modes:

- engine obligation preserved when `analyze_proof()` returns no formal obligation
- engine obligation preserved when an `unknown` engine proof status is ignored

## Verification

### Requested test suite

Command:

```bash
python -m pytest tests/ -x
```

Result:

```text
101 passed in 2.86s
```

### Requested case-study sweep

Command:

```bash
python3 -c "
import glob, yaml
from interface.extractor.rust_diagnostic import generate_diagnostic

rendered_yes = rendered_no = 0
for f in sorted(glob.glob('case_study/cases/**/*.yaml', recursive=True)):
    with open(f) as fh:
        case = yaml.safe_load(fh)
    vlog = case.get('verifier_log', '')
    if isinstance(vlog, dict): vlog = vlog.get('combined', '')
    if not vlog or len(vlog) < 50: continue
    try:
        result = generate_diagnostic(vlog)
        metadata = result.json_data.get('metadata', {}) if isinstance(result.json_data.get('metadata'), dict) else {}
        if metadata.get('obligation') is not None and metadata.get('obligation') != {}:
            rendered_yes += 1
        else:
            rendered_no += 1
    except:
        rendered_no += 1
total = rendered_yes + rendered_no
print(f'Rendered obligation: {rendered_yes}/{total} ({100*rendered_yes/total:.1f}%)')
"
```

Result:

```text
Rendered obligation: 397/412 (96.4%)
```

## Residual Gap

- Remaining missing obligations: `15/412`
- These are not pipeline drops after this fix.
- They are cases where the available inference paths still do not recover an obligation from the verifier log/trace.
