# Proof Engine Integration Report

## What Changed

`interface/extractor/rust_diagnostic.py` now calls `proof_engine.analyze_proof()` as the first-pass proof analysis in `_analyze_proof()`. The engine is tried before the old `proof_analysis.py` heuristic path.

### Integration logic

1. `_try_proof_engine()` calls `analyze_proof(parsed_trace, error_line, error_insn)`
2. If the engine returns `obligation=None AND proof_status="unknown"` → falls back to old path
3. Otherwise, converts `ProofAnalysisResult` to `_FallbackProofResult`:
   - `establish_site` → `proof_established` event
   - `loss_site` + `TransitionWitness` → `proof_lost` event with atom expression
   - `reject_site` → `rejected` event
   - `ObligationSpec` → `ProofObligation`
4. Old `proof_analysis.py` is still in the codebase but only used as fallback

### Tests

- 73/73 tests pass after integration
- 0 regressions

## Batch Diagnostic Eval: Before vs After

| Metric | Before (v1) | After (v2, proof_engine) | Delta |
|--------|------------|-------------------------|-------|
| Success rate | 241/241 (100%) | 241/241 (100%) | — |
| BTF correlation | 62.7% | 62.7% | — |
| **established_then_lost** | **97** | **72** | **-25** |
| **never_established** | **114** | **108** | **-6** |
| **unknown** | **22** | **21** | **-1** |
| **established_but_insufficient** | **8** | **40** | **+32** |
| Span: established | 45.6% | 46.5% | +0.9pp |
| Span: lost | 40.2% | 30.3% | -9.9pp |
| Span: rejected | 100% | 100% | — |

### Interpretation

The proof engine is **more conservative** than the old diagnoser:
- 32 cases moved from `established_then_lost` → `established_but_insufficient` (engine sees some establishment but no defensible loss witness)
- 25 fewer `established_then_lost` overall
- This is by design: the engine refuses to claim proof loss without a formal transition witness

## A/B Repair Experiment: 30-Case Detailed Comparison

### Engine coverage on A/B cases

- Engine used (obligation found): **16/30**
- Fallback to old path: **11/30**
- Errors: **3/30** (format errors in comparison script, not engine bugs)

### Status changes (6 cases)

| Case | Old status | New status | Obligation | Assessment |
|------|-----------|-----------|-----------|-----------|
| SO-74178703 (lowering_artifact) | never_established | **established_then_lost** | map_value_access | **Correct** — map value proof IS established then lost |
| SO-76160985 (lowering_artifact) | established_but_insufficient | **unknown** | memory_access | **Correct** — subprogram boundary, engine correctly defers |
| SO-79530762 (lowering_artifact) | established_then_lost | **established_but_insufficient** | packet_access | More conservative — this IS a real loss but engine lacks full split model |
| SO-70721661 (source_bug) | established_but_insufficient | **never_established** | packet_access | **Correct** — real source bug with no proof |
| SO-70760516 (source_bug) | established_but_insufficient | **never_established** | packet_access | **Correct** — real source bug with no proof |
| SO-70873332 (source_bug) | established_but_insufficient | **never_established** | packet_access | **Correct** — real source bug with no proof |

### Net quality improvement

- 4/6 status changes are **correctness improvements** (wrong → right)
- 1/6 is a conservative deferral (acceptable)
- 1/6 is overly conservative (SO-79530762: real loss classified as insufficient)

### A/B rescoring

Since the LLM responses were cached from v1, `--rescore-only` produces identical scores:
- A=B 10/30 (33%), lowering_artifact A 0/8 → B 2/8 (+25pp), source_bug A 9/13 → B 6/13 (-23pp)

To measure actual impact of the new engine on repair quality, a **full re-run** with new condition B prompts is needed (requires API key).

## Proof Engine Batch Eval (standalone)

- Cases evaluated: **241**
- Obligation found: **102** (42.3%)
- proof_status: unknown=140, never_established=42, established_but_insufficient=35, established_then_lost=24
- Proof errors/crashes: **0**
- Matches with old diagnoser: 63/241 (26.1%)

## Remaining Gaps

1. **Obligation coverage**: 139/241 still `obligation=None` → engine can't classify
2. **Helper-call conservatism**: Several helper-arg cases now `established_but_insufficient` instead of old `established_then_lost`
3. **A/B re-run needed**: New engine output may help LLM differently, but can't verify without API calls
4. **3 format errors**: Non-critical, caused by comparison script handling of None values
