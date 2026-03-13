# Backward Obligation Slice Report

Date: 2026-03-12

## Summary

Implemented backward obligation slicing and composite obligation tracking in `interface/extractor/proof_engine.py`.

Key additions:

- `backward_obligation_slice(parsed_trace, transition_witness_idx, obligation)`
  - walks backward from the transition witness
  - tracks predicate registers plus transitive source registers
  - incorporates `mark_precise` backtracking hints from verifier traces
  - returns an instruction-level causal chain as `(insn_idx, reason)` pairs
- `CompositeObligation`
  - supports multiple sub-obligations tracked independently
- `track_composite(parsed_trace, composite)`
  - analyzes each sub-obligation with the same formal evaluator
  - reports the first failed sub-obligation and failure site
- `ProofAnalysisResult.causal_chain`
  - populated for `established_then_lost` results alongside existing `slice_edges`

## Regression Coverage

Added proof-engine tests for:

- real-case backward slice coverage on `stackoverflow-70750259`
- inclusion of `mark_precise` backtrack targets in the causal chain
- propagation of the causal chain through `analyze_proof()`
- composite obligation tracking with two sub-obligations

## Verification

Command:

```bash
python -m pytest tests/ -x
```

Result:

- `104 passed in 2.86s`
