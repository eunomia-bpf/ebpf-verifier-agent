# Diagnoser Implementation Report

## What was built

Added `interface/extractor/diagnoser.py` as the single proof-aware diagnosis entry point.

The new `diagnose()` API:

- calls the existing `parse_log()` and `parse_trace()` helpers
- localizes a symptom instruction from the raw verifier log
- infers proof status as `never_established`, `established_then_lost`, or `established_but_insufficient`
- reclassifies packet-access failures when proof loss shows they are lowering artifacts instead of source bugs
- detects verifier-limit and environment-mismatch signatures directly from the raw log
- emits a unified `Diagnosis` dataclass with evidence, confidence, transitions, causal chain, and a recommended fix

## Differential diagnosis logic

Implemented the requested proof-aware split:

- `source_bug`: no critical transitions before the reject site and no earlier proof-establishing signal
- `lowering_artifact`: proof existed and was later lost through `BOUNDS_COLLAPSE`, `TYPE_DOWNGRADE`, `PROVENANCE_LOSS`, or `RANGE_LOSS`
- `verifier_limit`: back-edge / loop-bound failures, state-explosion language, stack-budget failures, or processed-insn budget exhaustion
- `env_mismatch`: helper/kfunc availability, attach-type restrictions, and BTF metadata mismatches

Loss context inference is intentionally compact and currently maps to:

- `arithmetic`
- `function_boundary`
- `branch`
- `loop`
- `register_spill`

## Fix recommendations

Added a lightweight recommendation layer that maps `(taxonomy_class, error_id, loss_context)` to concrete next actions, including:

- packet bounds guards for source bugs
- unsigned clamps / separated offset registers for arithmetic proof loss
- `__always_inline` for function-boundary provenance loss
- tail calls / branch reduction for verifier-limit cases
- kernel feature and BTF alignment checks for environment mismatches

## Tests

Added `tests/test_diagnoser.py` with real case-study logs:

- `stackoverflow-60053570`: source bug packet access
- `stackoverflow-70750259`: lowering artifact with arithmetic proof loss
- `stackoverflow-70841631`: verifier-limit program-too-large case
- differential packet-access check comparing `stackoverflow-60053570` vs `stackoverflow-70729664`

## Verification

Ran:

- `pytest -q tests/test_diagnoser.py`
- `pytest -q tests/test_trace_parser.py`

Both passed.
