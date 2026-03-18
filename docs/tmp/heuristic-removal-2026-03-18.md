# Heuristic Removal Audit

Date: 2026-03-18

## Scope

Goal: remove heuristics from the novelty-critical diagnostic path so `proof_status`, `taxonomy`, `spans`, and `backward_slice` are driven by opcode decoding, predicate monitoring, transition analysis, and slicing rather than regex matching.

## Audit

### `interface/extractor/log_parser.py`

- Critical before: yes, for taxonomy and error interpretation via regex-scored error-line selection and catalog taxonomy assignment.
- Critical after: partially isolated.
- Kept:
  - initial raw-log normalization
  - stable `error_id` lookup
  - raw log excerpt / evidence collection for rendering
- Removed from core path:
  - pipeline no longer takes taxonomy from `parsed_log.taxonomy_class`
  - pipeline proof-status / slice criterion no longer depend on regex-selected reject details
- Remaining caveat:
  - structural cases with no instruction-level engine signal still use `error_id` as a last-resort taxonomy fallback (`verifier_limit` / `env_mismatch` / `verifier_bug`).

### `interface/extractor/reject_info.py`

- Critical before: yes, for proof-status fallback, obligation shaping, and indirectly the slice criterion.
- Critical after: no.
- Kept only for:
  - note/help text
  - raw log excerpt
  - optional obligation refinement for rendering quality
- Removed from core path:
  - no longer used to derive `proof_status`
  - no longer used to derive `taxonomy`
  - no longer used to choose the backward-slice register

### `interface/extractor/trace_parser_parts/_impl.py`

- Critical before: partially.
  - `ERROR_MARKERS`, `_looks_like_error`, and error-line scoring still help detect error text.
  - legacy `_extract_causal_chain()` was also feeding `pipeline.py` via `parsed_trace.causal_chain.error_register`.
- Critical after: reduced.
- Removed from core path:
  - pipeline no longer consults `parsed_trace.causal_chain.error_register`
  - slice criterion is no longer seeded from the legacy causal-chain heuristic
- Kept for compatibility/non-core:
  - legacy causal-chain and critical-transition extraction remain in `ParsedTrace`
  - `_looks_like_error` still supports parser robustness for log ingestion

### `interface/extractor/engine/transition_analyzer.py`

- Critical before: yes.
- Change:
  - removed the “analyze all registers” fallback
  - if `proof_registers` is empty, the analyzer now returns a neutral/empty result with `proof_status="unknown"`
- Effect:
  - no speculative lifecycle story is synthesized from unrelated registers

### `interface/extractor/engine/opcode_safety.py`

- Critical before: yes.
- Change:
  - `infer_conditions_from_error_insn()` now requires `opcode_hex`
  - removed the bytecode-text opcode-class fallback from the critical path
- Effect:
  - safety-condition inference is now driven by the real opcode byte only

### `interface/extractor/engine/cfg_builder.py`

- Critical before: yes, because backward slicing depends on CFG reconstruction.
- Change:
  - `_get_opcode_info()` now requires `opcode_hex`
  - removed bytecode-text opcode inference from CFG construction
- Effect:
  - `backward_slice` now relies on parser-provided opcode bytes, not heuristic text decoding

### `interface/extractor/pipeline.py`

- Critical before: yes.
- Changes:
  - taxonomy is now derived from engine output:
    - instruction-level cases: `source_bug` vs `lowering_artifact` comes from monitor/transition results
    - structural meta-errors fall back only through `error_id` mapping
  - `proof_status` is now derived from engine results only
  - safety predicate inference no longer uses `parsed_trace.causal_chain.error_register` or regex register extraction
  - backward-slice criterion no longer depends on `reject_info` obligations
  - removed dead code:
    - unused `source_code` parameter
    - unused `_df_chain`
    - unused `_transition_chain_to_events`
    - unused imports

## Summary Of Code Changes

- `pipeline.py`
  - taxonomy moved from `log_parser` output to engine-derived classification
  - reject-info removed from the core diagnostic path
  - slice criterion restricted to predicate target regs or syntactic instruction uses/defs
- `transition_analyzer.py`
  - removed analyze-all-registers fallback
- `opcode_safety.py`
  - removed opcode-class inference fallback from the core path
- `cfg_builder.py`
  - removed opcode-text fallback from CFG construction
- Cleanup:
  - removed unused imports/locals in `pipeline.py`, `control_dep.py`, `source_correlator.py`, and `trace_parser_parts/_impl.py`

## Validation

Ran:

```bash
python -m pytest tests/ -x -q
```

Result:

- `372 passed`
- `5 skipped`
- `0 failed`
