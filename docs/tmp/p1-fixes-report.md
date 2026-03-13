# P1 Fixes Report

Date: 2026-03-12

## Scope

This pass fixed the P1 items listed in `docs/tmp/code-review-maintainability.md` across:

- `interface/extractor/proof_engine.py`
- `interface/extractor/diagnoser.py`
- `interface/extractor/trace_parser.py`
- `interface/extractor/proof_analysis.py`
- `interface/extractor/source_correlator.py`
- `interface/extractor/renderer.py`
- `interface/extractor/rust_diagnostic.py`
- packaging / dependency metadata

## Correctness fixes

1. Duplicate instruction visits in `proof_engine`
   - Completed the per-visit `trace_pos` IR path instead of collapsing dynamic states by `insn_idx`.
   - Obligation inference, predicate evaluation, transition finding, backward slicing, and obligation node lookup now track per-visit occurrences.
   - Backward obligation slicing now walks trace order instead of a deduplicated `insn_idx` map.

2. CFG-aware slicing in `proof_engine`
   - Replaced the old reverse linear scan in `_find_reaching_definition()` and `_find_guard_that_changed_atom()` with predecessor-aware traversal over the per-visit predecessor graph.
   - This removes unreachable def/guard selections at joins.

3. Centralized proof-obligation inference in `proof_engine`
   - `infer_obligation()` and `analyze_proof()` now share `_infer_obligation_internal()`.
   - The shared path carries the selected failing visit through `failing_trace_pos`.

4. Textual backtrack register sets
   - Centralized register-mask parsing in `interface/extractor/shared_utils.py`.
   - `decode_regs_mask()` now handles both numeric masks and textual forms such as `r6` / `r1,r2`.
   - `proof_engine` and `proof_analysis` now use the shared decoder.

5. `diagnoser` processed-insn heuristic
   - Large `processed ... insns` counts no longer override a specific reject reason by themselves.
   - The verifier-limit fallback now only fires when the selected error line also looks like a verifier-limit symptom.

6. `trace_parser` fabricated causal chains
   - Removed the unconditional fallback in `_find_previous_definition()` that previously selected the latest write even when state matching failed.

7. Typed verifier pointer recognition
   - Pointer-family detection is centralized in `shared_utils.py`.
   - `trace_parser` now treats `ptr_sock`, `trusted_ptr_*`, `rcu_ptr_*`, and related modern families as pointers.

8. Exact packet-pointer matching in `proof_analysis`
   - Packet-access register selection now uses exact packet-pointer predicates instead of substring matching.
   - `pkt_end` is no longer misclassified as a packet-access obligation register.

9. Per-register source-span preservation
   - `source_correlator.group_by_source_line()` now includes `register` in the merge key.
   - Propagated-span merges in both `source_correlator` and `rust_diagnostic` also preserve per-register separation.

10. Structured source correlation state
   - `SourceSpan` now carries structured `state_before` / `state_after` fields.
   - `renderer` uses those structured fields directly instead of reparsing formatted state strings.
   - ASCII `->` remains accepted as a fallback parse path.

11. `rust_diagnostic` proof-analysis fallbacks
   - Removed stale import compatibility shims.
   - Narrowed proof-engine / proof-analysis exception handling to expected domain failures.
   - Fallback reasons are now recorded under `metadata.proof_analysis.fallback_reasons`.

## Structural fixes

12. `proof_engine.py` split
   - `proof_engine.py` is now a compatibility facade.
   - Responsibility-specific modules are exposed via:
     - `interface/extractor/obligation_inference.py`
     - `interface/extractor/predicate_tracking.py`
     - `interface/extractor/backward_slicing.py`
     - `interface/extractor/ir_builder.py`
   - A compatibility package also exists under `interface/extractor/proof_engine_parts/` for internal grouping.

13. `rust_diagnostic.py` split
   - `rust_diagnostic.py` is now a compatibility facade.
   - Responsibility-specific modules are exposed via:
     - `interface/extractor/pipeline.py`
     - `interface/extractor/reject_info.py`
     - `interface/extractor/obligation_refinement.py`
     - `interface/extractor/spans.py`
   - Internal package boundary lives under `interface/extractor/rust_diagnostic_parts/`.
   - Restored the pre-split public API by re-exporting `DiagnosticOutput` from `rust_diagnostic.py`.
   - Added a top-level `obligation_refinement.py` facade with signature-compatible wrappers so existing callers can keep passing the legacy helper-injection kwargs.

14. `trace_parser.py` split
   - `trace_parser.py` is now a compatibility facade.
   - Responsibility-specific modules are exposed via:
     - `interface/extractor/line_parser.py`
     - `interface/extractor/state_parser.py`
     - `interface/extractor/transitions.py`
     - `interface/extractor/causal_chain.py`
   - Internal package boundary lives under `interface/extractor/trace_parser_parts/`.

15. Shared helper consolidation
   - `_decode_regs_mask()`, register extraction, register normalization, register indexing, and pointer-family helpers are consolidated in `interface/extractor/shared_utils.py`.
   - `diagnoser`, `proof_analysis`, `proof_engine`, and `trace_parser` now consume the shared helpers.

16. Stale import shims
   - Removed the `ImportError` compatibility shims in `rust_diagnostic.py` and `source_correlator.py`.

17. Dead modules
   - Checked for live importers of `obligation` / `btf_mapper`: none were found in the repo.
   - The code now lives only under `interface/extractor/legacy/`.
   - The old top-level files remain deleted.

18. Canonical dependency declaration
   - `pyproject.toml` remains the canonical dependency source.
   - `requirements.txt` now delegates to the project metadata via `-e .[dev]` and is explicitly marked as a convenience entry point.

## Regression tests added or updated

- `tests/test_diagnoser.py`
  - processed-insn counts no longer override a specific packet-access reject reason.
- `tests/test_proof_engine.py`
  - textual backtrack register masks now produce backtrack slice edges.
- `tests/test_proof_analysis.py`
  - packet-access inference skips `pkt_end` and selects a real packet pointer.
- `tests/test_renderer.py`
  - structured `SourceSpan.state_before` / `state_after` values drive rendered abstract state without reparsing `state_change`.
  - specific helper/kfunc contract wording still preserves raw verifier type tokens and dynptr-specific repair guidance after the module split.
- `tests/test_source_correlator.py`
  - distinct registers on the same source line are preserved as distinct spans.
- `tests/test_trace_parser.py`
  - typed verifier pointers are recognized as pointers.
- Existing `proof_engine` coverage now exercises the occurrence-aware path without regressions.

## Verification

- Final integrated verification:
  - `python -m pytest tests/ -x -q` -> `118 passed`
