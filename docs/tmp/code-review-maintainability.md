# OBLIGE Maintainability Review

Date: 2026-03-12

## Scope and method

- Read the active extractor stack in `interface/extractor/`, including `proof_engine.py`, `trace_parser.py`, `rust_diagnostic.py`, `diagnoser.py`, `source_correlator.py`, `renderer.py`, `log_parser.py`, `proof_analysis.py`, `obligation.py`, `btf_mapper.py`, and `bpftool_parser.py`.
- Reviewed packaging, docs, tests, entry points, and import surfaces.
- Ran `python -m pytest tests/ -x -q` after fixes.
- Verified packaging in a throwaway virtualenv with `pip install -e .` and `python -m oblige --help`.

## Executive summary

- The core extractor pipeline is functional and well-covered by tests, but the package boundary was inconsistent with the actual implementation. The old public API emitted schema-invalid data, the repository was not installable with `pip`, there was no clean CLI, and the README described an older scaffold instead of the current layout.
- Those are the only issues I classified as `P0` for this review pass, and they are fixed now.
- The remaining risks are mostly `P1` heuristic/correctness problems in `proof_engine.py`, `trace_parser.py`, `diagnoser.py`, `proof_analysis.py`, `source_correlator.py`, and `renderer.py`, plus `P2` module-boundary and cleanup work.

## Fixes applied in this pass

- `P0 fixed`: `interface/api/__init__.py:22` now delegates to the real `generate_diagnostic()` pipeline instead of emitting the stale scaffold payload. `build_diagnostic()` now returns a schema-valid record and preserves `case_id`, `kernel_release`, and a caller-supplied fallback `source_path`.
- `P0 fixed`: added `pyproject.toml:1` so the project can be installed with `pip install -e .`.
- `P0 fixed`: added a clean entry point in `oblige/cli.py:16` and `oblige/__main__.py:1`, so users can run `python -m oblige` or the installed `oblige` console script.
- `P0 fixed`: added explicit package surfaces in `interface/__init__.py`, `interface/extractor/__init__.py`, `interface/schema/__init__.py`, `taxonomy/__init__.py`, and `oblige/__init__.py`.
- `P0 fixed`: rewrote the README install and usage sections in `README.md:7` to match the real repo structure and current entry points.
- `P0 fixed`: added regression coverage in `tests/test_api.py:29`, `tests/test_cli.py:12`, and `tests/test_smoke.py:15`.

## A. Code quality

### `P1` correctness risks

- `proof_engine.py:282`, `proof_engine.py:1838`, `proof_engine.py:1862`
  Problem: duplicate instruction visits are merged by `insn_idx`, which can fabricate states that never existed on a real path.
  Suggestion: key the IR by trace occurrence, not just instruction index, or separate static instruction metadata from dynamic per-visit states.

- `proof_engine.py:1498`, `proof_engine.py:3213`, `proof_engine.py:3226`
  Problem: CFG metadata is built but the main slicing/lineage logic still relies on linear scans, so joins can select unreachable definitions or guards.
  Suggestion: make slicing predecessor-aware over the CFG, or explicitly downgrade these results to heuristic lineage.

- `proof_engine.py:1169`, `proof_engine.py:1750`
  Problem: `infer_obligation()` and `analyze_proof()` use materially different inference paths, so callers can get inconsistent obligation results from the same trace.
  Suggestion: centralize obligation inference behind one internal function and make both public APIs call it.

- `proof_engine.py:3176`, `proof_engine.py:3274`, `proof_engine.py:3316`
  Problem: textual backtrack register sets such as `regs=r6` are silently dropped because `_decode_regs_mask()` only handles numeric masks.
  Suggestion: parse both numeric masks and textual register lists, ideally once in `trace_parser.py`.

- `diagnoser.py:606`, `diagnoser.py:621`, `diagnoser.py:637`
  Problem: a large processed-insn count can overwrite a more specific reject reason and force `verifier_limit`.
  Suggestion: only use the processed-count heuristic when the selected error line also looks like a verifier-limit symptom, or after more specific classifiers fail.

- `trace_parser.py:713`, `trace_parser.py:728`
  Problem: `_find_previous_definition()` falls back to the latest write to a register even when state matching fails, which can fabricate causal chains.
  Suggestion: remove the unconditional fallback or mark it as explicitly low-confidence and keep it out of root-cause selection.

- `trace_parser.py:71`, `trace_parser.py:850`
  Problem: typed verifier pointers such as `ptr_sock`, `trusted_ptr_*`, and `rcu_ptr_*` are treated as non-pointers, so some downgrade/provenance-loss transitions are missed.
  Suggestion: centralize pointer-family recognition and cover modern BTF/kfunc pointer prefixes.

- `proof_analysis.py:251`, `proof_analysis.py:257`, `proof_analysis.py:296`
  Problem: packet-access inference can select `pkt_end` as the obligation register because substring matching treats it as `pkt`.
  Suggestion: use exact pointer-kind predicates or reuse stricter helpers from `proof_engine.py`.

- `source_correlator.py:121`, `source_correlator.py:128`
  Problem: distinct proof events on the same source line and role collapse together even when they involve different registers.
  Suggestion: include `register` in the merge key, or carry a list of per-register facts inside `SourceSpan`.

- `source_correlator.py:186`, `renderer.py:313`
  Problem: source correlation formats state transitions with `->`, while the renderer parses `→`; this can serialize a whole transition as the register state string.
  Suggestion: stop reparsing formatted strings and carry structured `before` and `after` state through `SourceSpan`.

- `rust_diagnostic.py:270`, `rust_diagnostic.py:402`, `rust_diagnostic.py:422`
  Problem: proof-analysis exceptions are swallowed silently and the pipeline degrades to heuristics without exposing that fallback.
  Suggestion: catch only expected domain failures, and record fallback reasons in diagnostic metadata or logs.

### `P2` maintainability issues

- `proof_engine.py:420`
  Problem: `infer_formal_obligation()` is too large and mixes formal inference, verifier-text heuristics, helper-contract logic, and family-specific rules in one function.
  Suggestion: split into ordered family detectors such as `packet.py`, `helper_contracts.py`, `memory_access.py`, and `verifier_limits.py`.

- `rust_diagnostic.py:166`
  Problem: the top-level flow is readable, but the file also owns span normalization, specific-reject parsing, obligation refinement, compatibility shims, and catalog loading.
  Suggestion: split into `pipeline.py`, `reject_info.py`, `obligation_refinement.py`, and `spans.py`.

- `trace_parser.py:284`
  Problem: the file bundles lexical parsing, state parsing, error-line selection, transition detection, backtrack parsing, and causal-chain inference.
  Suggestion: split into `line_parser.py`, `state_parser.py`, `transitions.py`, and `causal_chain.py`.

- `proof_analysis.py:589`, `diagnoser.py:324`, `proof_engine.py:3316`, `proof_engine.py:3370`
  Problem: `_decode_regs_mask()`, `_extract_registers()`, and `_normalize_register()` are duplicated across modules.
  Suggestion: move these helpers into a shared utility module so fixes land once.

- `rust_diagnostic.py:38`, `rust_diagnostic.py:44`, `source_correlator.py:13`
  Problem: stale `try/except ImportError` compatibility shims hide real import problems and make type expectations ambiguous.
  Suggestion: delete the old-schema fallbacks now that the current dataclasses exist and are tested.

- `interface/extractor/obligation.py` and `interface/extractor/btf_mapper.py`
  Problem: after fixing the public API, these modules no longer appear to have live importers in the repo.
  Suggestion: either remove them or move them to a clearly labeled `legacy/` area to avoid confusing readers about the active pipeline.

## B. Module structure

- `P1`: `proof_engine.py` is 3433 lines, `rust_diagnostic.py` is 1753 lines, `trace_parser.py` is 1165 lines, and `diagnoser.py` is 889 lines. These sizes alone are a signal that boundaries are blurred.
- `P1`: `diagnoser.py` is still live. It is called directly by `rust_diagnostic.py:173` and by evaluation scripts, so it is not dead code.
- `P1`: `interface/extractor/` is the real domain package; `interface/api/` should stay a very thin wrapper; `interface/schema/` is data; `taxonomy/` is data. That split is logical, but `interface/extractor/` contains too many overlapping responsibilities.
- `P2`: there is no active circular-import crash in the tested path, but there is an import tangle around `rust_diagnostic.py`, `proof_engine.py`, `proof_analysis.py`, `source_correlator.py`, and `diagnoser.py`. The shims reduce clarity even when they do not break execution.

## C. Usability

- `P0 fixed`: before this pass, there was no installable package and no top-level CLI.
- `P0 fixed`: `python -m oblige` and the `oblige` console script now work through `oblige/cli.py`.
- `P0 fixed`: the README now shows a real install path, CLI examples, and Python usage.
- `P1`: the project now installs cleanly, but there are two dependency declarations: `requirements.txt` and `pyproject.toml`. These can drift.
  Suggestion: choose `pyproject.toml` as canonical and either generate `requirements.txt` or limit it to contributor convenience.
- `P2`: many tests still inject `ROOT` into `sys.path`.
  Suggestion: once packaging is stable, rely more on installed-package imports and less on ad hoc path mutation.

## D. Documentation structure

- `Good`: `docs/tmp/` is clearly separated from longer-lived docs. That boundary is understandable.
- `P2`: `docs/tmp/` has accumulated many experiment/review reports and at least one backup file, `docs/tmp/research-plan.md.bak`.
  Suggestion: add a small `docs/tmp/README.md` describing retention policy and naming conventions.
- `P2`: `docs/paper/` still contains generated LaTeX build artifacts such as `docs/paper/main.aux`, `docs/paper/main.bbl`, `docs/paper/main.blg`, `docs/paper/main.log`, and `docs/paper/main.out`.
  Suggestion: remove tracked build artifacts and keep only source plus reproducible outputs that are intentionally versioned.

## E. Tests

- `Good`: test names are generally descriptive and organized by module.
- `Good`: after this pass the suite covers extractor internals, renderer output, schema validity, and the new CLI/API surface.
- `P0 fixed`: added missing coverage for the public schema-valid API and the top-level CLI.
- `P2`: renderer tests in `tests/test_renderer.py` are large golden-style assertions over formatted text and metadata, which makes them valuable but somewhat brittle.
  Suggestion: split them into smaller groups for schema shape, proof-span structure, and text rendering so formatting churn does not obscure semantic regressions.

## F. Configuration and packaging

- `P0 fixed`: there is now a `pyproject.toml` with dependencies, package discovery, packaged schema/taxonomy data, and a console script.
- `P0 fixed`: editable install was verified in a throwaway virtualenv.
- `Good`: `.gitignore` already covers Python build artifacts, local caches, and LaTeX temporaries.
- `P2`: tracked LaTeX artifacts under `docs/paper/` mean `.gitignore` is not enough by itself.

## Recommended next steps

1. Tackle the `P1` correctness bugs in `proof_engine.py`, `trace_parser.py`, `diagnoser.py`, `proof_analysis.py`, `source_correlator.py`, and `renderer.py` before doing cosmetic refactors.
2. Split `proof_engine.py`, `rust_diagnostic.py`, and `trace_parser.py` by responsibility so each file has one dominant concern.
3. Delete or quarantine `obligation.py` and `btf_mapper.py` if they are not meant to survive as public legacy modules.
4. Add a small docs index for `docs/tmp/` and remove tracked LaTeX build outputs from `docs/paper/`.
5. Consolidate duplicated parsing helpers shared across diagnoser/proof-analysis/proof-engine.

## Verification

- `python -m pytest tests/ -x -q` -> `110 passed`
- Editable install verified in a temporary virtualenv.
- `python -m oblige --help` works from source and after editable install.
