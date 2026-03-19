# Full Code Review and Status Audit

Generated: `2026-03-12`

Scope reviewed in full:

- `interface/extractor/log_parser.py`
- `interface/extractor/trace_parser.py`
- `interface/extractor/proof_analysis.py`
- `interface/extractor/source_correlator.py`
- `interface/extractor/renderer.py`
- `interface/extractor/rust_diagnostic.py`
- `interface/extractor/diagnoser.py`
- `taxonomy/error_catalog.yaml`
- `taxonomy/obligation_catalog.yaml`
- all files under `tests/`
- project-status docs in `docs/tmp/`

Commands run during this audit:

- `pytest -q` -> `44 passed in 2.09s`
- `python eval/batch_diagnostic_eval.py` -> `241/241` eligible cases succeeded
- `python eval/span_coverage_eval.py` -> report regenerated

Notes on current workspace state:

- The git worktree is dirty. Core extractor files, taxonomy, tests, and several `docs/tmp/*` reports already have local changes.
- I did not rerun `repair_experiment.py`; the report below uses the checked-in `docs/tmp/repair-experiment-report.md`.

## Executive Summary

The diagnostic engine is a seven-stage pipeline:

1. raw-log headline extraction and catalog seeding
2. verbose-trace parsing into instruction/state structures
3. diagnosis/classification
4. proof-obligation and proof-lifecycle analysis
5. source correlation
6. span normalization/synthesis/pruning
7. text + JSON rendering

The design is workable and the current workspace is stable enough to run: all 44 tests pass, batch evaluation completes with zero crashes, and the Round 2 fixes materially improved headline quality (`taxonomy_class=unknown` down to `2`, false `proof_status=satisfied` down to `0`).

The main architectural weaknesses are now different from the earlier parser/catalog bugs:

- the hot path reparses the same log twice and reloads catalogs repeatedly
- the final JSON contract is not the repository schema
- proof obligations are only fully surfaced for `8/23` catalog templates
- the diagnoser aggressively overrides catalog-seeded source-bug IDs to lowering-artifact IDs
- zero-trace / artifact-poor cases still dominate the weak-output bucket

Current batch-eval snapshot from `docs/tmp/batch-diagnostic-eval.md`:

- Eligible cases: `241`
- Successes: `241`
- `taxonomy_class=unknown`: `2`
- `proof_status=unknown`: `20`
- one-span outputs: `125`
- overall BTF/file-line correlation: `151/241 (62.7%)`
- Stack Overflow BTF correlation: `1/65 (1.5%)`

## Architecture Diagram

```text
                                  +---------------------------+
                                  | taxonomy/error_catalog    |
                                  +-------------+-------------+
                                                |
raw verifier log                                v
-------------------> log_parser.parse_log() -> ParsedLog
                         |                      error_line
                         |                      error_id
                         |                      taxonomy_class
                         |                      evidence
                         |
                         +------------------------------------------+
                                                                    |
raw verifier log                                                    |
-------------------> trace_parser.parse_trace() -> ParsedTrace      |
                         |                      instructions         |
                         |                      transitions          |
                         |                      causal_chain         |
                         |                      backtrack_chains     |
                         |                      error_line           |
                         |                                          |
                         +--------------------------+---------------+
                                                    |
raw verifier log                                    v
-------------------> diagnoser.diagnose() -> Diagnosis
                         |                    symptom_insn
                         |                    root_cause_insn
                         |                    proof_status
                         |                    loss_context
                         |                    recommended_fix
                         |
                         |  NOTE: diagnose() reparses the same raw log
                         |        with parse_log() + parse_trace()
                         v
               rust_diagnostic._analyze_proof()
                         |
                         |-- proof_analysis.infer_obligation()
                         |-- proof_analysis.analyze_proof_lifecycle()
                         |   or synthetic fallback events
                         v
                    ProofEvent[] + ProofObligation?
                         |
                         v
               source_correlator.correlate_to_source()
                         |
                         v
                      SourceSpan[]
                         |
                         v
            rust_diagnostic._normalize_spans()
              - dedupe
              - synthesize missing roles
              - prune to <= 5 spans
                         |
                         v
                renderer.render_diagnostic()
                         |
                         +--> text output
                         +--> JSON output

Side path not used by generate_diagnostic():
interface/api.build_diagnostic() -> BTFMapper + ObligationExtractor + schema-ish record
```

Important architectural fact: the main engine does not use `interface/extractor/btf_mapper.py`; source correlation is string-based parsing of verifier `@ file:line` annotations, not ELF/BTF lookup.

## Per-Module Analysis

### 1. `interface/extractor/log_parser.py`

- What it does: first-pass raw-log normalization. It selects a likely verifier headline, matches it against the error catalog, extracts a coarse source line number, and captures a small evidence set.
- LOC: `236`
- Key classes/functions:
  - `ParsedLog(...)`
  - `VerifierLogParser.__init__(catalog_path: Path | None = None) -> None`
  - `VerifierLogParser.parse(raw_log: str) -> ParsedLog`
  - `VerifierLogParser._select_error_line(lines: list[str]) -> str`
  - `VerifierLogParser._match_catalog(lines: list[str]) -> tuple[str | None, str | None]`
  - `parse_log(raw_log: str, catalog_path: str | Path | None = None) -> ParsedLog`
- Pipeline connection: this is the first stage in `generate_diagnostic()`. `diagnose()` also calls it again internally, so the hot path runs it twice.
- Code quality issues:
  - Catalog matching is first-match wins, so YAML ordering is part of semantics. Overlapping patterns in `error_catalog.yaml` can shadow later IDs. The clearest overlap is `E007`/`E018` around state/complexity limits and `E008`/`E018` around loop failures.
  - Error-line scoring logic is duplicated elsewhere in `trace_parser.py` and then arbitrated again in `diagnoser.py`, which creates three different headline-selection heuristics for one concept.
  - `ParsedLog.source_line` is effectively unused by the main diagnostic engine; it only feeds the older `interface/api` path.
- Performance concerns:
  - The error catalog YAML is loaded on parser construction. Because `generate_diagnostic()` and `diagnose()` each instantiate parsing independently, the catalog is read twice per request.
  - `_match_catalog()` scans the whole joined log with each regex pattern on every parse. At 23 IDs this is fine; it becomes more expensive as the catalog grows.

### 2. `interface/extractor/trace_parser.py`

- What it does: parses verbose verifier traces into instruction-level structures with register states, backtracking chains, causal chains, critical transitions, and a trace-local error line.
- LOC: `1135`
- Key classes/functions:
  - `RegisterState`, `TracedInstruction`, `CriticalTransition`, `BacktrackChain`, `CausalChain`, `ParsedTrace`
  - `parse_line(line: str) -> TraceLine`
  - `parse_trace(log_text: str) -> ParsedTrace`
  - `extract_backtrack_chains(log_text: str) -> list[BacktrackChain]`
  - `_aggregate_instructions(raw_lines: list[str]) -> list[TracedInstruction]`
  - `_detect_critical_transitions(instructions: list[TracedInstruction]) -> list[CriticalTransition]`
  - `_extract_causal_chain(instructions: list[TracedInstruction]) -> CausalChain | None`
- Pipeline connection: this is the structural backbone for `diagnoser.py`, `proof_analysis.py`, `source_correlator.py`, and `rust_diagnostic.py`.
- Code quality issues:
  - `_aggregate_instructions()` can smear future state into the current instruction’s `post_state` when it sees an explicitly indexed state line for a later instruction (`current.insn_idx < target_idx`). That heuristic is useful for sparse traces but can create false transitions on logs with non-local state dumps.
  - `_states_related()` only compares `type`, `id`, `off`, and `range`. It ignores scalar bounds and `var_off`, so causal-chain tracing can link semantically different scalar states.
  - `has_btf_annotations` is set by any non-empty `instruction.source_line`, but `source_line` can come from plain inline comments, not only true `@ file:line` annotations. The name overstates what is actually available.
  - Trace-local `_select_error_line()` is another independent scorer with different priorities from `log_parser.py`.
  - `_extract_causal_chain()` is depth-limited to 5 edges, which is pragmatic but can truncate long propagation histories.
- Performance concerns:
  - This is a monolithic parser with several full passes over the instruction list.
  - Causal-chain tracing repeatedly scans backward for previous definitions. The depth cap keeps it bounded, but the approach is still quadratic-ish on long traces.

### 3. `interface/extractor/proof_analysis.py`

- What it does: infers a missing proof obligation from the reject site, builds proof events from backtracking and state evolution, and summarizes the proof lifecycle as `never_established`, `established_then_lost`, `established_but_insufficient`, `unknown`, or `satisfied`.
- LOC: `732`
- Key classes/functions:
  - `ProofEvent`, `ProofObligation`, `ProofLifecycle`
  - `infer_obligation(error_line: str, error_register: str, error_instruction: TracedInstruction | None) -> ProofObligation | None`
  - `analyze_proof_lifecycle(parsed_trace: ParsedTrace, obligation: ProofObligation, backtrack_chains: list[BacktrackChain], error_insn: int | None) -> ProofLifecycle`
  - `build_proof_events(parsed_trace: ParsedTrace, obligation: ProofObligation, backtrack_chains: list[BacktrackChain]) -> list[ProofEvent]`
  - `_events_from_backtrack_chain(...)`
  - `_events_from_state_evolution(...)`
- Pipeline connection: `rust_diagnostic.py` uses this when available to avoid relying only on lightweight synthetic events.
- Code quality issues:
  - Obligation inference covers only a small generic subset: `packet_access`, `map_value_access`, `null_check`, `helper_arg`, and `stack_access`. The taxonomy defines 23 obligations, so most obligation fidelity is deferred to `rust_diagnostic.py` and a separate hardcoded mapping.
  - `_state_has_useful_proof()` treats `ctx` and `fp` as proof-bearing pointer types. That is broad enough to produce false “proof established” signals from ordinary context/frame-pointer states.
  - `_select_relevant_chain()` falls back to the last backtrack chain when it cannot match by `error_insn`. On multi-failure or multi-block logs this can bind the wrong chain.
  - The module still carries `satisfied` as a possible lifecycle terminal state even though the input is a verifier failure log; that state is now mostly blocked by Round 2 fixes, but the API surface is still conceptually broader than the actual engine needs.
- Performance concerns:
  - Event building sorts and deduplicates repeatedly and reconstructs transition lookup maps per call.
  - In the main pipeline, proof-analysis work is followed by additional synthetic normalization in `rust_diagnostic.py`, so some event work is duplicated.

### 4. `interface/extractor/source_correlator.py`

- What it does: maps `ProofEvent`s onto source or bytecode spans and attaches compact state-change/reason strings.
- LOC: `467`
- Key classes/functions:
  - `SourceSpan(...)`
  - `correlate_to_source(parsed_trace: ParsedTrace, proof_events: list[ProofEvent]) -> list[SourceSpan]`
  - `group_by_source_line(spans: list[SourceSpan]) -> list[SourceSpan]`
  - `prune_redundant_spans(spans: list[SourceSpan]) -> list[SourceSpan]`
  - `format_state_change(before: RegisterState | None, after: RegisterState | None, register: str) -> str | None`
- Pipeline connection: `rust_diagnostic.py` converts proof events into spans through this module before final normalization and rendering.
- Code quality issues:
  - Despite the “BTF source mapping” role, this module only parses inline `@ file:line` suffixes already present in verifier text. It does not use `BTFMapper`, ELF metadata, or true BTF lookup.
  - Span grouping/pruning is duplicated again in `rust_diagnostic.py`, so ownership of “final span shape” is split across two modules.
  - `_guess_relevant_register()` falls back to the lexicographically first register present in state maps when no explicit register is available, which is weak for multi-register instructions.
  - Compatibility shims for temporary `ProofEvent`/`ProofObligation` imports make the public data model looser than it should be.
- Performance concerns:
  - There are multiple sorts and merge passes over spans. At current output sizes this is negligible, but it duplicates work already done in the caller.

### 5. `interface/extractor/renderer.py`

- What it does: renders the final source spans as Rust-style diagnostic text and a compact JSON structure.
- LOC: `167`
- Key classes/functions:
  - `DiagnosticOutput(text: str, json_data: dict[str, Any])`
  - `render_diagnostic(error_id: str, taxonomy_class: str, proof_status: str, spans: list[SourceSpan], obligation: ProofObligation | None, note: str | None, help_text: str | None) -> DiagnosticOutput`
  - `_headline_summary(...) -> str`
  - `_role_label(span: SourceSpan) -> str`
- Pipeline connection: final stage of `generate_diagnostic()`.
- Code quality issues:
  - The JSON shape emitted here is not the repository schema in `interface/schema/diagnostic.json`.
  - `SourceSpan.insn_range` is lossy in JSON: only `insn_range[0]` is emitted as `insn_idx`, so multi-instruction spans lose their end bound.
  - The text header assumes one file (`_header_label()` takes the first filename). Cross-file or mixed-source outputs will be flattened under a misleading single header.
- Performance concerns:
  - None that matter. Rendering cost is tiny relative to parsing.

### 6. `interface/extractor/rust_diagnostic.py`

- What it does: top-level orchestration for the current extractor path. It parses the log, diagnoses it, optionally runs proof analysis, correlates events to source, normalizes spans, and renders final text/JSON.
- LOC: `911`
- Key classes/functions:
  - `generate_diagnostic(verifier_log: str, catalog_path: str | None = None) -> DiagnosticOutput`
  - `_analyze_proof(parsed_log: ParsedLog, parsed_trace: ParsedTrace, diagnosis: Diagnosis) -> _FallbackProofResult`
  - `_infer_with_proof_analysis(...) -> tuple[ProofObligation, Any] | ProofObligation | None`
  - `_synthesize_proof_events(parsed_trace: ParsedTrace, diagnosis: Diagnosis) -> list[ProofEvent]`
  - `_normalize_spans(...) -> list[SourceSpan]`
  - `_infer_obligation(parsed_log: ParsedLog, diagnosis: Diagnosis) -> ProofObligation | None`
- Pipeline connection: this is the current top-level entry point the rest of the evaluation tooling exercises.
- Code quality issues:
  - `generate_diagnostic()` parses the same raw log twice: once directly (`parse_log`, `parse_trace`) and again indirectly through `diagnose()`.
  - `_infer_with_proof_analysis()` catches `Exception` and silently falls back. That keeps the pipeline from crashing, but it also hides real proof-analysis bugs.
  - `OBLIGATION_DETAILS` hardcodes only `8` obligation templates even though `obligation_catalog.yaml` defines `23`. In the current batch output, `116/241` successful diagnostics still have `obligation = null`.
  - `_build_rejected_event()` and `_build_minimum_rejected_event()` prefer the destination register from bytecode before the explicit error register from the verifier text. For load/store failures, that can attach the wrong state to the reject site.
  - The emitted JSON fails schema validation. On a representative `generate_diagnostic()` output, validation fails because required schema fields are missing and extra fields (`proof_status`, `spans`, `note`, `help`, `taxonomy_class`) are present.
  - The compatibility shim typing is confused: `_build_causal_context_event()` is typed as `BacktrackChain` but actually expects a `CausalChain`-like object with `.chain`.
- Performance concerns:
  - duplicate parse work
  - repeated obligation-catalog loads in `_infer_obligation()` and `_build_help_text()`
  - extra span dedupe/merge/prune passes after `source_correlator.py` already did a similar pass

### 7. `interface/extractor/diagnoser.py`

- What it does: chooses the symptom instruction, relevant transitions, proof status, final classification, root-cause instruction, evidence, recommended fix, and confidence.
- LOC: `803`
- Key classes/functions:
  - `Diagnosis(...)`
  - `diagnose(verifier_log: str, catalog_path: str | None = None) -> Diagnosis`
  - `_select_symptom_insn(...) -> int | None`
  - `_select_relevant_transitions(...) -> list[CriticalTransition]`
  - `_assess_proof(...) -> _ProofAssessment`
  - `_classify(...) -> tuple[str | None, str | None]`
  - `_select_root_cause_insn(...) -> int | None`
- Pipeline connection: `generate_diagnostic()` depends on this for the coarse diagnosis and fix recommendation.
- Code quality issues:
  - This module reparses the raw log instead of accepting `ParsedLog` / `ParsedTrace` from the caller.
  - `_assess_proof()` labels any surviving relevant transition as `established_then_lost`. That is a strong assumption and can over-trigger lowering-artifact diagnoses.
  - `_select_relevant_transitions()` falls back to the full prefix of the trace when no transition is near the symptom instruction. `_select_root_transition()` then chooses the earliest high-priority transition. This can let very early generic type downgrades dominate a much later concrete reject site.
  - Catalog override policy is aggressive. In the current corpus, there are `109` cases where a catalog-seeded ID/class is overridden by the final diagnosis, mostly from various source-bug IDs to `BPFIX-E005` / `BPFIX-E006`.
  - The quality-fix Round 2 report already flags a downstream symptom of this kind of sensitivity: `7` cases shifted from `established_then_lost` to `never_established` and were not yet audited.
- Performance concerns:
  - second complete parse of the raw log
  - multiple whole-trace scans to collect proof signals, transitions, and evidence

### 8. `taxonomy/error_catalog.yaml`

- What it does: defines `23` stable error IDs, their taxonomy classes, representative verifier messages, likely obligations, and example repair actions.
- LOC: `336`
- Key schema:
  - `error_id`
  - `short_name`
  - `taxonomy_class`
  - `title`
  - `verifier_messages`
  - `likely_obligation`
  - `example_fix_actions`
- Pipeline connection: `log_parser.py` uses it to seed `error_id` and `taxonomy_class`.
- Code quality issues:
  - Several entries intentionally overlap. Because `log_parser._match_catalog()` is first-match wins, ordering is semantic. `E007` / `E018`, `E008` / `E018`, and several source-bug vs env-mismatch patterns are only separated by order and later fallback heuristics.
  - The catalog is richer than what the final renderer exposes. `likely_obligation` and `example_fix_actions` are not surfaced directly in the main JSON.
  - Error IDs are uppercase `BPFIX-E...`, while `interface/schema/diagnostic.json` currently requires lowercase-ish `[a-z0-9_.:-]+`; the repository’s own schema and catalog disagree.
- Performance concerns:
  - Linear scan over all patterns per parse. Fine today, but still fully dynamic because regexes are not precompiled at load time.

### 9. `taxonomy/obligation_catalog.yaml`

- What it does: defines `23` proof-obligation templates keyed by `obligation_id`, with expected/observed state text, verifier cues, repair hints, and related error IDs.
- LOC: `327`
- Key schema:
  - `obligation_id`
  - `taxonomy_class`
  - `title`
  - `expected_state`
  - `observed_state`
  - `verifier_cues`
  - `repair_hints`
  - `related_error_ids`
- Pipeline connection: `rust_diagnostic.py` loads it for help text and a limited obligation mapping.
- Code quality issues:
  - The catalog itself is complete: all `23` error IDs have a related obligation template. The engine is not. The main extractor only hardcodes `8` obligation mappings in `OBLIGATION_DETAILS`.
  - Only the first repair hint is surfaced, and the richer `expected_state` / `observed_state` text is not carried through to the final diagnostic JSON.
  - There are no tests that assert end-to-end coverage of all templates.
- Performance concerns:
  - YAML is loaded at runtime instead of once at module load or via a cache.

## Exact `generate_diagnostic()` Flow

| Stage | Function | Input | Output | Key decision points | Failure modes |
| --- | --- | --- | --- | --- | --- |
| 1 | `parse_log()` | raw verifier log string | `ParsedLog` | headline selection, catalog match, evidence extraction | wrong headline; no catalog match |
| 2 | `parse_trace()` | same raw verifier log | `ParsedTrace` | line classification, state association, backtrack extraction, transition detection | zero instructions; missed embedded instructions; wrong causal chain |
| 3 | `diagnose()` | same raw verifier log again | `Diagnosis` | symptom insn, proof status, loss context, final class/ID, fix hint | aggressive overrides; early unrelated transition wins |
| 4 | `_analyze_proof()` | `ParsedLog`, `ParsedTrace`, `Diagnosis` | proof status + events + obligation | use real proof analysis vs synthetic fallback | silent exception fallback; missing obligation |
| 5 | `correlate_to_source()` | `ParsedTrace`, `ProofEvent[]` | `SourceSpan[]` | use `@ file:line` if available, else bytecode fallback | no source markers -> bytecode-only spans |
| 6 | `_normalize_spans()` | spans + diagnosis context | final span list | synthesize missing roles, placeholder reject span, prune to <=5 | over-pruning; fabricated context; loss of range detail |
| 7 | `render_diagnostic()` | class/ID, proof status, spans, note/help | `DiagnosticOutput` | headline text, JSON packing | JSON/schema mismatch; lossy span serialization |

### Data flow details

`ParsedLog` carries:

- `error_line`
- `error_id`
- `taxonomy_class`
- `source_line`
- `evidence`

`ParsedTrace` carries:

- `instructions`
- `critical_transitions`
- `causal_chain`
- `backtrack_chains`
- `error_line`

`Diagnosis` adds:

- `symptom_insn`
- `root_cause_insn`
- `proof_status`
- `loss_context`
- `recommended_fix`
- diagnosis-level `evidence`

Proof analysis adds:

- `ProofObligation`
- ordered `ProofEvent`s

Source correlation converts events into `SourceSpan`s, and rendering converts that into:

- Rust-style text
- compact JSON

### Key decision points

1. Headline arbitration:
   - `generate_diagnostic()` trusts both `log_parser.py` and `trace_parser.py`, then `diagnoser.py` chooses the “preferred” one.
2. Symptom instruction choice:
   - if a causal chain exists, `diagnoser.py` anchors on that error instruction
   - otherwise it walks backward from the selected error line to the nearest preceding instruction
3. Proof-status choice:
   - if transitions are present, the diagnoser leans toward `established_then_lost`
   - otherwise it looks for proof-like narrowing/guard signals
4. Final classification:
   - catalog seed first
   - then structural verifier-limit / env-mismatch heuristics
   - then proof-loss override to `E005`/`E006`
5. Source mapping:
   - inline `@ file:line` marker if present
   - otherwise raw bytecode
   - otherwise placeholder rejected span

### Principal failure modes

- No parseable instructions:
  - output still succeeds, but proof analysis becomes sparse and spans collapse to rejected-only placeholders.
- Wrong headline selection:
  - catalog match and downstream classification can be wrong even if trace parsing succeeded.
- Overeager transition-based proof loss:
  - a generic earlier transition can cause catalog-seeded source-bug cases to become lowering-artifact outputs.
- Missing source markers:
  - source correlator falls back to bytecode even when the corpus has human text elsewhere.
- Silent proof-analysis failure:
  - exceptions are swallowed and the pipeline degrades without any explicit signal.
- Contract mismatch:
  - final JSON is not the repository schema, so downstream consumers cannot rely on one canonical format.

## Test Coverage Assessment

### Summary

- Test files: `8`
- Collected/passing tests: `44`
- Coverage style: mostly library-level regression/integration tests over real logs
- True end-to-end/system tests: none
- Closest E2E coverage: `tests/test_renderer.py` via `generate_diagnostic()`

### What is covered

- `log_parser.py`
  - error-line prioritization over comments/wrappers/summaries
  - catalog matching for selected IDs (`E005`, `E006`, `E019`, `E020`, `E021`, `E023`)
- `trace_parser.py`
  - real-line classification
  - instruction aggregation
  - backtrack chain extraction
  - critical transitions (`BOUNDS_COLLAPSE`, `TYPE_DOWNGRADE`, `RANGE_LOSS`)
  - causal-chain extraction
  - loader-prefixed and colon-prefixed instruction recovery
- `proof_analysis.py`
  - packet-access obligation inference
  - lifecycle reconstruction from backtracking
  - zero-trace `never_established` and `unknown`
- `diagnoser.py`
  - explicit `source_bug`, `lowering_artifact`, `verifier_limit`, and `env_mismatch` scenarios
  - “same symptom, different root cause” differential diagnosis
  - fallback classification with an empty catalog
- `source_correlator.py`
  - BTF-style `@ file:line` extraction
  - role preservation on the same source line
  - propagated-span pruning
- `rust_diagnostic.py`
  - full `generate_diagnostic()` path for lowering-artifact, source-bug, zero-trace, BTF-backed, and bytecode-only cases
  - role synthesis and span cap
  - JSON structure smoke checks
- project smoke / eval tooling
  - schema file exists
  - CLI `--help` works
  - eval case-record and prompt-building logic works

### What is not covered

- No behavioral `verifier_bug` classification test.
- No direct unit tests for `renderer.render_diagnostic()` formatting branches.
- No direct tests for `PROVENANCE_LOSS` transition detection even though the parser implements it.
- No direct end-to-end tests for all `23` error IDs or all `23` obligation templates.
- No schema-conformance test for the actual outputs of `generate_diagnostic()` or `interface.api.build_diagnostic()`.
- No malformed-input tests for:
  - broken YAML
  - missing `verifier_log`
  - missing catalog files
  - proof-analysis exceptions
  - absent optional dependencies like `pyelftools`
- No coverage for adjacent extractor modules `interface/extractor/obligation.py` and `interface/extractor/btf_mapper.py`.
- No real CLI / agent workflow tests for `agent/repair_loop.py`, `case_study/collect.py`, or `case_study/reproduce.py`; smoke tests only check `--help`.

### Unit vs integration

| File | Type | Notes |
| --- | --- | --- |
| `tests/test_log_parser.py` | unit-ish integration | real logs, focused on parser behavior |
| `tests/test_trace_parser.py` | integration/regression | real traces and weird-format recovery |
| `tests/test_proof_analysis.py` | integration | real traces + lifecycle checks |
| `tests/test_source_correlator.py` | unit | synthetic trace/event fixtures |
| `tests/test_diagnoser.py` | integration | full diagnose path |
| `tests/test_renderer.py` | integration / closest E2E | full `generate_diagnostic()` path |
| `tests/test_llm_comparison.py` | integration | eval tooling, not extractor core |
| `tests/test_smoke.py` | smoke | file existence, schema presence, CLI help |

### Key scenario coverage

- `lowering_artifact`: yes
- `source_bug`: yes
- `verifier_limit`: yes
- `env_mismatch`: yes
- `verifier_bug`: schema/enumeration only, not behavioral

## Data Inventory

Method for case counts below:

- “case files” means immediate `*.yaml` case files in each `case_study/cases/<dir>/`, excluding `index.yaml`
- sample for `verifier_log` presence = first `10` sorted case YAML files in each directory
- “full with verifier_log” = exact count across all non-index case YAML files

### Case files by source directory

| Directory | Case files | Sample size | Sample with `verifier_log` | Full with `verifier_log` |
| --- | ---: | ---: | ---: | ---: |
| `eval_commits` | 591 | 10 | 0/10 | 0/591 |
| `eval_commits_synthetic` | 535 | 10 | 10/10 | 535/535 |
| `github_issues` | 26 | 10 | 10/10 | 26/26 |
| `kernel_selftests` | 200 | 10 | 9/10 | 171/200 |
| `kernel_selftests.pre_unique_ids_20260311T0903` | 200 | 10 | 9/10 | 150/200 |
| `stackoverflow` | 76 | 10 | 10/10 | 76/76 |

Additional note:

- If you include `index.yaml`, the raw file totals are `27 / 201 / 201 / 77` for the four corpus directories that carry indexes.

### Eval scripts

- `eval/*.py`: `13`

Files present:

- `batch_diagnostic_eval.py`
- `compile_synthetic_cases.py`
- `cross_kernel.py`
- `cross_kernel_stability.py`
- `cross_log_stability.py`
- `diagnoser_30case_evaluation.py`
- `generate_synthetic_cases.py`
- `llm_comparison.py`
- `metrics.py`
- `pretty_verifier_comparison.py`
- `repair_experiment.py`
- `span_coverage_eval.py`
- `taxonomy_coverage.py`

### Result files

- Files in `eval/results/`: `14`
- Result artifacts excluding `README.md`: `13`

Artifacts present:

- `_taxonomy_coverage.json`
- `batch_diagnostic_results.json`
- `diagnoser_30case_results.json`
- `llm_comparison_manual_responses.json`
- `llm_comparison_results.json`
- `llm_multi_model_manual_responses.json`
- `llm_multi_model_manual_scores.json`
- `llm_multi_model_results.json`
- `pretty_verifier_comparison.json`
- `repair_experiment_results.json`
- `span_coverage_results.json`
- `synthetic_compilation_results.json`
- `taxonomy_coverage.json`

## Known Problems

This section separates:

- still-open problems
- fixed/historical issues already documented in earlier reports
- new issues found in this review

### Priority 0: Open Now

1. The project has no single canonical diagnostic contract.
   - `generate_diagnostic()` JSON does not validate against `interface/schema/diagnostic.json`.
   - `interface.api.build_diagnostic()` also does not validate against that schema.
   - Impact: downstream tooling cannot rely on one stable machine-readable format.

2. Obligation extraction is incomplete relative to the taxonomy.
   - `obligation_catalog.yaml` defines `23` templates.
   - `rust_diagnostic.py` hardcodes only `8` mappings in `OBLIGATION_DETAILS`.
   - In the current batch output, `116/241` successful diagnostics still have `obligation = null`.
   - Impact: the engine classifies many cases correctly but does not carry through the proof obligation that the taxonomy already knows.

3. Final classification is highly override-heavy and prone to false lowering-artifact diagnoses.
   - `diagnoser._classify()` trusts catalog seeds first but then rewrites many source-bug cases to `E005`/`E006` when proof-loss heuristics trigger.
   - Current corpus audit: `109` catalog-seeded cases are overridden.
   - Dominant override patterns include `E012 -> E006`, `E011 -> E005/E006`, and `E001 -> E005`.
   - Impact: output quality becomes sensitive to early generic transitions rather than the actual reject site.

4. Zero-trace and under-specified logs still dominate the weakest outputs.
   - Current batch: `20` `proof_status=unknown`, `125` one-span outputs.
   - Remaining `taxonomy_class=unknown` cases: `stackoverflow-68815540`, `stackoverflow-78633443`.
   - Docs consistently identify this as a corpus/artifact quality problem, especially for SO/GitHub logs.

### Priority 1: Open Now

5. The hot path does duplicate work.
   - `generate_diagnostic()` runs `parse_log()` and `parse_trace()`.
   - `diagnose()` immediately runs `parse_log()` and `parse_trace()` again.
   - Obligation catalog YAML is then reloaded again for note/help generation.
   - Impact: unnecessary latency and duplicated logic paths.

6. The seven `established_then_lost -> never_established` shifts introduced after Round 2 remain unaudited.
   - `quality-fix-round2-report.md` explicitly calls this out.
   - Impact: current proof-status distribution may be more conservative, or it may hide a regression; it is not yet known.

7. Batch evaluation still does not reuse “best block” selection for multi-block SO/GitHub logs.
   - `eval/batch_diagnostic_eval.py` still prefers `combined` if present.
   - `eval/pretty_verifier_comparison.py` already has `select_primary_log()` with log scoring.
   - Impact: evaluator stability is lower than it could be on multi-block cases.

8. Span coverage remains more uncertain than “success rate” suggests.
   - `span-coverage-eval.md` reports `101 yes / 10 no / 152 unknown`.
   - SO/GH rejected-span semantic match is effectively unavailable.
   - Lowering-artifact localization is still limited by missing caller/callee or subprogram provenance in the JSON.

9. Repair usefulness remains unproven.
   - `repair-experiment-report.md` shows no overall fix-type accuracy gain (`10/30` in both conditions).
   - `env_mismatch` remains `0/5`.
   - `source_bug` actually regressed in the comparison.

### Priority 2: Open Now

10. Tests are good at corpus-regression detection, but not at API-contract or adversarial-input coverage.
    - no behavioral `verifier_bug` test
    - no schema-conformance test for real outputs
    - no malformed-input tests
    - no full catalog/template coverage tests

11. Source correlation is still naming itself more strongly than it behaves.
    - Main engine source mapping is inline-text `@ file:line` parsing, not BTF/ELF lookup.
    - The actual `BTFMapper` path is outside `generate_diagnostic()`.

12. The worktree is not a clean baseline.
    - This audit was done against a dirty workspace with modified extractor files and regenerated docs.
    - Impact: any future diff-based evaluation should pin a specific commit or snapshot before comparing numbers.

### Historical Issues Already Fixed by Round 2

These were real problems in `output-quality-analysis.md`, but the current code/report state indicates they were addressed:

- `taxonomy_class=unknown` dropped from `14` to `2`
- false `proof_status=satisfied` dropped from `3` to `0`
- prefixed/embedded instruction recovery was added to `trace_parser.py`
- several catalog gaps (`E005`, `E006`, `E019`, `E020`, `E021`, `E023`) were patched

### New Issues Found in This Review

1. Schema mismatch is not just theoretical.
   - I validated both output paths.
   - `generate_diagnostic()` fails because it emits a different object model (`taxonomy_class`, `proof_status`, `spans`, `obligation`, `note`, `help`) and omits required schema fields.
   - `interface.api.build_diagnostic()` also fails because it uses `schema_version` instead of `diagnostic_version`, `taxonomy_class` instead of `failure_class`, and evidence items with the wrong field names.

2. The main renderer drops instruction-range end bounds.
   - Multi-instruction spans are stored as `(start, end)` internally but serialized as a single `insn_idx`.

3. Rejected-event register selection is fragile.
   - `rust_diagnostic.py` prefers bytecode destination register before the explicit error register from verifier text.
   - This is backwards for many dereference failures.

4. Proof heuristics are broad enough to treat `ctx`/`fp` as proof-bearing states.
   - That makes proof establishment easier to infer than it should be and likely contributes to override-heavy lowering-artifact diagnoses.

## Recommended Next Steps

1. Unify the output contract first.
   - Choose one canonical diagnostic JSON schema.
   - Make `generate_diagnostic()` emit it.
   - Add a real schema-conformance test.

2. Remove hardcoded obligation mapping.
   - Drive obligations directly from `obligation_catalog.yaml`.
   - Surface all 23 templates consistently.
   - Cache the catalog instead of rereading it per request.

3. Refactor the hot path around shared parsed objects.
   - Change `diagnose()` to accept `ParsedLog` and `ParsedTrace`.
   - Parse the raw log once per request.
   - Centralize error-line arbitration in one place.

4. Tighten proof-loss override logic before more catalog work.
   - Audit the `109` catalog overrides.
   - Require reject-nearby, same-register evidence before rewriting a catalog-seeded source-bug case to `E005`/`E006`.
   - Audit the 7 post-Round-2 proof-status shifts.

5. Separate corpus problems from engine problems.
   - Reuse `select_primary_log()` in batch evaluation.
   - Continue preserving better raw verifier blocks for SO/GH cases.
   - Do not spend core-parser time trying to infer BTF that the raw logs do not contain.

6. Expand tests where current blind spots matter.
   - behavioral `verifier_bug`
   - `PROVENANCE_LOSS`
   - full error-ID / obligation-template coverage
   - malformed/partial logs
   - output schema validation

7. Clarify project ownership of the two diagnostic stacks.
   - Either retire `interface/api.build_diagnostic()` / `BTFMapper` as the old path, or make it the canonical contract and update the extractor to match.

## Bottom Line

The engine is no longer in the “obvious parser bugs” stage. It runs, the tests pass, and the current batch success rate is clean. The real remaining risks are architectural:

- duplicate parsing and split logic paths
- no single stable machine-readable contract
- incomplete obligation surfacing
- aggressive trace-heuristic overrides
- persistent low-information inputs from the corpus

If the project lead wants the next round to improve product quality rather than just corpus-specific regression handling, the highest-leverage work is contract unification, obligation unification, and classifier de-risking.
