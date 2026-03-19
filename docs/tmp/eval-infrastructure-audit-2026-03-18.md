# OBLIGE Eval Infrastructure Audit

Date: 2026-03-18

Scope reviewed:
- `tests/`
- `eval/`
- `eval/results/`
- `case_study/cases/`
- `case_study/ground_truth_labels.yaml`
- `Makefile`

## Executive Summary

The current evaluation stack is functional in parts, but it is not a single coherent architecture.

Key findings:
- The automated test suite is healthy: `377` tests collect, and a full run in this workspace finished `372 passed, 5 skipped in 21.82s`.
- The main logged batch corpus is effectively `262` eligible cases, not `241`, and not consistently `263`; different scripts use different eligibility rules.
- `case_study/schema.yaml` is explicitly aspirational and unused, while `case_study/eval_schema.yaml` is closer to reality but still does not match the actual per-source case shapes.
- `case_study/ground_truth_labels.yaml` is thin taxonomy metadata only. It does not contain fix spans, root-cause lines, instruction indices, fix code, or error IDs.
- Several evaluation scripts do not use `ground_truth_labels.yaml` at all; they instead parse `docs/tmp/manual-labeling-30cases.md`, which is effectively a hidden part of the eval pipeline.
- Two advertised Makefile targets are currently broken in this workspace: `eval/per_language_eval.py` and `eval/pv_comparison_expanded.py` both hardcode `eval/results/batch_diagnostic_results_v4.json`, which does not exist.
- README and Makefile documentation are version-drifted relative to the code and result files on disk.

## 1. Test Suite Architecture

### 1.1 Pytest layout

Pytest is configured in `pyproject.toml` with:
- `testpaths = ["tests"]`
- `pythonpath = ["."]`

Observations:
- All tests live in one flat `tests/` directory.
- There is no `tests/conftest.py`.
- There are no pytest markers or explicit unit/integration subdirectories.
- `make test-quick` is identical to `make test`.

### 1.2 Requested command outputs

Requested command:

```bash
python -m pytest tests/ --collect-only -q 2>&1 | tail -20
```

Observed tail:

```text
tests/test_verifier_oracle.py::TestSecInjectionCompile::test_no_sec_snippet_compiles
tests/test_verifier_oracle.py::TestSecInjectionCompile::test_llm_includes_no_sec_compiles
tests/test_verifier_oracle.py::TestSecInjectionCompile::test_llm_includes_with_sec_no_license_compiles
tests/test_verifier_oracle.py::TestFullVerifier::test_good_program_passes_verifier
tests/test_verifier_oracle.py::TestFullVerifier::test_oob_program_rejected_by_verifier
tests/test_verifier_oracle.py::TestFullVerifier::test_verifier_log_contains_error
tests/test_verifier_oracle.py::TestFullVerifier::test_fixed_so_case_passes_verifier
tests/test_verifier_oracle.py::TestFullVerifier::test_snippet_passes_verifier
tests/test_verifier_oracle.py::TestFullVerifier::test_syntax_error_gives_no_verifier_result
tests/test_verifier_oracle.py::TestFullVerifier::test_no_sec_bare_snippet_passes_verifier
tests/test_verifier_oracle.py::TestFullVerifier::test_llm_with_includes_no_sec_passes_verifier
tests/test_verifier_oracle.py::TestVerifyCase::test_no_source_code
tests/test_verifier_oracle.py::TestVerifyCase::test_case_with_source_code_field
tests/test_verifier_oracle.py::TestVerifyCase::test_case_with_snippets_sorted_by_length
tests/test_verifier_oracle.py::TestVerifyCase::test_real_yaml_case
tests/test_verifier_oracle.py::TestKnownPairsPF::test_fixed_passes_buggy_fails
tests/test_verifier_oracle.py::TestKnownPairsPF::test_so70091221_fix_passes
tests/test_verifier_oracle.py::TestKnownPairsPF::test_oob_gives_useful_verifier_log

377 tests collected in 0.73s
```

Requested command:

```bash
python -m pytest tests/ -v --tb=no 2>&1 | head -100
```

Observed head:
- Session starts under Python `3.12.3`, pytest `9.0.2`.
- `377` items collected.
- Early output shows the suite starting with `test_api.py`, `test_batch_correctness.py`, `test_bpftool_parser.py`, `test_cfg_builder.py`, `test_cli.py`, `test_control_dep.py`, `test_dataflow.py`, all passing in the first 100 lines.

Additional full-suite run for audit:

```text
372 passed, 5 skipped in 21.82s
```

Skip reasons:
- All 5 skips are in `tests/test_verifier_oracle.py`.
- Reason: Linux UAPI kernel headers unavailable for the UAPI-based compile tests.

### 1.3 Test inventory

| File | Count | Category | Purpose | Fixtures / data |
| --- | ---: | --- | --- | --- |
| `tests/test_api.py` | 2 | Integration | `interface.api` schema loading and `build_diagnostic()` behavior | Uses `stackoverflow-70750259.yaml` |
| `tests/test_batch_correctness.py` | 15 | Regression | Batch-level invariants and known-answer regressions for the diagnostic pipeline | Scans all 66 SO cases with non-empty logs; explicit cases `70750259`, `70729664`, `70841631`, `60053570`, `77462271` |
| `tests/test_bpftool_parser.py` | 1 | Unit | `bpftool` instruction/source mapping parser | Inline sample only |
| `tests/test_cfg_builder.py` | 16 | Unit + regression | Branch-target extraction and CFG construction | Inline traces plus `stackoverflow-70750259.yaml` |
| `tests/test_cli.py` | 1 | Integration | `python -m oblige ... --format json` CLI smoke | Subprocess on `stackoverflow-60053570.yaml` |
| `tests/test_control_dep.py` | 9 | Unit + regression | Control-dependence and IPDOM behavior | Inline graphs plus `stackoverflow-70750259.yaml` |
| `tests/test_dataflow.py` | 49 | Unit + regression | Def/use extraction, reaching definitions, data slicing | Local fixture `chain_and_trace`; `stackoverflow-70750259.yaml` |
| `tests/test_diagnostic_schema.py` | 1 | Integration | Generated diagnostic JSON matches the declared schema | `stackoverflow-70750259.yaml` |
| `tests/test_helper_signatures.py` | 8 | Unit | Helper signature tables and helper-ID decoding | Inline opcode/helper samples |
| `tests/test_llm_comparison.py` | 5 | Unit + regression | Eval helper behavior for `eval/llm_comparison.py` | Manual-label parsing, case normalization, prompt construction |
| `tests/test_log_parser.py` | 4 | Regression | Error-line selection and taxonomy matching in tricky logs | Multiple selftest, SO, and GH YAMLs |
| `tests/test_monitor.py` | 3 | Unit | Gap-based proof establishment/loss semantics | Inline state transitions |
| `tests/test_opcode_safety.py` | 60 | Unit + regression | Opcode-to-safety-obligation inference | Inline opcodes plus `stackoverflow-70750259.yaml` |
| `tests/test_renderer.py` | 24 | Integration + regression | Final rendered diagnostic text/JSON, spans, BTF and metadata behavior | Broad mix of SO, selftest, and GitHub YAMLs |
| `tests/test_slicer.py` | 31 | Unit + regression | Backward slicer across data and control dependence | Local fixtures `parsed`, `slice_result`; `stackoverflow-70750259.yaml` |
| `tests/test_smoke.py` | 5 | Smoke | Repository file presence, schema presence, taxonomy presence, CLI `--help` | Subprocess checks; validates aspirational `case_study/schema.yaml` |
| `tests/test_source_correlator.py` | 6 | Unit + regression | Correlation of spans to source via BTF or `bpftool` mappings | Inline mappings and source text |
| `tests/test_trace_parser.py` | 10 | Unit + regression | Trace block parsing, backtracking extraction, critical-transition detection | Several real SO and selftest logs |
| `tests/test_transition_analyzer.py` | 68 | Unit + regression | Abstract transition classification | Mostly inline states plus two real SO logs |
| `tests/test_value_lineage.py` | 20 | Unit | Register/spill/fill lineage tracking | Inline traces |
| `tests/test_verifier_oracle.py` | 39 | Integration + env-sensitive | Compile-only and live verifier oracle for candidate fixes | Needs `clang`; some tests also need headers and `sudo bpftool` |

### 1.4 How the suite is really organized

There is no physical separation of unit vs integration vs regression tests. The effective organization is:

- Pure unit tests:
  `test_bpftool_parser.py`, `test_helper_signatures.py`, `test_monitor.py`, `test_value_lineage.py`, large portions of `test_cfg_builder.py`, `test_control_dep.py`, `test_dataflow.py`, `test_opcode_safety.py`, `test_transition_analyzer.py`, `test_slicer.py`
- Corpus-backed regression tests:
  `test_batch_correctness.py`, `test_log_parser.py`, `test_renderer.py`, `test_trace_parser.py`, `test_diagnostic_schema.py`, `test_llm_comparison.py`
- Integration / subprocess / environment-sensitive tests:
  `test_cli.py`, `test_api.py`, `test_smoke.py`, `test_verifier_oracle.py`

### 1.5 Fixtures and test data

Notable fixtures:
- `tests/test_dataflow.py`: `chain_and_trace`
- `tests/test_slicer.py`: `parsed`, `slice_result`

There are no shared global fixtures.

Test data patterns:
- Heavy reuse of a single canonical case: `case_study/cases/stackoverflow/stackoverflow-70750259.yaml` is referenced `26` times across the suite.
- Other recurring real logs: `stackoverflow-70729664.yaml`, `stackoverflow-77462271.yaml`, `stackoverflow-77713434.yaml`, `stackoverflow-78958420.yaml`, several selftests, and a few GitHub issues.
- `tests/test_verifier_oracle.py` also uses inline source strings to create compile-only and verifier-only cases.

## 2. Eval Dataset Architecture

### 2.1 `eval/results/` inventory

| File | Size | Notes |
| --- | ---: | --- |
| `README.md` | 361 B | Results directory note |
| `batch_diagnostic_results.json` | 1,761,308 B | Main logged batch output; `302` scanned, `262` eligible |
| `batch_proof_engine_round3.json` | 190,724 B | Proof-engine vs diagnoser comparison; `262` cases |
| `latency_benchmark_v3.json` | 153,505 B | Latency benchmark over `262` cases |
| `llm_comparison_manual_responses.json` | 12,028 B | Small manual-response bundle |
| `llm_multi_model_manual_responses.json` | 90,468 B | Manual responses for multi-model LLM eval |
| `llm_multi_model_manual_scores.json` | 86,504 B | Manual scores for multi-model LLM eval |
| `llm_multi_model_results.json` | 757,011 B | Multi-model LLM eval output; `22` cases |
| `per_language_eval.json` | 2,449 B | Stored per-language summary; references missing v4 input |
| `pretty_verifier_comparison.json` | 480,624 B | Raw Pretty Verifier comparison; `263` cases |
| `pv_comparison_expanded.json` | 237,490 B | Post-processed PV vs OBLIGE comparison; `262` cases |
| `repair_experiment_results_v3.json` | 2,057,038 B | A/B repair experiment, version 3; `56` selected cases |
| `repair_experiment_results_v5.json` | 1,762,895 B | Repair results bundle version 5; no matching `repair_experiment_v5.py` script |
| `root_cause_validation.json` | 299,870 B | Root-cause validation bundle |
| `span_coverage_results.json` | 1,466,975 B | Span coverage bundle; `263` cases |
| `taxonomy_coverage.json` | 221,579 B | Taxonomy/catalog coverage across `302` cases |

All JSON files in `eval/results/` parsed successfully. The inconsistency is semantic, not syntactic.

### 2.2 `case_study/cases/` inventory

Directory-level inventory:

| Directory | Case files | Manifest file | Actual role |
| --- | ---: | --- | --- |
| `kernel_selftests/` | 200 | `index.yaml` | Logged kernel selftest failures |
| `stackoverflow/` | 76 | `index.yaml` | Logged Stack Overflow cases |
| `github_issues/` | 26 | `index.yaml` | Logged GitHub issue cases |
| `eval_commits/` | 591 | none | Commit-derived buggy/fixed code pairs; no logs |
| `eval_commits_synthetic/` | 535 | none | Synthetic buggy/fixed pairs; empty logs |

Totals:
- `1431` YAML files under `case_study/cases/`
- `1428` actual case files
- `3` manifest/index files

Important architectural split:
- Current logged diagnostic evals use only `kernel_selftests`, `stackoverflow`, and `github_issues`.
- `eval_commits` and `eval_commits_synthetic` are code/fix corpora, not current log-driven diagnostic corpora.

### 2.3 Current logged corpus size

The logged corpus used by `batch_diagnostic_eval.py` is:
- `200` selftests
- `76` Stack Overflow
- `26` GitHub issues
- `302` total scanned

With `MIN_LOG_CHARS = 50`, current eligibility is:
- `171` selftests
- `65` Stack Overflow
- `26` GitHub issues
- `262` eligible total

This is materially different from the `241-case` figure still mentioned in repo docs.

## 3. Case Corpus Structure

### 3.1 Real per-source schemas

Actual case shapes are source-specific.

| Source | Main fields present | Verifier log shape | Fix/source info |
| --- | --- | --- | --- |
| `kernel_selftests` | `case_id`, `source`, `collected_at`, `selftest`, `expected_verifier_messages`, `verifier_log`, `source_snippets` | Plain multiline string | No `fixed_code`; source snippet present for all 200 |
| `stackoverflow` | `case_id`, `source`, `collected_at`, `question`, `verifier_log`, `source_snippets`, `question_body_text`, optional `selected_answer` | Dict with `blocks` and `combined` | `selected_answer` often acts as fix text |
| `github_issues` | `case_id`, `source`, `collected_at`, `issue`, `verifier_log`, optional `source_snippets`, `issue_body_text`, optional `fix` | Dict with `blocks` and `combined` | `fix.summary` / selected comment acts as fix text |
| `eval_commits` | `case_id`, `source`, `repository`, `commit_hash`, `commit_message`, `commit_date`, `fix_type`, `buggy_code`, `fixed_code`, `diff_summary` | None | Best source of exact buggy/fixed code |
| `eval_commits_synthetic` | `case_id`, `source`, original commit metadata, `fix_type`, `taxonomy_class`, `source_snippets`, `fixed_code`, `fix_description`, `verifier_log` | Empty string | Synthetic transformed cases |

Representative examples reviewed:
- `case_study/cases/kernel_selftests/kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda.yaml`
- `case_study/cases/stackoverflow/stackoverflow-47591176.yaml`
- `case_study/cases/github_issues/github-aya-rs-aya-1002.yaml`
- `case_study/cases/eval_commits/eval-aya-05c1586202ce.yaml`
- `case_study/cases/eval_commits_synthetic/synth-eval-bcc-02daf8d84ecd.yaml`

### 3.2 Schema drift vs declared schemas

`case_study/schema.yaml`:
- Explicitly aspirational.
- Requires fields like `source_code`, `compile_args`, `target_kernel`, `fix_patch`, `semantic_test`.
- The README says it is not used by the eval pipeline.

`case_study/eval_schema.yaml`:
- Closer to the intended eval shape.
- Declares inputs `buggy_code` and `verifier_log`.
- Declares ground truth fields like `fixed_code`, `fix_description`, `fix_type`, `expected_verifier_message`, `source_url`, `commit_hash`.

But even `eval_schema.yaml` is not a faithful schema for the actual corpus:
- Logged selftests/SO/GitHub cases usually do not contain `buggy_code`.
- Selftests do not contain `fixed_code` or `fix_type`.
- Stack Overflow and GitHub issues usually do not contain `fixed_code` or `commit_hash`.
- `eval_commits` does not contain `verifier_log`.
- `eval_commits_synthetic` contains an empty `verifier_log`.

Conclusion:
- There is no single enforced machine schema that all current case files satisfy.

### 3.3 Source snippet coverage

`source_snippets` availability:
- `kernel_selftests`: `200/200`
- `stackoverflow`: `59/76`
- `github_issues`: `15/26`
- `eval_commits`: `0/591`
- `eval_commits_synthetic`: `535/535`

Multi-snippet cases:
- `stackoverflow`: `28`
- `github_issues`: `10`

### 3.4 Verifier-log completeness

Using a simple audit heuristic:
- `trace_rich`: at least 3 instruction-like lines plus `processed ... insns`
- `partial_trace`: some instruction-like lines, but not a full rich trace
- `message_only`: non-empty log text with no real instruction trace
- `no_log`: empty or missing

| Source | Trace-rich | Partial trace | Message-only | No log |
| --- | ---: | ---: | ---: | ---: |
| `kernel_selftests` | 169 | 0 | 2 | 29 |
| `stackoverflow` | 39 | 13 | 14 | 10 |
| `github_issues` | 11 | 8 | 7 | 0 |
| `eval_commits_synthetic` | 0 | 0 | 0 | 535 |

Implications:
- The logged corpus is heterogeneous even before modeling.
- Selftests are the strongest source for detailed verifier traces.
- Stack Overflow and GitHub cases are a mix of full traces, partial traces, and wrapper/error-message excerpts.
- `eval_commits` and `eval_commits_synthetic` are not presently suitable for the main logged diagnostic pipeline.

## 4. Ground Truth Architecture

### 4.1 `case_study/ground_truth_labels.yaml`

The file has top-level keys:
- `metadata`
- `cases`

Metadata:
- `generated: 2026-03-13`
- `description: Ground truth taxonomy labels for OBLIGE evaluation`
- `total_cases: 292`
- `by_source: {manual: 30, selftest_auto: 189, so_auto: 58, gh_auto: 15}`
- `by_taxonomy: {verifier_limit: 6, source_bug: 193, env_mismatch: 47, lowering_artifact: 44, verifier_bug: 2}`

Each case entry has only:
- `case_id`
- `source`
- `taxonomy`
- `confidence`
- `notes`

Non-null counts:
- all 292 rows have all 5 fields

What is not present:
- no `error_id`
- no `fix_type`
- no `root_cause`
- no `root_cause_line`
- no instruction index
- no source line
- no fixed code
- no diff/span anchors

Conclusion:
- This is taxonomy-only labeling metadata, not full localization or repair ground truth.

### 4.2 Manual vs auto labels

The file mixes manual and heuristic labels in the `source` field:
- `manual`: `30`
- `selftest_auto`: `189`
- `so_auto`: `58`
- `gh_auto`: `15`

This overloading is confusing because case files also use `source`, but there it means provenance bucket like `stackoverflow` or `kernel_selftests`.

`notes` prefixes show the provenance clearly:
- `msg_pattern`: `174`
- `keyword`: `56`
- `log_msg`: `17`
- `log_pattern`: `15`
- `manually labeled; error_id`: `30`

So the majority of this file is heuristic/auto-labeled, not manually adjudicated.

### 4.3 Label coverage gaps

`ground_truth_labels.yaml` covers `292/302` logged corpus cases.

Missing labels:
- `github-aya-rs-aya-1104`
- `github-aya-rs-aya-1324`
- `github-aya-rs-aya-546`
- `github-facebookincubator-katran-149`
- `stackoverflow-68815540`
- `stackoverflow-69413427`
- `stackoverflow-76371104`
- `stackoverflow-78695342`
- `stackoverflow-79616493`
- `stackoverflow-79812509`

Of those, `7` are currently in the `262` eligible batch corpus:
- `stackoverflow-68815540`
- `stackoverflow-69413427`
- `stackoverflow-79812509`
- `github-aya-rs-aya-1104`
- `github-aya-rs-aya-1324`
- `github-aya-rs-aya-546`
- `github-facebookincubator-katran-149`

### 4.4 De facto ground-truth file used by scripts

Several eval scripts do not use `ground_truth_labels.yaml` at all. They parse:

- `docs/tmp/manual-labeling-30cases.md`

This file contains the current 30-case manual benchmark table and includes:
- taxonomy class
- error ID
- confidence
- localizability
- specificity
- rationale
- ground truth fix text

Rows in the labeled-case table:
- `30`

Scripts that use `docs/tmp/manual-labeling-30cases.md`:
- `eval/span_coverage_eval.py`
- `eval/pretty_verifier_comparison.py`
- `eval/llm_comparison.py`
- `eval/repair_experiment_v3.py`
- `eval/repair_experiment_v4.py`

That makes `docs/tmp/manual-labeling-30cases.md` part of the real eval architecture even though it lives in a temporary docs directory.

## 5. Eval Script Inventory and Current Architecture

There is no `eval/batch_eval.py`. The current batch driver is `eval/batch_diagnostic_eval.py`.

| Script | Purpose | Output | Status |
| --- | --- | --- | --- |
| `batch_diagnostic_eval.py` | Main logged batch runner over selftests/SO/GH logs | `eval/results/batch_diagnostic_results.json` | Current primary batch runner |
| `batch_proof_engine_eval.py` | Proof-engine vs diagnoser comparison on the same eligible logged corpus | `eval/results/batch_proof_engine_round3.json` | Works conceptually; no Makefile target |
| `latency_benchmark.py` | End-to-end latency timing | `eval/results/latency_benchmark*.json` | Current |
| `span_coverage_eval.py` | Compare emitted spans against inferred/manual fix locations | `eval/results/span_coverage_results.json` | Current, but uses a different corpus threshold |
| `root_cause_validation.py` | Compare `proof_lost` spans against code diffs/fix text where available | `eval/results/root_cause_validation.json` | Current, but weakly supported by data |
| `taxonomy_coverage.py` | Catalog/error-ID coverage over the logged corpus | `eval/results/taxonomy_coverage.json` | Current |
| `pretty_verifier_comparison.py` | Raw PV vs OBLIGE corpus comparison | `eval/results/pretty_verifier_comparison.json` | Current raw comparison |
| `pv_comparison_expanded.py` | Post-process PV vs OBLIGE using PV output plus batch output | `eval/results/pv_comparison_expanded.json` | Broken: hardcoded missing `batch_diagnostic_results_v4.json` |
| `per_language_eval.py` | Language-level post-processing of batch results | `eval/results/per_language_eval.json` | Broken: hardcoded missing `batch_diagnostic_results_v4.json` |
| `llm_comparison.py` | Multi-condition LLM diagnosis experiment | `eval/results/llm_multi_model_results.json` | Uses manual-label doc, not YAML labels |
| `repair_experiment_v3.py` | A/B repair experiment with local model and verifier oracle | `eval/results/repair_experiment_results_v3.json` | Current for Makefile `eval-repair-20b` |
| `repair_experiment_v4.py` | Qwen-based repair experiment | `eval/results/repair_experiment_results_v4.json` | Script exists; result file not present |
| `synthesis_pilot.py` | Prototype repair synthesis workflow | none stable | Likely stale; references missing `batch_diagnostic_results_v5.json` |
| `cross_kernel_stability.py` | Prototype cross-kernel stability runner | markdown/JSON per run | Prototype |
| `cross_log_stability.py` | Offline multi-block log stability analysis | markdown report | Prototype |
| `metrics.py` | Generic result aggregation helper | stdout JSON summary | Skeleton utility, not core orchestrator |
| `verifier_oracle.py` | Compile/verifier pass oracle for repaired code | direct use by experiments/tests | Utility, not corpus scorer |

### 5.1 How the main batch pipeline works

`eval/batch_diagnostic_eval.py` currently does this:

1. Iterate over:
   - `case_study/cases/kernel_selftests/*.yaml`
   - `case_study/cases/stackoverflow/*.yaml`
   - `case_study/cases/github_issues/*.yaml`
2. Skip `index.yaml`.
3. Extract `verifier_log` from either:
   - plain string
   - dict `{combined, blocks}`
4. Skip cases where `len(verifier_log) < 50`.
5. Call `interface.extractor.rust_diagnostic.generate_diagnostic(verifier_log)`.
6. Record per-case fields:
   - success/skipped
   - verifier log length
   - `error_id`
   - `taxonomy_class`
   - `proof_status`
   - span count
   - presence of BTF/source lines
   - presence of `proof_established`, `proof_lost`, and `rejected` spans
   - output text length
   - compression ratio
7. Write:
   - JSON bundle to `eval/results/batch_diagnostic_results.json`
   - Markdown report to `docs/tmp/batch-diagnostic-eval.md`

Important point:
- The main batch runner does not compare predictions against any ground-truth label file.
- Ground-truth comparison happens only in downstream analysis scripts.

### 5.2 Makefile eval targets

Relevant targets in `Makefile`:

| Target | Command | Current status |
| --- | --- | --- |
| `eval-batch` | `python eval/batch_diagnostic_eval.py --results-path eval/results/batch_diagnostic_results.json` | Works conceptually |
| `eval-latency` | `python eval/latency_benchmark.py --results-path eval/results/latency_benchmark.json` | Works conceptually |
| `eval-pv` | `python eval/pv_comparison_expanded.py --output-json eval/results/pv_comparison_expanded.json --output-md docs/tmp/pv-comparison-expanded.md` | Broken in current workspace |
| `eval-language` | `python eval/per_language_eval.py` | Broken in current workspace |
| `eval-all` | Chains batch, latency, pv, language | Broken because `eval-pv` and `eval-language` fail |
| `eval-repair` / `eval-repair-20b` | Run `repair_experiment_v3.py` | Requires local llama server/model path |
| `eval-repair-qwen` | Run `repair_experiment_v4.py` | Requires local llama.cpp setup |

Verified runtime failures:

`python eval/per_language_eval.py`

```text
FileNotFoundError: ... eval/results/batch_diagnostic_results_v4.json
```

`python eval/pv_comparison_expanded.py`

```text
FileNotFoundError: ... eval/results/batch_diagnostic_results_v4.json
```

### 5.3 Metrics currently computed

By script:

- `batch_diagnostic_eval.py`
  - scanned / eligible / skipped / failures
  - per-source success counts
  - proof-status distribution
  - taxonomy distribution
  - span histogram
  - BTF/source-line rate
  - compression ratio
  - role completeness checks

- `batch_proof_engine_eval.py`
  - proof-engine success/errors
  - obligation-kind counts
  - proof-status distribution
  - diagnoser-vs-proof status matrix
  - mismatch examples

- `latency_benchmark.py`
  - per-stage latency stats
  - min/mean/median/p95/p99
  - slowest cases
  - correlation fields

- `span_coverage_eval.py`
  - fix-location coverage (`yes` / `no` / `unknown`)
  - taxonomy match
  - rejected-span match
  - source breakdown
  - separate summary for the manual 30-case subset
  - synthetic-case summary

- `root_cause_validation.py`
  - proof-lost rate
  - instruction-level backtracking vs at-error
  - source-line match rates
  - text match rates

- `taxonomy_coverage.py`
  - catalog coverage rate
  - matched cases
  - error-ID distribution
  - recommendation candidates for catalog expansion

- `pretty_verifier_comparison.py` / `pv_comparison_expanded.py`
  - PV handled/unhandled/crash rates
  - OBLIGE multi-span/BTF/causal-chain rates
  - by-taxonomy and by-source aggregates

- `repair_experiment_v3.py` / `repair_experiment_v4.py`
  - fix-type accuracy
  - location accuracy
  - semantic accuracy
  - in newer result bundles, compile/verifier pass rates via oracle

- `llm_comparison.py`
  - taxonomy/root-cause/fix-direction accuracy
  - condition and model-strength breakdowns

## 6. Result Consistency and Data Quality

### 6.1 What is consistent

- All JSON result bundles parse.
- The main logged batch artifact is internally consistent:
  - `302` scanned
  - `40` skipped
  - `262` eligible
  - `262` successes
  - `0` failures
- `batch_diagnostic_results.json`, `batch_proof_engine_round3.json`, `latency_benchmark_v3.json`, and `pv_comparison_expanded.json` all align on the same `262` eligible case IDs.

Current main batch summary:
- proof status:
  - `established_then_lost`: `131`
  - `never_established`: `105`
  - `unknown`: `21`
  - `established_but_insufficient`: `5`
- taxonomy:
  - `lowering_artifact`: `141`
  - `source_bug`: `98`
  - `env_mismatch`: `20`
  - `verifier_limit`: `3`
- all `262` successful cases have a `rejected` span
- `172` have BTF/source-line info
- `133` have `proof_lost`
- `136` have `proof_established`

### 6.2 What is inconsistent

#### A. Corpus-definition drift

There are at least three different corpus definitions in active code/results:

- `302` scanned logged cases:
  - all selftests + SO + GH case files
- `262` eligible logged cases:
  - `batch_diagnostic_eval.py`, `batch_proof_engine_eval.py`, `latency_benchmark.py`, `pv_comparison_expanded.json`
  - threshold: `len(verifier_log) >= 50`
- `263` logged cases:
  - `pretty_verifier_comparison.json`
  - `span_coverage_results.json`
  - includes `stackoverflow-67441023`, whose combined log is only `41` chars:

```text
>> 0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
```

This same inconsistency also appears in tests:
- `tests/test_batch_correctness.py` asserts `66` Stack Overflow cases with non-empty logs.
- The main batch pipeline only treats `65` Stack Overflow cases as eligible because it applies the `>= 50 chars` rule.

#### B. Version drift in script dependencies

Broken hardcoded inputs:
- `eval/per_language_eval.py` expects `eval/results/batch_diagnostic_results_v4.json`
- `eval/pv_comparison_expanded.py` expects `eval/results/batch_diagnostic_results_v4.json`
- `eval/synthesis_pilot.py` references `eval/results/batch_diagnostic_results_v5.json`

Missing files:
- `batch_diagnostic_results_v4.json`
- `batch_diagnostic_results_v5.json`
- `repair_experiment_results_v4.json`
- `pretty_verifier_comparison_v3.json`

But stored output files still reference those missing versions, for example:
- `eval/results/per_language_eval.json` has `source_file = .../batch_diagnostic_results_v4.json`
- `eval/results/pv_comparison_expanded.json` says its method used `batch_diagnostic_results_v4.json`

#### C. Documentation drift

`eval/README.md` is stale:
- names active scripts that do not exist in the directory anymore, including:
  - `repair_experiment_v2.py`
  - `pv_comparison_v3.py`
  - `diagnoser_30case_evaluation.py`
- lists historical scripts that are also absent
- still describes the ecosystem as if those versioned files were present

`case_study/README.md` is also stale:
- says `eval_commits/` has `591 cases + index.yaml`, but there is no `index.yaml`
- says the primary batch corpus is `241` cases; current code yields `262`

`Makefile` help text is stale:
- `eval-batch` help says "on 302 cases", but the script actually reports `302 scanned / 262 eligible`
- `eval-all` is presented as usable, but it currently fails due missing v4 inputs

#### D. Ground-truth wiring is fragmented

`ground_truth_labels.yaml` is not the single source of truth.

Instead:
- taxonomy-only labels live in `case_study/ground_truth_labels.yaml`
- richer 30-case manual labels live in `docs/tmp/manual-labeling-30cases.md`
- downstream scripts mix heuristics, manual markdown parsing, and YAML fields like `selected_answer` / `fix.summary`

That means there is no single, versioned, machine-readable ground-truth object that supports:
- taxonomy
- error ID
- localization
- fix direction
- root cause
- repair text

all at once.

#### E. Batch results vs ground truth labels do not align well

Joining `batch_diagnostic_results.json` against `ground_truth_labels.yaml` on eligible successful cases:
- labeled overlap: `255`
- exact taxonomy match: `89`
- overall match rate: `34.9%`

Manual 30-case subset only:
- overlap: `30`
- exact taxonomy match: `12`
- match rate: `40.0%`

Dominant mismatch patterns:
- gold `source_bug` -> predicted `lowering_artifact`: `99`
- gold `env_mismatch` -> predicted `lowering_artifact`: `26`
- gold `lowering_artifact` -> predicted `source_bug`: `16`

This could mean:
- the current classifier has drifted,
- the heuristic auto-labels are weak,
- the taxonomy boundary has changed,
- or all three.

But the current repo state does not support a clean interpretation, because the ground truth is mixed-provenance and not centrally enforced.

#### F. Root-cause validation is structurally under-supported

`root_cause_validation.json` reports:
- `262` total evaluated
- only `30` with any `proof_lost`
- only `27` with diff information
- only `19` with BTF line info
- `0` line-evaluable cases
- `1` text-evaluable case

That means current corpus/labels do not support strong line-level root-cause claims.

#### G. Tests and schemas give a partial false sense of coverage

- `tests/test_smoke.py` validates `case_study/schema.yaml`, but the README explicitly says this schema is unused and aspirational.
- There is no repo-level validation that actual case files conform to one real enforced schema.
- Test coverage is heavily concentrated on `stackoverflow-70750259.yaml`, which is valuable as a regression anchor but risky as the dominant fixture.

## 7. Practical Usage Guide

### 7.1 What works now

For the main diagnostic pipeline:

```bash
make eval-batch
```

Equivalent direct command:

```bash
python eval/batch_diagnostic_eval.py \
  --results-path eval/results/batch_diagnostic_results.json
```

For latency:

```bash
make eval-latency
```

For proof-engine batch comparison:

```bash
python eval/batch_proof_engine_eval.py
```

For taxonomy coverage:

```bash
python eval/taxonomy_coverage.py
```

For span coverage:

```bash
python eval/span_coverage_eval.py
```

For root-cause validation:

```bash
python eval/root_cause_validation.py
```

For tests:

```bash
python -m pytest tests/ -q
```

### 7.2 What is currently broken or stale

These currently fail in this workspace:

```bash
python eval/per_language_eval.py
python eval/pv_comparison_expanded.py
make eval-language
make eval-pv
make eval-all
```

Reason:
- missing `eval/results/batch_diagnostic_results_v4.json`

### 7.3 Current end-to-end architecture

The real flow is:

1. Case files
   - heterogeneous YAMLs in `kernel_selftests/`, `stackoverflow/`, `github_issues/`
2. Batch diagnostic generation
   - `generate_diagnostic(verifier_log)`
3. Stored batch bundle
   - `eval/results/batch_diagnostic_results.json`
4. Downstream analysis
   - proof engine, latency, taxonomy coverage, span coverage, root-cause validation, PV comparison, LLM/repair experiments
5. Ground-truth joins
   - not centralized
   - split across YAML taxonomy labels, manual markdown labels, and per-case fix text fields

## 8. Recommendations for Research Plan Section 5

### 8.1 Freeze a single canonical evaluation manifest

Add one machine-readable manifest, for example:
- `case_study/eval_manifest.yaml`

It should explicitly define:
- case IDs
- source bucket
- split membership
- eligibility flags per eval
- log richness class
- label coverage status
- manifest version/hash

Every eval script should read that manifest instead of reimplementing corpus selection.

### 8.2 Replace fragmented ground truth with one versioned label store

Move all evaluation labels out of `docs/tmp/` and into versioned data under `case_study/labels/`.

Each labeled case should support:
- `case_id`
- corpus source
- label provenance (`manual`, `heuristic`, `imported`)
- taxonomy class
- error ID
- confidence
- root-cause text
- fix text
- fix type
- localizability
- source line / instruction annotations when available
- notes

### 8.3 Decide what the primary benchmark actually is

Pick one and use it everywhere:
- `302` scanned corpus
- `262` eligible batch corpus
- `263` any-nonempty-log corpus
- `30` manual benchmark subset

Right now the paper/eval story can accidentally mix all four.

### 8.4 Enforce one real case schema

Either:
- normalize all case files to one schema, or
- keep source-specific raw YAMLs but generate one canonical normalized JSONL/YAML layer for evaluation

Do not keep `schema.yaml`, `eval_schema.yaml`, and actual corpus layouts drifting independently.

### 8.5 Make every advertised target runnable in CI

At minimum, CI should smoke:
- `make eval-batch`
- `python eval/batch_proof_engine_eval.py`
- `python eval/span_coverage_eval.py`
- `python eval/root_cause_validation.py`
- `python eval/taxonomy_coverage.py`
- `make eval-language`
- `make eval-pv`

If a target depends on a historical `v4` or `v5` artifact, that dependency should be explicit and versioned, or the script should be updated to use current outputs.

### 8.6 Add result provenance metadata

Each result bundle should record:
- git commit
- input manifest path
- input manifest hash
- script version
- threshold values like `min_log_chars`
- model version for LLM experiments
- label source path/version

That will make stored JSON interpretable months later.

### 8.7 Separate research claims by evidence strength

Given current data availability:
- taxonomy classification claims are supportable only after label cleanup
- source-line localization claims are not currently supportable at scale
- repair claims need a stable, machine-readable ground-truth fix set

For Section 5, I would recommend explicitly defining:
- a taxonomy benchmark
- a localization benchmark
- a repair benchmark

instead of treating the current heterogeneous corpus as if it supports all three equally.

### 8.8 Improve the test architecture modestly

Recommended changes:
- split tests into `unit/`, `regression/`, `integration/`
- add pytest markers for env-sensitive tests
- centralize YAML loaders in shared fixtures
- reduce over-reliance on `stackoverflow-70750259.yaml`
- add a schema-validation test for the actual canonical eval schema, not just the aspirational one

## Bottom Line

Current state:
- The core diagnostic engine and its main test suite are in decent shape.
- The evaluation infrastructure around it is partially reproducible and partially version-drifted.
- The logged case corpus is useful, but heterogeneous.
- The ground truth is fragmented and too thin for strong localization/root-cause claims.

If Section 5 of the research plan is meant to become the durable evaluation story, the next step is not more one-off scripts. It is consolidating corpus selection, schema normalization, and machine-readable ground truth into one versioned evaluation layer that every script and paper table shares.
