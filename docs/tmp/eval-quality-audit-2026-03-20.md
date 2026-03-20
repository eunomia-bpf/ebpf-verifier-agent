# Eval Quality Audit 2026-03-20

## Scope

Audited all Python files under:

- `eval/`
- `scripts/`
- `core/baseline/`
- `tests/`

Validation steps run during this audit:

- `python3 -m pyflakes eval scripts core/baseline tests`
- `python3 -m compileall eval scripts core/baseline tests`
- `python3 eval/batch_diagnostic_eval.py --results-path /tmp/batch-diagnostic-audit.json --report-path /tmp/batch-diagnostic-audit.md`
- `python3 eval/localization_eval.py --output-json /tmp/localization-audit.json --output-md /tmp/localization-audit.md`
- `python3 eval/fix_type_eval.py --output-json /tmp/fix-type-audit.json --output-md /tmp/fix-type-audit.md`
- `python3 eval/comparison_report.py --report-path /tmp/comparison-report-audit.md`
- `python3 eval/summarize_eval_refresh.py --report-path /tmp/eval-refresh-audit.md`
- `python3 eval/per_language_eval.py`
- `python3 -m pytest tests/test_verifier_oracle.py -q -rs`

Observed oracle result on this host: `38 passed, 2 skipped`. The skipped cases are explicit legacy-map-definition load cases under libbpf v1.0+.

## Part 1: Dead Code, Stale References, Compatibility Cleanup

### Fixed Directly

#### Dead imports and locals

- Removed unused import `yaml` from `eval/baseline_eval.py`.
- Removed unused imports from `eval/root_cause_validation.py`.
- Removed unused imports and locals from `eval/per_language_eval.py`.
- Removed unused locals from `eval/batch_proof_engine_eval.py`.
- Removed unused locals and broken cleanup fallout in `eval/repair_experiment_v3.py`.
- Removed unused locals and broken cleanup fallout in `eval/repair_experiment_v4.py`.
- Removed unused imports in multiple tests:
  - `tests/test_opcode_safety.py`
  - `tests/test_source_correlator.py`
  - `tests/test_cfg_builder.py`
  - `tests/test_slicer.py`
  - `tests/test_transition_analyzer.py`
  - `tests/test_value_lineage.py`
  - `tests/test_verifier_oracle.py`
  - `tests/test_control_dep.py`
  - `tests/test_dataflow.py`

#### Dead functions removed

- Removed `stratum_case_ids()` from `eval/source_strata.py`.
- Removed compatibility wrapper `extract_final_error_message()` from `core/baseline/error_patterns.py`.
- Removed dead helper `fix_type_label()` from:
  - `eval/repair_experiment_v3.py`
  - `eval/repair_experiment_v4.py`

#### Backward-compatibility shims removed

- Removed old nested span-format fallback from `eval/batch_diagnostic_eval.py`.
  - The current `batch_diagnostic_results.json` contains only the newer top-level `path`/`line` span layout.
- Removed old nested span-format fallback from `eval/root_cause_validation.py`.
- Removed the archive-label fallback from `eval/comparison_report.py`.
  - The report now uses only `case_study/ground_truth.yaml`, which is the canonical current label set.

#### Stale default output names and dated report paths fixed

- `eval/latency_benchmark.py`
  - default output changed from `latency_benchmark_v3.json` to `latency_benchmark.json`
- `eval/summarize_eval_refresh.py`
  - default latency input changed from `latency_benchmark_v4.json` to `latency_benchmark.json`
  - default report changed from dated `eval-refresh-2026-03-18.md` to stable `eval-refresh.md`
- `eval/comparison_report.py`
  - default report changed from dated `comparison-report-2026-03-18.md` to stable `comparison-report.md`
- `eval/per_language_eval.py`
  - removed hardcoded `2026-03-12` timestamps
  - now writes current UTC `generated_at`

#### Makefile cleanup

Fixed stale/default pipeline issues in `Makefile`:

- `eval-all` now actually includes the documented core pipeline:
  - `eval-baseline`
  - `eval-batch`
  - `eval-localization`
  - `eval-fix-type`
  - `eval-latency`
  - `eval-language`
- Added missing runnable targets for existing scripts:
  - `eval-ablation`
  - `eval-comparison`
  - `eval-proof-engine`
  - `eval-span-coverage`
  - `eval-root-cause`
  - `eval-taxonomy-coverage`
  - `eval-refresh`
- Updated `clean` to remove these generated outputs.

#### Documentation cleanup

- Rewrote `eval/README.md` so it matches the actual current eval surface instead of mentioning deleted or superseded scripts such as `repair_experiment_v2.py`.

### Flagged, Not Removed

These remain intentionally because the cleanup is not trivial or would change active behavior:

- `eval/verifier_oracle.py` keeps the legacy `struct bpf_map_def` shim.
  - This is a real backward-compatibility shim.
  - It is still needed for historical snippets and is exercised by tests.
  - Two verifier tests are skipped specifically because libbpf v1.0+ rejects legacy map defs during load.
- `eval/repair_experiment_v3.py` and `eval/repair_experiment_v4.py` remain as separate versioned experiment entrypoints.
  - They are structurally duplicative, but they are still active experiment surfaces.
- `eval/bpfix_eval_helpers.py` and `eval/llm_comparison.py` still contain overlapping helper logic.
  - Consolidation is worthwhile, but not a safe “delete dead code” edit.
- Historical `docs/tmp/*.md` files still reference old artifact names such as `ground_truth_labels.yaml`, `manual-labeling-30cases.md`, and `latency_benchmark_v3.json`.
  - These are stale writeups, not active eval code paths.

## Part 2: Actual Eval Pipeline Architecture

### Script-by-Script

| Script | Input | Processing | Output | Does it touch the kernel? |
| --- | --- | --- | --- | --- |
| `eval/batch_diagnostic_eval.py` | YAML case files under `case_study/cases/*` and their stored `verifier_log` fields | Reads stored logs, runs `generate_diagnostic(verifier_log)`, computes proof/taxonomy/span summary stats | `eval/results/batch_diagnostic_results.json`, markdown report | No |
| `eval/verifier_oracle.py` | Source code snippet or case YAML with source; optional verifier-log hint | Compiles with `clang -target bpf`, then runs `sudo bpftool -d prog load`, captures verifier stderr/log | `OracleResult` object; CLI can print JSON per case | Yes |
| `eval/localization_eval.py` | `case_study/ground_truth.yaml`, `eval/results/batch_diagnostic_results.json` | Reads saved BPFix diagnostic spans from batch results and scores them against labeled instruction indices | `eval/results/localization_eval.json`, markdown report | No |
| `eval/comparison_report.py` | `eval/results/ablation_results.json`, `case_study/eval_manifest.yaml`, `case_study/ground_truth.yaml` | Aggregates accuracy/F1/McNemar/gap-analysis tables across BPFix, baseline, and ablations | Markdown report only | No |
| `eval/fix_type_eval.py` | `case_study/ground_truth.yaml`, `eval/results/batch_diagnostic_results.json` | Reads saved diagnostic text/JSON from batch results and maps it to repair-type predictions | `eval/results/fix_type_eval.json`, markdown report | No |

### Make Targets

#### `make eval-batch`

Observed command:

```bash
python3 eval/batch_diagnostic_eval.py --results-path eval/results/batch_diagnostic_results.json
```

This does not compile programs.

This does not call `bpftool`.

This only processes stored verifier logs already embedded in the case-study YAML files.

#### `make eval-localization`

Observed command:

```bash
python3 eval/localization_eval.py \
  --batch-results-path eval/results/batch_diagnostic_results.json \
  --output-json eval/results/localization_eval.json \
  --output-md docs/tmp/localization-eval-report.md
```

This does not compile programs.

This does not fetch fresh verifier logs.

It consumes the stored batch-results artifact.

### Is There Any Real Compile -> `bpftool` Load -> Verifier Log -> Analysis Path?

Yes, but not in the default `make eval-batch` or `make eval-localization` path.

Real kernel-touching paths that exist today:

- `eval/verifier_oracle.py`
  - compile with `clang`
  - load with `sudo bpftool -d prog load`
  - capture verifier log
- `eval/cross_kernel_stability.py`
  - executes case programs against host or configured kernel runtimes
  - uses fresh verifier outcomes/logs
- `eval/repair_experiment_v3.py`
  - validates repaired code with `verify_fix(...)`
- `eval/repair_experiment_v4.py`
  - same pattern, different model/experiment surface
- `scripts/find_lowering_artifact_commits.py`
  - uses verification flow for candidate validation
- `scripts/batch_verify_eval_commits.py`
  - executes compile/load verification for eval-commit cases

Observed host evidence:

- `tests/test_verifier_oracle.py` passed the compile-only and full verifier paths on this machine.
- Result: `38 passed, 2 skipped`.
- The two skips are expected legacy-map-definition load cases under newer libbpf.

### Bottom Line

- `make eval-batch` is artifact-driven, not kernel-driven.
- `make eval-localization` is artifact-driven, not kernel-driven.
- The repo does contain a real compile/load/log path.
- That real path is currently separate from the main batch/localization/fix-type evaluation pipeline.

## Part 3: Quality Improvement Recommendations

### 1. Batch eval should support an optional fresh-log mode

`batch_diagnostic_eval.py` should keep its current stored-log mode as the default for reproducibility.

But it should also support an optional manifest-driven fresh-log mode that:

- compiles source snippets
- loads them with `bpftool`
- captures verifier logs
- stores the fresh logs in a dedicated artifact
- then runs the same diagnostic analysis over that artifact

Without that, the “main eval” numbers are only as current as the checked-in YAML logs.

### 2. Localization and fix-type evals should be able to consume fresh batch outputs

`localization_eval.py` and `fix_type_eval.py` currently depend on saved `batch_diagnostic_results.json`.

That is fine for offline reproducibility, but it means they cannot currently answer:

- how the system performs on a fresh kernel run today
- whether verifier-log drift changes the downstream numbers

Recommendation:

- keep current artifact mode
- add a clean path from fresh-log producer -> fresh batch results -> localization/fix-type

### 3. Reproducibility is mixed

Offline artifact-driven evaluation is reproducible now:

- the case-study YAML corpus already contains stored verifier logs
- the batch/localization/fix-type/comparison/refresh scripts run without kernel interaction

Kernel-touching evaluation is not fully reproducible across machines because it depends on:

- local kernel version
- `sudo bpftool` availability
- libbpf behavior
- system `vmlinux.h`
- clang toolchain

Recommendation:

Every result artifact should record:

- script name
- git commit SHA
- kernel release
- clang version
- bpftool version
- manifest hash or case-list hash
- whether logs were stored or freshly collected

### 4. Missing Makefile surface is mostly fixed, but one important path is still absent

This audit added Makefile targets for the current offline eval/report scripts.

Still missing conceptually:

- an explicit fresh-log target, for example `make eval-fresh-logs` or `make eval-oracle-batch`

That is the missing bridge between the real compile/load oracle and the headline batch eval.

### 5. Some result artifacts are clearly stale or historical

Current status after this audit:

- `per_language_eval.json` was refreshed with the current script.
- Core current artifacts:
  - `baseline_results.json`
  - `batch_diagnostic_results.json`
  - `localization_eval.json`
  - `fix_type_eval.json`
  - `latency_benchmark.json`
  - `per_language_eval.json`
  - `ablation_results.json`
- Historical or suspicious artifacts that should be archived, renamed, or documented as non-canonical:
  - `latency_benchmark_v3.json`
  - `latency_benchmark_v4.json`
  - `repair_experiment_results_v5.json`
    - internally reports `version = v3`
  - `pretty_verifier_comparison.json`
  - `pv_comparison_expanded.json`

These files are not wired into the current core Makefile pipeline and should not be treated as canonical current outputs.

### 6. Duplicate functionality remains

The biggest duplication still worth addressing:

- `eval/repair_experiment_v3.py` vs `eval/repair_experiment_v4.py`
- `eval/bpfix_eval_helpers.py` vs helper logic inside `eval/llm_comparison.py`

Recommendation:

- move shared parsing/scoring/oracle helpers into one module
- keep thin experiment entrypoints for model-specific differences only

## Practical Conclusions

### What changed in code

- dead imports removed
- dead helpers removed
- old span-format fallbacks removed
- archive-label fallback removed
- stale default artifact names normalized
- Makefile expanded and corrected
- `eval/README.md` brought in line with reality

### What the repo does today

- The default eval pipeline is mostly offline and artifact-driven.
- The repo does contain a real kernel verifier oracle.
- The default headline eval targets do not currently use that oracle.

### What should happen next

Highest-value follow-up:

1. Add a fresh-log producer target built on `verifier_oracle.py`.
2. Thread that artifact into batch/localization/fix-type as an optional mode.
3. Archive or clearly label old result snapshots.
