# Paper Data Audit

Generated on `2026-03-12` against the current OBLIGE tree.

## Scope

This audit checks the numeric claims requested in `docs/paper/main.tex` against current project artifacts and fresh runs.

Fresh runs used:

- `python eval/batch_diagnostic_eval.py --results-path eval/results/batch_diagnostic_results_v3.json --report-path docs/tmp/batch-diagnostic-eval-v3.md`
- full-pipeline obligation coverage one-liner over `case_study/cases/**/*.yaml`
- `python -m pytest tests/ -x -q`
- `python3 eval/latency_benchmark.py --results-path eval/results/latency_benchmark_v2.json`

Primary evidence files:

- `docs/tmp/batch-diagnostic-eval-v3.md`
- `eval/results/batch_diagnostic_results_v3.json`
- `docs/tmp/repair-experiment-v2-results.md`
- `docs/tmp/manual-labeling-30cases.md`
- `eval/results/latency_benchmark_v2.json`
- `taxonomy/obligation_catalog.yaml`
- `taxonomy/error_catalog.yaml`
- `interface/extractor/rust_diagnostic.py`

## Executive Summary

- `MATCH`: batch diagnostic generation success stays at `241/241 (100.0%)`.
- `MATCH`: the stored 54-case A/B experiment table still matches the manuscript table.
- `MISMATCH`: current batch obligation coverage is `227/241 (94.2%)`, not `229/241 (95.1%)`.
- `MISMATCH`: current full-pipeline obligation coverage is `397/412 (96.4%)`; this is a different metric than the paper's 241-case batch number and should not be conflated with it.
- `MISMATCH`: the test suite is now `101 passed`, not `99`.
- `MISMATCH`: the paper's "30 manually labeled cases" taxonomy percentages are actually the 241-case batch percentages.
- `MISMATCH`: fresh latency is now lower than the paper claims: `26.98 ms` median, `42.61 ms` p95, `91.91 ms` max.
- `MISMATCH`: the manuscript's obligation-family count is not supported by the current code. The paper says `15`, the table shows `10` rows, the current catalog has `23` obligation templates, and the renderer has only `8` template-specific obligation-detail entries (`7` unique low-level types).
- `MISMATCH`: the abstract/contribution text says `+25 percentage points` on lowering artifacts, but the stored A/B table is `3/10 -> 6/10`, i.e. `+30pp`.

## Claim-by-Claim Audit

| Claim area | Paper claim | Actual current value | Status | Evidence | Suggested correction |
| --- | --- | --- | --- | --- | --- |
| Evaluation corpus size | `302` scanned, `241` eligible | `302` scanned, `241` eligible | MATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | No change needed. |
| Batch eval success rate | `241/241 (100%)` | `241/241 (100.0%)` | MATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | No change needed. |
| Batch obligation coverage | `229/241 (95.1%)` | `227/241 (94.2%)` | MISMATCH | derived from `eval/results/batch_diagnostic_results_v3.json` via `diagnostic_json.metadata.obligation` | Update paper batch-coverage claims to `227/241 (94.2%)` if the paper continues to use the 241-case benchmark. |
| Full-pipeline obligation coverage | not separately reported in paper | `397/412 (96.4%)` | NEW / DIFFERENT METRIC | requested full-pipeline run over `case_study/cases/**/*.yaml` | If you want a broader current-project number, add this as a separate metric and keep it clearly separate from the 241-case batch benchmark. |
| Batch BTF source correlation | `151/241 (62.7%)` | `151/241 (62.7%)` | MATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | No change needed. |
| Batch proof-established span count | `97/241 (40.2%)` | `103/241 (42.7%)` | MISMATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | Update Table 4 and any prose that quotes this count. |
| Batch proof-lost span count | `82/241 (34.0%)` | `90/241 (37.3%)` | MISMATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | Update Table 4 and any prose that quotes this count. |
| Batch `never_established` count | `124/241 (51.5%)` | `117/241 (48.5%)` | MISMATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | Update Table 4 and the following paragraph. |
| Batch `established_then_lost` count | `81/241 (33.6%)` | `90/241 (37.3%)` | MISMATCH | `docs/tmp/batch-diagnostic-eval-v3.md` | Update Table 4 and the following paragraph. |
| Number of tests | `99` unit tests | `101 passed` | MISMATCH | fresh `pytest` run | Update the manuscript to `101` unless you intentionally want to count a narrower subset than the shipped `tests/` suite. |
| Obligation-family count | text says `15`; Table 1 caption says `15`; Table 1 itself lists `10` rows | current catalog has `23` obligation templates (`OBLIGE-O001`..`OBLIGE-O023`); renderer maps `8` template IDs with `7` unique low-level types | MISMATCH / AMBIGUOUS | `taxonomy/obligation_catalog.yaml`, `taxonomy/error_catalog.yaml`, `interface/extractor/rust_diagnostic.py` | Pick one definition and use it consistently. If you mean catalog entries, update to `23`. If you mean renderer-level formal predicate kinds, the current code supports only `7` unique kinds (`8` mapped template IDs). As written, `15` is unsupported. |
| A/B overall location accuracy | A `53/54 (98.1%)`, B `48/54 (88.9%)` | same | MATCH | `docs/tmp/repair-experiment-v2-results.md` | No change needed. |
| A/B overall fix-type accuracy | A `46/54 (85.2%)`, B `43/54 (79.6%)` | same | MATCH | `docs/tmp/repair-experiment-v2-results.md` | No change needed. |
| A/B lowering-artifact fix-type accuracy | A `3/10 (30%)`, B `6/10 (60%)`, `+30pp` | same | MATCH | `docs/tmp/repair-experiment-v2-results.md` | No change needed in the table. |
| A/B headline improvement wording | abstract/contributions say `+25 percentage points` | stored experiment is `+30pp` on lowering-artifact fix type (`3/10 -> 6/10`) | MISMATCH | `docs/paper/main.tex`, `docs/tmp/repair-experiment-v2-results.md` | Change the abstract/introduction/contribution wording to `+30 percentage points`, or change the metric being described and define it explicitly. |
| Latency median | `33 ms` | `26.977 ms` | MISMATCH | fresh `eval/results/latency_benchmark_v2.json` | Update to `27 ms` median, or explicitly freeze the older benchmark artifact and date it. |
| Latency p95 | `48 ms` | `42.610 ms` | MISMATCH | fresh `eval/results/latency_benchmark_v2.json` | Update to `42.6 ms` p95 if using the fresh benchmark. |
| Latency max | `116 ms` | `91.913 ms` | MISMATCH | fresh `eval/results/latency_benchmark_v2.json` | Update to `91.9 ms` max if using the fresh benchmark. |
| Latency correlation | Pearson `r = 0.68` | Pearson `r = 0.7447` | MISMATCH | fresh `eval/results/latency_benchmark_v2.json` | Update if you want the paper to reflect the current rerun. |
| Taxonomy distribution in "30 manually labeled cases" | `source_bug 45.2%`, `env_mismatch 34.4%`, `lowering_artifact 12.0%`, `verifier_limit 8.3%` | actual 30-case manual distribution is `source_bug 13/30 (43.3%)`, `lowering_artifact 6/30 (20.0%)`, `verifier_limit 5/30 (16.7%)`, `env_mismatch 4/30 (13.3%)`, `verifier_bug 2/30 (6.7%)` | MISMATCH | `docs/tmp/manual-labeling-30cases.md` | Replace the paragraph with the actual manual-label distribution, or relabel the current percentages as the 241-case batch taxonomy distribution. |

## Notes on the Taxonomy Mismatch

The paper's "manual labels" percentages exactly match the current 241-case batch distribution:

- `source_bug`: `109/241 (45.2%)`
- `env_mismatch`: `83/241 (34.4%)`
- `lowering_artifact`: `29/241 (12.0%)`
- `verifier_limit`: `20/241 (8.3%)`

Those are real current numbers, but they are not the 30-case manual-label distribution.

## Recommended Manuscript Edits

- Update the 241-case obligation-coverage claim from `229/241 (95.1%)` to `227/241 (94.2%)`.
- Keep `241/241 (100%)` diagnostic-generation success and `151/241 (62.7%)` BTF correlation; those still match.
- Update the batch proof-status/span rows to the current values: established `103`, lost `90`, `never_established 117`, `established_then_lost 90`.
- Change the test-count claim from `99` to `101`, unless you intentionally document a narrower subset than the full shipped test suite.
- Fix the taxonomy paragraph so it uses the real 30-case manual distribution and includes the current `verifier_bug` bucket.
- Resolve the obligation-family terminology. Right now the paper uses `15`, the table shows `10`, the catalog has `23`, and the renderer has only `8` explicit template mappings.
- Update the abstract/contribution A/B headline from `+25pp` to `+30pp`, which matches the stored 54-case repair report.
- Update latency claims to the fresh rerun numbers (`26.98 ms` median, `42.61 ms` p95, `91.91 ms` max, `r=0.7447`) or freeze the older benchmark artifact and state that the paper is intentionally reporting that dated run.

## Fresh Run Outputs

- Batch eval report: `docs/tmp/batch-diagnostic-eval-v3.md`
- Batch eval raw results: `eval/results/batch_diagnostic_results_v3.json`
- Fresh latency raw results: `eval/results/latency_benchmark_v2.json`
- This audit: `docs/tmp/paper-data-audit.md`
