# eval/

Evaluation infrastructure for BPFix. All scripts are standalone Python
programs. Results are written to `eval/results/` (gitignored except
`taxonomy_coverage.json`).

## Current (Active) Scripts

| Script | Research Question | Output |
|--------|------------------|--------|
| `batch_diagnostic_eval.py` | Q1: classification accuracy; Q2: span production rate across 241-case corpus | `results/batch_diagnostic_results*.json` |
| `span_coverage_eval.py` | Q3: do BPFix spans cover known fix locations? | `results/span_coverage_results.json` |
| `repair_experiment_v2.py` | Q4: A/B LLM repair — raw log vs BPFix diagnostic | `results/repair_experiment_results.v2.json` |
| `pv_comparison_v3.py` | Q5: BPFix vs Pretty Verifier on 30-case benchmark | `results/pv_comparison_v3.json` |
| `latency_benchmark.py` | Q6: end-to-end and per-stage runtime overhead | `results/latency_benchmark*.json` |
| `batch_proof_engine_eval.py` | Proof engine ablation (obligation coverage) | `results/batch_proof_engine_round3.json` |

### Running

```bash
# Unit tests
python -m pytest tests/ -x -q

# Individual eval scripts (all standalone)
python eval/batch_diagnostic_eval.py
python eval/span_coverage_eval.py
python eval/latency_benchmark.py
```

## Historical / Archived Scripts

These are still runnable but have been superseded by newer versions.

| Script | Notes |
|--------|-------|
| `diagnoser_30case_evaluation.py` | v1 evaluator on 30 manually labeled cases; superseded by `batch_diagnostic_eval.py` |
| `repair_experiment.py` | v1 A/B repair experiment; superseded by `repair_experiment_v2.py` (v2 imports from v1 for shared helpers) |
| `repair_experiment_v2_rerun.py` | Reruns v2 with a fixed pipeline |
| `llm_comparison.py` | Multi-condition LLM taxonomy classification study; proved classification is not the contribution (95-100% ceiling across all conditions) |
| `pretty_verifier_comparison.py` | Earlier PV comparison; superseded by `pv_comparison_v3.py` |
| `cross_kernel.py`, `cross_kernel_stability.py`, `cross_log_stability.py` | Cross-kernel and cross-log stability analyses |
| `taxonomy_coverage.py` | Error catalog coverage analysis |

## Data Generation Scripts

| Script | Notes |
|--------|-------|
| `generate_synthetic_cases.py` | Generates `eval_commits_synthetic/` corpus from `eval_commits/` buggy snippets |
| `compile_synthetic_cases.py` | Attempted compilation of synthetic cases to obtain verifier logs (0/20 success in pilot) |

## Results Directory

`eval/results/` contains JSON outputs from all evaluation runs. Only
`taxonomy_coverage.json` is tracked by git; all other result files are
gitignored (regenerate by re-running the scripts).

## Metrics

`metrics.py` defines shared metric computation helpers used across scripts.
