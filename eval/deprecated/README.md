# Deprecated Eval Scripts

These scripts are superseded by newer versions or were one-off analysis tools. Kept for historical reference.

## Current Active Scripts (in parent eval/ directory)

| Script | Purpose |
|--------|---------|
| batch_diagnostic_eval.py | Main batch evaluation over 262 cases (current pipeline) |
| batch_proof_engine_eval.py | Proof engine evaluation over corpus |
| latency_benchmark.py | End-to-end latency benchmarking |
| pv_comparison_expanded.py | PV vs OBLIGE comparison (262 cases, current) |
| repair_experiment_v3.py | A/B repair experiment v3 (56 cases, current) |
| per_language_eval.py | Per-language (C/Rust/Go) breakdown |
| span_coverage_eval.py | Multi-span coverage evaluation |
| cross_kernel_stability.py | Cross-kernel diagnostic stability |
| cross_log_stability.py | Cross-log offline stability analysis |
| taxonomy_coverage.py | Error catalog coverage analysis |
| llm_comparison.py | Multi-condition LLM experiment |
| pretty_verifier_comparison.py | Pretty Verifier baseline runner |
| metrics.py | Shared metric utilities |

## Deprecated Scripts

| Script | Superseded by | Reason |
|--------|---------------|--------|
| repair_experiment.py | repair_experiment_v3.py | v1 A/B experiment (OpenAI API, 30 cases) |
| repair_experiment_v2.py | repair_experiment_v3.py | v2 manual-bundle approach |
| repair_experiment_v2_rerun.py | repair_experiment_v3.py | v2 paired rerun on current pipeline |
| pv_comparison_v3.py | pv_comparison_expanded.py | 30-case PV comparison (expanded covers 262 cases) |
| diagnoser_30case_evaluation.py | batch_diagnostic_eval.py | Pilot 30-case diagnoser (batch covers 262 cases) |
| formal_engine_comparison.py | — | One-off v3 vs v4 comparison analysis |
| cross_kernel.py | cross_kernel_stability.py | Utility module folded into stability runner |
| generate_synthetic_cases.py | — | One-off synthetic case generator (cases already generated) |
| compile_synthetic_cases.py | — | One-off synthetic case compiler (cases already compiled) |
