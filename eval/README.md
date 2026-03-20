# eval/

Evaluation scripts for BPFix. Most scripts are standalone Python entrypoints that read
stored case-study YAML logs and write JSON or Markdown artifacts under `eval/results/`
and `docs/tmp/`.

## Core Artifact-Driven Evaluations

| Script | Purpose | Outputs |
|--------|---------|---------|
| `baseline_eval.py` | Regex baseline on labeled comparison cases | `eval/results/baseline_results.json` |
| `batch_diagnostic_eval.py` | Run BPFix on stored verifier logs from the case-study corpus | `eval/results/batch_diagnostic_results.json`, `docs/tmp/batch-diagnostic-eval.md` |
| `localization_eval.py` | Compare stored BPFix proof spans against `case_study/ground_truth.yaml` | `eval/results/localization_eval.json`, `docs/tmp/localization-eval-report.md` |
| `fix_type_eval.py` | Compare stored BPFix repair hints against `case_study/ground_truth.yaml` | `eval/results/fix_type_eval.json`, `docs/tmp/fix-type-eval-report.md` |
| `latency_benchmark.py` | Benchmark diagnostic latency on stored verifier logs | `eval/results/latency_benchmark.json` |
| `per_language_eval.py` | Per-language breakdown derived from batch results | `eval/results/per_language_eval.json`, `docs/tmp/per-language-eval.md` |
| `ablation_eval.py` | Compare BPFix, regex baseline, and ablation variants | `eval/results/ablation_results.json` |
| `comparison_report.py` | Render the comparison report from ablation results | `docs/tmp/comparison-report.md` |
| `batch_proof_engine_eval.py` | Batch-check proof-engine status on stored verifier logs | `eval/results/batch_proof_engine_round3.json` |
| `span_coverage_eval.py` | Measure whether BPFix spans cover known fix locations | `eval/results/span_coverage_results.json`, `docs/tmp/span-coverage-eval.md` |
| `root_cause_validation.py` | Validate proof-loss spans against known fix diffs | `eval/results/root_cause_validation.json`, `docs/tmp/root-cause-validation-results.md` |
| `taxonomy_coverage.py` | Catalog coverage analysis over collected logs | `eval/results/taxonomy_coverage.json`, `docs/tmp/taxonomy-coverage-report.md` |
| `summarize_eval_refresh.py` | Assemble a refresh report from manifest and eval outputs | `docs/tmp/eval-refresh.md` |

## Kernel-Touching Evaluation Utilities

| Script | Purpose |
|--------|---------|
| `verifier_oracle.py` | Compile snippets, run `bpftool prog load`, and capture fresh verifier logs |
| `cross_kernel_stability.py` | Re-run cases across local kernel/toolchain configurations |
| `repair_experiment_v3.py` | LLM repair experiment using raw logs vs BPFix diagnostics |
| `repair_experiment_v4.py` | Qwen-based variant of the same repair experiment |

## Notes

- `case_study/ground_truth.yaml` is the canonical ground-truth label file used by current evaluations.
- `make eval-all` runs the core artifact-driven pipeline only. It does not compile programs or invoke `bpftool`.
- Historical and one-off experiment scripts remain in this directory, but they are not part of the default Makefile pipeline.
