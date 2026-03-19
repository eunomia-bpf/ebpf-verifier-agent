# Comparison Report 2026-03-18

## Inputs

- Results: `eval/results/ablation_results.json`
- Labels: `case_study/ground_truth.yaml`
- Manifest: `case_study/eval_manifest.yaml`
- Eligible cases in comparison run: `136`
- Core-set eligible cases: `136`
- `ground_truth.yaml` is used for the primary tables; the older `ground_truth_labels.yaml` is still used below for the historical 70.2% vs 75.7% gap analysis.
- Quarantined cases in `ground_truth.yaml` are excluded from the primary tables.

## Full Corpus

- Labeled cases: `136`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 108/136 | 79.4% | 71.9% to 85.4% |
| Baseline | 105/136 | 77.2% | 69.5% to 83.5% |
| Ablation A | 112/136 | 82.4% | 75.1% to 87.8% |
| Ablation B | 110/136 | 80.9% | 73.5% to 86.6% |
| Ablation C | 110/136 | 80.9% | 73.5% to 86.6% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 80.5% | 95.0% | 87.2% | 95 | 23 | 5 |
| source_bug | Baseline | 81.7% | 89.0% | 85.2% | 89 | 20 | 11 |
| source_bug | Ablation A | 81.7% | 98.0% | 89.1% | 98 | 22 | 2 |
| source_bug | Ablation B | 80.3% | 98.0% | 88.3% | 98 | 24 | 2 |
| source_bug | Ablation C | 79.8% | 99.0% | 88.4% | 99 | 25 | 1 |
| lowering_artifact | BPFix | 42.9% | 16.7% | 24.0% | 3 | 4 | 15 |
| lowering_artifact | Baseline | 37.5% | 33.3% | 35.3% | 6 | 10 | 12 |
| lowering_artifact | Ablation A | 80.0% | 22.2% | 34.8% | 4 | 1 | 14 |
| lowering_artifact | Ablation B | 66.7% | 11.1% | 19.0% | 2 | 1 | 16 |
| lowering_artifact | Ablation C | 100.0% | 5.6% | 10.5% | 1 | 0 | 17 |
| env_mismatch | BPFix | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Baseline | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation A | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation B | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation C | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| verifier_limit | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 11 | 8 | 0.6476 |
| BPFix vs Ablation A | 3 | 7 | 0.3438 |
| BPFix vs Ablation B | 3 | 5 | 0.7266 |
| BPFix vs Ablation C | 2 | 4 | 0.6875 |

## Core Set

- Labeled cases: `136`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 108/136 | 79.4% | 71.9% to 85.4% |
| Baseline | 105/136 | 77.2% | 69.5% to 83.5% |
| Ablation A | 112/136 | 82.4% | 75.1% to 87.8% |
| Ablation B | 110/136 | 80.9% | 73.5% to 86.6% |
| Ablation C | 110/136 | 80.9% | 73.5% to 86.6% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 80.5% | 95.0% | 87.2% | 95 | 23 | 5 |
| source_bug | Baseline | 81.7% | 89.0% | 85.2% | 89 | 20 | 11 |
| source_bug | Ablation A | 81.7% | 98.0% | 89.1% | 98 | 22 | 2 |
| source_bug | Ablation B | 80.3% | 98.0% | 88.3% | 98 | 24 | 2 |
| source_bug | Ablation C | 79.8% | 99.0% | 88.4% | 99 | 25 | 1 |
| lowering_artifact | BPFix | 42.9% | 16.7% | 24.0% | 3 | 4 | 15 |
| lowering_artifact | Baseline | 37.5% | 33.3% | 35.3% | 6 | 10 | 12 |
| lowering_artifact | Ablation A | 80.0% | 22.2% | 34.8% | 4 | 1 | 14 |
| lowering_artifact | Ablation B | 66.7% | 11.1% | 19.0% | 2 | 1 | 16 |
| lowering_artifact | Ablation C | 100.0% | 5.6% | 10.5% | 1 | 0 | 17 |
| env_mismatch | BPFix | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Baseline | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation A | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation B | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| env_mismatch | Ablation C | 87.5% | 50.0% | 63.6% | 7 | 1 | 7 |
| verifier_limit | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 11 | 8 | 0.6476 |
| BPFix vs Ablation A | 3 | 7 | 0.3438 |
| BPFix vs Ablation B | 3 | 5 | 0.7266 |
| BPFix vs Ablation C | 2 | 4 | 0.6875 |

## Core vs Full Delta

- BPFix improves from `79.4%` to `79.4%` on the core subset (`+0.0pp`).
- Baseline also improves from `77.2%` to `77.2%` (`+0.0pp`), so the BPFix-vs-baseline gap is nearly unchanged on trace-rich cases.

| Method | Full Accuracy | Core Accuracy | Core - Full |
| --- | ---: | ---: | ---: |
| BPFix | 79.4% | 79.4% | +0.0pp |
| Baseline | 77.2% | 77.2% | +0.0pp |
| Ablation A | 82.4% | 82.4% | +0.0pp |
| Ablation B | 80.9% | 80.9% | +0.0pp |
| Ablation C | 80.9% | 80.9% | +0.0pp |

## Why BPFix Trails Baseline

This section uses the older `ground_truth_labels.yaml` split so it lines up with the cited 70.2% BPFix vs 75.7% baseline comparison.
- Baseline-correct / BPFix-wrong cases: `21`
- `source_bug -> lowering_artifact` within that bucket: `5`

### Confusion Patterns

| Ground Truth | BPFix Prediction | Count |
| --- | ---: | ---: |
| lowering_artifact | source_bug | 14 |
| source_bug | lowering_artifact | 5 |
| env_mismatch | source_bug | 1 |
| verifier_bug | source_bug | 1 |

### Case List

| Case ID | Ground Truth | BPFix | cross_analysis_class |
| --- | ---: | ---: | ---: |
| kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84 | lowering_artifact | source_bug | source_bug |
| kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460 | lowering_artifact | source_bug | source_bug |
| kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49 | lowering_artifact | source_bug | source_bug |
| kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb | lowering_artifact | source_bug | source_bug |
| kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725 | source_bug | lowering_artifact | ambiguous |
| kernel-selftest-iters-iter-err-too-permissive1-raw-tp-25649784 | source_bug | lowering_artifact | ambiguous |
| kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943 | lowering_artifact | source_bug | source_bug |
| kernel-selftest-iters-iter-err-unsafe-c-loop-raw-tp-4b9ee52e | lowering_artifact | source_bug | source_bug |
| kernel-selftest-iters-looping-wrong-sized-read-fail-raw-tp-b975c554 | lowering_artifact | source_bug | source_bug |
| stackoverflow-60506220 | lowering_artifact | source_bug | None |
| stackoverflow-70760516 | source_bug | lowering_artifact | ambiguous |
| stackoverflow-74531552 | lowering_artifact | source_bug | source_bug |
| stackoverflow-77713434 | lowering_artifact | source_bug | source_bug |
| stackoverflow-78236856 | lowering_artifact | source_bug | source_bug |
| stackoverflow-79485758 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-1056 | lowering_artifact | source_bug | source_bug |
| github-aya-rs-aya-1062 | lowering_artifact | source_bug | ambiguous |
| github-aya-rs-aya-1267 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-863 | lowering_artifact | source_bug | source_bug |
| github-cilium-cilium-35182 | env_mismatch | source_bug | None |
| github-cilium-cilium-44216 | verifier_bug | source_bug | None |

## Multi-Span Analysis

- Multi-span BPFix outputs: `21/262`
- Concrete `cross_analysis_class` present: `81/262`
- Missing `cross_analysis_class`: `181/262`
- Concrete `cross_analysis_class != source_bug`: `16/262`
- `cross_analysis_class == ambiguous`: `15/262`
- `cross_analysis_class == established_then_lost`: `1/262`
- Any carrier establishment: `6/262`
- Multi-span cases with any carrier establishment: `4/21`
- Interpretation: most eligible cases never emit a concrete `cross_analysis_class`, so the pipeline usually falls back to a single rejected span instead of a richer carrier story.
- Interpretation: carrier establishment is rare, but `cross_analysis_class == established_then_lost` does appear in `1/262` eligible cases, so only a small slice of the 21 multi-span outputs come from explicit cross-analysis loss tracking.

### cross_analysis_class Distribution

| Bucket | All Eligible | Multi-Span Subset |
| --- | ---: | ---: |
| None | 181 | 0 |
| ambiguous | 15 | 8 |
| established_then_lost | 1 | 1 |
| source_bug | 65 | 12 |
