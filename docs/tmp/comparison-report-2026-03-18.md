# Comparison Report 2026-03-18

## Inputs

- Results: `eval/results/ablation_results.json`
- Labels: `case_study/ground_truth_v2.yaml`
- Manifest: `case_study/eval_manifest.yaml`
- Eligible cases in comparison run: `260`
- Core-set eligible cases: `210`
- `ground_truth_v2.yaml` is used for the primary tables; the older `ground_truth_labels.yaml` is still used below for the historical 70.2% vs 75.7% gap analysis.

## Full Corpus

- Labeled cases: `260`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 186/260 | 71.5% | 65.8% to 76.7% |
| Baseline | 192/260 | 73.8% | 68.2% to 78.8% |
| Ablation A | 188/260 | 72.3% | 66.6% to 77.4% |
| Ablation B | 184/260 | 70.8% | 65.0% to 76.0% |
| Ablation C | 184/260 | 70.8% | 65.0% to 76.0% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 71.6% | 94.7% | 81.5% | 161 | 64 | 9 |
| source_bug | Baseline | 74.9% | 91.2% | 82.2% | 155 | 52 | 15 |
| source_bug | Ablation A | 71.8% | 95.9% | 82.1% | 163 | 64 | 7 |
| source_bug | Ablation B | 70.4% | 95.3% | 81.0% | 162 | 68 | 8 |
| source_bug | Ablation C | 70.3% | 95.9% | 81.1% | 163 | 69 | 7 |
| lowering_artifact | BPFix | 62.5% | 16.7% | 26.3% | 5 | 3 | 25 |
| lowering_artifact | Baseline | 65.2% | 50.0% | 56.6% | 15 | 8 | 15 |
| lowering_artifact | Ablation A | 83.3% | 16.7% | 27.8% | 5 | 1 | 25 |
| lowering_artifact | Ablation B | 66.7% | 6.7% | 12.1% | 2 | 1 | 28 |
| lowering_artifact | Ablation C | 100.0% | 3.3% | 6.5% | 1 | 0 | 29 |
| env_mismatch | BPFix | 68.2% | 30.0% | 41.7% | 15 | 7 | 35 |
| env_mismatch | Baseline | 66.7% | 32.0% | 43.2% | 16 | 8 | 34 |
| env_mismatch | Ablation A | 68.2% | 30.0% | 41.7% | 15 | 7 | 35 |
| env_mismatch | Ablation B | 68.2% | 30.0% | 41.7% | 15 | 7 | 35 |
| env_mismatch | Ablation C | 68.2% | 30.0% | 41.7% | 15 | 7 | 35 |
| verifier_limit | BPFix | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 11 | 17 | 0.3449 |
| BPFix vs Ablation A | 3 | 5 | 0.7266 |
| BPFix vs Ablation B | 5 | 3 | 0.7266 |
| BPFix vs Ablation C | 4 | 2 | 0.6875 |

## Core Set

- Labeled cases: `210`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 159/210 | 75.7% | 69.5% to 81.0% |
| Baseline | 164/210 | 78.1% | 72.0% to 83.2% |
| Ablation A | 161/210 | 76.7% | 70.5% to 81.9% |
| Ablation B | 157/210 | 74.8% | 68.5% to 80.2% |
| Ablation C | 157/210 | 74.8% | 68.5% to 80.2% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 77.3% | 94.7% | 85.1% | 143 | 42 | 8 |
| source_bug | Baseline | 80.0% | 92.7% | 85.9% | 140 | 35 | 11 |
| source_bug | Ablation A | 77.5% | 96.0% | 85.8% | 145 | 42 | 6 |
| source_bug | Ablation B | 75.8% | 95.4% | 84.5% | 144 | 46 | 7 |
| source_bug | Ablation C | 75.5% | 96.0% | 84.5% | 145 | 47 | 6 |
| lowering_artifact | BPFix | 62.5% | 21.7% | 32.3% | 5 | 3 | 18 |
| lowering_artifact | Baseline | 72.2% | 56.5% | 63.4% | 13 | 5 | 10 |
| lowering_artifact | Ablation A | 83.3% | 21.7% | 34.5% | 5 | 1 | 18 |
| lowering_artifact | Ablation B | 66.7% | 8.7% | 15.4% | 2 | 1 | 21 |
| lowering_artifact | Ablation C | 100.0% | 4.3% | 8.3% | 1 | 0 | 22 |
| env_mismatch | BPFix | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| env_mismatch | Baseline | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| env_mismatch | Ablation A | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| env_mismatch | Ablation B | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| env_mismatch | Ablation C | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| verifier_limit | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 8 | 13 | 0.3833 |
| BPFix vs Ablation A | 3 | 5 | 0.7266 |
| BPFix vs Ablation B | 5 | 3 | 0.7266 |
| BPFix vs Ablation C | 4 | 2 | 0.6875 |

## Core vs Full Delta

- BPFix improves from `71.5%` to `75.7%` on the core subset (`+4.2pp`).
- Baseline also improves from `73.8%` to `78.1%` (`+4.2pp`), so the BPFix-vs-baseline gap is nearly unchanged on trace-rich cases.

| Method | Full Accuracy | Core Accuracy | Core - Full |
| --- | ---: | ---: | ---: |
| BPFix | 71.5% | 75.7% | +4.2pp |
| Baseline | 73.8% | 78.1% | +4.2pp |
| Ablation A | 72.3% | 76.7% | +4.4pp |
| Ablation B | 70.8% | 74.8% | +4.0pp |
| Ablation C | 70.8% | 74.8% | +4.0pp |

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
