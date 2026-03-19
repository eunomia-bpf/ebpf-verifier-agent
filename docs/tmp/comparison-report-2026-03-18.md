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
| BPFix | 189/260 | 72.7% | 67.0% to 77.7% |
| Baseline | 192/260 | 73.8% | 68.2% to 78.8% |
| Ablation A | 188/260 | 72.3% | 66.6% to 77.4% |
| Ablation B | 184/260 | 70.8% | 65.0% to 76.0% |
| Ablation C | 183/260 | 70.4% | 64.6% to 75.6% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 74.8% | 92.4% | 82.6% | 157 | 53 | 13 |
| source_bug | Baseline | 74.9% | 91.2% | 82.2% | 155 | 52 | 15 |
| source_bug | Ablation A | 73.0% | 95.3% | 82.7% | 162 | 60 | 8 |
| source_bug | Ablation B | 71.6% | 94.7% | 81.5% | 161 | 64 | 9 |
| source_bug | Ablation C | 71.1% | 95.3% | 81.4% | 162 | 66 | 8 |
| lowering_artifact | BPFix | 61.1% | 36.7% | 45.8% | 11 | 7 | 19 |
| lowering_artifact | Baseline | 65.2% | 50.0% | 56.6% | 15 | 8 | 15 |
| lowering_artifact | Ablation A | 83.3% | 16.7% | 27.8% | 5 | 1 | 25 |
| lowering_artifact | Ablation B | 66.7% | 6.7% | 12.1% | 2 | 1 | 28 |
| lowering_artifact | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 30 |
| env_mismatch | BPFix | 59.3% | 32.0% | 41.6% | 16 | 11 | 34 |
| env_mismatch | Baseline | 66.7% | 32.0% | 43.2% | 16 | 8 | 34 |
| env_mismatch | Ablation A | 59.3% | 32.0% | 41.6% | 16 | 11 | 34 |
| env_mismatch | Ablation B | 59.3% | 32.0% | 41.6% | 16 | 11 | 34 |
| env_mismatch | Ablation C | 59.3% | 32.0% | 41.6% | 16 | 11 | 34 |
| verifier_limit | BPFix | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 83.3% | 90.9% | 5 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 15 | 18 | 0.7283 |
| BPFix vs Ablation A | 6 | 5 | 1.0000 |
| BPFix vs Ablation B | 11 | 6 | 0.3323 |
| BPFix vs Ablation C | 11 | 5 | 0.2101 |

## Core Set

- Labeled cases: `210`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 162/210 | 77.1% | 71.0% to 82.3% |
| Baseline | 164/210 | 78.1% | 72.0% to 83.2% |
| Ablation A | 161/210 | 76.7% | 70.5% to 81.9% |
| Ablation B | 157/210 | 74.8% | 68.5% to 80.2% |
| Ablation C | 156/210 | 74.3% | 68.0% to 79.7% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 81.4% | 92.7% | 86.7% | 140 | 32 | 11 |
| source_bug | Baseline | 80.0% | 92.7% | 85.9% | 140 | 35 | 11 |
| source_bug | Ablation A | 78.8% | 96.0% | 86.6% | 145 | 39 | 6 |
| source_bug | Ablation B | 77.0% | 95.4% | 85.2% | 144 | 43 | 7 |
| source_bug | Ablation C | 76.3% | 96.0% | 85.0% | 145 | 45 | 6 |
| lowering_artifact | BPFix | 61.1% | 47.8% | 53.7% | 11 | 7 | 12 |
| lowering_artifact | Baseline | 72.2% | 56.5% | 63.4% | 13 | 5 | 10 |
| lowering_artifact | Ablation A | 83.3% | 21.7% | 34.5% | 5 | 1 | 18 |
| lowering_artifact | Ablation B | 66.7% | 8.7% | 15.4% | 2 | 1 | 21 |
| lowering_artifact | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 23 |
| env_mismatch | BPFix | 47.1% | 25.8% | 33.3% | 8 | 9 | 23 |
| env_mismatch | Baseline | 57.1% | 25.8% | 35.6% | 8 | 6 | 23 |
| env_mismatch | Ablation A | 47.1% | 25.8% | 33.3% | 8 | 9 | 23 |
| env_mismatch | Ablation B | 47.1% | 25.8% | 33.3% | 8 | 9 | 23 |
| env_mismatch | Ablation C | 47.1% | 25.8% | 33.3% | 8 | 9 | 23 |
| verifier_limit | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Baseline | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Baseline | 12 | 14 | 0.8450 |
| BPFix vs Ablation A | 6 | 5 | 1.0000 |
| BPFix vs Ablation B | 11 | 6 | 0.3323 |
| BPFix vs Ablation C | 11 | 5 | 0.2101 |

## Core vs Full Delta

- BPFix improves from `72.7%` to `77.1%` on the core subset (`+4.5pp`).
- Baseline also improves from `73.8%` to `78.1%` (`+4.2pp`), so the BPFix-vs-baseline gap is nearly unchanged on trace-rich cases.

| Method | Full Accuracy | Core Accuracy | Core - Full |
| --- | ---: | ---: | ---: |
| BPFix | 72.7% | 77.1% | +4.5pp |
| Baseline | 73.8% | 78.1% | +4.2pp |
| Ablation A | 72.3% | 76.7% | +4.4pp |
| Ablation B | 70.8% | 74.8% | +4.0pp |
| Ablation C | 70.4% | 74.3% | +3.9pp |

## Why BPFix Trails Baseline

This section uses the older `ground_truth_labels.yaml` split so it lines up with the cited 70.2% BPFix vs 75.7% baseline comparison.
- Baseline-correct / BPFix-wrong cases: `24`
- `source_bug -> lowering_artifact` within that bucket: `10`

### Confusion Patterns

| Ground Truth | BPFix Prediction | Count |
| --- | ---: | ---: |
| source_bug | lowering_artifact | 10 |
| lowering_artifact | source_bug | 9 |
| lowering_artifact | env_mismatch | 3 |
| source_bug | env_mismatch | 1 |
| verifier_bug | source_bug | 1 |

### Case List

| Case ID | Ground Truth | BPFix | cross_analysis_class |
| --- | ---: | ---: | ---: |
| kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84 | lowering_artifact | env_mismatch | None |
| kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460 | lowering_artifact | env_mismatch | None |
| kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb | lowering_artifact | source_bug | source_bug |
| kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725 | source_bug | lowering_artifact | ambiguous |
| kernel-selftest-dynptr-fail-skb-invalid-data-slice1-tc-0b35a757 | source_bug | lowering_artifact | source_bug |
| kernel-selftest-dynptr-fail-skb-invalid-data-slice3-tc-a15c4322 | source_bug | lowering_artifact | source_bug |
| kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9 | source_bug | env_mismatch | None |
| kernel-selftest-dynptr-fail-xdp-invalid-data-slice1-xdp-c0fa30d5 | source_bug | lowering_artifact | source_bug |
| kernel-selftest-iters-iter-err-too-permissive1-raw-tp-25649784 | source_bug | lowering_artifact | ambiguous |
| kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943 | lowering_artifact | source_bug | source_bug |
| kernel-selftest-iters-iter-err-unsafe-c-loop-raw-tp-4b9ee52e | lowering_artifact | source_bug | source_bug |
| kernel-selftest-iters-looping-wrong-sized-read-fail-raw-tp-b975c554 | lowering_artifact | env_mismatch | None |
| stackoverflow-60506220 | lowering_artifact | source_bug | None |
| stackoverflow-70760516 | source_bug | lowering_artifact | ambiguous |
| stackoverflow-72575736 | source_bug | lowering_artifact | source_bug |
| stackoverflow-74531552 | lowering_artifact | source_bug | source_bug |
| stackoverflow-75643912 | source_bug | lowering_artifact | source_bug |
| stackoverflow-77713434 | lowering_artifact | source_bug | source_bug |
| stackoverflow-79485758 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-1056 | lowering_artifact | source_bug | source_bug |
| github-aya-rs-aya-1062 | lowering_artifact | source_bug | ambiguous |
| github-aya-rs-aya-1267 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-863 | lowering_artifact | source_bug | source_bug |
| github-cilium-cilium-44216 | verifier_bug | source_bug | None |

## Multi-Span Analysis

- Multi-span BPFix outputs: `19/262`
- Concrete `cross_analysis_class` present: `78/262`
- Missing `cross_analysis_class`: `184/262`
- Concrete `cross_analysis_class != source_bug`: `15/262`
- `cross_analysis_class == ambiguous`: `15/262`
- `cross_analysis_class == established_then_lost`: `0/262`
- Any carrier establishment: `6/262`
- Multi-span cases with any carrier establishment: `4/19`
- Interpretation: most eligible cases never emit a concrete `cross_analysis_class`, so the pipeline usually falls back to a single rejected span instead of a richer carrier story.
- Interpretation: carrier establishment is rare and `cross_analysis_class == established_then_lost` never occurs in this run, so the 19 multi-span outputs mostly come from the legacy proof-loss path rather than cross-analysis success cases.

### cross_analysis_class Distribution

| Bucket | All Eligible | Multi-Span Subset |
| --- | ---: | ---: |
| None | 184 | 0 |
| ambiguous | 15 | 8 |
| source_bug | 63 | 11 |
