# Comparison Report

## Inputs

- Results: `eval/results/ablation_results.json`
- Labels: `case_study/ground_truth.yaml`
- Manifest: `case_study/eval_manifest.yaml`
- Labeled comparison cases: `136`
- Selftest cases: `85`
- Real-world cases: `51`
- `All Cases` combines the selftest and real-world strata.
- `Regex Baseline` is the message-only, PV-equivalent baseline; it parses verifier tail messages without trace analysis.
- `ground_truth.yaml` is used for the primary tables; the older `ground_truth_labels.yaml` is still used below for the historical 70.2% vs 75.7% gap analysis.
- Quarantined cases in `ground_truth.yaml` are excluded from the primary tables.

## Selftest Cases

- `kernel_selftests` cases only.

- Labeled cases: `85`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 81/85 | 95.3% | 88.5% to 98.2% |
| Regex Baseline | 78/85 | 91.8% | 84.0% to 96.0% |
| Ablation A | 83/85 | 97.6% | 91.8% to 99.4% |
| Ablation B | 82/85 | 96.5% | 90.1% to 98.8% |
| Ablation C | 83/85 | 97.6% | 91.8% to 99.4% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 98.7% | 96.1% | 97.4% | 74 | 1 | 3 |
| source_bug | Regex Baseline | 98.6% | 92.2% | 95.3% | 71 | 1 | 6 |
| source_bug | Ablation A | 98.7% | 98.7% | 98.7% | 76 | 1 | 1 |
| source_bug | Ablation B | 98.7% | 97.4% | 98.0% | 75 | 1 | 2 |
| source_bug | Ablation C | 98.7% | 98.7% | 98.7% | 76 | 1 | 1 |
| lowering_artifact | BPFix | 0.0% | 0.0% | 0.0% | 0 | 2 | 0 |
| lowering_artifact | Regex Baseline | 0.0% | 0.0% | 0.0% | 0 | 5 | 0 |
| lowering_artifact | Ablation A | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 |
| lowering_artifact | Ablation B | 0.0% | 0.0% | 0.0% | 0 | 1 | 0 |
| lowering_artifact | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 |
| env_mismatch | BPFix | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Regex Baseline | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation A | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation B | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation C | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| verifier_limit | BPFix | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation A | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation B | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation C | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| Macro-F1 | BPFix | n/a | n/a | 70.2% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 69.7% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 70.5% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 70.3% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 70.5% | n/a | n/a | n/a |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Regex Baseline | 5 | 2 | 0.4531 |
| BPFix vs Ablation A | 0 | 2 | 0.5000 |
| BPFix vs Ablation B | 1 | 2 | 1.0000 |
| BPFix vs Ablation C | 0 | 2 | 0.5000 |

## Real-World Cases

- Stack Overflow + GitHub issue cases only.

- Labeled cases: `51`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 28/51 | 54.9% | 41.4% to 67.7% |
| Regex Baseline | 32/51 | 62.7% | 49.0% to 74.7% |
| Ablation A | 30/51 | 58.8% | 45.2% to 71.2% |
| Ablation B | 29/51 | 56.9% | 43.3% to 69.5% |
| Ablation C | 28/51 | 54.9% | 41.4% to 67.7% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 50.0% | 91.3% | 64.6% | 21 | 21 | 2 |
| source_bug | Regex Baseline | 55.9% | 82.6% | 66.7% | 19 | 15 | 4 |
| source_bug | Ablation A | 52.4% | 95.7% | 67.7% | 22 | 20 | 1 |
| source_bug | Ablation B | 51.1% | 100.0% | 67.6% | 23 | 22 | 0 |
| source_bug | Ablation C | 50.0% | 100.0% | 66.7% | 23 | 23 | 0 |
| lowering_artifact | BPFix | 60.0% | 16.7% | 26.1% | 3 | 2 | 15 |
| lowering_artifact | Regex Baseline | 72.7% | 44.4% | 55.2% | 8 | 3 | 10 |
| lowering_artifact | Ablation A | 80.0% | 22.2% | 34.8% | 4 | 1 | 14 |
| lowering_artifact | Ablation B | 100.0% | 11.1% | 20.0% | 2 | 0 | 16 |
| lowering_artifact | Ablation C | 100.0% | 5.6% | 10.5% | 1 | 0 | 17 |
| env_mismatch | BPFix | 100.0% | 37.5% | 54.5% | 3 | 0 | 5 |
| env_mismatch | Regex Baseline | 75.0% | 37.5% | 50.0% | 3 | 1 | 5 |
| env_mismatch | Ablation A | 100.0% | 37.5% | 54.5% | 3 | 0 | 5 |
| env_mismatch | Ablation B | 100.0% | 37.5% | 54.5% | 3 | 0 | 5 |
| env_mismatch | Ablation C | 100.0% | 37.5% | 54.5% | 3 | 0 | 5 |
| verifier_limit | BPFix | 100.0% | 50.0% | 66.7% | 1 | 0 | 1 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation A | 100.0% | 50.0% | 66.7% | 1 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 50.0% | 66.7% | 1 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 50.0% | 66.7% | 1 | 0 | 1 |
| Macro-F1 | BPFix | n/a | n/a | 53.0% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 68.0% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 55.9% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 52.2% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 49.6% | n/a | n/a | n/a |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Regex Baseline | 5 | 9 | 0.4240 |
| BPFix vs Ablation A | 3 | 5 | 0.7266 |
| BPFix vs Ablation B | 2 | 3 | 1.0000 |
| BPFix vs Ablation C | 2 | 2 | 1.0000 |

## All Cases

- Combined selftest + real-world comparison slice.

- Labeled cases: `136`

### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 109/136 | 80.1% | 72.7% to 86.0% |
| Regex Baseline | 110/136 | 80.9% | 73.5% to 86.6% |
| Ablation A | 113/136 | 83.1% | 75.9% to 88.5% |
| Ablation B | 111/136 | 81.6% | 74.3% to 87.2% |
| Ablation C | 111/136 | 81.6% | 74.3% to 87.2% |

### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 81.2% | 95.0% | 87.6% | 95 | 22 | 5 |
| source_bug | Regex Baseline | 84.9% | 90.0% | 87.4% | 90 | 16 | 10 |
| source_bug | Ablation A | 82.4% | 98.0% | 89.5% | 98 | 21 | 2 |
| source_bug | Ablation B | 81.0% | 98.0% | 88.7% | 98 | 23 | 2 |
| source_bug | Ablation C | 80.5% | 99.0% | 88.8% | 99 | 24 | 1 |
| lowering_artifact | BPFix | 42.9% | 16.7% | 24.0% | 3 | 4 | 15 |
| lowering_artifact | Regex Baseline | 50.0% | 44.4% | 47.1% | 8 | 8 | 10 |
| lowering_artifact | Ablation A | 80.0% | 22.2% | 34.8% | 4 | 1 | 14 |
| lowering_artifact | Ablation B | 66.7% | 11.1% | 19.0% | 2 | 1 | 16 |
| lowering_artifact | Ablation C | 100.0% | 5.6% | 10.5% | 1 | 0 | 17 |
| env_mismatch | BPFix | 88.9% | 57.1% | 69.6% | 8 | 1 | 6 |
| env_mismatch | Regex Baseline | 80.0% | 57.1% | 66.7% | 8 | 2 | 6 |
| env_mismatch | Ablation A | 88.9% | 57.1% | 69.6% | 8 | 1 | 6 |
| env_mismatch | Ablation B | 88.9% | 57.1% | 69.6% | 8 | 1 | 6 |
| env_mismatch | Ablation C | 88.9% | 57.1% | 69.6% | 8 | 1 | 6 |
| verifier_limit | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 4 | 0 | 0 |
| verifier_limit | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| Macro-F1 | BPFix | n/a | n/a | 66.7% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 75.3% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 69.9% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 65.8% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 63.6% | n/a | n/a | n/a |

### McNemar Tests

| Comparison | BPFix-only correct | Other-only correct | Exact p |
| --- | ---: | ---: | ---: |
| BPFix vs Regex Baseline | 10 | 11 | 1.0000 |
| BPFix vs Ablation A | 3 | 7 | 0.3438 |
| BPFix vs Ablation B | 3 | 5 | 0.7266 |
| BPFix vs Ablation C | 2 | 4 | 0.6875 |

## Source-Stratified Results

### kernel_selftests

- Labeled cases: `85`

#### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 81/85 | 95.3% | 88.5% to 98.2% |
| Regex Baseline | 78/85 | 91.8% | 84.0% to 96.0% |
| Ablation A | 83/85 | 97.6% | 91.8% to 99.4% |
| Ablation B | 82/85 | 96.5% | 90.1% to 98.8% |
| Ablation C | 83/85 | 97.6% | 91.8% to 99.4% |

#### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 98.7% | 96.1% | 97.4% | 74 | 1 | 3 |
| source_bug | Regex Baseline | 98.6% | 92.2% | 95.3% | 71 | 1 | 6 |
| source_bug | Ablation A | 98.7% | 98.7% | 98.7% | 76 | 1 | 1 |
| source_bug | Ablation B | 98.7% | 97.4% | 98.0% | 75 | 1 | 2 |
| source_bug | Ablation C | 98.7% | 98.7% | 98.7% | 76 | 1 | 1 |
| lowering_artifact | BPFix | 0.0% | 0.0% | 0.0% | 0 | 2 | 0 |
| lowering_artifact | Regex Baseline | 0.0% | 0.0% | 0.0% | 0 | 5 | 0 |
| lowering_artifact | Ablation A | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 |
| lowering_artifact | Ablation B | 0.0% | 0.0% | 0.0% | 0 | 1 | 0 |
| lowering_artifact | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 |
| env_mismatch | BPFix | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Regex Baseline | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation A | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation B | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| env_mismatch | Ablation C | 83.3% | 83.3% | 83.3% | 5 | 1 | 1 |
| verifier_limit | BPFix | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation A | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation B | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| verifier_limit | Ablation C | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| Macro-F1 | BPFix | n/a | n/a | 70.2% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 69.7% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 70.5% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 70.3% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 70.5% | n/a | n/a | n/a |

### stackoverflow

- Labeled cases: `41`

#### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 24/41 | 58.5% | 43.4% to 72.2% |
| Regex Baseline | 23/41 | 56.1% | 41.0% to 70.1% |
| Ablation A | 24/41 | 58.5% | 43.4% to 72.2% |
| Ablation B | 23/41 | 56.1% | 41.0% to 70.1% |
| Ablation C | 22/41 | 53.7% | 38.7% to 67.9% |

#### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 54.1% | 100.0% | 70.2% | 20 | 17 | 0 |
| source_bug | Regex Baseline | 53.3% | 80.0% | 64.0% | 16 | 14 | 4 |
| source_bug | Ablation A | 54.3% | 95.0% | 69.1% | 19 | 16 | 1 |
| source_bug | Ablation B | 52.6% | 100.0% | 69.0% | 20 | 18 | 0 |
| source_bug | Ablation C | 51.3% | 100.0% | 67.8% | 20 | 19 | 0 |
| lowering_artifact | BPFix | 100.0% | 18.8% | 31.6% | 3 | 0 | 13 |
| lowering_artifact | Regex Baseline | 66.7% | 37.5% | 48.0% | 6 | 3 | 10 |
| lowering_artifact | Ablation A | 80.0% | 25.0% | 38.1% | 4 | 1 | 12 |
| lowering_artifact | Ablation B | 100.0% | 12.5% | 22.2% | 2 | 0 | 14 |
| lowering_artifact | Ablation C | 100.0% | 6.2% | 11.8% | 1 | 0 | 15 |
| env_mismatch | BPFix | 0.0% | 0.0% | 0.0% | 0 | 0 | 4 |
| env_mismatch | Regex Baseline | 0.0% | 0.0% | 0.0% | 0 | 1 | 4 |
| env_mismatch | Ablation A | 0.0% | 0.0% | 0.0% | 0 | 0 | 4 |
| env_mismatch | Ablation B | 0.0% | 0.0% | 0.0% | 0 | 0 | 4 |
| env_mismatch | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 4 |
| verifier_limit | BPFix | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| verifier_limit | Ablation A | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| verifier_limit | Ablation B | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| verifier_limit | Ablation C | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| Macro-F1 | BPFix | n/a | n/a | 50.4% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 53.0% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 51.8% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 47.8% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 44.9% | n/a | n/a | n/a |

### github_issues

- Labeled cases: `10`

#### Overall Accuracy

| Method | Correct / N | Accuracy | Wilson 95% CI |
| --- | ---: | ---: | ---: |
| BPFix | 4/10 | 40.0% | 16.8% to 68.7% |
| Regex Baseline | 9/10 | 90.0% | 59.6% to 98.2% |
| Ablation A | 6/10 | 60.0% | 31.3% to 83.2% |
| Ablation B | 6/10 | 60.0% | 31.3% to 83.2% |
| Ablation C | 6/10 | 60.0% | 31.3% to 83.2% |

#### Per-Class Precision / Recall / F1

| Class | Method | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source_bug | BPFix | 20.0% | 33.3% | 25.0% | 1 | 4 | 2 |
| source_bug | Regex Baseline | 75.0% | 100.0% | 85.7% | 3 | 1 | 0 |
| source_bug | Ablation A | 42.9% | 100.0% | 60.0% | 3 | 4 | 0 |
| source_bug | Ablation B | 42.9% | 100.0% | 60.0% | 3 | 4 | 0 |
| source_bug | Ablation C | 42.9% | 100.0% | 60.0% | 3 | 4 | 0 |
| lowering_artifact | BPFix | 0.0% | 0.0% | 0.0% | 0 | 2 | 2 |
| lowering_artifact | Regex Baseline | 100.0% | 100.0% | 100.0% | 2 | 0 | 0 |
| lowering_artifact | Ablation A | 0.0% | 0.0% | 0.0% | 0 | 0 | 2 |
| lowering_artifact | Ablation B | 0.0% | 0.0% | 0.0% | 0 | 0 | 2 |
| lowering_artifact | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 2 |
| env_mismatch | BPFix | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| env_mismatch | Regex Baseline | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| env_mismatch | Ablation A | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| env_mismatch | Ablation B | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| env_mismatch | Ablation C | 100.0% | 75.0% | 85.7% | 3 | 0 | 1 |
| verifier_limit | BPFix | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 |
| verifier_limit | Regex Baseline | 100.0% | 100.0% | 100.0% | 1 | 0 | 0 |
| verifier_limit | Ablation A | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 |
| verifier_limit | Ablation B | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 |
| verifier_limit | Ablation C | 0.0% | 0.0% | 0.0% | 0 | 0 | 1 |
| Macro-F1 | BPFix | n/a | n/a | 27.7% | n/a | n/a | n/a |
| Macro-F1 | Regex Baseline | n/a | n/a | 92.9% | n/a | n/a | n/a |
| Macro-F1 | Ablation A | n/a | n/a | 36.4% | n/a | n/a | n/a |
| Macro-F1 | Ablation B | n/a | n/a | 36.4% | n/a | n/a | n/a |
| Macro-F1 | Ablation C | n/a | n/a | 36.4% | n/a | n/a | n/a |

## Why BPFix Trails Baseline

This section uses the older `ground_truth_labels.yaml` split so it lines up with the cited 70.2% BPFix vs 75.7% baseline comparison.
- Baseline-correct / BPFix-wrong cases: `23`
- `source_bug -> lowering_artifact` within that bucket: `5`

### Confusion Patterns

| Ground Truth | BPFix Prediction | Count |
| --- | ---: | ---: |
| lowering_artifact | source_bug | 15 |
| source_bug | lowering_artifact | 5 |
| env_mismatch | source_bug | 1 |
| verifier_bug | source_bug | 1 |
| verifier_limit | source_bug | 1 |

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
| stackoverflow-74178703 | lowering_artifact | source_bug | ambiguous |
| stackoverflow-74531552 | lowering_artifact | source_bug | source_bug |
| stackoverflow-77713434 | lowering_artifact | source_bug | source_bug |
| stackoverflow-78236856 | lowering_artifact | source_bug | source_bug |
| stackoverflow-79485758 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-1056 | lowering_artifact | source_bug | source_bug |
| github-aya-rs-aya-1062 | lowering_artifact | source_bug | ambiguous |
| github-aya-rs-aya-1267 | source_bug | lowering_artifact | ambiguous |
| github-aya-rs-aya-863 | lowering_artifact | source_bug | source_bug |
| github-cilium-cilium-35182 | env_mismatch | source_bug | None |
| github-cilium-cilium-41412 | verifier_limit | source_bug | None |
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
