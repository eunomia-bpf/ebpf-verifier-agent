# OBLIGE Engine Evaluation — Batch + Ground Truth

Date: 2026-03-13

## Batch Evaluation (171 cases with logs)

Total case files: 1431. Cases with non-empty verifier logs: 171.
All 171 processed without errors (0 crashes, 0 exceptions).

### Proof Status Distribution

| Proof Status              | Count |
|---------------------------|-------|
| unknown                   |  94   |
| never_established         |  54   |
| established_then_lost     |  19   |
| established_but_insufficient |  4 |

### Predicted Failure Class Distribution

| Failure Class      | Count |
|--------------------|-------|
| source_bug         |  89   |
| env_mismatch       |  75   |
| lowering_artifact  |   5   |
| verifier_limit     |   2   |

### Multi-Span Diagnostics

23/171 (13.5%) cases produced multi-span diagnostics (more than one annotated proof span).

---

## Ground Truth Validation (171 cases with logs, 292 GT labels total)

### Setup
- Ground truth: `case_study/ground_truth_labels.yaml` — 292 labeled cases across 5 classes.
- 121 GT cases had no verifier log and were skipped.
- 171 GT cases had logs and were evaluated.

### Overall Accuracy

**96/171 — 56.1%**

### Per-Class Accuracy

| GT Class          | Correct | Total | Accuracy |
|-------------------|---------|-------|----------|
| env_mismatch      |  14     |  26   | 53.8%    |
| lowering_artifact |   3     |   7   | 42.9%    |
| source_bug        |  77     | 136   | 56.6%    |
| verifier_limit    |   2     |   2   | 100.0%   |

### Confusion Matrix (rows = GT, cols = predicted)

|                   | env_mismatch | lowering_artifact | source_bug | verifier_limit |
|-------------------|:------------:|:-----------------:|:----------:|:--------------:|
| env_mismatch      |     14       |         0         |     12     |       0        |
| lowering_artifact |      4       |         3         |      0     |       0        |
| source_bug        |     57       |         2         |     77     |       0        |
| verifier_limit    |      0       |         0         |      0     |       2        |

---

## Key Findings

1. **Zero crash rate**: The engine successfully processed all 171 cases with logs (0% crash vs PV baseline of 10.7%).

2. **Taxonomy accuracy is 56.1%**, significantly below the target of 80%+. The primary failure mode is over-predicting `env_mismatch`: 57 `source_bug` cases and 4 `lowering_artifact` cases are predicted as `env_mismatch`. This suggests the heuristics for distinguishing `source_bug` from `env_mismatch` are too aggressive toward `env_mismatch`.

3. **`source_bug` recall is 56.6%** (77/136). The largest error bucket is `source_bug` predicted as `env_mismatch` (57 cases). These are likely cases where a dynptr, kfunc, or helper-usage error triggers an `env_mismatch` keyword match even though the root cause is a programmer logic error.

4. **`lowering_artifact` recall is 42.9%** (3/7), with 4 cases misclassified as `env_mismatch`. This is a small class in the evaluated set; the 37 skipped `lowering_artifact` cases (no log) suppress the true picture.

5. **Multi-span rate is 13.5%** (23/171). The engine identifies a causal chain spanning multiple instructions in roughly 1 in 7 cases.

6. **Proof status coverage**: 45.0% of cases have a non-trivial proof status (never_established, established_then_lost, or established_but_insufficient), showing active trace analysis beyond the error-line fallback.

## Recommended Next Steps

- Fix the `env_mismatch` over-prediction: tighten the keyword list or add a secondary discriminator that checks whether the rejected helper/kfunc is documented as available for the program type.
- Investigate the 57 `source_bug → env_mismatch` mismatches using the first 10 mismatch case IDs to identify common patterns.
- Increase log coverage: 121/292 GT cases have no log; reproducing those logs would expand the usable eval set significantly.
