# Fix-Type Evaluation

- Generated at: `2026-03-19T20:04:13+00:00`
- Evaluated labeled cases: `136`
- Fix-type exact match: `99/136 (72.8%)`

## By Source Stratum

| Stratum | Cases | Fix-Type Match |
| --- | --- | --- |
| Selftest Cases | 85 | 76/85 (89.4%) |
| Real-World Cases | 51 | 23/51 (45.1%) |
| All Cases | 136 | 99/136 (72.8%) |

## Match Rate By Taxonomy Class

| Ground-Truth Taxonomy | Fix-Type Match |
| --- | --- |
| `source_bug` | 82/100 (82.0%) |
| `lowering_artifact` | 5/18 (27.8%) |
| `env_mismatch` | 9/14 (64.3%) |
| `verifier_limit` | 3/4 (75.0%) |

## Predicted Fix-Type Distribution

| Predicted Fix Type | Count |
| --- | --- |
| `bounds_check` | 21 |
| `null_check` | 9 |
| `type_cast` | 5 |
| `clamp` | 5 |
| `mask` | 1 |
| `refcount` | 4 |
| `env_fix` | 10 |
| `loop_rewrite` | 2 |
| `inline` | 3 |
| `reorder` | 35 |
| `other` | 41 |

## Confusion Matrix

| GT \ Pred | `bounds_check` | `null_check` | `type_cast` | `clamp` | `mask` | `refcount` | `env_fix` | `loop_rewrite` | `inline` | `reorder` | `other` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bounds_check` | 11 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `null_check` | 0 | 9 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| `type_cast` | 1 | 0 | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| `clamp` | 5 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| `mask` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `refcount` | 0 | 0 | 0 | 0 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| `env_fix` | 0 | 0 | 0 | 0 | 0 | 0 | 9 | 0 | 0 | 2 | 3 |
| `loop_rewrite` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| `inline` | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 2 | 1 | 0 |
| `reorder` | 3 | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 21 | 0 |
| `other` | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 7 | 37 |

## Mapping Rules Used

| Rule | Cases |
| --- | --- |
| specialized contract signal | 40 |
| proof-restoration ordering signal | 35 |
| explicit bounds-guard signal | 13 |
| environment-compatibility signal | 10 |
| null-check signal | 9 |
| mask/cast fallback to bounds signal | 7 |
| offset/size clamp signal | 5 |
| lifetime/reference signal | 4 |
| mask/cast tightening signal | 4 |
| control-flow simplification signal | 3 |
| loop/complexity signal | 2 |
| masking signal | 1 |
| fallback-other | 1 |
| cast/temporary signal | 1 |
| bounds text signal | 1 |
