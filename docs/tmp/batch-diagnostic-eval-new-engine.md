# Batch Diagnostic Evaluation — New Engine Comparison

- Generated at: `2026-03-14T00:49:49` (new run)
- Compared against: v5 baseline run (`2026-03-13T04:45:56`)
- Cases: 302 scanned, 262 eligible (40 skipped for short logs), 0 failures in both runs

## Summary Comparison Table

| Metric | v5 Baseline | New Engine | Delta |
| --- | ---: | ---: | ---: |
| Success rate | 262/262 (100.0%) | 262/262 (100.0%) | 0 |
| Failures | 0 | 0 | 0 |
| BTF source correlation | 172/262 (65.6%) | 172/262 (65.6%) | 0 |
| `established` span | 115/262 (43.9%) | 136/262 (51.9%) | **+8.0 pp** |
| `lost` span | 99/262 (37.8%) | 133/262 (50.8%) | **+13.0 pp** |
| `rejected` span | 262/262 (100.0%) | 262/262 (100.0%) | 0 |
| Missing expected roles | 0 | 0 | 0 |
| Missing BTF despite source markers | 0 | 0 | 0 |
| 6+ span (noisy) cases | 0 | 0 | 0 |
| Zero-span cases | 0 | 0 | 0 |
| Single-span cases | 146 (55.7%) | 124 (47.3%) | **−22 cases** |
| 3-span cases | 99 (37.8%) | 131 (50.0%) | **+32 cases** |

## Proof Status Distribution

| proof_status | v5 Baseline | New Engine | Delta |
| --- | ---: | ---: | ---: |
| `established_then_lost` | 99 (37.8%) | 131 (50.0%) | **+32 / +12.2 pp** |
| `never_established` | 126 (48.1%) | 105 (40.1%) | −21 / −8.0 pp |
| `established_but_insufficient` | 16 (6.1%) | 5 (1.9%) | −11 / −4.2 pp |
| `unknown` | 21 (8.0%) | 21 (8.0%) | 0 |

The new engine reclassified 32 cases from `never_established` or `established_but_insufficient` into `established_then_lost`, which is the richer diagnostic path that emits all three role spans (established, lost, rejected).

## Taxonomy Class Distribution

| taxonomy_class | v5 Baseline | New Engine | Delta |
| --- | ---: | ---: | ---: |
| `source_bug` | 127 (48.5%) | 98 (37.4%) | −29 |
| `lowering_artifact` | 33 (12.6%) | 141 (53.8%) | **+108** |
| `env_mismatch` | 82 (31.3%) | 20 (7.6%) | −62 |
| `verifier_limit` | 20 (7.6%) | 3 (1.1%) | −17 |

Note: taxonomy classification logic changed significantly in the new engine. The large shift toward `lowering_artifact` warrants a review of the classification rules.

## Span Histogram

| Spans | v5 Baseline | New Engine | Delta |
| --- | ---: | ---: | ---: |
| 0 | 0 | 0 | 0 |
| 1 | 146 (55.7%) | 124 (47.3%) | −22 |
| 2 | 17 (6.5%) | 7 (2.7%) | −10 |
| 3 | 99 (37.8%) | 131 (50.0%) | **+32** |
| 4+ | 0 | 0 | 0 |

The new engine produces full 3-span outputs for 32 more cases (131 vs 99), with corresponding reductions in single-span outputs.

## Per-Source Breakdown

| Source | v5 Baseline Avg Spans | New Engine Avg Spans | Delta |
| --- | ---: | ---: | ---: |
| Selftests (171 eligible) | 2.02 | 2.27 | **+0.25** |
| Stack Overflow (65 eligible) | 1.46 | 1.51 | +0.05 |
| GitHub (26 eligible) | 1.42 | 1.69 | **+0.27** |

## Latency Results (New Engine)

From `eval/results/latency_benchmark_v3.json`:

| Statistic | Latency (ms) |
| --- | ---: |
| min | 19.2 |
| median | 32.0 |
| mean | 31.5 |
| p95 | 41.9 |
| p99 | 72.4 |
| max | 82.7 |

- Pearson r between log-line count and latency: **0.744** (strong linear correlation)
- All 262 eligible cases completed successfully with 0 failures
- Slowest case: `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` at 82.7 ms (516 log lines)

Latency is dominated by log size. Sub-100 ms for all cases; sub-50 ms for 95% of cases.

## Key Improvements in New Engine

1. **+13.0 pp `proof_lost` coverage**: 133 vs 99 cases now emit a `proof_lost` role span. This means the engine finds the critical state-transition point in 34 more cases.
2. **+8.0 pp `proof_established` coverage**: 136 vs 115 cases now emit a `proof_established` role span.
3. **+32 full 3-span outputs**: 131 vs 99 cases (50.0% vs 37.8%) produce the complete established/lost/rejected triple — the highest-quality diagnostic output.
4. **No regressions**: 0 failures, 0 missing-role mismatches, 0 BTF-source-marker drops, 0 noisy outputs.
5. **Role completeness enforcement**: 0 cases missing expected roles (was also 0 in v5), but now with 32 more cases entering the `established_then_lost` path those three roles are all emitted correctly.

## Remaining Issues

- **124 single-span cases** (47.3%): The largest improvement opportunity. These cases have only a `rejected` span and no causal chain. They are primarily Stack Overflow and GitHub cases with minimal verifier logs (no BTF source markers).
- **Taxonomy shift to `lowering_artifact`**: The 4x increase (33→141) needs a review — it likely indicates a rule ordering change in the new engine rather than a genuine case reclassification.
- **21 `unknown` proof_status**: Unchanged. These may need explicit pattern matchers.

## Comparison with v5 Baseline Targets

v5 baseline note: "Key question: did multi_span coverage improve? (was 37.8% for established_then_lost)"

Answer: **Yes.** The `established_then_lost` rate rose from 37.8% to 50.0% (+12.2 pp). Multi-span (3-span) coverage for established_then_lost cases: 99/99 → 131/131 (100% within that category, same as before since all established_then_lost emit 3 spans). The total fraction of cases with 3 spans rose from 37.8% to 50.0%.
