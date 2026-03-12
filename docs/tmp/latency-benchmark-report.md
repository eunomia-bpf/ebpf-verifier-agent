# OBLIGE Latency Benchmark Report

- Command: `python eval/latency_benchmark.py`
- Dataset: `302` case files scanned, `241` eligible (`verifier_log >= 50` chars), `241` succeeded, `0` failed
- Raw results: `eval/results/latency_benchmark.json`

## Reviewer Answer

OBLIGE is fast enough for interactive use on the current case-study corpus.

- Median end-to-end latency is `33.204 ms` per case.
- Mean latency is `34.787 ms`.
- p95 latency is `48.062 ms`.
- p99 latency is `76.311 ms`.
- Worst-case latency is `115.621 ms`.
- `96.3%` of cases finish within `50 ms`.
- `99.6%` of cases finish within `100 ms`.

In practice, this means a single diagnostic is usually returned in a few tens of milliseconds, with only one corpus case exceeding `100 ms`.

## Stage Summary

| Stage | Min (ms) | Median (ms) | Mean (ms) | p95 (ms) | p99 (ms) | Max (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `generate_diagnostic` | 18.907 | 33.204 | 34.787 | 48.062 | 76.311 | 115.621 |
| `parse_log` | 9.369 | 10.171 | 10.834 | 13.114 | 21.619 | 41.258 |
| `parse_trace` | 0.043 | 0.586 | 0.896 | 2.395 | 7.033 | 9.414 |
| `diagnose` | 9.363 | 10.941 | 11.820 | 15.689 | 29.020 | 50.288 |
| `proof_engine.analyze_proof` | 0.011 | 0.232 | 0.521 | 1.932 | 5.908 | 10.198 |

Notes:

- Stage timings were captured on the real `generate_diagnostic()` call path in `interface/extractor/rust_diagnostic.py`.
- These stage numbers are not additive: `diagnose()` reparses the log internally, and total latency also includes source correlation, span normalization, note/help generation, and rendering.
- Across all successful cases, each named stage was invoked exactly once per `generate_diagnostic()` call.

## Main Observations

- `parse_log` and `diagnose` dominate latency. Each sits around `10-11 ms` at median.
- `parse_trace` is usually sub-millisecond and stays below `2.395 ms` at p95.
- `proof_engine.analyze_proof` is very cheap in this corpus: `0.232 ms` median, `1.932 ms` p95.
- Log size has a moderate positive correlation with end-to-end latency: Pearson `r = 0.6779`.

The slowest cases were also the largest traces:

| Case | Source | Lines | Total latency (ms) |
| --- | --- | ---: | ---: |
| `github-aya-rs-aya-1267` | `github` | 544 | 115.621 |
| `kernel-selftest-async-stack-depth-async-call-root-check` | `selftests` | 516 | 96.333 |
| `kernel-selftest-async-stack-depth-pseudo-call-check` | `selftests` | 411 | 80.019 |
| `github-aya-rs-aya-1062` | `github` | 337 | 70.748 |
| `kernel-selftest-crypto-basic-crypto-acquire` | `selftests` | 190 | 52.458 |

## Bottom Line

For reviewer purposes, the current answer is:

- OBLIGE takes about `33 ms` per case at median and `48 ms` at p95.
- Tail latency remains under `100 ms` for all but one case in the `241`-case benchmark set.
- That is comfortably within an interactive latency budget for a verifier-diagnostic tool.
