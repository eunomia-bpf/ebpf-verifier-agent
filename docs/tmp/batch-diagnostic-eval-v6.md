# Batch Diagnostic Evaluation — v6

- Generated at: `2026-03-13T04:45:56.744053+00:00`
- Minimum verifier log length: `50` chars
- Case files scanned: `302`
- Eligible for evaluation: `262`
- Skipped: `40`
- Successful runs: `262`
- Failed runs: `0`

## Overall Success Rate

- Success rate: `262/262 (100.0%)`
- BTF source correlation: `172/262 (65.6%)`
- Span role coverage: established `115/262 (43.9%)`, lost `99/262 (37.8%)`, rejected `262/262 (100.0%)`

## Distribution of taxonomy_class

| Value | Count | Share |
| --- | ---: | ---: |
| `verifier_limit` | 20 | 7.6% |
| `source_bug` | 127 | 48.5% |
| `env_mismatch` | 82 | 31.3% |
| `lowering_artifact` | 33 | 12.6% |

## Distribution of proof_status

| Value | Count | Share |
| --- | ---: | ---: |
| `established_then_lost` | 99 | 37.8% |
| `never_established` | 126 | 48.1% |
| `established_but_insufficient` | 16 | 6.1% |
| `unknown` | 21 | 8.0% |

## Number of Spans Histogram

| Value | Count | Share |
| --- | ---: | ---: |
| `1` | 146 | 55.7% |
| `2` | 17 | 6.5% |
| `3` | 99 | 37.8% |

## Per-Source Breakdown

| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Selftests | 200 | 171 | 171 | 0 | 29 | 100.0% | 98.8% | 2.02 |
| Stack Overflow | 76 | 65 | 65 | 0 | 11 | 100.0% | 1.5% | 1.46 |
| GitHub | 26 | 26 | 26 | 0 | 0 | 100.0% | 7.7% | 1.42 |

## Failure Cases

_None_

## Top 5 Best Outputs

_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | Selftests | 145.8 | 3 | est,lost,rej | yes | 0.020 | established then lost |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | Selftests | 145.7 | 3 | est,lost,rej | yes | 0.027 | established then lost |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | Selftests | 145.4 | 3 | est,lost,rej | yes | 0.059 | established then lost |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` | Selftests | 145.4 | 3 | est,lost,rej | yes | 0.061 | established then lost |
| `kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725` | Selftests | 145.3 | 3 | est,lost,rej | yes | 0.067 | established then lost |

## Top 5 Worst Outputs

_Ranking heuristic penalizes sparse spans, missing roles, missing BTF, and bloated output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-78525670` | Stack Overflow | 44.0 | 1 | rej | no | 2.940 | verifier rejection |
| `stackoverflow-76994829` | Stack Overflow | 44.0 | 1 | rej | no | 2.400 | verifier rejection |
| `kernel-selftest-exceptions-fail-reject-multiple-exception-cb-tc-fb35b800` | Selftests | 44.0 | 1 | rej | no | 2.272 | verifier rejection |
| `stackoverflow-78753911` | Stack Overflow | 44.0 | 1 | rej | no | 2.196 | verifier rejection |
| `kernel-selftest-dummy-st-ops-fail-test-unsupported-field-sleepable-struct-ops-s-test-2-e009f86b` | Selftests | 44.0 | 1 | rej | no | 1.778 | verifier rejection |

## Quality Issues Found

- `0` successful cases emitted `6+` spans; these outputs risk becoming noisy.
- `0` successful cases emitted zero correlated spans.
- `146` successful cases emitted only one span, which often reduces causal context.
- `0` successful cases had source markers in the verifier log but no `file:line` in emitted spans.
- `0` successful cases were missing role(s) expected by their `proof_status`.
- `0` successful cases were missing an explicit rejected span.

Examples:
- Missing BTF despite source markers: 0
- Too many spans: 0
- Missing expected roles: 0

## Recommendations

- Strengthen fallback proof-event synthesis for sparse outputs; 146 successful cases render at most one span.

---

## v5 vs v6 Comparison

> **v5 baseline**: generated at `2026-03-13T04:36:28.447621+00:00` (from `eval/results/batch_diagnostic_results_v5.json`)
> **v6 run**: generated at `2026-03-13T04:45:56.744053+00:00` (from `docs/tmp/batch-diagnostic-eval.md`, the default report path)

### Key Metrics

| Metric | v5 | v6 | Delta |
| --- | ---: | ---: | ---: |
| Success rate | 262/262 (100.0%) | 262/262 (100.0%) | 0 |
| BTF correlation | 172 (65.6%) | 172 (65.6%) | 0 |
| `proof_established` spans | 113 (43.1%) | 115 (43.9%) | **+2** |
| `proof_lost` spans | 97 (37.0%) | 99 (37.8%) | **+2** |
| `proof_rejected` spans | 262 (100.0%) | 262 (100.0%) | 0 |
| Cases with `causal_chain` in metadata | 24 | ~26 (est.) | **+2** |
| `proof_status: established_then_lost` | 97 | 99 | **+2** |
| `proof_status: never_established` | 128 | 126 | **−2** |
| `proof_status: established_but_insufficient` | 16 | 16 | 0 |
| `proof_status: unknown` | 21 | 21 | 0 |
| Single-span outputs | 148 | 146 | **−2** |
| Avg selftests spans | 1.99 | 2.02 | +0.03 |
| Failures | 0 | 0 | 0 |

### What Changed

**Interval arithmetic improvements** (`abstract_domain.py`): Two cases previously classified as `never_established` are now correctly identified as `established_then_lost`. The improved `ScalarBounds` class with proper tnum intersection (`upper_bound()` / `lower_bound()`) and the `is_bounded()` check that accounts for tnum-constrained values (e.g., `r0 &= 0xff` with `var_off=(0x0; 0xff)`) allows the predicate evaluator to detect more proof-satisfaction events earlier in the trace. This reclassification adds 2 `proof_established` + 2 `proof_lost` spans (+2 each) and reduces `never_established` by 2.

**Causal chain wiring fix** (`pipeline.py` `attach_proof_analysis_metadata`): The `causal_chain` serialization was changed from raw tuple arrays (JSON arrays-of-arrays: `[[insn_idx, reason], ...]`) to structured dicts (`[{"insn_idx": ..., "reason": ...}, ...]`). This makes the metadata more readable for downstream tools (LLM agents, repair loop) without changing the number of cases that produce causal chains. The approximately 24–26 cases with non-empty causal chains correspond to `established_then_lost` cases where the backward obligation slice found contributing instructions.

### No Regressions

- BTF correlation rate: unchanged at 65.6%
- Taxonomy distribution: unchanged (verifier_limit 7.6%, source_bug 48.5%, env_mismatch 31.3%, lowering_artifact 12.6%)
- Zero failures in both v5 and v6
- Zero cases with missing expected roles
- Selftests BTF rate: unchanged at 98.8%

### Remaining Improvement Areas

- 146 cases (55.7%) still emit only one span; the dominant path is `never_established` (126 cases) which falls through to a single rejected span.
- Stack Overflow BTF rate remains low (1.5%) due to missing BTF annotations in user-supplied snippets.
- 21 cases (8.0%) remain `unknown` proof status — these are subprog-only traces or helper-boundary cases that resist formal obligation inference.
