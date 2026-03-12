# Batch Diagnostic Evaluation

- Generated at: `2026-03-12T20:02:15.648575+00:00`
- Minimum verifier log length: `50` chars
- Case files scanned: `302`
- Eligible for evaluation: `241`
- Skipped: `61`
- Successful runs: `241`
- Failed runs: `0`

## Overall Success Rate

- Success rate: `241/241 (100.0%)`
- BTF source correlation: `151/241 (62.7%)`
- Span role coverage: established `97/241 (40.2%)`, lost `82/241 (34.0%)`, rejected `241/241 (100.0%)`

## Distribution of taxonomy_class

| Value | Count | Share |
| --- | ---: | ---: |
| `verifier_limit` | 20 | 8.3% |
| `source_bug` | 109 | 45.2% |
| `env_mismatch` | 83 | 34.4% |
| `lowering_artifact` | 29 | 12.0% |

## Distribution of proof_status

| Value | Count | Share |
| --- | ---: | ---: |
| `established_then_lost` | 81 | 33.6% |
| `never_established` | 124 | 51.5% |
| `unknown` | 20 | 8.3% |
| `established_but_insufficient` | 16 | 6.6% |

## Number of Spans Histogram

| Value | Count | Share |
| --- | ---: | ---: |
| `1` | 142 | 58.9% |
| `2` | 18 | 7.5% |
| `3` | 80 | 33.2% |
| `5` | 1 | 0.4% |

## Per-Source Breakdown

| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Selftests | 200 | 150 | 150 | 0 | 50 | 100.0% | 98.7% | 1.91 |
| Stack Overflow | 76 | 65 | 65 | 0 | 11 | 100.0% | 1.5% | 1.52 |
| GitHub | 26 | 26 | 26 | 0 | 0 | 100.0% | 7.7% | 1.46 |

## Failure Cases

_None_

## Top 5 Best Outputs

_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `kernel-selftest-async-stack-depth-async-call-root-check` | Selftests | 145.8 | 3 | est,lost,rej | yes | 0.020 | established then lost |
| `kernel-selftest-async-stack-depth-pseudo-call-check` | Selftests | 145.7 | 3 | est,lost,rej | yes | 0.027 | established then lost |
| `kernel-selftest-crypto-basic-crypto-acquire` | Selftests | 145.5 | 3 | est,lost,rej | yes | 0.054 | established then lost |
| `kernel-selftest-cgrp-kfunc-failure-bpf-prog` | Selftests | 145.5 | 3 | est,lost,rej | yes | 0.055 | established then lost |
| `kernel-selftest-dynptr-fail-dynptr-invalidate-slice-reinit` | Selftests | 145.4 | 3 | est,lost,rej | yes | 0.063 | established then lost |

## Top 5 Worst Outputs

_Ranking heuristic penalizes sparse spans, missing roles, missing BTF, and bloated output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-78525670` | Stack Overflow | 44.0 | 1 | rej | no | 2.940 | verifier rejection |
| `kernel-selftest-exceptions-fail-reject-multiple-exception-cb` | Selftests | 44.0 | 1 | rej | no | 2.272 | verifier rejection |
| `stackoverflow-78753911` | Stack Overflow | 44.0 | 1 | rej | no | 2.196 | verifier rejection |
| `kernel-selftest-dummy-st-ops-fail-dummy-st-ops-fail` | Selftests | 44.0 | 1 | rej | no | 1.778 | verifier rejection |
| `stackoverflow-56872436` | Stack Overflow | 44.0 | 1 | rej | no | 1.236 | verifier rejection |

## Quality Issues Found

- `0` successful cases emitted `6+` spans; these outputs risk becoming noisy.
- `0` successful cases emitted zero correlated spans.
- `142` successful cases emitted only one span, which often reduces causal context.
- `0` successful cases had source markers in the verifier log but no `file:line` in emitted spans.
- `0` successful cases were missing role(s) expected by their `proof_status`.
- `0` successful cases were missing an explicit rejected span.

Examples:
- Missing BTF despite source markers: 0
- Too many spans: 0
- Missing expected roles: 0

## Recommendations

- Strengthen fallback proof-event synthesis for sparse outputs; 142 successful cases render at most one span.
