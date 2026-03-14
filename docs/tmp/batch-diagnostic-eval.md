# Batch Diagnostic Evaluation

- Generated at: `2026-03-14T00:49:49.546302+00:00`
- Minimum verifier log length: `50` chars
- Case files scanned: `302`
- Eligible for evaluation: `262`
- Skipped: `40`
- Successful runs: `262`
- Failed runs: `0`

## Overall Success Rate

- Success rate: `262/262 (100.0%)`
- BTF source correlation: `172/262 (65.6%)`
- Span role coverage: established `136/262 (51.9%)`, lost `133/262 (50.8%)`, rejected `262/262 (100.0%)`

## Distribution of taxonomy_class

| Value | Count | Share |
| --- | ---: | ---: |
| `lowering_artifact` | 141 | 53.8% |
| `source_bug` | 98 | 37.4% |
| `env_mismatch` | 20 | 7.6% |
| `verifier_limit` | 3 | 1.1% |

## Distribution of proof_status

| Value | Count | Share |
| --- | ---: | ---: |
| `established_then_lost` | 131 | 50.0% |
| `never_established` | 105 | 40.1% |
| `established_but_insufficient` | 5 | 1.9% |
| `unknown` | 21 | 8.0% |

## Number of Spans Histogram

| Value | Count | Share |
| --- | ---: | ---: |
| `1` | 124 | 47.3% |
| `2` | 7 | 2.7% |
| `3` | 131 | 50.0% |

## Per-Source Breakdown

| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Selftests | 200 | 171 | 171 | 0 | 29 | 100.0% | 98.8% | 2.27 |
| Stack Overflow | 76 | 65 | 65 | 0 | 11 | 100.0% | 1.5% | 1.51 |
| GitHub | 26 | 26 | 26 | 0 | 0 | 100.0% | 7.7% | 1.69 |

## Failure Cases

_None_

## Top 5 Best Outputs

_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | Selftests | 145.9 | 3 | est,lost,rej | yes | 0.013 | established then lost |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | Selftests | 145.8 | 3 | est,lost,rej | yes | 0.017 | established then lost |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | Selftests | 145.6 | 3 | est,lost,rej | yes | 0.040 | established then lost |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b` | Selftests | 145.5 | 3 | est,lost,rej | yes | 0.053 | established then lost |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` | Selftests | 145.3 | 3 | est,lost,rej | yes | 0.068 | established then lost |

## Top 5 Worst Outputs

_Ranking heuristic penalizes sparse spans, missing roles, missing BTF, and bloated output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-78525670` | Stack Overflow | 44.0 | 1 | rej | no | 2.940 | verifier rejection |
| `stackoverflow-76994829` | Stack Overflow | 44.0 | 1 | rej | no | 2.400 | verifier rejection |
| `kernel-selftest-exceptions-fail-reject-multiple-exception-cb-tc-fb35b800` | Selftests | 44.0 | 1 | rej | no | 2.224 | verifier rejection |
| `stackoverflow-78753911` | Stack Overflow | 44.0 | 1 | rej | no | 2.074 | verifier rejection |
| `kernel-selftest-dummy-st-ops-fail-test-unsupported-field-sleepable-struct-ops-s-test-2-e009f86b` | Selftests | 44.0 | 1 | rej | no | 1.737 | verifier rejection |

## Quality Issues Found

- `0` successful cases emitted `6+` spans; these outputs risk becoming noisy.
- `0` successful cases emitted zero correlated spans.
- `124` successful cases emitted only one span, which often reduces causal context.
- `0` successful cases had source markers in the verifier log but no `file:line` in emitted spans.
- `0` successful cases were missing role(s) expected by their `proof_status`.
- `0` successful cases were missing an explicit rejected span.

Examples:
- Missing BTF despite source markers: 0
- Too many spans: 0
- Missing expected roles: 0

## Recommendations

- Strengthen fallback proof-event synthesis for sparse outputs; 124 successful cases render at most one span.
