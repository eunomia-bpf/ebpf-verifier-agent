# Batch Diagnostic Evaluation

- Generated at: `2026-03-20T04:03:21.692441+00:00`
- Minimum verifier log length: `50` chars
- Case files scanned: `302`
- Eligible for evaluation: `261`
- Skipped: `41`
- Successful runs: `261`
- Failed runs: `0`

## Overall Success Rate

- Success rate: `261/261 (100.0%)`
- BTF source correlation: `191/261 (73.2%)`
- Span role coverage: established `13/261 (5.0%)`, lost `9/261 (3.4%)`, rejected `261/261 (100.0%)`

## Distribution of taxonomy_class

| Value | Count | Share |
| --- | ---: | ---: |
| `verifier_limit` | 4 | 1.5% |
| `source_bug` | 214 | 82.0% |
| `env_mismatch` | 35 | 13.4% |
| `lowering_artifact` | 8 | 3.1% |

## Distribution of proof_status

| Value | Count | Share |
| --- | ---: | ---: |
| `unknown` | 189 | 72.4% |
| `never_established` | 59 | 22.6% |
| `established_then_lost` | 13 | 5.0% |

## Number of Spans Histogram

| Value | Count | Share |
| --- | ---: | ---: |
| `1` | 243 | 93.1% |
| `2` | 14 | 5.4% |
| `3` | 4 | 1.5% |

## Per-Source Breakdown

| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Selftests | 200 | 171 | 171 | 0 | 29 | 100.0% | 98.8% | 1.05 |
| Stack Overflow | 76 | 64 | 64 | 0 | 12 | 100.0% | 31.2% | 1.19 |
| GitHub | 26 | 26 | 26 | 0 | 0 | 100.0% | 7.7% | 1.08 |

## Failure Cases

_None_

## Top 5 Best Outputs

_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-76637174` | Stack Overflow | 145.7 | 3 | est,lost,rej | yes | 0.029 | established then lost |
| `stackoverflow-70760516` | Stack Overflow | 125.7 | 3 | est,lost,rej | no | 0.032 | proof established, then lost before rejection |
| `stackoverflow-72575736` | Stack Overflow | 125.1 | 3 | est,lost,rej | no | 0.087 | established then lost |
| `stackoverflow-79530762` | Stack Overflow | 124.8 | 3 | est,lost,rej | no | 0.119 | established then lost |
| `kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725` | Selftests | 112.4 | 2 | lost,rej | yes | 0.061 | never established |

## Top 5 Worst Outputs

_Ranking heuristic penalizes sparse spans, missing roles, missing BTF, and bloated output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-70091221` | Stack Overflow | 44.0 | 1 | rej | no | 4.443 | helper expected a map pointer |
| `github-facebookincubator-katran-149` | GitHub | 44.0 | 1 | rej | no | 3.512 | helper expected a map pointer |
| `stackoverflow-78525670` | Stack Overflow | 44.0 | 1 | rej | no | 2.929 | verifier rejection |
| `stackoverflow-79045875` | Stack Overflow | 44.0 | 1 | rej | no | 2.912 | kfunc expected a scalar-compatible pointee |
| `stackoverflow-76994829` | Stack Overflow | 44.0 | 1 | rej | no | 2.391 | verifier rejection |

## Quality Issues Found

- `0` successful cases emitted `6+` spans; these outputs risk becoming noisy.
- `0` successful cases emitted zero correlated spans.
- `243` successful cases emitted only one span, which often reduces causal context.
- `0` successful cases had source markers in the verifier log but no `file:line` in emitted spans.
- `9` successful cases were missing role(s) expected by their `proof_status`.
- `0` successful cases were missing an explicit rejected span.

Examples:
- Missing BTF despite source markers: 0
- Too many spans: 0
- Missing expected roles: 9 (`kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49`, `stackoverflow-72005172`, `stackoverflow-74531552`, +4 more)

## Recommendations

- Strengthen fallback proof-event synthesis for sparse outputs; 243 successful cases render at most one span.
- Enforce a minimal role set from `proof_status` during rendering so `established_then_lost` always includes established/lost/rejected context when recoverable.
