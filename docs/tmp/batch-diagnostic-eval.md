# Batch Diagnostic Evaluation

- Generated at: `2026-03-19T02:45:56.569277+00:00`
- Minimum verifier log length: `50` chars
- Case files scanned: `302`
- Eligible for evaluation: `262`
- Skipped: `40`
- Successful runs: `262`
- Failed runs: `0`

## Overall Success Rate

- Success rate: `262/262 (100.0%)`
- BTF source correlation: `172/262 (65.6%)`
- Span role coverage: established `14/262 (5.3%)`, lost `13/262 (5.0%)`, rejected `262/262 (100.0%)`

## Distribution of taxonomy_class

| Value | Count | Share |
| --- | ---: | ---: |
| `verifier_limit` | 5 | 1.9% |
| `source_bug` | 220 | 84.0% |
| `env_mismatch` | 17 | 6.5% |
| `lowering_artifact` | 20 | 7.6% |

## Distribution of proof_status

| Value | Count | Share |
| --- | ---: | ---: |
| `unknown` | 174 | 66.4% |
| `never_established` | 74 | 28.2% |
| `established_then_lost` | 13 | 5.0% |
| `established_but_insufficient` | 1 | 0.4% |

## Number of Spans Histogram

| Value | Count | Share |
| --- | ---: | ---: |
| `1` | 241 | 92.0% |
| `2` | 15 | 5.7% |
| `3` | 6 | 2.3% |

## Per-Source Breakdown

| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Selftests | 200 | 171 | 171 | 0 | 29 | 100.0% | 98.8% | 1.05 |
| Stack Overflow | 76 | 65 | 65 | 0 | 11 | 100.0% | 1.5% | 1.26 |
| GitHub | 26 | 26 | 26 | 0 | 0 | 100.0% | 7.7% | 1.08 |

## Failure Cases

_None_

## Top 5 Best Outputs

_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._

| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |
| --- | --- | ---: | ---: | --- | --- | ---: | --- |
| `stackoverflow-70760516` | Stack Overflow | 125.7 | 3 | est,lost,rej | no | 0.032 | proof established, then lost before rejection |
| `stackoverflow-79485758` | Stack Overflow | 125.5 | 3 | est,lost,rej | no | 0.048 | proof established, then lost before rejection |
| `stackoverflow-72575736` | Stack Overflow | 124.9 | 3 | est,lost,rej | no | 0.107 | proof established, then lost before rejection |
| `stackoverflow-76637174` | Stack Overflow | 124.7 | 3 | est,lost,rej | no | 0.133 | proof established, then lost before rejection |
| `stackoverflow-79530762` | Stack Overflow | 124.6 | 3 | est,lost,rej | no | 0.142 | proof established, then lost before rejection |

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
- `241` successful cases emitted only one span, which often reduces causal context.
- `0` successful cases had source markers in the verifier log but no `file:line` in emitted spans.
- `7` successful cases were missing role(s) expected by their `proof_status`.
- `0` successful cases were missing an explicit rejected span.

Examples:
- Missing BTF despite source markers: 0
- Too many spans: 0
- Missing expected roles: 7 (`kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49`, `stackoverflow-76160985`, `stackoverflow-78236856`, +2 more)

## Recommendations

- Strengthen fallback proof-event synthesis for sparse outputs; 241 successful cases render at most one span.
- Enforce a minimal role set from `proof_status` during rendering so `established_then_lost` always includes established/lost/rejected context when recoverable.
