# v3 Core Near-Duplicate Analysis

Method: lexical similarity over three signals per same-source pair.

- `source_snippets`: normalized code similarity when both cases include code
- `verifier_log`: similarity between extracted verifier-error lines or the final message-bearing lines
- `topic`: similarity between Stack Overflow titles/bodies or GitHub issue titles/bodies
- `overall`: weighted duplicate score that emphasizes user-authored content
- When code is present: `0.45 * topic + 0.45 * source_snippets + 0.10 * verifier_log`
- When code is absent: `0.70 * topic + 0.30 * verifier_log`
- Rationale: generic verifier failures such as `invalid access to packet` recur across unrelated posts, so topic and code overlap should dominate duplicate detection

Threshold for flagging near-duplicates: overall similarity > 0.70

## Stack Overflow

- Pair count reviewed: 903
- Near-duplicate threshold: overall similarity > 0.70
- Flagged pairs: 1

### Top scored pairs

| Pair | Source Snippets | Verifier Log | Topic | Overall |
| --- | ---: | ---: | ---: | ---: |
| `stackoverflow-70750259` / `stackoverflow-70760516` | 0.953 | 0.164 | 0.692 | 0.756 |
| `stackoverflow-75643912` / `stackoverflow-78958420` | N/A | 1.000 | 0.463 | 0.624 |
| `stackoverflow-75643912` / `stackoverflow-76637174` | N/A | 1.000 | 0.447 | 0.613 |
| `stackoverflow-72005172` / `stackoverflow-76637174` | N/A | 1.000 | 0.427 | 0.599 |
| `stackoverflow-72005172` / `stackoverflow-79530762` | N/A | 1.000 | 0.425 | 0.597 |
| `stackoverflow-72575736` / `stackoverflow-75643912` | N/A | 1.000 | 0.416 | 0.591 |
| `stackoverflow-74178703` / `stackoverflow-77762365` | N/A | 1.000 | 0.414 | 0.590 |
| `stackoverflow-76637174` / `stackoverflow-79530762` | N/A | 1.000 | 0.412 | 0.589 |
| `stackoverflow-75643912` / `stackoverflow-79485758` | N/A | 1.000 | 0.411 | 0.588 |
| `stackoverflow-72005172` / `stackoverflow-75643912` | N/A | 1.000 | 0.398 | 0.579 |

### Flagged near-duplicates

#### `stackoverflow-70750259` vs `stackoverflow-70760516`

- Source snippet similarity: 0.953
- Verifier-log similarity: 0.164
- Topic similarity: 0.692
- Overall similarity: 0.756
- `stackoverflow-70750259` title: BPF verification error when trying to extract SNI from TLS packet
- `stackoverflow-70760516` title: BPF verifier fails because of invalid access to packet
- `stackoverflow-70750259` error excerpt: math between pkt pointer and register with unbounded min value is not allowed
- `stackoverflow-70760516` error excerpt: invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)

## GitHub Issues

- Pair count reviewed: 55
- Near-duplicate threshold: overall similarity > 0.70
- Flagged pairs: 0

### Top scored pairs

| Pair | Source Snippets | Verifier Log | Topic | Overall |
| --- | ---: | ---: | ---: | ---: |
| `github-aya-rs-aya-1056` / `github-aya-rs-aya-1267` | 1.000 | 0.231 | 0.247 | 0.584 |
| `github-cilium-cilium-41412` / `github-cilium-cilium-41522` | N/A | 0.145 | 0.363 | 0.297 |
| `github-aya-rs-aya-1002` / `github-aya-rs-aya-1267` | 0.056 | 0.765 | 0.265 | 0.221 |
| `github-aya-rs-aya-1062` / `github-aya-rs-aya-440` | 0.233 | 0.270 | 0.179 | 0.212 |
| `github-aya-rs-aya-440` / `github-aya-rs-aya-521` | 0.304 | 0.186 | 0.090 | 0.196 |
| `github-cilium-cilium-41522` / `github-facebookincubator-katran-149` | N/A | 0.120 | 0.218 | 0.189 |
| `github-aya-rs-aya-1062` / `github-aya-rs-aya-521` | 0.240 | 0.275 | 0.101 | 0.181 |
| `github-aya-rs-aya-1062` / `github-aya-rs-aya-1267` | 0.108 | 0.353 | 0.213 | 0.180 |
| `github-aya-rs-aya-1056` / `github-aya-rs-aya-440` | 0.053 | 0.224 | 0.265 | 0.165 |
| `github-aya-rs-aya-1002` / `github-aya-rs-aya-440` | 0.072 | 0.289 | 0.224 | 0.162 |

### Flagged near-duplicates

No pairs crossed the 0.70 threshold.

