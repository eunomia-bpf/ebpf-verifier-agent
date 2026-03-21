# Localization Evaluation

- Generated at: `2026-03-20T04:03:33+00:00`
- Evaluated non-quarantined ground-truth cases: `136`
- Cases with `root_cause_insn_idx != rejected_insn_idx`: `18`
- Earlier-root cases (`root_cause_insn_idx < rejected_insn_idx`): `17`
- Later-root cases (`root_cause_insn_idx > rejected_insn_idx`): `1`

## Coverage Metrics

- Proof-lost span emitted: `8/136 (5.9%)`
- Any earlier span before the rejected span: `13/136 (9.6%)`
- Proof-established span emitted: `11/136 (8.1%)`
- Rejected span emitted: `135/136 (99.3%)`
- Rejected span exact match: `96/136 (70.6%)`

## Accuracy When `proof_lost` Is Present

- Cases with `proof_lost`: `8`
- Exact GT root-cause match: `3/8 (37.5%)`
- Within 5 instructions: `5/8 (62.5%)`
- Within 10 instructions: `6/8 (75.0%)`
- Mean absolute error on `proof_lost` cases: `6.88`

## Conditional Accuracy Table

- `All` uses end-to-end denominators over all labeled cases; `Has proof_lost` is the conditional root-cause accuracy slice.

| Metric | All (N=136) | Has proof_lost (N=8) | No proof_lost (N=128) |
| --- | --- | --- | --- |
| Proof-lost coverage | 8/136 (5.9%) | 8/8 (100.0%) | 0/128 (0.0%) |
| Any-earlier coverage | 13/136 (9.6%) | 7/8 (87.5%) | 6/128 (4.7%) |
| Exact GT root match | 3/136 (2.2%) | 3/8 (37.5%) | 0/0 (n/a) |
| Within 5 insns | 5/136 (3.7%) | 5/8 (62.5%) | 0/0 (n/a) |
| Within 10 insns | 6/136 (4.4%) | 6/8 (75.0%) | 0/0 (n/a) |

## By Source Stratum

| Stratum | Cases | Proof-lost Coverage | Any-earlier Coverage | Exact (all cases) | Within 5 (all cases) | Within 10 (all cases) | Rejected Exact |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Selftest Cases | 85 | 5/85 (5.9%) | 6/85 (7.1%) | 1/85 (1.2%) | 2/85 (2.4%) | 3/85 (3.5%) | 71/85 (83.5%) |
| Real-World Cases | 51 | 3/51 (5.9%) | 7/51 (13.7%) | 2/51 (3.9%) | 3/51 (5.9%) | 3/51 (5.9%) | 25/51 (49.0%) |
| All Cases | 136 | 8/136 (5.9%) | 13/136 (9.6%) | 3/136 (2.2%) | 5/136 (3.7%) | 6/136 (4.4%) | 96/136 (70.6%) |

## By Taxonomy Class

| Taxonomy | Cases | Proof-lost Coverage | Any-earlier Coverage | Exact (proof_lost) | Within 5 (proof_lost) | Within 10 (proof_lost) |
| --- | --- | --- | --- | --- | --- | --- |
| `source_bug` | 100 | 5/100 (5.0%) | 10/100 (10.0%) | 1/5 (20.0%) | 2/5 (40.0%) | 3/5 (60.0%) |
| `lowering_artifact` | 18 | 3/18 (16.7%) | 3/18 (16.7%) | 2/3 (66.7%) | 3/3 (100.0%) | 3/3 (100.0%) |
| `verifier_limit` | 4 | 0/4 (0.0%) | 0/4 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |
| `env_mismatch` | 14 | 0/14 (0.0%) | 0/14 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |

## By Distance Bucket

| Distance | Cases | Proof-lost Coverage | Any-earlier Coverage | Exact (proof_lost) | Within 5 (proof_lost) | Within 10 (proof_lost) |
| --- | --- | --- | --- | --- | --- | --- |
| `0` | 118 | 5/118 (4.2%) | 10/118 (8.5%) | 1/5 (20.0%) | 2/5 (40.0%) | 3/5 (60.0%) |
| `1-5` | 6 | 0/6 (0.0%) | 0/6 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |
| `6-10` | 5 | 0/5 (0.0%) | 0/5 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |
| `11-25` | 6 | 3/6 (50.0%) | 3/6 (50.0%) | 2/3 (66.7%) | 3/3 (100.0%) | 3/3 (100.0%) |
| `26+` | 1 | 0/1 (0.0%) | 0/1 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |

## Distance Analysis

- Nonzero-distance cases: `18`
- Any earlier span on nonzero-distance cases: `3/18 (16.7%)`
- Any earlier span on earlier-root cases only: `3/17 (17.6%)`
- Cases with any earlier span in the nonzero-distance slice: `3`
- Exact GT root-cause match among that earlier-span slice: `2/3 (66.7%)`
- Within 5 instructions among that earlier-span slice: `3/3 (100.0%)`
- Within 10 instructions among that earlier-span slice: `3/3 (100.0%)`
- Note: the current labeled set has one later-root outlier where the ground-truth root cause is after the reject site.
- Later-root outlier(s): `stackoverflow-74178703`

| Case | Taxonomy | GT Root | GT Reject | BPFix Lost | BPFix Est | BPFix Reject | Any Earlier? | Exact | Within 5 | Within 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1062` | `lowering_artifact` | 8 | 242 | n/a | n/a | 242 | No | No | No | No |
| `stackoverflow-70750259` | `lowering_artifact` | 20 | 39 | n/a | n/a | 30 | No | No | No | No |
| `stackoverflow-76637174` | `lowering_artifact` | 39 | 54 | 44 | 44 | 54 | Yes | No | Yes | Yes |
| `stackoverflow-79530762` | `lowering_artifact` | 22 | 36 | 22 | 16 | 33 | Yes | Yes | Yes | Yes |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | `source_bug` | 67 | 80 | n/a | n/a | 80 | No | No | No | No |
| `stackoverflow-72575736` | `lowering_artifact` | 28 | 39 | 28 | 12 | 39 | Yes | Yes | Yes | Yes |
| `github-aya-rs-aya-1056` | `lowering_artifact` | 37 | 48 | n/a | n/a | 48 | No | No | No | No |
| `stackoverflow-74178703` | `lowering_artifact` | 204 | 195 | n/a | n/a | 0 | No | No | No | No |
| `stackoverflow-70729664` | `lowering_artifact` | 2940 | 2948 | n/a | n/a | 17 | No | No | No | No |
| `stackoverflow-70873332` | `lowering_artifact` | 11 | 18 | n/a | n/a | 0 | No | No | No | No |
| `stackoverflow-77762365` | `lowering_artifact` | 127 | 133 | n/a | n/a | 1 | No | No | No | No |
| `stackoverflow-76160985` | `lowering_artifact` | 189 | 195 | n/a | 193 | 193 | No | No | No | No |
| `stackoverflow-79485758` | `lowering_artifact` | 44 | 48 | n/a | n/a | 31 | No | No | No | No |
| `stackoverflow-73088287` | `lowering_artifact` | 69 | 73 | n/a | n/a | 73 | No | No | No | No |
| `stackoverflow-53136145` | `lowering_artifact` | 105 | 109 | n/a | n/a | 19 | No | No | No | No |
| `stackoverflow-72560675` | `lowering_artifact` | 24 | 27 | n/a | n/a | 25 | No | No | No | No |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` | `source_bug` | 5 | 7 | n/a | n/a | 65 | No | No | No | No |
| `stackoverflow-72074115` | `lowering_artifact` | 234 | 235 | n/a | n/a | 232 | No | No | No | No |
