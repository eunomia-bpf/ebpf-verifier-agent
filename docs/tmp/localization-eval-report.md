# Localization Evaluation

- Generated at: `2026-03-19T19:31:27+00:00`
- Evaluated non-quarantined ground-truth cases: `136`
- Cases with `root_cause_insn_idx != rejected_insn_idx`: `18`
- Earlier-root cases (`root_cause_insn_idx < rejected_insn_idx`): `17`
- Later-root cases (`root_cause_insn_idx > rejected_insn_idx`): `1`

## Coverage Metrics

- Proof-lost span emitted: `12/136 (8.8%)`
- Any earlier span before the rejected span: `14/136 (10.3%)`
- Proof-established span emitted: `12/136 (8.8%)`
- Rejected span emitted: `136/136 (100.0%)`
- Rejected span exact match: `114/136 (83.8%)`

## Accuracy When `proof_lost` Is Present

- Cases with `proof_lost`: `12`
- Exact GT root-cause match: `3/12 (25.0%)`
- Within 5 instructions: `8/12 (66.7%)`
- Within 10 instructions: `9/12 (75.0%)`
- Mean absolute error on `proof_lost` cases: `6.33`

## Conditional Accuracy Table

- `All` uses end-to-end denominators over all labeled cases; `Has proof_lost` is the conditional root-cause accuracy slice.

| Metric | All (N=136) | Has proof_lost (N=12) | No proof_lost (N=124) |
| --- | --- | --- | --- |
| Proof-lost coverage | 12/136 (8.8%) | 12/12 (100.0%) | 0/124 (0.0%) |
| Any-earlier coverage | 14/136 (10.3%) | 10/12 (83.3%) | 4/124 (3.2%) |
| Exact GT root match | 3/136 (2.2%) | 3/12 (25.0%) | 0/0 (n/a) |
| Within 5 insns | 8/136 (5.9%) | 8/12 (66.7%) | 0/0 (n/a) |
| Within 10 insns | 9/136 (6.6%) | 9/12 (75.0%) | 0/0 (n/a) |

## By Taxonomy Class

| Taxonomy | Cases | Proof-lost Coverage | Any-earlier Coverage | Exact (proof_lost) | Within 5 (proof_lost) | Within 10 (proof_lost) |
| --- | --- | --- | --- | --- | --- | --- |
| `source_bug` | 100 | 7/100 (7.0%) | 9/100 (9.0%) | 1/7 (14.3%) | 3/7 (42.9%) | 4/7 (57.1%) |
| `lowering_artifact` | 18 | 5/18 (27.8%) | 5/18 (27.8%) | 2/5 (40.0%) | 5/5 (100.0%) | 5/5 (100.0%) |
| `verifier_limit` | 4 | 0/4 (0.0%) | 0/4 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |
| `env_mismatch` | 14 | 0/14 (0.0%) | 0/14 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |

## By Distance Bucket

| Distance | Cases | Proof-lost Coverage | Any-earlier Coverage | Exact (proof_lost) | Within 5 (proof_lost) | Within 10 (proof_lost) |
| --- | --- | --- | --- | --- | --- | --- |
| `0` | 118 | 7/118 (5.9%) | 9/118 (7.6%) | 1/7 (14.3%) | 3/7 (42.9%) | 4/7 (57.1%) |
| `1-5` | 6 | 1/6 (16.7%) | 1/6 (16.7%) | 0/1 (0.0%) | 1/1 (100.0%) | 1/1 (100.0%) |
| `6-10` | 5 | 0/5 (0.0%) | 0/5 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |
| `11-25` | 6 | 4/6 (66.7%) | 4/6 (66.7%) | 2/4 (50.0%) | 4/4 (100.0%) | 4/4 (100.0%) |
| `26+` | 1 | 0/1 (0.0%) | 0/1 (0.0%) | 0/0 (n/a) | 0/0 (n/a) | 0/0 (n/a) |

## Distance Analysis

- Nonzero-distance cases: `18`
- Any earlier span on nonzero-distance cases: `5/18 (27.8%)`
- Any earlier span on earlier-root cases only: `5/17 (29.4%)`
- Cases with any earlier span in the nonzero-distance slice: `5`
- Exact GT root-cause match among that earlier-span slice: `2/5 (40.0%)`
- Within 5 instructions among that earlier-span slice: `5/5 (100.0%)`
- Within 10 instructions among that earlier-span slice: `5/5 (100.0%)`
- Note: the current labeled set has one later-root outlier where the ground-truth root cause is after the reject site.
- Later-root outlier(s): `stackoverflow-74178703`

| Case | Taxonomy | GT Root | GT Reject | BPFix Lost | BPFix Est | BPFix Reject | Any Earlier? | Exact | Within 5 | Within 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1062` | `lowering_artifact` | 8 | 242 | n/a | n/a | 242 | No | No | No | No |
| `stackoverflow-70750259` | `lowering_artifact` | 20 | 39 | 22 | n/a | 24 | Yes | No | Yes | Yes |
| `stackoverflow-76637174` | `lowering_artifact` | 39 | 54 | 41 | 41 | 54 | Yes | No | Yes | Yes |
| `stackoverflow-79530762` | `lowering_artifact` | 22 | 36 | 22 | 16 | 33 | Yes | Yes | Yes | Yes |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | `source_bug` | 67 | 80 | n/a | n/a | 80 | No | No | No | No |
| `stackoverflow-72575736` | `lowering_artifact` | 28 | 39 | 28 | 12 | 39 | Yes | Yes | Yes | Yes |
| `github-aya-rs-aya-1056` | `lowering_artifact` | 37 | 48 | n/a | n/a | 48 | No | No | No | No |
| `stackoverflow-74178703` | `lowering_artifact` | 204 | 195 | n/a | 191 | 191 | No | No | No | No |
| `stackoverflow-70729664` | `lowering_artifact` | 2940 | 2948 | n/a | n/a | 2947 | No | No | No | No |
| `stackoverflow-70873332` | `lowering_artifact` | 11 | 18 | n/a | n/a | 18 | No | No | No | No |
| `stackoverflow-77762365` | `lowering_artifact` | 127 | 133 | n/a | n/a | 129 | No | No | No | No |
| `stackoverflow-76160985` | `lowering_artifact` | 189 | 195 | n/a | 193 | 193 | No | No | No | No |
| `stackoverflow-79485758` | `lowering_artifact` | 44 | 48 | 48 | 28 | 48 | Yes | No | Yes | Yes |
| `stackoverflow-73088287` | `lowering_artifact` | 69 | 73 | n/a | n/a | 73 | No | No | No | No |
| `stackoverflow-53136145` | `lowering_artifact` | 105 | 109 | n/a | n/a | 109 | No | No | No | No |
| `stackoverflow-72560675` | `lowering_artifact` | 24 | 27 | n/a | n/a | 27 | No | No | No | No |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` | `source_bug` | 5 | 7 | n/a | n/a | 7 | No | No | No | No |
| `stackoverflow-72074115` | `lowering_artifact` | 234 | 235 | n/a | n/a | 232 | No | No | No | No |
