# Localization Evaluation

- Generated at: `2026-03-19T19:02:14+00:00`
- Evaluated non-quarantined ground-truth cases: `136`
- Cases with `root_cause_insn_idx != rejected_insn_idx`: `18`
- Earlier-root cases (`root_cause_insn_idx < rejected_insn_idx`): `17`
- Later-root cases (`root_cause_insn_idx > rejected_insn_idx`): `1`

## Overall

- Proof-lost span present: `12/136 (8.8%)`
- Proof-lost exact match: `3/136 (2.2%)`
- Proof-lost within 5 instructions: `8/136 (5.9%)`
- Proof-lost within 10 instructions: `9/136 (6.6%)`
- Rejected span exact match: `114/136 (83.8%)`
- Earlier-span found on earlier-root cases: `5/17 (29.4%)`

## By Taxonomy Class

| Taxonomy | Cases | Exact | Within 5 | Within 10 | Rejected Exact |
| --- | --- | --- | --- | --- | --- |
| `source_bug` | 100 | 1/100 (1.0%) | 3/100 (3.0%) | 4/100 (4.0%) | 89/100 (89.0%) |
| `lowering_artifact` | 18 | 2/18 (11.1%) | 5/18 (27.8%) | 5/18 (27.8%) | 11/18 (61.1%) |
| `verifier_limit` | 4 | 0/4 (0.0%) | 0/4 (0.0%) | 0/4 (0.0%) | 4/4 (100.0%) |
| `env_mismatch` | 14 | 0/14 (0.0%) | 0/14 (0.0%) | 0/14 (0.0%) | 10/14 (71.4%) |

## By Distance Bucket

| Distance | Cases | Exact | Within 5 | Within 10 | Rejected Exact |
| --- | --- | --- | --- | --- | --- |
| `0` | 118 | 1/118 (0.8%) | 3/118 (2.5%) | 4/118 (3.4%) | 103/118 (87.3%) |
| `1-5` | 6 | 0/6 (0.0%) | 1/6 (16.7%) | 1/6 (16.7%) | 5/6 (83.3%) |
| `6-10` | 5 | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 1/5 (20.0%) |
| `11-25` | 6 | 2/6 (33.3%) | 4/6 (66.7%) | 4/6 (66.7%) | 4/6 (66.7%) |
| `26+` | 1 | 0/1 (0.0%) | 0/1 (0.0%) | 0/1 (0.0%) | 1/1 (100.0%) |

## Nonzero-Distance Focus

- Nonzero-distance cases: `18`
- Proof-lost exact match: `2/18 (11.1%)`
- Proof-lost within 5 instructions: `5/18 (27.8%)`
- Proof-lost within 10 instructions: `5/18 (27.8%)`
- Earlier-span found on earlier-root cases: `5/17 (29.4%)`
- Note: `distance_insns > 0` is not always an earlier-root case in the canonical labels. In the current ground truth there is one later-root case: `stackoverflow-74178703` (`root=204`, `reject=195`).

| Case | Taxonomy | GT Root | GT Reject | BPFix Lost | BPFix Est | BPFix Reject | Exact | Within 5 | Earlier Span? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1062` | `lowering_artifact` | 8 | 242 | n/a | n/a | 242 | No | No | No |
| `stackoverflow-70750259` | `lowering_artifact` | 20 | 39 | 22 | n/a | 24 | No | Yes | Yes |
| `stackoverflow-76637174` | `lowering_artifact` | 39 | 54 | 41 | 41 | 54 | No | Yes | Yes |
| `stackoverflow-79530762` | `lowering_artifact` | 22 | 36 | 22 | 16 | 33 | Yes | Yes | Yes |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | `source_bug` | 67 | 80 | n/a | n/a | 80 | No | No | No |
| `stackoverflow-72575736` | `lowering_artifact` | 28 | 39 | 28 | 12 | 39 | Yes | Yes | Yes |
| `github-aya-rs-aya-1056` | `lowering_artifact` | 37 | 48 | n/a | n/a | 48 | No | No | No |
| `stackoverflow-74178703` | `lowering_artifact` | 204 | 195 | n/a | 191 | 191 | No | No | No |
| `stackoverflow-70729664` | `lowering_artifact` | 2940 | 2948 | n/a | n/a | 2947 | No | No | No |
| `stackoverflow-70873332` | `lowering_artifact` | 11 | 18 | n/a | n/a | 18 | No | No | No |
| `stackoverflow-77762365` | `lowering_artifact` | 127 | 133 | n/a | n/a | 129 | No | No | No |
| `stackoverflow-76160985` | `lowering_artifact` | 189 | 195 | n/a | 193 | 193 | No | No | No |
| `stackoverflow-79485758` | `lowering_artifact` | 44 | 48 | 48 | 28 | 48 | No | Yes | Yes |
| `stackoverflow-73088287` | `lowering_artifact` | 69 | 73 | n/a | n/a | 73 | No | No | No |
| `stackoverflow-53136145` | `lowering_artifact` | 105 | 109 | n/a | n/a | 109 | No | No | No |
| `stackoverflow-72560675` | `lowering_artifact` | 24 | 27 | n/a | n/a | 27 | No | No | No |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` | `source_bug` | 5 | 7 | n/a | n/a | 7 | No | No | No |
| `stackoverflow-72074115` | `lowering_artifact` | 234 | 235 | n/a | n/a | 232 | No | No | No |
