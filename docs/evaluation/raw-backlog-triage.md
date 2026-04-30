# Raw Backlog Triage

This document explains the non-admitted external raw records in
`bpfix-bench/raw/`. It replaces the old coarse `not_attempted` bucket with
more precise statuses so the paper can distinguish raw material from replayable
benchmark cases.

Primary benchmark claims must still use only `bpfix-bench/cases/`, where each
case locally builds and replays to a verifier rejection. Raw records are an audit
surface and a future expansion pool.

## Status Definitions

| status | meaning |
|---|---|
| `candidate_for_replay` | Has verifier-reject evidence and enough source/context to plausibly build a local replay harness next. |
| `needs_manual_reconstruction` | Useful raw evidence exists, but a standalone `prog.c`/`Makefile`/loader harness must be manually reconstructed. |
| `missing_verifier_log` | Source/context exists, but the raw record lacks a concrete verifier log. |
| `missing_source` | Verifier-like evidence exists, but source or harness context is missing. |
| `environment_required` | Reproduction depends on a larger framework, cluster, kernel feature, architecture, or toolchain environment not captured locally. |
| `out_of_scope_non_verifier` | Collected record is not a verifier-reject benchmark candidate. |

## Current Counts

The current raw index has no remaining `not_attempted` records.

| status | records |
|---|---:|
| `needs_manual_reconstruction` | 566 |
| `replay_valid` | 101 |
| `attempted_unknown` | 35 |
| `environment_required` | 8 |
| `candidate_for_replay` | 8 |
| `missing_source` | 5 |
| `attempted_accepted` | 4 |
| `missing_verifier_log` | 4 |
| `replay_reject_no_rejected_insn` | 3 |
| `out_of_scope_non_verifier` | 2 |
| **total** | **736** |

By source:

| source_kind | replay_valid | attempted/other replay status | candidate_for_replay | needs_manual_reconstruction | missing_source | missing_verifier_log | environment_required | out_of_scope_non_verifier | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `github_commit` | 0 | 30 | 0 | 561 | 0 | 0 | 0 | 0 | 591 |
| `github_issue` | 18 | 7 | 1 | 0 | 1 | 0 | 4 | 0 | 31 |
| `stackoverflow` | 83 | 5 | 7 | 5 | 4 | 4 | 4 | 2 | 114 |

`attempted/other replay status` combines `attempted_accepted`,
`attempted_unknown`, and `replay_reject_no_rejected_insn`.

## Candidate For Replay

These 8 records are the next best manual reconstruction targets:

| raw_id | reason |
|---|---|
| `github-aya-rs-aya-864` | Clear verifier reject plus embedded Aya eBPF source/context. |
| `stackoverflow-48267671` | Reject log and complete small sockops/tail-call program. |
| `stackoverflow-62936008` | Load rejection plus BPF/user/Makefile context. |
| `stackoverflow-68460177` | BCC script plus verifier reject. |
| `stackoverflow-70392721` | BPF/user code, disassembly, and BTF/load failure context. |
| `stackoverflow-77191387` | Complete cgroup skb program plus verifier reject. |
| `stackoverflow-77225068` | Complete XDP program and unsupported-helper reject log. |
| `stackoverflow-79513583` | BPF/user/header snippets plus concrete reserved-fields reject. |

## Why Most Commit-Derived Records Are Not Cases

The 561 `github_commit` records in `needs_manual_reconstruction` usually have a
buggy/fixed diff but not a self-contained verifier reproducer. They often lack a
captured verifier log, map definitions, attach type, loader command, kernel
environment, or complete standalone program. They are useful raw evidence, but
not benchmark cases until reconstructed into:

```text
bpfix-bench/cases/<case>/
  prog.c
  Makefile
  case.yaml
```

and validated by `tools/validate_benchmark.py --replay bpfix-bench`.

## Out Of Scope Examples

Some raw records should not become verifier-reject cases. For example,
`stackoverflow-47591176` has a verifier log showing successful load; the user
problem is `tc` direct-action runtime semantics. Such records remain useful for
corpus transparency, but they must not enter the primary benchmark.

## Audit Command

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter, defaultdict
import yaml

idx = yaml.safe_load(Path("bpfix-bench/raw/index.yaml").read_text())
print(Counter(e["reproduction_status"] for e in idx["entries"]))
by_source = defaultdict(Counter)
for entry in idx["entries"]:
    by_source[entry["source_kind"]][entry["reproduction_status"]] += 1
for source, counts in sorted(by_source.items()):
    print(source, dict(counts))
PY
```
