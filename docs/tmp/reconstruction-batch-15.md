# Reconstruction Batch 15

Date: 2026-04-30

Scope:

- Assigned Batch 15 records only.
- Shared benchmark files, raw YAML, `raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not intentionally edited.
- Successful case directory created:
  - `bpfix-bench/cases/github-commit-cilium-bbf57970f552/`

## Summary

- Assigned records inspected: 20
- Local raw records present: 7
- Missing local raw records: 13
- Successful standalone verifier-reject reconstructions: 1
- Not admitted: 19

The successful case was admitted only after local `make clean`, `make`, and
`make replay-verify` produced a fresh verifier reject log that parses as
`trace_rich` with a terminal error and rejected instruction index.

## Successful Replays

### `github-commit-cilium-bbf57970f552`

Files:

- `bpfix-bench/cases/github-commit-cilium-bbf57970f552/Makefile`
- `bpfix-bench/cases/github-commit-cilium-bbf57970f552/prog.c`
- `bpfix-bench/cases/github-commit-cilium-bbf57970f552/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-bbf57970f552/capture.yaml`

Commands and outcomes:

- `make clean`: exit 0.
- `make`: exit 0, produced `prog.o`.
- `make replay-verify`: exit 2 because `bpftool` exited 255 on verifier
  rejection; produced `replay-verifier.log`.

Verifier outcome:

- terminal error: `invalid write to stack R1 off=-600 size=280`
- rejected instruction index: `9`
- parser check: `trace_rich` from fresh `replay-verifier.log`

Reconstruction basis: the raw fixed Cilium diff moves IPv6 NAT tuple and NAT
target scratch objects from stack-passed arguments into per-CPU map storage. The
standalone case models the pre-fix stack-pressure shape with two NAT-like stack
objects passed to helpers; clang is allowed to build the object, and the kernel
verifier rejects the second helper write beyond the BPF stack limit.

## Record Results

| raw_id | result | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-a36a4c93ff92` | no case | `environment_required` | Reducing `SNAT_COLLISION_RETRIES` is a generated Cilium NodePort/SNAT verifier-complexity tuning; the raw record has no terminal verifier log and a faithful failure depends on the full generated datapath and historical path explosion. |
| `github-commit-cilium-a41609e90bb9` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-a4e3bd900e3b` | no case | `out_of_scope_non_verifier` | Fixes double policy enforcement with IPsec and BPF host routing by changing delivery/redirect control flow; no verifier-load failure or terminal verifier message is present. |
| `github-commit-cilium-a73da3584b7e` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-a75f49716581` | no case | `not_reconstructable_from_diff` | A local wildcard-classifier loop probe rejected with `The sequence of 8193 jumps is too complex`, but the fresh log did not parse as `trace_rich`; the raw record has no verifier log to anchor an admissible terminal error. |
| `github-commit-cilium-a7d04d20c614` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-a8813d5fac61` | no case | `out_of_scope_non_verifier` | Drops service traffic when no backend is available and changes load-balancer fallback behavior; no verifier rejection is identified in the raw snippets. |
| `github-commit-cilium-a95188ba3286` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-aa251f8c61a5` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-ac8f896999c2` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-ad4a4ffcbe26` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-ae2f938dbd91` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-aee334a6e490` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-af50cf234e91` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-b6d2dc67fe83` | no case | `out_of_scope_non_verifier` | Removes redundant map-key fixups on load-balancer lookup failure paths; raw snippets describe code cleanup/behavioral simplification, not a verifier-load failure. |
| `github-commit-cilium-b7aefd932197` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-b817c50f4a17` | no case | `out_of_scope_non_verifier` | Adds NodePort L7 load-balancer redirect behavior. The visible verifier-workaround comments are pre-existing context, not the reconstructed failure fixed by this commit. |
| `github-commit-cilium-b917475f1c06` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-b920be7d25df` | no case | `missing_source` | No local raw YAML or repository reference for this assigned raw ID. |
| `github-commit-cilium-bbf57970f552` | case created | `replay_valid` | Reconstructed the IPv6 NAT stack-to-map-storage failure mode; local replay rejects as a stack write beyond verifier limits and parses as `trace_rich`. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg --files bpfix-bench/raw/gh
python3 - <<'PY'
# Loaded assigned raw YAML and summarized title, commit date, fix_type,
# source snippets, verifier-log presence, and diff_summary.
PY
```

Local probe attempts:

```bash
# github-commit-cilium-a75f49716581
make -C /tmp/bpfix-b15-a75 clean
make -C /tmp/bpfix-b15-a75
make -C /tmp/bpfix-b15-a75 replay-verify

# github-commit-cilium-bbf57970f552
make -C /tmp/bpfix-b15-bbf clean
make -C /tmp/bpfix-b15-bbf
make -C /tmp/bpfix-b15-bbf replay-verify
```

Final successful replay check:

```bash
cd bpfix-bench/cases/github-commit-cilium-bbf57970f552
make clean
make
make replay-verify

python3 - <<'PY'
# Parsed fresh replay-verifier.log with tools.replay_case.parse_verifier_log
# and compared terminal_error, rejected_insn_idx, and log_quality to case.yaml.
PY
```

Parsed replay result:

```text
github-commit-cilium-bbf57970f552: build=0 load=2 terminal="invalid write to stack R1 off=-600 size=280" rejected_insn_idx=9 quality=trace_rich
```

## Review

- `case.yaml` and `capture.yaml` use capture id
  `github-commit-cilium-bbf57970f552__kernel-6.15.11-clang-18-log2`.
- `source.kind` is `github_commit`.
- `reproducer.reconstruction` is `reconstructed`.
- `external_match.status` is `not_applicable`.
- Fresh parser output matches `case.yaml` for terminal error, rejected
  instruction index, and log quality.

## Review Recheck

Commands run from
`bpfix-bench/cases/github-commit-cilium-bbf57970f552`: `make clean` (0),
`make` (0), and `make replay-verify` (2, `bpftool` 255 verifier reject).
Parsed the fresh `replay-verifier.log` with
`tools.replay_case.parse_verifier_log`.

Findings: build succeeds; load is a verifier reject; parsed terminal error
`invalid write to stack R1 off=-600 size=280`, rejected instruction index `9`,
and log quality `trace_rich` match `case.yaml`. `capture_metadata:
capture.yaml` exists and is consistent with `capture.yaml`; capture ids use the
`__kernel-6.15.11-clang-18-log2` suffix and both capture files use
`kernel-6.15.11-clang-18-log2`. Validator-sensitive metadata values are
compatible: `reproducer.reconstruction: reconstructed`, `source.kind:
github_commit`, and `external_match.status: not_applicable`. The record table
covers 20 unique assigned raw IDs, and every non-admitted raw has a concrete
final classification. No case metadata changes were needed.
