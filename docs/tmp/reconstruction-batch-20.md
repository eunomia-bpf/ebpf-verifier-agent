# Reconstruction Batch 20

Date: 2026-04-30

Scope:

- Assigned Batch 20 records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- No successful case directory was created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 1
- Missing local raw records: 19
- Successful standalone verifier-reject reconstructions: 0
- Attempted but accepted by the local verifier: 1
- Not admitted: 20

Only `github-commit-cilium-ff54dbd703b6` is present locally in
`bpfix-bench/raw/gh/` and `bpfix-bench/raw/index.yaml`. The other assigned
records have no local raw YAML record, so they were classified as
`missing_source`.

The available Cilium record describes a 4.19.57 verifier complaint in
`bpf_lxc` with DSR. A standalone tc probe was built to model the pre-fix shape:
validate an IPv4-header byte, call `bpf_skb_load_bytes()`, and then read through
the previously validated packet pointer without revalidating `data`,
`data_end`, and `ip4`. On the pinned `kernel-6.15.11-clang-18-log2`
environment, that probe was accepted, so no replayable verifier-reject case was
admitted.

## Attempted Not Admitted

- `github-commit-cilium-ff54dbd703b6`: local stale-packet-pointer-after-helper
  probe accepted on kernel 6.15.11. The raw record has no captured verifier log
  block, and the upstream commit's complaint is explicitly tied to kernel
  4.19.57 behavior.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-fd55c209169d` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-fd55c209169d.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ff50d721c009` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ff50d721c009.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ff54dbd703b6` | no case | `attempted_accepted` | Standalone tc probe matching the raw DSR shape was accepted locally: direct packet bounds check, `bpf_skb_load_bytes()`, then a post-helper IPv4-header byte read without revalidation. No fresh verifier rejection was available on kernel 6.15.11. |
| `github-commit-libbpf-007d0c414207` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-007d0c414207.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-01169b03e081` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-01169b03e081.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-019713cd7605` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-019713cd7605.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-01ee4dad718d` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-01ee4dad718d.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-06535b717f6c` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-06535b717f6c.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-06d70e86b48c` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-06d70e86b48c.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-085a9e223fe1` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-085a9e223fe1.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-0ad08758fb58` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-0ad08758fb58.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-0d6d63a86a5d` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-0d6d63a86a5d.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-0ec286eeccf1` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-0ec286eeccf1.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-139206f6c12b` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-139206f6c12b.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-14c4ab219186` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-14c4ab219186.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-162ee4280c55` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-162ee4280c55.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-16eb7b0d5e5d` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-16eb7b0d5e5d.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-1840a0640841` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-1840a0640841.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-185b162778da` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-185b162778da.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-libbpf-19500d45edb5` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-libbpf-19500d45edb5.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |

## Commands Run

Context and raw inspection:

```bash
git status --short
test -f bpfix-bench/raw/gh/<assigned-id>.yaml
rg -n "<assigned-id>" bpfix-bench/raw/index.yaml bpfix-bench/cases docs/tmp
sed -n '1,280p' bpfix-bench/raw/gh/github-commit-cilium-ff54dbd703b6.yaml
```

Upstream commit context checked:

```text
https://github.com/cilium/cilium/commit/ff54dbd703b6f30140a2671c3e03074bfa4642ed.patch
```

Local non-admitted probe:

```bash
clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 \
  -xc -c -o /tmp/b20-ff54.o -
sudo -n bpftool -d prog load /tmp/b20-ff54.o /sys/fs/bpf/b20-ff54
```

No `make clean`, `make`, or `make replay-verify` commands were run inside an
admitted `bpfix-bench/cases/<assigned raw id>/` directory because no assigned
record produced a candidate satisfying the admission rule.

## Review

- Confirmed the Record Results table covers all 20 assigned raw IDs exactly
  once.
- Confirmed only `github-commit-cilium-ff54dbd703b6` has a local raw YAML record
  and `bpfix-bench/raw/index.yaml` entry.
- Confirmed no `bpfix-bench/cases/<assigned raw id>/` directory exists for any
  assigned Batch 20 ID.
- No successful case files were created, so no `case.yaml` metadata admission
  checks were required.
- Confirmed `github-commit-cilium-ff54dbd703b6` is reported as locally
  accepted; because no verifier rejection was reproduced, it should not be
  admitted as a verifier-reject benchmark case.
- No blockers.
