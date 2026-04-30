# Reconstruction Batch 17

Date: 2026-04-30

Scope:

- Assigned Batch 17 raw records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not intentionally edited.
- Successful case directory created:
  - `bpfix-bench/cases/github-commit-cilium-de679382fe1e/`

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Attempted but accepted by the local verifier: 2
- Not admitted: 19

All assigned raw records lack an original verifier log. The admitted case was
created only after local `make clean`, `make`, and `make replay-verify`
produced a fresh verifier rejection whose `replay-verifier.log` parses as
`trace_rich` with a terminal error and rejected instruction index.

## Successful Replay

### `github-commit-cilium-de679382fe1e`

Files:

- `bpfix-bench/cases/github-commit-cilium-de679382fe1e/Makefile`
- `bpfix-bench/cases/github-commit-cilium-de679382fe1e/prog.c`
- `bpfix-bench/cases/github-commit-cilium-de679382fe1e/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-de679382fe1e/capture.yaml`

Commands and outcomes:

- `make clean`: exit 0.
- `make`: exit 0, produced `prog.o`.
- `make replay-verify`: exit 2 because `bpftool` exited 255 on verifier
  rejection; produced fresh `replay-verifier.log`.

Fresh parsed verifier outcome:

- terminal error: `invalid access to packet, off=0 size=1, R2(id=0,off=0,r=0)`
- rejected instruction index: `4`
- log quality: `trace_rich`

Reconstruction basis: the commit fixes an ICMPv6 load failure on L3-only
devices where Cilium's effective `ETH_HLEN` can be zero even though an Ethernet
header is 14 bytes. The standalone program models the pre-fix shape: it proves
only `data + 0 <= data_end`, then dereferences `eth->h_dest[0]`, so the kernel
verifier rejects the packet load.

## Attempted Not Admitted

- `github-commit-cilium-cf3976af0d06`: endpoint-helper and plain-`memcpy`
  probes for the commit's misaligned stack-access note built and loaded on the
  local 6.15.11 verifier. No local verifier rejection was available.
- `github-commit-cilium-cf88cad9bbdb`: a VTEP-MAC helper-access probe based on
  the upstream `R1 invalid mem access 'inv'` note also loaded on the local
  verifier. The committed diff already contains the initialized `vtep_mac`
  workaround, so the raw before/after diff does not contain a replayable buggy
  program.

## Record Results

| raw_id | result | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-cf3976af0d06` | no case | `attempted_accepted` | Local endpoint map-update and memcpy/stack-alignment probes accepted on kernel 6.15.11; the raw record has no terminal verifier log to anchor a stricter reconstruction. |
| `github-commit-cilium-cf88cad9bbdb` | no case | `attempted_accepted` | The upstream message mentions a development-time `R1 invalid mem access 'inv'`, but the committed diff already initializes `vtep_mac`; a local VTEP helper-access probe accepted. |
| `github-commit-cilium-d19889561aed` | no case | `environment_required` | Removes `relax_verifier()` to save instructions in a historical Cilium 4.9 full-datapath build; no standalone rejected operation is present. |
| `github-commit-cilium-d21f65406f1a` | no case | `out_of_scope_non_verifier` | Adds WireGuard strict-mode compile/complexity test configuration; no verifier-load failure or buggy BPF operation is identified. |
| `github-commit-cilium-d2274ab14652` | no case | `out_of_scope_non_verifier` | Adds a test for larger built-in `memcmp` lengths while keeping iterations low to avoid test complexity; it is not a verifier rejection fix. |
| `github-commit-cilium-d261ac587615` | no case | `out_of_scope_non_verifier` | Corrects VXLAN VNI checksum update flags; the failure mode is packet checksum correctness, not verifier rejection. |
| `github-commit-cilium-d2b63414e57e` | no case | `environment_required` | Passes existing `fraginfo` into LB tuple extraction to reduce verifier complexity in generated Cilium programs; faithful replay depends on the full datapath. |
| `github-commit-cilium-d3edaec19789` | no case | `not_reconstructable_from_diff` | The commit design notes verifier constraints around keeping two policy lookup results, but the diff intentionally avoids that shape and has no terminal reject log. |
| `github-commit-cilium-d3ff998f2b30` | no case | `environment_required` | Commit body cites an alternative 4.19 full-program complexity failure, `BPF program is too large. Processed 131073 insn`; the committed diff is a SNAT behavior fix and needs historical Cilium generation to replay. |
| `github-commit-cilium-d538b1fa9d39` | no case | `out_of_scope_non_verifier` | Fixes swapped CT lookup parameters affecting IPv6 packet tracing and CT state behavior; no verifier-load failure is implicated. |
| `github-commit-cilium-d5b73d68898d` | no case | `out_of_scope_non_verifier` | Populates ipcache entries with node IDs and discusses avoiding an extra lookup for complexity/performance; no verifier rejection is identified. |
| `github-commit-cilium-d7c5c0c7062f` | no case | `environment_required` | Copies map values to stack only for kernels before 4.18 where helpers could not directly access map values; local 6.15.11 accepts the modern shape. |
| `github-commit-cilium-d7f58e84d878` | no case | `environment_required` | Replaces ipcache lookup helpers for older-kernel support; reconstruction would require the unsupported historical helper/map-value behavior. |
| `github-commit-cilium-d8b783be3808` | no case | `environment_required` | Caches `skb->protocol` to help an old compiler/verifier full datapath stay tractable; no isolated current-kernel terminal reject is available. |
| `github-commit-cilium-da04e683faeb` | no case | `environment_required` | Splits SNAT mapping helpers to improve full-datapath verifier complexity; no standalone rejected operation appears in the raw snippets. |
| `github-commit-cilium-dbc0d32daf17` | no case | `environment_required` | Moves egress handling into a tail call to avoid the host program growing too large; replay depends on the generated Cilium program size. |
| `github-commit-cilium-dc5dd36fef04` | no case | `out_of_scope_non_verifier` | Switches IPv6 checksum updates to use `BPF_F_IPV6` with runtime fallback; this is checksum correctness/kernel-feature handling, not a verifier reject. |
| `github-commit-cilium-dcc3dcf02e71` | no case | `out_of_scope_non_verifier` | Removes `CT_REOPENED` behavior to fix stale CT/proxy redirection semantics; no verifier-load failure is present. |
| `github-commit-cilium-de679382fe1e` | case created | `replay_valid` | Reconstructed the L3-only Ethernet-header bounds bug; local replay rejects and parses as `trace_rich`. |
| `github-commit-cilium-df56cce8f0a7` | no case | `out_of_scope_non_verifier` | Fixes hairpin service flow behavior when routing is disabled; the commit discusses complexity/readability tradeoffs but no verifier rejection. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg -n "github-commit-cilium-..." -S .
python3 - <<'PY'
# Loaded assigned raw YAML and summarized title, commit date, fix_type,
# source snippets, verifier-log presence, and diff_summary.
PY
curl -fsSL https://github.com/cilium/cilium/commit/<sha>.patch
```

Local probes:

```bash
# github-commit-cilium-de679382fe1e
clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -xc -c -o /tmp/b17-de679.o -
sudo -n bpftool -d prog load /tmp/b17-de679.o /sys/fs/bpf/b17-de679

# github-commit-cilium-cf3976af0d06
clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -xc -c -o /tmp/b17-cf3976.o -
sudo -n bpftool -d prog load /tmp/b17-cf3976.o /sys/fs/bpf/b17-cf3976

# github-commit-cilium-cf88cad9bbdb
clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -xc -c -o /tmp/b17-cf88.o -
sudo -n bpftool -d prog load /tmp/b17-cf88.o /sys/fs/bpf/b17-cf88
```

Final successful replay check:

```bash
cd bpfix-bench/cases/github-commit-cilium-de679382fe1e
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
github-commit-cilium-de679382fe1e: build=0 load=2 terminal="invalid access to packet, off=0 size=1, R2(id=0,off=0,r=0)" rejected_insn_idx=4 quality=trace_rich
```

## Review

- `case.yaml` and `capture.yaml` use capture ID
  `github-commit-cilium-de679382fe1e__kernel-6.15.11-clang-18-log2`.
- `source.kind` is `github_commit`.
- `reproducer.reconstruction` is `reconstructed`.
- `external_match.status` is `not_applicable`.
- Fresh parser output matches `case.yaml` for terminal error, rejected
  instruction index, and log quality.

## Review (QC)

Fresh verification commands run from
`bpfix-bench/cases/github-commit-cilium-de679382fe1e`:

```bash
make clean
make
make replay-verify
```

`make clean` and `make` exited 0. `make replay-verify` exited 2 because
`bpftool` returned 255 for the expected verifier rejection and regenerated
`replay-verifier.log`.

Fresh parser comparison using `tools.replay_case.parse_verifier_log`:

- terminal error: `invalid access to packet, off=0 size=1, R2(id=0,off=0,r=0)`
- rejected instruction index: `4`
- log quality: `trace_rich`

These values match `case.yaml`. `capture_metadata: capture.yaml` exists, the
case and capture IDs match, and both use
`github-commit-cilium-de679382fe1e__kernel-6.15.11-clang-18-log2` with
environment `kernel-6.15.11-clang-18-log2`. Metadata already used
validator-compatible values for `reproducer.reconstruction`, `source.kind`, and
`external_match.status`, so no case metadata edits were required. The record
table covers 20 unique assigned raw IDs; all 20 local raw files exist, and all
19 non-admitted records have concrete final classifications.
