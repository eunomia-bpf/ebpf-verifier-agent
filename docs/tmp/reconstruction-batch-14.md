# Reconstruction Batch 14

Date: 2026-04-30

Scope:

- Assigned Batch 14 raw records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- Successful case directory created:
  - `bpfix-bench/cases/github-commit-cilium-99ac9998471f/`

## Summary

- Assigned records inspected: 20
- Successful standalone verifier-reject reconstructions: 1
- Attempted but not admitted because the fresh log did not parse as
  `trace_rich`: 1
- Not reconstructed: 18

Most records in this batch are Cilium full-datapath complexity reductions,
compile/configuration fixes, or datapath behavior changes without a standalone
terminal verifier log. One record was admitted: the backport record for moving
large IPv6 NAT scratch storage from stack to a map.

## Successful Replay

### `github-commit-cilium-99ac9998471f`

Files:

- `bpfix-bench/cases/github-commit-cilium-99ac9998471f/Makefile`
- `bpfix-bench/cases/github-commit-cilium-99ac9998471f/prog.c`
- `bpfix-bench/cases/github-commit-cilium-99ac9998471f/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-99ac9998471f/capture.yaml`

Commands and outcomes:

- `make clean`: exit 0
- `make`: exit 0, produced `prog.o`
- `make replay-verify`: exit 2 because `bpftool` exited 255 on verifier
  rejection; produced a fresh `replay-verifier.log`

Fresh parsed verifier outcome:

- terminal error: `invalid write to stack R1 off=-600 size=600`
- rejected instruction index: `3`
- log quality: `trace_rich`

Reconstruction basis: the commit moves `struct ipv6_nat_entry` scratch values
from stack storage to a per-CPU array map because the full Cilium path was close
to the 512-byte BPF stack limit. The standalone program forces a 600-byte stack
buffer to be passed as writable helper memory, reproducing the verifier-visible
oversized stack access class.

## Attempted Not Admitted

- `github-commit-cilium-a185c1103518`: reconstructed the commit's exact
  XDP/read-only map-value shape with `BPF_F_RDONLY_PROG` and
  `bpf_xdp_store_bytes()`. Local replay rejects with
  `write into map forbidden, value_size=8 off=0 size=6`; a direct map write
  variant similarly rejects with `write into map forbidden, value_size=4 off=0
  size=4`. `tools.replay_case.parse_verifier_log` currently returns
  `terminal_error=None`, `log_quality=no_terminal_error` for that terminal line,
  so the case was not admitted under the required `trace_rich` rule.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-975f5bd9cd2b` | no case | `environment_required` | Removes debug messages to reduce instruction count with debugging enabled; replay depends on a historical full Cilium debug build and instruction-size pressure, with no standalone terminal log. |
| `github-commit-cilium-99070f653924` | no case | `out_of_scope_non_verifier` | Cleans up includes to fix compile errors on older kernels; the failure mode is build/header compatibility, not kernel verifier rejection. |
| `github-commit-cilium-9987e4816d1a` | no case | `environment_required` | Adds tail calls for IPv4-only/IPv6-only generated datapath complexity; faithful replay requires the full Cilium K8sVerifier configuration. |
| `github-commit-cilium-99ac9998471f` | case created | `replay_valid` | Local replay rejects with the parsed oversized stack write that the upstream map-storage change avoids. |
| `github-commit-cilium-9b48866e7acd` | no case | `environment_required` | Tail-calls IPv6 RevDNAT from XDP to avoid a 1M processed-instruction limit in selected older/full Cilium configurations. |
| `github-commit-cilium-9b644fc3fb8f` | no case | `environment_required` | `.data` section handling targets older kernels that reject missing global-data rewrites; the raw captured log is an object-without-program error, not a local verifier trace. |
| `github-commit-cilium-9cbb6e594247` | no case | `environment_required` | Commit body cites a 4.19 full-program complexity failure, `BPF program is too large. Processed 131073 insn`; local faithful replay requires that historical Cilium build. |
| `github-commit-cilium-9d2aecfcaa92` | no case | `environment_required` | Splits tracing and processing into tail calls to simplify `cil_from_netdev`/`cil_from_host`; no isolated rejected operation is present. |
| `github-commit-cilium-9de5f4338c9d` | no case | `environment_required` | Enables an LXC-entry tail call when debug is enabled to reduce full-program complexity; no standalone terminal verifier error is available. |
| `github-commit-cilium-9e108c171ed1` | no case | `environment_required` | NAT46 support was split into tail calls to stay under the old 4K instruction/complexity limit; replay depends on the historical full datapath. |
| `github-commit-cilium-9f27973a1052` | no case | `out_of_scope_non_verifier` | Fixes an SCTP-over-IPv6 checksum condition in load-balancing logic; no verifier-load failure is implicated. |
| `github-commit-cilium-9f4d267c1edb` | no case | `out_of_scope_non_verifier` | Checkpatch formatting/alignment cleanup in a test file; not a BPF verifier rejection. |
| `github-commit-cilium-9f8b2a99a9d4` | no case | `environment_required` | Combines IPv6 extension-header walks to reduce verifier complexity in full Cilium programs; no terminal reject is isolated. |
| `github-commit-cilium-a04698e3b464` | no case | `environment_required` | Reuses an IPv6 NAT tuple to reduce complexity and preserve later semantics; faithful verifier behavior is tied to full NAT/CT datapath generation. |
| `github-commit-cilium-a0d059e1192e` | no case | `environment_required` | Splits IPv6 SNAT/RevSNAT functions to reduce verifier complexity; no standalone current-kernel reject is identified from the diff. |
| `github-commit-cilium-a0ec2ad991c3` | no case | `out_of_scope_non_verifier` | Decouples masquerade and NodePort address selection; the verifier note describes missed constant optimization, not a load rejection. |
| `github-commit-cilium-a156825297d2` | no case | `environment_required` | Extracts source-ID resolution from high-complexity host programs; replay requires historical generated Cilium host datapath. |
| `github-commit-cilium-a185c1103518` | no case | `missing_verifier_log` | Local probes reproduce the raw `write into map forbidden` verifier rejection, but that terminal line does not parse as `trace_rich` with the current benchmark parser. |
| `github-commit-cilium-a1d54e34f68f` | no case | `environment_required` | Adds pruning checkpoints for older 4.9/4.14 verifier complexity limits; no standalone current-kernel reject is available. |
| `github-commit-cilium-a2086bcc5b3c` | no case | `environment_required` | Compiles out NodePort scope-switch code to reduce 4.9 complexity; faithful replay requires old full Cilium program generation. |

## Verification Commands

Successful case:

```bash
cd bpfix-bench/cases/github-commit-cilium-99ac9998471f
make clean
make
make replay-verify
```

Parser check:

```bash
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
case = Path("bpfix-bench/cases/github-commit-cilium-99ac9998471f")
print(parse_verifier_log((case / "replay-verifier.log").read_text(),
                         source="replay-verifier.log"))
PY
```

Parsed replay result:

```text
github-commit-cilium-99ac9998471f: build=0 load=2 terminal="invalid write to stack R1 off=-600 size=600" rejected_insn_idx=3 quality=trace_rich
```

## Review

Commands run for `bpfix-bench/cases/github-commit-cilium-99ac9998471f/`:

- `make clean`: exit 0.
- `make`: exit 0; rebuilt `prog.o`.
- `make replay-verify`: exit 2 from `bpftool` verifier rejection; refreshed
  `replay-verifier.log`.

Fresh `tools.replay_case.parse_verifier_log` result matches `case.yaml`:
terminal error `invalid write to stack R1 off=-600 size=600`, rejected
instruction index `3`, and log quality `trace_rich`. The case metadata
references `capture_metadata: capture.yaml`; `case.yaml` and `capture.yaml`
agree on capture ID, environment ID `kernel-6.15.11-clang-18-log2`, build/load
commands, and replay status. Validator-sensitive fields are set to
`reproducer.reconstruction: reconstructed`, `source.kind: github_commit`, and
`external_match.status: not_applicable`; the capture ID ends with
`__kernel-6.15.11-clang-18-log2`.

The record table covers all 20 Batch 14 raw IDs from
`github-commit-cilium-975f5bd9cd2b` through
`github-commit-cilium-a2086bcc5b3c`. Each non-admitted raw record has a concrete
final classification and reason. No metadata changes were required.
