# Reconstruction Batch 27

Date: 2026-04-30

Scope:

- Assigned Batch 27 records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- Created one admitted case directory:
  `bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/`.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Not admitted: 19

Most records are Cilium verifier-workaround commits without a captured verifier
terminal error. The admitted record reconstructs the XDP `ctx_adjust_room`
failure shape: packet pointers are proven before `bpf_xdp_adjust_head()` and
then reused after the helper invalidates them. Local replay rejects on
`kernel-6.15.11-clang-18-log2`, and `tools.replay_case.parse_verifier_log`
parses the fresh log as trace-rich with both terminal error and rejected
instruction index.

## Successful Replays

| raw_id | commands | parsed verifier outcome |
| --- | --- | --- |
| `github-commit-cilium-2ff1a462cd33` | `make clean` rc 0; `make` rc 0; `make replay-verify` rc 2 (`bpftool` verifier reject) | `log_quality=trace_rich`; `terminal_error="R7 invalid mem access 'scalar'"`; `rejected_insn_idx=10` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-2c3263a80020` | no case | `missing_verifier_log` | Metrics-map test flake record has code snippets but no verifier log or terminal error to anchor a faithful reject replay. |
| `github-commit-cilium-2c9c8c17aeeb` | no case | `environment_required` | Inline/branch workaround is described as keeping state acceptable to older kernels; local stale-helper-style probe accepted on the current kernel. |
| `github-commit-cilium-2d5be9ea8679` | no case | `not_reconstructable_from_diff` | Large cilium_host unroutable-control-flow rewrite lacks a verifier log and enough standalone source context for a faithful local reject. |
| `github-commit-cilium-2e344bf76438` | no case | `out_of_scope_non_verifier` | Compile-tested binary symbol replacement has no verifier log and does not identify a load-time verifier rejection. |
| `github-commit-cilium-2e39b5cca8c7` | no case | `not_reconstructable_from_diff` | Destination-MAC removal touches large LXC paths and invalidation comments, but no terminal verifier log or self-contained source is available. |
| `github-commit-cilium-2f0275ee3ee2` | no case | `environment_required` | Raw summary explicitly targets older-kernel rejection of global functions whose arguments lost PTR_TO_CTX typing; local global-ctx probe accepted. |
| `github-commit-cilium-2f950671d3ea` | no case | `environment_required` | FROM_HOST/inlining workaround and direct-packet-read comments are tied to old verifier behavior; no fresh local reject was reconstructed. |
| `github-commit-cilium-2fe8ce47afdf` | no case | `environment_required` | Node-config VTEP loop-size reduction cites older-kernel unrolled-loop limits; no local current-kernel reject was available. |
| `github-commit-cilium-2ff1a462cd33` | admitted | `replay_valid` | Added XDP adjust-head stale-packet-pointer replay; fresh local log is trace-rich with terminal error and rejected instruction index. |
| `github-commit-cilium-30102d66d535` | no case | `environment_required` | Conntrack/LPM loop rewrite is tied to older-kernel unrolled-loop capacity; no terminal verifier log was captured. |
| `github-commit-cilium-3076311add63` | no case | `environment_required` | EGW CT lookup slimming is an older-kernel verifier-state workaround without a captured terminal reject. |
| `github-commit-cilium-321ec097bcf1` | no case | `environment_required` | Conntrack inline/complexity workaround lacks a captured verifier log and appears dependent on historical verifier limits. |
| `github-commit-cilium-3310f6906cd1` | no case | `environment_required` | IPIP health-encap fix is explicitly for older kernels and has no local verifier log to replay. |
| `github-commit-cilium-3323fb0c62a9` | no case | `out_of_scope_non_verifier` | Raw log parses as `no_terminal_error`; libbpf reports the object contains no BPF program rather than a verifier rejection. |
| `github-commit-cilium-334f7f0456b5` | no case | `not_reconstructable_from_diff` | L3 local-delivery type/cast change has no verifier log and insufficient standalone context for a faithful reject. |
| `github-commit-cilium-36c7d6628244` | no case | `not_reconstructable_from_diff` | NodePort HostFW ingress split/type change spans several Cilium helpers with no verifier terminal error. |
| `github-commit-cilium-37308ef267eb` | no case | `environment_required` | CB_FROM_TUNNEL/inlining workaround is summarized as preserving older-kernel verifier state and lacks a captured reject log. |
| `github-commit-cilium-3801c14ef454` | no case | `missing_verifier_log` | BPF test-log prefix/type-cast record has no verifier log; no local verifier-reject source can be anchored to the diff. |
| `github-commit-cilium-380833eabae3` | no case | `missing_verifier_log` | Session-affinity timeout flake/volatile-access record has no verifier log or terminal rejection message. |
| `github-commit-cilium-38d9bf589e6b` | no case | `not_reconstructable_from_diff` | Tunnel-key TTL type/cast diff lacks a verifier log and enough source context to reconstruct a faithful reject. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg --files docs/tmp bpfix-bench
sed -n '1,260p' bpfix-bench/raw/gh/<assigned-id>.yaml
python3 - <<'PY'
# Loaded each assigned raw YAML and printed title, fix_type, has_verifier_log,
# diff_summary, and any raw verifier_log excerpt.
PY
```

Local probes:

```bash
clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -c global_ctx.c -o global_ctx.o
sudo -n bpftool -d prog load global_ctx.o /sys/fs/bpf/b27_global_ctx
# Accepted on current kernel.

clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -c post_helper.c -o post_helper.o
sudo -n bpftool -d prog load post_helper.o /sys/fs/bpf/b27_post_helper
# Accepted on current kernel.

clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -c xdp_adjust.c -o xdp_adjust.o
sudo -n bpftool -d prog load xdp_adjust.o /sys/fs/bpf/b27_xdp_adjust
# Rejected with terminal error: R7 invalid mem access 'scalar'.
```

Admitted case validation:

```bash
cd bpfix-bench/cases/github-commit-cilium-2ff1a462cd33
make clean
# rc 0
make
# rc 0
make replay-verify
# rc 2; bpftool verifier reject, fresh replay-verifier.log written

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("replay-verifier.log")
print(parse_verifier_log(p.read_text(), str(p)))
PY
# ParsedVerifierLog(terminal_error="R7 invalid mem access 'scalar'",
#                   rejected_insn_idx=10,
#                   log_quality='trace_rich',
#                   source='replay-verifier.log')
```

Raw non-admitted log parsing:

```bash
python3 - <<'PY'
import yaml
from pathlib import Path
from tools.replay_case import parse_verifier_log
r = yaml.safe_load(Path("bpfix-bench/raw/gh/github-commit-cilium-3323fb0c62a9.yaml").read_text())["raw"]["verifier_log"]
print(parse_verifier_log(r, "raw verifier_log"))
PY
# ParsedVerifierLog(terminal_error=None, rejected_insn_idx=None,
#                   log_quality='no_terminal_error', source='raw verifier_log')
```

## Parsed Verifier Outcomes

- `github-commit-cilium-2ff1a462cd33`: `trace_rich`,
  `terminal_error="R7 invalid mem access 'scalar'"`, `rejected_insn_idx=10`.
- `github-commit-cilium-3323fb0c62a9` raw log: `no_terminal_error`,
  `terminal_error=None`, `rejected_insn_idx=None`; classified
  `out_of_scope_non_verifier`.

## Review

Date: 2026-04-30

Review checks:

- Record Results contains exactly 20 Batch 27 raw IDs, each once; duplicate
  check returned `duplicates: []`.
- Admitted case metadata matches review requirements:
  `source.kind=github_commit`, `reproducer.reconstruction=reconstructed`,
  `external_match.status=not_applicable`, `capture.log_quality=trace_rich`,
  and `capture.yaml` has `source_artifact.verifier_error_match=not_applicable`.
- Non-admitted classifications are all accepted by
  `tools/integrate_reconstruction_batch.py`: `environment_required`,
  `missing_verifier_log`, `not_reconstructable_from_diff`, and
  `out_of_scope_non_verifier`.

Commands rerun for admitted case:

```bash
cd bpfix-bench/cases/github-commit-cilium-2ff1a462cd33
make clean
# rc 0
make
# rc 0
make replay-verify
# rc 2; bpftool verifier reject path, fresh replay-verifier.log written

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("replay-verifier.log")
print(parse_verifier_log(p.read_text(), str(p)))
PY
# ParsedVerifierLog(terminal_error="R7 invalid mem access 'scalar'",
#                   rejected_insn_idx=10,
#                   log_quality='trace_rich',
#                   source='replay-verifier.log')
```

Integration dry run:

```bash
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-27.md --bench-root bpfix-bench
# apply: false
# rows: 20
# admitted:
# - github-commit-cilium-2ff1a462cd33
# missing_raw: []
# skipped_index: []
# errors: []
```

Blockers: none.
