# Reconstruction Batch 25

Date: 2026-04-30

Scope:

- Assigned Batch 25 raw records only.
- Edited only this report and the admitted case directory under
  `bpfix-bench/cases/<assigned raw id>/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Attempted but accepted by the local verifier: 1
- Not admitted: 19

One record produced a local replayable verifier reject on
`kernel-6.15.11-clang-18-log2`:

- `github-commit-cilium-46024c6c4a30`: Cilium NodePort tunnel path nullability
  guard. Fresh replay rejects with `R1 invalid mem access 'map_value_or_null'`.

Most remaining records have no raw verifier log and depend on historical Cilium
macro expansion, kernel/helper behavior, verifier complexity limits, compiler
code generation, or runtime datapath semantics that cannot be faithfully reduced
from the stored diff snippets.

## Successful Replays

| case_id | command result | parsed verifier outcome |
| --- | --- | --- |
| `github-commit-cilium-46024c6c4a30` | `make clean` 0; `make` 0; `make replay-verify` 2 (`bpftool` 255 verifier reject) | `log_quality=trace_rich`; `terminal_error="R1 invalid mem access 'map_value_or_null'"`; `rejected_insn_idx=12` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-394e72478a8d` | no case | `attempted_accepted` | A local `cgroup/post_bind4` probe for the `ctx->src_port` access pattern built and passed verifier analysis on the current kernel; `bpftool` then failed only while pinning the cgroup program path, so there was no verifier terminal error to admit. |
| `github-commit-cilium-3a3f4e1815f2` | no case | `environment_required` | NAT source-port preservation and retry-limit changes depend on Cilium's historical NAT maps, feature defines, and verifier complexity behavior; the raw record has no verifier log. |
| `github-commit-cilium-3a51667c088b` | no case | `not_reconstructable_from_diff` | Trace/drop notification length factoring spans several Cilium headers and tests; the snippets do not isolate a standalone rejected access or a concrete verifier log. |
| `github-commit-cilium-3a93b00269b1` | no case | `out_of_scope_non_verifier` | The change works around `skb->mark` scrubbing across veth transition and adjusts datapath metadata propagation; no verifier-rejected program shape is identified. |
| `github-commit-cilium-3b0d61abe2b1` | no case | `not_reconstructable_from_diff` | FIB redirect consolidation changes helper control flow across IPv4/IPv6 paths without a stored verifier log or enough surrounding Cilium state for a faithful standalone replay. |
| `github-commit-cilium-3c3e7692b8f2` | no case | `environment_required` | Host-firewall tail-call split is a verifier-complexity mitigation tied to Cilium feature configuration and tail-call program layout; no raw verifier log is present. |
| `github-commit-cilium-3d82a4b46517` | no case | `out_of_scope_non_verifier` | Map migration changes libelf/gelf userspace handling for map properties, not a kernel verifier-rejected BPF program. |
| `github-commit-cilium-3df1264c3e9d` | no case | `environment_required` | IPv6 CIDR prefix reduction is a historical build/configuration and complexity-limit issue; no concrete rejected source/log is stored. |
| `github-commit-cilium-3df7fb4313ee` | no case | `out_of_scope_non_verifier` | Include cleanup in `bpf_network.c` does not identify a verifier rejection or standalone failing program. |
| `github-commit-cilium-3e4604fb219a` | no case | `not_reconstructable_from_diff` | Pod-to-node encapsulation and host-firewall flow changes span Cilium CT/VTEP/encap state; the raw snippets lack a verifier log and cannot be reduced faithfully. |
| `github-commit-cilium-3f0c2b71bab6` | no case | `not_reconstructable_from_diff` | NAT tuple reuse across conntrack/NAT helpers depends on large Cilium map and tuple context; no standalone verifier-rejected source is isolated. |
| `github-commit-cilium-405ac1549f53` | no case | `not_reconstructable_from_diff` | Segment Routing Header support touches egress policy and room-adjustment helpers; no raw verifier log or minimal failing path is present. |
| `github-commit-cilium-40c582aed330` | no case | `environment_required` | Initial BPF masquerading support is a large historical datapath feature set requiring old Cilium build defines, maps, and verifier limits. |
| `github-commit-cilium-412fc8437c4f` | no case | `out_of_scope_non_verifier` | Magic mark masking fixes runtime cluster-ID mark semantics; the raw record has no verifier log or verifier-specific rejected pattern. |
| `github-commit-cilium-4132b71e9abe` | no case | `environment_required` | NodePort redirect avoidance is an old branch/complexity workaround tied to Cilium `ENCAP_IFINDEX`/`NO_REDIRECT` configuration and historical verifier behavior. |
| `github-commit-cilium-416456de4253` | no case | `environment_required` | Optimized memset/stack alignment in `send_trace_notify` depends on compiler lowering and Cilium trace-notify layout; no concrete verifier log is stored. |
| `github-commit-cilium-42df1373f108` | no case | `out_of_scope_non_verifier` | Queue-mapping reset fixes runtime physical-device queue selection rather than a verifier rejection. |
| `github-commit-cilium-433242d55f84` | no case | `out_of_scope_non_verifier` | Policy-reject-response test modernization changes Cilium's test harness structure and includes, not an identified verifier-rejected benchmark. |
| `github-commit-cilium-442003456364` | no case | `out_of_scope_non_verifier` | Removal of an unused `LPM_LOOKUP_FN` macro is cleanup with no source/log evidence of a verifier rejection. |
| `github-commit-cilium-46024c6c4a30` | admitted | `replay_valid` | Added local TC replay for the pre-fix nullability shape where `if (tunnel_endpoint)` does not prove a map lookup result `info` is non-null before dereference; fresh verifier rejection is trace-rich and parser reports terminal error plus rejected instruction index. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg --files docs bpfix-bench
find bpfix-bench/cases -maxdepth 2 -name case.yaml -print
rg -n "parse_verifier_log|replay-verify|trace-rich|terminal_error|rejected_insn" -S .
python3 - <<'PY'
# loaded each assigned bpfix-bench/raw/gh/<id>.yaml and printed source title,
# commit date, fix_type, content flags, snippet lengths, and diff summary
PY
sed -n '1,220p' docs/tmp/reconstruction-batch-24.md
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/Makefile
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/{prog.c,case.yaml,capture.yaml}
```

Temporary local probe:

```bash
# 394 ctx->src_port post-bind access probe in /tmp/b25-394.*
make -C /tmp/b25-394.* clean
make -C /tmp/b25-394.*
make -C /tmp/b25-394.* replay-verify

# Parsed result: log_quality=no_terminal_error, terminal_error=None,
# rejected_insn_idx=7. The verifier accepted; load failed while pinning the
# cgroup/post_bind4 program path, so no case was admitted.
```

Admitted case validation:

```bash
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30 clean
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30 replay-verify

python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("bpfix-bench/cases/github-commit-cilium-46024c6c4a30/replay-verifier.log")
print(parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
PY
```

Parser result:

```text
ParsedVerifierLog(terminal_error="R1 invalid mem access 'map_value_or_null'", rejected_insn_idx=12, log_quality='trace_rich', source='bpfix-bench/cases/github-commit-cilium-46024c6c4a30/replay-verifier.log')
```

## Review

Review date: 2026-04-30

Commands run:

```bash
sed -n '1,260p' docs/tmp/reconstruction-batch-25.md
find bpfix-bench/cases/github-commit-cilium-46024c6c4a30 -maxdepth 2 -type f | sort
git status --short
sed -n '1,240p' bpfix-bench/cases/github-commit-cilium-46024c6c4a30/case.yaml
sed -n '1,240p' bpfix-bench/cases/github-commit-cilium-46024c6c4a30/capture.yaml
rg -n "attempted_accepted|environment_required|not_reconstructable_from_diff|out_of_scope_non_verifier|replay_valid|classification|canonical|accepted" tools/integrate_reconstruction_batch.py
sed -n '1,260p' tools/integrate_reconstruction_batch.py
python3 - <<'PY'
from pathlib import Path
text = Path("docs/tmp/reconstruction-batch-25.md").read_text()
in_table = False
ids = []
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] not in ("raw_id", "---") and set(cells[0]) != {"-"}:
            rid = cells[0].strip("`")
            if rid and rid != "raw_id" and not rid.startswith("---"):
                ids.append(rid)
print(len(ids))
for rid in ids:
    print(rid)
print("duplicates", sorted({x for x in ids if ids.count(x) > 1}))
PY
rg -n "batch.?25|Batch 25|github-commit-cilium-46024c6c4a30|github-commit-cilium-394e72478a8d" bpfix-bench/raw bpfix-bench/raw/index.yaml docs -S
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30 clean
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30
make -C bpfix-bench/cases/github-commit-cilium-46024c6c4a30 replay-verify
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("bpfix-bench/cases/github-commit-cilium-46024c6c4a30/replay-verifier.log")
print(parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
PY
tail -n 80 bpfix-bench/cases/github-commit-cilium-46024c6c4a30/replay-verifier.log
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-25.md --bench-root bpfix-bench
```

Findings:

- Record Results contains exactly 20 rows, with no duplicate raw IDs. The listed IDs match the local Batch 25 raw/index range from `github-commit-cilium-394e72478a8d` through `github-commit-cilium-46024c6c4a30`.
- The admitted case `github-commit-cilium-46024c6c4a30` rebuilds cleanly. `make replay-verify` exits 2 from `bpftool` verifier rejection, and `tools.replay_case.parse_verifier_log` returns `log_quality='trace_rich'`, `terminal_error="R1 invalid mem access 'map_value_or_null'"`, and `rejected_insn_idx=12`, matching `case.yaml`.
- `case.yaml` has `source.kind: github_commit`, `reproducer.reconstruction: reconstructed`, `external_match.status: not_applicable`, and `capture.log_quality: trace_rich`.
- Non-admitted classifications are accepted by `tools/integrate_reconstruction_batch.py`: `attempted_accepted`, `environment_required`, `not_reconstructable_from_diff`, and `out_of_scope_non_verifier`.
- Integration dry run completed with `errors: []`.

Post-review fix:

- `bpfix-bench/cases/github-commit-cilium-46024c6c4a30/capture.yaml` now uses
  `source_artifact.verifier_error_match: not_applicable`. The metadata blocker
  is resolved.
