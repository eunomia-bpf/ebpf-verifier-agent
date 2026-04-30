# Reconstruction Batch 35

Date: 2026-04-30

Scope:

- Assigned Batch 35 raw records only.
- Edited this report and the admitted case directory
  `bpfix-bench/cases/github-commit-cilium-c046309b0ff5/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 0
- Successful admitted replays: 1
- Not admitted: 19

One record was admitted: `github-commit-cilium-c046309b0ff5`. The raw diff is
the Cilium `map_array_get_16()` Maglev backend retrieval fix. The reconstructed
program builds locally, `make replay-verify` produces a fresh verifier reject,
and `tools.replay_case.parse_verifier_log` classifies the fresh log as
`trace_rich` with terminal error and rejected instruction index.

The remaining records were not admitted because they either describe runtime
datapath/configuration fixes, depend on historical Cilium generated datapath or
old compiler/kernel behavior without a captured verifier log, or accepted under
a local minimal probe.

## Successful Replays

| case_id | command | build | load | parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-c046309b0ff5` | `make clean && make && make replay-verify` | success | verifier reject (`make replay-verify` returned 2; `bpftool` returned 255) | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-bc13b39af1c9` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff is `bpf_alignchecker.c`, a placeholder C struct alignment generator, replacing inline asm retention with `trace_printk()` calls; no verifier-load failure or rejected instruction is identified. |
| `github-commit-cilium-bc41a39e8519` | no case | `environment_required` | Raw `has_verifier_log=false`. The snippets move builtin memory tests into Cilium's BPF unit-test framework and adjust random-position masking; faithful replay requires the generated builtin test harness and historical verifier/compiler behavior. |
| `github-commit-cilium-bd23d375832e` | no case | `environment_required` | Raw title says `cil_sock{4,6}_connect prog load` complexity, but `has_verifier_log=false`. The fix inserts `barrier()` around backend pointer lookup/null-check paths in full socket-LB code; no standalone rejected log is available. |
| `github-commit-cilium-bd73c2d825ab` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change prefers `ctx->mark` over metadata for host metadata transfer and references runtime issue `36329`; it is datapath metadata behavior, not an isolated verifier reject. |
| `github-commit-cilium-bd8b4d0ee3ee` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff gates a 16-bit `ifindex` field behind `HAVE_FIB_IFINDEX` and updates conntrack/nodeport state handling; the evidence is runtime ifindex width handling, not a verifier log. |
| `github-commit-cilium-bd8c73cdff24` | no case | `environment_required` | Raw `has_verifier_log=false`. The commit removes historical `relax_verifier()` calls from host/LXC paths after complexity changes; reproducing the old 4.9-era complexity behavior requires the full generated datapath. |
| `github-commit-cilium-bfaef16f3485` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff compresses Maglev service LUT state, changes loader map metadata, and updates map migration handling; it is map layout/migration behavior, not a captured verifier failure. |
| `github-commit-cilium-bfdfc3dea6b7` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff shifts ingress ipcache source lookup to netdev and changes policy lookup arguments in full datapath control flow; no verifier terminal error or rejected instruction is present. |
| `github-commit-cilium-c005d6c56965` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets stop carrying node IDs in ipcache/tunnel structs by replacing fields with padding; this is datapath metadata/schema cleanup, not verifier rejection evidence. |
| `github-commit-cilium-c02c41fb3875` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The NAT change punts unknown protocols to the stack instead of returning `DROP_NAT_UNSUPP_PROTO`; it is packet handling behavior, not a verifier-load issue. |
| `github-commit-cilium-c046309b0ff5` | admitted | `replay_valid` | Reconstructed the Maglev `map_array_get_16()` byte-offset bounds bug from `bpf/include/bpf/access.h`. Local clean build and replay produce a fresh trace-rich map-value out-of-bounds verifier rejection. |
| `github-commit-cilium-c08e72af878b` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff renames example SNAT map macros to `test_cilium_*`; this is test/example map naming, not a verifier-reject case. |
| `github-commit-cilium-ebb781e5ba1b` | no case | `attempted_accepted` | Raw `has_verifier_log=false`. A temporary sockops probe of `ops->remote_port >> 16` built and loaded on the local kernel; current clang emitted a 32-bit context load and `make replay-verify` returned 0. |
| `github-commit-cilium-ebc32309be74` | no case | `environment_required` | Raw title says potential nodeport complexity issue, but `has_verifier_log=false`. The change only narrows DSR preprocessor conditions inside `skip_service_lookup`; replay requires the full nodeport/generated-feature matrix. |
| `github-commit-cilium-ec3529b5ddfe` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff replaces subtraction-based `ipv6_addrcmp()` with boolean equality across socket, ICMPv6, NAT, LXC, and nodeport tests; no single rejected verifier trace is available outside full Cilium contexts. |
| `github-commit-cilium-eca1f331b2f7` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix changes disabled UDP/peer reverse-NAT stubs from `-1` to `0` so host-to-TCP services continue; this is service behavior under feature flags, not verifier rejection. |
| `github-commit-cilium-ecdff123780d` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change includes `lib/qm.h` and calls `reset_queue_mapping(ctx)` in `handle_xgress`; it fixes host-veth queue mapping behavior, not verifier load. |
| `github-commit-cilium-ee5f473199ac` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix swaps argument order in the IPv6 conntrack tracing call to `__ct_lookup6`; this is packet tracing correctness, not a verifier terminal error. |
| `github-commit-cilium-eebbfbe7fbf5` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff adds `relax_verifier()` on a CT lookup drop path in full LXC egress handling; reproducing the historical complexity issue requires old Cilium datapath composition. |
| `github-commit-cilium-eeca01efc0b7` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff changes IPv6 address copies to builtin `memcpy()` or an unaligned helper across encap, LB, nodeport, trace, and tests; replay depends on full Cilium contexts and compiler lowering. |

## Commands Run

Context and raw-record inspection:

```bash
pwd && rg --files docs bpfix-bench | sed -n '1,200p'
git status --short
rg -n "reconstruction-batch|Record Results|Parsed Verifier Outcomes|external_match|replay-verify|trace_rich" docs bpfix-bench -S
for id in github-commit-cilium-bc13b39af1c9 ... github-commit-cilium-eeca01efc0b7; do
  rg --files bpfix-bench/raw | rg "$id" || true
done
sed -n '1,260p' docs/tmp/reconstruction-batch-29.md
sed -n '1,220p' tools/replay_case.py
sed -n '1,140p' bpfix-bench/cases/github-commit-cilium-1a5596de414a/case.yaml
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["content"]["has_verifier_log"],
          d["raw"]["fix_type"], d["raw"].get("diff_summary", "").splitlines()[0])
PY
```

Case existence check:

```bash
for id in github-commit-cilium-bc13b39af1c9 ... github-commit-cilium-eeca01efc0b7; do
  test -d bpfix-bench/cases/$id && echo CASE_EXISTS $id || true
done
```

Admitted-case validation:

```bash
cd bpfix-bench/cases/github-commit-cilium-c046309b0ff5
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
parsed = parse_verifier_log(Path("replay-verifier.log").read_text(errors="replace"))
print("terminal_error", parsed.terminal_error)
print("rejected_insn_idx", parsed.rejected_insn_idx)
print("log_quality", parsed.log_quality)
PY
```

Replay API validation:

```bash
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import replay_case
case_dir = Path("bpfix-bench/cases/github-commit-cilium-c046309b0ff5")
case_data = yaml.safe_load((case_dir / "case.yaml").read_text())
res = replay_case(case_dir, case_data, timeout_sec=60)
print("build_rc", res.build.returncode)
print("load_rc", res.load.returncode)
print("quality", res.parsed_log.log_quality)
print("terminal_error", res.parsed_log.terminal_error)
print("rejected_insn_idx", res.parsed_log.rejected_insn_idx)
print("source", res.parsed_log.source)
PY
```

Temporary accepted probe:

```bash
rm -rf /tmp/batch35-ebb && mkdir -p /tmp/batch35-ebb
cp bpfix-bench/cases/github-commit-cilium-c046309b0ff5/Makefile /tmp/batch35-ebb/Makefile
# Wrote a temporary sockops prog.c using ops->remote_port >> 16.
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
text = Path("replay-verifier.log").read_text(errors="replace")
print(parse_verifier_log(text, source="replay-verifier.log"))
PY
sudo rm -f /sys/fs/bpf/batch35-ebb || true
make clean
```

## Parsed Verifier Outcomes

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-c046309b0ff5` | admitted case directory | success | verifier reject (`make replay-verify` returned 2; `bpftool` returned 255) | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14` |
| `github-commit-cilium-c046309b0ff5` | `tools.replay_case.replay_case` | `build_rc=0` | `load_rc=2` | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14`, `source=replay-verifier.log` |
| `github-commit-cilium-ebb781e5ba1b` | `/tmp/batch35-ebb` standalone probe | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=4`; emitted load was `r1 = *(u32 *)(r1 +64)` for `remote_port` |

## Review

Reviewed 2026-04-30. Outcome: pass; safe to integrate.

Commands run:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docs/tmp/reconstruction-batch-35.md")
text = p.read_text()
section = text.split("## Record Results", 1)[1].split("\n## ", 1)[0]
rows = []
for line in section.splitlines():
    if line.startswith("| `"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append(cells)
ids = [r[0].strip("`") for r in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("dups", sorted({x for x in ids if ids.count(x) > 1}))
PY
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-c046309b0ff5/case.yaml
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-c046309b0ff5/capture.yaml
cd bpfix-bench/cases/github-commit-cilium-c046309b0ff5 && make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log, replay_case
case_dir = Path("bpfix-bench/cases/github-commit-cilium-c046309b0ff5")
case = yaml.safe_load((case_dir / "case.yaml").read_text())
parsed = parse_verifier_log((case_dir / "replay-verifier.log").read_text(errors="replace"), source="replay-verifier.log")
print(parsed.log_quality, parsed.terminal_error, parsed.rejected_insn_idx)
print(parsed.log_quality == case["capture"]["log_quality"])
print(parsed.terminal_error == case["capture"]["terminal_error"])
print(parsed.rejected_insn_idx == case["capture"]["rejected_insn_idx"])
res = replay_case(case_dir, case, timeout_sec=60)
print(res.build.returncode, res.load.returncode, res.parsed_log.log_quality, res.parsed_log.terminal_error, res.parsed_log.rejected_insn_idx)
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-35.md --bench-root bpfix-bench
```

Checks:

- `Record Results` has exactly 20 rows, all unique, with no missing or extra assigned IDs.
- Classifications are accepted by `tools/integrate_reconstruction_batch.py`: `replay_valid`, `attempted_accepted`, `environment_required`, and `out_of_scope_non_verifier`.
- Admitted case `github-commit-cilium-c046309b0ff5` rebuilt cleanly; fresh replay rejected as expected. `tools.replay_case` parsed `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, and `rejected_insn_idx=14`, matching `case.yaml`.
- GitHub commit metadata has `external_match.status=not_applicable`; capture metadata has `source_artifact.verifier_error_match=not_applicable`.
- Dry-run integration completed with `errors: []`, one admitted case, 20 raw updates, no missing raw records, and no skipped index records.

No fixes applied.
