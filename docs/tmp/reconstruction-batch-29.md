# Reconstruction Batch 29

Date: 2026-04-30

Scope:

- Assigned Batch 29 raw records only.
- Edited this report and the admitted case directory
  `bpfix-bench/cases/github-commit-cilium-1a5596de414a/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Not admitted: 19

One record was admitted: `github-commit-cilium-1a5596de414a`. Its local replay
builds with clang, produces a fresh `replay-verifier.log`, and
`tools.replay_case.parse_verifier_log` parses the log as `trace_rich` with
terminal error and rejected instruction index.

The other 19 records were not admitted because they either accepted on a local
minimal reconstruction attempt, describe runtime datapath/compiler-warning
fixes rather than verifier-load failures, or require the historical generated
Cilium datapath / older kernel behavior with no captured verifier log.

## Successful Replays

| case_id | command | build | load | parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-1a5596de414a` | `make clean && make && make replay-verify` | success | verifier reject (`make replay-verify` returned 2) | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-0e7436369925` | no case | `out_of_scope_non_verifier` | Uses the `from_tunnel` parameter for the kube-proxy local-delivery workaround. The diff changes datapath routing/marking behavior and has no verifier log or isolated rejected operation. |
| `github-commit-cilium-0f11ce8d87c2` | no case | `out_of_scope_non_verifier` | Clarifies the kube-proxy workaround in the LXC to-container path by changing policy helper arguments/control flow. No verifier-load failure is identified. |
| `github-commit-cilium-1085ae269e71` | no case | `environment_required` | Splits the full `bpf_host.c` IPv6 path after conntrack lookup. Faithful reproduction depends on generated Cilium host datapath, maps, tail calls, and configuration; no terminal verifier log is present. |
| `github-commit-cilium-108aa4212f8e` | no case | `out_of_scope_non_verifier` | Fixes an implicit cast in TPROXY debug-message context (`dbg_ctx`). The raw record contains no verifier rejection and the change is not a standalone verifier-reject pattern. |
| `github-commit-cilium-1119f7856f0c` | no case | `environment_required` | Adds `relax_verifier()` to reduce full XDP load-balancer complexity. The rejection depends on the historical generated XDP program, not an isolated snippet. |
| `github-commit-cilium-11e5f5936631` | no case | `out_of_scope_non_verifier` | Restricts outer source-IP handling for tunnel encapsulation in XDP. This is datapath encapsulation behavior with no verifier log or rejected instruction evidence. |
| `github-commit-cilium-126cc503abab` | no case | `out_of_scope_non_verifier` | Implements wildcard service lookup for nodeport services from socket hooks. The change is service lookup/runtime behavior, not a verifier-load failure. |
| `github-commit-cilium-12e29221d278` | no case | `attempted_accepted` | A minimal XDP reconstruction of the IPv6 prefilter `memcpy` shape was built and replayed locally. Current verifier accepted it, so it did not meet the admission rule. |
| `github-commit-cilium-12e3ae9936bd` | no case | `out_of_scope_non_verifier` | SRv6 fix changes `ctx_adjust_hroom()` flags to avoid GSO type mismatch packet drops. No verifier rejection is described or captured. |
| `github-commit-cilium-13f2cd0a889c` | no case | `out_of_scope_non_verifier` | Same SRv6 GSO type mismatch fix shape as `12e3ae9936bd`; runtime packet-drop behavior, not a verifier-reject case. |
| `github-commit-cilium-13f2d90daada` | no case | `out_of_scope_non_verifier` | Removes a redundant IPcache lookup in the from-host path. The change is datapath lookup/control-flow behavior with no captured verifier failure. |
| `github-commit-cilium-142c0f7128c7` | no case | `environment_required` | Separates policy and L4 policy checks through an inline helper. Any verifier effect depends on the full policy map path and generated datapath, with no raw verifier log. |
| `github-commit-cilium-14a653ad4aac` | no case | `environment_required` | Splits SNAT processing into NAT/rev-NAT helpers across NAT and nodeport paths. A faithful replay requires the full Cilium NAT/nodeport environment and feature configuration. |
| `github-commit-cilium-181ed5a73517` | no case | `out_of_scope_non_verifier` | Avoids checking `encrypt_key` twice in encapsulation/IPsec handling. This is runtime control-flow cleanup, not an identified verifier rejection. |
| `github-commit-cilium-1915b7348367` | no case | `environment_required` | Changes XDP adjust-room checksum flag handling for newer kernels and nodeport DSR helpers. Reproduction depends on helper/kernel feature behavior and full nodeport context. |
| `github-commit-cilium-1a5596de414a` | admitted | `replay_valid` | Reconstructed the Maglev `map_array_get_16()` inline-assembly bounds bug. Local replay rejects with a trace-rich map-value out-of-bounds verifier log. |
| `github-commit-cilium-1b6a98ccf809` | no case | `environment_required` | Adds tail-call structure for IPvX-only setups. This depends on Cilium tail-call map generation and full LXC program composition, with no standalone verifier log. |
| `github-commit-cilium-1b95d351eb76` | no case | `environment_required` | Fixes a back-edge in `bpf_sock` for older kernels. Faithful reproduction requires the old-kernel verifier and full socket-LB/session-affinity control flow. |
| `github-commit-cilium-1c000f5f4726` | no case | `out_of_scope_non_verifier` | Fixes the ifindex reported in `TRACE_TO_OVERLAY` notifications. This is trace metadata correctness, not verifier rejection. |
| `github-commit-cilium-1d9f97e2b9f2` | no case | `out_of_scope_non_verifier` | Adds the missing return type to fix a `-Wimplicit-int` compiler error. The failure is source compilation hygiene, not a BPF verifier reject. |

## Commands Run

Context and raw-record inspection:

```bash
pwd && rg --files bpfix-bench | sed -n '1,120p'
git status --short
for id in github-commit-cilium-0e7436369925 ... github-commit-cilium-1d9f97e2b9f2; do
  ls bpfix-bench/raw/gh/$id.yaml
done
sed -n '1,220p' docs/tmp/reconstruction-batch-26.md
sed -n '1,220p' docs/tmp/reconstruction-batch-28.md
sed -n '1,220p' bpfix-bench/README.md
sed -n '1,240p' tools/replay_case.py
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"))
    print(d["raw"].get("diff_summary", ""))
PY
```

Case-directory checks:

```bash
for id in github-commit-cilium-0e7436369925 ... github-commit-cilium-1d9f97e2b9f2; do
  test -d bpfix-bench/cases/$id && echo CASE_EXISTS $id || true
done
```

Standalone attempts:

```bash
make -C /tmp/batch29-12e292 clean
make -C /tmp/batch29-12e292
make -C /tmp/batch29-12e292 replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/batch29-12e292/replay-verifier.log").read_text(errors="replace")))
PY

make -C /tmp/batch29-1a559 clean
make -C /tmp/batch29-1a559
make -C /tmp/batch29-1a559 replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/batch29-1a559/replay-verifier.log").read_text(errors="replace")))
PY
```

Admitted-case validation:

```bash
cd bpfix-bench/cases/github-commit-cilium-1a5596de414a
make clean
make
make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
parsed = parse_verifier_log(Path("replay-verifier.log").read_text(errors="replace"))
print(parsed.terminal_error)
print(parsed.rejected_insn_idx)
print(parsed.log_quality)
PY
```

Replay API validation:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import replay_case
case_dir = Path("bpfix-bench/cases/github-commit-cilium-1a5596de414a")
case_data = yaml.safe_load((case_dir / "case.yaml").read_text())
res = replay_case(case_dir, case_data, timeout_sec=60)
print("build_rc", res.build.returncode)
print("load_rc", res.load.returncode)
print("quality", res.parsed_log.log_quality)
print("terminal_error", res.parsed_log.terminal_error)
print("rejected_insn_idx", res.parsed_log.rejected_insn_idx)
PY
```

## Parsed Verifier Outcomes

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-12e29221d278` | `/tmp` standalone attempt | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=28` |
| `github-commit-cilium-1a5596de414a` | `/tmp` standalone attempt | success | verifier reject (`make replay-verify` returned 2) | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14` |
| `github-commit-cilium-1a5596de414a` | admitted case directory | success | verifier reject (`make replay-verify` returned 2) | `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14` |

Replay API result for admitted case:

```text
build_rc 0
load_rc 2
quality trace_rich
terminal_error invalid access to map value, value_size=2 off=16380 size=2
rejected_insn_idx 14
source replay-verifier.log
```

## Review

Reviewer: Codex

Commands run:

```bash
python3 - <<'PY'
from pathlib import Path
import re
p = Path("docs/tmp/reconstruction-batch-29.md")
rows = []
in_table = False
for line in p.read_text().splitlines():
    if line.strip() == "## Record Results":
        in_table = True
        continue
    if in_table and line.startswith("## "):
        break
    if in_table and line.startswith("| `"):
        m = re.match(r"\| `([^`]+)` \|", line)
        if m:
            rows.append(m.group(1))
print(len(rows))
print("dupes", sorted({x for x in rows if rows.count(x) > 1}))
PY

cd bpfix-bench/cases/github-commit-cilium-1a5596de414a
make clean && make && make replay-verify

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
parsed = parse_verifier_log(Path("replay-verifier.log").read_text(errors="replace"))
print("log_quality", parsed.log_quality)
print("terminal_error", parsed.terminal_error)
print("rejected_insn_idx", parsed.rejected_insn_idx)
PY

python3 - <<'PY'
from pathlib import Path
import yaml
case = yaml.safe_load(Path("case.yaml").read_text())
capture = yaml.safe_load(Path("capture.yaml").read_text())
print("case.source.kind", case["source"]["kind"])
print("case.reproducer.reconstruction", case["reproducer"]["reconstruction"])
print("case.external_match.status", case["external_match"]["status"])
print("case.capture.log_quality", case["capture"]["log_quality"])
print("capture.source_artifact.verifier_error_match", capture["source_artifact"].get("verifier_error_match"))
PY

cd /home/yunwei37/workspace/ebpf-verifier-agent
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-29.md --bench-root bpfix-bench
```

Review result:

- Record Results contains exactly 20 rows, with no duplicate raw IDs.
- The admitted case `github-commit-cilium-1a5596de414a` rebuilds from clean state and `make replay-verify` regenerates a verifier rejection log.
- Fresh parser output matches `case.yaml`: `log_quality=trace_rich`, `terminal_error=invalid access to map value, value_size=2 off=16380 size=2`, `rejected_insn_idx=14`.
- `case.yaml` has `source.kind=github_commit`, `reproducer.reconstruction=reconstructed`, `external_match.status=not_applicable`, and `capture.log_quality=trace_rich`.
- `capture.yaml` has `source_artifact.verifier_error_match=not_applicable`.
- Non-admitted classifications are accepted by `tools/integrate_reconstruction_batch.py`.
- Integration dry run reported `errors: []`.

Blockers: none.
