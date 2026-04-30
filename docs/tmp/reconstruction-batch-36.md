# Reconstruction Batch 36

Date: 2026-04-30

Scope:

- Assigned Batch 36 raw records only.
- Edited this report and the admitted assigned case directory
  `bpfix-bench/cases/github-commit-cilium-f51f4dfac542/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any
  `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful verifier-reject reconstructions admitted: 1
- Not admitted: 19

One record was admitted: `github-commit-cilium-f51f4dfac542`. The raw diff adds
an explicit `if (!state)` guard after `snat_v6_nat_handle_mapping()` and before
dereferencing `state`. The reconstructed case builds locally and produces a
fresh verifier rejection log parsed as `trace_rich` with a terminal error and
rejected instruction index.

All raw records in this batch have `content.has_verifier_log: false`. The other
records were not admitted because they describe runtime datapath behavior,
loader/map-definition changes, historical full-program verifier complexity, or
a locally probed skb revalidation shape that accepts on the current verifier.

## Successful Replays

| case_id | command | build | load | parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-f51f4dfac542` | `make clean && make && make replay-verify` | success | verifier reject (`make replay-verify` returned 2; `bpftool` 255) | `log_quality=trace_rich`, `terminal_error=R0 invalid mem access 'map_value_or_null'`, `rejected_insn_idx=8` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-efb5d6509fea` | no case | `environment_required` | Raw title is "bpf: Fix verifier issue in fib_redirect", but `has_verifier_log=false`; the diff depends on full Cilium `fib_redirect()` state, FIB helper results, neighbor maps, and feature macros, so the isolated snippets do not identify a faithful rejected program. |
| `github-commit-cilium-f132c2a4dd27` | no case | `environment_required` | Reverts broad inlining/lookup changes across `bpf_lxc.c`, `bpf_sock.c`, `lb.h`, `nodeport.h`, sockops, and XDP tests; raw has no verifier log and the affected behavior is older-kernel full-Cilium verifier shape. |
| `github-commit-cilium-f19a97a47f8c` | no case | `out_of_scope_non_verifier` | Commit title fixes tuple address restore after map update; snippets add trace tuple helpers and tuple-field selection, with `has_verifier_log=false` and no load-time reject evidence. |
| `github-commit-cilium-f1a2789dbccc` | no case | `environment_required` | Changes SNAT retry constants based on `HAVE_LARGE_INSN_LIMIT`; any verifier effect is instruction-limit/full NAT program dependent, and the raw record has no terminal verifier log. |
| `github-commit-cilium-f1c3c71f0003` | no case | `out_of_scope_non_verifier` | Lifts v4-in-v6 local-redirect service behavior in socket LB paths; the raw snippets are service-translation logic and contain no verifier rejection. |
| `github-commit-cilium-f1c5760a760e` | no case | `environment_required` | Removes unused arguments from load-balancer slave selection across `bpf_lb.c` and `lb.h`; replay would require historical Cilium LB maps/helpers and generated program context, with no captured verifier log. |
| `github-commit-cilium-f244861ad34b` | no case | `out_of_scope_non_verifier` | IPsec monitor aggregation change controls trace notifications and includes a `barrier_data(ctx)` clang workaround; no verifier-load failure is captured. |
| `github-commit-cilium-f2bcb69afa0c` | no case | `out_of_scope_non_verifier` | Remaps `MARK_MAGIC_SNAT_DONE` constants to avoid mark conflicts; this is datapath mark semantics, not a replayable verifier reject. |
| `github-commit-cilium-f436f90f3d17` | no case | `out_of_scope_non_verifier` | Removes source MAC validation and associated dummy config values; snippets change runtime packet validation, and `has_verifier_log=false`. |
| `github-commit-cilium-f518e884775e` | no case | `out_of_scope_non_verifier` | Kernel-HZ probing change gates jiffies-based monotonic time on `KERNEL_HZ != 1`; this is feature probing/time conversion behavior, not verifier rejection. |
| `github-commit-cilium-f51f4dfac542` | admitted | `replay_valid` | Reconstructed the nullable SNAT state bug. Local replay produces fresh trace-rich verifier reject: `R0 invalid mem access 'map_value_or_null'`, rejected instruction 8. |
| `github-commit-cilium-f67260a842eb` | no case | `out_of_scope_non_verifier` | Limits the kube-proxy workaround in IPv6 local delivery to `IS_BPF_OVERLAY`; the change selects redirect vs stack delivery and has no verifier log. |
| `github-commit-cilium-fbbf549c6865` | no case | `out_of_scope_non_verifier` | Same kube-proxy workaround restriction for IPv4 local delivery; runtime delivery path change, no verifier rejection evidence. |
| `github-commit-cilium-fc388cb6d2f9` | no case | `out_of_scope_non_verifier` | Reuses/swaps NAT and conntrack tuples and updates NAT tests; the failure mode is tuple semantics, not an isolated verifier-load failure. |
| `github-commit-cilium-fcbd5d780bc5` | no case | `out_of_scope_non_verifier` | Fixes LB loopback with ingress policy across host/LXC/overlay/L3 paths; broad runtime control-flow change with no terminal verifier log. |
| `github-commit-cilium-fdca23e2b23f` | no case | `attempted_accepted` | Local `/tmp` probe of the raw skb `__revalidate_data_first()` before-shape built and loaded successfully on kernel 6.15.11; parser result was `log_quality=no_terminal_error`, so it fails admission. |
| `github-commit-cilium-ff096fd5f425` | no case | `out_of_scope_non_verifier` | Stops populating node IDs in ipcache value structs by replacing fields with padding; data-model change, no rejected instruction or verifier log. |
| `github-commit-cilium-ff65a2bd28f2` | no case | `out_of_scope_non_verifier` | Adds `btf_decl_tag("do-not-prune")` to maps so the loader/dead-code pass keeps them; not a BPF program verifier-reject record. |
| `github-commit-katran-07e10334022f` | no case | `out_of_scope_non_verifier` | Makes Katran array-of-maps definitions self-describing with inner-map metadata; this is map declaration/libbpf loading shape, not a verifier instruction rejection. |
| `github-commit-katran-1c79d8c6db85` | no case | `out_of_scope_non_verifier` | Adds drop stats for hash-ring lookup failures; snippets add stats-map increments after missing real lookups, with no verifier log or source-level reject. |

## Commands Run

Context and raw-record inspection:

```bash
pwd && rg --files docs bpfix-bench | head -200
git status --short
for id in github-commit-cilium-efb5d6509fea ... github-commit-katran-1c79d8c6db85; do
  rg --files bpfix-bench/raw | rg "$id" || true
done
for id in github-commit-cilium-efb5d6509fea ... github-commit-katran-1c79d8c6db85; do
  test -d bpfix-bench/cases/$id && echo CASE_EXISTS $id || true
done
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("fix_type"),
          d["content"].get("has_verifier_log"))
    print(textwrap.shorten(d["raw"].get("diff_summary", "").replace("\n", " | "), 420))
PY
rg -n "verifier|invalid|unbounded|permission|processed|complexity|clang|BPF|bpf" \
  bpfix-bench/raw/gh/github-commit-cilium-*.yaml bpfix-bench/raw/gh/github-commit-katran-*.yaml
sed -n '1,260p' tools/replay_case.py
clang --version; bpftool version || true; uname -a
```

Scratch replay probes:

```bash
make -C /tmp/bpfix-b36-f51 clean
make -C /tmp/bpfix-b36-f51
make -C /tmp/bpfix-b36-f51 replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/bpfix-b36-f51/replay-verifier.log").read_text(errors="replace")))
PY

make -C /tmp/bpfix-b36-fdca clean
make -C /tmp/bpfix-b36-fdca
make -C /tmp/bpfix-b36-fdca replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/bpfix-b36-fdca/replay-verifier.log").read_text(errors="replace")))
PY
```

Admitted-case validation:

```bash
cd bpfix-bench/cases/github-commit-cilium-f51f4dfac542
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

python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import replay_case
case_dir = Path("bpfix-bench/cases/github-commit-cilium-f51f4dfac542")
case_data = yaml.safe_load((case_dir / "case.yaml").read_text())
res = replay_case(case_dir, case_data, timeout_sec=60)
print("build_rc", res.build.returncode)
print("load_rc", res.load.returncode)
print("quality", res.parsed_log.log_quality)
print("terminal_error", res.parsed_log.terminal_error)
print("rejected_insn_idx", res.parsed_log.rejected_insn_idx)
print("source", res.parsed_log.source)
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-36.md --bench-root bpfix-bench
python3 - <<'PY'
from pathlib import Path
p = Path("docs/tmp/reconstruction-batch-36.md")
sec = p.read_text().split("## Record Results", 1)[1].split("\n## ", 1)[0]
rows = [line for line in sec.splitlines() if line.startswith("| `")]
print("count", len(rows))
print("unique", len({line.split("|")[1].strip() for line in rows}))
PY
```

## Parsed Verifier Outcomes

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-f51f4dfac542` | `/tmp` standalone probe | success | verifier reject (`make replay-verify` returned 2) | `log_quality=trace_rich`, `terminal_error=R0 invalid mem access 'map_value_or_null'`, `rejected_insn_idx=8` |
| `github-commit-cilium-f51f4dfac542` | admitted case directory | success | verifier reject (`make replay-verify` returned 2) | `log_quality=trace_rich`, `terminal_error=R0 invalid mem access 'map_value_or_null'`, `rejected_insn_idx=8` |
| `github-commit-cilium-fdca23e2b23f` | `/tmp` standalone probe | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=25` |

Replay API result for admitted case:

```text
build_rc 0
load_rc 2
quality trace_rich
terminal_error R0 invalid mem access 'map_value_or_null'
rejected_insn_idx 8
source replay-verifier.log
external_match.status not_applicable
capture.source_artifact.verifier_error_match not_applicable
```

## Review

Reviewer checks run on 2026-04-30:

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter
assigned = [...]
text = Path("docs/tmp/reconstruction-batch-36.md").read_text()
sec = text.split("## Record Results", 1)[1].split("\n## ", 1)[0]
rows = [line for line in sec.splitlines() if line.startswith("| `")]
ids = [line.split("|")[1].strip().strip("`") for line in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("missing", sorted(set(assigned)-set(ids)))
print("extra", sorted(set(ids)-set(assigned)))
print("dupes", sorted([k for k, v in Counter(ids).items() if v > 1]))
PY

cd bpfix-bench/cases/github-commit-cilium-f51f4dfac542
make clean && make && make replay-verify

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log, replay_case
case_dir = Path("/home/yunwei37/workspace/ebpf-verifier-agent/bpfix-bench/cases/github-commit-cilium-f51f4dfac542")
case = yaml.safe_load((case_dir / "case.yaml").read_text())
capture = yaml.safe_load((case_dir / "capture.yaml").read_text())
parsed = parse_verifier_log((case_dir / "replay-verifier.log").read_text(errors="replace"), source="replay-verifier.log")
print(parsed.log_quality)
print(parsed.terminal_error)
print(parsed.rejected_insn_idx)
print(case["external_match"]["status"])
print(capture["source_artifact"]["verifier_error_match"])
res = replay_case(case_dir, case, timeout_sec=60)
print(res.build.returncode, res.load.returncode, res.parsed_log.log_quality, res.parsed_log.terminal_error, res.parsed_log.rejected_insn_idx)
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-36.md --bench-root bpfix-bench
```

Outcome: pass. `Record Results` has exactly 20 rows, 20 unique assigned IDs, no missing/extra IDs, and no duplicate IDs. Classifications are accepted by `tools/integrate_reconstruction_batch.py`; dry-run integration reported `errors: []`.

Fresh replay for `github-commit-cilium-f51f4dfac542` rebuilt from clean state and rejected as expected. `make replay-verify` returned non-zero via `bpftool`, and the fresh parser result matched `case.yaml`/`capture.yaml`: `log_quality=trace_rich`, `terminal_error=R0 invalid mem access 'map_value_or_null'`, `rejected_insn_idx=8`. GitHub commit metadata is consistent with policy: `external_match.status=not_applicable` and `capture.source_artifact.verifier_error_match=not_applicable`.
