# Reconstruction Batch 37

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 37 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. Every raw record has
`content.has_verifier_log: false` and `verifier_log_block_count: 0`, so none
provides a terminal verifier error or rejected instruction to anchor replay.
The Katran records are either full datapath, old-kernel/compiler verifier
workarounds, or non-verifier datapath semantics. The libbpf records are
mostly user-space loader, BTF, attach, netlink, or reporting changes rather
than standalone verifier-rejected BPF programs. The two libbpf records that are
plausibly verifier-shaped lack the triggering BPF source/object, so they were
not replayable under the strict admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-katran-5d1e2ca8b9d7` | no case | `environment_required` | Raw diff says the change avoided older-kernel rejection of stack-passed TCP option parser state and bounded loops. The snippet is only `katran/lib/bpf/pckt_parsing.h` context, with no verifier log or standalone XDP harness. |
| `github-commit-katran-745374f1cf04` | no case | `environment_required` | TPR validation changes `parse_hdr_opt()` and `tcp_hdr_opt_lookup_server_id()` in Katran's packet parser. Reproduction depends on Katran feature macros and parser call graph, and the raw record has no terminal verifier log. |
| `github-commit-katran-918c0e169773` | no case | `environment_required` | The commit spans `balancer_consts.h`, `balancer_helpers.h`, `balancer_kern.c`, and `balancer_maps.h`, including flood, connection-table, L3, and map contexts. It is a full Katran datapath rewrite without isolated rejected bytecode. |
| `github-commit-katran-996c74a07133` | no case | `environment_required` | Removes `#pragma clang loop unroll(full)` from TCP option lookup loops. Any rejection depends on Katran's generated parser body, loop bounds, compiler output, and kernel verifier version; no captured verifier error is present. |
| `github-commit-katran-a20ebf46f0d5` | no case | `out_of_scope_non_verifier` | The actual fixed snippet changes TPR server-id byte-order handling with a big-endian `__builtin_bswap32()` path. That is cross-architecture datapath semantics, not a verifier-load rejection, and no verifier log exists. |
| `github-commit-katran-d195c045a01b` | no case | `environment_required` | Katran reload changes touch helper functions, `process_packet()`, BPF maps, control-data maps, and tail-call map names. A faithful replay requires the Katran loader/datapath environment rather than a standalone rejected program. |
| `github-commit-katran-d3c0229b0731` | no case | `environment_required` | The fixed code comment identifies a Linux 5.2 verifier register-copy issue with `protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6`. Reproduction requires that old verifier/compiler behavior and the full Katran edge-balancer path. |
| `github-commit-katran-d4edcd2c5a99` | no case | `environment_required` | Replaces a TCP option unroll pattern with a global helper call across `balancer_kern.c` and `pckt_parsing.h`. The failure mode is tied to Katran's full parser, maps, and feature configuration, with no terminal verifier evidence. |
| `github-commit-libbpf-0141d9ddeda6` | no case | `missing_source` | The raw snippets are libbpf relocation/resolution code for unresolved weak kfuncs, including `BPF_PSEUDO_KFUNC_CALL` `imm/off` handling. They do not include the BPF source/object that triggers the unresolved weak kfunc load, and no verifier log is captured. |
| `github-commit-libbpf-0504b7ff2211` | no case | `out_of_scope_non_verifier` | Changes BTF loading log-buffer plumbing in user-space `src/btf.c` and an internal opts helper. It affects BTF load diagnostics/API behavior, not a standalone BPF program verifier reject. |
| `github-commit-libbpf-05acce9e03d9` | no case | `out_of_scope_non_verifier` | Adds kprobe-multi attach support and libbpf API/section handling. The raw evidence is attach-time user-space library code and has no verifier rejected instruction. |
| `github-commit-libbpf-06c4624c8cf8` | no case | `out_of_scope_non_verifier` | Fixes a potential NULL dereference while parsing ELF sections in `bpf_object__init_global_data_maps()`. This is libbpf robustness during object parsing, not verifier rejection evidence. |
| `github-commit-libbpf-09b528e8472e` | no case | `out_of_scope_non_verifier` | Adds legacy uprobe event cleanup/attach handling around `bpf_link_perf_detach()` and uprobe helpers. This is runtime attach cleanup behavior, not verifier-load failure. |
| `github-commit-libbpf-0a901dd1cd70` | no case | `out_of_scope_non_verifier` | Drops libbpf's extra "program too large" warning after a load failure. The diff changes error reporting only and supplies no BPF source or verifier terminal error. |
| `github-commit-libbpf-0b80970cb65e` | no case | `out_of_scope_non_verifier` | Fixes BTF-to-C converter padding/packing logic in `src/btf_dump.c`. The change is generated-C formatting/layout behavior, not verifier replay material. |
| `github-commit-libbpf-0cc3d9d33292` | no case | `out_of_scope_non_verifier` | Fixes a libbpf NULL-pointer issue by initializing `open_attr` after validating `attr`. The touched code is user-space loader API setup, not verifier-rejected BPF bytecode. |
| `github-commit-libbpf-0d4cefc4fc64` | no case | `out_of_scope_non_verifier` | Adds fallback from `bpf_link_create()` to `bpf_raw_tracepoint_open()` and attach-BTF handling. This is old-kernel attach compatibility, not program verification failure. |
| `github-commit-libbpf-0d7ac2881879` | no case | `out_of_scope_non_verifier` | Fixes `bpf_xdp_query()` feature-flag querying when the old kernel lacks the `netdev` generic netlink family. This is netlink compatibility rather than verifier behavior. |
| `github-commit-libbpf-0e195e4597d2` | no case | `out_of_scope_non_verifier` | Refactors BTF fixup helpers around ELF section size and variable symbol lookup. The snippets are libbpf object/BTF handling, with no rejected BPF program or verifier log. |
| `github-commit-libbpf-0e3971339f06` | no case | `missing_source` | Fixes `sym_is_subprog()` recognition for weak global subprogram symbols. A replay would need a BPF object exercising that symbol layout; the raw record contains only libbpf implementation snippets and no verifier log. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files | rg '(^docs/tmp/|^bpfix-bench/(raw|cases)|tools/replay_case|manifest.yaml)'
git status --short
ls -la docs/tmp bpfix-bench/raw bpfix-bench/cases 2>/dev/null
```

Raw-record presence and assigned case-directory checks:

```bash
for id in github-commit-katran-5d1e2ca8b9d7 ... github-commit-libbpf-0e3971339f06; do
  find bpfix-bench/raw -name "$id.yaml" -print
done

for id in github-commit-katran-5d1e2ca8b9d7 ... github-commit-libbpf-0e3971339f06; do
  if test -d bpfix-bench/cases/$id; then echo "EXISTS $id"; fi
done
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"))
    print(textwrap.shorten(" ".join(d["raw"].get("diff_summary", "").split()), width=900))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["content"], d["reproduction"], d["source"])
    print(d["raw"].get("diff_summary"))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    raw = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())["raw"]
    print(id, raw.get("commit_message"))
    for line in (raw.get("buggy_code") or "").splitlines():
        if line.startswith("// FILE:") or line.startswith("// CONTEXT:"):
            print(line)
PY
```

Replay-contract and existing-case format inspection:

```bash
sed -n '1,240p' tools/replay_case.py
sed -n '1,220p' bpfix-bench/raw/README.md
sed -n '1,180p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/case.yaml
sed -n '1,180p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/capture.yaml
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/Makefile
```

Cross-checks:

```bash
rg -n "github-commit-libbpf|github-commit-katran" \
  docs/tmp bpfix-bench/cases bpfix-bench/manifest.yaml bpfix-bench/raw/index.yaml
date +%F && date -u +%FT%TZ
```

## Parsed Verifier Outcomes

No assigned case produced a fresh verifier-reject log.

| scope | result |
| --- | --- |
| assigned case directories | none existed and none were created |
| `make clean` / `make` / `make replay-verify` | not run in assigned case directories because no faithful standalone candidate satisfied admission prerequisites |
| `tools.replay_case.parse_verifier_log` | no new verifier log to parse |
| admitted trace-rich rejects | 0 |

Admission validation result:

```text
admitted cases: 0
fresh terminal_error: none
fresh rejected_insn_idx: none
```

## Review

Commands run:

```bash
python3 - <<'PY'
from pathlib import Path
from tools.integrate_reconstruction_batch import parse_batch_report, ALLOWED_STATUSES
expected = [
    "github-commit-katran-5d1e2ca8b9d7",
    "github-commit-katran-745374f1cf04",
    "github-commit-katran-918c0e169773",
    "github-commit-katran-996c74a07133",
    "github-commit-katran-a20ebf46f0d5",
    "github-commit-katran-d195c045a01b",
    "github-commit-katran-d3c0229b0731",
    "github-commit-katran-d4edcd2c5a99",
    "github-commit-libbpf-0141d9ddeda6",
    "github-commit-libbpf-0504b7ff2211",
    "github-commit-libbpf-05acce9e03d9",
    "github-commit-libbpf-06c4624c8cf8",
    "github-commit-libbpf-09b528e8472e",
    "github-commit-libbpf-0a901dd1cd70",
    "github-commit-libbpf-0b80970cb65e",
    "github-commit-libbpf-0cc3d9d33292",
    "github-commit-libbpf-0d4cefc4fc64",
    "github-commit-libbpf-0d7ac2881879",
    "github-commit-libbpf-0e195e4597d2",
    "github-commit-libbpf-0e3971339f06",
]
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-37.md"))
ids = [row.raw_id for row in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("unsupported", sorted({row.classification for row in rows} - ALLOWED_STATUSES))
print("replay_valid", [row.raw_id for row in rows if row.classification == "replay_valid"])
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-37.md --bench-root bpfix-bench
```

Review result: pass. `Record Results` has exactly 20 rows, all assigned IDs
appear exactly once, no extra IDs are present, and all classifications are
canonical statuses accepted by `tools/integrate_reconstruction_batch.py`.
No `replay_valid` classification exists, so `make clean`, `make`, and
`make replay-verify` were not rerun. Dry-run integration completed with
`errors: []` and `admitted: []`.

Outcome: safe to integrate as a no-admission batch.
