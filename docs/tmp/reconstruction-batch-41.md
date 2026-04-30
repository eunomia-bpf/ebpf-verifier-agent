# Reconstruction Batch 41

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 41 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection
  time, and none were created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 1
- Successful admitted replays: 0
- Not admitted: 20

No assigned record was admitted. Nineteen records have
`content.has_verifier_log: false` and `verifier_log_block_count: 0`. The only
record with a raw verifier-log field, `github-commit-libbpf-75a2e3bda8d9`,
contains a libbpf load diagnostic ending in `Error: object file doesn't contain
any bpf program`; `tools.replay_case.parse_verifier_log` classifies it as
`no_terminal_error` with no `terminal_error` and no `rejected_insn_idx`.

Most records are libbpf user-space loader, BTF, ELF, netlink, API, or header
convenience changes rather than standalone verifier-rejected BPF programs. The
few verifier-shaped records lack the triggering BPF source/object or depend on
specific kernel feature support, so they do not satisfy the strict admission
rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-732f5982826c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets add `bpf_object__open_{file,mem}` extensible options and object-name handling in user-space `src/libbpf.c`/headers; no BPF program, verifier terminal error, or rejected instruction is present. |
| `github-commit-libbpf-741277511035` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff replaces ELF `e_shnum` use with `elf_getshdrnum()` and changes `sec_cnt` sizing in libbpf's ELF parser; this is user-space object parsing, not verifier replay material. |
| `github-commit-libbpf-75a2e3bda8d9` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=true`, but the captured text ends with `Error: object file doesn't contain any bpf program`; parser result is `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=None`. The diff only adds `NULL` and `KERNEL_VERSION` convenience macros in `bpf_helpers.h`. |
| `github-commit-libbpf-7cfc3659953c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change validates libbpf map/program FDs before pin, lookup, link update, attach, or struct_ops operations; these are user-space API guard paths with no verifier-loaded BPF bytecode. |
| `github-commit-libbpf-7db9ce5fdad1` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix adds `if (!obj->btf) return -ENOENT` before initializing map BTF info in libbpf; it prevents a loader NULL dereference and supplies no verifier failure. |
| `github-commit-libbpf-8404d1396c0b` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff defines missing `BTF_KIND_*` constants in `btf.h` to avoid application compilation errors; it is header compatibility, not a verifier-rejected program. |
| `github-commit-libbpf-855bf91055a6` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets parse Ubuntu/Debian kernel version files and probe kernel version behavior in libbpf user space; no standalone BPF source or verifier terminal error is captured. |
| `github-commit-libbpf-896a3ae0d0f3` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff changes `bpf_prog_load()` log-buffer handling for `log_level == 0`; it affects diagnostic/log plumbing and includes no rejected BPF program or captured verifier error. |
| `github-commit-libbpf-8ac9773f52ae` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change fixes NULL/size validation in `btf_dump__dump_type_data()` user-space API; the evidence is BTF dump bounds handling, not verifier load rejection. |
| `github-commit-libbpf-8fd8b5bb4641` | no case | `missing_source` | Raw `has_verifier_log=false`. The CO-RE relocation diff can rewrite a failed relocation into an invalid helper call (`imm = 195896080`) so the verifier would complain if reachable, but the raw record contains only libbpf relocation code and no triggering BPF source/object. |
| `github-commit-libbpf-939ab641b89b` | no case | `environment_required` | Raw `has_verifier_log=false`. The fixed code adds a synthetic `arg:ctx` feature probe using raw BTF and `bpf_prog_load(BPF_PROG_TYPE_KPROBE, ...)`; replay depends on kernel support for `arg:ctx` tags and related kfunc/context behavior, with no captured verifier log. |
| `github-commit-libbpf-93c109c9ee23` | no case | `missing_source` | Raw `has_verifier_log=false`. The fix changes a CO-RE relocation bounds check from `insn_idx > prog->insns_cnt` to `>=`; a faithful replay would need an object whose relocation offset equals the instruction count, but no such object/source or verifier log is included. |
| `github-commit-libbpf-969018545d49` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff turns `btf_dedup_opts` into an opts-based ABI and adjusts BTF/linker internals; it is libbpf user-space BTF deduplication and API compatibility, not verifier rejection. |
| `github-commit-libbpf-989d7189cdcf` | no case | `missing_source` | Raw `has_verifier_log=false`. The header macro change makes `__bpf_printk` use a `static const` format string unless `BPF_NO_GLOBAL_DATA` is set, but the raw record lacks the BPF program and verifier log needed to identify a faithful rejected stack/global-data pattern. |
| `github-commit-libbpf-9b91dce6913e` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix changes libbpf object-name selection for `bpf_object__open_file()`/memory buffers; this is loader metadata naming, not verifier-visible program behavior. |
| `github-commit-libbpf-9d2f8aaf21a9` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff adds the new `BPF_CORE_WRITE_BITFIELD()` macro to `bpf_core_read.h`; it is a helper macro feature with no buggy BPF program, terminal verifier error, or rejected instruction. |
| `github-commit-libbpf-9ff2b7669370` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change introduces a typed netlink request buffer and updates XDP/TC netlink helpers; it affects user-space netlink message construction, not verifier replay. |
| `github-commit-libbpf-a00b10df8c89` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff renames the weak kfunc declaration from `bpf_stream_vprintk` to `bpf_stream_vprintk_impl`; reproducing any failure requires a kernel exposing that kfunc naming scheme plus a BPF program using `bpf_stream_printk`, neither of which is captured. |
| `github-commit-libbpf-a0ad81d9c464` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change undefines/redefines `__always_inline` in `bpf_helpers.h` to avoid `linux/stddef.h` macro conflicts; it is header/compiler compatibility rather than verifier rejection evidence. |
| `github-commit-libbpf-a20b60f97135` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix switches direct writes of `feature_flags` and `xdp_zc_max_segs` to `OPTS_SET()` in `bpf_xdp_query()`; this is user-space opts compatibility and netlink query behavior, not a verifier failure. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | sed -n '1,160p'
git status --short
rg -n "reconstruction-batch|trace_rich|external_match|verifier_error_match|replay-verify" docs bpfix-bench tools -g '!bpfix-bench/raw/**'
```

Raw-record and assigned case-directory checks:

```bash
rg -n "github-commit-libbpf-(732f5982826c|741277511035|75a2e3bda8d9|7cfc3659953c|7db9ce5fdad1|8404d1396c0b|855bf91055a6|896a3ae0d0f3|8ac9773f52ae|8fd8b5bb4641|939ab641b89b|93c109c9ee23|969018545d49|989d7189cdcf|9b91dce6913e|9d2f8aaf21a9|9ff2b7669370|a00b10df8c89|a0ad81d9c464|a20b60f97135)" bpfix-bench/raw bpfix-bench/cases bpfix-bench/manifest.yaml docs/tmp -g '*.yaml' -g '*.md'

for id in github-commit-libbpf-732f5982826c ... github-commit-libbpf-a20b60f97135; do
  test -d bpfix-bench/cases/$id && printf '%s case_dir\n' "$id"
done

python3 - <<'PY'
from pathlib import Path
ids = [...]
for id in ids:
    print(id, "case_dir=", (Path("bpfix-bench/cases") / id).exists(),
          "raw=", (Path("bpfix-bench/raw/gh") / f"{id}.yaml").exists())
PY
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    raw = d["raw"]
    print(id, d["source"]["title"], raw.get("commit_date"),
          raw.get("fix_type"), d["content"])
    print(textwrap.shorten(" ".join((raw.get("diff_summary") or "").split()),
                            width=900))
    for fld in ("buggy_code", "fixed_code"):
        code = raw.get(fld) or ""
        print(fld, len(code.splitlines()),
              [line for line in code.splitlines()
               if line.startswith("// FILE:") or line.startswith("// CONTEXT:")][:20])
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print("===== ", id)
    print(d["raw"].get("commit_message", "")[:1200])
    print("--- buggy ---")
    print((d["raw"].get("buggy_code") or "")[:2500])
    print("--- fixed ---")
    print((d["raw"].get("fixed_code") or "")[:2500])
PY
```

Replay parser check for the only raw verifier-log field:

```bash
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log
id = "github-commit-libbpf-75a2e3bda8d9"
d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
parsed = parse_verifier_log(d["raw"].get("verifier_log", ""), source="raw verifier_log")
print(parsed)
print("terminal_error", parsed.terminal_error)
print("idx", parsed.rejected_insn_idx)
print("quality", parsed.log_quality)
PY
```

Replay-contract and existing-case format inspection:

```bash
sed -n '1,180p' bpfix-bench/cases/github-commit-cilium-c046309b0ff5/Makefile
sed -n '1,180p' bpfix-bench/cases/github-commit-cilium-c046309b0ff5/prog.c
sed -n '1,240p' tools/replay_case.py
sed -n '240,520p' tools/replay_case.py
```

Report review:

```bash
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-41.md --bench-root bpfix-bench
git status --short
```

## Parsed Verifier Outcomes

No assigned case produced a fresh verifier-reject log.

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-libbpf-75a2e3bda8d9` | raw `verifier_log` field | not run | not a verifier reject; raw text says `Error: object file doesn't contain any bpf program` | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=None` |

Admission validation result:

```text
admitted cases: 0
fresh terminal_error: none
fresh rejected_insn_idx: none
```

## Review

Validation commands completed successfully:

```text
rows 20
unique 20
missing []
extra []
unsupported_by_integrator []
unsupported_by_user []
replay_valid []
```

Dry-run integration completed with `errors: []`, `admitted: []`,
`missing_raw: []`, and `skipped_index: []`. No `replay_valid` rows exist, so no
assigned case directories were created and no local `make clean`, `make`, or
`make replay-verify` commands were run for admitted cases.

## Review

Reviewer validation commands run:

```bash
python3 - <<'PY'
from pathlib import Path
import ast

report = Path("docs/tmp/reconstruction-batch-41.md")
expected = """github-commit-libbpf-732f5982826c
github-commit-libbpf-741277511035
github-commit-libbpf-75a2e3bda8d9
github-commit-libbpf-7cfc3659953c
github-commit-libbpf-7db9ce5fdad1
github-commit-libbpf-8404d1396c0b
github-commit-libbpf-855bf91055a6
github-commit-libbpf-896a3ae0d0f3
github-commit-libbpf-8ac9773f52ae
github-commit-libbpf-8fd8b5bb4641
github-commit-libbpf-939ab641b89b
github-commit-libbpf-93c109c9ee23
github-commit-libbpf-969018545d49
github-commit-libbpf-989d7189cdcf
github-commit-libbpf-9b91dce6913e
github-commit-libbpf-9d2f8aaf21a9
github-commit-libbpf-9ff2b7669370
github-commit-libbpf-a00b10df8c89
github-commit-libbpf-a0ad81d9c464
github-commit-libbpf-a20b60f97135""".splitlines()

rows = []
in_table = False
for line in report.read_text().splitlines():
    if line.strip() == "## Record Results":
        in_table = True
        continue
    if in_table and line.startswith("## "):
        break
    if in_table and line.startswith("| `github-commit-"):
        rows.append([c.strip().strip("`") for c in line.strip().strip("|").split("|")])

source = Path("tools/integrate_reconstruction_batch.py").read_text()
non_replay = None
for node in ast.parse(source).body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "NON_REPLAY_STATUSES":
                non_replay = ast.literal_eval(node.value)
allowed = {"replay_valid", *non_replay}

ids = [row[0] for row in rows]
classes = [row[2] for row in rows]
print("rows", len(rows))
print("unique_ids", len(set(ids)))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("duplicates", sorted({raw_id for raw_id in ids if ids.count(raw_id) > 1}))
print("unsupported", sorted(set(classes) - allowed))
print("replay_valid", [row[0] for row in rows if row[2] == "replay_valid"])
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-41.md --bench-root bpfix-bench
```

Reviewer results:

```text
rows 20
unique_ids 20
missing []
extra []
duplicates []
unsupported []
replay_valid []

apply: false
rows: 20
admitted: []
missing_raw: []
skipped_index: []
errors: []
```

Outcome: pass. Record Results has exactly the 20 assigned IDs once each, all
classifications are accepted by `tools/integrate_reconstruction_batch.py`, and
the dry-run integration reports no errors. There are no `replay_valid` rows, so
`make clean`, `make`, and `make replay-verify` were not applicable for this
batch.
