# Reconstruction Batch 42

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 42 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time, and none were created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 0
- Successful admitted replays: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records have `content.has_verifier_log: false`, `verifier_log_block_count: 0`, `source_snippet_count: 0`, and no `raw.verifier_log` field. The records are libbpf commit diffs covering user-space APIs, BTF/CO-RE relocation handling, AF_XDP setup, helper/feature probes, or header macros. None includes both a complete triggering BPF program and a concrete verifier terminal error, so none satisfies the strict admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-a22abb9c8570` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff removes libbpf-side validation of `log_level`/`log_buf` restrictions in `src/bpf.c:bpf_prog_load()`; it changes user-space syscall option handling and supplies no BPF program, terminal verifier error, or rejected instruction. |
| `github-commit-libbpf-a26ae1b2540a` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The record adds non-CO-RE `BPF_PROBE_READ*` macro variants in `src/bpf_core_read.h`; this is helper macro/API surface, not a captured verifier-rejected program. |
| `github-commit-libbpf-a5459eac49ff` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff changes `bpf_map__init_kern_struct_ops()` to skip zero/null struct_ops members missing from kernel BTF; reproducing the behavior requires a matching struct_ops object and kernel BTF shape, neither captured in the raw record. |
| `github-commit-libbpf-a5831bef6da5` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change is a libbpf resource-leak fix in `bpf_object__elf_collect()` when the kernel does not support BTF; it does not describe a verifier terminal rejection. |
| `github-commit-libbpf-a62b08dd0c3c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff adds libbpf `autoload` state and API handling around program loading, extern resolution, and skeleton loading; no standalone rejected BPF source or verifier log is present. |
| `github-commit-libbpf-a8a3089b5e43` | no case | `not_reconstructable_from_diff` | Raw `has_verifier_log=false`. The fix adjusts libbpf relocation detection of BPF helper-call instructions in `bpf_object__collect_reloc()`; a faithful replay would need the specific ELF/BTF relocation object that was misdetected, not just the loader diff. |
| `github-commit-libbpf-a8bc578af92e` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets add map auto-create opt-out behavior and associated libbpf map iteration/creation checks; this is loader/map lifecycle behavior without a captured verifier reject. |
| `github-commit-libbpf-a945df243902` | no case | `environment_required` | Raw `has_verifier_log=false`. The enum64 sanitization change depends on kernel BTF feature support (`FEAT_BTF_ENUM64`) and object BTF contents; the raw diff has no triggering object/source or verifier terminal error to replay locally. |
| `github-commit-libbpf-abdb15beddcb` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The commit adds getters for BTF.ext function and line info after `bpf_program__set_log_buf()` and declares them in `libbpf.h`; this is introspection API plumbing, not verifier failure material. |
| `github-commit-libbpf-ac4279012921` | no case | `missing_source` | Raw `has_verifier_log=false`. The header diff force-redefines `offsetof()`/`container_of()` for CO-RE relocation preservation; reproducing a verifier-visible failure would require a BPF CO-RE program/object using those relocations, which is absent. |
| `github-commit-libbpf-ae673dc91fbb` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change adds AF_XDP UMEM config flags, symbol-versioned create functions, and XSK address helpers in `src/xsk.c`/`src/xsk.h`; this is user-space socket/ABI behavior, not verifier replay content. |
| `github-commit-libbpf-af3c9f9fc480` | no case | `missing_source` | Raw `has_verifier_log=false`. The CO-RE `.text` relocation fix changes how libbpf finds the program section for relocation records; the raw record lacks the ELF/BPF object with `.text` relocations needed for a faithful verifier case. |
| `github-commit-libbpf-b062410166aa` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff updates `libbpf_probe_bpf_helper()` parsing of unsupported-helper verifier diagnostics from a probe load; replay depends on kernel helper availability and exact verifier message text, with no captured log. |
| `github-commit-libbpf-b09a4999d959` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The commit adds a libbpf object kernel-version setter/getter path in `src/libbpf.c`/`src/libbpf.h`; it changes object metadata handling and includes no rejected program. |
| `github-commit-libbpf-b19fdbf1be21` | no case | `missing_source` | Raw `has_verifier_log=false`. The GCC CO-RE macro support adjusts casts/type handling in `src/bpf_core_read.h`; no GCC-built BPF source/object or verifier reject log is included. |
| `github-commit-libbpf-b1e911e9ba17` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The XSK change removes a `getsockopt(XDP_OPTIONS)` check around socket setup and stores `fd` state; it is AF_XDP user-space setup behavior, not a verifier-rejected BPF program. |
| `github-commit-libbpf-b24a6277cc94` | no case | `environment_required` | Raw `has_verifier_log=false`. The fix changes `need_func_arg_type_fixup()` for PERF_EVENT `__arg_ctx` handling; reproducing it requires matching BTF context types, program type, and kernel behavior not present in the raw record. |
| `github-commit-libbpf-b5bfbab4888f` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff makes libbpf reject static legacy/BTF maps before load (`static maps are not supported`, unsupported map linkage); this is object-format validation, not a verifier terminal rejection. |
| `github-commit-libbpf-b6e179e67c89` | no case | `missing_source` | Raw `has_verifier_log=false`. The header-only change adds `__noinline` to `bpf_helpers.h`; any verifier effect would depend on a particular BPF program's subprogram/inlining shape, which is not captured. |
| `github-commit-libbpf-b95b28103915` | no case | `environment_required` | Raw `has_verifier_log=false`. The new `bpf_probe_large_insn_limit()` loads `BPF_MAXINSNS + 1` instructions and interprets `E2BIG`/`EINVAL`; replay depends on old/new kernel instruction-limit behavior and provides no trace-rich verifier log. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | sed -n '1,160p'
git status --short
find bpfix-bench/cases -maxdepth 2 -type f | sed -n '1,120p'
```

Raw-record location checks:

```bash
for id in github-commit-libbpf-a22abb9c8570 ... github-commit-libbpf-b95b28103915; do
  rg -n "id: $id|$id" bpfix-bench/raw bpfix-bench/raw/index.yaml
done
```

Prior report and replay-contract inspection:

```bash
sed -n '1,220p' docs/tmp/reconstruction-batch-41.md
rg -n "def parse_verifier_log|trace_rich|terminal_error|rejected_insn_idx|log_quality" tools/replay_case.py
sed -n '1,260p' tools/replay_case.py
sed -n '1,260p' tools/integrate_reconstruction_batch.py
sed -n '1,70p' docs/evaluation/raw-backlog-triage.md
sed -n '1,90p' docs/evaluation/reconstruction-todo.md
```

Raw inspection:

```bash
for f in bpfix-bench/raw/gh/github-commit-libbpf-{a22abb9c8570,a26ae1b2540a,a5459eac49ff,a5831bef6da5,a62b08dd0c3c,a8a3089b5e43,a8bc578af92e,a945df243902,abdb15beddcb,ac4279012921}.yaml; do
  printf '\n### %s\n' "$f"
  sed -n '1,220p' "$f"
done

for f in bpfix-bench/raw/gh/github-commit-libbpf-{ae673dc91fbb,af3c9f9fc480,b062410166aa,b09a4999d959,b19fdbf1be21,b1e911e9ba17,b24a6277cc94,b5bfbab4888f,b6e179e67c89,b95b28103915}.yaml; do
  printf '\n### %s\n' "$f"
  sed -n '1,220p' "$f"
done
```

Concise metadata extraction:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    raw = d["raw"]
    print(id, d["source"]["title"], raw.get("commit_date"), raw.get("fix_type"), d["content"])
    print("summary:", " ".join((raw.get("diff_summary") or "").split())[:1000])
PY
```

Assigned case-directory and raw-log checks:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    case_dir = Path("bpfix-bench/cases") / id
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, "case_dir_exists=", case_dir.exists())
    print(
        "has_log=", d["content"]["has_verifier_log"],
        "blocks=", d["content"]["verifier_log_block_count"],
        "source_snippets=", d["content"]["source_snippet_count"],
        "verifier_log_field=", bool(d["raw"].get("verifier_log")),
    )
PY
```

No `make clean`, `make`, or `make replay-verify` commands were run because no record met the threshold for creating an admitted case directory.

Report validation:

```bash
python3 - <<'PY'
from pathlib import Path
expected = """github-commit-libbpf-a22abb9c8570
github-commit-libbpf-a26ae1b2540a
github-commit-libbpf-a5459eac49ff
github-commit-libbpf-a5831bef6da5
github-commit-libbpf-a62b08dd0c3c
github-commit-libbpf-a8a3089b5e43
github-commit-libbpf-a8bc578af92e
github-commit-libbpf-a945df243902
github-commit-libbpf-abdb15beddcb
github-commit-libbpf-ac4279012921
github-commit-libbpf-ae673dc91fbb
github-commit-libbpf-af3c9f9fc480
github-commit-libbpf-b062410166aa
github-commit-libbpf-b09a4999d959
github-commit-libbpf-b19fdbf1be21
github-commit-libbpf-b1e911e9ba17
github-commit-libbpf-b24a6277cc94
github-commit-libbpf-b5bfbab4888f
github-commit-libbpf-b6e179e67c89
github-commit-libbpf-b95b28103915""".split()
allowed = {
    "attempted_accepted", "environment_required", "missing_source",
    "missing_verifier_log", "not_reconstructable_from_diff",
    "out_of_scope_non_verifier", "attempted_unknown", "replay_valid",
    "replay_reject_no_rejected_insn",
}
text = Path("docs/tmp/reconstruction-batch-42.md").read_text()
in_table = False
rows = []
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if cells[0] in {"raw_id", "---"} or set(cells[0]) <= {"-"}:
            continue
        rows.append((cells[0], cells[2]))
ids = [r[0] for r in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("bad_status", [(i, s) for i, s in rows if s not in allowed])
print("replay_valid", [i for i, s in rows if s == "replay_valid"])
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-42.md --bench-root bpfix-bench
git status --short
```

Validation output:

```text
rows 20
unique 20
missing []
extra []
bad_status []
replay_valid []

integrator dry run: rows=20, admitted=[], missing_raw=[], skipped_index=[], errors=[]
```

## Parsed Verifier Outcomes

No fresh verifier logs were produced, and no raw verifier-log fields were available to parse.

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| all 20 assigned IDs | raw records only | not run | not run | no captured verifier log; no `terminal_error`; no `rejected_insn_idx`; no `trace_rich` classification |

Admission validation result:

```text
admitted cases: 0
fresh terminal_error: none
fresh rejected_insn_idx: none
```

## Review

Reviewed on 2026-04-29 (America/Vancouver).

Commands run:

```bash
sed -n '1,240p' docs/tmp/reconstruction-batch-42.md
rg -n "canonical|status|replay_valid|accepted|Record Results" tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-42.md
git status --short
sed -n '1,120p' tools/integrate_reconstruction_batch.py
python3 - <<'PY'
from pathlib import Path
from collections import Counter

expected = """github-commit-libbpf-a22abb9c8570
github-commit-libbpf-a26ae1b2540a
github-commit-libbpf-a5459eac49ff
github-commit-libbpf-a5831bef6da5
github-commit-libbpf-a62b08dd0c3c
github-commit-libbpf-a8a3089b5e43
github-commit-libbpf-a8bc578af92e
github-commit-libbpf-a945df243902
github-commit-libbpf-abdb15beddcb
github-commit-libbpf-ac4279012921
github-commit-libbpf-ae673dc91fbb
github-commit-libbpf-af3c9f9fc480
github-commit-libbpf-b062410166aa
github-commit-libbpf-b09a4999d959
github-commit-libbpf-b19fdbf1be21
github-commit-libbpf-b1e911e9ba17
github-commit-libbpf-b24a6277cc94
github-commit-libbpf-b5bfbab4888f
github-commit-libbpf-b6e179e67c89
github-commit-libbpf-b95b28103915""".splitlines()
allowed = {
    "attempted_accepted", "attempted_failed", "attempted_unknown",
    "candidate_for_replay", "environment_required", "missing_source",
    "missing_verifier_log", "not_reconstructable_from_diff",
    "out_of_scope_non_verifier", "replay_reject_no_rejected_insn",
    "replay_valid",
}
text = Path("docs/tmp/reconstruction-batch-42.md").read_text()
rows = []
in_table = False
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] in {"raw_id", "---"} or set(cells[0]) <= {"-"}:
            continue
        rows.append((cells[0], cells[2]))
ids = [raw_id for raw_id, _ in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("duplicates", sorted([k for k, v in Counter(ids).items() if v != 1]))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("bad_status", [(raw_id, status) for raw_id, status in rows if status not in allowed])
print("replay_valid", [raw_id for raw_id, status in rows if status == "replay_valid"])
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-42.md --bench-root bpfix-bench
```

Results:

```text
rows 20
unique 20
duplicates []
missing []
extra []
bad_status []
replay_valid []

dry-run integration: apply=false, rows=20, admitted=[], missing_raw=[], skipped_index=[], errors=[]
```

No `replay_valid` rows exist, so `make clean`, `make`, and `make replay-verify` were not run.

Outcome: PASS. The report is safe to integrate.
