# Reconstruction Batch 39

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 39 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time, and none were created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records have
`content.has_verifier_log: false` and `verifier_log_block_count: 0`, so none
contains an external terminal verifier error or rejected instruction. Most
records are libbpf user-space loader, BTF, ELF, attach, feature probing, or
build-warning changes rather than standalone verifier-rejected BPF programs.
One raw record (`github-commit-libbpf-429aaef6a3d4`) includes an inline feature
probe that can locally trigger a verifier rejection, but the fresh log contains
only a terminal message and `processed 0 insns`; `tools.replay_case.parse_verifier_log`
classifies it as `message_only` with no `rejected_insn_idx`, so it fails the
strict admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-3319982d34dd` | no case | `missing_source` | Raw diff adds `__hidden` and libbpf BTF FUNC linkage rewriting so hidden global/weak subprograms are verified like static functions. It contains only libbpf/header implementation snippets and no triggering BPF source/object or verifier log. |
| `github-commit-libbpf-33b22671c2cd` | no case | `out_of_scope_non_verifier` | Commit subject is a `-Wmaybe-uninitialized` false-positive workaround in `src/elf.c`. The raw evidence is compiler-warning control flow, not a verifier-load reject. |
| `github-commit-libbpf-36cc591ac8a7` | no case | `out_of_scope_non_verifier` | Improves ELF relocation sanitization in `bpf_object__elf_collect()` and `find_prog_by_sec_insn()`. This is libbpf object parsing/relocation hygiene with no rejected BPF program or terminal verifier error. |
| `github-commit-libbpf-39cf9fc90f36` | no case | `out_of_scope_non_verifier` | Auto-detects BTF IDs for BTF-based raw tracepoints through libbpf load/section metadata paths. The snippets are loader API changes and contain no verifier rejection evidence. |
| `github-commit-libbpf-3a3ef0c1d09e` | no case | `out_of_scope_non_verifier` | Fixes a NULL-pointer dereference in libbpf relocation bookkeeping around `find_prog_by_sec_insn()`. The failure is user-space loader robustness, not kernel verifier behavior. |
| `github-commit-libbpf-3b19b1bb5599` | no case | `out_of_scope_non_verifier` | Changes libbpf to call `memfd_create()` directly. The touched `find_elf_var_sym()`/memfd path is user-space compatibility code and has no verifier log. |
| `github-commit-libbpf-3b2837e2961b` | no case | `out_of_scope_non_verifier` | Handles missing `BPF_OBJ_GET_INFO_BY_FD` gracefully in perf buffer setup. This is syscall compatibility for map info lookup, not a BPF program verification failure. |
| `github-commit-libbpf-3b301cf75d12` | no case | `out_of_scope_non_verifier` | Commit subject is another `-Wmaybe-uninitialized` false-positive workaround in `find_ksym_btf_id()`/struct_ops autoload code. It is build-warning cleanup, not verifier replay material. |
| `github-commit-libbpf-3b80b6c77e5c` | no case | `out_of_scope_non_verifier` | Fixes a build failure from an uninitialized-variable warning in `bpf_object__relocate()`. No verifier-rejected program or log is present. |
| `github-commit-libbpf-3cd45b660ce2` | no case | `out_of_scope_non_verifier` | Changes libbpf's decision to add `BPF_F_MMAPABLE` only for data maps with global variables. This is map-creation compatibility/user-space policy, not a standalone verifier rejection. |
| `github-commit-libbpf-3d81b13b364e` | no case | `missing_source` | Fixes the `BPF_KRETPROBE` return-value macro from `PT_REGS_RET(ctx)` to `PT_REGS_RC(ctx)`. The raw record contains only `bpf_tracing.h` macro text and lacks an affected BPF program plus verifier log. |
| `github-commit-libbpf-3db758537866` | no case | `out_of_scope_non_verifier` | Adds names to libbpf auxiliary maps used by feature probes. The embedded probes are capability checks and map-name compatibility changes, not a captured verifier-reject benchmark. |
| `github-commit-libbpf-41c612167e2b` | no case | `out_of_scope_non_verifier` | Rejects legacy `maps` ELF sections in libbpf object parsing before normal program load. The behavior is libbpf policy/diagnostics rather than kernel verifier rejection. |
| `github-commit-libbpf-429aaef6a3d4` | temporary replay rejected without index | `replay_reject_no_rejected_insn` | A temp reconstruction of the raw `probe_ldimm64_full_range_off()` instruction sequence rejected locally with `direct value offset of 1073741824 is not allowed`, but the log reported `processed 0 insns` and parser output was `log_quality=message_only`, `rejected_insn_idx=None`. |
| `github-commit-libbpf-444f3c0e7a0f` | no case | `out_of_scope_non_verifier` | Works around kernel kallsyms name stripping for `.llvm.` suffixes in libbpf symbol availability logic. This is kernel-symbol matching behavior, not verifier bytecode rejection. |
| `github-commit-libbpf-471e7c241d30` | no case | `out_of_scope_non_verifier` | Adds `BTF_KIND_FLOAT` support across BTF parsing, dumping, sanitization, and feature probing. The broad BTF implementation change has no standalone verifier-rejected BPF source or log. |
| `github-commit-libbpf-49058f8c6f37` | no case | `missing_source` | Extends CO-RE relocation patching from ALU immediates to LDX/ST/STX offsets. A faithful replay would need the BPF CO-RE object whose relocation previously failed; the raw record only contains libbpf relocation code and no verifier log. |
| `github-commit-libbpf-4dc3aeb072ef` | no case | `out_of_scope_non_verifier` | Fixes pinned map reuse on older kernels by gating BTF/map-info behavior in libbpf. This is loader/map compatibility rather than a verifier-rejected program. |
| `github-commit-libbpf-4ec5e360ae01` | no case | `out_of_scope_non_verifier` | Fixes `bpf_ksym_exists()` macro behavior for GCC by changing compile-time attribute checks. The issue is compiler/header compatibility and no verifier terminal error is provided. |
| `github-commit-libbpf-509ef92905f0` | no case | `out_of_scope_non_verifier` | Provides a more helpful libbpf message for uninitialized global variables during relocation collection. The change is user-space diagnostics, not a kernel verifier trace. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files | rg '(^docs/tmp/reconstruction-batch-|^bpfix-bench/(raw|cases)|manifest.yaml|tools/replay_case)'
git status --short
rg -n "<assigned raw IDs>" -S bpfix-bench docs tools
for id in <assigned raw IDs>; do test -d bpfix-bench/cases/$id && echo "EXISTS $id"; done
```

Raw-record inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"])
    print(textwrap.shorten(" ".join(d["raw"].get("diff_summary", "").split()), width=900))
    for line in (d["raw"].get("buggy_code") or "").splitlines():
        if line.startswith("// FILE:") or line.startswith("// CONTEXT:"):
            print(line)
PY
```

Replay-contract and existing-case format inspection:

```bash
sed -n '1,520p' tools/replay_case.py
sed -n '1,240p' docs/tmp/reconstruction-batch-37.md
sed -n '1,220p' tools/integrate_reconstruction_batch.py
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-f51f4dfac542/Makefile
sed -n '1,180p' bpfix-bench/cases/github-commit-cilium-f51f4dfac542/case.yaml
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-f51f4dfac542/prog.c
```

Temporary replay probe for `github-commit-libbpf-429aaef6a3d4`:

```bash
# Compiled and ran a /tmp C syscall loader matching the raw fixed-code probe:
# BPF_MAP_CREATE array map, then BPF_PROG_LOAD tracepoint with:
#   BPF_LD_MAP_VALUE(BPF_REG_1, map_fd, 1U << 30)
#   BPF_EXIT_INSN()
# Parsed the captured output with tools.replay_case.parse_verifier_log.
```

Environment snapshot:

```bash
date +%F && date +%Z
uname -r
clang --version | head -1
bpftool version 2>/dev/null | head -1 || true
```

Observed environment:

```text
2026-04-29
PDT
6.15.11-061511-generic
Ubuntu clang version 18.1.3 (1ubuntu1)
bpftool v7.7.0
```

## Parsed Verifier Outcomes

No assigned case produced an admissible fresh trace-rich verifier reject.

| scope | result |
| --- | --- |
| assigned case directories | none existed and none were created |
| `make clean` / `make` / `make replay-verify` | not run in assigned case directories because no candidate satisfied admission prerequisites |
| `tools.replay_case.parse_verifier_log` on `github-commit-libbpf-429aaef6a3d4` temp probe | `terminal_error="direct value offset of 1073741824 is not allowed"`, `rejected_insn_idx=None`, `log_quality=message_only`, `source=tmp` |
| admitted trace-rich rejects | 0 |

Fresh temp verifier output for `github-commit-libbpf-429aaef6a3d4`:

```text
prog_load errno=22 Invalid argument
direct value offset of 1073741824 is not allowed
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

Admission validation result:

```text
admitted cases: 0
fresh terminal_error: none admitted
fresh rejected_insn_idx: none admitted
```

## Review

Commands run:

```bash
python3 - <<'PY'
from pathlib import Path
from tools.integrate_reconstruction_batch import parse_batch_report, ALLOWED_STATUSES
expected = [...]
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-39.md"))
ids = [r.raw_id for r in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("unsupported", sorted({r.classification for r in rows} - ALLOWED_STATUSES))
print("statuses", sorted({r.classification for r in rows}))
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-39.md --bench-root bpfix-bench
```

Review result: pass. `Record Results` has exactly 20 rows, all assigned IDs
appear exactly once, no extra IDs are present, and all classifications are
accepted by `tools/integrate_reconstruction_batch.py`. Dry-run integration
reported `errors: []` and `admitted: []`.

## Review

Commands run:

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter
from tools.integrate_reconstruction_batch import parse_batch_report, ALLOWED_STATUSES
expected = [...]
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-39.md"))
ids = [r.raw_id for r in rows]
counts = Counter(ids)
row429 = next((r for r in rows if r.raw_id == "github-commit-libbpf-429aaef6a3d4"), None)
print("rows", len(rows))
print("unique", len(counts))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("duplicates", sorted(k for k, v in counts.items() if v != 1))
print("unsupported", sorted({r.classification for r in rows} - ALLOWED_STATUSES))
print("replay_valid", sorted(r.raw_id for r in rows if r.classification == "replay_valid"))
print("row429", row429.classification if row429 else None, row429.reason if row429 else None)
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-39.md --bench-root bpfix-bench
```

Review result: pass. `Record Results` has exactly 20 rows, exactly 20 unique
assigned IDs, no missing/extra/duplicate IDs, and no unsupported
classifications. No `replay_valid` rows exist, so `make clean`, `make`, and
`make replay-verify` were not re-run. The `github-commit-libbpf-429aaef6a3d4`
row is not `replay_valid`; it is `replay_reject_no_rejected_insn` with
`log_quality=message_only` and `rejected_insn_idx=None` in the recorded reason.
Dry-run integration completed with `errors: []`, `admitted: []`, and
`apply: false`. Safe to integrate.
