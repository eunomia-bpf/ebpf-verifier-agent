# Reconstruction Batch 43

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 43 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time, and none were created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 0
- Successful admitted replays: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records have `content.has_verifier_log: false`, `verifier_log_block_count: 0`, and `source_snippet_count: 0`. The raw material consists of libbpf implementation/header snippets and commit metadata, without a standalone BPF `prog.c`, loadable object, verifier terminal error, or rejected instruction. The verifier-shaped CO-RE/log-level/feature-probe records do not contain the triggering BPF source or a captured verifier log, so none satisfies the strict admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-b9f1a06c7042` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff changes user-space `src/btf_dump.c` packed-struct alignment detection in `btf_dump_emit_type()`/`btf_natural_align_of()`, with no BPF program or verifier rejection. |
| `github-commit-libbpf-bb14c6f5b581` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The snippets add `bool skipped` to libbpf's `struct bpf_map` and skip user-space map creation/relocation/pinning paths; this is loader map bookkeeping, not verifier bytecode rejection. |
| `github-commit-libbpf-bde69b0ee007` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff fixes `ptr_is_aligned()` use in `src/btf_dump.c` typed-data formatting for integers/floats/structs, which is user-space BTF dump behavior rather than kernel verification. |
| `github-commit-libbpf-c008eb921eec` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The fix adds a NULL guard in `bpf_object__collect_prog_relos()` before libbpf relocation-section diagnostics; it prevents a user-space loader dereference and supplies no rejected instruction. |
| `github-commit-libbpf-c378eff58c68` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The header change adds `__arg_ctx` and `__arg_nonnull` BTF declaration-tag macros to `bpf_helpers.h`; no BPF call site, object, or verifier terminal error is present. |
| `github-commit-libbpf-c3f58eb6cfc8` | no case | `missing_source` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff post-processes verifier logs for poisoned failed CO-RE relocations matching `invalid func unknown#195896080`, but the raw record contains only libbpf/relo_core log-fixup code and no BPF object with the unguarded failing CO-RE relocation. |
| `github-commit-libbpf-c438cecc546f` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The change fixes a samples build failure by making `UINT32_MAX` available through `src/bpf.h`; it is compile/header compatibility, not a verifier replay. |
| `github-commit-libbpf-c772c9cbde2c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff sanitizes internal libbpf map names before `BPF_MAP_CREATE` so names are not rejected by kernel map-name validation; this is map creation metadata, not program verifier rejection. |
| `github-commit-libbpf-ca515c0ddab7` | no case | `environment_required` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The commit is an LLVM nop-4 workaround in libbpf ELF relocation-section collection; reproducing it would require a matching clang/LLVM-generated object exhibiting that toolchain bug, and no verifier log is captured. |
| `github-commit-libbpf-cb426140d093` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The snippets honor `autocreate` for struct_ops maps in libbpf map initialization/prepared data paths; this is loader struct_ops map handling, with no verifier terminal error. |
| `github-commit-libbpf-d5013de6a5a4` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff changes libbpf `bpf_object__load_progs()` to preserve per-program `log_level`; it affects diagnostic option plumbing, not verifier acceptance. |
| `github-commit-libbpf-d714245dd9ec` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The change adds `bpf_object__load_xattr()` so callers can pass `log_level` through libbpf load APIs; no rejected BPF program or terminal verifier log is included. |
| `github-commit-libbpf-d761220e33b0` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The snippets add get/set APIs for per-program `log_level` in libbpf headers and implementation; this is user-space API/log control, not a verifier failure. |
| `github-commit-libbpf-d9b3fae39124` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff improves libbpf logging around `bpf_prog_load()` and program names; it changes how failures are reported, but includes no captured verifier reject or replay source. |
| `github-commit-libbpf-d9f9fd5b2222` | no case | `environment_required` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The change probes kernel multi-uprobe PID filtering by loading a tiny program and attempting an invalid `uprobe_multi` attach; reproduction depends on a kernel with the broken/fixed PID-filtering behavior and is attach-feature validation, not a captured verifier reject. |
| `github-commit-libbpf-de1d0a25a857` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff adds a NULL guard in `btf_dump__free()`/resize cleanup after allocation failure; this is user-space memory cleanup in BTF dumping, not verifier behavior. |
| `github-commit-libbpf-de3c5a17cb0b` | no case | `environment_required` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The snippets stop libbpf from enforcing explicit `kern_version` and instead populate it from `uname()` for program loading; faithful reproduction depends on libbpf/kernel-version loader policy and a matching BPF object, with no verifier log present. |
| `github-commit-libbpf-de60a31eba19` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The change supports stripping modifiers in `btf_dump` type declaration output through `btf.h`/`btf_dump.c`; it is BTF-to-C formatting, not verifier replay material. |
| `github-commit-libbpf-e152510d72b2` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff fixes `strncat` bounds while deriving raw tracepoint BTF names in `libbpf_prog_type_by_name()`; it is user-space string handling, not a verifier rejection. |
| `github-commit-libbpf-e2d8a820cb4c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`, `source_snippet_count=0`. The diff refactors CO-RE relocation human-description formatting in `src/relo_core.c`; it changes libbpf diagnostic formatting and includes no triggering BPF program or verifier terminal error. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | sed -n '1,160p'
git status --short
rg -n "reconstruction-batch|Record Results|Parsed Verifier Outcomes|external_match|replay-verify|trace_rich" docs/tmp bpfix-bench/cases bpfix-bench/raw -g '*.md' -g '*.yaml' | sed -n '1,220p'
```

Raw-record and assigned case-directory checks:

```bash
for id in github-commit-libbpf-b9f1a06c7042 ... github-commit-libbpf-e2d8a820cb4c; do
  if test -f bpfix-bench/raw/gh/$id.yaml; then echo "$id present"; else echo "$id MISSING"; fi
done

rg -n "github-commit-libbpf-(b9f1a06c7042|bb14c6f5b581|bde69b0ee007|c008eb921eec|c378eff58c68|c3f58eb6cfc8|c438cecc546f|c772c9cbde2c|ca515c0ddab7|cb426140d093|d5013de6a5a4|d714245dd9ec|d761220e33b0|d9b3fae39124|d9f9fd5b2222|de1d0a25a857|de3c5a17cb0b|de60a31eba19|e152510d72b2|e2d8a820cb4c)" bpfix-bench/raw bpfix-bench/cases bpfix-bench/manifest.yaml docs/tmp -g '*.yaml' -g '*.md'

find bpfix-bench/cases -maxdepth 1 -type d | sed 's#bpfix-bench/cases/##' | rg 'github-commit-libbpf-(b9f1a06c7042|bb14c6f5b581|bde69b0ee007|c008eb921eec|c378eff58c68|c3f58eb6cfc8|c438cecc546f|c772c9cbde2c|ca515c0ddab7|cb426140d093|d5013de6a5a4|d714245dd9ec|d761220e33b0|d9b3fae39124|d9f9fd5b2222|de1d0a25a857|de3c5a17cb0b|de60a31eba19|e152510d72b2|e2d8a820cb4c)' || true
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    raw = d.get("raw", {})
    print(id, d.get("source", {}).get("title"), d.get("content", {}))
    print(raw.get("fix_type"), raw.get("commit_date"))
    print(textwrap.shorten(" ".join((raw.get("diff_summary") or "").split()), 900))
    for fld in ("buggy_code", "fixed_code", "verifier_log"):
        val = raw.get(fld) or ""
        print(fld, len(val.splitlines()), len(val))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
for id in ["github-commit-libbpf-c3f58eb6cfc8", "github-commit-libbpf-e2d8a820cb4c",
           "github-commit-libbpf-d9f9fd5b2222", "github-commit-libbpf-ca515c0ddab7",
           "github-commit-libbpf-c378eff58c68", "github-commit-libbpf-c772c9cbde2c",
           "github-commit-libbpf-de3c5a17cb0b"]:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"])
    print(d["raw"].get("commit_message", ""))
    print((d["raw"].get("buggy_code") or "")[:7000])
    print((d["raw"].get("fixed_code") or "")[:7000])
PY
```

Report validation:

```bash
python3 - <<'PY'
from pathlib import Path
from tools.integrate_reconstruction_batch import parse_batch_report
expected = """github-commit-libbpf-b9f1a06c7042
github-commit-libbpf-bb14c6f5b581
github-commit-libbpf-bde69b0ee007
github-commit-libbpf-c008eb921eec
github-commit-libbpf-c378eff58c68
github-commit-libbpf-c3f58eb6cfc8
github-commit-libbpf-c438cecc546f
github-commit-libbpf-c772c9cbde2c
github-commit-libbpf-ca515c0ddab7
github-commit-libbpf-cb426140d093
github-commit-libbpf-d5013de6a5a4
github-commit-libbpf-d714245dd9ec
github-commit-libbpf-d761220e33b0
github-commit-libbpf-d9b3fae39124
github-commit-libbpf-d9f9fd5b2222
github-commit-libbpf-de1d0a25a857
github-commit-libbpf-de3c5a17cb0b
github-commit-libbpf-de60a31eba19
github-commit-libbpf-e152510d72b2
github-commit-libbpf-e2d8a820cb4c""".splitlines()
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-43.md"))
user_allowed = {"attempted_accepted", "environment_required", "missing_source",
                "missing_verifier_log", "not_reconstructable_from_diff",
                "out_of_scope_non_verifier", "attempted_unknown",
                "replay_valid", "replay_reject_no_rejected_insn"}
print("rows", len(rows))
print("unique", len({r.raw_id for r in rows}))
print("missing", sorted(set(expected) - {r.raw_id for r in rows}))
print("extra", sorted({r.raw_id for r in rows} - set(expected)))
print("unsupported_by_user", sorted({r.classification for r in rows} - user_allowed))
print("statuses", sorted({r.classification for r in rows}))
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-43.md --bench-root bpfix-bench
git status --short docs/tmp/reconstruction-batch-43.md bpfix-bench/cases
```

Validation output:

```text
rows 20
unique 20
missing []
extra []
unsupported_by_user []
statuses ['environment_required', 'missing_source', 'out_of_scope_non_verifier']

apply: false
rows: 20
admitted: []
missing_raw: []
skipped_index: []
errors: []

?? docs/tmp/reconstruction-batch-43.md
```

## Parsed Verifier Outcomes

No assigned record produced a fresh verifier-reject log, and no raw record includes a verifier log to parse.

| Source | Count | Parser outcome |
| --- | ---: | --- |
| Raw `verifier_log` fields | 0 | not applicable; all assigned records have `has_verifier_log=false` and `verifier_log_block_count=0` |
| Fresh `make replay-verify` logs | 0 | not run; no record had enough source/log material to create an admitted case |

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
expected = '''github-commit-libbpf-b9f1a06c7042
github-commit-libbpf-bb14c6f5b581
github-commit-libbpf-bde69b0ee007
github-commit-libbpf-c008eb921eec
github-commit-libbpf-c378eff58c68
github-commit-libbpf-c3f58eb6cfc8
github-commit-libbpf-c438cecc546f
github-commit-libbpf-c772c9cbde2c
github-commit-libbpf-ca515c0ddab7
github-commit-libbpf-cb426140d093
github-commit-libbpf-d5013de6a5a4
github-commit-libbpf-d714245dd9ec
github-commit-libbpf-d761220e33b0
github-commit-libbpf-d9b3fae39124
github-commit-libbpf-d9f9fd5b2222
github-commit-libbpf-de1d0a25a857
github-commit-libbpf-de3c5a17cb0b
github-commit-libbpf-de60a31eba19
github-commit-libbpf-e152510d72b2
github-commit-libbpf-e2d8a820cb4c'''.splitlines()
rows = parse_batch_report(Path('docs/tmp/reconstruction-batch-43.md'))
ids = [r.raw_id for r in rows]
print('rows', len(rows))
print('unique_ids', len(set(ids)))
print('missing', sorted(set(expected) - set(ids)))
print('extra', sorted(set(ids) - set(expected)))
print('duplicate_ids', sorted({x for x in ids if ids.count(x) > 1}))
print('unsupported_classifications', sorted({r.classification for r in rows} - ALLOWED_STATUSES))
print('classifications', sorted({r.classification for r in rows}))
print('replay_valid_count', sum(r.classification == 'replay_valid' for r in rows))
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-43.md --bench-root bpfix-bench
```

Results:

```text
rows 20
unique_ids 20
missing []
extra []
duplicate_ids []
unsupported_classifications []
classifications ['environment_required', 'missing_source', 'out_of_scope_non_verifier']
replay_valid_count 0

apply: false
rows: 20
admitted: []
updated_raw:
- bpfix-bench/raw/gh/github-commit-libbpf-b9f1a06c7042.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-bb14c6f5b581.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-bde69b0ee007.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-c008eb921eec.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-c378eff58c68.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-c3f58eb6cfc8.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-c438cecc546f.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-c772c9cbde2c.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-ca515c0ddab7.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-cb426140d093.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-d5013de6a5a4.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-d714245dd9ec.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-d761220e33b0.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-d9b3fae39124.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-d9f9fd5b2222.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-de1d0a25a857.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-de3c5a17cb0b.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-de60a31eba19.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-e152510d72b2.yaml
- bpfix-bench/raw/gh/github-commit-libbpf-e2d8a820cb4c.yaml
missing_raw: []
skipped_index: []
errors: []
```

No `replay_valid` classifications exist in Record Results, so `make clean`, `make`, and `make replay-verify` were not rerun. Outcome: PASS, safe to integrate.
