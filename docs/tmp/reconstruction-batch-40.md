# Reconstruction Batch 40

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 40 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 0
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records have
`content.has_verifier_log: false`, `verifier_log_block_count: 0`, and
`source_snippet_count: 0`. The available snippets are libbpf implementation
diffs, not standalone BPF programs with captured kernel verifier traces. Most
records are user-space libbpf API, BTF, linker, skeleton, attach, build, or
diagnostic fixes. The few records that mention loader relocation, ksyms, kfuncs,
or old-kernel behavior still lack the triggering BPF object and a terminal
verifier rejection, so they do not satisfy the strict replay admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-50d1b8e6b45b` | no case | `out_of_scope_non_verifier` | Raw diff removes `linux/unaligned.h` use in user-space `src/libbpf_utils.c` and adds local packed helpers for `libbpf_sha256()`. It is a libbpf portability/build dependency change, with no BPF program or verifier log. |
| `github-commit-libbpf-5579664205e4` | no case | `out_of_scope_non_verifier` | Raw diff changes symbol-versioning macros in `src/libbpf_internal.h` and reorders `DEFAULT_VERSION()` around XSK APIs to fix GCC/binutils LTO builds. This is shared-library build behavior, not verifier rejection. |
| `github-commit-libbpf-58b164237a44` | no case | `out_of_scope_non_verifier` | Raw diff updates user-space `btf__align_of()` to account for member offsets and packed structs. It affects BTF layout introspection, not kernel verifier acceptance of a BPF program. |
| `github-commit-libbpf-5a8c675d0a3b` | no case | `out_of_scope_non_verifier` | Raw diff frees `obj->btf_ext` after `btf__load()` fails to avoid a libbpf SIGSEGV. The evidence is loader cleanup after BTF load failure, with no verifier trace or rejected instruction. |
| `github-commit-libbpf-5b6dfd7f6b90` | no case | `out_of_scope_non_verifier` | Raw diff adds a NULL guard in `bpf_object__destroy_skeleton()`. This is a user-space skeleton destruction robustness fix, not verifier-load behavior. |
| `github-commit-libbpf-5c31bcf220f6` | no case | `environment_required` | Raw diff explicitly targets legacy kernels without global-data support, skipping internal data-map creation and later returning `kernel doesn't support global data` during relocation. Faithful reproduction would require an old-kernel feature matrix and a matching BPF object, and still does not provide a verifier log. |
| `github-commit-libbpf-5fe9c1217a63` | no case | `out_of_scope_non_verifier` | Raw diff makes libbpf fail early when `prog->type == BPF_PROG_TYPE_UNSPEC` and logs an unrecognized ELF section name. The failure is libbpf-side program-type validation before verifier replay material exists. |
| `github-commit-libbpf-6028cec50c55` | no case | `out_of_scope_non_verifier` | Raw diff rejects static entry-point programs during ELF program discovery with `program '%s' is static and not supported`. That is libbpf object-format validation, not a kernel verifier terminal error. |
| `github-commit-libbpf-60ce9af668b3` | no case | `out_of_scope_non_verifier` | Raw diff changes BTF dedup equivalence for duplicated compiler-emitted structs. The affected code is user-space BTF deduplication, with no BPF source/object or verifier rejection. |
| `github-commit-libbpf-6215836a089f` | no case | `out_of_scope_non_verifier` | Raw diff validates `xsk_socket__create()` flags and rejects unknown `libbpf_flags`. This is AF_XDP socket API input validation, not verifier behavior. |
| `github-commit-libbpf-691c22dc0c29` | no case | `out_of_scope_non_verifier` | Raw diff sanitizes map pin paths by replacing periods before `bpf_map__pin()`/`bpf_map__unpin()`. It concerns bpffs path naming during pinning, not verifier rejection. |
| `github-commit-libbpf-6a41f02ad405` | no case | `out_of_scope_non_verifier` | Raw diff adjusts `bpf_map__init_kern_struct_ops()` handling of zeroed or nulled struct_ops callbacks and autoload state. This is libbpf struct_ops map initialization against kernel BTF, with no captured verifier error. |
| `github-commit-libbpf-6bec18258cd7` | no case | `out_of_scope_non_verifier` | Raw diff adds `BPF_NETFILTER` link-create options and a `bpf_program__attach_netfilter()` helper. It is attach-helper/API support, not a verifier-rejected program. |
| `github-commit-libbpf-6d0fcc3bd534` | no case | `missing_source` | Raw diff adds typed ksym metadata, vmlinux BTF lookup, and extern relocation support. A replay would need the BPF object declaring the typed ksym and the target BTF environment; the raw record contains only libbpf implementation snippets and no verifier log. |
| `github-commit-libbpf-6d704c7ffd5d` | no case | `missing_source` | Raw diff supports triple-underscore flavor names for kfunc/ksym relocation via `bpf_core_essential_name_len()` and `essent_name`. Reproduction would require a BPF object using the flavored extern; none is present, and no verifier log is captured. |
| `github-commit-libbpf-6d7acdae6de8` | no case | `out_of_scope_non_verifier` | Raw diff teaches libbpf about verifier `log_level` bit 2 and increases `BPF_LOG_BUF_SIZE`. It changes log plumbing and accepted option values, but supplies no rejected BPF program or terminal verifier error. |
| `github-commit-libbpf-6fdbfb00f1f8` | no case | `missing_source` | Raw diff renames the in-kernel skeleton syscall shim from `bpf_sys_bpf()` to `kern_sys_bpf()` in `src/skel_internal.h`. Any verifier-shaped replay would require the generated loader/BPF program that exercised the forbidden call path; the raw record has only the header diff and no log. |
| `github-commit-libbpf-6ff506248078` | no case | `out_of_scope_non_verifier` | Raw diff relaxes libbpf's `bpf_object__is_btf_mandatory()` check by excluding `.BTF` maps. It is BTF-load policy in the user-space loader, not verifier instruction rejection. |
| `github-commit-libbpf-72ef206260db` | no case | `out_of_scope_non_verifier` | Raw diff moves a `pr_debug()` statement in `bpf_object__init_maps()` to avoid dereferencing absent map data. This is a libbpf NULL/zero-map diagnostic crash fix, not verifier behavior. |
| `github-commit-libbpf-732d6c011fad` | no case | `out_of_scope_non_verifier` | Raw diff moves `sys_memfd_create()` into `libbpf_internal.h` and uses it from `linker.c` for Android/bionic compatibility. It is libc/syscall portability, not verifier replay material. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | sed -n '1,200p'
ls -la docs/tmp bpfix-bench bpfix-bench/cases bpfix-bench/raw 2>/dev/null
git status --short
```

Raw-record presence and assigned case-directory checks:

```bash
for id in github-commit-libbpf-50d1b8e6b45b ... github-commit-libbpf-732d6c011fad; do
  rg -l "id: $id|raw_id: $id|$id" bpfix-bench/raw
done

for id in github-commit-libbpf-50d1b8e6b45b ... github-commit-libbpf-732d6c011fad; do
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
    p = Path("bpfix-bench/raw/gh") / f"{id}.yaml"
    d = yaml.safe_load(p.read_text())
    raw = d.get("raw", {})
    print(id, d.get("source", {}).get("title"))
    print(raw.get("commit_date"), raw.get("fix_type"), d.get("content"))
    print(textwrap.shorten(" ".join((raw.get("diff_summary") or "").split()), width=900))
    for line in (raw.get("buggy_code") or "").splitlines():
        if line.startswith("// FILE:") or line.startswith("// CONTEXT:"):
            print(line)
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    raw = d["raw"]
    print("###", id)
    print(raw.get("commit_message", "").strip()[:2000])
    print(raw.get("buggy_code", "")[:3500])
    print(raw.get("fixed_code", "")[:2500])
PY
```

Replay-contract and prior-format inspection:

```bash
sed -n '1,220p' docs/tmp/reconstruction-batch-37.md
sed -n '1,260p' tools/integrate_reconstruction_batch.py
sed -n '1,260p' tools/replay_case.py
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/case.yaml
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/capture.yaml
```

Timestamp:

```bash
date +%F && date -u +%FT%TZ
```

Report validation:

```bash
python3 - <<'PY'
from pathlib import Path
from tools.integrate_reconstruction_batch import parse_batch_report, ALLOWED_STATUSES
expected = [...]
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-40.md"))
ids = [r.raw_id for r in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("unsupported", sorted({r.classification for r in rows} - ALLOWED_STATUSES))
print("replay_valid", [r.raw_id for r in rows if r.classification == "replay_valid"])
print("status_counts", {s: sum(1 for r in rows if r.classification == s)
                        for s in sorted({r.classification for r in rows})})
PY

python3 tools/integrate_reconstruction_batch.py \
  docs/tmp/reconstruction-batch-40.md --bench-root bpfix-bench

git status --short docs/tmp/reconstruction-batch-40.md \
  bpfix-bench/cases/github-commit-libbpf-50d1b8e6b45b \
  ... \
  bpfix-bench/cases/github-commit-libbpf-732d6c011fad
```

## Parsed Verifier Outcomes

No assigned case produced a fresh verifier-reject log.

| scope | result |
| --- | --- |
| assigned raw records | 20 present; all have `content.has_verifier_log: false`, `verifier_log_block_count: 0`, and `source_snippet_count: 0` |
| assigned case directories | none existed and none were created |
| `make clean` / `make` / `make replay-verify` | not run in assigned case directories because no faithful standalone candidate satisfied admission prerequisites |
| `tools.replay_case.parse_verifier_log` | no new verifier log to parse |
| admitted trace-rich rejects | 0 |

Admission validation result:

```text
admitted cases: 0
fresh terminal_error: none
fresh rejected_insn_idx: none
report rows: 20
unique assigned rows: 20
missing assigned IDs: none
extra IDs: none
unsupported statuses: none
dry-run integration errors: none
```

## Review

Review commands run:

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter
from tools.integrate_reconstruction_batch import parse_batch_report, ALLOWED_STATUSES
expected = [...]
rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-40.md"))
ids = [r.raw_id for r in rows]
counts = Counter(ids)
print("rows", len(rows))
print("unique", len(counts))
print("missing", sorted(set(expected) - set(ids)))
print("extra", sorted(set(ids) - set(expected)))
print("duplicates", sorted(k for k, v in counts.items() if v != 1))
print("unsupported", sorted({r.classification for r in rows} - ALLOWED_STATUSES))
print("replay_valid", [r.raw_id for r in rows if r.classification == "replay_valid"])
print("status_counts", dict(sorted(Counter(r.classification for r in rows).items())))
PY

python3 tools/integrate_reconstruction_batch.py \
  docs/tmp/reconstruction-batch-40.md --bench-root bpfix-bench
```

Review result: pass. `Record Results` has exactly 20 rows, all assigned IDs appear exactly once, there are no missing or extra IDs, classifications are accepted by `tools/integrate_reconstruction_batch.py`, and the dry-run integration completed with `errors: []`. No row is classified `replay_valid`, so `make clean`, `make`, `make replay-verify`, and fresh verifier-log parsing were not run.
