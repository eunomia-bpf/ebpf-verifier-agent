# Reconstruction Batch 38

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 38 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at inspection time.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Admitted cases: 0
- Not admitted: 20

Every assigned raw record has `content.has_verifier_log: false`,
`verifier_log_block_count: 0`, and `source_snippet_count: 0`. Most records are
libbpf user-space loader, BTF, BTF dump, linker, formatting, or helper-header
compatibility changes rather than standalone verifier-rejected BPF programs.
The most verifier-shaped record, `github-commit-libbpf-23898cf8583b`, was tried
as a scratch replay of the old `bpf_usdt_arg()` bound pattern on this host, but
the program loaded without a verifier terminal error; the upstream failure text
is s390x-specific, so it was not admitted.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-0e7520949e5a` | no case | `missing_source` | Raw diff only changes libbpf resolution/relocation for weak typed ksyms in `src/libbpf.c` (`ext->ksym.type_id && ext->is_set`, weak `-ESRCH` handling). No BPF object using an unresolved weak typed ksym and no verifier log are included. |
| `github-commit-libbpf-0ff6d28aecf2` | no case | `out_of_scope_non_verifier` | Fixes a libbpf crash/error path for `SEC("freplace")` programs without `attach_prog_fd`; the diff adds an early `-EINVAL` warning before BTF-ID lookup. This is user-space loader validation, not verifier rejection evidence. |
| `github-commit-libbpf-112479afb736` | no case | `missing_source` | Adds the `struct_ops.s+` section definition with `SEC_SLEEPABLE`. The raw record contains only libbpf section-dispatch code and no struct_ops BPF program/object that could be loaded and rejected. |
| `github-commit-libbpf-1770ac49cf2f` | no case | `out_of_scope_non_verifier` | Fixes UBSAN/null-source `memcpy()` issues in user-space `src/bpf.c` map/program-name plumbing. The changed code builds `union bpf_attr`; it is not verifier-visible BPF bytecode. |
| `github-commit-libbpf-18922504c336` | no case | `missing_source` | Header change splits `bpf_printk()` between `bpf_trace_printk` and `bpf_trace_vprintk` based on argument count. No BPF call site with too many printk arguments, object, or terminal verifier log is captured. |
| `github-commit-libbpf-1f30788b417c` | no case | `missing_source` | Header change makes `__kptr`/`__kptr_ref` always emit `btf_type_tag` attributes. A reproducer would need a BPF map/value type using these annotations; raw has only macro definitions and no load log. |
| `github-commit-libbpf-2200fefd8741` | no case | `environment_required` | Commit subject says XDP load regression on old kernels; diff changes libbpf's `xdp` section definition from expected-attach form to attach form. Reproduction depends on an old-kernel libbpf load path, not a local standalone verifier reject. |
| `github-commit-libbpf-23898cf8583b` | no case | `attempted_accepted` | This is verifier-shaped: the fix splits `arg_num >= BPF_USDT_MAX_ARG_CNT` from `arg_num >= spec->arg_cnt` and inserts `barrier_var(arg_num)`. A scratch old-pattern tracepoint program on local x86_64 kernel 6.15 built and loaded; `parse_verifier_log(/tmp/bpfix-23898-exp/load.err)` returned `terminal_error=None`, `log_quality=no_terminal_error`. Upstream patch text identifies the reject as s390x-specific, so no local trace-rich reject was admitted. |
| `github-commit-libbpf-240b8fa09860` | no case | `out_of_scope_non_verifier` | Changes libbpf/BTF log-buffer allocation and retry behavior (`log_buf_size = 0`, retry on `ENOSPC`). It affects diagnostics and memory allocation around load failures, not a verifier-rejected BPF program. |
| `github-commit-libbpf-25eb5c4e02cc` | no case | `out_of_scope_non_verifier` | Moves `btf_ext_parse_hdr()` after copying data to aligned storage and changes `btf_ext__new()` input to `const`. This is user-space BTF extension parsing/alignment, not verifier replay material. |
| `github-commit-libbpf-294c85e9b3a4` | no case | `missing_source` | Marks `bpf_iter_num_{new,next,destroy}` extern kfuncs as `__weak __ksym`. Raw includes only helper declarations; a replay would need a BPF object using numeric iterators on a kernel/libbpf combination where unresolved non-weak kfuncs matter. |
| `github-commit-libbpf-29e229ef1426` | no case | `environment_required` | Handles old kernels without global data-section support by probing capability and rejecting global-data relocations earlier. Reproduction requires a pre-global-data kernel/libbpf path and a full ELF object with data relocations; no verifier log is captured. |
| `github-commit-libbpf-2b940bcde10c` | no case | `out_of_scope_non_verifier` | Replaces packed-struct unaligned big-endian helpers in `src/libbpf_utils.c` with `memcpy()`. This is user-space undefined-behavior cleanup in SHA/libbpf utilities, not BPF verifier behavior. |
| `github-commit-libbpf-2c5038dcf485` | no case | `out_of_scope_non_verifier` | Adds a typed-dump data-end bounds check in `btf_dump_get_bitfield_value`. The affected code reads user-space dump buffers, not verifier-visible program memory. |
| `github-commit-libbpf-2c6f445a8ea4` | no case | `out_of_scope_non_verifier` | Adds `btf_dump_type_values(d, "'\\0'")` before terminating array dump output. This is BTF dump formatting, not a verifier load failure. |
| `github-commit-libbpf-2cfeea135cd7` | no case | `out_of_scope_non_verifier` | Adds an `if (!obj->btf)` guard in the static linker before iterating BTF types. It fixes a user-space linker segfault for objects without BTF, not verifier rejection. |
| `github-commit-libbpf-2d042d22a73c` | no case | `out_of_scope_non_verifier` | Adds libbpf recognition and initialization for `.arena.1` global variables and ARENA maps. The raw evidence is ELF/map-loader support, with no rejected instruction or verifier terminal error. |
| `github-commit-libbpf-2d5df9f626bf` | no case | `out_of_scope_non_verifier` | Changes `LIBBPF_OPTS_RESET` to avoid uninitialized tail padding via a temporary and `memcpy`. This is user-space options-struct initialization, not verifier bytecode. |
| `github-commit-libbpf-2f52e2afc068` | no case | `out_of_scope_non_verifier` | Adds a null/type guard before using a BTF VAR during libbpf BTF datasec fixup. It is libbpf object/BTF sanity checking and supplies no verifier reject. |
| `github-commit-libbpf-30c61391bf06` | no case | `missing_source` | Switches tracing and CO-RE macros from `bpf_probe_read()` to `bpf_probe_read_kernel()` / `_str()`. Raw has header macros only; no tracing BPF source/object using the old macro and no captured terminal verifier error are present. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files bpfix-bench docs/tmp tools | sed -n '1,160p'
git status --short
rg -n "github-commit-libbpf-(0e7520949e5a|...|30c61391bf06)" -S bpfix-bench docs/tmp || true
for id in github-commit-libbpf-0e7520949e5a ... github-commit-libbpf-30c61391bf06; do
  if test -d bpfix-bench/cases/$id; then echo EXISTS $id; fi
done
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    p = Path("bpfix-bench/raw/gh") / f"{id}.yaml"
    d = yaml.safe_load(p.read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"),
          d["content"].get("verifier_log_block_count"))
    print(d["raw"].get("diff_summary"))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, difflib
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())["raw"]
    print(id, d["commit_message"])
    for line in difflib.unified_diff((d.get("buggy_code") or "").splitlines(),
                                     (d.get("fixed_code") or "").splitlines(),
                                     fromfile="buggy", tofile="fixed", lineterm=""):
        print(line)
PY
```

Replay-contract and parser inspection:

```bash
sed -n '1,260p' tools/replay_case.py
sed -n '1,220p' docs/tmp/reconstruction-batch-37.md
sed -n '1,220p' bpfix-bench/cases/kernel-selftest-iters-state-safety-double-create-fail-raw-tp-11a53add/Makefile
sed -n '1,180p' bpfix-bench/cases/kernel-selftest-iters-state-safety-double-create-fail-raw-tp-11a53add/case.yaml
sed -n '1,180p' bpfix-bench/cases/kernel-selftest-iters-state-safety-double-create-fail-raw-tp-11a53add/capture.yaml
```

`23898cf8583b` scratch check:

```bash
uname -a
clang --version | sed -n '1,3p'
bpftool version 2>&1 | sed -n '1,5p'
sudo -n true; echo sudo_rc:$?
curl -L --max-time 20 https://github.com/libbpf/libbpf/commit/23898cf8583b.patch | sed -n '1,220p'
```

```bash
rm -rf /tmp/bpfix-23898-exp && mkdir -p /tmp/bpfix-23898-exp
# Created /tmp/bpfix-23898-exp/prog.c as a scratch old-pattern bpf_usdt_arg()-style reproducer.
CLANG_SYS_INCLUDES=$(clang -v -E - </dev/null 2>&1 | awk '/#include <...> search starts here:/{flag=1; next} /End of search list./{flag=0} flag && $1 ~ /^\// {printf "-idirafter %s ", $1}')
clang -g -O2 -Wall -Werror -D__TARGET_ARCH_x86 --target=bpfel -mcpu=v3 $CLANG_SYS_INCLUDES -c prog.c -o prog.o
sudo -n bpftool -d prog load prog.o /sys/fs/bpf/bpfix_23898_exp type tracepoint 2>load.err || true
sed -n '1,280p' load.err
sudo -n rm -f /sys/fs/bpf/bpfix_23898_exp
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/bpfix-23898-exp/load.err").read_text(),
                         source="/tmp/bpfix-23898-exp/load.err"))
PY
```

## Parsed Verifier Outcomes

No assigned case produced an admissible fresh verifier-reject log.

| scope | result |
| --- | --- |
| assigned case directories | none existed and none were created |
| `make clean` / `make` / `make replay-verify` | not run in assigned case directories because no candidate satisfied the strict case-admission contract |
| `github-commit-libbpf-23898cf8583b` scratch replay | local x86_64 6.15 tracepoint object loaded; parser returned `terminal_error=None`, `rejected_insn_idx=17`, `log_quality=no_terminal_error` |
| `tools.replay_case.parse_verifier_log` on admitted logs | no admitted replay logs to parse |
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
sed -n '1,220p' docs/tmp/reconstruction-batch-38.md
sed -n '1,70p' tools/integrate_reconstruction_batch.py
python3 - <<'PY'
from pathlib import Path
import re
from collections import Counter

text = Path("docs/tmp/reconstruction-batch-38.md").read_text()
body = re.search(r'^## Record Results\n(?P<body>.*?)(?=^## )', text, re.S | re.M).group("body")
rows = []
for line in body.splitlines():
    if line.startswith("| `github-commit-libbpf-"):
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append((cells[0].strip("`"), cells[2].strip("`")))
print("row_count", len(rows))
print("unique_count", len(set(r[0] for r in rows)))
print("dupes", [k for k, v in Counter(r[0] for r in rows).items() if v > 1])
print("classifications", sorted(set(c for _, c in rows)))
print("replay_valid_count", sum(c == "replay_valid" for _, c in rows))
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-38.md --bench-root bpfix-bench
```

Review result: pass. `Record Results` has exactly 20 rows, all assigned IDs appear exactly once, no missing or extra IDs were found, and all classifications are accepted by `tools/integrate_reconstruction_batch.py`.

No `replay_valid` rows are present, so `make clean`, `make`, and `make replay-verify` were not re-run.

Dry-run integration passed with `rows: 20`, `admitted: []`, `missing_raw: []`, `skipped_index: []`, and `errors: []`. Safe to integrate.
