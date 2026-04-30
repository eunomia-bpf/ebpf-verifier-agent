# Reconstruction Batch 44

Date: 2026-04-30

Scope:

- Assigned Batch 44 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, any
  raw YAML file, or any `bpfix-bench/cases/<assigned-raw-id>/` directory.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 5
- Successful admitted replays: 0
- Not admitted: 20

No record in this batch met the strict admission rule. The libbpf commit records
mostly describe user-space libbpf loader, BTF, USDT, header, warning, or
historical-kernel probing behavior, and all have `content.has_verifier_log:
false`. The Katran issue has a trace-rich external verifier log but no source
snippet. Three StackOverflow records with enough source/instruction context were
probed in `/tmp`; all accepted under the local privileged `bpftool` replay path,
so no replay-valid case was created.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-libbpf-e5146eff759a` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff adds libbpf-side early rejection for `BPF_PROG_TYPE_STRUCT_OPS` programs with `attach_btf_id == 0`; it is loader prevalidation with no kernel verifier terminal error or standalone rejected program. |
| `github-commit-libbpf-e64e62d19f2d` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets split BTF initialization from BTF loading and sanitization inside libbpf; the affected path is BTF/object setup, not a verifier-rejected BPF program. |
| `github-commit-libbpf-e6cc30f445bc` | no case | `environment_required` | Raw `has_verifier_log=false`. The change poisons unresolved weak kfunc calls so libbpf can later rewrite verifier logs like `invalid func unknown#2002...`; faithful replay requires a matching unresolved kfunc relocation/libbpf load path and kernel BTF context, which the raw diff alone does not provide. |
| `github-commit-libbpf-e9adfa851f68` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix adds `<string.h>` to `libbpf_common.h` for installed-header `memset()` usage; this is a user-space/header build issue, not verifier rejection. |
| `github-commit-libbpf-ea02e10fc435` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff removes pointer-to-enum casts in `bpf_tracing.h`/`usdt.bpf.h`; evidence points to C macro/type hygiene, with no verifier log or rejected instruction. |
| `github-commit-libbpf-eca524d5a675` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change adds a GCC diagnostic pragma around a packed user-space helper struct in `libbpf_utils.c`; no BPF program load or verifier evidence is present. |
| `github-commit-libbpf-f11708030716` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The commit fixes libbpf realloc handling for zero-sized edge cases in `libbpf.c` and `usdt.c`; this is user-space memory/API handling, not a verifier reject. |
| `github-commit-libbpf-f15814c93ade` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff changes `__always_inline` to include `inline` to avoid an unused-function warning for `bpf_tail_call_static`; no verifier terminal error is identified. |
| `github-commit-libbpf-f6f24022d305` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The snippets fix `bpf_object__open_skeleton()` option/name handling in libbpf; the evidence is loader API correctness, not kernel verifier rejection. |
| `github-commit-libbpf-f8faf2b33d5f` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The fix initializes a local `btf_var_secinfo *` pointer to silence a false uninitialized-variable warning in libbpf relocation code; no replayable verifier failure is present. |
| `github-commit-libbpf-fb3809e94078` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The diff adjusts alignment checks for BTF typed dump data in user-space `btf_dump.c`; it does not describe a BPF verifier-load failure. |
| `github-commit-libbpf-fcc06c3da46c` | no case | `out_of_scope_non_verifier` | Raw `has_verifier_log=false`. The change removes unused arguments from USDT note parsing and target collection; this is user-space parser cleanup without verifier evidence. |
| `github-commit-libbpf-fd28ca4b5bea` | no case | `environment_required` | Raw `has_verifier_log=false`. The diff fixes kfunc ksym relocation for `ld_imm64` by carrying kernel BTF object FD data; any reject depends on a specific kfunc relocation and kernel/module BTF setup not captured by the raw record. |
| `github-commit-libbpf-fd6c9d906aff` | no case | `environment_required` | Raw `has_verifier_log=false`. The `BPF_KSYSCALL` macro change depends on syscall-wrapper kconfig extern resolution and architecture-specific register layout; no terminal verifier log is available for a standalone replay. |
| `github-commit-libbpf-ffd4015f3b6e` | no case | `environment_required` | Raw `has_verifier_log=false`. The change switches libbpf's `bpf_probe_read_kernel()` feature probe from kprobe to tracepoint program type for old kernels; reproducing the bug requires an old-kernel helper/prog-type support matrix. |
| `github-facebookincubator-katran-149` | no case | `missing_source` | External raw log is trace-rich (`R1 type=inv expected=map_ptr`, rejected insn 553), but `source_snippet_count=0` and no buggy/fixed code are present; the full Katran `xdp-balancer` program is not reconstructable from the issue text alone. |
| `stackoverflow-48267671` | no case | `attempted_accepted` | Raw external log is only message-level for the original LLVM 3.8/libbpf section issue (`unreachable insn 2`, no rejected instruction). A `/tmp/batch44-so482` reconstruction of the shown sockops tail-call program built and loaded successfully on kernel 6.15.11 with clang 18; parser result was `log_quality=no_terminal_error`. |
| `stackoverflow-60383861` | no case | `missing_source` | Raw log reports `unknown opcode 00`, but the source snippets contain ellipses and BCC-only context around `strcmp()`/task namespace access; there is no complete C program or attach/load setup for a faithful replay. |
| `stackoverflow-62936008` | no case | `environment_required` | Raw error (`invalid relo for insn[6].code 0x85`, then `last insn is not an exit or jmp`) depends on the historical kernel `samples/bpf` loader and missing helper declaration path. A modern `/tmp/batch44-so629` probe with `bpf_helpers.h` built and loaded successfully, so it was not admitted. |
| `stackoverflow-71351495` | no case | `attempted_accepted` | Raw log is trace-rich under a constrained CAP_BPF-only scenario (`R3 pointer comparison prohibited`, rejected insn 4). The local benchmark replay uses privileged `sudo bpftool`; `/tmp/batch44-so713` built and loaded the shown `sk_reuseport` packet-access program successfully, so no local verifier reject was available. |

## Commands Run

Context and raw-record inspection:

```bash
pwd && rg --files | rg '(^bpfix-bench/|^docs/tmp/|tools/replay_case|raw)'
git status --short
for id in github-commit-libbpf-e5146eff759a ... github-facebookincubator-katran-149; do
  sed -n '1,220p' bpfix-bench/raw/gh/$id.yaml
done
for id in stackoverflow-48267671 stackoverflow-60383861 stackoverflow-62936008 stackoverflow-71351495; do
  sed -n '1,280p' bpfix-bench/raw/so/$id.yaml
done
sed -n '1,240p' docs/tmp/reconstruction-batch-36.md
sed -n '1,220p' docs/tmp/reconstruction-batch-35.md
sed -n '1,260p' tools/replay_case.py
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["content"].get("has_verifier_log"),
          d["raw"].get("fix_type"))
    print(textwrap.shorten(d["raw"].get("diff_summary", "").replace("\n", " | "), 600))
PY
clang --version
bpftool version
uname -a
```

Temporary replay probes:

```bash
rm -rf /tmp/batch44-so713 /tmp/batch44-so482 /tmp/batch44-so629
mkdir -p /tmp/batch44-so713 /tmp/batch44-so482 /tmp/batch44-so629
cp bpfix-bench/cases/stackoverflow-72575736/Makefile /tmp/batch44-so713/Makefile
cp bpfix-bench/cases/stackoverflow-72575736/Makefile /tmp/batch44-so482/Makefile
cp bpfix-bench/cases/stackoverflow-72575736/Makefile /tmp/batch44-so629/Makefile
# Added temporary prog.c files in /tmp with apply_patch.

cd /tmp/batch44-so713 && make clean && make && make replay-verify
cd /tmp/batch44-so482 && make clean && make && make replay-verify
cd /tmp/batch44-so629 && make clean && make && make replay-verify

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
for d in ["so713", "so482", "so629"]:
    p = Path(f"/tmp/batch44-{d}/replay-verifier.log")
    print(d, parse_verifier_log(p.read_text(errors="replace"), source=str(p)))
PY
```

External raw-log parsing:

```bash
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log
for bucket, id in [
    ("so", "stackoverflow-48267671"),
    ("so", "stackoverflow-60383861"),
    ("so", "stackoverflow-62936008"),
    ("so", "stackoverflow-71351495"),
    ("gh", "github-facebookincubator-katran-149"),
]:
    d = yaml.safe_load((Path("bpfix-bench/raw") / bucket / f"{id}.yaml").read_text())
    print(id, parse_verifier_log(d["raw"]["verifier_log"]["combined"], source="raw"))
PY
```

## Parsed Verifier Outcomes

| Raw ID | Source | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-facebookincubator-katran-149` | raw external log | not run | external reject evidence only | `log_quality=trace_rich`, `terminal_error=R1 type=inv expected=map_ptr`, `rejected_insn_idx=553` |
| `stackoverflow-48267671` | raw external log | not run | external reject evidence only | `log_quality=message_only`, `terminal_error=EINVAL For BPF_PROG_LOAD...`, `rejected_insn_idx=None` |
| `stackoverflow-48267671` | `/tmp/batch44-so482` local probe | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=1` |
| `stackoverflow-60383861` | raw external log | not run | external reject evidence only | `log_quality=message_only`, `terminal_error=unknown opcode 00`, `rejected_insn_idx=None` |
| `stackoverflow-62936008` | raw external log | not run | external reject evidence only | `log_quality=message_only`, `terminal_error=last insn is not an exit or jmp`, `rejected_insn_idx=None` |
| `stackoverflow-62936008` | `/tmp/batch44-so629` local probe | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=10` |
| `stackoverflow-71351495` | raw external log | not run | external reject evidence only | `log_quality=trace_rich`, `terminal_error=R3 pointer comparison prohibited`, `rejected_insn_idx=4` |
| `stackoverflow-71351495` | `/tmp/batch44-so713` local probe | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=10` |

Environment observed for local probes:

```text
clang: Ubuntu clang version 18.1.3
bpftool: v7.7.0 using libbpf v1.7
kernel: Linux lab 6.15.11-061511-generic x86_64
```

## Review

Commands run:

```bash
sed -n '1,260p' docs/tmp/reconstruction-batch-44.md
sed -n '1,55p' tools/integrate_reconstruction_batch.py
python3 - <<'PY'
from pathlib import Path
p = Path('docs/tmp/reconstruction-batch-44.md')
sec = p.read_text().split('## Record Results', 1)[1].split('\n## ', 1)[0]
rows = []
for line in sec.splitlines():
    if line.startswith('| `'):
        rows.append([c.strip() for c in line.strip().strip('|').split('|')])
ids = [r[0].strip('`') for r in rows]
assigned = '''github-commit-libbpf-e5146eff759a
github-commit-libbpf-e64e62d19f2d
github-commit-libbpf-e6cc30f445bc
github-commit-libbpf-e9adfa851f68
github-commit-libbpf-ea02e10fc435
github-commit-libbpf-eca524d5a675
github-commit-libbpf-f11708030716
github-commit-libbpf-f15814c93ade
github-commit-libbpf-f6f24022d305
github-commit-libbpf-f8faf2b33d5f
github-commit-libbpf-fb3809e94078
github-commit-libbpf-fcc06c3da46c
github-commit-libbpf-fd28ca4b5bea
github-commit-libbpf-fd6c9d906aff
github-commit-libbpf-ffd4015f3b6e
github-facebookincubator-katran-149
stackoverflow-48267671
stackoverflow-60383861
stackoverflow-62936008
stackoverflow-71351495'''.splitlines()
print('rows', len(rows))
print('unique', len(set(ids)))
print('missing', sorted(set(assigned) - set(ids)))
print('extra', sorted(set(ids) - set(assigned)))
print('classifications', sorted(set(r[2].strip('`') for r in rows)))
print('replay_valid_count', sum(1 for r in rows if r[2].strip('`') == 'replay_valid'))
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-44.md --bench-root bpfix-bench
```

Review outcome: pass. `Record Results` has exactly 20 rows, all assigned IDs
appear exactly once, and there are no missing or extra IDs. Classifications are
canonical statuses accepted by `tools/integrate_reconstruction_batch.py`:
`attempted_accepted`, `environment_required`, `missing_source`, and
`out_of_scope_non_verifier`. No `replay_valid` rows exist, so no
`make clean && make && make replay-verify` rerun was required. The StackOverflow
and GitHub issue rows explain why they are not admitted: missing source,
environment dependence, or accepted local probes. Dry-run integration completed
with `rows: 20`, `admitted: []`, `missing_raw: []`, and `errors: []`.

Safe to integrate: yes.
