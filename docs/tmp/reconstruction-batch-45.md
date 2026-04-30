# Reconstruction Batch 45

Date: 2026-04-29 (America/Vancouver)

Scope:

- Assigned Batch 45 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any raw YAML file.
- No assigned case was admitted; no `bpfix-bench/cases/<assigned-raw-id>/`
  directory remains.

## Summary

- Assigned records inspected: 6
- Local raw records present: 6
- Raw records with non-empty captured verifier text: 5
- Local reconstruction attempts: 3
- Successful admitted replays: 0
- Not admitted: 6

No assigned record was admitted. Three source-shaped records were tested locally
in scratch directories. `stackoverflow-71529801` and `stackoverflow-79513583`
compiled but the local verifier accepted the reconstructed programs. The exact
`stackoverflow-77225068` snippet also loaded successfully on this kernel; its
verbose log contains a parser-recognized diagnostic line, but `bpftool` returned
success and pinned the program, so it is not a fresh verifier reject. The
remaining records lack standalone source, a parser-usable verifier trace, or both.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `stackoverflow-71529801` | no case | `attempted_accepted` | Raw log is trace-rich (`invalid indirect read from stack R3 off -32+10 size 16`, rejected insn 84), and the answer identifies uninitialized `struct client_port_addr val.pad`. A local reconstruction using the reported structs, partial `val.client_ip`/`val.dmac` initialization, and `bpf_map_update_elem()` built successfully, but replay did not reject: the log ended with `processed 17 insns` and no terminal verifier error, followed only by a pin failure. |
| `stackoverflow-77225068` | no case | `attempted_accepted` | Raw includes the full `bpf_printk("Hello World %d", counter)` XDP snippet and a message-only raw parser result (`reg type unsupported for arg#0 function hello#4`, no rejected instruction). The exact snippet built locally with the distro arch include path. `make replay-verify` returned success and `bpftool prog show pinned /sys/fs/bpf/stackoverflow-77225068` showed a loaded XDP program; the pin was removed. Because the local load succeeded, the parser-recognized `arg#0 reference type('UNKNOWN ') size cannot be determined: -22` line in the verbose log is not admissible as a fresh verifier reject. |
| `stackoverflow-78373013` | no case | `missing_source` | Raw has a verifier-shaped failure (`jump out of range from insn 38 to 148`) but parser quality is `message_only` with no rejected instruction. The post provides a BCC C fragment derived from `filetop.py` and says the actual code is elsewhere, but the raw record has no standalone source, BCC Python loader, or complete reconstruction inputs for the `dentry_path_raw()` call site. |
| `stackoverflow-78753911` | no case | `missing_source` | Raw has only a bounded-loop snippet plus a short disassembly window. The verifier block says `The sequence of 8193 jumps is too complex` but parser quality is `no_terminal_error` with no rejected instruction. Required program context, map/argument definitions, constants, and surrounding control flow are absent. |
| `stackoverflow-79513583` | no case | `attempted_accepted` | Raw includes full BPF snippet plus `demo.h` and reports `BPF_STX uses reserved fields`, but parser quality is `no_terminal_error`. The local reconstruction built and replayed; clang 18 generated `atomic64_fetch_add`, the verifier log marked the path `safe`, ended with `processed 27 insns`, and had no terminal verifier error. It was not a fresh reject on kernel 6.15. |
| `stackoverflow-79817058` | no case | `missing_verifier_log` | Raw metadata says `has_verifier_log=true`, but `verifier_log.blocks` is empty, `combined` is empty, and parser quality is `empty`. The snippets are partial userspace/LSM/string-search fragments, so there is no captured terminal verifier error or rejected instruction to validate a replay. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files | rg '(^docs/tmp/reconstruction|bpfix-bench/(cases|raw|manifest)|tools/replay_case|README|Makefile)'
git status --short
for id in stackoverflow-71529801 stackoverflow-77225068 stackoverflow-78373013 stackoverflow-78753911 stackoverflow-79513583 stackoverflow-79817058; do
  rg --files bpfix-bench/raw | rg "$id"
done
for id in stackoverflow-71529801 stackoverflow-77225068 stackoverflow-78373013 stackoverflow-78753911 stackoverflow-79513583 stackoverflow-79817058; do
  test -d bpfix-bench/cases/$id && printf '%s case_dir exists\n' "$id" || printf '%s no_case_dir\n' "$id"
done
```

Raw inspection and parser checks:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/so") / f"{id}.yaml").read_text())
    log = (d["raw"].get("verifier_log") or {}).get("combined") or ""
    print(id, d["content"], parse_verifier_log(log, source="raw verifier_log"))
PY
```

Local scratch replay attempts:

```bash
# stackoverflow-71529801: reconstructed reported uninitialized map-update value in /tmp
make -C /tmp/bpfix-71529801.8Gv7Ux clean
make -C /tmp/bpfix-71529801.8Gv7Ux
make -C /tmp/bpfix-71529801.8Gv7Ux replay-verify

# stackoverflow-77225068: exact snippet, with arch include path needed for <linux/bpf.h>
make -C /tmp/bpfix-77225068.kAx7nU clean
make -C /tmp/bpfix-77225068.kAx7nU CFLAGS='-target bpf -O2 -g -I /usr/include -I /usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86'
make -C /tmp/bpfix-77225068.kAx7nU CFLAGS='-target bpf -O2 -g -I /usr/include -I /usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86' replay-verify

# stackoverflow-79513583: exact BPF snippet plus demo.h in /tmp
make -C /tmp/bpfix-79513583.7PXU2q clean
make -C /tmp/bpfix-79513583.7PXU2q
make -C /tmp/bpfix-79513583.7PXU2q replay-verify
```

Cleanup for the unadmitted `stackoverflow-77225068` case attempt:

```bash
sudo rm -f /sys/fs/bpf/stackoverflow-77225068
make clean
rmdir bpfix-bench/cases/stackoverflow-77225068 2>/dev/null || true
```

Report validation:

```bash
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-45.md --bench-root bpfix-bench
git status --short -- docs/tmp/reconstruction-batch-45.md bpfix-bench/cases/stackoverflow-77225068
```

## Parsed Verifier Outcomes

| Raw ID | Source | Build/load result | Parser outcome |
| --- | --- | --- | --- |
| `stackoverflow-71529801` | raw `verifier_log` | raw only | `trace_rich`, terminal `invalid indirect read from stack R3 off -32+10 size 16`, rejected insn 84 |
| `stackoverflow-71529801` | local scratch replay | build succeeded; verifier accepted; pin failed | `no_terminal_error`, no terminal error, rejected insn 17 from final instruction scan only |
| `stackoverflow-77225068` | raw `verifier_log` | raw only | `message_only`, terminal `reg type unsupported for arg#0 function hello#4`, no rejected instruction |
| `stackoverflow-77225068` | local scratch replay | build succeeded; `bpftool` returned success and pinned program | parser saw `trace_rich`, terminal `arg#0 reference type('UNKNOWN ') size cannot be determined: -22`, rejected insn 11, but this was not a reject because load status was success |
| `stackoverflow-78373013` | raw `verifier_log` | raw only | `message_only`, terminal `bpf: Failed to load program: Invalid argument`, no rejected instruction |
| `stackoverflow-78753911` | raw `verifier_log` | raw only | `no_terminal_error`, no terminal error, no rejected instruction |
| `stackoverflow-79513583` | raw `verifier_log` | raw only | `no_terminal_error`, no terminal error, no rejected instruction |
| `stackoverflow-79513583` | local scratch replay | build succeeded; verifier accepted; pin failed | `no_terminal_error`, no terminal error, rejected insn 27 from final instruction scan only |
| `stackoverflow-79817058` | raw `verifier_log` | raw only | `empty`, no terminal error, no rejected instruction |

Admission validation result:

```text
admitted cases: 0
fresh verifier rejects: none
fresh terminal_error with rejected_insn_idx from an actual failed load: none
```

## Review

Review commands:

```bash
python3 - <<'PY'
from pathlib import Path
p=Path('docs/tmp/reconstruction-batch-45.md')
text=p.read_text()
section=text.split('## Record Results',1)[1].split('\n## ',1)[0]
rows=[line for line in section.splitlines() if line.startswith('| `')]
print('rows', len(rows))
ids=[]
for r in rows:
    cols=[c.strip() for c in r.strip('|').split('|')]
    ids.append(cols[0].strip('`'))
    print(cols[0], cols[2])
print('unique', len(set(ids)))
print('ids', ids)
PY
test -e /sys/fs/bpf/stackoverflow-77225068 && { echo 'PIN_EXISTS'; ls -l /sys/fs/bpf/stackoverflow-77225068; } || echo 'PIN_ABSENT'
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-45.md --bench-root bpfix-bench
```

Pass. `Record Results` has exactly 6 rows with the assigned IDs exactly once:
`stackoverflow-71529801`, `stackoverflow-77225068`,
`stackoverflow-78373013`, `stackoverflow-78753911`,
`stackoverflow-79513583`, and `stackoverflow-79817058`. All
classifications are canonical for `tools/integrate_reconstruction_batch.py`:
`attempted_accepted`, `missing_source`, and `missing_verifier_log`.

No `replay_valid` classification is present, so no fresh
`make clean && make && make replay-verify` run was required. Each
StackOverflow row explains why it is not admitted: attempted local replays were
accepted or the record lacks standalone source/verifier material. The
non-destructive stale pin check reported `PIN_ABSENT` for
`/sys/fs/bpf/stackoverflow-77225068`.

Dry-run integration passed:

```text
apply: false
rows: 6
admitted: []
missing_raw: []
skipped_index: []
errors: []
```

Outcome: safe to integrate.
