# Reconstruction Batch 23

Date: 2026-04-30

Scope:

- Assigned Batch 23 raw records only.
- Edited only this report and admitted case directories under
  `bpfix-bench/cases/<assigned raw id>/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 2
- Attempted but accepted by the local verifier: 2
- Not admitted: 18

Two records produced faithful local replayable verifier rejects on
`kernel-6.15.11-clang-18-log2`:

- `github-commit-bcc-a75f0180b714`: direct `inet_sock` field loads from a
  verifier-known `struct sock *` in an fentry program. Fresh replay rejects with
  `access beyond struct sock at off 798 size 2`.
- `github-commit-bcc-d4e505c1e4ed`: `comm_allowed()` checks
  `targ_comm[i] != '\0'` before `i < TASK_COMM_LEN`. Fresh replay rejects with
  `invalid access to map value, value_size=16 off=16 size=1`.

The remaining records either describe BCC user-space/frontend/loader changes,
historical compiler or kernel-environment behavior without a captured verifier
log, or local probes that accepted on the current kernel.

## Successful Replays

| case_id | command result | parsed verifier outcome |
| --- | --- | --- |
| `github-commit-bcc-a75f0180b714` | `make clean` 0; `make` 0; `make replay-verify` 2 (`bpftool` 255 verifier reject) | `log_quality=trace_rich`; `terminal_error="access beyond struct sock at off 798 size 2"`; `rejected_insn_idx=1` |
| `github-commit-bcc-d4e505c1e4ed` | `make clean` 0; `make` 0; `make replay-verify` 2 (`bpftool` 255 verifier reject) | `log_quality=trace_rich`; `terminal_error="invalid access to map value, value_size=16 off=16 size=1"`; `rejected_insn_idx=11` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-bcc-81a783a8f992` | no case | `out_of_scope_non_verifier` | Commit changes BCC `bpf_prog_load()` logging behavior and verifier log collection flags, not an eBPF program rejected by the verifier. No verifier log or program source is present. |
| `github-commit-bcc-8206f547b8e3` | no case | `environment_required` | USDT generated-code barrier/volatile change for LLVM optimization behavior. Raw record has no captured verifier log and no standalone generated rejected program. |
| `github-commit-bcc-82f4302a651a` | no case | `out_of_scope_non_verifier` | Introduces `lookup_or_try_init()`/rewriter support across examples and frontend code; no captured verifier log or specific failing program source. |
| `github-commit-bcc-8319d52dc883` | no case | `environment_required` | Adds `-fno-jump-tables` to BCC's x86 compile flags. This depends on historical LLVM code generation and has no captured verifier log or replayable source. |
| `github-commit-bcc-89c7f409b4a6` | no case | `attempted_accepted` | A standalone reconstruction of the ksnoop `func_stack->ips[stack_depth++]` indexing pattern built locally; the verifier log contained no terminal error, so it was not admitted. |
| `github-commit-bcc-93fad89ca457` | no case | `out_of_scope_non_verifier` | Commit is in `libbpf-tools/tcpconnect.c` user-space output/alignment code, not a verifier-rejected BPF program. |
| `github-commit-bcc-952415e490bd` | no case | `environment_required` | Biolatency change selects tracepoint layouts using BTF instead of `LINUX_KERNEL_VERSION`; raw record has no verifier log and depends on kernel tracepoint ABI availability. |
| `github-commit-bcc-a75f0180b714` | admitted | `replay_valid` | Added local fentry reproducer for direct `inet_sock` field loads; fresh verifier rejection is trace-rich and parser reports terminal error plus rejected instruction index. |
| `github-commit-bcc-ae6ed35ccf5c` | no case | `out_of_scope_non_verifier` | Commit is in `libbpf-tools/biosnoop.c` user-space formatting/alignment code, not a BPF verifier failure. |
| `github-commit-bcc-b0b4239a6c3c` | no case | `out_of_scope_non_verifier` | Commit fixes `tcptop` user-space PID column formatting/alignment for large PIDs; no BPF verifier rejection. |
| `github-commit-bcc-b0f891d129a9` | no case | `environment_required` | USDT context-register load volatility/inline generation change; no captured verifier log or faithful generated rejected program. |
| `github-commit-bcc-b9545a5ca101` | no case | `out_of_scope_non_verifier` | Adds BCC tracepoint `__data_loc` support in helpers/frontend code. Raw record has no verifier log or concrete rejected BPF source. |
| `github-commit-bcc-b9a318729754` | no case | `out_of_scope_non_verifier` | Commit is in `libbpf-tools/gethostlatency.c` user-space pointer/formatting alignment code, not verifier-facing BPF source. |
| `github-commit-bcc-c6a3f0298ebf` | no case | `out_of_scope_non_verifier` | Removes namespace code from BCC libbpf attach/probe-event handling for USDT. No verifier-rejected BPF program or verifier log is present. |
| `github-commit-bcc-d4e505c1e4ed` | admitted | `replay_valid` | Added local tracepoint reproducer for the `targ_comm[i]` before bounds-check loop condition; fresh verifier rejection is trace-rich and parser reports terminal error plus rejected instruction index. |
| `github-commit-bcc-ed827decb985` | no case | `out_of_scope_non_verifier` | Commit is in `libbpf-tools/statsnoop.c` user-space output/alignment code, not a verifier-rejected BPF program. |
| `github-commit-bcc-f09b5b8acdd5` | no case | `environment_required` | BCC compatibility header/helper version-check removal from 2016; no captured verifier log or concrete rejected program source. |
| `github-commit-bcc-f2006eaa5901` | no case | `attempted_accepted` | A standalone reconstruction of the cpufreq global-array indexing shape built and loaded locally without a verifier terminal error on kernel 6.15.11. |
| `github-commit-bcc-f6c8cfe4244a` | no case | `out_of_scope_non_verifier` | Fixes BCC-generated BTF DataSec size metadata, not a verifier-rejected program with a replayable source/log pair. |
| `github-commit-bcc-feadea6d789f` | no case | `out_of_scope_non_verifier` | Supports loading BPF programs larger than `BPF_MAXINSNS` through BCC loader changes; no specific rejected program source or local verifier reject was available. |

## Review

Review date: 2026-04-30

Verified Record Results has exactly 20 rows and no duplicate raw IDs.
Classifications were normalized to statuses accepted by
`tools/integrate_reconstruction_batch.py`.

Commands rerun for admitted cases:

```bash
cd bpfix-bench/cases/github-commit-bcc-a75f0180b714
make clean && make && make replay-verify

cd bpfix-bench/cases/github-commit-bcc-d4e505c1e4ed
make clean && make && make replay-verify
```

Both `make replay-verify` invocations exited through the expected verifier
reject path (`bpftool` error 255; make exit 2). Parser checks matched
`case.yaml`:

```text
github-commit-bcc-a75f0180b714: log_quality=trace_rich; terminal_error="access beyond struct sock at off 798 size 2"; rejected_insn_idx=1
github-commit-bcc-d4e505c1e4ed: log_quality=trace_rich; terminal_error="invalid access to map value, value_size=16 off=16 size=1"; rejected_insn_idx=11
```

Metadata inspection confirmed both admitted cases have
`source.kind=github_commit`, `reproducer.reconstruction=reconstructed`,
`capture.log_quality=trace_rich`, and no fixed-version requirement.

Post-review fix: both admitted `case.yaml` files now use
`external_match.status=not_applicable`, and both `capture.yaml` files now use
`source_artifact.verifier_error_match=not_applicable`. The metadata blocker is
resolved:

```text
bpfix-bench/cases/github-commit-bcc-a75f0180b714/case.yaml:34
bpfix-bench/cases/github-commit-bcc-d4e505c1e4ed/case.yaml:34
```

## Commands Run

Context and raw inspection:

```bash
git status --short
rg -l "<assigned-id>" bpfix-bench/raw
python3 - <<'PY'
# loaded each assigned bpfix-bench/raw/gh/<id>.yaml and printed title,
# content flags, reproduction status, fix_type, and diff summary
PY
sed -n '1,220p' docs/tmp/reconstruction-batch-20.md
sed -n '1,140p' bpfix-bench/cases/github-commit-bcc-02daf8d84ecd/{Makefile,prog.c,case.yaml,capture.yaml}
```

Temporary local probes:

```bash
# a75 direct inet_sock field access probe in /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes clean
make -C /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes replay-verify
python3 - <<'PY'
from tools.replay_case import parse_verifier_log
PY

# f200 cpufreq global-array indexing probe in /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes clean
make -C /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes replay-verify

# d4 comm_allowed loop-condition probe in /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes clean
make -C /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes replay-verify

# 89 ksnoop stack-depth/indexing probe in /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes clean
make -C /tmp/bpfix-b23-probes
make -C /tmp/bpfix-b23-probes replay-verify
```

Admitted case validation:

```bash
cd bpfix-bench/cases/github-commit-bcc-a75f0180b714
make clean
make
make replay-verify

cd bpfix-bench/cases/github-commit-bcc-d4e505c1e4ed
make clean
make
make replay-verify

python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
for rid in ["github-commit-bcc-a75f0180b714", "github-commit-bcc-d4e505c1e4ed"]:
    p = Path("bpfix-bench/cases") / rid / "replay-verifier.log"
    print(rid, parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
PY
```

Parser results:

```text
github-commit-bcc-a75f0180b714 ParsedVerifierLog(terminal_error='access beyond struct sock at off 798 size 2', rejected_insn_idx=1, log_quality='trace_rich', source='bpfix-bench/cases/github-commit-bcc-a75f0180b714/replay-verifier.log')
github-commit-bcc-d4e505c1e4ed ParsedVerifierLog(terminal_error='invalid access to map value, value_size=16 off=16 size=1', rejected_insn_idx=11, log_quality='trace_rich', source='bpfix-bench/cases/github-commit-bcc-d4e505c1e4ed/replay-verifier.log')
```
