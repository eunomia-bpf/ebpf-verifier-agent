# Reconstruction Batch 22

Date: 2026-04-30

Scope:

- Assigned Batch 22 records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- One successful case directory was created:
  `bpfix-bench/cases/github-commit-bcc-118bf168f9f6/`.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Not admitted: 19

The admitted case is the BCC `tcpconnect` filter-port loop fixed by adding the
`i < MAX_PORTS` guard. A standalone C replay with the pre-fix loop produced a
fresh verifier rejection on the local `kernel-6.15.11-clang-18-log2`
environment, and `tools.replay_case.parse_verifier_log` parsed it as
`trace_rich` with both `terminal_error` and `rejected_insn_idx`.

Most non-admitted records had no captured verifier log and did not provide a
faithful standalone verifier-reject shape: the BCC perf-buffer alignment records
modify userspace event readers, several Aya records depend on Rust/loader or
historical-kernel behavior, and the BCC `http_filter` snippet could be made to
reject locally only through a packet-bounds failure that the fixed loop shape
also still triggers, so it was not admitted as a faithful reconstruction of the
commit's loop rewrite.

## Successful Replays

| case_id | command result | parsed verifier outcome |
| --- | --- | --- |
| `github-commit-bcc-118bf168f9f6` | `make clean` rc 0; `make` rc 0; `make replay-verify` rc 2 with fresh `replay-verifier.log` | `log_quality=trace_rich`; `terminal_error="invalid access to map value, value_size=36 off=36 size=2"`; `rejected_insn_idx=23` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-aya-bdb2750e66f9` | no case | `environment_required` | Raw diff only adds `#[inline(always)]` to `write_record_header()` so the verifier can keep log-buffer offsets precise; no verifier log is captured, and a faithful replay depends on Aya Rust code generation/noinline behavior rather than an isolated C source snippet. |
| `github-commit-aya-ca0c32d1076a` | no case | `environment_required` | Fixes Aya loader materialization/finalization of `.bss` maps as zero-filled data. The failure is a userspace object-loader/map-initialization condition, not a standalone `prog.c` verifier-reject source. |
| `github-commit-aya-d5e4e9270ae4` | no case | `out_of_scope_non_verifier` | Raw diff removes only an irrelevant `FIXME` comment from `Array::get()`; no verifier log or behavioral verifier-reject source is present. |
| `github-commit-aya-f6606473af43` | no case | `environment_required` | Fix changes Aya log-level storage from mutable static to immutable rodata and adds Rust integration coverage. The raw record has no verifier log; faithful reproduction requires Aya/Rust global-data code generation and loader patching, not a standalone C replay. |
| `github-commit-aya-fc69a0697274` | no case | `environment_required` | Fix changes a feature-detection probe from `BPF_SUB 8` to `BPF_ADD -8` for aarch64 Linux 5.5. The local x86_64 6.15 verifier is not the historical target, and no local verifier rejection can be faithfully captured. |
| `github-commit-bcc-03f9322cc688` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `tcpstates.c` before dereferencing because perf-buffer alignment is not guaranteed; this is not BPF verifier-load behavior. |
| `github-commit-bcc-118bf168f9f6` | admitted | `replay_valid` | Pre-fix `filter_ports_len` loop lacks the `i < MAX_PORTS` guard and locally rejects with an out-of-bounds rodata map-value access. |
| `github-commit-bcc-16508e5684b1` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `opensnoop.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-18208507666d` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `filelife.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-1d659c7f3388` | no case | `environment_required` | Fix changes BCC LLVM IR generation for `sscanf` string pointer GEP under opaque pointers. Faithful replay requires BCC's C++ code generator and LLVM-version-specific output; no verifier log or standalone source is available. |
| `github-commit-bcc-2070a2aefb0b` | no case | `environment_required` | Fix changes generated USDT argument reader code to use volatile stores and `__always_inline`. The raw record has no verifier log and requires BCC USDT code generation plus target probe metadata. |
| `github-commit-bcc-45f5df4c5942` | no case | `environment_required` | Fix removes `BPF_F_NO_PREALLOC` from many hash maps. This is map/object load compatibility rather than an isolated verifier instruction rejection with a terminal verifier error. |
| `github-commit-bcc-5a547e73d31d` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `tcptracer.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-60b0166f8ed4` | no case | `not_reconstructable_from_diff` | A local `http_filter` reconstruction rejected as `invalid access to packet, off=25 size=1`, but the fixed loop shape still rejected the same way because the snippet lacks the full historical BCC context and packet bounds; not admitted as a faithful loop-rewrite verifier case. |
| `github-commit-bcc-61230b2396f3` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `drsnoop.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-661711344d57` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `exitsnoop.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-6ab97976d8fc` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `fsslower.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-6cf0299ae5f8` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `runqslower.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-7962f1389a96` | no case | `out_of_scope_non_verifier` | Fix copies perf-buffer event data in userspace `tcplife.c` before field access; no BPF program verifier rejection is represented. |
| `github-commit-bcc-799acc7ca2c6` | no case | `out_of_scope_non_verifier` | Adds a CPU filter option to `softirqs`; no captured verifier log, and the changed BPF code is a feature guard rather than a verifier-reject fix. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg -n "<assigned-id>" bpfix-bench/raw bpfix-bench/cases docs/tmp -S
python3 - <<'PY'
# Loaded all 20 bpfix-bench/raw/gh/<assigned-id>.yaml records and summarized
# source title, commit date, fix_type, verifier-log presence, diff summary,
# buggy_code, and fixed_code.
PY
rg -n "AYA_LOG_LEVEL|level_enabled|read_volatile|log level|black_box" bpfix-bench/cases docs/tmp -S
rg -n "misaligned|alignment|unaligned|perf buffer|stack layout|read from stack|misalign" bpfix-bench/cases docs/tmp/reconstruction-batch-*.md -S
rg -n "http_filter|load_byte|payload_length|BPF_SUB|probe_read_kernel|bss|zero-filled|inline write_record_header|write_record_header" bpfix-bench/cases docs/tmp/reconstruction-batch-*.md -S
```

Temporary candidate checks:

```bash
# BCC http_filter old loop shape, adapted from the local packet parser case.
make -C /tmp/b22-http.* clean
make -C /tmp/b22-http.*
make -C /tmp/b22-http.* replay-verify
# Parsed result: trace_rich, terminal_error="invalid access to packet, off=23 size=1, R1(id=0,off=23,r=15)", rejected_insn_idx=15.

# Minimal http_filter loop reconstruction.
make -C /tmp/b22-min.* 
make -C /tmp/b22-min.* replay-verify
# Parsed result: trace_rich, terminal_error="invalid access to packet, off=25 size=1, R4(id=0,off=25,r=15)", rejected_insn_idx=6.
# The fixed-loop variant produced the same packet-bounds rejection, so this was not admitted.

# BCC tcpconnect filter_ports loop reconstruction.
make -C /tmp/b22-tcpconnect2.*
make -C /tmp/b22-tcpconnect2.* replay-verify
# Parsed result: trace_rich, terminal_error="invalid access to map value, value_size=36 off=36 size=2", rejected_insn_idx=23.
```

Admitted case validation:

```bash
cd bpfix-bench/cases/github-commit-bcc-118bf168f9f6
make clean
make
make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("replay-verifier.log")
parsed = parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"))
print(parsed)
PY
```

Observed:

```text
make clean: rc 0
make: rc 0
make replay-verify: rc 2, fresh replay-verifier.log written
terminal_error: invalid access to map value, value_size=36 off=36 size=2
rejected_insn_idx: 23
log_quality: trace_rich
```

Replay harness check:

```bash
PYTHONPATH=. python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import replay_case
case_dir = Path("bpfix-bench/cases/github-commit-bcc-118bf168f9f6")
case_data = yaml.safe_load((case_dir / "case.yaml").read_text())
r = replay_case(case_dir, case_data, timeout_sec=30)
print("build_rc", r.build.returncode, "load_rc", r.load.returncode)
print("parsed", r.parsed_log)
print("captured_len", len(r.verifier_log_captured or ""))
PY
```

Observed:

```text
build_rc 0 load_rc 2
parsed ParsedVerifierLog(terminal_error='invalid access to map value, value_size=36 off=36 size=2', rejected_insn_idx=23, log_quality='trace_rich', source='replay-verifier.log')
captured_len 74136
```

## Review

- Confirmed the Record Results table covers all 20 assigned raw IDs exactly
  once.
- Normalized Record Results classifications to statuses accepted by
  `tools/integrate_reconstruction_batch.py`.
- Confirmed only the admitted assigned directory
  `bpfix-bench/cases/github-commit-bcc-118bf168f9f6/` was added.
- Confirmed `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/raw/*.yaml` were not edited.
- Confirmed the admitted replay produces a fresh trace-rich verifier rejection
  with both `terminal_error` and `rejected_insn_idx`.
- Confirmed `case.yaml` has `source.kind=github_commit`,
  `reproducer.reconstruction=reconstructed`, and `capture.log_quality=trace_rich`.
- Post-review fix: `case.yaml` now uses
  `external_match.status=not_applicable`, and `capture.yaml` now uses
  `source_artifact.verifier_error_match=not_applicable`. The metadata blocker
  is resolved.

Review commands:

```bash
python3 - <<'PY'
# Parsed Record Results rows from docs/tmp/reconstruction-batch-22.md and
# checked row count, uniqueness, duplicate IDs, and classification values.
PY
git status --short docs/tmp/reconstruction-batch-22.md \
  bpfix-bench/cases/github-commit-bcc-118bf168f9f6 \
  bpfix-bench/manifest.yaml bpfix-bench/raw/index.yaml \
  bpfix-bench/raw/gh/github-commit-bcc-118bf168f9f6.yaml
make -C bpfix-bench/cases/github-commit-bcc-118bf168f9f6 clean
make -C bpfix-bench/cases/github-commit-bcc-118bf168f9f6
make -C bpfix-bench/cases/github-commit-bcc-118bf168f9f6 replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import parse_verifier_log
case = Path("bpfix-bench/cases/github-commit-bcc-118bf168f9f6")
case_data = yaml.safe_load((case / "case.yaml").read_text())
cap_data = yaml.safe_load((case / "capture.yaml").read_text())
parsed = parse_verifier_log((case / "replay-verifier.log").read_text(
    encoding="utf-8", errors="replace"))
print(parsed)
print(case_data["source"]["kind"])
print(case_data["reproducer"]["reconstruction"])
print(case_data["external_match"]["status"])
print(case_data["capture"]["log_quality"])
print(cap_data["source_artifact"]["verifier_error_match"])
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-22.md
```
