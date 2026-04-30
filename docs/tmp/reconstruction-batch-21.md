# Reconstruction Batch 21

Date: 2026-04-30

Scope:

- Assigned Batch 21 raw records only.
- `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, and raw YAML
  records were not edited.
- No case directories were admitted.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

Three issue records had concrete verifier logs and were attempted as standalone
C reconstructions. All three built locally, but the faithful current-kernel
replays loaded successfully instead of producing verifier rejects. Under the
strict admission rule, those tentative case directories were removed and the
records were classified as non-admitted.

## Successful Replays

None.

No assigned raw record produced a local `bpfix-bench/cases/<id>/` directory
where `make clean`, `make`, and `make replay-verify` generated a fresh
trace-rich verifier reject log with both `terminal_error` and
`rejected_insn_idx`.

## Record Results

| raw_id | result | classification | reason |
| --- | --- | --- | --- |
| `github-aya-rs-aya-407` | no case | `attempted_accepted` | The issue log reports `invalid indirect read from stack` from a 16-byte perf-event payload with only 14 initialized bytes. A faithful TC `bpf_perf_event_output` reconstruction built and loaded on the local 6.15.11 replay kernel, producing no terminal verifier error. |
| `github-aya-rs-aya-458` | no case | `attempted_accepted` | The issue log reports unchecked PerCpuArray lookup use as `R0 invalid mem access 'map_value_or_null'`. A faithful PerCpuArray write without a null check built and loaded locally because the current verifier treats this array lookup result as non-null. |
| `github-aya-rs-aya-864` | no case | `attempted_accepted` | The issue log reports `unknown func bpf_get_current_pid_tgid#14` from a TC classifier. A faithful TC helper-call reconstruction built and loaded locally on the current replay kernel, so the original failure appears tied to historical helper availability. |
| `github-cilium-cilium-41412` | no case | `environment_required` | The report depends on Cilium's `bpf/tests/builtins.o`, `/proc/sys/net/core/bpf_jit_harden=2`, and a large memmove complexity path. No standalone source snippet or isolated terminal instruction is available. |
| `github-commit-aya-05c1586202ce` | no case | `environment_required` | The commit switches pt_regs field reads to `bpf_probe_read_kernel`; replay depends on Aya's Rust lowering and kernel helper support, with no verifier log or standalone source. |
| `github-commit-aya-11c227743de9` | no case | `environment_required` | The commit changes inlining around probe-read string helpers and memory builtins for older verifier behavior. No terminal verifier log or isolated C/Rust program is present. |
| `github-commit-aya-1f3acbcfe0fb` | no case | `missing_verifier_log` | The commit adds a bounded `bpf_probe_read_user_str` wrapper, but the raw record has no verifier log and no complete failing program to replay faithfully. |
| `github-commit-aya-223e2f4ea1ef` | no case | `environment_required` | The fix is an Aya log inlining change; reproducing it requires the historical Rust/Aya codegen shape, and the raw record has no verifier terminal log. |
| `github-commit-aya-28abaece2af7` | no case | `missing_verifier_log` | The commit restores explicit log-buffer bounds in shared Aya log code, but only before/after library snippets are available, not a failing verifier log or complete eBPF source. |
| `github-commit-aya-29d539751a6d` | no case | `environment_required` | The fallback `memcpy` commit targets compiler-builtins lowering that could trip the verifier. Faithful replay requires the historical compiler lowering and no terminal log is provided. |
| `github-commit-aya-2ac433449cde` | no case | `missing_verifier_log` | The commit adds explicit log-buffer bounds and perf-output guards, but the raw record lacks a verifier log and complete failing eBPF program. |
| `github-commit-aya-2d79f22b4022` | no case | `environment_required` | The commit switches pt_regs reads from `bpf_probe_read_kernel` to older `bpf_probe_read` for pre-5.5 compatibility; this is historical-kernel helper behavior with no local standalone reject. |
| `github-commit-aya-2e0702854b0e` | no case | `missing_verifier_log` | The commit adds constant-capacity log-buffer checks, but the raw record has only library diffs and no verifier terminal message or full source. |
| `github-commit-aya-32350f81b756` | no case | `environment_required` | The commit adds a verifier-friendly `memset` fallback for old BPF backend lowering. Reproducing the failure depends on historical compiler output and no verifier log is available. |
| `github-commit-aya-3569c9afc3dc` | no case | `environment_required` | The change alters map-helper signatures and inlining across many Aya eBPF map APIs. The raw record has no terminal log and requires a large historical Aya/Rust lowering context. |
| `github-commit-aya-3cfd886dc512` | no case | `environment_required` | The commit tunes logging function inlining and integration tests; replay depends on Aya log integration codegen and no verifier log is included. |
| `github-commit-aya-42c4d5c3af90` | no case | `environment_required` | The commit adjusts casts and helper return-value handling across Aya helpers and map APIs. It lacks a verifier log and depends on historical Rust lowering. |
| `github-commit-aya-62c6dfd764ce` | no case | `environment_required` | The commit sanitizes BTF FUNC linkage to avoid BTF loading/verifier errors. The raw record has no eBPF program verifier log and replay would require crafted historical BTF object loading. |
| `github-commit-aya-88f5ac31142f` | no case | `out_of_scope_non_verifier` | The commit changes user-space ProgramInfo/MapInfo handling for older kernels, not a rejected eBPF program load. |
| `github-commit-aya-bce3c4fb1d0c` | no case | `out_of_scope_non_verifier` | The commit is a clippy/doc-comment cleanup in helper wrappers with no verifier-load failure evidence. |

## Review

No blockers. The Record Results table has exactly 20 unique assigned IDs, no
assigned case directories remain, and shared metadata files were not edited.

Normalized status changes:

- `current_kernel_accepts_reconstruction` -> `attempted_accepted` for
  `github-aya-rs-aya-407`, `github-aya-rs-aya-458`, and
  `github-aya-rs-aya-864`.
- `lacks_replay_evidence` -> `missing_verifier_log` for
  `github-commit-aya-1f3acbcfe0fb`, `github-commit-aya-28abaece2af7`,
  `github-commit-aya-2ac433449cde`, and `github-commit-aya-2e0702854b0e`.
- `non_program_btf_environment` -> `environment_required` for
  `github-commit-aya-62c6dfd764ce`.

## Commands Run

Raw-record inspection:

```bash
rg -l "id: <assigned>|raw_id: <assigned>|<assigned>" bpfix-bench/raw bpfix-bench/cases docs/tmp/reconstruction-batch-*.md
python3 - <<'PY'
# Loaded each assigned bpfix-bench/raw/gh/<id>.yaml and printed source kind,
# title/commit message, content/reproduction metadata, diff summaries, touched
# files, issue body/fix summaries, and verifier-log tails where present.
PY
```

Attempted local replay candidates:

```bash
make -C bpfix-bench/cases/github-aya-rs-aya-407 clean
make -C bpfix-bench/cases/github-aya-rs-aya-407
make -C bpfix-bench/cases/github-aya-rs-aya-407 replay-verify

make -C bpfix-bench/cases/github-aya-rs-aya-458 clean
make -C bpfix-bench/cases/github-aya-rs-aya-458
make -C bpfix-bench/cases/github-aya-rs-aya-458 replay-verify

make -C bpfix-bench/cases/github-aya-rs-aya-864 clean
make -C bpfix-bench/cases/github-aya-rs-aya-864
make -C bpfix-bench/cases/github-aya-rs-aya-864 replay-verify
```

Cleanup after failed admission:

```bash
rm -f bpfix-bench/cases/github-aya-rs-aya-407/prog.o bpfix-bench/cases/github-aya-rs-aya-407/replay-verifier.log
rm -f bpfix-bench/cases/github-aya-rs-aya-458/prog.o bpfix-bench/cases/github-aya-rs-aya-458/replay-verifier.log
rm -f bpfix-bench/cases/github-aya-rs-aya-864/prog.o bpfix-bench/cases/github-aya-rs-aya-864/replay-verifier.log
rmdir bpfix-bench/cases/github-aya-rs-aya-407 bpfix-bench/cases/github-aya-rs-aya-458 bpfix-bench/cases/github-aya-rs-aya-864
```

## Parsed Verifier Outcomes

No admitted replay logs exist for this batch.

For the three attempted candidates, `make` succeeded and `make replay-verify`
also exited `0` because `bpftool` loaded the reconstructed programs
successfully. The generated load logs contained normal `processed ... insns`
summaries and no terminal verifier error, so `tools.replay_case.parse_verifier_log`
would classify them as `no_terminal_error` with `terminal_error=None` and
`rejected_insn_idx` unavailable. They were therefore not admitted.

Observed attempted replay outcomes:

```text
github-aya-rs-aya-407: build=success load=accepted parser_quality=no_terminal_error terminal=None rejected_insn_idx=None
github-aya-rs-aya-458: build=success load=accepted parser_quality=no_terminal_error terminal=None rejected_insn_idx=None
github-aya-rs-aya-864: build=success load=accepted parser_quality=no_terminal_error terminal=None rejected_insn_idx=None
```
