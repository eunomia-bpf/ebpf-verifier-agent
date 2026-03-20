# Kernel Selftest Verification

Run date: 2026-03-20

## Scope

- Intentional negative benchmark cases processed: 85
- Kernel source root: `/tmp/linux-selftests`
- Output root: `/home/yunwei37/workspace/ebpf-verifier-agent/case_study/cases/kernel_selftests_verified`
- Each case directory contains a reduced single-case `prog.c`, copied local headers, a `Makefile`, and per-case verification status.
- `vmlinux.h` was sanitized to drop `__ksym` declarations that conflict with selftest helper headers on this host kernel.
- Verifier checks were executed with a small libbpf loader that selects the target program by function name; this avoids `bpftool prog load` ambiguity for multi-function selftest objects.

## Results

- Source files found: 85 / 85
- Reduced sources with exactly one retained SEC program: 85 / 85
- Compiled successfully: 85 / 85
- Rejected by verifier as expected: 85 / 85
- Captured logs matching all expected message strings: 77 / 85
- Captured logs matching the YAML diagnostic tail: 75 / 85
- Exact normalized full-log matches: 0 / 85

## Matching Rule

- Primary `matching verifier logs` count above uses the YAML diagnostic tail: the last 1-3 non-trace diagnostic lines from the benchmark YAML must appear in the captured verifier log.
- Exact full-log match is reported separately because verifier traces contain unstable addresses and kernel-version-specific detail.

## Common Compilation Issues

- None in this run.

## Cases With Problems

- None.

## Timing

- Started: 2026-03-20T00:37:09.475867+00:00
- Finished: 2026-03-20T00:37:27.193425+00:00
- Duration seconds: 17.7

