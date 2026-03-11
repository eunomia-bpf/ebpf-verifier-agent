# Cross-Kernel Stability Feasibility Report

Date: 2026-03-11

## Bottom line

The experiment is **partially feasible now** and **not yet feasible end-to-end** for the requested `5.15 / 6.1 / 6.6 / 6.15` matrix on this machine.

- What works now:
  - host-side compile/load/log-capture for `kernel_selftests` cases on the current kernel
  - OBLIGE diagnosis over captured logs
  - offline comparison on existing multi-log GitHub/Stack Overflow cases
- What is missing:
  - runnable `5.15`, `6.1`, and `6.6` kernels
  - matching per-kernel source/BTF assets
  - an execution layer that can load the same `.bpf.o` inside multiple kernel environments

The right execution vehicle is **QEMU/KVM VMs**, not Docker. Docker can isolate userspace, but it still shares the host kernel and therefore cannot give a real cross-kernel verifier comparison.

## What is available on this machine

### Current runtime

- Running kernel: `6.15.11-061511-generic`
- Tooling present: `docker 28.2.2`, `clang 18.1.3`, `bpftool v7.7.0`, `qemu-system-x86_64 8.2.2`
- Privileged BPF load path works on the host:
  - `sudo -n true` succeeds
  - `/sys/kernel/btf/vmlinux` is present
  - `/dev/kvm` is present
  - `kernel.unprivileged_bpf_disabled = 2`

### Kernel assets

- `/tmp/ebpf-eval-repos/` contains exactly one kernel source tree:
  - `/tmp/ebpf-eval-repos/linux`
- That tree is a **shallow blobless checkout** pinned at tag `v6.15`
  - `git rev-parse --is-shallow-repository` → `true`
  - `git rev-list --count HEAD` → `1`
  - tags present locally: `v6.15`
  - tags missing locally: `v5.15`, `v6.1`, `v6.6`

### Docker

- Docker daemon is reachable, but `docker images` shows no images corresponding to `5.15`, `6.1`, `6.6`, or `6.15`.
- Even if such images existed, they would still use the host kernel, so they would not solve the verifier-version problem.

### Local bootable kernels

- Installed kernel images under `/boot` and `/lib/modules` include `6.8`, `6.11`, `6.13`, `6.14`, `6.15`.
- They do **not** include the requested `5.15`, `6.1`, or `6.6`.
- There is no repo-integrated reboot/orchestration flow to select among installed kernels and rerun the experiment automatically.

### VM-related assets

- QEMU/KVM is available on the host.
- `virsh` is not usable in the current session.
- There is a separate local workspace at `/home/yunwei37/workspace/multikernel/` with:
  - QEMU launch scripts
  - a disk image and initramfs
  - a built kernel image `6.19.0-rc5`
- This proves that VM-based execution is plausible on this machine, but it is **not wired into OBLIGE** and it does **not** provide the target kernels `5.15`, `6.1`, `6.6`, `6.15`.

## What already works in the repo

The repo already has a usable single-kernel selftest runtime path.

- `case_study/capture_kernel_selftests_verifier_logs.py`
  - compiles selftest programs
  - builds a loader helper
  - loads one target program at a time with verifier log level 2
  - captures the verbose verifier log
- `case_study/selftest_prog_loader.c`
  - opens a `.bpf.o`
  - enables a large verifier log buffer
  - calls `bpf_object__load()`
  - prints JSON with `load_ok`, `error_message`, and `verifier_log`
- `eval/pretty_verifier_comparison.py`
  - already contains the OBLIGE-side diagnosis logic needed after log capture

I also ran a smoke test on the current host using:

- case: `kernel-selftest-irq-irq-restore-missing-3-tc-4022925c`
- kernel: host `6.15.11`

Result:

- compile succeeded
- load failed as expected
- non-empty verifier log was captured
- end-to-end runtime took about `0.7s`

So the single-kernel path is real. The blocker is the multi-kernel execution layer, not the log parser.

## Cases that already show cross-environment drift

These are useful because they already contain multiple verifier-log blocks or explicit kernel-version references in the corpus.

### Existing multi-log examples

| Case | Evidence already in corpus | Why useful |
| --- | --- | --- |
| `github-cilium-cilium-37478` | 5 verifier-log blocks; raw error line varies (`R1` vs `R3 invalid mem access 'map_value_or_null'`) | Good example where raw wording/register naming changes while OBLIGE still maps to one error family |
| `github-cilium-cilium-36936` | 4 verifier-log blocks; 3 distinct raw error lines | Similar multi-log drift case with stable OBLIGE `error_id` |
| `github-cilium-cilium-41996` | explicit kernel refs `4.18.0-553...`, `5.15.0-67`, fix note says upgrade to `6.8.x` | Strong motivation/example for kernel-sensitive verifier behavior |
| `stackoverflow-75515263` | 2 verifier logs from the same question; kernel shown as `5.10.0-20-arm64` / `5.10.158-2` | Good structured-diagnosis stability case for map-value bounds/layout errors |
| `stackoverflow-69413427` | 3 log variants; raw line changes from `R2 type=inv` to `R2 type=ptr_` | Nice example of message drift with the same underlying type-mismatch diagnosis |
| `github-aya-rs-aya-1233` | 2 log blocks with very different surface text | Good case where raw logs are noisy but OBLIGE still stabilizes the classification |

### Version-referenced eval cases

The `eval_commits` bucket also contains explicit kernel-version references in commit messages. Representative examples:

| Case | Commit message signal |
| --- | --- |
| `eval-bcc-89c7f409b4a6` | “fix verification failures on `5.15` kernel” |
| `eval-cilium-0279a19a34bd` | “Fix `4.19` complexity issue” |
| `eval-cilium-d7c5c0c7062f` | “Copy map value to stack on `<4.18` kernels” |
| `eval-cilium-ff54dbd703b6` | “Fix `4.19.57` verifier complaint” |

These are good **legacy-version candidate sources**, but they are weaker runtime choices on the current machine because historical buggy revisions do not reliably reproduce as negative tests on the present host kernel.

## Recommended runnable cohort for a real experiment

The cleanest starting point is a **newer-6.x selftest cohort**. These cases are already structured, have canonical expected messages, and compile/load cleanly through the existing harness.

Recommended initial cohort:

| Case ID | Family | Expected failure shape | Recommended first matrix |
| --- | --- | --- | --- |
| `kernel-selftest-iters-iter-destroy-bad-arg-raw-tp-0045e2f2` | iterator API misuse | `arg#0 expected pointer to an iterator on stack` | `6.6`, `6.15` |
| `kernel-selftest-iters-iter-err-too-permissive2-raw-tp-177534f5` | iterator nullability / memory access | `invalid mem access 'map_value_or_null'` | `6.6`, `6.15` |
| `kernel-selftest-iters-looping-wrong-sized-read-fail-raw-tp-b975c554` | bounds / read size | `invalid access to memory ... size=8` | `6.6`, `6.15` |
| `kernel-selftest-iters-state-safety-create-and-forget-to-destroy-fail-raw-tp-074de205` | reference leak | `Unreleased reference` | `6.6`, `6.15` |
| `kernel-selftest-irq-irq-restore-missing-3-tc-4022925c` | irq-region exit discipline | `BPF_EXIT instruction ... cannot be used inside ... region` | `6.15` now, then `6.6` |
| `kernel-selftest-irq-irq-restore-bad-arg-tc-28a1cb48` | bad irq flag pointer | `arg#0 doesn't point to an irq flag on stack` | `6.15` now, then `6.6` |
| `kernel-selftest-irq-irq-ooo-refs-array-tc-193001a6` | out-of-order irq restore | `cannot restore irq state out of order` | `6.15` now, then `6.6` |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | dynptr offset misuse | `cannot pass in dynptr at an offset` | `6.15` now, then `6.6` |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | dynptr type mismatch | `arg#0 expected pointer to stack or const struct bpf_dynptr` | `6.15` now, then `6.6` |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-null-tp-btf-cgroup-mkdir-2a562fb3` | trusted-null check | `Possibly NULL pointer passed to trusted arg0` | `6.15` now, then `6.6` |
| `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unreleased-tp-btf-cgroup-mkdir-0f46d712` | kfunc ref leak | `Unreleased reference` | `6.15` now, then `6.6` |
| `kernel-selftest-cpumask-failure-test-cpumask-null-tp-btf-task-newtask-40fa612f` | trusted kfunc arg nullness | `NULL pointer passed to trusted arg0` | `6.15` now, then `6.6` |

Important caveat:

- This cohort is **not** a good `5.15` cohort. Many of these features are too new or too tied to newer selftests.
- For `5.15`, use a separate legacy cohort derived from GitHub / Stack Overflow / `eval_commits` cases.

## Recommended experiment design

### Phase A: newer-6.x executable study

Use the 12 selftest cases above.

- Kernels: start with `6.6` and `6.15`
- For each case:
  - compile the same program against each kernel runtime
  - capture the verbose verifier log
  - run OBLIGE diagnosis
- Metrics:
  - pairwise Jaccard similarity of raw error-line tokens
  - exact-match of OBLIGE `error_id`
  - exact-match of OBLIGE `taxonomy_class`
  - optional exact-match of a root-cause proxy

This phase is the fastest path to a convincing figure because the cases are already negative selftests.

### Phase B: legacy-kernel extension

Build a second cohort specifically for `5.15`, `6.1`, `6.6`, `6.15`.

- Seed from:
  - `github-cilium-cilium-41996`
  - `github-cilium-cilium-37478`
  - `stackoverflow-75515263`
  - `stackoverflow-69413427`
  - version-referenced `eval_commits` cases
- Goal:
  - use programs that do not depend on brand-new verifier features
  - make `5.15` a real participant rather than a compile/load failure bucket

## Infrastructure needed for the full matrix

To make the requested `5.15 / 6.1 / 6.6 / 6.15` experiment real, we need:

1. One runnable environment per kernel

- best option: QEMU/KVM VMs
- each VM needs:
  - the target kernel
  - modules
  - `/sys/kernel/btf/vmlinux` or an exported matching BTF file
  - a rootfs with `clang`, `bpftool`, `libbpf`, and passwordless command execution

2. Matching source/BTF assets

- one kernel source tree per version, or at least one known-good source tree plus per-kernel BTF
- current repo only has `/tmp/ebpf-eval-repos/linux` at `v6.15`

3. An execution wrapper

- something that can:
  - copy or mount the compiled `.bpf.o`
  - run the loader inside the target kernel environment
  - return JSON with `load_ok`, `error_message`, and `verifier_log`

4. A `runtime.json` descriptor per kernel

The prototype runner expects a hook like:

```json
{
  "kernel_root": "/path/to/linux-6.6",
  "vmlinux_btf": "/path/to/exports/6.6/vmlinux",
  "load_command": [
    "scripts/run_in_vm.sh",
    "--kernel",
    "6.6",
    "--object",
    "{object}",
    "--program",
    "{program}"
  ]
}
```

That command can be backed by SSH, QEMU guest exec, or any other orchestrator. The repo does not have this layer yet.

## Prototype status

I added `eval/cross_kernel_stability.py`.

What it does:

- takes a case YAML and a list of kernel labels
- compiles `kernel_selftests` cases using the existing selftest harness logic
- loads them through a pluggable per-kernel `load_command`
- captures verifier logs
- runs OBLIGE diagnosis
- emits:
  - a per-kernel comparison table
  - pairwise raw-token Jaccard
  - exact-match checks for `error_id`, `taxonomy_class`, and a root-cause proxy

What it does **not** do yet:

- boot or manage VMs
- provision kernel trees
- automatically make `5.15`, `6.1`, `6.6`, and `6.15` exist
- compile arbitrary GitHub/Stack Overflow snippets into standalone programs

## Feasibility judgment

### Feasible now

- single-kernel selftest execution on the host
- offline multi-log stability analysis on the existing corpus
- development of the comparison pipeline and tables

### Feasible with moderate additional work

- a real `6.6` vs `6.15` study using QEMU/KVM
- a publishable figure based on 10-12 negative selftests

### Not feasible on this machine today

- a full `5.15 / 6.1 / 6.6 / 6.15` runtime matrix without first building or importing those kernels and wiring VM execution

## Recommendation

Do the experiment in two steps:

1. Land the pipeline now with a **`6.6` vs `6.15` selftest cohort**.
2. Add a **legacy `5.15`/`6.1` cohort** once we have per-kernel VMs or boot entries.

That path gives a credible stability result quickly while keeping the eventual full-kernel claim honest.
