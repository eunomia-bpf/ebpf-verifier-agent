# Verifier Runtime Test Report

Run date: 2026-03-11

## Environment

- Kernel: `6.15.11-061511-generic`
- User: `yunwei37` (`sudo -n` available; unprivileged BPF is disabled via `kernel.unprivileged_bpf_disabled = 2`)
- Clang: `/usr/bin/clang`, Ubuntu clang `18.1.3`
- Kernel headers: `/usr/include/linux/bpf.h` present
- bpftool: `v7.7.0`, using libbpf `v1.7`
- Debian libbpf packages: `libbpf-dev 1:1.3.0-2build2`, `libbpf1 1:1.3.0-2build2`, `libbpfcc 0.29.1+ds-1ubuntu7`
- BPF FS: mounted at `/sys/fs/bpf`

## Method

- For `eval_commits`, I did not compile the truncated YAML snippets directly. Instead, for each sampled case I extracted the actual upstream file at `commit^` (buggy) and `commit` (fixed), compiled it with `clang -target bpf`, and loaded it with `sudo -n bpftool -d prog loadall ...` to capture verifier logs.
- The sampled `eval_commits` cases all came from BCC `libbpf-tools`, because they were the cleanest standalone C targets on this machine.
- When those historical buggy revisions did not fail on kernel `6.15`, I fell back to Linux kernel selftests negative programs to confirm that the local verifier path does produce real rejection logs with expected messages.

## Eval Commits

Sampled cases:

| Case | File | Buggy compile | Buggy load failed? | Fixed compile | Fixed load passed? | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `eval-bcc-02daf8d84ecd` | `libbpf-tools/biosnoop.bpf.c` | yes | no | yes | yes | Both revisions loaded successfully on this kernel. |
| `eval-bcc-118bf168f9f6` | `libbpf-tools/tcpconnect.bpf.c` | yes | no | yes | yes | Historical loop-bound issue did not reproduce on kernel `6.15`. |
| `eval-bcc-a75f0180b714` | `libbpf-tools/tcprtt.bpf.c` | yes | no | yes | yes | Direct `inet_sock` field reads were accepted on this host/kernel combo. |
| `eval-bcc-d4e505c1e4ed` | `libbpf-tools/bitesize.bpf.c` | yes | no | yes | yes | Potential out-of-bounds verifier concern did not reproduce. |
| `eval-bcc-0ae562c8862f` | `libbpf-tools/ksnoop.bpf.c` | yes | no | yes | yes | Both revisions loaded; no invalid map-value rejection on this kernel. |
| `eval-bcc-03f9322cc688` | `libbpf-tools/tcpstates.c` | no | n/a | no | n/a | Not directly runtime-testable as sampled: this case points at userspace `tcpstates.c`, not a standalone `.bpf.c` object. |

Representative buggy load observations:

- `eval-bcc-118bf168f9f6`: buggy object loaded successfully; verifier finished with `processed 85 insns` and pinned four programs.
- `eval-bcc-a75f0180b714`: buggy object loaded successfully; verifier finished with `processed 405 insns`.
- `eval-bcc-0ae562c8862f`: buggy object loaded successfully; verifier finished with `processed 8125 insns`.

Conclusion for sampled `eval_commits`:

- The machine can compile and load real BPF objects extracted from the `eval_commits` corpus.
- The sampled historical buggy revisions did **not** fail the verifier on this modern kernel, so they are not reliable runtime-negative cases on this host.
- This is consistent with many of these commits being older verifier-compatibility fixes for specific kernel/compiler combinations rather than timeless negative tests.

## Kernel Selftests Fallback

To verify that the local verifier can still emit real rejection logs, I sparse-cloned Linux selftests into `/tmp/ebpf-eval-repos/linux` at commit `80234b5` and compiled a few negative-test programs directly against `/sys/kernel/btf/vmlinux`.

| Program | Compile | Load failed? | Expected message found? | Verifier result |
| --- | --- | --- | --- | --- |
| `async_stack_depth.c` / `pseudo_call_check` | yes | yes | yes | `combined stack size of 2 calls is 544. Too large` |
| `cpumask_failure.c` / `test_alloc_no_release` | yes | yes | yes | `Unreleased reference id=2 alloc_insn=0` |
| `cgrp_kfunc_failure.c` / `cgrp_kfunc_acquire_untrusted` | yes | yes | yes | `Possibly NULL pointer passed to trusted arg0` |
| `dynptr_fail.c` / `ringbuf_missing_release1` | no | n/a | no | Blocked at compile time: missing `bpf_kfuncs.h` in the sparse checkout used for this quick test. |

Representative verifier log excerpts:

- `async_stack_depth.c`: `combined stack size of 2 calls is 544. Too large`
- `cpumask_failure.c`: `Unreleased reference id=2 alloc_insn=0`
- `cgrp_kfunc_failure.c`: `Possibly NULL pointer passed to trusted arg0`

## Takeaways

- Yes, this machine can run the BPF verifier and capture real verbose rejection logs.
- No, sampled `eval_commits` buggy revisions are not dependable runtime-negative tests on this host; all five compileable sampled buggy revisions loaded successfully on kernel `6.15.11`.
- Kernel selftests are the best immediate source of reproducible local verifier failures here.
- If we want runtime-negative `eval_commits`, we likely need one of:
  - older kernel VMs/containers matched to the original commit era;
  - commit-specific compiler/toolchain pinning;
  - manual minimization of each historical bug into a stable standalone reproducer.
