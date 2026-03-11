# GitHub Issues Benchmark Collection Report

Run date: 2026-03-11

Command executed:

```bash
python3 benchmark/collect_github_issues.py --output-dir benchmark/cases/github_issues --max-issues 100 --verbose
```

## Outcome

- Output directory: `benchmark/cases/github_issues`
- Candidate issues fetched from GitHub search: 84
- Cases written: 26
- Index written: `benchmark/cases/github_issues/index.yaml`

## Cases Per Project

| Project | Repository | Cases |
| --- | --- | ---: |
| cilium | `cilium/cilium` | 7 |
| aya | `aya-rs/aya` | 18 |
| katran | `facebookincubator/katran` | 1 |

## Representative Interesting Cases

- `cilium/cilium#44216`
  - Title: `Cilium breaks the cluster on 6.18.5-talos because of regressin in kernel/bpf/verifier.c`
  - Why it stands out: the verifier log shows a kernel-side `REG INVARIANTS VIOLATION` in `kernel/bpf/verifier.c`, so this looks like a genuine upstream verifier regression rather than just an application bug.
  - Collected fix summary: Cilium maintainers note the warning is a known upstream issue, likely reported by syzkaller before, and that both a long-term fix and possibly a short-term mitigation are needed.

- `cilium/cilium#37478`
  - Title: `Verifier error: program tail_handle_snat_fwd_ipv4 ... R1 invalid mem access 'map_value_or_null'`
  - Why it stands out: it contains multiple dense verifier traces, including `map_value_or_null` access failures in a real datapath program, which makes it useful for benchmark cases involving pointer/null-state reasoning.
  - Collected fix summary: maintainer guidance points to kernel-version sensitivity and recommends retrying on a newer Cilium patch release before deeper diagnosis.

- `aya-rs/aya#1324`
  - Title: `Bad file descriptor only when EbpfLogger::init is called`
  - Why it stands out: it ties a verifier-facing `fd ... is not pointing to valid bpf_map` load failure to Aya logger lifecycle misuse in user space, with multiple source snippets preserved.
  - Collected fix summary: the returned logger was being dropped instead of consumed, which likely invalidated the expected logging setup.

- `aya-rs/aya#1062`
  - Title: `uretprobe latest aya version cannot pass anymore ctx.ret().unwrap to bpf_probe_read`
  - Why it stands out: it captures a subtle verifier failure where a dynamic return value passed into `bpf_probe_read_user` becomes invalid unless sanitized, and it preserves several minimal reproducer snippets.
  - Collected fix summary: avoid `unwrap`/panic-style handling in eBPF code and handle the return value explicitly.

- `facebookincubator/katran#149`
  - Title: `Load balancer_kern.o error：Prog section 'xdp-balancer' rejected: Permission denied (13)!`
  - Why it stands out: it is the only retained Katran case and combines BTF rejection on an older 4.18 kernel with a verifier failure (`R1 type=inv expected=map_ptr`).
  - Collected fix summary: none extracted.

## Issues Encountered

- The requested CLI invocation used `--verbose`, but `benchmark/collect_github_issues.py` did not accept that flag. I patched the script to accept `--verbose` as a compatibility flag.
- `GITHUB_TOKEN` was not set in the environment, so the collection used the unauthenticated GitHub API.
- To keep the unauthenticated run practical, I patched the collector to reuse the GitHub search payload as the issue body/metadata source, only fetch comments after an issue already shows verifier signals, and degrade cleanly if comment fetches later hit the core rate limit.
- No hard API failure occurred during the final run, but the search space only yielded 84 candidates and 26 retained verifier-signal cases, so the run finished well below `--max-issues 100`.
