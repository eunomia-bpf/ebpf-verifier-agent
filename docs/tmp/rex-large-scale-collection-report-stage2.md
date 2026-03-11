# Eval Large-Scale Collection Report

Run date: 2026-03-11

## Outcome

- New YAML cases written this run: 1.
- Total `eval_commits` YAML cases now present: 504.
- Target status: not met for the requested floor of 100 new cases.

## Per-Repo Search Summary

| Repo | Commits searched | Candidates found | Cases collected | Already present | Duplicates skipped | Too large skipped | Weak-match skipped | Git failures skipped |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| katran | 14 | 6 | 1 | 5 | 0 | 1 | 7 | 0 |
| bpftrace | 146 | 0 | 0 | 0 | 0 | 0 | 68 | 76 |
| calico | 25 | 0 | 0 | 0 | 0 | 0 | 12 | 10 |
| falco | 68 | 0 | 0 | 0 | 0 | 0 | 29 | 39 |
| tracee | 36 | 0 | 0 | 0 | 0 | 0 | 15 | 21 |
| tetragon | 56 | 0 | 0 | 0 | 0 | 0 | 19 | 37 |

## Fix Type Distribution

| Fix type | Cases |
| --- | ---: |
| alignment | 18 |
| attribute_annotation | 8 |
| bounds_check | 42 |
| helper_switch | 18 |
| inline_hint | 216 |
| loop_rewrite | 61 |
| null_check | 20 |
| other | 58 |
| refactor | 16 |
| type_cast | 34 |
| volatile_hack | 13 |

## Top Repos By Contribution

| Repo | Total cases in corpus |
| --- | ---: |
| katran | 10 |

## Notable Patterns

- Most common workaround classes in the collected corpus: inline_hint (216), loop_rewrite (61), other (58), bounds_check (42), type_cast (34).
- Compact verifier workarounds cluster around explicit bounds proofs, helper compatibility for older kernels, stack/alignment fixes, and control-flow reshaping.
- Modern eBPF projects still carry verifier-compatibility patches outside pure `.bpf.c` code, especially in generated headers, helper wrappers, and loader-side compatibility probes.
- Older-kernel support remains a major source of workaround commits, especially in BCC, bpftrace, Calico, Tracee, and Tetragon.

## Notes

- Complexity filter: skipped commits whose relevant code diff exceeded 200 changed lines.
- Snippets were extracted from actual git blob versions (`commit^:path` and `commit:path`) and trimmed to the touched sections with diff context.
- Obvious duplicate backports and cherry-picks were de-duplicated using a patch fingerprint over the relevant code diff.
