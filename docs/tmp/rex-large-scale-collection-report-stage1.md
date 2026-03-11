# Eval Large-Scale Collection Report

Run date: 2026-03-11

## Outcome

- New YAML cases written this run: 56.
- Total `eval_commits` YAML cases now present: 560.
- Target status: not met for the requested floor of 100 new cases.

## Per-Repo Search Summary

| Repo | Commits searched | Candidates found | Cases collected | Already present | Duplicates skipped | Too large skipped | Weak-match skipped | Git failures skipped |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cilium | 1086 | 284 | 24 | 260 | 37 | 23 | 610 | 0 |
| aya | 63 | 13 | 2 | 11 | 0 | 1 | 45 | 0 |
| bcc | 427 | 8 | 8 | 0 | 0 | 0 | 323 | 62 |
| libbpf | 417 | 94 | 22 | 72 | 0 | 6 | 316 | 0 |

## Fix Type Distribution

| Fix type | Cases |
| --- | ---: |
| alignment | 19 |
| attribute_annotation | 10 |
| bounds_check | 48 |
| helper_switch | 19 |
| inline_hint | 225 |
| loop_rewrite | 64 |
| null_check | 20 |
| other | 85 |
| refactor | 16 |
| type_cast | 38 |
| volatile_hack | 16 |

## Top Repos By Contribution

| Repo | Total cases in corpus |
| --- | ---: |
| cilium | 370 |
| libbpf | 147 |
| aya | 26 |
| bcc | 8 |

## Notable Patterns

- Most common workaround classes in the collected corpus: inline_hint (225), other (85), loop_rewrite (64), bounds_check (48), type_cast (38).
- Compact verifier workarounds cluster around explicit bounds proofs, helper compatibility for older kernels, stack/alignment fixes, and control-flow reshaping.
- Modern eBPF projects still carry verifier-compatibility patches outside pure `.bpf.c` code, especially in generated headers, helper wrappers, and loader-side compatibility probes.
- Older-kernel support remains a major source of workaround commits, especially in BCC, bpftrace, Calico, Tracee, and Tetragon.

## Notes

- Complexity filter: skipped commits whose relevant code diff exceeded 200 changed lines.
- Snippets were extracted from actual git blob versions (`commit^:path` and `commit:path`) and trimmed to the touched sections with diff context.
- Obvious duplicate backports and cherry-picks were de-duplicated using a patch fingerprint over the relevant code diff.
