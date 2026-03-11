# Eval Commit Collection Report

Run date: 2026-03-11

## Outcome

- Collected 21 verifier-workaround commit cases into `case_study/cases/eval_commits/`.
- Extraction unit is a before/after code snippet with unified-diff context, not a full-file dump, to keep large datapath files readable.
- When the actual workaround lived in an inline BPF header, I included the adjacent `.h` snippet alongside the primary `.c`/`.rs` changes.

## Search Summary

| Repo | `git log --grep=verifier` hits | Collected cases |
| --- | ---: | ---: |
| cilium | 455 | 12 |
| aya | 36 | 8 |
| katran | 3 | 1 |

## Fix Type Distribution

| Fix type | Cases |
| --- | ---: |
| bounds_check | 4 |
| helper_switch | 1 |
| inline_hint | 3 |
| null_check | 1 |
| other | 6 |
| refactor | 5 |
| type_cast | 1 |

## Quality Assessment

- Clean before/after snippet pairs written: 21 / 21 selected commits.
- Cases using only primary `.c`/`.rs` files: 17.
- Cases that also needed inline-header snippets (`.h`) because the workaround lived there: 4.
- I preferred one canonical commit per logical fix and skipped obvious backports/cherry-picks when the diff was identical.

## Additional Source Check

- `parttimenerd/ebpf-verifier-errors` currently exposes 10 submission issues via GitHub API; 10 include both structured cause code and verifier logs.
- 10 advertise an explicit `Fix`/`Solution` section, and none provide authoritative before/after commit pairs, so I did not convert them into `eval_commits` YAMLs.
- Example structured submissions checked:
  - #11 [Submission]: Verifier complaining about pointer arithmetic on pkt_end
  - #10 [Submission]: Task comm value as BPF map key value
  - #9 [Submission]: Function used as a global variable

## Issues Encountered

- Cilium stores a meaningful share of datapath logic in inline headers, so some verifier workarounds are split across `.c` and `.h` files.
- Katran had very few small verifier-named commits with directly extractable C code; only one met the size and code-pair constraints cleanly.
- Several repos contain duplicate backports or branch copies of the same workaround; those were intentionally de-duplicated in the collected set.
