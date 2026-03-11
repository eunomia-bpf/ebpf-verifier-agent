# Kernel Selftests Collection Report

Date: 2026-03-11

Command run:

```bash
python3 benchmark/collect_kernel_selftests.py --output-dir benchmark/cases/kernel_selftests --max-cases 200 --verbose
```

## Result

- Collected 200 case files plus `index.yaml` in `benchmark/cases/kernel_selftests`.
- Source checkout: `torvalds/linux.git` at commit `b29fb8829bff243512bb8c8908fd39406f9fd4c3`.
- All 200 collected cases were `privileged_only`.
- None of the collected 200 carried `__msg_unpriv()` expectations.

## Failure Class Distribution

This distribution is heuristic. It is inferred from the expected verifier error strings in `__msg()` annotations for the 200 collected cases.

| Heuristic class | Count | Notes |
| --- | ---: | --- |
| Memory access / bounds / stack safety | 66 | Examples: `invalid mem access 'scalar'`, `invalid read from stack`, `value is outside of the allowed memory range`, `misaligned stack access` |
| Dynptr / iterator / type-state API contract | 53 | Examples: `Expected an initialized dynptr as arg #0`, `has no valid kptr`, iterator argument/type-state failures |
| Control-flow / callback / locking / RCU context | 34 | Examples: `BPF_EXIT instruction ... inside bpf_local_irq_save-ed region`, `cannot restore irq state out of order`, `requires RCU critical section protection` |
| Reference lifetime / ownership | 25 | Examples: `Unreleased reference`, `arg 1 is an unacquired reference`, `must be referenced or trusted` |
| Nullability / trusted-pointer checks | 12 | Examples: `Possibly NULL pointer passed to trusted arg0`, `NULL pointer passed to trusted arg0`, `pointer type ... must point` |
| Other structural verifier constraints | 10 | Examples: `combined stack size of 2 calls is`, unsupported attach/member checks, scalar return/value invariants |

Most frequent exact messages in the 200-case sample:

- `invalid mem access 'scalar'`: 25
- `Unreleased reference`: 9
- `cannot overwrite referenced dynptr`: 8
- `invalid read from stack`: 7
- `Expected an initialized dynptr as arg #0`: 7
- `BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region`: 7

## Coverage Notes

- The first 200 cases are not a balanced sample of all kernel selftests. The collector scans source files in sorted order and stops at `--max-cases 200`.
- That means the output is front-loaded by early files such as:
  - `dynptr_fail.c`: 83 cases
  - `irq.c`: 26 cases
  - `exceptions_fail.c`: 21 cases
  - `iters.c`: 17 cases

For reference, after fixing case-id collisions, the collector can derive 1,026 unique selftest cases from the current cached kernel checkout; this run intentionally wrote only the first 200.

## Issues Encountered

1. The requested command failed initially because the script did not support `--verbose`; it only accepted `--quiet`.
   Fix: added `--verbose` as the explicit inverse of `--quiet`.

2. The original collector generated non-unique filenames and case ids for many `BPF_PROG(...)` selftests.
   Impact: at least 118 distinct extractable cases were collapsing into duplicate output paths.
   Fix: improved `BPF_PROG(...)` name extraction and switched output filenames to deterministic unique case ids that include section context plus a short content hash.

3. I could not remove the first generated output directory with a blocked `rm -rf` shell path, so I moved the old directory aside before regenerating the clean corpus.
   Backup path: `benchmark/cases/kernel_selftests.pre_unique_ids_20260311T0903`
