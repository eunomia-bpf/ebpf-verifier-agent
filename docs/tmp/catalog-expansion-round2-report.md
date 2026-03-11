# Catalog Expansion Round 2

## Summary

- Baseline coverage before this round: **193 / 302 cases (63.9%)**
- Coverage after adding `OBLIGE-E019` through `OBLIGE-E023` and widening selected existing patterns: **263 / 302 cases (87.1%)**
- Net improvement: **+70 matched cases** and **+23.2 percentage points**

## What Changed

- Added five new error IDs to [taxonomy/error_catalog.yaml](/home/yunwei37/workspace/ebpf-verifier-agent/taxonomy/error_catalog.yaml):
  - `OBLIGE-E019` dynptr storage or release contract violations
  - `OBLIGE-E020` IRQ flag state or stack-slot protocol violations
  - `OBLIGE-E021` BTF/reference metadata gaps
  - `OBLIGE-E022` mutable global state unsupported
  - `OBLIGE-E023` register or stack contract violations at use sites
- Added matching obligations `OBLIGE-O019` through `OBLIGE-O023` to [taxonomy/obligation_catalog.yaml](/home/yunwei37/workspace/ebpf-verifier-agent/taxonomy/obligation_catalog.yaml).
- Widened selected existing patterns:
  - `OBLIGE-E015` now catches helper-argument nullability variants.
  - `OBLIGE-E016` now catches exception-callback and attach-context restrictions.
  - `OBLIGE-E018` now catches explicit "program too large" failures.
- Updated [interface/extractor/log_parser.py](/home/yunwei37/workspace/ebpf-verifier-agent/interface/extractor/log_parser.py) so `error_line` selection is more reliable for non-`invalid ...` diagnostics such as IRQ, dynptr, BTF, and type-contract messages.
- Updated [eval/taxonomy_coverage.py](/home/yunwei37/workspace/ebpf-verifier-agent/eval/taxonomy_coverage.py) to accept the task’s requested CLI flags: `--cases-dir`, `--catalog`, `--output-dir`, and `--results-json`.

## After Coverage

- `github_issues`: **20 / 26 (76.9%)**
- `kernel_selftests`: **186 / 200 (93.0%)**
- `stackoverflow`: **57 / 76 (75.0%)**

## New ID Utilization

- `OBLIGE-E019`: **13 cases**
- `OBLIGE-E020`: **9 cases**
- `OBLIGE-E021`: **2 cases**
- `OBLIGE-E022`: **1 case**
- `OBLIGE-E023`: **34 cases**

## Residual Gaps

- Remaining unmatched cases are mostly sparse one-offs and generic loader failures rather than repeated high-frequency verifier themes.
- The largest remaining repeated message is `Invalid argument (os error 22)` with **2** cases, which is still too loader-generic to classify safely without more context.
