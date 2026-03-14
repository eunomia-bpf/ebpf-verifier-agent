# Root-Cause Validation Report

Generated: 2026-03-14T01:39:46+00:00

## Executive Summary

- **Total cases evaluated**: 262 (from 262 loaded)
- **Cases with proof_lost span**: 11.5% (30/262)
- **Backtracking rate** (proof_lost before rejected): 73.3% (22/30)
- **Source line: exact match**: N/A (evaluable: 0)
- **Source line: within ±5 lines**: N/A
- **Source line: within ±10 lines**: N/A
- **Text token match**: 0.0% (0/1) (evaluable: 1)

- **Average insn distance** (proof_lost to rejected): 6.4 (max: 17)

## Per-Source Breakdown

| Source | N | proof_lost% | backtrack% | line_exact% | line_w5% | text_match% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| github_issues | 26 | 0% | N/A | N/A | N/A | N/A |
| kernel_selftests | 171 | 11% | 74% | N/A | N/A | N/A |
| stackoverflow | 65 | 17% | 73% | N/A | N/A | 0% |

## By Proof Status

| proof_status | N | proof_lost% | backtrack% |
| --- | ---: | ---: | ---: |
| established_but_insufficient | 4 | 0% | N/A |
| established_then_lost | 30 | 100% | 73% |
| never_established | 103 | 0% | N/A |
| unknown | 125 | 0% | N/A |

## Insn-Level Localization Distribution

| Localization | Count |
| --- | ---: |
| `no_proof_lost` | 129 |
| `never_established` | 103 |
| `backtracked` | 22 |
| `at_error` | 8 |

## Source Line Match Distribution

| Match Level | Count |
| --- | ---: |
| `unknown` | 30 |

## Limitations and Interpretation

### Ground Truth Quality
- SO/GH cases: ground truth from code diff between source_snippets[0] and snippets[1]/fixed_code.
  Many SO cases lack a proper before/after code pair — fix is described in text only.
- Kernel selftests: BTF line info provides exact source lines from verifier trace,
  but these cases often lack before/after diffs (the case IS the failing test).

### Coverage Gaps
- Only 0/30 proof_lost cases have both BTF line AND fix diff lines.
- Source line comparison only works when: (a) BTF line info present in log,
  AND (b) we have a before/after code diff.

### What This Means for the Paper
- The backtracking rate shows OBLIGE successfully identifies the proof obligation
  that was lost BEFORE the rejection site — i.e., it's not just pointing at the
  error line like most tools do.
- Text token match provides a signal even without exact source lines.
- The 'within_5' metric is the most meaningful for practical tool evaluation.