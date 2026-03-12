# Span Coverage Evaluation

- Generated at: `2026-03-12T01:29:00+00:00`
- Logged cases evaluated: `263`
- Synthetic diff-only cases analyzed: `535`
- Successful `generate_diagnostic()` runs: `263/263`

## Per-source Span Coverage

| Source | Cases | Diagnostic success | Covered | Not covered | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| `SO` | 66 | 66 | 15 | 1 | 50 |
| `GH` | 26 | 26 | 1 | 0 | 25 |
| `KS` | 171 | 171 | 84 | 10 | 77 |

## Rejected Span vs Verifier Error

| Source | Semantic match | Total with expected message | Rate |
| --- | ---: | ---: | ---: |
| `SO` | 0 | 0 | n/a |
| `GH` | 0 | 0 | n/a |
| `KS` | 87 | 102 | 85.3% |

## Taxonomy Match vs Ground Truth

| Source | Taxonomy matches | Total with ground truth taxonomy | Rate |
| --- | ---: | ---: | ---: |
| `SO` | 14 | 24 | 58.3% |
| `GH` | 6 | 9 | 66.7% |
| `KS` | 49 | 103 | 47.6% |

## Manual 30-case Subset

- Coverage among evaluable manual cases: `12/14` (85.7%)
- Taxonomy match on manual cases: `23/30` (76.7%)
- Rejected-span/error semantic match on manual cases: `7/10` (70.0%)

| Coverage state | Count |
| --- | ---: |
| `yes` | 12 |
| `no` | 2 |
| `unknown` | 16 |

## Synthetic Fix-pattern Distribution

| fix_type | Count |
| --- | ---: |
| `inline_hint` | 221 |
| `other` | 71 |
| `loop_rewrite` | 50 |
| `bounds_check` | 46 |
| `type_cast` | 37 |
| `alignment` | 32 |
| `null_check` | 20 |
| `volatile_hack` | 17 |
| `helper_switch` | 16 |
| `refactor` | 14 |
| `attribute_annotation` | 11 |

### Synthetic Pattern Summary

| pattern_summary | Count |
| --- | ---: |
| `added __always_inline or similar inlining hint` | 223 |
| `added or strengthened an explicit bounds guard` | 112 |
| `other localized source change` | 49 |
| `added an explicit null guard before the failing operation` | 45 |
| `rewrote the loop shape or its verifier-visible bound` | 28 |
| `changed the type, cast, or object provenance at the failing site` | 24 |
| `added volatile annotation to preserve verifier-visible proof` | 19 |
| `added an attribute or annotation that changes lowering behavior` | 8 |
| `copied or reshaped data to satisfy alignment constraints` | 8 |
| `switched helper or API usage` | 8 |

- Average changed lines per synthetic case: `22.92`

## Key Findings

- Overall span coverage is `100/263` cases marked `yes`, `11` marked `no`, and `152` marked `unknown`. The `unknown` bucket is dominated by fixes that are not source-localizable from the available artifacts, such as verifier-limit, BTF/toolchain, or kernel-upgrade remedies.
- Rejected-span/error semantic agreement is strongest where the ground truth is an expected verifier message, especially kernel selftests. Coverage is stricter than error agreement because some fixes are diffuse even when the reject site is correctly identified.
- Taxonomy agreement is computed only when a usable ground-truth taxonomy can be inferred or is manually labeled. The most trustworthy subset is the manual 30-case benchmark.
- The synthetic corpus is heavily skewed toward `inline_hint`, `other`, and `loop_rewrite` patterns, so future span coverage work should expect many lowering-artifact and verifier-limit style fixes even when no verifier log is available yet.

## Example Uncovered Cases

| Case | Src | Ground-truth pattern | Basis |
| --- | --- | --- | --- |
| `stackoverflow-69192685` | `SO` | `helper_switch` | `no_localized_match` |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `KS` | `helper_switch` | `localizable_pattern_without_match` |
| `kernel-selftest-dynptr-fail-data-slice-missing-null-check1-raw-tp-af2be9c9` | `KS` | `bounds_check` | `no_localized_match` |
| `kernel-selftest-dynptr-fail-data-slice-missing-null-check2-raw-tp-8e533162` | `KS` | `bounds_check` | `no_localized_match` |
| `kernel-selftest-dynptr-fail-skb-invalid-data-slice1-tc-0b35a757` | `KS` | `bounds_check` | `no_localized_match` |

## Example Unknown Cases

| Case | Src | Ground-truth pattern | Localizability |
| --- | --- | --- | --- |
| `stackoverflow-47591176` | `SO` | `unknown` | `unknown` |
| `stackoverflow-48267671` | `SO` | `unknown` | `unknown` |
| `stackoverflow-53136145` | `SO` | `unknown` | `unknown` |
| `stackoverflow-56872436` | `SO` | `loop_rewrite` | `partial` |
| `stackoverflow-60053570` | `SO` | `unknown` | `unknown` |

## Recommendations

- Promote exact changed-line matching wherever paired buggy/fixed snippets are available; it is the strongest coverage signal and is already available for all synthetic cases.
- Keep a separate `rejected span matches verifier error` metric from `fix location covered`. The former is stable on selftests, while the latter is often unknowable for verifier-limit or environment-only fixes.
- For future data collection, preserve explicit fixed snippets for Stack Overflow and GitHub cases. Many current `unknown` outcomes are caused by good fix descriptions without a line-level before/after artifact.
- For lowering-artifact cases, add provenance from caller/callee or subprogram identity into the diagnostic JSON. That would convert many current `partial` or `unknown` inline-fix cases into direct span matches.
