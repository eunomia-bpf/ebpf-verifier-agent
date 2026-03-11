# Verbose Log Audit

Run date: 2026-03-11

Scope:

- Scanned YAML case files under `case_study/cases/{stackoverflow,github_issues,kernel_selftests*}/`.
- Excluded `index.yaml` manifests.
- Treated both `kernel_selftests` directories as the `KS` source bucket for summary statistics.

## Corpus Summary

| Bucket | Directories | Cases | With verifier_log | With register-state dumps | With BTF annotations | With backtracking annotations | With source snippets | With fix description | Log lines min / median / max |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| SO | `stackoverflow` | 76 | 66 | 37 | 31 | 19 | 59 | 66 | 0 / 14.5 / 331 |
| GH | `github_issues` | 26 | 26 | 14 | 4 | 4 | 15 | 22 | 4 / 17 / 544 |
| KS | `kernel_selftests*` | 400 | 0 | 0 | 0 | 0 | 400 | 0 | 0 / 0 / 0 |

## Summary Statistics

### Feature Coverage by Source

| Metric | SO | GH | KS | Total |
| --- | ---: | ---: | ---: | ---: |
| Per-instruction register state | 37 | 14 | 0 | 51 |
| BTF source annotations | 31 | 4 | 0 | 35 |
| Backtracking annotations | 19 | 4 | 0 | 23 |
| Code + verbose_log + fix_description triples | 43 | 12 | 0 | 55 |

### Log Length Distribution

| Statistic | Lines |
| --- | ---: |
| Cases | 502 |
| Min | 0 |
| Q1 | 0 |
| Median | 0 |
| Q3 | 0 |
| Max | 544 |

### Non-Empty Log Length Distribution

| Statistic | Lines |
| --- | ---: |
| Cases with logs | 92 |
| Min | 1 |
| Q1 | 8 |
| Median | 20 |
| Q3 | 61 |
| Max | 544 |

## Richest Prototype Targets

Ranking heuristic: longest logs first, then register-state density, then presence of BTF annotations and backtracking markers.

| Rank | Case ID | Bucket | Dir | Log lines | Register-state lines | BTF lines | Backtracking lines | Has source | Has fix |
| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| 1 | `github-aya-rs-aya-1267` | GH | `github_issues` | 544 | 261 | 0 | 0 | yes | no |
| 2 | `github-aya-rs-aya-1062` | GH | `github_issues` | 337 | 300 | 0 | 0 | yes | yes |
| 3 | `stackoverflow-70760516` | SO | `stackoverflow` | 331 | 34 | 67 | 56 | yes | yes |
| 4 | `github-cilium-cilium-37478` | GH | `github_issues` | 262 | 26 | 52 | 67 | yes | yes |
| 5 | `stackoverflow-79485758` | SO | `stackoverflow` | 208 | 20 | 32 | 88 | yes | yes |
| 6 | `github-cilium-cilium-36936` | GH | `github_issues` | 204 | 8 | 0 | 44 | no | yes |
| 7 | `stackoverflow-78958420` | SO | `stackoverflow` | 191 | 103 | 63 | 0 | yes | yes |
| 8 | `github-aya-rs-aya-1056` | GH | `github_issues` | 147 | 46 | 0 | 0 | yes | yes |
| 9 | `github-cilium-cilium-41996` | GH | `github_issues` | 147 | 0 | 0 | 0 | no | yes |
| 10 | `stackoverflow-70729664` | SO | `stackoverflow` | 139 | 13 | 6 | 79 | no | yes |
| 11 | `stackoverflow-70750259` | SO | `stackoverflow` | 112 | 16 | 22 | 18 | yes | yes |
| 12 | `stackoverflow-74531552` | SO | `stackoverflow` | 110 | 5 | 0 | 15 | yes | yes |
| 13 | `stackoverflow-79530762` | SO | `stackoverflow` | 109 | 15 | 26 | 6 | no | yes |
| 14 | `stackoverflow-78236201` | SO | `stackoverflow` | 102 | 63 | 30 | 0 | no | yes |
| 15 | `github-cilium-cilium-44216` | GH | `github_issues` | 91 | 0 | 0 | 0 | no | yes |
| 16 | `stackoverflow-70392721` | SO | `stackoverflow` | 89 | 0 | 0 | 0 | yes | yes |
| 17 | `github-cilium-cilium-41522` | GH | `github_issues` | 84 | 48 | 24 | 0 | yes | yes |
| 18 | `stackoverflow-72575736` | SO | `stackoverflow` | 83 | 16 | 0 | 12 | yes | yes |
| 19 | `stackoverflow-76960866` | SO | `stackoverflow` | 80 | 4 | 16 | 13 | yes | yes |
| 20 | `stackoverflow-76637174` | SO | `stackoverflow` | 75 | 47 | 22 | 0 | no | yes |

## Notes

- `BTF source annotations` only counts log lines whose trimmed form starts with `;`, matching the requested signal.
- `Per-instruction register state` counts logs containing explicit register facts such as `R1=ctx()` or `R0_w=inv(...)`.
- `Backtracking annotations` counts presence of `last_idx`, `first_idx`, `regs=`, or `stack=` markers anywhere in the combined log.
- Selftest YAMLs often omit a captured `verifier_log`; those cases remain in the denominator with log length `0`.
