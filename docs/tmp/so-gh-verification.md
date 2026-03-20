# SO/GH Verification

Generated from the checked-in corpus on 2026-03-19.

- Target cases in current `case_study/ground_truth.yaml`: `51`
- Note: this checkout contains `41` non-quarantined Stack Overflow cases and `10` non-quarantined GitHub issue cases, not `43 + 10`.
- Buggy programs that compiled: `9`
- Buggy programs rejected by verifier: `8`
- Rejections with at least partial error-message agreement: `1`
- Fixed variants accepted by verifier: `2`
- Blocked / skipped cases: `42`

| Case | Source | Language | Buggy | Verifier | Match | Fixed | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1002` | `github_issues` | `rust` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-aya-rs-aya-1056` | `github_issues` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `github-aya-rs-aya-1062` | `github_issues` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-aya-rs-aya-1267` | `github_issues` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `github-aya-rs-aya-407` | `github_issues` | `unknown` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `github-aya-rs-aya-440` | `github_issues` | `rust` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-aya-rs-aya-458` | `github_issues` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-aya-rs-aya-521` | `github_issues` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-cilium-cilium-41412` | `github_issues` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-facebookincubator-katran-149` | `github_issues` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-53136145` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-60506220` | `stackoverflow` | `unknown` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-61945212` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-67402772` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-67679109` | `stackoverflow` | `c` | `Recovered source depends on BCC frontend rewriting, not standalone clang C.` | `not_run` | `unknown` | `not_attempted` | Recovered source depends on BCC frontend rewriting, not standalone clang C. |
| `stackoverflow-68752893` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-69413427` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-69767533` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-70721661` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-70729664` | `stackoverflow` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-70750259` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-70841631` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-70873332` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-71351495` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-71522674` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-71946593` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-72005172` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-72074115` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-72560675` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-72575736` | `stackoverflow` | `rust` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-72606055` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-73088287` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-74178703` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-74531552` | `stackoverflow` | `c` | `Recovered source uses BCC macro DSL that is not standalone clang C.` | `not_run` | `unknown` | `not_attempted` | Recovered source uses BCC macro DSL that is not standalone clang C. |
| `stackoverflow-75294010` | `stackoverflow` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-75515263` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-75643912` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-76160985` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-76277872` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-76637174` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-76960866` | `stackoverflow` | `c` | `Recovered source depends on BCC frontend rewriting, not standalone clang C.` | `not_run` | `unknown` | `not_attempted` | Recovered source depends on BCC frontend rewriting, not standalone clang C. |
| `stackoverflow-77205912` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-77673256` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-77762365` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-78236201` | `stackoverflow` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-78236856` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | <none> |
| `stackoverflow-78958420` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-79348306` | `stackoverflow` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-79485758` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-79530762` | `stackoverflow` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-79812509` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
