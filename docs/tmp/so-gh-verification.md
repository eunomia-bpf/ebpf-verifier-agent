# SO/GH Verification

Generated from the checked-in corpus on 2026-03-19.

- Target cases in current `case_study/ground_truth.yaml`: `51`
- Note: this checkout contains `41` non-quarantined Stack Overflow cases and `10` non-quarantined GitHub issue cases, not `43 + 10`.
- Buggy programs that compiled: `37`
- Buggy programs rejected by verifier: `28`
- Rejections with at least partial error-message agreement: `14`
- Fixed variants accepted by verifier: `4`
- Blocked / skipped cases: `14`

| Case | Source | Language | Buggy | Verifier | Match | Fixed | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1002` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-1056` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-1062` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-1267` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-407` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-440` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-458` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-aya-rs-aya-521` | `github_issues` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `github-cilium-cilium-41412` | `github_issues` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `github-facebookincubator-katran-149` | `github_issues` | `c` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-53136145` | `stackoverflow` | `c` | `compiled` | `rejected` | `partial` | `not_attempted` | Restored the inlined IPv4/IPv6 helper flow; current 6.15 rejects on a related scalar-pointer failure instead of the original `R0 inv` state. |
| `stackoverflow-60506220` | `stackoverflow` | `unknown` | `No recoverable C source found in snippets or body text.` | `not_run` | `unknown` | `not_attempted` | No recoverable C source found in snippets or body text. |
| `stackoverflow-61945212` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-67402772` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `rejected:fixed[1]/wrapped` | <none> |
| `stackoverflow-67679109` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-68752893` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-69413427` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-69767533` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-70721661` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-70729664` | `stackoverflow` | `c` | `compiled` | `rejected` | `partial` | `rejected:fixed[14]/wrapped` | Restored the 32-iteration SCTP loop and an explicit spill/reload so packet bounds are lost again at the same offset. |
| `stackoverflow-70750259` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | Preserved the signed spill/reload around `ext_len`; the fresh run matches the original verifier headline exactly. |
| `stackoverflow-70841631` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-70873332` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | Replaced the legacy `SEC(\"maps\")` definition so the object reaches the verifier and reproduces the original packet-access failure. |
| `stackoverflow-71351495` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-71522674` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | Reintroduced the Ethernet-header offset so the failing TCP access occurs at packet offset `14`, matching the original verifier shape. |
| `stackoverflow-71946593` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `rejected:fixed[3]/wrapped` | <none> |
| `stackoverflow-72005172` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-72074115` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | Replaced the non-loadable standalone struct_ops wrapper with a focused cubic-root repro; current 6.15 accepts the bounded table access. |
| `stackoverflow-72560675` | `stackoverflow` | `c` | `compiled` | `rejected` | `partial` | `not_attempted` | Switched back to `bpf_probe_read`; newer kernels still reject on the expected map-value bound, but report helper size `65535` instead of `0`. |
| `stackoverflow-72575736` | `stackoverflow` | `rust` | `Corpus artifact is not C.` | `not_run` | `unknown` | `not_attempted` | Corpus artifact is not C. |
| `stackoverflow-72606055` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-73088287` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | Fixed the wrapper loader issues by using an `xdp` section and modern `.maps`; once it loads, current 6.15 accepts it. |
| `stackoverflow-74178703` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-74531552` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-75294010` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-75515263` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-75643912` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `rejected:fixed[0]/raw` | <none> |
| `stackoverflow-76160985` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | Reworked the wrapper into a focused subprogram repro without the old ELF/loader issue; current 6.15 accepts it. |
| `stackoverflow-76277872` | `stackoverflow` | `c` | `compiled` | `rejected` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-76637174` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `rejected:fixed[0]/wrapped` | Preserved the original loop/body shape; the current host still reproduces the packet-access failure. |
| `stackoverflow-76960866` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-77205912` | `stackoverflow` | `c` | `compiled` | `rejected` | `partial` | `not_attempted` | <none> |
| `stackoverflow-77673256` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-77762365` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | Restored the original map-backed args/event state instead of stack-only locals; the verifier now reproduces the original map-value OOB exactly. |
| `stackoverflow-78236201` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | <none> |
| `stackoverflow-78236856` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | <none> |
| `stackoverflow-78958420` | `stackoverflow` | `c` | `No source variant compiled with the exact clang command requested.` | `not_run` | `unknown` | `not_attempted` | No source variant compiled with the exact clang command requested. |
| `stackoverflow-79348306` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `accepted:fixed[0]/raw` | <none> |
| `stackoverflow-79485758` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | Restored the original large context-map layout and action offsets so the failure returns to packet access instead of an artificial small-map OOB. |
| `stackoverflow-79530762` | `stackoverflow` | `c` | `compiled` | `accepted` | `mismatch` | `not_attempted` | Restored the full question-body logic, including `bpf_xdp_adjust_head`, but current clang+6.15 still accept it. |
| `stackoverflow-79812509` | `stackoverflow` | `c` | `compiled` | `rejected` | `exact` | `not_attempted` | <none> |
