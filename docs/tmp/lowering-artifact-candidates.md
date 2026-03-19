# Lowering-Artifact Candidate Scan

- Generated at: `2026-03-19T20:07:11+00:00`
- Cases scanned: `591`
- Promising candidates: `312`
- Oracle compile attempts: `312`
- Oracle compile successes: `3`
- Verifier logs captured: `3`
- Trace-rich logs: `0`
- YAML files updated with verifier logs: `3`

## Promising Candidate Mix

| Fix Type | Count |
| --- | --- |
| `inline_hint` | 229 |
| `bounds_check` | 52 |
| `volatile_hack` | 18 |
| `attribute_annotation` | 11 |
| `other` | 1 |
| `helper_switch` | 1 |

## Cases With Captured Verifier Logs

| Case ID | Fix Type | Score | Verifier Result | Log Quality | Insn Lines | State Lines | YAML Updated |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `eval-cilium-3323fb0c62a9` | `inline_hint` | 6 | fail | `message_only` | 0 | 0 | yes |
| `eval-cilium-9b644fc3fb8f` | `volatile_hack` | 6 | fail | `message_only` | 0 | 0 | yes |
| `eval-libbpf-75a2e3bda8d9` | `inline_hint` | 6 | fail | `message_only` | 0 | 0 | yes |

## High-Scoring Candidates Without Logs

| Case ID | Fix Type | Score | Commit Keywords | Diff Signals | Last Oracle Error |
| --- | --- | --- | --- | --- | --- |
| `eval-cilium-02e696c855cf` | `inline_hint` | 8 | clamp, LLVM | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-45f5df4c5942` | `inline_hint` | 7 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-799acc7ca2c6` | `volatile_hack` | 7 | none | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-8206f547b8e3` | `volatile_hack` | 7 | LLVM | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-952415e490bd` | `volatile_hack` | 7 | none | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-b0f891d129a9` | `inline_hint` | 7 | volatile | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-d4e505c1e4ed` | `inline_hint` | 7 | bounds | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-5d882fdd1f8a` | `volatile_hack` | 7 | LLVM | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-c3b65fce8b84` | `inline_hint` | 7 | volatile | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-ebb781e5ba1b` | `inline_hint` | 7 | LLVM | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-katran-918c0e169773` | `inline_hint` | 7 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-katran-d195c045a01b` | `inline_hint` | 7 | reload | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-aya-11c227743de9` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-aya-223e2f4ea1ef` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-aya-3569c9afc3dc` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-aya-bdb2750e66f9` | `inline_hint` | 6 | none | verifier_visible_bound | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-aya-d5e4e9270ae4` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-118bf168f9f6` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-1d659c7f3388` | `volatile_hack` | 6 | none | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-2070a2aefb0b` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-bcc-f2006eaa5901` | `volatile_hack` | 6 | none | codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-0279a19a34bd` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-040d264ebcd7` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-064b947efb86` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |
| `eval-cilium-0a4a393d6554` | `inline_hint` | 6 | none | verifier_visible_bound, codegen_workaround | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' |

## Top Compile Failures

| Error | Count |
| --- | --- |
| Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/kasan-checks.h:22:15: error: unknown type name 'bool' | 309 |
