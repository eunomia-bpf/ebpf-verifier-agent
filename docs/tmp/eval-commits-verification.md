# Eval Commits Verification

- Candidate ranking source: `scripts/find_lowering_artifact_commits.py` scoring logic.
- Note: `docs/tmp/lowering-artifact-candidates.md` renders only 25 no-log rows, so the top 50 were reconstructed from the same scoring function over `case_study/cases/eval_commits/*.yaml`.
- Candidates scanned: `50`
- Buggy snippets that compiled after the oracle fix: `0`
- Cases with verifier logs: `0`
- Cases with trace-rich verifier logs: `0`
- YAML files updated with captured buggy verifier logs: `0`
- Confirmed lowering_artifact candidates (buggy reject + fixed pass): `0`

## Confirmed Cases

No top-50 eval_commits candidate was confirmed on this host/kernel.

## Per-Case Results

| Case ID | Score | Fix Type | Buggy Compiles | Buggy Result | Log Quality | Fixed Compiles | Fixed Result | Confirmed | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `eval-cilium-02e696c855cf` | 8 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_dg9v1jce.c:42:17: error: 'section' attribute only applies to functions, global variables, Objective-C methods, and Objective-C properties |
| `eval-bcc-45f5df4c5942` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_8bpjtz0w.c:19:14: error: use of undeclared identifier 'u32' |
| `eval-bcc-799acc7ca2c6` | 7 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /usr/include/vmlinux.h:826:2: error: redefinition of enumerator 'BPF_ADJ_ROOM_ENCAP_L2_MASK' |
| `eval-bcc-8206f547b8e3` | 7 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_70pan9ig.c:19:1: error: unknown type name 'namespace' |
| `eval-bcc-952415e490bd` | 7 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_hk18cjmd.c:31:14: error: use of undeclared identifier 'u32' |
| `eval-bcc-b0f891d129a9` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_u88qqtc9.c:18:11: error: expected ';' after top level declarator |
| `eval-bcc-d4e505c1e4ed` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_6jt8_3nz.c:21:1: error: extraneous closing brace ('}') |
| `eval-cilium-5d882fdd1f8a` | 7 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_ikyhq6yn.c:17:2: error: expected identifier or '(' |
| `eval-cilium-c3b65fce8b84` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_k1f67g36.c:16:10: error: '../builtins.h' file not found, did you mean 'builtins.h'? |
| `eval-cilium-ebb781e5ba1b` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_8fi0y1p3.c:17:2: error: expected identifier or '(' |
| `eval-katran-918c0e169773` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_6b3f_bg5.c:51:4: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int] |
| `eval-katran-d195c045a01b` | 7 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_40dhzvc5.c:25:3: error: extraneous closing brace ('}') |
| `eval-aya-11c227743de9` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_w_gzdit4.c:22:1: error: unknown type name 'use' |
| `eval-aya-223e2f4ea1ef` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_vw86dbb9.c:18:1: error: unknown type name 'impl_write_to_buf' |
| `eval-aya-3569c9afc3dc` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_ksy4nsic.c:16:2: error: invalid preprocessing directive |
| `eval-aya-bdb2750e66f9` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_wz0vgcs9.c:18:1: error: unknown type name 'impl_write_to_buf' |
| `eval-aya-d5e4e9270ae4` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_o_vcleb4.c:17:17: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int] |
| `eval-bcc-118bf168f9f6` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_48ghu9pb.c:18:26: error: use of undeclared identifier 'u32' |
| `eval-bcc-1d659c7f3388` | 6 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_nsq0iwez.c:20:3: error: unknown type name 'Value' |
| `eval-bcc-2070a2aefb0b` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_rly7t45a.c:18:11: error: expected ';' after top level declarator |
| `eval-bcc-f2006eaa5901` | 6 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_espt_q0w.c:17:17: error: use of undeclared identifier 'MAX_CPU_NR' |
| `eval-cilium-0279a19a34bd` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_zmu__nyn.c:17:3: error: extraneous closing brace ('}') |
| `eval-cilium-040d264ebcd7` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_mjdb2hum.c:17:1: error: extraneous closing brace ('}') |
| `eval-cilium-064b947efb86` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix__uxabo8g.c:17:8: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int] |
| `eval-cilium-0a4a393d6554` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_zd1yvsej.c:20:10: fatal error: 'lib/common.h' file not found |
| `eval-cilium-0ab817e77209` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_29qsjm9u.c:17:4: error: expected identifier or '(' |
| `eval-cilium-0ae984552b8f` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_rmaruic_.c:17:5: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int] |
| `eval-cilium-0cf109933350` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_p1i0yd8e.c:17:35: error: expected ';' after top level declarator |
| `eval-cilium-0d89f055806d` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_9h2y5i7b.c:17:3: error: expected identifier or '(' |
| `eval-cilium-0f11ce8d87c2` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_49_k8uql.c:17:2: error: extraneous closing brace ('}') |
| `eval-cilium-1085ae269e71` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_pnoysmm6.c:17:3: error: extraneous closing brace ('}') |
| `eval-cilium-108aa4212f8e` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_2crsqgbw.c:21:2: error: unterminated conditional directive |
| `eval-cilium-11e5f5936631` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_f1y8gd7j.c:17:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int] |
| `eval-cilium-12e29221d278` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_gqc8jdvg.c:17:2: error: unterminated conditional directive |
| `eval-cilium-12e3ae9936bd` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_mm1uznah.c:17:3: error: expected identifier or '(' |
| `eval-cilium-13f2cd0a889c` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_fl_08365.c:17:3: error: expected identifier or '(' |
| `eval-cilium-13f2d90daada` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_ongqdt92.c:17:4: error: expected identifier or '(' |
| `eval-cilium-142c0f7128c7` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_24z8r5x1.c:23:10: fatal error: 'drop.h' file not found |
| `eval-cilium-14a653ad4aac` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_6nz8poso.c:17:2: error: unknown type name 'state' |
| `eval-cilium-181ed5a73517` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_y4j2fw7f.c:17:2: error: #endif without #if |
| `eval-cilium-1915b7348367` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_omvunk05.c:17:3: error: expected identifier or '(' |
| `eval-cilium-1a5596de414a` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_qmlnmt5_.c:19:2: error: expected identifier or '(' |
| `eval-cilium-1b6a98ccf809` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_e4lb11mt.c:17:4: error: expected identifier or '(' |
| `eval-cilium-1b95d351eb76` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_hy5atv7_.c:23:2: error: expected identifier or '(' |
| `eval-cilium-1c000f5f4726` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_0lwlzama.c:22:2: error: expected identifier or '(' |
| `eval-cilium-1e25adb69b44` | 6 | `volatile_hack` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_k_zath8a.c:17:3: error: expected identifier or '(' |
| `eval-cilium-210b5866e0f5` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_gmcv_k0n.c:17:3: error: expected identifier or '(' |
| `eval-cilium-227ed483633c` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_obh60xfy.c:18:3: error: expected identifier or '(' |
| `eval-cilium-239711b71174` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_hz7ixvjy.c:16:10: fatal error: 'compiler.h' file not found |
| `eval-cilium-275856b1650f` | 6 | `inline_hint` | no | `compile_error` | `none` | no | `compile_error` | no | Compilation failed (wrap-uapi): /tmp/bpfix_4pidvikz.c:27:2: error: #endif without #if |
