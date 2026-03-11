# Eval Verification And Expansion Report

Run date: 2026-03-11

## Verification Summary

- Verified 21 original Eval cases against the actual cloned repositories in `/tmp/ebpf-eval-repos`.
- Commit existence, subject, date, and extracted `buggy_code` / `fixed_code` matched upstream git data for all 21 original cases.
- 17 original cases passed all content checks, and 4 failed due to incomplete `diff_summary` coverage.

## Original 21 Case Results

| Case | Status | YAML Valid Before Rewrite | Note |
| --- | --- | --- | --- |
| eval-aya-29d539751a6d | PASS | no | Real commit data matched exactly. |
| eval-aya-2ac433449cde | PASS | no | Real commit data matched exactly. |
| eval-aya-2e0702854b0e | PASS | no | Real commit data matched exactly. |
| eval-aya-32350f81b756 | PASS | no | Real commit data matched exactly. |
| eval-aya-3cfd886dc512 | FAIL | no | `diff_summary` omitted changed files: test/integration-ebpf/src/log.rs, test/integration-test/src/tests/log.rs. |
| eval-aya-628b473e0937 | PASS | no | Real commit data matched exactly. |
| eval-aya-bdb2750e66f9 | PASS | no | Real commit data matched exactly. |
| eval-aya-f6606473af43 | PASS | no | Real commit data matched exactly. |
| eval-cilium-2f0275ee3ee2 | FAIL | no | `diff_summary` omitted changed files: bpf/tests/tc_nodeport_lb4_dsr_backend.c, bpf/tests/tc_nodeport_lb4_nat_lb.c, bpf/tests/tc_nodeport_test.c, bpf/tests/xdp_nodeport_lb4_nat_lb.c, bpf/tests/xdp_nodeport_lb4_test.c. |
| eval-cilium-4853fb153410 | FAIL | no | `diff_summary` omitted changed files: bpf/tests/lib/lb.h, bpf/tests/tc_nodeport_lb6_dsr_backend.c. |
| eval-cilium-71f8962acd55 | PASS | no | Real commit data matched exactly. |
| eval-cilium-74f7fd1d40bc | PASS | no | Real commit data matched exactly. |
| eval-cilium-77685c2280ae | PASS | no | Real commit data matched exactly. |
| eval-cilium-7e3115694f03 | PASS | no | Real commit data matched exactly. |
| eval-cilium-8eb389403823 | PASS | no | Real commit data matched exactly. |
| eval-cilium-9100ffbef979 | PASS | no | Real commit data matched exactly. |
| eval-cilium-bd23d375832e | PASS | no | Real commit data matched exactly. |
| eval-cilium-caf84595d9cb | PASS | no | Real commit data matched exactly. |
| eval-cilium-e607d0c161dc | PASS | no | Real commit data matched exactly. |
| eval-cilium-ec3529b5ddfe | FAIL | no | `diff_summary` omitted changed files: bpf/bpf_sock.c, bpf/lib/icmp6.h, bpf/lib/lxc.h, bpf/lib/nat.h, bpf/lib/nat_46x64.h, bpf/tests/tc_nodeport_lb6_dsr_backend.c, bpf/tests/tc_nodeport_lb6_dsr_lb.c, bpf/tests/xdp_nodeport_lb6_dsr_lb.c. |
| eval-katran-d3c0229b0731 | PASS | no | Real commit data matched exactly. |

## Failure Details

- `eval-aya-3cfd886dc512`: commit/message/date/snippets matched, but `diff_summary` was incomplete for test/integration-ebpf/src/log.rs, test/integration-test/src/tests/log.rs.
- `eval-cilium-2f0275ee3ee2`: commit/message/date/snippets matched, but `diff_summary` was incomplete for bpf/tests/tc_nodeport_lb4_dsr_backend.c, bpf/tests/tc_nodeport_lb4_nat_lb.c, bpf/tests/tc_nodeport_test.c, bpf/tests/xdp_nodeport_lb4_nat_lb.c, bpf/tests/xdp_nodeport_lb4_test.c.
- `eval-cilium-4853fb153410`: commit/message/date/snippets matched, but `diff_summary` was incomplete for bpf/tests/lib/lb.h, bpf/tests/tc_nodeport_lb6_dsr_backend.c.
- `eval-cilium-ec3529b5ddfe`: commit/message/date/snippets matched, but `diff_summary` was incomplete for bpf/bpf_sock.c, bpf/lib/icmp6.h, bpf/lib/lxc.h, bpf/lib/nat.h, bpf/lib/nat_46x64.h, bpf/tests/tc_nodeport_lb6_dsr_backend.c, bpf/tests/tc_nodeport_lb6_dsr_lb.c, bpf/tests/xdp_nodeport_lb6_dsr_lb.c.

## New Commits Added

### cilium

- `3740e9db8fef` `bpf: Fix "R2 !read_ok" verifier error with LLVM 17` (refactor; bpf/lib/lb.h)
- `46024c6c4a30` `bpf/lib/nodeport.h: Fix verifier error on RHEL 8.6 + mCPU v3` (null_check; bpf/lib/nodeport.h)
- `4dc7d8047caf` `bpf: Fix "same insn cannot be used with different pointers" in proxy.h` (refactor; bpf/lib/proxy.h)
- `50c319d0cbfe` `bpf/lib/nat.h: Fix verifier error for RHEL + mcpu=v3` (refactor; bpf/lib/nat.h)
- `6b3c9f16c99f` `bpf: Init (ipv6_frag_hdr) frag struct` (refactor; bpf/lib/ipv6.h)
- `6e18eb020b68` `bpf: Fix compatibility with Clang 17 in __lb6_affinity_backend_id` (refactor; bpf/lib/lb.h)
- `783648c20626` `bpf: Add missing __align_stack_8 in encap_geneve_dsr_opt4` (other; bpf/lib/nodeport.h)
- `847014aa62f9` `bpf: Avoid 32bit assignment of packet pointer` (refactor; bpf/include/bpf/ctx/common.h, bpf/include/bpf/ctx/skb.h, bpf/include/bpf/ctx/xdp.h)
- `8dd5de960167` `bpf/tests: fix complexity issue in __corrupt_mem` (refactor; bpf/tests/builtin_test.h)
- `de679382fe1e` `ICMPv6: Fix verifier error when loading on l2-less devices` (bounds_check; bpf/lib/icmp6.h)
- `f51f4dfac542` `bpf: Add check for null state in snat_v6_nat` (null_check; bpf/lib/nat.h)

### aya

- `1f3acbcfe0fb` `bpf: add override for bpf_probe_read_user_str` (bounds_check; bpf/aya-bpf/src/helpers.rs)
- `28abaece2af7` `Fix the log buffer bounds` (bounds_check; aya-log/aya-log-common/src/lib.rs)
- `2d79f22b4022` `aya-bpf: use bpf_read_probe for reading pt_regs` (helper_switch; bpf/aya-bpf/src/args.rs)
- `62c6dfd764ce` `tmp: hack for btf verifier error` (refactor; aya-obj/src/btf/btf.rs)
- `ca0c32d1076a` `fix(aya): Fill bss maps with zeros` (other; aya-obj/src/obj.rs, aya/src/maps/mod.rs)
- `fc69a0697274` `aya: fix is_probe_read_kernel_supported in aarch64 kernels 5.5 (#1235)` (other; aya/src/sys/bpf.rs)

### katran

- `5d1e2ca8b9d7` `Guard the loop unroll and noinline definition of parse_hdr_opt behind a flag` (inline_hint; katran/lib/bpf/pckt_parsing.h)

### Extra Repo Search Notes

- `linux`: Searched `tools/testing/selftests/bpf/` with commit-message filters for verifier-related fixes, but did not find additional small workaround commits that cleanly extract into before/after pairs.
- `libbpf-bootstrap`: Searched the repo after cloning it. The strongest hit was `27607b8c0d51561486e391db3b63de2979953497` (`examples/c: prevent uprobe_add/uprobe_sub inlining`), but it is an example-loader/compiler hygiene change rather than a clear verifier workaround, so it was not added.
- `katran`: Found one additional clean verifier-related workaround (`5d1e2ca8b9d71a1175352ff3994237f4e6530c1e`). Other Katran hits were larger feature commits, not small workaround patches.

## New YAML Files Created

- `case_study/cases/eval_commits/eval-aya-1f3acbcfe0fb.yaml`
- `case_study/cases/eval_commits/eval-aya-28abaece2af7.yaml`
- `case_study/cases/eval_commits/eval-aya-2d79f22b4022.yaml`
- `case_study/cases/eval_commits/eval-aya-62c6dfd764ce.yaml`
- `case_study/cases/eval_commits/eval-aya-ca0c32d1076a.yaml`
- `case_study/cases/eval_commits/eval-aya-fc69a0697274.yaml`
- `case_study/cases/eval_commits/eval-cilium-3740e9db8fef.yaml`
- `case_study/cases/eval_commits/eval-cilium-46024c6c4a30.yaml`
- `case_study/cases/eval_commits/eval-cilium-4dc7d8047caf.yaml`
- `case_study/cases/eval_commits/eval-cilium-50c319d0cbfe.yaml`
- `case_study/cases/eval_commits/eval-cilium-6b3c9f16c99f.yaml`
- `case_study/cases/eval_commits/eval-cilium-6e18eb020b68.yaml`
- `case_study/cases/eval_commits/eval-cilium-783648c20626.yaml`
- `case_study/cases/eval_commits/eval-cilium-847014aa62f9.yaml`
- `case_study/cases/eval_commits/eval-cilium-8dd5de960167.yaml`
- `case_study/cases/eval_commits/eval-cilium-de679382fe1e.yaml`
- `case_study/cases/eval_commits/eval-cilium-f51f4dfac542.yaml`
- `case_study/cases/eval_commits/eval-katran-5d1e2ca8b9d7.yaml`

## Updated Fix Type Distribution

| Fix type | Cases |
| --- | ---: |
| bounds_check | 7 |
| helper_switch | 2 |
| inline_hint | 4 |
| null_check | 3 |
| other | 9 |
| refactor | 13 |
| type_cast | 1 |

## Quality Issues Found

- All 21 original Eval files were invalid YAML before rewrite because scalar fields were serialized with stray `...` document-end markers.
- No hallucinated commit hashes or fabricated before/after snippets were found in the original 21 cases.
- Four original `diff_summary` fields were semantically too narrow because they did not name every changed code file; those summaries were corrected during rewrite.
- Added 18 new real git-backed Eval cases, bringing the corpus to 39 total cases.

