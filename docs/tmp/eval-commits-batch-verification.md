# Eval Commits Batch Verification

- Generated at: `2026-03-20T02:37:30+00:00`
- Host kernel: `6.15.11-061511-generic`
- Guest kernel: `5.10.0-39-amd64`

## Scope

- Candidate source: `case_study/cases/eval_commits/*.yaml`
- Selection policy: `promising == true` from `scripts/find_lowering_artifact_commits.py` scoring, then score-descending order.
- Promising candidates in full pool: `312`
- Supported C-repo candidates before any limit: `246`
- Supported C-repo candidates attempted here: `246`
- Skipped unsupported repos: `66`

## Unsupported Repos

- `aya`: `11` skipped
- `libbpf`: `55` skipped

## Summary

- Host buggy compile successes: `11`
- Host buggy verifier passes on 6.15: `7`
- Host fixed verifier passes on 6.15: `6`
- 5.10 buggy clean verifier rejects: `1`
- 5.10 buggy loader/BTF incompatibilities: `2`
- Confirmed lowering artifacts: `1`

## Per-Repo Breakdown

| Repo | Attempted | Buggy Compiled | Buggy 6.15 Pass | Fixed Compiled | Fixed 6.15 Pass | Buggy 5.10 Pass | Buggy 5.10 Verifier Reject | Buggy 5.10 Loader Incompat | Fixed 5.10 Pass | Confirmed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bcc | 16 | 8 | 7 | 8 | 6 | 4 | 1 | 2 | 5 | 1 |
| cilium | 222 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| katran | 8 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |

## Confirmed Cases

| Case | Repo | Score | Selected File | 5.10 Buggy Headline | 5.10 Fixed Headline |
| --- | --- | ---: | --- | --- | --- |
| `eval-bcc-89c7f409b4a6` | bcc | 4 | `libbpf-tools/ksnoop.bpf.c` | func#0 @0 | func#0 @0 |

## Interesting But Unconfirmed

| Case | Repo | Host Buggy | Host Fixed | Guest Buggy | Guest Fixed | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| `eval-bcc-952415e490bd` | bcc | pass | pass | loader_incompat | pass | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-bcc-d4e505c1e4ed` | bcc | pass | pass | loader_incompat | loader_incompat | buggy did not hit a clean verifier rejection on 5.10 |

## Full Results

| Case | Repo | Score | Buggy Compile | Buggy 6.15 | Fixed Compile | Fixed 6.15 | Buggy 5.10 | Fixed 5.10 | Selected File | Note |
| --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| `eval-cilium-02e696c855cf` | cilium | 8 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-bcc-45f5df4c5942` | bcc | 7 | yes | load_error | yes | load_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `libbpf-tools/numamove.bpf.c` | buggy did not pass on 6.15 |
| `eval-bcc-799acc7ca2c6` | bcc | 7 | yes | pass | yes | fail | pass | fixed_not_pass_on_6_15 | `libbpf-tools/softirqs.bpf.c` | fixed did not pass on 6.15 |
| `eval-bcc-8206f547b8e3` | bcc | 7 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-952415e490bd` | bcc | 7 | yes | pass | yes | pass | loader_incompat | pass | `libbpf-tools/biolatency.bpf.c` | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-bcc-b0f891d129a9` | bcc | 7 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-d4e505c1e4ed` | bcc | 7 | yes | pass | yes | pass | loader_incompat | loader_incompat | `libbpf-tools/bitesize.bpf.c` | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-cilium-5d882fdd1f8a` | cilium | 7 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-c3b65fce8b84` | cilium | 7 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-ebb781e5ba1b` | cilium | 7 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-katran-918c0e169773` | katran | 7 | yes | load_error | yes | load_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/lib/bpf/balancer_kern.c` | buggy did not pass on 6.15 |
| `eval-katran-d195c045a01b` | katran | 7 | yes | load_error | yes | load_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/lib/bpf/balancer_kern.c` | buggy did not pass on 6.15 |
| `eval-bcc-118bf168f9f6` | bcc | 6 | yes | pass | yes | pass | pass | pass | `libbpf-tools/tcpconnect.bpf.c` | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-bcc-1d659c7f3388` | bcc | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-2070a2aefb0b` | bcc | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-f2006eaa5901` | bcc | 6 | yes | pass | yes | pass | pass | pass | `libbpf-tools/cpufreq.bpf.c` | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-cilium-0279a19a34bd` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-040d264ebcd7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-064b947efb86` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/custom/bpf_custom.c` | buggy did not pass on 6.15 |
| `eval-cilium-0a4a393d6554` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-0ab817e77209` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-0ae984552b8f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-0cf109933350` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/l4lb_ipip_health_check_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-0d89f055806d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-0f11ce8d87c2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-1085ae269e71` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-108aa4212f8e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-11e5f5936631` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-12e29221d278` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-12e3ae9936bd` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-13f2cd0a889c` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-13f2d90daada` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-142c0f7128c7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-14a653ad4aac` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-181ed5a73517` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-1915b7348367` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-1a5596de414a` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-1b6a98ccf809` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-1b95d351eb76` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-1c000f5f4726` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-1e25adb69b44` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-210b5866e0f5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-227ed483633c` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-239711b71174` | cilium | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-cilium-275856b1650f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-27eda2c934dd` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-28dfbaaeaeaf` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/sockops/bpf_redir.c` | buggy did not pass on 6.15 |
| `eval-cilium-2a0bc762c095` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-2a1db392b3ca` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipsec_redirect_tunnel.c` | buggy did not pass on 6.15 |
| `eval-cilium-2a6780cf8afb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-2ba0b4fd4bff` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-2c3263a80020` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_lxc_policy_drop.c` | buggy did not pass on 6.15 |
| `eval-cilium-2c9c8c17aeeb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-2f0275ee3ee2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_nat_lb.c` | buggy did not pass on 6.15 |
| `eval-cilium-2f950671d3ea` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-2ff1a462cd33` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_prefilter.c` | buggy did not pass on 6.15 |
| `eval-cilium-3076311add63` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-31a01b994f8b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_icmp4_snat.c` | buggy did not pass on 6.15 |
| `eval-cilium-321ec097bcf1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-3310f6906cd1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-3323fb0c62a9` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock_term.c` | buggy did not pass on 6.15 |
| `eval-cilium-37308ef267eb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-380833eabae3` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-394e72478a8d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-3a3f4e1815f2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-3a51667c088b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/classifiers_l2_dev.c` | buggy did not pass on 6.15 |
| `eval-cilium-3a93b00269b1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-3b0d61abe2b1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-3c3e7692b8f2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-3df7fb4313ee` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-3f0c2b71bab6` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/nat_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-3f356b0156d8` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-405ac1549f53` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-40c582aed330` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-412fc8437c4f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipsec_redirect_tunnel.c` | buggy did not pass on 6.15 |
| `eval-cilium-416456de4253` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-442003456364` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipv6_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-47bd87551277` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_netdev.c` | buggy did not pass on 6.15 |
| `eval-cilium-47eae08f915e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-48486304df0f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/l4lb_ipip_health_check_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-4866264f77d1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-489da3e3f924` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-4b8ad8fa6bd8` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-4cba4f153b9b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-4d36cac2ee63` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-4dbbe2aa8c90` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-4fa26a4105eb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-4ff4a0ee93fa` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-50831aee16a9` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-514825596e44` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_wireguard.c` | buggy did not pass on 6.15 |
| `eval-cilium-515b99559972` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-52b565fa30cb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-5322af54a581` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-53339a8f44e3` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-536ad0c9a322` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/custom/bpf_custom.c` | buggy did not pass on 6.15 |
| `eval-cilium-5745846a5212` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-5a76cf2c5e96` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-5b05cc92dd66` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-5b3a32131da6` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-5bb58205d955` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-5cdd3258dca5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-5ddedadc81f2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipfrag.c` | buggy did not pass on 6.15 |
| `eval-cilium-5e1139d09b2d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-5f9c8fbbe2d3` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-6693e11d50c9` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-66b60bcad811` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/classifiers_l2_dev.c` | buggy did not pass on 6.15 |
| `eval-cilium-6c91da4815a5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-6da3cb628d63` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-6e343142bf22` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/custom/bpf_custom.c` | buggy did not pass on 6.15 |
| `eval-cilium-724a101aed68` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-7350d08e9059` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_egressgw_redirect_from_overlay_with_egress_interface.c` | buggy did not pass on 6.15 |
| `eval-cilium-737262d8d52d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-7600599e8d7e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_netdev.c` | buggy did not pass on 6.15 |
| `eval-cilium-78a771f361f5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_wireguard.c` | buggy did not pass on 6.15 |
| `eval-cilium-7b72cc4d60e4` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-7c2ace918c2f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-7c3ba66895f8` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_nat_lb.c` | buggy did not pass on 6.15 |
| `eval-cilium-7c9a45a2fd28` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-7de434985f89` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_netdev.c` | buggy did not pass on 6.15 |
| `eval-cilium-7e8aee152484` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-7fa2782adde0` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-80a3023ddb74` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-81f68d69ca95` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-854473726b50` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_wireguard.c` | buggy did not pass on 6.15 |
| `eval-cilium-86c904761b39` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-87855a957541` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-892316d8df68` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-8a2b370692cd` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-8be6990e265e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-8c8459f42308` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-8f9bab723dd5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_icmp4_snat.c` | buggy did not pass on 6.15 |
| `eval-cilium-90ddfb3fcf3f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-911ccd86df5f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-9141129561ff` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-959b24a8135e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-968227de9cc5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-97283583e26c` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-99070f653924` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-9987e4816d1a` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-99ac9998471f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat6_netdev_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-9b644fc3fb8f` | cilium | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-cilium-9cbb6e594247` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-9de5f4338c9d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-9f27973a1052` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/sockops/bpf_redir.c` | buggy did not pass on 6.15 |
| `eval-cilium-9f4d267c1edb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_lb6_dsr_backend.c` | buggy did not pass on 6.15 |
| `eval-cilium-9f8b2a99a9d4` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipfrag.c` | buggy did not pass on 6.15 |
| `eval-cilium-a04698e3b464` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-a0d059e1192e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-a0ec2ad991c3` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-a156825297d2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-a1d54e34f68f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-a2086bcc5b3c` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-a495abda8528` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-a4e3bd900e3b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-a75f49716581` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-a7625471733f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_hostdev_ingress.c` | buggy did not pass on 6.15 |
| `eval-cilium-a78f75e1eb1d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-a8813d5fac61` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/sockops/bpf_sockops.c` | buggy did not pass on 6.15 |
| `eval-cilium-a9679280e805` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-aa7180eb3463` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_xdp.c` | buggy did not pass on 6.15 |
| `eval-cilium-ab329d2efb46` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-ad0d3cf34140` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-b156a3abae71` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_probes.c` | buggy did not pass on 6.15 |
| `eval-cilium-b4a0fa7425c7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_nat6_netdev_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-b6d2dc67fe83` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-b7af6e8ffda1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-b817c50f4a17` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-b8e041db503b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-bb0126fdafcf` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-bb0f6d8213aa` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-bbf57970f552` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_icmp4_snat.c` | buggy did not pass on 6.15 |
| `eval-cilium-bc41a39e8519` | cilium | 6 | no | materialization_error: CalledProcessError: Command '['git', 'show', 'b1605abae9760f0422213de0ccce73ac931359ca:bpf/tests/builtins.c']' returned non-zero exit status 128. | no | materialization_error: CalledProcessError: Command '['git', 'show', 'b1605abae9760f0422213de0ccce73ac931359ca:bpf/tests/builtins.c']' returned non-zero exit status 128. | host_materialization_error | host_materialization_error | `None` | buggy did not pass on 6.15 |
| `eval-cilium-bd8b4d0ee3ee` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/custom/bpf_custom.c` | buggy did not pass on 6.15 |
| `eval-cilium-bd8c73cdff24` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-bfaef16f3485` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/cilium-map-migrate.c` | buggy did not pass on 6.15 |
| `eval-cilium-c02c41fb3875` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-c046309b0ff5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-c36986184bff` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-c46c0ed0e7d0` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_hostdev_ingress.c` | buggy did not pass on 6.15 |
| `eval-cilium-c5836de699b1` | cilium | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-cilium-c69d8cb801e5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-c7083543e993` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-c862a7157bb0` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-ccf7965e28a7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-cd5cdc35b9cd` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-cdd6694c94ac` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-ce6f2c7729df` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/sockops/bpf_redir.c` | buggy did not pass on 6.15 |
| `eval-cilium-ceaa4c42b010` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipv6_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-cf3976af0d06` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_srv6_decap.c` | buggy did not pass on 6.15 |
| `eval-cilium-cf88cad9bbdb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-d2b63414e57e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_lb6_dsr_backend.c` | buggy did not pass on 6.15 |
| `eval-cilium-d3ff998f2b30` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-d538b1fa9d39` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-d7c5c0c7062f` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-d7f58e84d878` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-da04e683faeb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/nat_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-dbc0d32daf17` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-dc5dd36fef04` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/l4lb_ipip_health_check_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-dcc3dcf02e71` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/conntrack_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-dfa8bb8ab3f0` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-e2760e62db78` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-e336073818b6` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/builtins.c` | buggy did not pass on 6.15 |
| `eval-cilium-e38a92115620` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-e43c2fff3749` | cilium | 6 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-cilium-e4c1ec7f9123` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-e5df587754e0` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-e62eb70cf03d` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-e80be9ebffd4` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_l2_announcement.c` | buggy did not pass on 6.15 |
| `eval-cilium-e9438c20e7d1` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_host.c` | buggy did not pass on 6.15 |
| `eval-cilium-e9bf184e3ddc` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-eca1f331b2f7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-ee5f473199ac` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/bpf_ct_tests.c` | buggy did not pass on 6.15 |
| `eval-cilium-eeca01efc0b7` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/tc_nodeport_lb6_dsr_backend.c` | buggy did not pass on 6.15 |
| `eval-cilium-efd1ad80bd4e` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_alignchecker.c` | buggy did not pass on 6.15 |
| `eval-cilium-f132c2a4dd27` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-f1a2789dbccc` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_hostdev_ingress.c` | buggy did not pass on 6.15 |
| `eval-cilium-f1c3c71f0003` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_sock.c` | buggy did not pass on 6.15 |
| `eval-cilium-f244861ad34b` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_network.c` | buggy did not pass on 6.15 |
| `eval-cilium-f67260a842eb` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-fbbf549c6865` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-fc388cb6d2f9` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/nat_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-fcbd5d780bc5` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_overlay.c` | buggy did not pass on 6.15 |
| `eval-cilium-ff65a2bd28f2` | cilium | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/xdp_nodeport_lb4_nat_lb.c` | buggy did not pass on 6.15 |
| `eval-katran-1c79d8c6db85` | katran | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/lib/bpf/balancer_kern.c` | buggy did not pass on 6.15 |
| `eval-katran-5d1e2ca8b9d7` | katran | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/decap/bpf/decap_kern.c` | buggy did not pass on 6.15 |
| `eval-katran-745374f1cf04` | katran | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/decap/bpf/decap.bpf.c` | buggy did not pass on 6.15 |
| `eval-katran-a20ebf46f0d5` | katran | 6 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/decap/bpf/decap.bpf.c` | buggy did not pass on 6.15 |
| `eval-katran-d4edcd2c5a99` | katran | 6 | yes | load_error | yes | load_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/lib/bpf/balancer_kern.c` | buggy did not pass on 6.15 |
| `eval-bcc-a75f0180b714` | bcc | 5 | yes | pass | yes | pass | pass | pass | `libbpf-tools/tcprtt.bpf.c` | buggy did not hit a clean verifier rejection on 5.10 |
| `eval-bcc-8319d52dc883` | bcc | 4 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-89c7f409b4a6` | bcc | 4 | yes | pass | yes | pass | verifier_reject | pass | `libbpf-tools/ksnoop.bpf.c` | buggy passes on 6.15, cleanly rejects on 5.10, fixed passes on both |
| `eval-bcc-f09b5b8acdd5` | bcc | 4 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-f6c8cfe4244a` | bcc | 4 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-bcc-feadea6d789f` | bcc | 4 | no | no_target_file | no | no_target_file | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `None` | buggy did not pass on 6.15 |
| `eval-cilium-06c6520c57ad` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_ipsec.c` | buggy did not pass on 6.15 |
| `eval-cilium-22af6b5c8c09` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-71f8962acd55` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/tests/ipv6_test.c` | buggy did not pass on 6.15 |
| `eval-cilium-848d41d1909b` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_netdev.c` | buggy did not pass on 6.15 |
| `eval-cilium-8cfe6efe6aa2` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-95bc719aede5` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-ad936f16d68f` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/probes/raw_main.c` | buggy did not pass on 6.15 |
| `eval-cilium-d3edaec19789` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/sockops/bpf_redir.c` | buggy did not pass on 6.15 |
| `eval-cilium-f19a97a47f8c` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-cilium-fdca23e2b23f` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_hostdev_ingress.c` | buggy did not pass on 6.15 |
| `eval-cilium-ff54dbd703b6` | cilium | 4 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `bpf/bpf_lxc.c` | buggy did not pass on 6.15 |
| `eval-katran-07e10334022f` | katran | 1 | no | compile_error | no | compile_error | buggy_not_pass_on_6_15 | fixed_not_pass_on_6_15 | `katran/lib/bpf/balancer_kern.c` | buggy did not pass on 6.15 |
