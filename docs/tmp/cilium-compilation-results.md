# Cilium Eval Commits Compilation Results

- Generated at: `2026-03-20T03:04:03+00:00`
- Cilium repo: `/tmp/cilium-repo` @ `cf9dfdfe2a2bc0b1702f732f11cd612a98ba6b2d`
- Include roots: `/tmp/cilium-repo/bpf`, `/tmp/cilium-repo/bpf/lib`, `/tmp/cilium-repo/bpf/include`
- Selection: top `50` `eval-cilium-*` cases sorted by heuristic score descending, then `case_id` ascending

## Summary

- Snippet compile successes: `1` / `50`
- Actual-file fallback attempted: `49` / `50`
- Actual-file compile successes: `42` / `49`
- Final compile successes: `43` / `50`
- Final load successes: `0` / `43`
- Final verifier rejects with captured load log: `0`

## Common Failures

### Snippet Compile

- `7` x prog.c:3:3: error: expected identifier or '('
- `3` x prog.c:3:4: error: expected identifier or '('
- `2` x prog.c:3:2: error: expected identifier or '('
- `2` x prog.c:3:3: error: extraneous closing brace ('}')
- `2` x prog.c:3:2: error: extraneous closing brace ('}')

### Actual File Compile

- `2` x builtins.h:232:3: error: A call to built-in function 'abort' is not supported.
- `1` x lb.h:638:9: error: 0x59f16ed67820: i64 = GlobalAddress<ptr @l4_modify_port> 0, lb.h:638:9 @[ lb.h:682:9 @[ bpf_lxc.c:498:9 @[ bpf_lxc.c:7...
- `1` x lb.h:591:9: error: 0x5e03f9bd6640: i64 = GlobalAddress<ptr @l4_modify_port> 0, lb.h:591:9 @[ lb.h:714:9 @[ bpf_lxc.c:115:9 @[ bpf_lxc.c:3...
- `1` x builtins.h:21:31: error: unknown type name '__u8'
- `1` x builtins.h:231:3: error: A call to built-in function 'abort' is not supported.

### Load

- `31` x libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+
- `5` x libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported
- `3` x libbpf: sec 'tc/tail': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported
- `1` x libbpf: failed to guess program type from ELF section 'custom'
- `1` x libbpf: sec 'xdp/tail': program 'tail_nodeport_rev_dnat_ipv4' is static and not supported

## Results

| Case | Score | Commit | Declared File | Actual File | Snippet | Actual | Final | Load | Note |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| `eval-cilium-02e696c855cf` | 8 | `02e696c855cf` | `bpf/lib/nat.h` | `bpf/bpf_alignchecker.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-5d882fdd1f8a` | 7 | `5d882fdd1f8a` | `bpf/lib/lxc.h` | `bpf/bpf_lxc.c` | no | no | `none` | `n/a` | lb.h:638:9: error: 0x59f16ed67820: i64 = GlobalAddress<ptr @l4_modify_port> 0, lb.h:638:9 @[ lb.h:682:9 @[ bpf_lxc.c:... |
| `eval-cilium-c3b65fce8b84` | 7 | `c3b65fce8b84` | `bpf/include/bpf/ctx/xdp.h` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-ebb781e5ba1b` | 7 | `ebb781e5ba1b` | `bpf/sockops/bpf_sockops.h` | `bpf/bpf_alignchecker.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-0279a19a34bd` | 6 | `0279a19a34bd` | `bpf/bpf_lxc.c` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-040d264ebcd7` | 6 | `040d264ebcd7` | `bpf/bpf_sock.c` | `bpf/bpf_sock.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-064b947efb86` | 6 | `064b947efb86` | `bpf/lib/common.h` | `bpf/custom/bpf_custom.c` | no | yes | `actual_file` | `loader_error` | libbpf: failed to guess program type from ELF section 'custom' |
| `eval-cilium-0a4a393d6554` | 6 | `0a4a393d6554` | `bpf/bpf_sock.c` | `bpf/bpf_sock.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-0ab817e77209` | 6 | `0ab817e77209` | `bpf/lib/nodeport.h` | `bpf/tests/xdp_nodeport_lb4_test.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec 'xdp/tail': program 'tail_nodeport_rev_dnat_ipv4' is static and not supported |
| `eval-cilium-0ae984552b8f` | 6 | `0ae984552b8f` | `bpf/lib/ipv6.h` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-0cf109933350` | 6 | `0cf109933350` | `bpf/lib/lb.h` | `bpf/tests/l4lb_ipip_health_check_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec 'tc/tail': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-0d89f055806d` | 6 | `0d89f055806d` | `bpf/bpf_host.c` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-0f11ce8d87c2` | 6 | `0f11ce8d87c2` | `bpf/bpf_lxc.c` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-1085ae269e71` | 6 | `1085ae269e71` | `bpf/bpf_host.c` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-108aa4212f8e` | 6 | `108aa4212f8e` | `bpf/lib/proxy.h` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-11e5f5936631` | 6 | `11e5f5936631` | `bpf/lib/nodeport.h` | `bpf/tests/xdp_nodeport_lb4_test.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-12e29221d278` | 6 | `12e29221d278` | `bpf/bpf_xdp.c` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-12e3ae9936bd` | 6 | `12e3ae9936bd` | `bpf/lib/srv6.h` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-13f2cd0a889c` | 6 | `13f2cd0a889c` | `bpf/lib/srv6.h` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-13f2d90daada` | 6 | `13f2d90daada` | `bpf/bpf_host.c` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-142c0f7128c7` | 6 | `142c0f7128c7` | `bpf/lib/policy.h` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-14a653ad4aac` | 6 | `14a653ad4aac` | `bpf/lib/nat.h` | `bpf/tests/xdp_nodeport_lb4_test.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-181ed5a73517` | 6 | `181ed5a73517` | `bpf/lib/encap.h` | `bpf/bpf_overlay.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-1915b7348367` | 6 | `1915b7348367` | `bpf/include/bpf/ctx/xdp.h` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-1a5596de414a` | 6 | `1a5596de414a` | `bpf/include/bpf/access.h` | `bpf/bpf_sock.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-1b6a98ccf809` | 6 | `1b6a98ccf809` | `bpf/bpf_lxc.c` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-1b95d351eb76` | 6 | `1b95d351eb76` | `bpf/bpf_sock.c` | `bpf/bpf_sock.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-1c000f5f4726` | 6 | `1c000f5f4726` | `bpf/lib/encap.h` | `bpf/bpf_overlay.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-1e25adb69b44` | 6 | `1e25adb69b44` | `bpf/lib/lxc.h` | `bpf/bpf_lxc.c` | no | no | `none` | `n/a` | lb.h:591:9: error: 0x5e03f9bd6640: i64 = GlobalAddress<ptr @l4_modify_port> 0, lb.h:591:9 @[ lb.h:714:9 @[ bpf_lxc.c:... |
| `eval-cilium-210b5866e0f5` | 6 | `210b5866e0f5` | `bpf/bpf_lxc.c` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec 'tc/tail': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-227ed483633c` | 6 | `227ed483633c` | `bpf/bpf_host.c` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-239711b71174` | 6 | `239711b71174` | `bpf/include/bpf/builtins.h` | `bpf/include/bpf/builtins.h` | no | no | `none` | `n/a` | builtins.h:21:31: error: unknown type name '__u8' |
| `eval-cilium-275856b1650f` | 6 | `275856b1650f` | `bpf/lib/nodeport.h` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-27eda2c934dd` | 6 | `27eda2c934dd` | `bpf/include/bpf/verifier.h` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-28dfbaaeaeaf` | 6 | `28dfbaaeaeaf` | `bpf/lib/lb.h` | `bpf/sockops/bpf_redir.c` | no | yes | `actual_file` | `loader_error` | libbpf: map 'test_cilium_ep_to_policy': failed to create: -EINVAL |
| `eval-cilium-2a0bc762c095` | 6 | `2a0bc762c095` | `bpf/lib/encap.h` | `bpf/bpf_overlay.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-2a1db392b3ca` | 6 | `2a1db392b3ca` | `bpf/lib/overloadable_skb.h` | `bpf/tests/ipsec_redirect_tunnel.c` | no | no | `none` | `n/a` | builtins.h:231:3: error: A call to built-in function 'abort' is not supported. |
| `eval-cilium-2a6780cf8afb` | 6 | `2a6780cf8afb` | `bpf/bpf_lxc.c` | `bpf/bpf_lxc.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-2ba0b4fd4bff` | 6 | `2ba0b4fd4bff` | `bpf/include/bpf/ctx/xdp.h` | `bpf/bpf_xdp.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-2c3263a80020` | 6 | `2c3263a80020` | `bpf/include/bpf/helpers.h` | `bpf/tests/tc_lxc_policy_drop.c` | no | no | `none` | `n/a` | builtins.h:232:3: error: A call to built-in function 'abort' is not supported. |
| `eval-cilium-2c9c8c17aeeb` | 6 | `2c9c8c17aeeb` | `bpf/bpf_host.c` | `bpf/bpf_overlay.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-2f0275ee3ee2` | 6 | `2f0275ee3ee2` | `bpf/tests/tc_nodeport_lb4_dsr_backend.c` | `bpf/tests/xdp_nodeport_lb4_nat_lb.c` | no | no | `none` | `n/a` | builtins.h:232:3: error: A call to built-in function 'abort' is not supported. |
| `eval-cilium-2f950671d3ea` | 6 | `2f950671d3ea` | `bpf/bpf_host.c` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-2ff1a462cd33` | 6 | `2ff1a462cd33` | `bpf/include/bpf/ctx/xdp.h` | `bpf/bpf_prefilter.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-3076311add63` | 6 | `3076311add63` | `bpf/bpf_host.c` | `bpf/bpf_host.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec '2/18': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-31a01b994f8b` | 6 | `31a01b994f8b` | `bpf/lib/nat.h` | `bpf/tests/tc_nodeport_icmp4_snat.c` | no | yes | `actual_file` | `loader_error` | libbpf: sec 'tc/tail': program 'tail_nodeport_rev_dnat_ingress_ipv6' is static and not supported |
| `eval-cilium-321ec097bcf1` | 6 | `321ec097bcf1` | `bpf/lib/conntrack.h` | `bpf/tests/bpf_ct_tests.c` | no | no | `none` | `n/a` | bpf_ct_tests.c:73:19: error: use of undeclared identifier 'test_cilium_ct_tcp4_65535' |
| `eval-cilium-3310f6906cd1` | 6 | `3310f6906cd1` | `bpf/lib/nodeport.h` | `bpf/tests/xdp_nodeport_lb4_test.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
| `eval-cilium-3323fb0c62a9` | 6 | `3323fb0c62a9` | `bpf/include/bpf/compiler.h` | `None` | yes | n/a | `snippet` | `loader_error` | Error: object file doesn't contain any bpf program |
| `eval-cilium-37308ef267eb` | 6 | `37308ef267eb` | `bpf/bpf_host.c` | `bpf/bpf_overlay.c` | no | yes | `actual_file` | `loader_error` | libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+ |
