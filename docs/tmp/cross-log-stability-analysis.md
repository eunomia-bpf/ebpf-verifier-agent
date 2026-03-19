# Cross-Log Stability Analysis

Date: 2026-03-11

## Scope

- Scanned `33` case YAMLs with multiple `verifier_log.blocks` under `case_study/cases/`.
- Source buckets represented: `11` GitHub issue cases and `22` Stack Overflow cases.
- Included the 6 feasibility-report examples plus every other case whose `verifier_log.blocks` list has length > 1.
- `stable BPFix diagnosis` means every block in a case keeps the same `(error_id, taxonomy_class)` pair.
- `raw text unstable` means the extracted raw error lines are not all identical; pairwise similarity uses whitespace-token Jaccard.

## Aggregate

- Stable BPFix diagnosis: `20/33` (60.6%).
- Unstable raw error text but stable BPFix `error_id`: `12/33` (36.4%).
- Stable `root_cause_insn`: `14/33` (42.4%).
- Stable `proof_status`: `15/33` (45.5%).
- Stable raw error line text after report-side extraction: `13/33` (39.4%).

## Feasibility-Report Cases

| case | blocks | error_id stable | taxonomy stable | root stable | proof stable | raw text stable | min Jaccard | avg Jaccard |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| github-cilium-cilium-37478 | 5 | no | no | no | no | no | 0.160 | 0.528 |
| github-cilium-cilium-36936 | 4 | yes | yes | no | no | no | 0.233 | 0.447 |
| github-cilium-cilium-41996 | 2 | yes | yes | no | no | no | 0.375 | 0.375 |
| stackoverflow-75515263 | 2 | yes | yes | yes | yes | no | 0.778 | 0.778 |
| stackoverflow-69413427 | 3 | yes | yes | no | no | no | 0.750 | 0.833 |
| github-aya-rs-aya-1233 | 2 | yes | yes | yes | yes | yes | 1.000 | 1.000 |

## All Multi-Block Cases

| case | bucket | blocks | diag stable | root stable | proof stable | raw text stable | min Jaccard | avg Jaccard |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| github-aya-rs-aya-1233 | github_issues | 2 | yes | yes | yes | yes | 1.000 | 1.000 |
| github-cilium-cilium-36936 | github_issues | 4 | yes | no | no | no | 0.233 | 0.447 |
| github-cilium-cilium-37478 | github_issues | 5 | no | no | no | no | 0.160 | 0.528 |
| github-cilium-cilium-41996 | github_issues | 2 | yes | no | no | no | 0.375 | 0.375 |
| stackoverflow-69413427 | stackoverflow | 3 | yes | no | no | no | 0.750 | 0.833 |
| stackoverflow-75515263 | stackoverflow | 2 | yes | yes | yes | no | 0.778 | 0.778 |
| github-aya-rs-aya-1056 | github_issues | 2 | yes | no | no | no | 0.000 | 0.000 |
| github-aya-rs-aya-1062 | github_issues | 3 | yes | no | no | no | 0.000 | 0.333 |
| github-aya-rs-aya-1324 | github_issues | 2 | yes | yes | yes | yes | 1.000 | 1.000 |
| github-cilium-cilium-35182 | github_issues | 2 | yes | yes | yes | yes | 1.000 | 1.000 |
| github-cilium-cilium-41412 | github_issues | 3 | yes | no | no | no | 0.077 | 0.385 |
| github-cilium-cilium-41522 | github_issues | 3 | no | no | no | no | 0.231 | 0.487 |
| github-cilium-cilium-44216 | github_issues | 2 | yes | yes | yes | no | 0.700 | 0.700 |
| stackoverflow-48267671 | stackoverflow | 2 | no | yes | yes | no | 0.026 | 0.026 |
| stackoverflow-67679109 | stackoverflow | 2 | yes | yes | yes | yes | 1.000 | 1.000 |
| stackoverflow-70721661 | stackoverflow | 2 | yes | no | no | no | 0.000 | 0.000 |
| stackoverflow-70729664 | stackoverflow | 4 | no | no | no | no | 0.000 | 0.179 |
| stackoverflow-70750259 | stackoverflow | 3 | yes | no | yes | no | 0.158 | 0.439 |
| stackoverflow-70873332 | stackoverflow | 2 | yes | no | yes | yes | 1.000 | 1.000 |
| stackoverflow-71946593 | stackoverflow | 2 | yes | yes | yes | yes | 1.000 | 1.000 |
| stackoverflow-72005172 | stackoverflow | 3 | no | no | no | no | 0.000 | 0.333 |
| stackoverflow-72575736 | stackoverflow | 2 | no | no | no | yes | 1.000 | 1.000 |
| stackoverflow-74178703 | stackoverflow | 2 | no | yes | yes | yes | 1.000 | 1.000 |
| stackoverflow-76960866 | stackoverflow | 3 | yes | no | no | no | 0.500 | 0.562 |
| stackoverflow-77673256 | stackoverflow | 2 | no | no | no | yes | 1.000 | 1.000 |
| stackoverflow-77713434 | stackoverflow | 2 | yes | yes | yes | no | 0.182 | 0.182 |
| stackoverflow-78525670 | stackoverflow | 2 | no | yes | yes | no | 0.200 | 0.200 |
| stackoverflow-78591601 | stackoverflow | 2 | no | yes | yes | no | 0.118 | 0.118 |
| stackoverflow-78958420 | stackoverflow | 2 | no | no | no | yes | 1.000 | 1.000 |
| stackoverflow-79348306 | stackoverflow | 2 | yes | yes | no | yes | 1.000 | 1.000 |
| stackoverflow-79485758 | stackoverflow | 2 | no | no | no | yes | 1.000 | 1.000 |
| stackoverflow-79530762 | stackoverflow | 3 | no | no | no | no | 0.000 | 0.333 |
| stackoverflow-79812509 | stackoverflow | 2 | yes | yes | yes | yes | 1.000 | 1.000 |

## Per-Block Detail

`stable?` below is case-level diagnosis stability for the whole case, repeated on each block row.

| case | block# | raw error line | BPFix error_id | taxonomy_class | stable? |
| --- | --- | --- | --- | --- | --- |
| github-aya-rs-aya-1233 | 1 | program of this type cannot use helper bpf_probe_read#4 | BPFIX-E009 | env_mismatch | yes |
| github-aya-rs-aya-1233 | 2 | program of this type cannot use helper bpf_probe_read#4 | BPFIX-E009 | env_mismatch | yes |
| github-cilium-cilium-36936 | 1 | attaching cilium_host: loading eBPF collection into the kernel: program tail_handle_ipv4_from_host: load program: permission denied: 127: (… | BPFIX-E002 | source_bug | yes |
| github-cilium-cilium-36936 | 2 | R1 invalid mem access 'map_value_or_null' (183 line(s) omitted)" | BPFIX-E002 | source_bug | yes |
| github-cilium-cilium-36936 | 3 | R1 invalid mem access 'map_value_or_null' (183 line(s) omitted)" | BPFIX-E002 | source_bug | yes |
| github-cilium-cilium-36936 | 4 | 2025-01-10T17:54:26.027023483Z Verifier error: program tail_handle_ipv4_from_host: load program: permission denied: 127: (61) r9 = *(u32 *)… | BPFIX-E002 | source_bug | yes |
| github-cilium-cilium-37478 | 1 | Verifier error: program tail_handle_snat_fwd_ipv4: load program: permission denied: 2908: (69) r5 = *(u16 *)(r1 +36): R1 invalid mem access… | BPFIX-E005 | lowering_artifact | no |
| github-cilium-cilium-37478 | 2 | R1 invalid mem access 'map_value_or_null' | BPFIX-E002 | source_bug | no |
| github-cilium-cilium-37478 | 3 | R3 invalid mem access 'map_value_or_null' | BPFIX-E002 | source_bug | no |
| github-cilium-cilium-37478 | 4 | R3 invalid mem access 'map_value_or_null' | BPFIX-E002 | source_bug | no |
| github-cilium-cilium-37478 | 5 | > R3 invalid mem access 'map_value_or_null' | BPFIX-E002 | source_bug | no |
| github-cilium-cilium-41996 | 1 | Error regenerating endpoint: attaching cilium_host: loading eBPF collection into the kernel: program tail_nodeport_nat_egress_ipv4: load pr… | BPFIX-E011 | source_bug | yes |
| github-cilium-cilium-41996 | 2 | 1074: (71) r1 = *(u8 *)(r2 +23): R2 invalid mem access 'inv' | BPFIX-E011 | source_bug | yes |
| stackoverflow-69413427 | 1 | R2 type=inv expected=fp, pkt, pkt_meta, map_key, map_value | BPFIX-E023 | source_bug | yes |
| stackoverflow-69413427 | 2 | R2 type=ptr_ expected=fp, pkt, pkt_meta, map_key, map_value | BPFIX-E023 | source_bug | yes |
| stackoverflow-69413427 | 3 | R2 type=inv expected=fp, pkt, pkt_meta, map_key, map_value | BPFIX-E023 | source_bug | yes |
| stackoverflow-75515263 | 1 | invalid access to map value, value_size=8 off=8 size=2 | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-75515263 | 2 | invalid access to map value, value_size=8 off=8 size=8 | BPFIX-E005 | lowering_artifact | yes |
| github-aya-rs-aya-1056 | 1 | Invalid argument (os error 22) | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1056 | 2 | math between fp pointer and register with unbounded min value is not allowed | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1062 | 1 | R2 min value is negative, either use unsigned or 'var &= const' | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1062 | 2 | Invalid argument (os error 22) | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1062 | 3 | R2 min value is negative, either use unsigned or 'var &= const' | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1324 | 1 | 0: the BPF_PROG_LOAD syscall failed. Verifier output: fd 12 is not pointing to valid bpf_map | BPFIX-E018 | verifier_limit | yes |
| github-aya-rs-aya-1324 | 2 | 0: the BPF_PROG_LOAD syscall failed. Verifier output: fd 12 is not pointing to valid bpf_map | BPFIX-E018 | verifier_limit | yes |
| github-cilium-cilium-35182 | 1 | arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | BPFIX-E021 | env_mismatch | yes |
| github-cilium-cilium-35182 | 2 | arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | BPFIX-E021 | env_mismatch | yes |
| github-cilium-cilium-41412 | 1 | bpf_test.go:170: verifier error: load program: operation not supported: | BPFIX-E018 | verifier_limit | yes |
| github-cilium-cilium-41412 | 2 | Error: failed to load object file | BPFIX-E018 | verifier_limit | yes |
| github-cilium-cilium-41412 | 3 | bpf_test.go:170: verifier error: load program: operation not supported: | BPFIX-E018 | verifier_limit | yes |
| github-cilium-cilium-41522 | 1 | Verifier error: program cil_from_netdev: load program: permission denied: invalid access to packet, off=0 size=4, R4(id=0,off=0,r=0): R4 of… | BPFIX-E001 | source_bug | no |
| github-cilium-cilium-41522 | 2 | invalid access to packet, off=0 size=4, R4(id=0,off=0,r=0) | BPFIX-E006 | lowering_artifact | no |
| github-cilium-cilium-41522 | 3 | invalid access to packet, off=0 size=4, R4(id=0,off=0,r=0) | BPFIX-E006 | lowering_artifact | no |
| github-cilium-cilium-44216 | 1 | kern: warning: [2026-02-06T01:31:33.774559243Z]: ---[ end trace 0000000000000000 ]--- | BPFIX-E010 | verifier_bug | yes |
| github-cilium-cilium-44216 | 2 | k8s-0: kern: warning: [2026-02-05T19:14:13.467216703Z]: ---[ end trace 0000000000000000 ]--- | BPFIX-E010 | verifier_bug | yes |
| stackoverflow-48267671 | 1 | libbpf: load bpf program failed: Invalid argument | None | None | no |
| stackoverflow-48267671 | 2 | EINVAL For BPF_PROG_LOAD, indicates an attempt to load an invalid program. eBPF programs can be deemed invalid due to unrecognized instruct… | BPFIX-E009 | env_mismatch | no |
| stackoverflow-67679109 | 1 | R8 invalid mem access 'inv' | BPFIX-E011 | source_bug | yes |
| stackoverflow-67679109 | 2 | R8 invalid mem access 'inv' | BPFIX-E011 | source_bug | yes |
| stackoverflow-70721661 | 1 | libbpf: load bpf program failed: Permission denied | BPFIX-E001 | source_bug | yes |
| stackoverflow-70721661 | 2 | invalid access to packet, off=30 size=4, R1(id=0,off=30,r=14) | BPFIX-E001 | source_bug | yes |
| stackoverflow-70729664 | 1 | invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-70729664 | 2 | invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0) | BPFIX-E001 | source_bug | no |
| stackoverflow-70729664 | 3 | 2934: (79) r1 = *(u64 *)(r10 -32) | None | None | no |
| stackoverflow-70729664 | 4 | 2782: (69) r2 = *(u16 *)(r8 +2) | None | None | no |
| stackoverflow-70750259 | 1 | math between pkt pointer and register with unbounded min value is not allowed | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-70750259 | 2 | value -2147483648 makes pkt pointer be out of bounds | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-70750259 | 3 | math between pkt pointer and register with unbounded min value is not allowed | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-70873332 | 1 | invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0) | BPFIX-E001 | source_bug | yes |
| stackoverflow-70873332 | 2 | invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0) | BPFIX-E001 | source_bug | yes |
| stackoverflow-71946593 | 1 | R1 invalid mem access 'inv' | BPFIX-E011 | source_bug | yes |
| stackoverflow-71946593 | 2 | R1 invalid mem access 'inv' | BPFIX-E011 | source_bug | yes |
| stackoverflow-72005172 | 1 | invalid access to packet, off=23 size=1, R1(id=0,off=23,r=15) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-72005172 | 2 | invalid access to packet, off=23 size=1, R1(id=0,off=23,r=15) | BPFIX-E001 | source_bug | no |
| stackoverflow-72005172 | 3 | 3: (bf) r3 = r1 | None | None | no |
| stackoverflow-72575736 | 1 | invalid access to packet, off=14 size=1, R1(id=2,off=14,r=13) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-72575736 | 2 | invalid access to packet, off=14 size=1, R1(id=2,off=14,r=13) | BPFIX-E001 | source_bug | no |
| stackoverflow-74178703 | 1 | invalid access to map value, value_size=1024 off=1024 size=1 | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-74178703 | 2 | invalid access to map value, value_size=1024 off=1024 size=1 | BPFIX-E017 | source_bug | no |
| stackoverflow-76960866 | 1 | 2023/08/22 19:01:25 loading objects: field KprobeInetAccept: program kprobe__inet_accept: load program: permission denied: 13: (79) r6 = *(… | BPFIX-E011 | source_bug | yes |
| stackoverflow-76960866 | 2 | 2023/08/22 19:13:49 loading objects: field KprobeInetAccept: program kprobe__inet_accept: load program: permission denied: 1: (69) r3 = *(u… | BPFIX-E011 | source_bug | yes |
| stackoverflow-76960866 | 3 | 2023/08/24 11:24:15 loading objects: field KprobeInetAccept: program kprobe__inet_accept: load program: permission denied: 20: (79) r3 = *(… | BPFIX-E011 | source_bug | yes |
| stackoverflow-77673256 | 1 | R1 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_ | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-77673256 | 2 | R1 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_ | BPFIX-E023 | source_bug | no |
| stackoverflow-77713434 | 1 | {"error": "field SyscallProbeRetRead: program syscall__probe_ret_read: load program: permission denied: invalid access to map value, value_… | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-77713434 | 2 | :invalid access to map value, value_size=70 off=0 size=16383 | BPFIX-E005 | lowering_artifact | yes |
| stackoverflow-78525670 | 1 | invalid unbounded variable-offset read from stack R2 | None | None | no |
| stackoverflow-78525670 | 2 | R2 invalid mem access 'scalar' | BPFIX-E011 | source_bug | no |
| stackoverflow-78591601 | 1 | invalid access to packet, off=74 size=4, R2(id=6,off=74,r=0) | BPFIX-E001 | source_bug | no |
| stackoverflow-78591601 | 2 | R2 unbounded memory access, make sure to bounds check any such access | None | None | no |
| stackoverflow-78958420 | 1 | invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-78958420 | 2 | invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63) | BPFIX-E001 | source_bug | no |
| stackoverflow-79348306 | 1 | R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_ | BPFIX-E023 | source_bug | yes |
| stackoverflow-79348306 | 2 | R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_ | BPFIX-E023 | source_bug | yes |
| stackoverflow-79485758 | 1 | invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-79485758 | 2 | invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0) | BPFIX-E001 | source_bug | no |
| stackoverflow-79530762 | 1 | invalid access to packet, off=33 size=1, R4(id=10,off=33,r=0) | BPFIX-E005 | lowering_artifact | no |
| stackoverflow-79530762 | 2 | invalid access to packet, off=33 size=1, R4(id=10,off=33,r=0) | BPFIX-E001 | source_bug | no |
| stackoverflow-79530762 | 3 | R8_w=invP(id=2,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 | None | None | no |
| stackoverflow-79812509 | 1 | R2 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_ | BPFIX-E011 | source_bug | yes |
| stackoverflow-79812509 | 2 | R2 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_ | BPFIX-E011 | source_bug | yes |

## Key Stable-Despite-Drift Examples

- `github-cilium-cilium-36936`: stable `BPFIX-E002` / `source_bug` across `4` blocks, but raw lines drifted (`min Jaccard = 0.233`, `avg = 0.447`).
  - `attaching cilium_host: loading eBPF collection into the kernel: program tail_handle_ipv4_from_host: load program: permi…`
  - `R1 invalid mem access 'map_value_or_null' (183 line(s) omitted)"`
  - `2025-01-10T17:54:26.027023483Z Verifier error: program tail_handle_ipv4_from_host: load program: permission denied: 127…`
- `github-cilium-cilium-41996`: stable `BPFIX-E011` / `source_bug` across `2` blocks, but raw lines drifted (`min Jaccard = 0.375`, `avg = 0.375`).
  - `Error regenerating endpoint: attaching cilium_host: loading eBPF collection into the kernel: program tail_nodeport_nat_…`
  - `1074: (71) r1 = *(u8 *)(r2 +23): R2 invalid mem access 'inv'`
- `stackoverflow-69413427`: stable `BPFIX-E023` / `source_bug` across `3` blocks, but raw lines drifted (`min Jaccard = 0.750`, `avg = 0.833`).
  - `R2 type=inv expected=fp, pkt, pkt_meta, map_key, map_value`
  - `R2 type=ptr_ expected=fp, pkt, pkt_meta, map_key, map_value`
- `stackoverflow-75515263`: stable `BPFIX-E005` / `lowering_artifact` across `2` blocks, but raw lines drifted (`min Jaccard = 0.778`, `avg = 0.778`).
  - `invalid access to map value, value_size=8 off=8 size=2`
  - `invalid access to map value, value_size=8 off=8 size=8`
- `github-aya-rs-aya-1056`: stable `BPFIX-E018` / `verifier_limit` across `2` blocks, but raw lines drifted (`min Jaccard = 0.000`, `avg = 0.000`).
  - `Invalid argument (os error 22)`
  - `math between fp pointer and register with unbounded min value is not allowed`

## Notable Unstable Target Cases

- `github-cilium-cilium-37478`: diagnosis is not stable across blocks (`BPFIX-E002/source_bug`, `BPFIX-E005/lowering_artifact`); `min Jaccard = 0.160`.
