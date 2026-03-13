# Repair Experiment V3: Raw Verifier Log vs OBLIGE Diagnostic (Local 20B Model)

- Generated: `2026-03-13T04:13:09+00:00`
- Model: local llama.cpp GPT-OSS 20B
- Selected cases: `56`
- Desired taxonomy targets: `{'lowering_artifact': 20, 'source_bug': 20, 'verifier_limit': 8, 'env_mismatch': 8}`
- Effective taxonomy targets: `{'lowering_artifact': 11, 'source_bug': 20, 'verifier_limit': 8, 'env_mismatch': 8}`
- Selected taxonomy counts: `{'lowering_artifact': 11, 'source_bug': 29, 'verifier_limit': 8, 'env_mismatch': 8}`
- BTF-misleading diagnostics suppressed in Condition B: `1`

Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.

## Overall Summary

| Condition | Location | Fix type | Root cause |
| --- | ---: | ---: | ---: |
| A (raw verifier log only) | 21/56 (37.5%) | 12/56 (21.4%) | 45/56 (80.4%) |
| B (raw log + OBLIGE diagnostic) | 22/56 (39.3%) | 16/56 (28.6%) | 47/56 (83.9%) |

## Summary By Taxonomy

| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 11 | 5/11 (45.5%) | 4/11 (36.4%) | 1/11 (9.1%) | 2/11 (18.2%) | 8/11 (72.7%) | 9/11 (81.8%) |
| `source_bug` | 29 | 10/29 (34.5%) | 13/29 (44.8%) | 9/29 (31.0%) | 11/29 (37.9%) | 25/29 (86.2%) | 26/29 (89.7%) |
| `verifier_limit` | 8 | 4/8 (50.0%) | 4/8 (50.0%) | 2/8 (25.0%) | 3/8 (37.5%) | 6/8 (75.0%) | 6/8 (75.0%) |
| `env_mismatch` | 8 | 2/8 (25.0%) | 1/8 (12.5%) | 0/8 (0.0%) | 0/8 (0.0%) | 6/8 (75.0%) | 6/8 (75.0%) |

## BTF-Suppression Analysis

- Cases where OBLIGE diagnostic was BTF-misleading → suppressed: `1`
- Cases with clean proof-analysis diagnostic: `55`

| Subset | Condition | Fix type | Location |
| --- | --- | ---: | ---: |
| BTF-suppressed (1) | A | 0/1 (0.0%) | 1/1 (100.0%) |
| BTF-suppressed (1) | B | 0/1 (0.0%) | 1/1 (100.0%) |
| Clean diagnostic (55) | A | 12/55 (21.8%) | 20/55 (36.4%) |
| Clean diagnostic (55) | B | 16/55 (29.1%) | 21/55 (38.2%) |

## Statistical Comparison

- Condition A fix-type accuracy: `12/56` (21.4%)
- Condition B fix-type accuracy: `16/56` (28.6%)
- McNemar exact test on paired fix-type: A-only=1, B-only=5, p=0.2188

## Per-Case Results

| Case | Taxonomy | A score | B score | A fix | B fix | Ground truth |
| --- | --- | ---: | ---: | --- | --- | --- |
| `stackoverflow-70729664` | `lowering_artifact` | `0/0/1` | `0/0/1` | other_refactor | bounds_check | The verifier errors because it thinks R7 is outside the packet's known bounds. I |
| `stackoverflow-70750259` | `lowering_artifact` | `1/1/1` | `1/1/1` | unsigned_clamp | unsigned_clamp | Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an u |
| `stackoverflow-72575736` | `lowering_artifact` | `0/0/1` | `0/0/1` | bounds_check | bounds_check | TL;DR. You are missing bug fix 2fa7d94afc1a for the BPF verifier. It was backpor |
| `stackoverflow-73088287` | `lowering_artifact` | `1/0/1` | `1/0/1` | unsigned_clamp | unsigned_clamp | Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed |
| `stackoverflow-74178703` | `lowering_artifact` | `1/0/1` | `0/0/1` | unsigned_clamp | bounds_check | Recompute and access through the same checked pointer expression inside the loop |
| `stackoverflow-74531552` | `lowering_artifact` | `0/0/1` | `1/1/1` | queue_map_api | unsigned_clamp | So, I've found the solution. It seems that I didn't properly check for the bound |
| `stackoverflow-75058008` | `lowering_artifact` | `1/0/1` | `0/0/1` | unsigned_clamp | null_check | TL;DR. Making your matchPrefix function a static inline one should work around t |
| `stackoverflow-76160985` | `lowering_artifact` | `1/0/0` | `1/0/1` | unsigned_clamp | unsigned_clamp | Mark the helper '__always_inline' or otherwise keep the proof within one functio |
| `stackoverflow-79485758` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The verifier complains on the packet access because the access seems to be out o |
| `stackoverflow-79530762` | `lowering_artifact` | `0/0/1` | `0/0/1` | bounds_check | bounds_check | Rewrite the code so the checked pointer/value is reused directly and the proof s |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Avoid 'unwrap'/panic paths in eBPF and rewrite to explicit error handling or uns |
| `stackoverflow-53136145` | `source_bug` | `1/1/1` | `0/0/1` | inline_hint | other_refactor | So, why it breaks at that point? I think it's because the verifier assumes ipv6_ |
| `stackoverflow-60053570` | `source_bug` | `1/1/1` | `1/1/1` | bounds_check | bounds_check | The to_size passed as third argument should be a number of bytes. Assuming that  |
| `stackoverflow-61945212` | `source_bug` | `1/1/1` | `1/1/1` | queue_map_api | queue_map_api | Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_ |
| `stackoverflow-67402772` | `source_bug` | `0/0/1` | `1/1/1` | other_refactor | bounds_check | The error is not caused by bpf_trace_prink(), but by the skb accesses that are p |
| `stackoverflow-67679109` | `source_bug` | `0/0/1` | `0/0/1` | unsigned_clamp | The verifier failed because the loop dereferenced a null pointer ('current' was  | Why not use a regular variable for current, instead of a pointer? |
| `stackoverflow-69767533` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | Initialize 'tmp_buffer' before the helper call and keep the copy length explicit |
| `stackoverflow-70091221` | `source_bug` | `1/1/1` | `1/1/1` | map_declaration | map_declaration | Declare the map in 'SEC("maps")' and preserve the loader-generated map pointer r |
| `stackoverflow-70392721` | `source_bug` | `0/0/1` | `1/0/0` | alignment_fix | The BPF program failed verification because the first argument to bpf_perf_event | I also encountered the same problem, and the solution is as follows，Add the comp |
| `stackoverflow-70760516` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Now, to fix this we need to change the code so data can't exceed 65536. We do th |
| `stackoverflow-70873332` | `source_bug` | `1/1/1` | `1/1/1` | bounds_check | bounds_check | TL;DR. You are hitting a corner-case of the verifier. See https://stackoverflow. |
| `stackoverflow-71946593` | `source_bug` | `0/0/1` | `0/0/1` | unsigned_clamp | other_refactor | I fixed it. Looks like have to use bpf_probe_read to read any memeber in sk_buff |
| `stackoverflow-72074115` | `source_bug` | `1/1/1` | `1/1/1` | bounds_check | bounds_check | A friend of mine told me that I should verify it by: He told me that I should ju |
| `stackoverflow-72606055` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | Your loader is not creating maps (or retrieving FDs for existing, compatible map |
| `stackoverflow-75294010` | `source_bug` | `0/0/1` | `0/0/1` | alignment_fix | alignment_fix | Root Cause The fourth argument to bpf_perf_event_output should be a pointer to t |
| `stackoverflow-75515263` | `source_bug` | `0/0/1` | `1/0/1` | other_refactor | map_declaration | If you want to store object of type struct sock_info in your BPF map, then its d |
| `stackoverflow-75643912` | `source_bug` | `1/1/1` | `1/1/1` | bounds_check | unsigned_clamp | I am not 100% certain if this is due to a off by one error in the condition or d |
| `stackoverflow-76277872` | `source_bug` | `0/0/1` | `1/1/1` | other_refactor | unsigned_clamp | The bounds check here is not correct. You are checking if you can access up to s |
| `stackoverflow-76637174` | `source_bug` | `1/1/1` | `1/1/1` | bounds_check | unsigned_clamp | There are two issues here. First is an off by 1 error in the loop, you need to a |
| `stackoverflow-76960866` | `source_bug` | `1/0/1` | `0/0/1` | context_member_read | other_refactor | In the C world you are casting the pointer in PARAM2 to a (struct socket *) but  |
| `stackoverflow-76994829` | `source_bug` | `0/0/1` | `0/0/1` | unsigned_clamp | unsigned_clamp | how about change struct { __uint(type, BPF_MAP_TYPE_ARRAY); |
| `stackoverflow-77205912` | `source_bug` | `0/0/0` | `0/0/1` | other_refactor | pointer_type_fix | Re-read packet pointers from 'skb' after the helper calls, or compute the checks |
| `stackoverflow-77762365` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | TL;DR. The verifier is not yet smart enough to use event->len + read < MAX_READ_ |
| `stackoverflow-78958420` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | It asserts that there must at least be 254 bytes bytes in the packet after offse |
| `stackoverflow-79045875` | `source_bug` | `1/1/1` | `1/1/1` | btf_regen | pointer_type_fix | arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar This erro |
| `stackoverflow-79348306` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Root Cause Solution |
| `github-aya-rs-aya-407` | `source_bug` | `0/0/1` | `0/0/1` | reduce_stack_depth | other_refactor | It is just a minor thing (for me) as I have a workaround, but I wonder if it is  |
| `github-cilium-cilium-41522` | `source_bug` | `0/0/0` | `1/1/1` | other_refactor | bounds_check | The sysdump is missing all node-specific information. I suspect it's because the |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | The verifier rejects the program because 'bpf_dynptr_read' is called with an inv | Pass the dynptr object at its exact stack slot / constant base address. |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | Destroy or release the iterator on every exit path, including the callee path. |
| `stackoverflow-47591176` | `verifier_limit` | `0/0/1` | `1/1/1` | other_refactor | reduce_branching | TL;DR: You should add direct-action flag to the tc filter command, as in Because |
| `stackoverflow-56872436` | `verifier_limit` | `1/1/1` | `1/1/1` | inline_hint | inline_hint | Use a loop form the verifier can fully unroll or otherwise make the bound/invari |
| `stackoverflow-70841631` | `verifier_limit` | `1/0/1` | `0/0/1` | loop_unroll | bounds_check | TL;DR. Your program is too complex for the verifier to analyze, as it must itera |
| `stackoverflow-78753911` | `verifier_limit` | `1/1/1` | `1/1/1` | <one short paragraph> | loop_unroll | Reduce branching/state fan-out, hoist common checks, or split the logic into sim |
| `github-aya-rs-aya-1324` | `verifier_limit` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | Also your code has the same problem as OP's. You are not actually consuming the  |
| `github-aya-rs-aya-521` [BTF-supp] | `verifier_limit` | `1/0/1` | `1/0/1` | inline_hint | inline_hint | I was of the impression that loops aren't allowed at all by the verifier. Are th |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Reduce combined stack use, split call structure, or shrink frame sizes. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Refactor the call tree or reduce per-frame stack use so the aggregate depth stay |
| `stackoverflow-69413427` | `env_mismatch` | `1/0/1` | `0/0/1` | unsigned_clamp | other_refactor | In your case, BPF_CORE_READ() returns a scalar (inv), and dir to a BTF id (ptr_) |
| `stackoverflow-76441958` | `env_mismatch` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | Align the user-space data/struct layout or target an architecture/context that s |
| `stackoverflow-78236201` | `env_mismatch` | `0/0/0` | `1/0/0` | bounds_check | inline_hint | You are using bpf_trace_printk incorrectly, you typically stack allocate the fmt |
| `stackoverflow-79812509` | `env_mismatch` | `0/0/1` | `0/0/1` | The verifier rejects the program because the cast to 'void *' turns the result o | pointer_type_fix | TL;DR. This is happening because the bpf_get_current_task helper doesn't preserv |
| `github-aya-rs-aya-1002` | `env_mismatch` | `0/0/1` | `0/0/1` | other_refactor | other_refactor | only read from bpf_array is supported You are trying to access a static item, wh |
| `github-aya-rs-aya-1104` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The template and book have been updated to only build ebpf in release mode. Plea |
| `github-aya-rs-aya-1233` | `env_mismatch` | `0/0/1` | `0/0/1` | Replace the disallowed use of 'bpf_probe_read' (via 'BPF_CORE_READ') with the al | Replace the disallowed BPF_CORE_READ helper with the allowed bpf_get_current_pid | Use a helper allowed in 'cgroup_skb', or move the logic to a program type that p |
| `github-aya-rs-aya-864` | `env_mismatch` | `1/0/1` | `0/0/1` | alignment_fix | other_refactor | Read the PID from 'TcContext'/'skb' instead of calling the unavailable helper. |

## Cases Where Condition B Does Better

### `stackoverflow-74531552`

- Taxonomy: `lowering_artifact`
- Condition A score: `0/0/1`
- Condition B score: `1/1/1`
- Ground truth: So, I've found the solution. It seems that I didn't properly check for the bounds of *curr_state. So the solution is to simply add the following snippet, prior to indexing aut.function.
- A fix: <|channel|>analysis<|message|>We need to fix BPF program. The error: "math between fp pointer and re
- B fix: <|channel|>analysis<|message|>We need to fix BPF program. The verifier error: math between fp pointe
- Notes: Condition B helped.

### `stackoverflow-67402772`

- Taxonomy: `source_bug`
- Condition A score: `0/0/1`
- Condition B score: `1/1/1`
- Ground truth: The error is not caused by bpf_trace_prink(), but by the skb accesses that are present in your bytecode only when you call bpf_trace_printk(). Accessing skb->local_ip4 and skb->remote_ip4 is not allow
- A fix: <|channel|>analysis<|message|>We need to fix BPF program. The verifier error: "invalid bpf_context a
- B fix: <|channel|>analysis<|message|>We need to fix BPF program. The verifier error: "invalid bpf_context a
- Notes: Condition B helped.

### `stackoverflow-76277872`

- Taxonomy: `source_bug`
- Condition A score: `0/0/1`
- Condition B score: `1/1/1`
- Ground truth: The bounds check here is not correct. You are checking if you can access up to struct ethhdr of bytes, but you should check for struct ethhdr + struct iphdr since you will be reading from the iphdr ne
- A fix: <|channel|>analysis<|message|>We need to analyze the verifier error. The error shows:  ''' 0: (b7) r
- B fix: <|channel|>analysis<|message|>We need to fix the verifier error: invalid access to packet at offset
- Notes: Condition B helped.

### `github-cilium-cilium-41522`

- Taxonomy: `source_bug`
- Condition A score: `0/0/0`
- Condition B score: `1/1/1`
- Ground truth: The sysdump is missing all node-specific information. I suspect it's because the node you tried to collect from (10.200.0.8) doesn't exist. At least, there are no references to that IP address in the 
- A fix: <|channel|>analysis<|message|>We need to analyze the verifier error. The error: "invalid access to p
- B fix: <|channel|>analysis<|message|>We need to analyze the verifier error. The error occurs at instruction
- Notes: Condition B helped.

### `stackoverflow-47591176`

- Taxonomy: `verifier_limit`
- Condition A score: `0/0/1`
- Condition B score: `1/1/1`
- Ground truth: TL;DR: You should add direct-action flag to the tc filter command, as in Because eBPF is kind of more flexible than the traditional actions and filters of tc, you can actually do both at once, filter 
- A fix: <|channel|>analysis<|message|>We need to fix BPF program. The program is:  ''' SEC("simple") int han
- B fix: <|channel|>analysis<|message|>We need to fix BPF program that fails verification due to verifier_lim
- Notes: Condition B helped.

## Cases Where Condition B Does Worse

### `stackoverflow-53136145`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `0/0/1`
- Ground truth: So, why it breaks at that point? I think it's because the verifier assumes ipv6_hdr could potentially be NULL, which is utterly WRONG because if the execution ever gets to that point, that's only beca
- A fix: <|channel|>analysis<|message|>We need to analyze the verifier error. The error occurs at line 109: r
- B fix: <|channel|>analysis<|message|>We need to fix BPF program. The verifier error occurs at line 109: r3
- Notes: Condition B hurt.

## Overall Conclusion

Condition B (OBLIGE) improved fix-type accuracy by +7.1pp (+4 cases).
For lowering_artifact (11 cases): A=1/11, B=2/11 (delta +9.1pp).
BTF-suppression affected 1 cases: A=0/1 (0.0%), B=0/1 (0.0%).
