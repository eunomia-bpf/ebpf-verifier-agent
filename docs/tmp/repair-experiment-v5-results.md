# Repair Experiment V3: Raw Verifier Log vs BPFix Diagnostic (Local 20B Model)

- Generated: `2026-03-13T22:37:57+00:00`
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
| A (raw verifier log only) | 5/56 (8.9%) | 1/56 (1.8%) | 14/56 (25.0%) |
| B (raw log + BPFix diagnostic) | 4/56 (7.1%) | 3/56 (5.4%) | 10/56 (17.9%) |

## Summary By Taxonomy

| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 11 | 0/11 (0.0%) | 0/11 (0.0%) | 0/11 (0.0%) | 0/11 (0.0%) | 2/11 (18.2%) | 2/11 (18.2%) |
| `source_bug` | 29 | 3/29 (10.3%) | 2/29 (6.9%) | 0/29 (0.0%) | 2/29 (6.9%) | 7/29 (24.1%) | 6/29 (20.7%) |
| `verifier_limit` | 8 | 2/8 (25.0%) | 2/8 (25.0%) | 1/8 (12.5%) | 1/8 (12.5%) | 5/8 (62.5%) | 2/8 (25.0%) |
| `env_mismatch` | 8 | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) |

## BTF-Suppression Analysis

- Cases where BPFix diagnostic was BTF-misleading → suppressed: `1`
- Cases with clean proof-analysis diagnostic: `55`

| Subset | Condition | Fix type | Location |
| --- | --- | ---: | ---: |
| BTF-suppressed (1) | A | 0/1 (0.0%) | 1/1 (100.0%) |
| BTF-suppressed (1) | B | 0/1 (0.0%) | 1/1 (100.0%) |
| Clean diagnostic (55) | A | 1/55 (1.8%) | 4/55 (7.3%) |
| Clean diagnostic (55) | B | 3/55 (5.5%) | 3/55 (5.5%) |

## Statistical Comparison

- Condition A fix-type accuracy: `1/56` (1.8%)
- Condition B fix-type accuracy: `3/56` (5.4%)
- McNemar exact test on paired fix-type: A-only=0, B-only=2, p=0.5000

## Oracle Verification Metrics

The verifier oracle compiled and/or loaded LLM-generated `patched_code` into the kernel.

| Condition | Compile rate | Verifier pass rate |
| --- | ---: | ---: |
| A (raw verifier log only) | 4/15 (26.7%) | 1/4 (25.0%) |
| B (raw log + BPFix diagnostic) | 2/13 (15.4%) | 0/2 (0.0%) |

- `verifier_pass_rate_A`: 25.0%
- `verifier_pass_rate_B`: 0.0%
- `compile_rate_A`: 26.7%
- `compile_rate_B`: 15.4%

## Per-Case Results

| Case | Taxonomy | A score | B score | A oracle | B oracle | A fix | B fix | Ground truth |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `stackoverflow-70729664` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The verifier errors because it thinks R7 is outside the packet's known bounds. I |
| `stackoverflow-70750259` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an u |
| `stackoverflow-72575736` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | TL;DR. You are missing bug fix 2fa7d94afc1a for the BPF verifier. It was backpor |
| `stackoverflow-73088287` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed |
| `stackoverflow-74178703` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Recompute and access through the same checked pointer expression inside the loop |
| `stackoverflow-74531552` | `lowering_artifact` | `0/0/1` | `0/0/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier rejects adding an unbounded map value ('*curr_state') to a stack | 1. The verifier cannot prove that '*curr_state' (read from map) is within valid  | So, I've found the solution. It seems that I didn't properly check for the bound |
| `stackoverflow-75058008` | `lowering_artifact` | `0/0/1` | `0/0/1` | `c=Y/v=N` | `c=Y/v=N` | 1. The verifier treats the 'str' pointer parameter as potentially NULL ('mem_or_ | 1. The verifier rejects the program because 'str' is dereferenced without first  | TL;DR. Making your matchPrefix function a static inline one should work around t |
| `stackoverflow-76160985` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Mark the helper '__always_inline' or otherwise keep the proof within one functio |
| `stackoverflow-79485758` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The verifier complains on the packet access because the access seems to be out o |
| `stackoverflow-79530762` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Rewrite the code so the checked pointer/value is reused directly and the proof s |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Avoid 'unwrap'/panic paths in eBPF and rewrite to explicit error handling or uns |
| `stackoverflow-53136145` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | So, why it breaks at that point? I think it's because the verifier assumes ipv6_ |
| `stackoverflow-60053570` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The to_size passed as third argument should be a number of bytes. Assuming that  |
| `stackoverflow-61945212` | `source_bug` | `1/0/1` | `1/1/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier rejects passing NULL as the key pointer because it expects a val | 1. The verifier fails because 'bpf_map_update_elem()' requires a valid key point | Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_ |
| `stackoverflow-67402772` | `source_bug` | `0/0/1` | `0/0/1` | `c=Y/v=N` | `c=Y/v=N` | 1. The verifier rejects access to 'local_ip4' and 'remote_ip4' because these fie | 1. The verifier rejects the access because '__sk_buff' does not have 'local_ip4' | The error is not caused by bpf_trace_prink(), but by the skb accesses that are p |
| `stackoverflow-67679109` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Why not use a regular variable for current, instead of a pointer? |
| `stackoverflow-69767533` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Initialize 'tmp_buffer' before the helper call and keep the copy length explicit |
| `stackoverflow-70091221` | `source_bug` | `1/0/1` | `1/1/1` | `c=Y/v=N` | `c=N/v=-` | 1. The verifier doesn't recognize '&EVENTS' as a valid map pointer because the m | 1. The verifier treats '&EVENTS' as a map-value pointer instead of a map object  | Declare the map in 'SEC("maps")' and preserve the loader-generated map pointer r |
| `stackoverflow-70392721` | `source_bug` | `0/0/0` | `0/0/0` | `c=N/v=-` | `c=N/v=-` | 1. The verifier error "unknown opcode 8d" indicates the kernel BPF program (trac | 1. Root cause: The BPF kernel program (trace_output_kern.o) was not compiled wit | I also encountered the same problem, and the solution is as follows，Add the comp |
| `stackoverflow-70760516` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Now, to fix this we need to change the code so data can't exceed 65536. We do th |
| `stackoverflow-70873332` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | TL;DR. You are hitting a corner-case of the verifier. See https://stackoverflow. |
| `stackoverflow-71946593` | `source_bug` | `0/0/1` | `0/0/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier cannot directly dereference kernel structure pointers (like 'skb | 1. Root cause: The verifier cannot track that 'skb->head' is a valid pointer aft | I fixed it. Looks like have to use bpf_probe_read to read any memeber in sk_buff |
| `stackoverflow-72074115` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | A friend of mine told me that I should verify it by: He told me that I should ju |
| `stackoverflow-72606055` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Your loader is not creating maps (or retrieving FDs for existing, compatible map |
| `stackoverflow-75294010` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Root Cause The fourth argument to bpf_perf_event_output should be a pointer to t |
| `stackoverflow-75515263` | `source_bug` | `0/0/1` | `0/0/1` | `c=N/v=-` | `c=N/v=-` | 1. The map value size (8 bytes) is smaller than the struct size (12 bytes), caus | 1. The map value size is 8 bytes but the struct sock_info is 12 bytes, causing o | If you want to store object of type struct sock_info in your BPF map, then its d |
| `stackoverflow-75643912` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | I am not 100% certain if this is due to a off by one error in the condition or d |
| `stackoverflow-76277872` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The bounds check here is not correct. You are checking if you can access up to s |
| `stackoverflow-76637174` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | There are two issues here. First is an off by 1 error in the loop, you need to a |
| `stackoverflow-76960866` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | In the C world you are casting the pointer in PARAM2 to a (struct socket *) but  |
| `stackoverflow-76994829` | `source_bug` | `0/0/1` | `0/0/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier miscalculates the map value size because '__type(value, sizeof(s | 1. The verifier calculates an incorrect map value size (8 bytes) because the map | how about change struct { __uint(type, BPF_MAP_TYPE_ARRAY); |
| `stackoverflow-77205912` | `source_bug` | `1/0/1` | `0/0/0` | `c=N/v=-` | `c=?/v=-` | 1. The verifier loses track of the packet pointer validity after the first 'bpf_ | other_refactor | Re-read packet pointers from 'skb' after the helper calls, or compute the checks |
| `stackoverflow-77762365` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | TL;DR. The verifier is not yet smart enough to use event->len + read < MAX_READ_ |
| `stackoverflow-78958420` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | It asserts that there must at least be 254 bytes bytes in the packet after offse |
| `stackoverflow-79045875` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar This erro |
| `stackoverflow-79348306` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Root Cause Solution |
| `github-aya-rs-aya-407` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | It is just a minor thing (for me) as I have a workaround, but I wonder if it is  |
| `github-cilium-cilium-41522` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The sysdump is missing all node-specific information. I suspect it's because the |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Pass the dynptr object at its exact stack slot / constant base address. |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Destroy or release the iterator on every exit path, including the callee path. |
| `stackoverflow-47591176` | `verifier_limit` | `0/0/1` | `0/0/0` | `c=N/v=-` | `c=?/v=-` | 1. The verifier output actually shows successful loading with no error, but the  | other_refactor | TL;DR: You should add direct-action flag to the tc filter command, as in Because |
| `stackoverflow-56872436` | `verifier_limit` | `1/1/1` | `1/1/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier cannot prove the loop is bounded because the loop counter 'i' is | 1. The verifier cannot prove the loop is bounded because '#pragma unroll' alone  | Use a loop form the verifier can fully unroll or otherwise make the bound/invari |
| `stackoverflow-70841631` | `verifier_limit` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | TL;DR. Your program is too complex for the verifier to analyze, as it must itera |
| `stackoverflow-78753911` | `verifier_limit` | `0/0/1` | `0/0/1` | `c=N/v=-` | `c=N/v=-` | 1. The verifier cannot prove loop termination due to missing iteration bounds, c | 1. The verifier is exploring too many states due to an unbounded loop with compl | Reduce branching/state fan-out, hoist common checks, or split the logic into sim |
| `github-aya-rs-aya-1324` | `verifier_limit` | `0/0/1` | `0/0/0` | `c=Y/v=Y` | `c=N/v=-` | 1. The verifier error indicates the BPF program references an invalid or uniniti | 1. The verifier fails because the BPF program references an invalid or uninitial | Also your code has the same problem as OP's. You are not actually consuming the  |
| `github-aya-rs-aya-521` [BTF-supp] | `verifier_limit` | `1/0/1` | `1/0/0` | `c=N/v=-` | `c=N/v=-` | 1. The verifier fails because the 'loop_body' callback function lacks proper BTF | 1. The callback function passed to 'bpf_loop' lacks proper BTF type information  | I was of the impression that loops aren't allowed at all by the verifier. Are th |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Reduce combined stack use, split call structure, or shrink frame sizes. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Refactor the call tree or reduce per-frame stack use so the aggregate depth stay |
| `stackoverflow-69413427` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | In your case, BPF_CORE_READ() returns a scalar (inv), and dir to a BTF id (ptr_) |
| `stackoverflow-76441958` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Align the user-space data/struct layout or target an architecture/context that s |
| `stackoverflow-78236201` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | You are using bpf_trace_printk incorrectly, you typically stack allocate the fmt |
| `stackoverflow-79812509` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | TL;DR. This is happening because the bpf_get_current_task helper doesn't preserv |
| `github-aya-rs-aya-1002` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | only read from bpf_array is supported You are trying to access a static item, wh |
| `github-aya-rs-aya-1104` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | The template and book have been updated to only build ebpf in release mode. Plea |
| `github-aya-rs-aya-1233` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Use a helper allowed in 'cgroup_skb', or move the logic to a program type that p |
| `github-aya-rs-aya-864` | `env_mismatch` | `0/0/0` | `0/0/0` | `c=?/v=-` | `c=?/v=-` | other_refactor | other_refactor | Read the PID from 'TcContext'/'skb' instead of calling the unavailable helper. |

## Cases Where Condition B Does Better

### `stackoverflow-61945212`

- Taxonomy: `source_bug`
- Condition A score: `1/0/1`
- Condition B score: `1/1/1`
- Ground truth: Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_elem()'.
- A fix: 1. The verifier rejects passing NULL as the key pointer because it expects a valid frame pointer (fp) type, not an invalid (inv) pointer type.  2. null_check  3. '''c #include <bpf/bpf.h> #include <string.h> struct bpf_map SEC("maps") queue_map = { .type = BPF_MAP_TYPE_QUEUE, .key_size = 0, .value_size = sizeof(int), .max_entries = 100, .map_flags = 0, }; SEC("tracepoint/syscalls/sys_enter_execve") int bpf_prog(void *ctx) { int value; int key = 0; value = 123; bpf_map_update_elem(&queue_map, &ke
- B fix: 1. The verifier fails because 'bpf_map_update_elem()' requires a valid key pointer, but QUEUE maps have no keys and must use 'bpf_map_push_elem()' instead.  2. inline_rewrite  3. '''c #include <bpf/bpf.h> #include <string.h> struct bpf_map SEC("maps") queue_map = { .type = BPF_MAP_TYPE_QUEUE, .key_size = 0, .value_size = sizeof(int), .max_entries = 100, .map_flags = 0, }; SEC("tracepoint/syscalls/sys_enter_execve") int bpf_prog(void *ctx) { int value; value = 123; bpf_map_push_elem(&queue_map, &
- Notes: Condition B helped.

### `stackoverflow-70091221`

- Taxonomy: `source_bug`
- Condition A score: `1/0/1`
- Condition B score: `1/1/1`
- Ground truth: Declare the map in 'SEC("maps")' and preserve the loader-generated map pointer relocation.
- A fix: 1. The verifier doesn't recognize '&EVENTS' as a valid map pointer because the map definition lacks the required 'SEC(".maps")' section attribute.  2. pointer_type_fix  3. '''c struct bpf_map_def {     __u32 type;     __u32 key_size;     __u32 value_size;     __u32 max_entries;     __u32 map_flags; };  struct bpf_map_def EVENTS __attribute__((section("maps"), used)) = {     .type = BPF_MAP_TYPE_HASH,     .key_size = sizeof(__u32),     .value_size = sizeof(__u32),     .max_entries = 1, };  SEC("x
- B fix: 1. The verifier treats '&EVENTS' as a map-value pointer instead of a map object pointer because the map definition lacks the proper section attribute to be recognized as a BPF map.  2. pointer_type_fix  3. '''c struct bpf_map_def SEC("maps") EVENTS = {     .type = BPF_MAP_TYPE_HASH,     .key_size = sizeof(__u32),     .value_size = sizeof(__u32),     .max_entries = 1, };  SEC("xdp") int _xdp_ip_filter(struct xdp_md *ctx) {     bpf_printk("got a packet\n");     void *data_end = (void *)(long)ctx->
- Notes: Condition B helped.

## Cases Where Condition B Does Worse

- None in this run.
## Overall Conclusion

Condition B (BPFix) improved fix-type accuracy by +3.6pp (+2 cases).
For lowering_artifact (11 cases): A=0/11, B=0/11 (delta +0.0pp).
BTF-suppression affected 1 cases: A=0/1 (0.0%), B=0/1 (0.0%).
