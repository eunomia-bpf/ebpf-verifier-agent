# Repair Experiment V4: Raw Verifier Log vs OBLIGE Diagnostic (Qwen3.5-122B-A10B)

- Generated: `2026-03-13T19:00:26+00:00`
- Model: Qwen3.5-122B-A10B (MoE, ~10B active params) via llama.cpp `-hf` loading
- Selected cases: `56`
- Desired taxonomy targets: `{'lowering_artifact': 20, 'source_bug': 20, 'verifier_limit': 8, 'env_mismatch': 8}`
- Effective taxonomy targets: `{'lowering_artifact': 11, 'source_bug': 20, 'verifier_limit': 8, 'env_mismatch': 8}`
- Selected taxonomy counts: `{'lowering_artifact': 11, 'source_bug': 29, 'verifier_limit': 8, 'env_mismatch': 8}`
- BTF-misleading diagnostics suppressed in Condition B: `1`

Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.

## Overall Summary

| Condition | Location | Fix type | Root cause |
| --- | ---: | ---: | ---: |
| A (raw verifier log only) | 1/56 (1.8%) | 0/56 (0.0%) | 4/56 (7.1%) |
| B (raw log + OBLIGE diagnostic) | 1/56 (1.8%) | 1/56 (1.8%) | 5/56 (8.9%) |

## Summary By Taxonomy

| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 11 | 1/11 (9.1%) | 1/11 (9.1%) | 0/11 (0.0%) | 1/11 (9.1%) | 4/11 (36.4%) | 5/11 (45.5%) |
| `source_bug` | 29 | 0/29 (0.0%) | 0/29 (0.0%) | 0/29 (0.0%) | 0/29 (0.0%) | 0/29 (0.0%) | 0/29 (0.0%) |
| `verifier_limit` | 8 | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) |
| `env_mismatch` | 8 | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) | 0/8 (0.0%) |

## BTF-Suppression Analysis

- Cases where OBLIGE diagnostic was BTF-misleading → suppressed: `1`
- Cases with clean proof-analysis diagnostic: `55`

| Subset | Condition | Fix type | Location |
| --- | --- | ---: | ---: |
| BTF-suppressed (1) | A | 0/1 (0.0%) | 0/1 (0.0%) |
| BTF-suppressed (1) | B | 0/1 (0.0%) | 0/1 (0.0%) |
| Clean diagnostic (55) | A | 0/55 (0.0%) | 1/55 (1.8%) |
| Clean diagnostic (55) | B | 1/55 (1.8%) | 1/55 (1.8%) |

## Statistical Comparison

- Condition A fix-type accuracy: `0/56` (0.0%)
- Condition B fix-type accuracy: `1/56` (1.8%)
- McNemar exact test on paired fix-type: A-only=0, B-only=1, p=1.0000

## Comparison: V3 (20B GPT-OSS) vs V4 (Qwen3.5-122B-A10B)

| Metric | V3-A (20B) | V4-A (Qwen3.5) | V3-B (20B+OBLIGE) | V4-B (Qwen3.5+OBLIGE) |
| --- | ---: | ---: | ---: | ---: |
| Fix-type accuracy | 12/56 (21.4%) | 0/56 (0.0%) | 16/56 (28.6%) | 1/56 (1.8%) |
| Location accuracy | 21/56 (37.5%) | 1/56 (1.8%) | 22/56 (39.3%) | 1/56 (1.8%) |
| Semantic accuracy | 45/56 (80.4%) | 4/56 (7.1%) | 47/56 (83.9%) | 5/56 (8.9%) |

**OBLIGE improvement delta**: V3: +7.1pp (+4 cases), V4: +1.8pp (+1 cases)

**Interpretation**: The stronger Qwen3.5 model shows a smaller or similar OBLIGE benefit compared to the 20B baseline. This suggests the 20B model may gain more from structured guidance, or the larger model is already better at interpreting raw logs.

## Per-Case Results

| Case | Taxonomy | A score | B score | A fix | B fix | Ground truth |
| --- | --- | ---: | ---: | --- | --- | --- |
| `stackoverflow-70729664` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The verifier errors because it thinks R7 is outside the packet's known bounds. I |
| `stackoverflow-70750259` | `lowering_artifact` | `1/0/1` | `1/1/1` | The verifier rejects adding ext_len to the packet pointer because ext_len is dec | The verifier loses bounds tracking on ext_len after the __bpf_htons() conversion | Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an u |
| `stackoverflow-72575736` | `lowering_artifact` | `0/0/0` | `0/0/1` | other_refactor | The verifier loses packet bounds tracking when arithmetic is performed on the ad | TL;DR. You are missing bug fix 2fa7d94afc1a for the BPF verifier. It was backpor |
| `stackoverflow-73088287` | `lowering_artifact` | `0/0/1` | `0/0/1` | The verifier cannot track packet bounds across loop iterations. The condition 'p | other_refactor | Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed |
| `stackoverflow-74178703` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Recompute and access through the same checked pointer expression inside the loop |
| `stackoverflow-74531552` | `lowering_artifact` | `0/0/1` | `0/0/1` | The verifier rejects array access using an unbounded value from map lookup (*cur | The verifier rejects the program because *curr_state from map lookup is used as  | So, I've found the solution. It seems that I didn't properly check for the bound |
| `stackoverflow-75058008` | `lowering_artifact` | `0/0/1` | `0/0/1` | The BPF verifier marks the str pointer as mem_or_null because it could be null.  | The BPF verifier rejects dereferencing str[i] because the pointer str is marked  | TL;DR. Making your matchPrefix function a static inline one should work around t |
| `stackoverflow-76160985` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Mark the helper '__always_inline' or otherwise keep the proof within one functio |
| `stackoverflow-79485758` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The verifier complains on the packet access because the access seems to be out o |
| `stackoverflow-79530762` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Rewrite the code so the checked pointer/value is reused directly and the proof s |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Avoid 'unwrap'/panic paths in eBPF and rewrite to explicit error handling or uns |
| `stackoverflow-53136145` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | So, why it breaks at that point? I think it's because the verifier assumes ipv6_ |
| `stackoverflow-60053570` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The to_size passed as third argument should be a number of bytes. Assuming that  |
| `stackoverflow-61945212` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_ |
| `stackoverflow-67402772` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The error is not caused by bpf_trace_prink(), but by the skb accesses that are p |
| `stackoverflow-67679109` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Why not use a regular variable for current, instead of a pointer? |
| `stackoverflow-69767533` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Initialize 'tmp_buffer' before the helper call and keep the copy length explicit |
| `stackoverflow-70091221` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Declare the map in 'SEC("maps")' and preserve the loader-generated map pointer r |
| `stackoverflow-70392721` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | I also encountered the same problem, and the solution is as follows，Add the comp |
| `stackoverflow-70760516` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Now, to fix this we need to change the code so data can't exceed 65536. We do th |
| `stackoverflow-70873332` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | TL;DR. You are hitting a corner-case of the verifier. See https://stackoverflow. |
| `stackoverflow-71946593` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | I fixed it. Looks like have to use bpf_probe_read to read any memeber in sk_buff |
| `stackoverflow-72074115` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | A friend of mine told me that I should verify it by: He told me that I should ju |
| `stackoverflow-72606055` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Your loader is not creating maps (or retrieving FDs for existing, compatible map |
| `stackoverflow-75294010` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Root Cause The fourth argument to bpf_perf_event_output should be a pointer to t |
| `stackoverflow-75515263` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | If you want to store object of type struct sock_info in your BPF map, then its d |
| `stackoverflow-75643912` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | I am not 100% certain if this is due to a off by one error in the condition or d |
| `stackoverflow-76277872` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The bounds check here is not correct. You are checking if you can access up to s |
| `stackoverflow-76637174` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | There are two issues here. First is an off by 1 error in the loop, you need to a |
| `stackoverflow-76960866` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | In the C world you are casting the pointer in PARAM2 to a (struct socket *) but  |
| `stackoverflow-76994829` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | how about change struct { __uint(type, BPF_MAP_TYPE_ARRAY); |
| `stackoverflow-77205912` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Re-read packet pointers from 'skb' after the helper calls, or compute the checks |
| `stackoverflow-77762365` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | TL;DR. The verifier is not yet smart enough to use event->len + read < MAX_READ_ |
| `stackoverflow-78958420` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | It asserts that there must at least be 254 bytes bytes in the packet after offse |
| `stackoverflow-79045875` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar This erro |
| `stackoverflow-79348306` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Root Cause Solution |
| `github-aya-rs-aya-407` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | It is just a minor thing (for me) as I have a workaround, but I wonder if it is  |
| `github-cilium-cilium-41522` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The sysdump is missing all node-specific information. I suspect it's because the |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Pass the dynptr object at its exact stack slot / constant base address. |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Destroy or release the iterator on every exit path, including the callee path. |
| `stackoverflow-47591176` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | TL;DR: You should add direct-action flag to the tc filter command, as in Because |
| `stackoverflow-56872436` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Use a loop form the verifier can fully unroll or otherwise make the bound/invari |
| `stackoverflow-70841631` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | TL;DR. Your program is too complex for the verifier to analyze, as it must itera |
| `stackoverflow-78753911` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Reduce branching/state fan-out, hoist common checks, or split the logic into sim |
| `github-aya-rs-aya-1324` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Also your code has the same problem as OP's. You are not actually consuming the  |
| `github-aya-rs-aya-521` [BTF-supp] | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | I was of the impression that loops aren't allowed at all by the verifier. Are th |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Reduce combined stack use, split call structure, or shrink frame sizes. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Refactor the call tree or reduce per-frame stack use so the aggregate depth stay |
| `stackoverflow-69413427` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | In your case, BPF_CORE_READ() returns a scalar (inv), and dir to a BTF id (ptr_) |
| `stackoverflow-76441958` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Align the user-space data/struct layout or target an architecture/context that s |
| `stackoverflow-78236201` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | You are using bpf_trace_printk incorrectly, you typically stack allocate the fmt |
| `stackoverflow-79812509` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | TL;DR. This is happening because the bpf_get_current_task helper doesn't preserv |
| `github-aya-rs-aya-1002` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | only read from bpf_array is supported You are trying to access a static item, wh |
| `github-aya-rs-aya-1104` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | The template and book have been updated to only build ebpf in release mode. Plea |
| `github-aya-rs-aya-1233` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Use a helper allowed in 'cgroup_skb', or move the logic to a program type that p |
| `github-aya-rs-aya-864` | `env_mismatch` | `0/0/0` | `0/0/0` | other_refactor | other_refactor | Read the PID from 'TcContext'/'skb' instead of calling the unavailable helper. |

## Cases Where Condition B Does Better

### `stackoverflow-70750259`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/0/1`
- Condition B score: `1/1/1`
- Ground truth: Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an unsigned form.
- A fix: The verifier rejects adding ext_len to the packet pointer because ext_len is declared as volatile int, causing the verifier to lose track of its bounds. The value can appear unbounded (including negative) after the stack store/reload, making pkt pointer arithmetic unsafe.
- B fix: The verifier loses bounds tracking on ext_len after the __bpf_htons() conversion due to the OR operation destroying scalar bounds. When ext_len is added to the packet pointer, the verifier rejects it because the offset has an unbounded minimum value. The fix is to use an unsigned type for ext_len and add an explicit bounds check against data_end before using it to advance the data pointer.
- Notes: Condition B helped.

## Cases Where Condition B Does Worse

- None in this run.
## Overall Conclusion

Condition B (OBLIGE) improved fix-type accuracy by +1.8pp (+1 cases).
For lowering_artifact (11 cases): A=0/11, B=1/11 (delta +9.1pp).
BTF-suppression affected 1 cases: A=0/1 (0.0%), B=0/1 (0.0%).
