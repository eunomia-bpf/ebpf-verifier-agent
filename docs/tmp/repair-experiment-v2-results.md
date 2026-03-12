# Repair Experiment V2: Raw Verifier Log vs OBLIGE Diagnostic

- Generated: `2026-03-12T20:41:45+00:00`
- Selected cases: `54`
- Desired taxonomy targets: `{"env_mismatch": 8, "lowering_artifact": 15, "source_bug": 23, "verifier_limit": 8}`
- Effective taxonomy targets: `{"env_mismatch": 8, "lowering_artifact": 10, "source_bug": 23, "verifier_limit": 8}`
- Selected taxonomy counts: `{"env_mismatch": 8, "lowering_artifact": 10, "source_bug": 28, "verifier_limit": 8}`

Only 10 `lowering_artifact` cases were eligible in the requested source buckets with usable code, verifier log, and ground-truth fix text, so the remaining slots were backfilled with `source_bug` cases.

Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.

## Overall Summary

| Condition | Location | Fix type | Root cause |
| --- | ---: | ---: | ---: |
| A (raw verifier log only) | 53/54 (98.1%) | 46/54 (85.2%) | 46/54 (85.2%) |
| B (raw log + OBLIGE diagnostic) | 48/54 (88.9%) | 43/54 (79.6%) | 43/54 (79.6%) |

## Summary By Taxonomy

| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 10 | 9/10 (90.0%) | 9/10 (90.0%) | 3/10 (30.0%) | 6/10 (60.0%) | 3/10 (30.0%) | 6/10 (60.0%) |
| `source_bug` | 28 | 28/28 (100.0%) | 25/28 (89.3%) | 27/28 (96.4%) | 23/28 (82.1%) | 27/28 (96.4%) | 23/28 (82.1%) |
| `verifier_limit` | 8 | 8/8 (100.0%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) |
| `env_mismatch` | 8 | 8/8 (100.0%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) |

## Per-Case Results

| Case | Taxonomy | A score | B score | A fix | B fix | Ground truth |
| --- | --- | ---: | ---: | --- | --- | --- |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `1/0/0` | `1/1/1` | Add or tighten the bounds check immediately before the failing access. | Replace 'ctx.ret().unwrap()' with explicit error handling and clamp the resulting length before the read. | Avoid 'unwrap'/panic paths in eBPF and rewrite to explicit error handling or unsigned/clamped arithmetic. |
| `stackoverflow-70729664` | `lowering_artifact` | `1/0/0` | `1/1/1` | Tighten the SCTP chunk-walk check so the code revalidates 'nh->pos + size + 4' against 'data_end' before reading the next chunk type. | Clamp the computed chunk advance to a small unsigned max such as 'MAX_PACKET_OFF' and keep the offset arithmetic in a separate verified r... | The verifier errors because it thinks R7 is outside the packet's known bounds. It tells us you're trying to make an access of size 1B at... |
| `stackoverflow-70750259` | `lowering_artifact` | `1/1/1` | `1/1/1` | Keep ext_len unsigned and clamp it before data += ext_len; avoid the signed or volatile conversion that makes the verifier lose the range... | Compute ext_len in a separate verified unsigned register, clamp it to the remaining packet span, then advance data with that checked value. | Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an unsigned form. |
| `stackoverflow-72575736` | `lowering_artifact` | `0/0/0` | `0/0/0` | Add an explicit unsigned clamp on 'off'/'i' and dereference the same checked 'address' register inside the loop. | Clamp the offset to a small unsigned range and keep the offset calculation in a separate verified register before dereference. | TL;DR. You are missing bug fix 2fa7d94afc1a for the BPF verifier. It was backported to the v5.13 kernel you are using as commit e7a61f15b... |
| `stackoverflow-73088287` | `lowering_artifact` | `1/0/0` | `1/0/0` | Add or tighten the bounds check immediately before the failing access. | Add or tighten the bounds check immediately before the failing access. | Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed pointer identical. |
| `stackoverflow-74178703` | `lowering_artifact` | `1/0/0` | `1/1/1` | Add or tighten the bounds check immediately before the failing access. | Recompute and dereference through the same checked 'b + offset + i' expression inside the loop body. | Recompute and access through the same checked pointer expression inside the loop body. |
| `stackoverflow-75058008` | `lowering_artifact` | `1/0/0` | `1/0/0` | Add a null check in the same function right before the dereference. | Add a null check in the same function right before the dereference. | TL;DR. Making your matchPrefix function a static inline one should work around the verifier issue. I believe this is happening because th... |
| `stackoverflow-76160985` | `lowering_artifact` | `1/1/1` | `1/1/1` | Mark 'find_substring' and, if needed, 'mystrlen' as '__always_inline' so the verifier sees the caller's proof in one function. | Mark 'find_substring' as '__always_inline' so the string-walk proof stays in the caller instead of being validated as a separate subprogram. | Mark the helper '__always_inline' or otherwise keep the proof within one function. |
| `stackoverflow-79485758` | `lowering_artifact` | `1/0/0` | `1/1/1` | Add a stronger guard before x = *((uint16_t *)(data + field_offset)), rejecting any case where field_offset or that 2-byte read may run p... | Clamp field_offset into a verifier-friendly unsigned range and read through a separately checked pkt_ptr before dereferencing it. | The verifier complains on the packet access because the access seems to be out of the known packet bounds. The access is at offset 0, wit... |
| `stackoverflow-79530762` | `lowering_artifact` | `1/1/1` | `1/0/0` | Introduce a temporary checked pointer and read/write through that exact pointer instead of recomputing 'data_bytes + i + option_length' a... | Add a stronger 'data_bytes + i + option_length + 1 <= data_end' guard immediately before the write. | Rewrite the code so the checked pointer/value is reused directly and the proof survives lowering. |
| `github-aya-rs-aya-407` | `source_bug` | `1/1/1` | `1/1/1` | Pass the scalar value expected by the call rather than an unsupported pointer wrapper. | Pass the scalar value expected by the call rather than an unsupported pointer wrapper. | It is just a minor thing (for me) as I have a workaround, but I wonder if it is intended to work only with u32/i32 for PerfEventArray, if... |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `1/1/1` | `0/0/0` | Pass the dynptr from its exact stack slot/base address instead of an offset or forged pointer. | Regenerate or align the BTF / func_info metadata for this build. | Pass the dynptr object at its exact stack slot / constant base address. |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `1/1/1` | `0/0/0` | Destroy the iterator on every exit path, including the callee path that currently leaks it. | Regenerate or align the BTF / func_info metadata for this build. | Destroy or release the iterator on every exit path, including the callee path. |
| `stackoverflow-60053570` | `source_bug` | `1/1/1` | `1/1/1` | Change the 'bpf_csum_diff' length argument to the actual ICMP header size, such as 'sizeof(struct icmphdr)', unless the code first proves... | Use the correct byte length at 'bpf_csum_diff' for the ICMP header instead of the larger unchecked constant, or add a dominating proof fo... | The to_size passed as third argument should be a number of bytes. Assuming that you copied ICMP_ECHO_LEN from kernel selftests, I suspect... |
| `stackoverflow-61945212` | `source_bug` | `1/0/0` | `1/1/1` | Fix the helper call site by passing a real stack-backed key to bpf_map_update_elem, or switch to a keyed map if you need keyed updates. | Replace bpf_map_update_elem with the queue-map API, e.g. bpf_map_push_elem(&queue_map, &value, 0). | Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_elem()'. |
| `stackoverflow-67402772` | `source_bug` | `1/1/1` | `1/1/1` | Stop reading 'skb->local_ip4' and 'skb->remote_ip4' in this 'lwt_out' program; use an allowed context field/API or move the logic to a pr... | Replace the forbidden 'skb' member reads with a verifier-allowed field or helper, or run this logic in a program type that permits those... | The error is not caused by bpf_trace_prink(), but by the skb accesses that are present in your bytecode only when you call bpf_trace_prin... |
| `stackoverflow-67679109` | `source_bug` | `1/1/1` | `1/1/1` | Use a plain value/current variable instead of pointer arithmetic that the verifier cannot prove safe. | Use a plain value/current variable instead of pointer arithmetic that the verifier cannot prove safe. | Why not use a regular variable for current, instead of a pointer? |
| `stackoverflow-69767533` | `source_bug` | `1/1/1` | `1/1/1` | Zero-initialize 'tmp_buffer' before 'bpf_probe_read' and keep the copy length explicitly bounded. | Zero-initialize 'tmp_buffer' before 'bpf_probe_read' and keep the copy length explicitly bounded. | Initialize 'tmp_buffer' before the helper call and keep the copy length explicitly bounded. |
| `stackoverflow-70091221` | `source_bug` | `1/1/1` | `1/1/1` | Declare the map with 'SEC("maps")' so helper arg 1 is the actual map object. | Declare the map with 'SEC("maps")' so helper arg 1 is the actual map object. | Declare the map in 'SEC("maps")' and preserve the loader-generated map pointer relocation. |
| `stackoverflow-70392721` | `source_bug` | `1/1/1` | `1/1/1` | Rebuild the BPF object with '-O2' and strip incompatible debug/BTF payloads with 'llvm-strip -g' instead of changing program logic. | Compile with '-O2' and strip the object so libbpf sees a clean BPF program/BTF payload; this is a build artifact issue, not a pointer fix... | I also encountered the same problem, and the solution is as follows，Add the compile option -O2 and use LLVM_STRIP |
| `stackoverflow-70721661` | `source_bug` | `1/1/1` | `1/1/1` | Prove the IP header is in bounds before memcpy, either with (void *)ip + sizeof(*ip) <= data_end or by folding that size into the first h... | Add an explicit bounds check that covers the full IP header before memcpy, not just the Ethernet header. | TL;DR. The issue is that you're making an out-of-bound access to the packet from the verifier's point of view. You need to check the pack... |
| `stackoverflow-70760516` | `source_bug` | `1/1/1` | `1/0/0` | Cap the number of parsed extensions and tighten per-extension and server-name lengths so the cumulative packet offset cannot grow past 64K. | Insert an explicit 'data + sizeof(struct extension) <= data_end' check right before reading 'ext->type'. | Now, to fix this we need to change the code so data can't exceed 65536. We do this by specifying a maximum amount of iterations(extension... |
| `stackoverflow-70873332` | `source_bug` | `1/1/1` | `1/1/1` | Restructure the access so the verifier can see the same bounded expression at check and dereference time. | Restructure the access so the verifier can see the same bounded expression at check and dereference time. | TL;DR. You are hitting a corner-case of the verifier. See https://stackoverflow.com/a/70731589/6884590. Adding a bounds check on pkt_ctx-... |
| `stackoverflow-71946593` | `source_bug` | `1/1/1` | `1/1/1` | Use 'bpf_probe_read*' to read the 'sk_buff' member instead of direct field dereference. | Use 'bpf_probe_read*' to read the 'sk_buff' member instead of direct field dereference. | I fixed it. Looks like have to use bpf_probe_read to read any memeber in sk_buff. |
| `stackoverflow-72074115` | `source_bug` | `1/1/1` | `1/1/1` | Add a dominating bounds check that proves the buffer access is within range on every path. | Add a dominating bounds check that proves the buffer access is within range on every path. | A friend of mine told me that I should verify it by: He told me that I should judge whether the corresponding position of the array exist... |
| `stackoverflow-72606055` | `source_bug` | `1/1/1` | `1/1/1` | Fix the custom loader to create the map and apply ELF relocation for 'my_map', or use libbpf/bpftool so the helper sees a real map refere... | Use a loader path that preserves the loader-generated map reference for 'my_map' rather than sending an unrelocated 'map_lookup_elem' cal... | Your loader is not creating maps (or retrieving FDs for existing, compatible maps), and does not update the bytecode accordingly. So the... |
| `stackoverflow-74531552` | `source_bug` | `1/1/1` | `1/1/1` | Check *curr_state is within [0, 4) before using it to index aut.function, and bail out if it is negative or too large. | Check *curr_state is within [0, 4) before indexing aut.function so the table access has an explicit verifier-visible bound. | So, I've found the solution. It seems that I didn't properly check for the bounds of *curr_state. So the solution is to simply add the fo... |
| `stackoverflow-75294010` | `source_bug` | `1/1/1` | `0/0/0` | Pass 'event' to 'bpf_perf_event_output' instead of '&event', so the helper receives the record buffer rather than a pointer to the pointer. | Re-derive the 'event' pointer from the verified map lookup before each dereference and write. | Root Cause The fourth argument to bpf_perf_event_output should be a pointer to the data to post on the ring buffer. Hence, you want to pa... |
| `stackoverflow-75515263` | `source_bug` | `1/1/1` | `1/1/1` | Declare the map value as 'struct sock_info' rather than a pointer so reads of 'sport' and 'dport' stay in-bounds. | Declare the map value as 'struct sock_info' rather than a pointer so reads of 'sport' and 'dport' stay in-bounds. | If you want to store object of type struct sock_info in your BPF map, then its declaration should be: Note how the value type is not a po... |
| `stackoverflow-75643912` | `source_bug` | `1/1/1` | `1/1/1` | Fix the off-by-one and width check so the loop only reads bytes that are proven in-bounds. | Fix the off-by-one and width check so the loop only reads bytes that are proven in-bounds. | I am not 100% certain if this is due to a off by one error in the condition or due to the way clang does the guard generation. In any cas... |
| `stackoverflow-76277872` | `source_bug` | `1/1/1` | `1/1/1` | Check bounds against the actual header/payload size you read, not just 'sizeof(struct ethhdr)'. | Check bounds against the actual header/payload size you read, not just 'sizeof(struct ethhdr)'. | The bounds check here is not correct. You are checking if you can access up to struct ethhdr of bytes, but you should check for struct et... |
| `stackoverflow-76637174` | `source_bug` | `1/1/1` | `1/1/1` | Rewrite the payload scan to use a checked 'tcp_data' pointer, test 'tcp_data + i + 1 <= data_end', and cap the loop with a fixed maximum... | Rewrite the payload walk around a verified 'tcp_data' pointer and add an explicit maximum iteration bound so both the packet-access proof... | There are two issues here. First is an off by 1 error in the loop, you need to account for the width of the read in the for loop conditio... |
| `stackoverflow-76960866` | `source_bug` | `1/1/1` | `1/1/1` | Do not dereference newsock directly; read the field via bpf_probe_read_kernel(&sk, sizeof(sk), &newsock->sk) and then inspect the resulti... | Re-read the socket field through bpf_probe_read_kernel using &newsock->sk, then pass that verified value to extract_sock_key. | In the C world you are casting the pointer in PARAM2 to a (struct socket *) but the verifier does not see that. It only sees that you too... |
| `stackoverflow-77205912` | `source_bug` | `1/1/1` | `1/0/0` | After 'skb_store_bytes' and the checksum helpers, reload 'data', 'data_end', and the IP/TCP pointers from 'skb', or compute both checksum... | Clamp the checksum offset arithmetic and keep it in a separate verified register before the second 'csum_diff'. | Re-read packet pointers from 'skb' after the helper calls, or compute the checksum work before mutating the packet. |
| `stackoverflow-77762365` | `source_bug` | `1/1/1` | `1/1/1` | Make the read length explicitly bounded before combining it with 'event->len' for the copy. | Make the read length explicitly bounded before combining it with 'event->len' for the copy. | TL;DR. The verifier is not yet smart enough to use event->len + read < MAX_READ_CONTENT_LENGTH. For the verifier to confirm that bpf_prob... |
| `stackoverflow-78958420` | `source_bug` | `1/1/1` | `1/1/1` | Track the parsed domain length, zero-init a fixed buffer, and bounds-check/copy only that many bytes. | Track the parsed domain length, zero-init a fixed buffer, and bounds-check/copy only that many bytes. | It asserts that there must at least be 254 bytes bytes in the packet after offset 62. So if you encounter a packet that is smaller than 3... |
| `stackoverflow-79045875` | `source_bug` | `1/1/1` | `1/1/1` | Pass data whose pointee type matches the kfunc contract instead of an 'UNKNOWN' pointer shape. | Pass data whose pointee type matches the kfunc contract instead of an 'UNKNOWN' pointer shape. | arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar This error is thrown because the kernel does strict type checking... |
| `stackoverflow-79348306` | `source_bug` | `1/1/1` | `1/1/1` | Delete 'BPF_CORE_READ_INTO(&file_path, file, f_path)' and call 'bpf_d_path(&file->f_path, path_buffer, sizeof(path_buffer))' directly. | Pass '&file->f_path' directly to 'bpf_d_path' and stop copying the path object onto the stack before the helper call. | Root Cause Solution |
| `github-aya-rs-aya-1324` | `verifier_limit` | `1/1/1` | `1/1/1` | Keep the logger returned by EbpfLogger::init alive for the lifetime of the program instead of dropping it immediately. | Keep the EbpfLogger handle alive instead of dropping it, so the logging map FD stays valid through program load and attach. | Also your code has the same problem as OP's. You are not actually consuming the logs. For posterity your init call is here: https://githu... |
| `github-aya-rs-aya-521` | `verifier_limit` | `1/1/1` | `0/0/0` | Reduce branching inside the 'bpf_loop' callback or replace it with a smaller bounded/unrolled loop so the verifier does not explode states. | Regenerate matching BTF and 'func_info' metadata for the 'bpf_loop' callback so the kernel can load it. | I was of the impression that loops aren't allowed at all by the verifier. Are there any examples of clever ways to get around the verifie... |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `1/1/1` | `1/1/1` | Reduce aggregate stack use across async calls or shrink the involved frames. | Reduce aggregate stack use across async calls or shrink the involved frames. | Reduce combined stack use, split call structure, or shrink frame sizes. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `1/1/1` | `1/1/1` | Refactor the call tree or shrink per-frame stack use so combined stack depth stays within limits. | Refactor the call tree or shrink per-frame stack use so combined stack depth stays within limits. | Refactor the call tree or reduce per-frame stack use so the aggregate depth stays within limits. |
| `stackoverflow-47591176` | `verifier_limit` | `1/1/1` | `1/1/1` | Load the tc program with the direct-action ('da') flag so 'TC_ACT_SHOT' is interpreted as an action result. | Load the tc program with the direct-action ('da') flag so 'TC_ACT_SHOT' is interpreted as an action result. | TL;DR: You should add direct-action flag to the tc filter command, as in Because eBPF is kind of more flexible than the traditional actio... |
| `stackoverflow-56872436` | `verifier_limit` | `1/1/1` | `1/1/1` | Rewrite the loop into a form the verifier can fully unroll, or manually unroll the 8-iteration walk and inline the helper if needed. | Make the loop verifier-visible by fully unrolling it or rewriting it so the bound/invariant is explicit at compile time. | Use a loop form the verifier can fully unroll or otherwise make the bound/invariant explicit. |
| `stackoverflow-70841631` | `verifier_limit` | `1/1/1` | `1/1/1` | Reduce verifier state explosion by simplifying or splitting the nested packet-scanning loops, hoisting checks, and keeping the per-packet... | Refactor the nested parsing loops into simpler bounded stages so verifier branching and iteration count stay below the analysis budget. | TL;DR. Your program is too complex for the verifier to analyze, as it must iterate over more than 1 million instructions to verify the fu... |
| `stackoverflow-78753911` | `verifier_limit` | `1/1/1` | `1/1/1` | Split the parser into simpler stages and hoist common checks so the bounded loop has fewer branches and state splits. | Split the program with tail calls or otherwise reduce branching and loop work so the verifier tracks fewer states. | Reduce branching/state fan-out, hoist common checks, or split the logic into simpler stages. |
| `github-aya-rs-aya-1002` | `env_mismatch` | `1/1/1` | `1/1/1` | Move mutable global state into a BPF map instead of writing static data directly. | Move mutable global state into a BPF map instead of writing static data directly. | only read from bpf_array is supported You are trying to access a static item, which is not supported in BPF. You will need to maintain st... |
| `github-aya-rs-aya-1104` | `env_mismatch` | `1/1/1` | `1/1/1` | Build the eBPF object in release mode instead of the debug/dev profile. | Build the eBPF object in release mode instead of the debug/dev profile. | The template and book have been updated to only build ebpf in release mode. Please file an issue against those if you continue to be able... |
| `github-aya-rs-aya-1233` | `env_mismatch` | `1/1/1` | `1/1/1` | Replace 'bpf_probe_read' with a helper allowed in 'cgroup_skb', or move the logic to a compatible program type. | Replace 'bpf_probe_read' with a helper allowed in 'cgroup_skb', or move the logic to a compatible program type. | Use a helper allowed in 'cgroup_skb', or move the logic to a program type that permits the read helper. |
| `github-aya-rs-aya-864` | `env_mismatch` | `1/1/1` | `1/1/1` | Stop using 'ctx.pid()' in 'TcContext'; read the PID from 'skb'/'TcContext' fields or patch Aya's wrapper so it does not call the unavaila... | Avoid 'ctx.pid()' and fetch the PID from classifier context data instead, or fix Aya's 'TcContext' helper wrapper so it stops calling 'bp... | Read the PID from 'TcContext'/'skb' instead of calling the unavailable helper. |
| `stackoverflow-69413427` | `env_mismatch` | `1/1/1` | `1/1/1` | Materialize the inode-derived key on the BPF stack and pass &key to bpf_map_lookup_elem, ideally using a scalar inode identifier instead... | Copy the inode key material into a stack local and pass a pointer to that stack object to bpf_map_lookup_elem. | In your case, BPF_CORE_READ() returns a scalar (inv), and dir to a BTF id (ptr_), and neither is suitable. You could try copying the data... |
| `stackoverflow-76441958` | `env_mismatch` | `1/1/1` | `1/1/1` | Ensure 'state_ptr' points to 8-byte aligned storage, for example an aligned struct or map value slot, before using 'atomic64_cmpxchg'. | Move the atomic state into an 8-byte aligned map value or padded struct field so the compare-and-swap target is naturally aligned. | Align the user-space data/struct layout or target an architecture/context that satisfies the atomic access requirements. |
| `stackoverflow-78236201` | `env_mismatch` | `1/1/1` | `0/0/0` | Use 'bpf_printk' or a stack-allocated format string with the correct size instead of the current printk call shape. | Re-derive the pointer immediately before the failing use instead of reusing the current value. | You are using bpf_trace_printk incorrectly, you typically stack allocate the fmt, then take the sizeof the char array and pass it as the... |
| `stackoverflow-79812509` | `env_mismatch` | `1/1/1` | `1/1/1` | Use 'bpf_get_current_task_btf()' so the task pointer stays trusted for 'bpf_task_storage_get'. | Use 'bpf_get_current_task_btf()' so the task pointer stays trusted for 'bpf_task_storage_get'. | TL;DR. This is happening because the bpf_get_current_task helper doesn't preserve the type of the returned pointer. Instead, you'll want... |

## Cases Where Condition B Does Better

### `github-aya-rs-aya-1062`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/0/0`
- Condition B score: `1/1/1`
- Ground truth: Avoid 'unwrap'/panic paths in eBPF and rewrite to explicit error handling or unsigned/clamped arithmetic.
- A fix: Add or tighten the bounds check immediately before the failing access.
- B fix: Replace 'ctx.ret().unwrap()' with explicit error handling and clamp the resulting length before the read.
- Notes: Condition B helped: the proof-oriented diagnostic pulled the repair from a reject-site patch toward the underlying lowering/proof-loss cause.

### `stackoverflow-70729664`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/0/0`
- Condition B score: `1/1/1`
- Ground truth: The verifier errors because it thinks R7 is outside the packet's known bounds. It tells us you're trying to make an access of size 1B at offset 26 into the packet pointer, but the packet has a known size of 0 (r=0, fo...
- A fix: Tighten the SCTP chunk-walk check so the code revalidates 'nh->pos + size + 4' against 'data_end' before reading the next chunk type.
- B fix: Clamp the computed chunk advance to a small unsigned max such as 'MAX_PACKET_OFF' and keep the offset arithmetic in a separate verified register before dereferencing 'nh->pos'.
- Notes: Condition B helped; the raw log mostly suggests a reject-site bounds check, while the diagnostic points to the proof-loss site in the chunk-offset arithmetic.

### `stackoverflow-74178703`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/0/0`
- Condition B score: `1/1/1`
- Ground truth: Recompute and access through the same checked pointer expression inside the loop body.
- A fix: Add or tighten the bounds check immediately before the failing access.
- B fix: Recompute and dereference through the same checked 'b + offset + i' expression inside the loop body.
- Notes: Condition B helped: the additional diagnostic context disambiguated the root cause and improved the repair.

### `stackoverflow-79485758`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/0/0`
- Condition B score: `1/1/1`
- Ground truth: The verifier complains on the packet access because the access seems to be out of the known packet bounds. The access is at offset 0, with a size of 2 bytes. The known packet length is 0 (r=0). Hence the program is re...
- A fix: Add a stronger guard before x = *((uint16_t *)(data + field_offset)), rejecting any case where field_offset or that 2-byte read may run past packet end.
- B fix: Clamp field_offset into a verifier-friendly unsigned range and read through a separately checked pkt_ptr before dereferencing it.
- Notes: Condition B helped; the raw log invites a symptom-level bounds tweak, while OBLIGE points to the MAX_PACKET_OFF-style clamp and checked-pointer workaround.

### `stackoverflow-61945212`

- Taxonomy: `source_bug`
- Condition A score: `1/0/0`
- Condition B score: `1/1/1`
- Ground truth: Use 'bpf_map_push_elem'/'pull'/'peek' for queue maps instead of 'bpf_map_update_elem()'.
- A fix: Fix the helper call site by passing a real stack-backed key to bpf_map_update_elem, or switch to a keyed map if you need keyed updates.
- B fix: Replace bpf_map_update_elem with the queue-map API, e.g. bpf_map_push_elem(&queue_map, &value, 0).
- Notes: Condition B helped; it turns a symptom-level arg2 repair into the correct queue-map API change.

## Cases Where Condition B Does Worse

### `stackoverflow-79530762`

- Taxonomy: `lowering_artifact`
- Condition A score: `1/1/1`
- Condition B score: `1/0/0`
- Ground truth: Rewrite the code so the checked pointer/value is reused directly and the proof survives lowering.
- A fix: Introduce a temporary checked pointer and read/write through that exact pointer instead of recomputing 'data_bytes + i + option_length' after the bounds check.
- B fix: Add a stronger 'data_bytes + i + option_length + 1 <= data_end' guard immediately before the write.
- Notes: Condition B hurt. Raw log plus source already suggested a lowering-induced pointer-reuse bug, while the diagnostic pushed toward another surface bounds check.

### `github-aya-rs-aya-521`

- Taxonomy: `verifier_limit`
- Condition A score: `1/1/1`
- Condition B score: `0/0/0`
- Ground truth: I was of the impression that loops aren't allowed at all by the verifier. Are there any examples of clever ways to get around the verifier for this? (bounded small for i in 0..5 has no issues for me though, I guess they're being unrolled). My use case for a loop at this point is to walk over each fixed chunk of a packet and do some parsing. Yeah I've done this many times. Loops are not unrolled, but you need to minimize the branching factor of the loop body in order not to run out of instructions.
- A fix: Reduce branching inside the 'bpf_loop' callback or replace it with a smaller bounded/unrolled loop so the verifier does not explode states.
- B fix: Regenerate matching BTF and 'func_info' metadata for the 'bpf_loop' callback so the kernel can load it.
- Notes: Condition B hurt. The raw packet context still points to verifier complexity in the loop body, while the diagnostic diverts entirely to BTF metadata.

### `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `0/0/0`
- Ground truth: Pass the dynptr object at its exact stack slot / constant base address.
- A fix: Pass the dynptr from its exact stack slot/base address instead of an offset or forged pointer.
- B fix: Regenerate or align the BTF / func_info metadata for this build.
- Notes: Condition B hurt: the diagnostic pulled attention toward a misleading proof/BTF story instead of the actual fix.

### `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `0/0/0`
- Ground truth: Destroy or release the iterator on every exit path, including the callee path.
- A fix: Destroy the iterator on every exit path, including the callee path that currently leaks it.
- B fix: Regenerate or align the BTF / func_info metadata for this build.
- Notes: Condition B hurt: the diagnostic pulled attention toward a misleading proof/BTF story instead of the actual fix.

### `stackoverflow-75294010`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `0/0/0`
- Ground truth: Root Cause The fourth argument to bpf_perf_event_output should be a pointer to the data to post on the ring buffer. Hence, you want to pass event as the argument, not &event.
- A fix: Pass 'event' to 'bpf_perf_event_output' instead of '&event', so the helper receives the record buffer rather than a pointer to the pointer.
- B fix: Re-derive the 'event' pointer from the verified map lookup before each dereference and write.
- Notes: Condition B hurt. The raw source exposes the pointer-to-pointer bug in 'bpf_perf_event_output', while the diagnostic redirects attention to an earlier symptom.

### `stackoverflow-78236201`

- Taxonomy: `env_mismatch`
- Condition A score: `1/1/1`
- Condition B score: `0/0/0`
- Ground truth: You are using bpf_trace_printk incorrectly, you typically stack allocate the fmt, then take the sizeof the char array and pass it as the second argument. I recommend you switch all usages to bpf_printk from bpf/bpf_helpers.h, since it does work exactly like you are invoking it right now. This macro does all of the heavy lifting for you.
- A fix: Use 'bpf_printk' or a stack-allocated format string with the correct size instead of the current printk call shape.
- B fix: Re-derive the pointer immediately before the failing use instead of reusing the current value.
- Notes: Condition B hurt: the diagnostic pulled attention toward a misleading proof/BTF story instead of the actual fix.

### `stackoverflow-70760516`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `1/0/0`
- Ground truth: Now, to fix this we need to change the code so data can't exceed 65536. We do this by specifying a maximum amount of iterations(extensions) and setting the max size of each extension. I modified the program to add these constrains, I chose max 32 extensions and max 2048 bytes per extension which seems sane values (32 * 2048 = 65536), these can be changed.
- A fix: Cap the number of parsed extensions and tighten per-extension and server-name lengths so the cumulative packet offset cannot grow past 64K.
- B fix: Insert an explicit 'data + sizeof(struct extension) <= data_end' check right before reading 'ext->type'.
- Notes: Condition B hurt. The accepted fix constrains loop growth and total offset, while the diagnostic steers toward a redundant local bounds check.

### `stackoverflow-77205912`

- Taxonomy: `source_bug`
- Condition A score: `1/1/1`
- Condition B score: `1/0/0`
- Ground truth: Re-read packet pointers from 'skb' after the helper calls, or compute the checksum work before mutating the packet.
- A fix: After 'skb_store_bytes' and the checksum helpers, reload 'data', 'data_end', and the IP/TCP pointers from 'skb', or compute both checksum diffs before mutating the packet.
- B fix: Clamp the checksum offset arithmetic and keep it in a separate verified register before the second 'csum_diff'.
- Notes: Condition B hurt. The raw case points to helper-induced packet-pointer invalidation, while the diagnostic turns it into an arithmetic-clamp problem.

## Cases Where Both Conditions Are Equal

### `stackoverflow-70750259`

- Taxonomy: `lowering_artifact`
- Shared score: `1/1/1`
- Ground truth: Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an unsigned form.
- A fix: Keep ext_len unsigned and clamp it before data += ext_len; avoid the signed or volatile conversion that makes the verifier lose the range proof.
- B fix: Compute ext_len in a separate verified unsigned register, clamp it to the remaining packet span, then advance data with that checked value.
- Notes: Condition B tied; the raw log already exposed the unbounded offset arithmetic, and OBLIGE mainly sharpened the proof-loss explanation.

### `stackoverflow-72575736`

- Taxonomy: `lowering_artifact`
- Shared score: `0/0/0`
- Ground truth: TL;DR. You are missing bug fix 2fa7d94afc1a for the BPF verifier. It was backported to the v5.13 kernel you are using as commit e7a61f15beea, but not to the v5.10 kernel. You might want to try a newer Android kernel i...
- A fix: Add an explicit unsigned clamp on 'off'/'i' and dereference the same checked 'address' register inside the loop.
- B fix: Clamp the offset to a small unsigned range and keep the offset calculation in a separate verified register before dereference.
- Notes: Condition B tied A. Both conditions chase a source rewrite, while the accepted fix is upgrading/backporting the kernel verifier fix.

### `stackoverflow-73088287`

- Taxonomy: `lowering_artifact`
- Shared score: `1/0/0`
- Ground truth: Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed pointer identical.
- A fix: Add or tighten the bounds check immediately before the failing access.
- B fix: Add or tighten the bounds check immediately before the failing access.
- Notes: Condition B tied: both conditions stayed anchored on the reject site and missed the deeper cause.

### `stackoverflow-75058008`

- Taxonomy: `lowering_artifact`
- Shared score: `1/0/0`
- Ground truth: TL;DR. Making your matchPrefix function a static inline one should work around the verifier issue. I believe this is happening because the BPF verifier recognizes your function as a global one (vs. inlined) and theref...
- A fix: Add a null check in the same function right before the dereference.
- B fix: Add a null check in the same function right before the dereference.
- Notes: Condition B tied: both conditions stayed anchored on the reject site and missed the deeper cause.

### `stackoverflow-76160985`

- Taxonomy: `lowering_artifact`
- Shared score: `1/1/1`
- Ground truth: Mark the helper '__always_inline' or otherwise keep the proof within one function.
- A fix: Mark 'find_substring' and, if needed, 'mystrlen' as '__always_inline' so the verifier sees the caller's proof in one function.
- B fix: Mark 'find_substring' as '__always_inline' so the string-walk proof stays in the caller instead of being validated as a separate subprogram.
- Notes: Condition B tied; the raw log already exposed the separate-subprog validation, and the diagnostic was misleading but not enough to change the repair.

### `github-aya-rs-aya-407`

- Taxonomy: `source_bug`
- Shared score: `1/1/1`
- Ground truth: It is just a minor thing (for me) as I have a workaround, but I wonder if it is intended to work only with u32/i32 for PerfEventArray, if this is a missing feature or some limitation in the Linux Kernel itself? The eB...
- A fix: Pass the scalar value expected by the call rather than an unsupported pointer wrapper.
- B fix: Pass the scalar value expected by the call rather than an unsupported pointer wrapper.
- Notes: Condition B tied: the raw verifier log already gave enough information, so the diagnostic did not materially change the repair.

### `stackoverflow-60053570`

- Taxonomy: `source_bug`
- Shared score: `1/1/1`
- Ground truth: The to_size passed as third argument should be a number of bytes. Assuming that you copied ICMP_ECHO_LEN from kernel selftests, I suspect its value is 64, thus asking the kernel to compute a checksum on a 64-bytes lon...
- A fix: Change the 'bpf_csum_diff' length argument to the actual ICMP header size, such as 'sizeof(struct icmphdr)', unless the code first proves a larger region is in bounds.
- B fix: Use the correct byte length at 'bpf_csum_diff' for the ICMP header instead of the larger unchecked constant, or add a dominating proof for that larger size.
- Notes: Condition B tied; the raw log already localizes the checksum-size bug at the helper call.

### `stackoverflow-67402772`

- Taxonomy: `source_bug`
- Shared score: `1/1/1`
- Ground truth: The error is not caused by bpf_trace_prink(), but by the skb accesses that are present in your bytecode only when you call bpf_trace_printk(). Accessing skb->local_ip4 and skb->remote_ip4 is not allowed for programs o...
- A fix: Stop reading 'skb->local_ip4' and 'skb->remote_ip4' in this 'lwt_out' program; use an allowed context field/API or move the logic to a program type that exposes them.
- B fix: Replace the forbidden 'skb' member reads with a verifier-allowed field or helper, or run this logic in a program type that permits those offsets.
- Notes: Condition B tied A. The raw log already pinpointed unsupported '__sk_buff' field access, so the extra diagnostic did not materially change the repair.

## Overall Conclusion

Condition B underperformed Condition A on root-cause targeting in this run; the diagnostic text may need tighter repair-oriented guidance.
