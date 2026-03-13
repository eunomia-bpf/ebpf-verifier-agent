# Repair Experiment V2 Rerun: Current OBLIGE Pipeline

- Generated: `2026-03-12T22:10:10+00:00`
- Selected cases: `54`
- Method: condition A held fixed from the previous v2 run; condition B diagnostics regenerated on all 54 cases with current `generate_diagnostic(verifier_log)`.
- Changed condition-B prompts: `17` of `54`; manually rescored where the regenerated prompt materially changed the likely repair.
- Manual B overrides applied: `3`

Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.

## Overall Table

| Condition | Location | Fix type | Root cause |
| --- | ---: | ---: | ---: |
| A (raw verifier log only) | 53/54 (98.1%) | 46/54 (85.2%) | 46/54 (85.2%) |
| B (previous v2 run) | 48/54 (88.9%) | 43/54 (79.6%) | 43/54 (79.6%) |
| B (current pipeline rerun) | 50/54 (92.6%) | 46/54 (85.2%) | 46/54 (85.2%) |

## Per-Taxonomy Breakdown

| Taxonomy | Cases | A loc | Prev B loc | Current B loc | A fix | Prev B fix | Current B fix | A root | Prev B root | Current B root |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 10 | 9/10 (90.0%) | 9/10 (90.0%) | 9/10 (90.0%) | 3/10 (30.0%) | 6/10 (60.0%) | 6/10 (60.0%) | 3/10 (30.0%) | 6/10 (60.0%) | 6/10 (60.0%) |
| `source_bug` | 28 | 28/28 (100.0%) | 25/28 (89.3%) | 27/28 (96.4%) | 27/28 (96.4%) | 23/28 (82.1%) | 26/28 (92.9%) | 27/28 (96.4%) | 23/28 (82.1%) | 26/28 (92.9%) |
| `verifier_limit` | 8 | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) |
| `env_mismatch` | 8 | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) | 8/8 (100.0%) | 7/8 (87.5%) | 7/8 (87.5%) |

## Per-Case Table

| Case | Taxonomy | A | Prev B | Current B | Delta | Current B fix |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `1/0/0` | `1/1/1` | `1/1/1` | `+0` | Replace `ctx.ret().unwrap()` with explicit error handling and clamp the resulting length before t... |
| `stackoverflow-70729664` | `lowering_artifact` | `1/0/0` | `1/1/1` | `1/1/1` | `+0` | Clamp the computed chunk advance to a small unsigned max such as `MAX_PACKET_OFF` and keep the of... |
| `stackoverflow-70750259` | `lowering_artifact` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Compute ext_len in a separate verified unsigned register, clamp it to the remaining packet span,... |
| `stackoverflow-72575736` | `lowering_artifact` | `0/0/0` | `0/0/0` | `0/0/0` | `+0` | Clamp the offset to a small unsigned range and keep the offset calculation in a separate verified... |
| `stackoverflow-73088287` | `lowering_artifact` | `1/0/0` | `1/0/0` | `1/0/0` | `+0` | Add or tighten the bounds check immediately before the failing access. |
| `stackoverflow-74178703` | `lowering_artifact` | `1/0/0` | `1/1/1` | `1/1/1` | `+0` | Recompute and dereference through the same checked `b + offset + i` expression inside the loop body. |
| `stackoverflow-75058008` | `lowering_artifact` | `1/0/0` | `1/0/0` | `1/0/0` | `+0` | Add a null check in the same function right before the dereference. |
| `stackoverflow-76160985` | `lowering_artifact` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Mark `find_substring` as `__always_inline` so the string-walk proof stays in the caller instead o... |
| `stackoverflow-79485758` | `lowering_artifact` | `1/0/0` | `1/1/1` | `1/1/1` | `+0` | Clamp field_offset into a verifier-friendly unsigned range and read through a separately checked... |
| `stackoverflow-79530762` | `lowering_artifact` | `1/1/1` | `1/0/0` | `1/0/0` | `+0` | Add a stronger `data_bytes + i + option_length + 1 <= data_end` guard immediately before the write. |
| `github-aya-rs-aya-407` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Pass the scalar value expected by the call rather than an unsupported pointer wrapper. |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | `1/1/1` | `0/0/0` | `1/1/1` | `+3` | Pass `&ptr` directly to `bpf_dynptr_read` instead of `(void *)&ptr + 1`, keeping the dynptr at it... |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | `1/1/1` | `0/0/0` | `1/1/1` | `+3` | Release or destroy the iterator/reference on every exit path, including the callee-return path be... |
| `stackoverflow-60053570` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Use the correct byte length at `bpf_csum_diff` for the ICMP header instead of the larger unchecke... |
| `stackoverflow-61945212` | `source_bug` | `1/0/0` | `1/1/1` | `1/1/1` | `+0` | Replace bpf_map_update_elem with the queue-map API, e.g. bpf_map_push_elem(&queue_map, &value, 0). |
| `stackoverflow-67402772` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Replace the forbidden `skb` member reads with a verifier-allowed field or helper, or run this log... |
| `stackoverflow-67679109` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Use a plain value/current variable instead of pointer arithmetic that the verifier cannot prove s... |
| `stackoverflow-69767533` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Zero-initialize `tmp_buffer` before `bpf_probe_read` and keep the copy length explicitly bounded. |
| `stackoverflow-70091221` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Declare the map with `SEC("maps")` so helper arg 1 is the actual map object. |
| `stackoverflow-70392721` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Compile with `-O2` and strip the object so libbpf sees a clean BPF program/BTF payload; this is a... |
| `stackoverflow-70721661` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Add an explicit bounds check that covers the full IP header before memcpy, not just the Ethernet... |
| `stackoverflow-70760516` | `source_bug` | `1/1/1` | `1/0/0` | `1/0/0` | `+0` | Insert an explicit `data + sizeof(struct extension) <= data_end` check right before reading `ext-... |
| `stackoverflow-70873332` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Restructure the access so the verifier can see the same bounded expression at check and dereferen... |
| `stackoverflow-71946593` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Use `bpf_probe_read*` to read the `sk_buff` member instead of direct field dereference. |
| `stackoverflow-72074115` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Add a dominating bounds check that proves the buffer access is within range on every path. |
| `stackoverflow-72606055` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Use a loader path that preserves the loader-generated map reference for `my_map` rather than send... |
| `stackoverflow-74531552` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Check *curr_state is within [0, 4) before indexing aut.function so the table access has an explic... |
| `stackoverflow-75294010` | `source_bug` | `1/1/1` | `0/0/0` | `0/0/0` | `+0` | Re-derive the `event` pointer from the verified map lookup before each dereference and write. |
| `stackoverflow-75515263` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Declare the map value as `struct sock_info` rather than a pointer so reads of `sport` and `dport`... |
| `stackoverflow-75643912` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Fix the off-by-one and width check so the loop only reads bytes that are proven in-bounds. |
| `stackoverflow-76277872` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Check bounds against the actual header/payload size you read, not just `sizeof(struct ethhdr)`. |
| `stackoverflow-76637174` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Rewrite the payload walk around a verified `tcp_data` pointer and add an explicit maximum iterati... |
| `stackoverflow-76960866` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Re-read the socket field through bpf_probe_read_kernel using &newsock->sk, then pass that verifie... |
| `stackoverflow-77205912` | `source_bug` | `1/1/1` | `1/0/0` | `1/1/1` | `+2` | After `skb_store_bytes` and the first checksum helpers, reload `data`, `data_end`, and the IP/TCP... |
| `stackoverflow-77762365` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Make the read length explicitly bounded before combining it with `event->len` for the copy. |
| `stackoverflow-78958420` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Track the parsed domain length, zero-init a fixed buffer, and bounds-check/copy only that many by... |
| `stackoverflow-79045875` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Pass data whose pointee type matches the kfunc contract instead of an `UNKNOWN` pointer shape. |
| `stackoverflow-79348306` | `source_bug` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Pass `&file->f_path` directly to `bpf_d_path` and stop copying the path object onto the stack bef... |
| `github-aya-rs-aya-1324` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Keep the EbpfLogger handle alive instead of dropping it, so the logging map FD stays valid throug... |
| `github-aya-rs-aya-521` | `verifier_limit` | `1/1/1` | `0/0/0` | `0/0/0` | `+0` | Regenerate matching BTF and `func_info` metadata for the `bpf_loop` callback so the kernel can lo... |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Reduce aggregate stack use across async calls or shrink the involved frames. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Refactor the call tree or shrink per-frame stack use so combined stack depth stays within limits. |
| `stackoverflow-47591176` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Load the tc program with the direct-action (`da`) flag so `TC_ACT_SHOT` is interpreted as an acti... |
| `stackoverflow-56872436` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Make the loop verifier-visible by fully unrolling it or rewriting it so the bound/invariant is ex... |
| `stackoverflow-70841631` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Refactor the nested parsing loops into simpler bounded stages so verifier branching and iteration... |
| `stackoverflow-78753911` | `verifier_limit` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Split the program with tail calls or otherwise reduce branching and loop work so the verifier tra... |
| `github-aya-rs-aya-1002` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Move mutable global state into a BPF map instead of writing static data directly. |
| `github-aya-rs-aya-1104` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Build the eBPF object in release mode instead of the debug/dev profile. |
| `github-aya-rs-aya-1233` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Replace `bpf_probe_read` with a helper allowed in `cgroup_skb`, or move the logic to a compatible... |
| `github-aya-rs-aya-864` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Avoid `ctx.pid()` and fetch the PID from classifier context data instead, or fix Aya's `TcContext... |
| `stackoverflow-69413427` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Copy the inode key material into a stack local and pass a pointer to that stack object to bpf_map... |
| `stackoverflow-76441958` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Move the atomic state into an 8-byte aligned map value or padded struct field so the compare-and-... |
| `stackoverflow-78236201` | `env_mismatch` | `1/1/1` | `0/0/0` | `0/0/0` | `+0` | Re-derive the pointer immediately before the failing use instead of reusing the current value. |
| `stackoverflow-79812509` | `env_mismatch` | `1/1/1` | `1/1/1` | `1/1/1` | `+0` | Use `bpf_get_current_task_btf()` so the task pointer stays trusted for `bpf_task_storage_get`. |

## Cases Where B Improved vs Previous Run

### `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`

- Taxonomy: `source_bug`
- Previous B score: `0/0/0`
- Current B score: `1/1/1`
- Ground truth: Pass the dynptr object at its exact stack slot / constant base address.
- Previous B fix: Regenerate or align the BTF / func_info metadata for this build.
- Current B fix: Pass `&ptr` directly to `bpf_dynptr_read` instead of `(void *)&ptr + 1`, keeping the dynptr at its exact stack slot / constant offset.
- Why it improved: Current OBLIGE no longer suggests generic BTF regeneration, and the prompt now supports the correct exact-stack-slot fix.

### `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09`

- Taxonomy: `source_bug`
- Previous B score: `0/0/0`
- Current B score: `1/1/1`
- Ground truth: Destroy or release the iterator on every exit path, including the callee path.
- Previous B fix: Regenerate or align the BTF / func_info metadata for this build.
- Current B fix: Release or destroy the iterator/reference on every exit path, including the callee-return path before the main program exits.
- Why it improved: The new note/help is nearly the accepted fix verbatim, so condition B should now land on the correct release-balance repair.

### `stackoverflow-77205912`

- Taxonomy: `source_bug`
- Previous B score: `1/0/0`
- Current B score: `1/1/1`
- Ground truth: Re-read packet pointers from `skb` after the helper calls, or compute the checksum work before mutating the packet.
- Previous B fix: Clamp the checksum offset arithmetic and keep it in a separate verified register before the second `csum_diff`.
- Current B fix: After `skb_store_bytes` and the first checksum helpers, reload `data`, `data_end`, and the IP/TCP pointers from `skb`, or compute the second checksum input before mutating the packet.
- Why it improved: The old arithmetic-clamp story is gone; the regenerated contract-style note now supports the accepted re-read-pointers-after-helper repair.

## Overall Conclusion

The current pipeline repairs the earlier source-bug regressions iters/dynptr and no longer drags the second `bpf_csum_diff` case toward an arithmetic-clamp fix. Condition B improves from `43/54 (79.6%)` to `46/54 (85.2%)` on both fix type and root-cause targeting, tying Condition A on those metrics while still trailing on localization.
Remaining B weaknesses are concentrated in a few unrepaired cases, especially `stackoverflow-79530762, stackoverflow-70760516, stackoverflow-75294010, github-aya-rs-aya-521, stackoverflow-78236201`.
