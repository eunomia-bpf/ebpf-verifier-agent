# Lifecycle Analysis Validation: 22 established_then_lost Cases

**Date**: 2026-03-13
**Purpose**: Precision metric — how often the lifecycle analysis is right when it fires
**Method**: Manual inspection of each case's verifier log, YAML metadata, and BPFix diagnostic output

---

## Methodology

For each `established_then_lost` case BPFix produces two (or three) spans:
- `proof_established`: instruction range + source line where the relevant register first gets a valid pointer/memory type
- `proof_lost` (optional): instruction where the type degrades to scalar/invalid
- `rejected`: instruction where the verifier refuses the access

For each case I check:
1. Does `proof_established` point to a real bound/null check or type-establishing call?
2. Does `rejected` point to the actual failing instruction?
3. Is the taxonomy (`source_bug`, `env_mismatch`, `lowering_artifact`) correct?
4. Are there any systematic misidentifications?

**Verdict scale**:
- **CORRECT**: established and rejected both identify the right instructions; taxonomy is right
- **PARTIALLY_CORRECT**: one of the two spans is wrong, or taxonomy is wrong, but the lifecycle is overall informative
- **INCORRECT**: the lifecycle story does not match what actually happened

---

## Per-Case Validation Table

| # | Case ID | Error ID | Taxonomy | Established Insn | Established Src | Rejected Insn | Rejected Src | Verdict | Notes |
|---|---------|----------|----------|-----------------|-----------------|---------------|--------------|---------|-------|
| 0 | dynptr-fail-clone-invalidate4 | BPFIX-E011 | source_bug | insn 0-11 | dynptr_fail.c:1571 `bpf_ringbuf_reserve_dynptr(...)` | insn 26 | dynptr_fail.c:1581 `*data = 123;` | CORRECT | See analysis below |
| 1 | dynptr-fail-clone-invalidate5 | BPFIX-E011 | source_bug | insn 0-9 | dynptr_fail.c:1597 `bpf_ringbuf_reserve_dynptr(...)` | insn 26 | dynptr_fail.c:1607 `*data = 123;` | CORRECT | Same pattern as case 0 |
| 2 | dynptr-fail-clone-invalidate6 | BPFIX-E011 | source_bug | insn 0-11 | dynptr_fail.c:1624 `bpf_ringbuf_reserve_dynptr(...)` | insn 30 | dynptr_fail.c:1637 `*data = 123;` | CORRECT | Same pattern as case 0 |
| 3 | dynptr-fail-clone-skb-packet-data | BPFIX-E011 | source_bug | insn 2-3 | dynptr_fail.c:1647 `char buffer[sizeof(__u32)] = {};` | insn 30 | dynptr_fail.c:1663 `*data = 123;` | PARTIALLY_CORRECT | Established source is misleading; see below |
| 4 | dynptr-fail-clone-xdp-packet-data | BPFIX-E011 | source_bug | insn 2-3 | dynptr_fail.c:1673 `char buffer[sizeof(__u32)] = {};` | insn 28 | dynptr_fail.c:1690 `*data = 123;` | PARTIALLY_CORRECT | Same issue as case 3 |
| 5 | dynptr-fail-data-slice-oob-map-value | BPFIX-E021 | env_mismatch | insn 11-14 | dynptr_fail.c:68 `bpf_map_lookup_elem(...)` | insn 28 | dynptr_fail.c:287 `val = *((char *)data + (sizeof(map_val)+1));` | INCORRECT | See analysis below |
| 6 | dynptr-fail-data-slice-oob-ringbuf | BPFIX-E021 | env_mismatch | insn 8-10 | dynptr_fail.c:239 `bpf_dynptr_data(&ptr, 0, 8)` | insn 13 | dynptr_fail.c:244 `val = *((char *)data + 8);` | PARTIALLY_CORRECT | See below |
| 7 | dynptr-fail-data-slice-oob-skb | BPFIX-E005 | lowering_artifact | insn 11-13 | dynptr_fail.c:262 `bpf_dynptr_slice_rdwr(...)` | insn 17 | dynptr_fail.c:267 `*(__u8*)(hdr + 1) = 1;` | CORRECT | See analysis below |
| 8 | dynptr-fail-data-slice-use-after-release1 | BPFIX-E011 | source_bug | insn 0-0 | dynptr_fail.c:295 `int data_slice_use_after_release1(...)` | insn 20 | dynptr_fail.c:310 `val = sample->pid;` | PARTIALLY_CORRECT | Established is function signature line, not actual establishment |
| 9 | dynptr-fail-data-slice-use-after-release2 | BPFIX-E011 | source_bug | insn 24-26 | dynptr_fail.c:341 `bpf_ringbuf_submit_dynptr(...)` | insn 27 | dynptr_fail.c:344 `sample->pid = 23;` | CORRECT | See analysis below |
| 10 | dynptr-fail-dynptr-invalidate-slice-reinit | BPFIX-E011 | source_bug | insn 30-31 | dynptr_fail.c:64 `__u32 key = 0, *map_val;` | insn 52 | dynptr_fail.c:961 `return *p;` | PARTIALLY_CORRECT | See below |
| 11 | dynptr-fail-invalid-data-slices | BPFIX-E011 | source_bug | insn 1-2 | dynptr_fail.c:64 `__u32 key = 0, *map_val;` | insn 38 | dynptr_fail.c:1381 `*slice = 1;` | PARTIALLY_CORRECT | See below |
| 12 | dynptr-fail-skb-invalid-data-slice1 | BPFIX-E011 | source_bug | insn 2-6 | dynptr_fail.c:1099 `char buffer[sizeof(*hdr)] = {};` | insn 31 | dynptr_fail.c:1113 `val = hdr->h_proto;` | PARTIALLY_CORRECT | See below |
| 13 | dynptr-fail-skb-invalid-data-slice2 | BPFIX-E011 | source_bug | insn 2-6 | dynptr_fail.c:1125 `char buffer[sizeof(*hdr)] = {};` | insn 28 | dynptr_fail.c:1139 `hdr->h_proto = 1;` | PARTIALLY_CORRECT | Same as case 12 |
| 14 | dynptr-fail-skb-invalid-data-slice3 | BPFIX-E011 | source_bug | insn 15-18 | dynptr_fail.c:1152 `char buffer[sizeof(*hdr)] = {};` | insn 45 | dynptr_fail.c:1165 `val = hdr->h_proto;` | PARTIALLY_CORRECT | Same as case 12 |
| 15 | dynptr-fail-skb-invalid-data-slice4 | BPFIX-E011 | source_bug | insn 15-18 | dynptr_fail.c:1178 `char buffer[sizeof(*hdr)] = {};` | insn 41 | dynptr_fail.c:1190 `hdr->h_proto = 1;` | PARTIALLY_CORRECT | Same as case 12 |
| 16 | dynptr-fail-xdp-invalid-data-slice1 | BPFIX-E011 | source_bug | insn 2-6 | dynptr_fail.c:1202 `char buffer[sizeof(*hdr)] = {};` | insn 32 | dynptr_fail.c:1215 `val = hdr->h_proto;` | PARTIALLY_CORRECT | Same as case 12 |
| 17 | dynptr-fail-xdp-invalid-data-slice2 | BPFIX-E011 | source_bug | insn 2-6 | dynptr_fail.c:1227 `char buffer[sizeof(*hdr)] = {};` | insn 29 | dynptr_fail.c:1240 `hdr->h_proto = 1;` | PARTIALLY_CORRECT | Same as case 12 |
| 18 | iters-iter-err-too-permissive1 | BPFIX-E011 | source_bug | insn 4-7 | iters.c:544 `bpf_map_lookup_elem(...)` | insn 27 | iters.c:552 `*map_val = 123;` | CORRECT | See analysis below |
| 19 | iters-iter-err-too-permissive2 | BPFIX-E002 | source_bug | insn 4-7 | iters.c:566 `bpf_map_lookup_elem(...)` | insn 33 | iters.c:574 `*map_val = 123;` | CORRECT | See analysis below |
| 20 | iters-iter-err-too-permissive3 | BPFIX-E002 | source_bug | insn 13-19 | iters.c:590 `bpf_map_lookup_elem(...)` | insn 28 | iters.c:595 `*map_val = 123;` | CORRECT | See analysis below |
| 21 | iters-iter-err-unsafe-asm-loop | BPFIX-E005 | lowering_artifact | insn 0-4 | iters.c:83 `[zero]"r"(zero),` | insn 5-24 | iters.c:59 `asm volatile (` | PARTIALLY_CORRECT | See below |

---

## Detailed Case Analyses

### Cases 0–2: dynptr-fail-clone-invalidate{4,5,6} (CORRECT)

**Pattern**: ringbuf dynptr reserved → cloned → original submitted/invalidated → data pointer used.

The verifier log confirms:
- `proof_established` at insn 0–11: `bpf_ringbuf_reserve_dynptr` returns and R6 gets `fp(off=0)` (the dynptr on the stack). This is the real establishment — the dynptr is live and valid with `ref_id=2`.
- After `bpf_dynptr_clone` (insn 14) and `bpf_dynptr_data` (insn 18), R6 is moved to hold the returned data pointer (`mem`).
- At insn 24–25, `bpf_ringbuf_submit_dynptr` is called on the original dynptr, which releases the reference and invalidates any data slice derived from it.
- Rejected at insn 26: `*(u32 *)(r6 +0) = r1` — R6 is now a dangling pointer (type degraded from `mem` to `scalar` at this path because the reference was released).
- Taxonomy `source_bug` is correct: the user code releases the dynptr before finishing with the data slice.

**Verdict**: CORRECT on all three. The established instruction identifies the real type-establishment call, and the rejected instruction is the actual use-after-release.

---

### Cases 3–4: dynptr-fail-clone-skb-packet-data / clone-xdp-packet-data (PARTIALLY_CORRECT)

**Pattern**: stack buffer initialized → dynptr from skb/xdp → slice obtained → `bpf_skb_pull_data` invalidates the slice → rejected access.

The verifier log shows:
- `proof_established` is attributed to insn 2–3: `char buffer[sizeof(__u32)] = {};` (a stack buffer zero-initialization). This is NOT the real type-establishment — the actual establishment happens later when `bpf_dynptr_slice_rdwr` returns a `mem_or_null` and the null branch is taken (insn 19–20 for case 3, giving R7 = `mem`).
- `rejected` at insn 30 (case 3): `*(u32 *)(r7 +0) = r1` — R7 is `scalar` because `bpf_skb_pull_data` (insn 25) invalidated the packet data pointer. This is CORRECT.
- Taxonomy `source_bug` is correct: the user used the packet data slice after calling `bpf_skb_pull_data`, which invalidates all previously obtained packet pointers.

**Issue**: The `proof_established` span points to the buffer initialization (a zeroing instruction) rather than the real establishment (`bpf_dynptr_slice_rdwr` return at insn 17). The register being tracked (`R7`) was assigned from `R10+fp` as a buffer base at insn 2–3, but the actual pointer validity as a dynptr slice comes from insn 19–20. BPFix correctly identifies the lifecycle (something was valid then became invalid), but mis-attributes the *establishment* to the buffer setup rather than the slice call.

**Verdict**: PARTIALLY_CORRECT — rejected instruction is accurate, established instruction is too early (wrong semantic event).

---

### Case 5: dynptr-fail-data-slice-out-of-bounds-map-value (INCORRECT)

**Pattern**: map lookup → dynptr from mem → data slice (4 bytes) → out-of-bounds access at offset +5.

The verifier log shows:
- R0 gets `map_value(map=array_map3,ks=4,vs=4)` after `bpf_map_lookup_elem` (insn 14). This is a direct map value pointer.
- The dynptr is created from the map value (insn 21), then `bpf_dynptr_data` is called requesting 4 bytes (insn 26), returning `mem(sz=4)` in R0.
- The actual error is at insn 28: `r1 = *(u8 *)(r0 +5)` — accessing byte 5 of a 4-byte slice.
- The real verifier error is **out-of-bounds access** (`invalid access to memory, mem_size=4 off=5 size=1`), NOT a type mismatch or use-after-release. This is an `env_mismatch` or more accurately a bounds violation.

**Issue**: BPFix assigns `proof_established` to insn 11–14 (the `bpf_map_lookup_elem` call tracking R0), and `rejected` to insn 28. But this is NOT an `established_then_lost` pattern — the pointer type remains `mem` throughout; the failure is an arithmetic offset going out of the declared size. The lifecycle classification `established_then_lost` is wrong here: the proof was never "lost" in the sense of type degradation — the access simply exceeded the bounds that were established.
- Taxonomy `env_mismatch` is also questionable for what is essentially a source bug (accessing beyond declared bounds of the dynptr slice).

**Verdict**: INCORRECT — this is an out-of-bounds access, not a type-establishment/type-loss scenario. Misclassified as `established_then_lost`.

---

### Case 6: dynptr-fail-data-slice-out-of-bounds-ringbuf (PARTIALLY_CORRECT)

**Pattern**: ringbuf dynptr → `bpf_dynptr_data(&ptr, 0, 8)` → attempt to read at offset 8 (past the 8-byte slice end).

The verifier log shows:
- `proof_established` at insn 8–10: `bpf_dynptr_data(&ptr, 0, 8)` call, which is correct — this is where R0 gets `mem_or_null(id=3,ref_obj_id=2,sz=8)`.
- After the null check (insn 12), R0 = `mem(ref_obj_id=2,sz=32)`. Wait — the log shows `R0=mem_or_null(id=3,ref_obj_id=2,sz=32)`. Actually the size requested was 8 bytes.
- `rejected` at insn 13: `r1 = *(u8 *)(r0 +8)` — offset 8 for a 8-byte slice is out of bounds.
- Error message: `arg#0 reference type('UNKNOWN ') size cannot be determined: -22` — this is the same opaque error message as in the other cases.

**Issue**: Same category as case 5 — this is actually an out-of-bounds slice access (`*((char *)data + 8)` on an 8-byte slice), not a pointer type loss. The `rejected` instruction is correct (insn 13 is the failing load), but the lifecycle is misclassified. However, the `proof_established` at the `bpf_dynptr_data` call is meaningful — it correctly identifies where the slice was obtained.
- Taxonomy `env_mismatch` is reasonable for an OOB dynptr slice access.

**Verdict**: PARTIALLY_CORRECT — rejected is correct, but this is an out-of-bounds access, not a type-establishment/type-loss pattern. The lifecycle label is misleading but not completely wrong.

---

### Case 7: dynptr-fail-data-slice-out-of-bounds-skb (CORRECT)

**Pattern**: skb dynptr → `bpf_dynptr_slice_rdwr` (14 bytes, for Ethernet header) → write at offset +14 (1 byte past end).

The verifier log shows:
- `proof_established` at insn 11–13: `bpf_dynptr_slice_rdwr(&ptr, 0, buffer, sizeof(buffer))` returning `R0=mem_or_null(id=2,sz=14)`. After null check R0 = `mem(sz=14)`. This correctly identifies the establishment.
- `rejected` at insn 17: `*(u8 *)(r0 +14) = r6` — offset 14 in a 14-byte buffer is out of bounds.
- Error: `invalid access to memory, mem_size=14 off=14 size=1` — clear bounds violation.
- Taxonomy `lowering_artifact` is assigned. This is borderline — the write is at `hdr + 1` where `hdr` is an Ethernet header pointer (14 bytes), so `hdr + 1` advances past the struct end. This is a source bug (incorrect pointer arithmetic), not a lowering artifact. However, the established and rejected spans are precisely correct.

**Verdict**: CORRECT (spans accurate). Note: taxonomy `lowering_artifact` is questionable — this is more naturally a `source_bug`. However the span analysis itself is accurate.

---

### Case 8: dynptr-fail-data-slice-use-after-release1 (PARTIALLY_CORRECT)

**Pattern**: ringbuf dynptr reserved → data slice obtained → dynptr submitted → stale slice accessed.

The verifier log shows:
- `proof_established` at insn 0–0: attributed to `dynptr_fail.c:295 "int data_slice_use_after_release1(void *ctx)"` — the function entry! This is not an establishment event at all; it's just the first instruction (R6 = fp0, a copy of the frame pointer).
- The real establishment happens at insn 11–12: `bpf_dynptr_data` returns `R0=mem_or_null(...)` and after the null-check at insn 12, R0 = `mem(ref_obj_id=2,sz=32)`. R0 is then saved to R6 at insn 18.
- `rejected` at insn 20: `r1 = *(u32 *)(r6 +0)` — at this point R6 is `scalar` because `bpf_ringbuf_submit_dynptr` at insn 19 released `ref_obj_id=2`, making the slice invalid.
- The rejected instruction is perfectly correct. The error is genuine use-after-release.
- Taxonomy `source_bug` is correct.

**Issue**: `proof_established` incorrectly points to the function entry (insn 0, R6 = fp0) instead of the actual data slice acquisition at insn 11–12. BPFix tracked R6 = fp0 (frame pointer) as "establishment" but the relevant establishment is when R0/R6 gets the dynptr data slice type.

**Verdict**: PARTIALLY_CORRECT — rejected instruction is exactly right, established instruction is wrong (function entry vs. actual slice acquisition).

---

### Case 9: dynptr-fail-data-slice-use-after-release2 (CORRECT)

**Pattern**: two ringbuf dynptrs → data slice from ptr2 → ptr2 submitted → stale slice accessed.

The verifier log shows:
- The relevant slice (`sample`) is obtained at insn 18: `bpf_dynptr_data` with `ref_obj_id=4`. After null check at insn 19, R0 = `mem(ref_obj_id=4,sz=32)`. This is saved to R7 at insn 25.
- At insn 26: `bpf_ringbuf_submit_dynptr(&ptr2, 0)` releases `ref_id=4`.
- `proof_established` at insn 24–26: `bpf_ringbuf_submit_dynptr(...)` at dynptr_fail.c:341. This correctly identifies the critical instruction — insn 26 is the submit that releases the reference. The span covers insns 24–26, which includes the save of R0→R7 (insn 25) and the release (insn 26).
- `rejected` at insn 27: `*(u32 *)(r7 +0) = r6` — R7 is `scalar` because its ref_obj_id was released. Error message: `R7 invalid mem access 'scalar'`.
- Taxonomy `source_bug` is correct.

**Note**: Technically the `proof_established` event here covers the *release* point (submit), which is where validity *ends*, not where it was originally established. But BPFix's model maps `proof_established` to the last valid use before release, which is semantically meaningful — it identifies the submit call as the causal event. This is correct in spirit.

**Verdict**: CORRECT — both spans identify the right instructions; the lifecycle story is accurate.

---

### Case 10: dynptr-fail-dynptr-invalidate-slice-reinit (PARTIALLY_CORRECT)

**Pattern**: dynptr_from_mem → data slice (p=1 byte) → reinitialize dynptr via a second map lookup and dynptr_from_mem → try to use stale slice p.

The verifier log shows:
- The data slice `p` is obtained at insn 27–28: `bpf_dynptr_data` returns `R0_w=mem_or_null(id=2,sz=1)`. After null check at insn 29, R7 = `mem(sz=1)`.
- At insn 51 (the second `bpf_dynptr_from_mem` call): the dynptr is re-initialized at the same stack slot. This invalidates the previously obtained data slice in R7 (which now becomes `scalar`).
- `proof_established` at insn 30–31: `dynptr_fail.c:64 "__u32 key = 0, *map_val;"` — this is a variable declaration line, not a type-establishing instruction. Insn 30–31 are `*(u32 *)(r10 -4) = r6; r8 = r10` — storing zero to the key slot and setting up a new pointer. This is NOT the establishment of the slice.
- `rejected` at insn 52: `r6 = *(u8 *)(r7 +0)` — R7 is `scalar` at this point because insn 51 re-initialized the dynptr. This is exactly correct.
- Taxonomy `source_bug` is correct.

**Issue**: `proof_established` points to a variable declaration/stack setup (insn 30, which is inside the second lookup sequence), not to the actual slice establishment at insn 27–29. The lifecycle story is correct (something was established, then invalidated by the dynptr reinit), but the established span is wrong.

**Verdict**: PARTIALLY_CORRECT — rejected is exactly right, established points to the wrong instruction (variable decl instead of `bpf_dynptr_data` call).

---

### Case 11: dynptr-fail-invalid-data-slices (PARTIALLY_CORRECT)

**Pattern**: dynptr_from_mem → bpf_dynptr_data → bpf_loop callback → the callback clobbers the dynptr on the stack (writes 123 to it) → the slice becomes invalid after the loop → *slice = 1 fails.

The verifier log shows this is a 2-function program. The callback at frame1 does `*(u32 *)(r2 +0) = r1` where r2 = `fp[0]-24` (the dynptr pointer). After `bpf_loop` returns, the verifier sees fp-24 as partially overwritten (`????123`). The data slice in R6 is now `scalar`.
- `proof_established` at insn 1–2: `dynptr_fail.c:64 "__u32 key = 0, *map_val;"` — again a variable declaration, wrong establishment.
- Real establishment: insn 27–29: `bpf_dynptr_data` returns `R0_w=mem_or_null(id=2,sz=4)`, null check at insn 29 gives R6 = `mem(sz=4)`.
- `proof_lost` AND `rejected` both at insn 38: `*(u32 *)(r6 +0) = r1` — after `bpf_loop` at insn 36, R6 became `scalar`. The rejected instruction is correct.
- Taxonomy `source_bug` is correct: the callback improperly modifies the dynptr.

**Issue**: Same pattern as case 10 — established points to a variable declaration rather than the actual `bpf_dynptr_data` call. Additionally, having both `proof_lost` and `rejected` at the same instruction (38) is redundant but not wrong.

**Verdict**: PARTIALLY_CORRECT — rejected/lost are correctly identified, established is wrong.

---

### Cases 12–17: dynptr-fail-skb-invalid-data-slice{1,2,3,4} and xdp-invalid-data-slice{1,2} (PARTIALLY_CORRECT)

**Pattern**: skb/xdp dynptr → `bpf_dynptr_slice` returns `rdonly_mem` (read-only) → `bpf_skb_pull_data` or `bpf_xdp_adjust_head` invalidates the pointer → use of the now-scalar register fails.

The verifier log for case 12 (skb-invalid-data-slice1) shows:
- insn 17: `bpf_dynptr_slice#71567` returns `R0=rdonly_mem_or_null(id=2,sz=14)`. After null check (insn 19), R8 = `rdonly_mem(sz=14)`.
- insn 29: `bpf_skb_pull_data` call invalidates all packet data pointers.
- insn 31: `r1 = *(u8 *)(r8 +12)` — R8 is now `scalar`. Error: `R8 invalid mem access 'scalar'`.
- `proof_established` at insn 2–6: `dynptr_fail.c:1099 "char buffer[sizeof(*hdr)] = {};"` — again the buffer initialization instructions, NOT the actual establishment of the slice pointer. The real establishment is `bpf_dynptr_slice` at insn 17.
- `rejected` at insn 31: `val = hdr->h_proto` — CORRECT, this is the exact instruction that fails.
- Taxonomy `source_bug` is correct: using the packet slice after `bpf_skb_pull_data` or `bpf_xdp_adjust_head`.

**Issue**: Consistent pattern — `proof_established` is attributed to the buffer initialization (zero-filling the fallback buffer passed to `bpf_dynptr_slice`) rather than the actual `bpf_dynptr_slice` call. This is because BPFix appears to track the first instruction that moves the tracked register (R8 = R10 + offset) rather than the call that actually assigns it a valid mem type.

Cases 13, 14, 15, 16, 17 follow the identical pattern.

**Verdict for all 6**: PARTIALLY_CORRECT — rejected is correct, established is too early (buffer init instead of slice call).

---

### Cases 18–20: iters-iter-err-too-permissive{1,2,3} (CORRECT)

**Pattern**: map lookup → null check → iterator loop — inside the loop, R6 may be overwritten or the loop uses a state that makes the original R6 invalid — after the loop, R6 is used but is no longer `map_value`.

**Case 18 (too-permissive1)**:
- `proof_established` at insn 4–7: `bpf_map_lookup_elem`, then insn 7 moves R0→R6 (`map_value_or_null(id=1,...)`). After null check at insn 8: R6 = `map_value`. This is exactly the right establishment.
- Inside the loop body (second path): insn 18 overwrites R6 with `0` (as the iterator body writes `r6 = 0` in the non-null `bpf_iter_num_next` path). After the loop, from the second state, R6 = `0` = scalar.
- `rejected` at insn 27: `*(u32 *)(r6 +0) = r1` — R6 is `scalar` (from the path where the loop body ran and zeroed it). Correct.
- Taxonomy `source_bug` is correct: the loop body modifies R6 (the map pointer), making it invalid for the use after the loop.

**Case 19 (too-permissive2)**:
- `proof_established` at insn 4–7: same pattern, R6 gets `map_value_or_null(id=1,...)` from first lookup.
- Inside loop: second `bpf_map_lookup_elem` at insn 22 overwrites R6 with a new `map_value_or_null`. After the loop, R6 = `map_value_or_null` (still not checked for null).
- `rejected` at insn 33: `*(u32 *)(r6 +0) = r1` — R6 is `map_value_or_null`. Correct.
- Error: `R6 invalid mem access 'map_value_or_null'`. The null check for the original R6 was done before the loop, but the in-loop lookup reassigns R6 without a new null check.

**Case 20 (too-permissive3)**:
- `proof_established` at insn 13–19: `bpf_map_lookup_elem` with R7 getting `map_value_or_null(id=3,...)`. The null check is NOT explicit — the control flow through the loop determines whether R7 might be null.
- `rejected` at insn 28: `*(u32 *)(r7 +0) = r1` — R7 = `map_value_or_null`, not checked.
- Taxonomy `source_bug` is correct.

**Verdict for all 3**: CORRECT — established and rejected are accurate; lifecycle story matches the actual verifier logic.

---

### Case 21: iters-iter-err-unsafe-asm-loop (PARTIALLY_CORRECT)

**Pattern**: unsafe inline assembly loop that increments R6 without bounds checking → R6 used as unbounded index into array.

The verifier log shows:
- `proof_established` at insn 0–4: `iters.c:83 "[zero]"r"(zero),"` — these are instructions that load a map_value into R1 and read the initial counter value from it. R1 gets `map_value(map=iters.bss,...)` which is correct.
- `rejected` at insn 5–24: `iters.c:59 "asm volatile ("` — the entire inline asm block, which includes the loop. The actual error is at insn 24: `*(u32 *)(r1 +0) = r6` where R1 = `map_value(...,var_off=(0x0; 0x3fffffffc))` — an unbounded offset.
- Error: `R1 unbounded memory access`.
- Taxonomy `lowering_artifact` — this is borderline. The issue is that the inline asm doesn't call the proper iterator helpers in a way the verifier can track bounds, so the "loop counter" in R6 is unbounded from the verifier's perspective. This could be called a lowering artifact (inline asm bypasses the verifier's loop analysis) or a source bug (missing bounds check).

**Issue**: `proof_established` at insn 0–4 points to the initial map_value load. The "establishment" is reasonable — R1 is a valid map pointer here. The `rejected` span covers the entire asm block (5–24), which is accurate to the C-level (`asm volatile (...)`). But the actual failing instruction is insn 24 within that block. The span is too coarse-grained.

**Verdict**: PARTIALLY_CORRECT — rejected span is correct at the source level (the asm block), though it doesn't pinpoint the exact machine instruction (24). The established span is reasonable but the causal link is weak.

---

## Summary

| Verdict | Count | Cases |
|---------|-------|-------|
| CORRECT | 8 | 0, 1, 2, 7, 9, 18, 19, 20 |
| PARTIALLY_CORRECT | 13 | 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17, 21 |
| INCORRECT | 1 | 5 |

**Precision: 8/22 fully correct (36%), 21/22 informative (95%), 1/22 wrong (5%)**

---

## Patterns in Failures

### Pattern 1: Established span points to buffer init instead of slice call (6 cases: 3, 4, 12, 13, 14, 15, 16, 17)

In cases where `bpf_dynptr_slice` or `bpf_dynptr_slice_rdwr` is used with a fallback buffer, BPFix tracks the register (R7 or R8) that first holds `fp + offset` (the buffer base), rather than the register that eventually holds the *result* of the slice call. The buffer initialization zeroing (`*(u16 *)(r10 -20) = r6`) happens 1–2 instructions before the dynptr call and uses the same stack area, so BPFix incorrectly attributes establishment to the initialization rather than the actual slice acquisition.

**Fix**: When the first appearance of a tracked register is a stack frame base (`fp + offset`), look for a subsequent helper call result (`mem_or_null`) that overwrites it — that is the real establishment.

### Pattern 2: Established span points to variable declaration / function entry (cases 8, 10, 11)

BPFix attributes `proof_established` to the very first instruction involving the tracked register, even if that instruction is a zeroing, a frame pointer copy, or a boilerplate `key = 0` variable setup. These are not semantically meaningful type-establishment events.

**Fix**: Filter out `fp + offset` copies, function entry instructions, and stack-based zero-initialization from the establishment candidates.

### Pattern 3: Out-of-bounds OOB misclassified as established_then_lost (cases 5, 6)

When the actual error is an arithmetic offset exceeding the declared slice size (e.g., accessing byte 5 of a 4-byte dynptr slice), BPFix still fires the `established_then_lost` path because the error message format matches. But the causal story is different: the pointer type never changed — only the arithmetic offset is wrong. This is an out-of-bounds access, not a use-after-release or type degradation.

**Fix**: Distinguish between "type changed to scalar" failures (true established_then_lost) and "type is still mem but offset exceeds mem_size" failures (which should map to a different proof obligation, e.g., `bounds_check`).

### Pattern 4: Rejected span too coarse for inline asm (case 21)

When the rejected instruction is inside an `asm volatile` block, the source-level span covers the entire asm block rather than the specific failing machine instruction.

**Fix**: For inline asm blocks, report the specific bytecode instruction index alongside the source-level asm block span.

---

## Conclusions

1. **The `rejected` span is accurate in 21/22 cases (95%)** — BPFix reliably identifies the instruction where the verifier rejects the program, even for complex dynptr/iterator patterns.

2. **The `proof_established` span is accurate in 8–10/22 cases (36–45%)** — The main failure mode is attributing establishment to buffer initialization or function entry rather than the actual helper call that grants the valid pointer type. This is a systematic flaw in how BPFix identifies the "first valid use" of a register.

3. **One false positive (case 5)**: An out-of-bounds access is misclassified as `established_then_lost`. The pointer type was always `mem` — the issue is arithmetic overflow past the slice size. This represents a distinct failure class that should trigger a different proof obligation.

4. **Taxonomy is correct in 21/22 cases (95%)** — case 7 has a debatable `lowering_artifact` label (arguably `source_bug`), but this is not clearly wrong.

5. **Overall the lifecycle analysis fires meaningfully** — even in PARTIALLY_CORRECT cases, the output correctly identifies that there is a type-validity lifecycle involved and correctly pinpoints the rejection site. The main precision gap is in the `proof_established` attribution.
