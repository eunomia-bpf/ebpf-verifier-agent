# Agreement Analysis

## Overall Statistics

- Total cases: `139`
- Exact taxonomy-class agreement: `124/139` (89.21%)
- Cohen's kappa: `0.737`
- Disagreement count: `15`

## Confusion Matrix

| A \\ B | source_bug | lowering_artifact | verifier_limit | env_mismatch | verifier_bug | Row Total |
| --- | --- | --- | --- | --- | --- | --- |
| `source_bug` | 99 | 9 | 1 | 1 | 0 | 110 |
| `lowering_artifact` | 1 | 8 | 0 | 0 | 1 | 10 |
| `verifier_limit` | 0 | 0 | 3 | 1 | 0 | 4 |
| `env_mismatch` | 0 | 0 | 0 | 13 | 0 | 13 |
| `verifier_bug` | 0 | 1 | 0 | 0 | 1 | 2 |
| Column Total | 100 | 18 | 4 | 15 | 2 | 139 |

## Per-Class Agreement

Definition: `agreement_rate = both_labeled_this_class / (A_labeled_this_class + B_labeled_this_class - both_labeled_this_class)`.

| Class | A Count | B Count | Both | Union | Agreement Rate |
| --- | --- | --- | --- | --- | --- |
| `source_bug` | 110 | 100 | 99 | 111 | 89.19% |
| `lowering_artifact` | 10 | 18 | 8 | 20 | 40.00% |
| `verifier_limit` | 4 | 4 | 3 | 5 | 60.00% |
| `env_mismatch` | 13 | 15 | 13 | 15 | 86.67% |
| `verifier_bug` | 2 | 2 | 1 | 3 | 33.33% |

## Disagreement Cases

### `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196`
- Case file: `case_study/cases/kernel_selftests/kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196.yaml`
- Labeler A: `source_bug` (`BPFIX-E019`)
- Labeler B: `env_mismatch` (`BPFIX-E016`)
- A root cause: The program requests a writable slice from read-only backing memory.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The program is invoking an API or using a capability or context feature that is not available in the active program type or execution context.
- B reasoning: The failure is driven by environment and context restrictions rather than missing safety checks in the BPF logic.

### `stackoverflow-53136145`
- Case file: `case_study/cases/stackoverflow/stackoverflow-53136145.yaml`
- Labeler A: `source_bug` (`BPFIX-E011`)
- Labeler B: `lowering_artifact` (`BPFIX-E006`)
- A root cause: The code merges alternative IPv4/IPv6-derived pointers and then dereferences the merged value after the verifier has lost which checked base it came from.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: Changing the return shape alters how the compiler inlines and schedules packet-parsing code, and the emitted bytecode loses the pointer proof that the source appears to intend.
- B reasoning: The shown source does not expose an obvious missing guard, while the failure appears only after a small control-flow change, which points to proof loss during lowering.

### `stackoverflow-70729664`
- Case file: `case_study/cases/stackoverflow/stackoverflow-70729664.yaml`
- Labeler A: `source_bug` (`BPFIX-E001`)
- Labeler B: `verifier_limit` (`BPFIX-E018`)
- A root cause: The SCTP chunk walk advances through packet data without a verifier-visible proof that each chunk access stays within `data_end`.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: Increasing the fully unrolled SCTP-chunk loop to 32 iterations makes the proof shape too complex for the verifier to maintain packet-range precision.
- B reasoning: The problem appears only when loop complexity increases, which is more consistent with verifier limits than with a new missing safety check.

### `stackoverflow-70750259`
- Case file: `case_study/cases/stackoverflow/stackoverflow-70750259.yaml`
- Labeler A: `source_bug` (`BPFIX-E005`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- Manual calibration label: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The TLS extension length is carried through signed arithmetic, so the later packet-pointer addition still has a possible negative or otherwise unsafe range.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The extension length is read from packet bytes and the verifier loses the non-negative bounded interpretation before pointer arithmetic, even though the source uses an unsigned value.
- B reasoning: The bug presents as scalar-range widening after byte extraction rather than the total absence of a bounds intent.

### `stackoverflow-70760516`
- Case file: `case_study/cases/stackoverflow/stackoverflow-70760516.yaml`
- Labeler A: `source_bug` (`BPFIX-E001`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The TLS parser uses variable packet offsets, but the final packet read is not dominated by a proof for the exact bytes consumed.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The parser checks the extension header bounds, but once the cursor is advanced inside the loop the verifier no longer associates the checked range with the `ext` pointer load.
- B reasoning: The source includes the needed check, but the verifier loses it after the loop or cursor lowering.

### `stackoverflow-72074115`
- Case file: `case_study/cases/stackoverflow/stackoverflow-72074115.yaml`
- Labeler A: `source_bug` (`BPFIX-E005`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The cubic lookup-table index is not proven to stay within a safe non-negative range when lowered, so the later table read becomes an invalid pointer access.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: Even with an explicit `shift < 64` guard, the emitted code for the table lookup loses the verifier's index proof and treats the access as a raw scalar dereference.
- B reasoning: The source already contains the intended bounds check; the failure comes from the lowered proof shape.

### `stackoverflow-72560675`
- Case file: `case_study/cases/stackoverflow/stackoverflow-72560675.yaml`
- Labeler A: `verifier_bug` (`BPFIX-E010`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The same bounded copy logic is accepted on newer kernels and rejected on 4.14, which points to an older verifier limitation or defect rather than a real source-level safety bug.
- A reasoning: The strongest signal here is version-dependent or otherwise inconsistent verifier behavior, which is more consistent with a verifier defect than with a real safety bug in the source.
- B root cause: The source clamps the read size with `MIN()`, but the older verifier loses that range proof and still treats the helper length as too wide unless it is written in a simpler form.
- B reasoning: The code has the right safety intent and works on newer kernels, so the failure is better explained by proof loss than by a missing check.

### `stackoverflow-74531552`
- Case file: `case_study/cases/stackoverflow/stackoverflow-74531552.yaml`
- Labeler A: `lowering_artifact` (`BPFIX-E005`)
- Labeler B: `source_bug` (`BPFIX-E023`)
- A root cause: The source checks the state value, but the lowered signed shifts used to turn it into a stack offset widen the range and the verifier no longer has a non-negative bound.
- A reasoning: The source is trying to establish the right safety property, but that proof is lost after lowering or range widening. A verifier-friendly rewrite should preserve the intent without changing the semantics.
- B root cause: The array index derived from map state is used before being clamped to the valid automaton table range, so pointer arithmetic is attempted with an unbounded signed value.
- B reasoning: There is no dominating range proof for the table index in the source, so this is not merely a lowering problem.

### `stackoverflow-75643912`
- Case file: `case_study/cases/stackoverflow/stackoverflow-75643912.yaml`
- Labeler A: `source_bug` (`BPFIX-E001`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The loop walks the TCP payload with a variable offset, but the actual byte read is not dominated by a packet-bounds proof for every iteration.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The loop checks `tcp_data + i <= data_end`, but the verifier loses the one-byte access proof when the pointer is rebuilt from the variable TCP-data cursor inside the loop.
- B reasoning: The source clearly attempts to guard the looped packet access, so this is closer to proof loss than to a missing check.

### `stackoverflow-76160985`
- Case file: `case_study/cases/stackoverflow/stackoverflow-76160985.yaml`
- Labeler A: `source_bug` (`BPFIX-E005`)
- Labeler B: `lowering_artifact` (`BPFIX-E006`)
- Manual calibration label: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The substring helpers take generic `char *` arguments, so the verifier loses the fixed-size bound of the local buffer and later indexed reads are no longer proven safe.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: Passing a fixed-size map-backed byte array through generic string helper subprograms erases the verifier's knowledge of its length, so later indexed reads are treated as out of range.
- B reasoning: The source carries explicit maximum lengths, but the proof is lost across the function boundary rather than omitted entirely.

### `stackoverflow-76637174`
- Case file: `case_study/cases/stackoverflow/stackoverflow-76637174.yaml`
- Labeler A: `source_bug` (`BPFIX-E001`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The payload scan reaches packet bytes that are not covered by the currently proven packet range.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The loop is guarded by `data + i < data_end`, but the verifier loses the range on the recomputed packet cursor after several variable-offset steps.
- B reasoning: The source has a safety guard; the rejection comes from that proof not surviving the lowered pointer arithmetic.

### `stackoverflow-79485758`
- Case file: `case_study/cases/stackoverflow/stackoverflow-79485758.yaml`
- Labeler A: `source_bug` (`BPFIX-E005`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The packet field offset is assembled from map-derived values and only partially bounded, so the later packet pointer still has an unsafe range at the read site.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: The packet check is present, but `field_offset` is carried through signed byte arithmetic and the verifier loses the non-negative range before the dereference.
- B reasoning: The source attempts a bounds proof; the rejection comes from the lowered scalar range becoming wider than the source intent.

### `github-aya-rs-aya-1062`
- Case file: `case_study/cases/github_issues/github-aya-rs-aya-1062.yaml`
- Labeler A: `source_bug` (`BPFIX-E005`)
- Labeler B: `lowering_artifact` (`BPFIX-E005`)
- Manual calibration label: `lowering_artifact` (`BPFIX-E005`)
- A root cause: The `bpf_probe_read_user()` length comes from a signed/optional return value, so the verifier still sees a possible negative or otherwise overly wide helper length.
- A reasoning: The failing path reflects a missing proof or an invalid helper/value contract in the program itself. This is not mainly a kernel-capability problem or a verifier budget issue.
- B root cause: Using `ctx.ret().unwrap()` as the read length yields a verifier range that becomes signed or negative after lowering, while the hard-coded constant preserves a safe proof.
- B reasoning: The safe intent is clear and the only change needed is to preserve that bound in a verifier-friendly lowered form.

### `github-cilium-cilium-41412`
- Case file: `case_study/cases/github_issues/github-cilium-cilium-41412.yaml`
- Labeler A: `verifier_limit` (`BPFIX-E018`)
- Labeler B: `env_mismatch` (`BPFIX-E016`)
- Manual calibration label: `verifier_limit` (`unmatched`)
- A root cause: The builtins test expands into a verifier proof shape with very large instruction and state counts, so the failure is best explained by verifier analysis-budget pressure.
- A reasoning: The log points to verifier analysis-budget or complexity limits, not a specific unsafe dereference. The proof shape needs to be simplified.
- B root cause: The builtins test only fails on the COS kernel or runtime configuration with JIT hardening enabled, so the rejection is tied to the target environment rather than the source program itself.
- B reasoning: The pass or fail behavior changes with runtime configuration rather than with source fixes, which points to an environment mismatch.

### `github-cilium-cilium-41522`
- Case file: `case_study/cases/github_issues/github-cilium-cilium-41522.yaml`
- Labeler A: `lowering_artifact` (`BPFIX-E001`)
- Labeler B: `verifier_bug` (`BPFIX-E010`)
- A root cause: The program has packet checks, but the generated builtins/memcopy sequence loses the checked packet provenance and ends in an out-of-bounds packet read after the upgrade.
- A reasoning: The source is trying to establish the right safety property, but that proof is lost after lowering or range widening. A verifier-friendly rewrite should preserve the intent without changing the semantics.
- B root cause: A node-specific verifier path rejects a long-established packet access pattern inside generated Cilium code after upgrade, even though the same logical program is accepted elsewhere.
- B reasoning: The node-specific regression pattern points more strongly to verifier behavior than to a clear source-level safety omission.
