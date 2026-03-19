# Lowering Artifact Deep-Dive: Trace Analysis vs Message-Line Analysis

## Executive Summary

The manually labeled benchmark currently contains **6 confirmed `lowering_artifact` cases**. The sixth confirmed case is **`github-aya-rs-aya-1062`**, not `stackoverflow-70729664`; the task prompt’s note about possible label drift was correct.

Using a strict Pretty-Verifier-style baseline that sees **only the headline verifier error line**, message-line analysis is correct on **2/6** confirmed lowering-artifact cases. On the **5/6** confirmed cases that include usable instruction/state traces, the trace parser finds a meaningful lowering-style critical transition in **4/5**. In all four of those successes, the transition points to an instruction **different from the final failing access**.

This is the key paper result: for lowering artifacts, the unique value of full proof-trace analysis is not just better class labels. It is the ability to point at the **earlier proof-loss instruction** instead of the **later symptom instruction**.

## Method

### Ground Truth Set

Confirmed lowering-artifact cases came from [`docs/tmp/manual-labeling-30cases.md`](../tmp/manual-labeling-30cases.md):

1. `github-aya-rs-aya-1062`
2. `stackoverflow-79530762`
3. `stackoverflow-73088287`
4. `stackoverflow-74178703`
5. `stackoverflow-76160985`
6. `stackoverflow-70750259`

The prompt’s `stackoverflow-70729664` is not in the manually labeled 30-case set, but it is a strong **likely** lowering-artifact support case and is included below as qualitative evidence only.

### Message-Line Baseline

For the main comparison I used the verifier’s **single headline rejection line only**, then matched that line against [`taxonomy/error_catalog.yaml`](../../taxonomy/error_catalog.yaml). This is the right baseline for the paper because [`docs/research-plan.md`](../research-plan.md) already defines `error_message_only` as “只有 error message 那一行”.

I did **not** use the current `VerifierLogParser.parse()` output as the main baseline because that parser scans the **full log**, not just the headline line, and therefore leaks some trace context into the baseline.

### Trace Analysis

For each case I selected the richest `verifier_log.blocks[i]` entry containing instruction-level verifier output and state lines, then ran `parse_trace()` on that block. I used:

- `critical_transitions`
- `causal_chain`
- `error_insn` vs earlier transition/root-cause instruction

This normalization matters because several YAMLs include duplicated loader/runtime wrapper text in `combined`.

## Step 1: Identified Lowering-Artifact Cases

### A. Confirmed Case-Study Cases

| Case | Status | Why it is a lowering artifact |
| --- | --- | --- |
| `github-aya-rs-aya-1062` | confirmed | `ctx.ret().unwrap()` lowers into signed arithmetic that destroys the helper-length proof. |
| `stackoverflow-79530762` | confirmed | Packet bounds checks exist in source, but the compiler reuses different registers for the checked pointer and the dereferenced pointer. |
| `stackoverflow-73088287` | confirmed | `payload + i + 1` and `payload[i]` are lowered through different registers, so the verifier loses equivalence. |
| `stackoverflow-74178703` | confirmed | Loop lowering hoists `b + offset` away from the check; the failing load is not using the proof the source intended. |
| `stackoverflow-76160985` | confirmed | A separate BPF subprogram is verified without the caller-side allocation/range facts; `__always_inline` fixes it. |
| `stackoverflow-70750259` | confirmed | Signed/unsigned lowering widens a scalar range so pointer arithmetic can no longer be proved safe. |

### B. Additional Likely Case-Study Candidates

These are not part of the 30 manually labeled cases, so I do **not** count them in the accuracy statistics. I do include them as supporting evidence because the accepted fixes are verifier/codegen rewrites, not source safety fixes.

| Case | Evidence |
| --- | --- |
| `stackoverflow-70729664` | Selected answer explicitly calls it a “corner-case limitation of the verifier” even though bounds checks are present; trace parser finds `RANGE_LOSS` at insn `2940` before the failing access at `2948`. |
| `stackoverflow-75643912` | Selected answer says the failure is likely due to clang’s guard generation and suggests moving the bounds check inside the loop; trace parser finds repeated range/provenance loss before the final packet access. |

### C. `eval_commits` Inventory Suggesting Lowering Artifacts

Querying `case_study/cases/eval_commits/*.yaml` gives:

- `fix_type: inline_hint` -> **229** cases
- `fix_type: volatile_hack` -> **18** cases
- `fix_type: alignment` -> **32** cases

Representative samples:

- `inline_hint`
  - `eval-aya-11c227743de9.yaml`: “Changed inlining annotations so verifier-visible state stays in a form older kernels accept.”
  - `eval-aya-bdb2750e66f9.yaml`: “Forced write_record_header() to inline so the verifier can keep precise track of log-buffer offsets.”
- `volatile_hack`
  - `eval-bcc-8206f547b8e3.yaml`: “generate proper usdt code to prevent llvm meddling with ctx->#fields”
  - `eval-bcc-1d659c7f3388.yaml`: volatile qualifier added to force verifier-friendly code generation.
- `alignment`
  - `eval-bcc-03f9322cc688.yaml`: “Fix misaligned pointer accesses in tcpstates”
  - `eval-bcc-5a547e73d31d.yaml`: “Fix misaligned pointer accesses in tcptracer”

Interpretation:

- `inline_hint` and `volatile_hack` are very strong lowering-artifact signals.
- `alignment` is weaker and more mixed: many of these look like verifier-hostile layout/codegen artifacts, but I treat them as **likely** rather than confirmed lowering artifacts unless a manual label exists.

## Step 2-3: Confirmed-Case Comparison Table

Main table uses:

- Ground truth: manual label from `manual-labeling-30cases.md`
- Message-line diagnosis: **headline error line only**
- Trace diagnosis: whether the trace parser surfaced an earlier lowering-style transition/root cause

| Case | Usable state trace? | Headline error message | Message-line diagnosis | Message-line correct? | Trace analysis diagnosis | Root/transition vs error insn | Trace correct? |
| --- | :---: | --- | --- | :---: | --- | --- | :---: |
| `github-aya-rs-aya-1062` | yes | `R2 min value is negative, either use unsigned or 'var &= const'` | `lowering_artifact` (`BPFIX-E005`) | ✓ | Early scalar-range collapse on `R1/R2` at insns `4-8` before helper call `39`; matches the `unwrap()` lowering problem | transition at `4` vs helper failure at `39` | ✓ |
| `stackoverflow-79530762` | yes | `invalid access to packet, off=33 size=1, R4(id=10,off=33,r=0)` | `source_bug` (`BPFIX-E001`) | ✗ | `TYPE_DOWNGRADE`/`PROVENANCE_LOSS` on the checked-vs-dereferenced packet registers, plus causal chain to the failing store | causal root `15`, key transitions `20/22/26`, error `36` | ✓ |
| `stackoverflow-73088287` | no | `invalid access to packet, off=120 size=1, R4(id=0,off=135,r=120)` | `source_bug` (`BPFIX-E001`) | ✗ | No usable state trace: only a 7-insn snippet with no register-state lines | no transition available | ✗ |
| `stackoverflow-74178703` | yes | `invalid access to map value, value_size=1024 off=1024 size=1` | `source_bug` (`BPFIX-E017`) | ✗ | `BOUNDS_COLLAPSE` on `R3` at the hoisted guard computation; this is the proof-loss point, not the map load itself | transition at `204` vs failing load `195` | ✓ |
| `stackoverflow-76160985` | yes | `invalid access to memory, mem_size=1 off=1 size=1` | unmatched / surface-source-like | ✗ | No critical transition detected. The artifact is across a subprogram boundary, and the current trace parser is not yet subprog-aware enough to recover it. | error at `195`, no earlier transition found | ✗ |
| `stackoverflow-70750259` | yes | `math between pkt pointer and register with unbounded min value is not allowed` | `lowering_artifact` (`BPFIX-E005`) | ✓ | Multiple early type/provenance/range collapses before packet-pointer addition; trace shows exactly where `ext_len` loses the proof the source intended | earliest transition `6`, later key collapses `28/36`, error `39` | ✓ |

## Supporting Cases Not Counted in Accuracy Stats

| Case | Why it still matters |
| --- | --- |
| `stackoverflow-70729664` | Headline error is ordinary packet-OOB (`source_bug` if line-only), but the selected answer says the bounds proof is already present and the verifier is hitting a corner-case limitation. Trace parser finds `RANGE_LOSS` at `2940` and causal root `2940` before the failing access at `2948`. |
| `stackoverflow-75643912` | Headline error is ordinary packet-OOB (`source_bug` if line-only), but the accepted fix is a clang/verifier-friendly loop rewrite. Trace parser finds repeated `RANGE_LOSS`/provenance transitions before the failing access at `36`. |

## Step 4: Detailed Case Studies

### 1. `stackoverflow-79530762`

- Source intent: remove a custom IP option after checking `(data_bytes + i + option_length + 1) <= data_end`.
- What the compiler did: the checked address is built through one register path (`r3`/`r4` around insns `28-32`), but the actual store uses a different recomputed pointer path (`33-36`).
- What the error message says: `invalid access to packet ... R4 offset is outside of the packet`.
- What a message-line tool says: `source_bug`, “add/fix bounds check”.
- What the trace says: `TYPE_DOWNGRADE` and `PROVENANCE_LOSS` hit the relevant packet registers before the store. The causal chain links an earlier root (`15`) to the final failing store (`36`).
- Actual fix: rewrite the loop so the compared pointer and the dereferenced pointer are the same verifier-visible value. This is a lowering/codegen fix, not a missing source-level guard.

### 2. `stackoverflow-74178703`

- Source intent: copy bytes from a map value only when `offset + i < 1024`.
- What the compiler did: it hoisted/split the `b + offset` computation so the verifier no longer sees the dereference as using the checked proof.
- What the error message says: `invalid access to map value, value_size=1024 off=1024 size=1`.
- What a message-line tool says: `source_bug`, “tighten map bounds check”.
- What the trace says: `BOUNDS_COLLAPSE` on `R3` at insn `204`, i.e. at the hoisted guard/value-computation sequence rather than the failing load itself.
- Actual fix: rewrite the loop so the load uses the same checked expression (`dst -= offset; for (i = offset; ... ) memcpy(dst + i, b + i, 1);`).

### 3. `stackoverflow-70750259`

- Source intent: read TLS extension length and advance a packet pointer safely.
- What the compiler did: the length computation becomes a widened scalar with no usable signed lower bound. The source’s negative check is ineffective because the original value is logically unsigned.
- What the error message says: `math between pkt pointer and register with unbounded min value is not allowed`.
- What a message-line tool says: correctly `lowering_artifact`.
- What the trace adds: it pinpoints the proof collapse at earlier instructions (`6`, `13`, `28`, `36`) before the final pointer add at `39`. This is the difference between “what class is this?” and “where exactly did the proof disappear?”
- Actual fix: add an explicit upper-bound clamp / unsigned rewrite so the verifier gets a non-negative bound it can preserve through lowering.

### 4. `stackoverflow-70729664` (supporting, not part of the manual-30 stats)

- Source intent: walk packet data with prior bounds checks.
- What the compiler/verifier interaction did: the packet range on `R7` collapses to `r=0` after loop/cursor arithmetic even though the proof looks present in source.
- What the error message says: `invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)`.
- What a message-line tool says: `source_bug`.
- What the trace says: `RANGE_LOSS` at `2940`, with causal root `2940` and failing access `2948`.
- Actual fix: restructure cursor advancement / add a verifier-friendly explicit cap (`MAX_PACKET_OFF`) so the range proof survives.

### 5. `github-aya-rs-aya-1062`

- Source intent: use `ctx.ret().unwrap()` as the byte count for `bpf_probe_read_user`.
- What lowering did: Rust/Aya emits signed-shift/sign-extension steps (`<<= 32`, `s>>= 32`) before the helper call. That creates a verifier-visible negative lower bound.
- What the error message says: `R2 min value is negative, either use unsigned or 'var &= const'`.
- What a message-line tool says: correctly `lowering_artifact`.
- What the trace adds: it localizes the damage to insns `4-8`, well before the eventual helper failure at `39`.
- Actual fix: avoid `unwrap()` / panic-style lowering in eBPF and rewrite to explicit error handling or a clamped unsigned length.

## Statistics

### Confirmed Manual Set

- Confirmed lowering-artifact cases: **6**
- Cases with some verifier log text: **6/6**
- Cases with usable instruction/state trace: **5/6**
  - `stackoverflow-73088287` only has a short final snippet, not a real state trace

### Message-Line Baseline

- Strict one-line baseline accuracy on confirmed lowering artifacts: **2/6 = 33.3%**
- Correct cases:
  - `github-aya-rs-aya-1062`
  - `stackoverflow-70750259`
- Incorrect or unmatched cases:
  - `stackoverflow-79530762`
  - `stackoverflow-73088287`
  - `stackoverflow-74178703`
  - `stackoverflow-76160985`

### Trace Analysis

- Trace parser finds a meaningful lowering-style critical transition on **4/5 analyzable traces = 80.0%**
- If counted over the full confirmed set, that is **4/6 = 66.7%**
- On the four successful trace cases, the transition/root-cause location differs from the final failing access on **4/4**

### Conservative Accuracy Summary

If I count a trace case as correct only when the parser surfaces a transition that matches the manual lowering rationale:

- Trace accuracy on analyzable confirmed traces: **4/5 = 80.0%**
- Trace accuracy on the full confirmed set: **4/6 = 66.7%**

This is conservative because `stackoverflow-73088287` is really a missing-log problem, not a parser reasoning failure.

## Key Finding

Yes: **full proof-trace analysis adds unique value for lowering artifacts**.

The reason is not merely that it sometimes produces a better taxonomy label. The stronger result is:

1. Message-line-only analysis usually points at the **symptom instruction** (`invalid access to packet`, `invalid access to map value`) and therefore recommends a **source-level bounds fix**.
2. Trace analysis often points at a **different earlier instruction** where the verifier’s proof actually collapses (`TYPE_DOWNGRADE`, `PROVENANCE_LOSS`, `BOUNDS_COLLAPSE`, `RANGE_LOSS`).
3. That earlier instruction is exactly what explains why the real fix is `__always_inline`, loop rewriting, pointer-expression reuse, or an explicit clamp instead of “just add another bounds check”.

In short: for lowering artifacts, the paper’s claim is supportable if it is phrased as:

> Whole-trace analysis can recover the proof-loss site that message-line tools miss.

That claim is supported strongly by:

- `stackoverflow-79530762`
- `stackoverflow-74178703`
- `stackoverflow-70729664` (supporting case)
- `stackoverflow-70750259` and `github-aya-rs-aya-1062` as “message line already hints at lowering, but trace still localizes the root cause” cases

The main current gap is `stackoverflow-76160985`: subprogram-boundary lowering artifacts are real, but the current trace parser does not yet recover them.
