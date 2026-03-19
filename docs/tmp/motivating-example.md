# Motivating Example

## 2.1 A Confusing Rejection

Consider a developer writing an XDP program to parse TLS extension headers.
The program iterates over variable-length extensions and must read each
extension's `type` and `len` fields from the packet.  The developer writes
correct bounds checks before every packet access, yet the verifier rejects the
program.  The following is a simplified version of a real Stack Overflow case
(SO #70750259, 5 upvotes, 2 answers over several weeks):

```c
SEC("xdp")
int parse_extensions(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;       //  1
    void *data_end = (void *)(long)ctx->data_end;   //  2

    if (data + sizeof(struct extension) > data_end) //  3  bounds check
        return XDP_DROP;                            //  4

    struct extension *ext = data;                   //  5

    /* Read extension type — guarded by check at line 3 */
    if (ext->type == SNI_TYPE) {                    //  6  ✓ safe
        /* ... handle SNI ... */
    }

    /* Read extension length — also guarded by line 3 */
    __u16 ext_len = __bpf_htons(ext->len);          //  7  byte-swap

    data += ext_len;                                //  8  ✗ REJECTED
    /* verifier: "math between pkt pointer and register
       with unbounded min value is not allowed"     */
}
```

The developer is confused: the bounds check at line 3 guarantees that
`ext->len` is within packet bounds, and `ext_len` is a `__u16` that cannot be
negative.  Why does the verifier call it "unbounded"?


## 2.2 What Existing Tools Show

**Raw verifier log (41 instructions, shown selectively).**
The verifier emits the full abstract-interpreter trace at `LOG_LEVEL=2`.
The relevant excerpt spans roughly 60 lines of register-state dumps:

```
22: R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00))
    R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff))

22: (4f) r0 |= r6

23: R0_w=inv(id=0)                              ← bounds GONE

23: (dc) r0 = be16 r0

24: R0_w=inv(id=0)                              ← still unbounded

; if (data_end < (data + ext_len)) {
24: (0f) r5 += r0

last_idx 24 first_idx 12
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)

math between pkt pointer and register with unbounded min value
is not allowed
```

A developer not versed in BPF abstract interpretation sees register names,
hex masks, and a cryptic "unbounded min value" error with no connection to
their source code.  The verifier's own backtracking output (`regs=1 stack=0
before ...`) points to the chain of instructions that produced the bad
register, but it is expressed in bytecode, not source.


**Pretty Verifier** (regex-on-error-line tool, 91 patterns).
Pretty Verifier recognizes the error message and highlights instruction 24:

> *"The value added to the packet pointer has an unbounded minimum. Consider
> adding `& 0xFFFF` or similar mask to bound the value."*

This is better than raw text, but it tells the developer only *what went wrong
at the final instruction* — not *why* a value that was read from a
bounds-checked packet region became unbounded.  The developer may try adding a
mask at line 8 (the symptom site), which works but does not explain the root
cause.  Worse, the developer may try adding *another* bounds check at line 8,
which does not help because the verifier has already lost the scalar's range.


**LLM with raw log.**
We gave GPT-4o and Claude 3.5 the full log plus source code.  Both correctly
identify the error class ("unbounded scalar added to packet pointer") and
suggest adding a bounds mask — the same advice as Pretty Verifier.  Neither
explains *where* the bounds were lost or *why*, because the critical state
transition (OR destroying tracked bounds) is buried in the 60-line register
dump.


## 2.3 What BPFix Shows

BPFix parses the complete verifier trace, detects the critical state
transition where bounds information was destroyed, and correlates it back to
the source via BTF line annotations.  It produces:

```
error[E005]: lowering_artifact — packet access with lost proof
  ┌─ parse_extensions.c
  │
3 │     if (data + sizeof(struct extension) > data_end)
  │     ──────────────────────────────────────────────── proof established
  │     R5: pkt(off=0) → pkt(off=4, range=4)
  │
7 │     __u16 ext_len = __bpf_htons(ext->len);
  │     ────────────────────────────────────── proof lost: OR destroys tracked bounds
  │     R0: scalar(umax=65280) → scalar(unbounded)
  │
8 │     data += ext_len;
  │     ──────────────── rejected: pkt_ptr + unbounded scalar
  │
  = note: The bounds check at line 3 correctly establishes a packet-range
          proof, but LLVM lowers __bpf_htons() into a byte-load, shift, OR
          sequence.  The verifier cannot track scalar bounds across bitwise
          OR of two registers (insn 22: r0 |= r6), so R0 becomes unbounded
          even though both operands were individually bounded (0..65280 and
          0..255).
  = help: Add an explicit range clamp after the byte swap:
          ext_len &= 0xFFFF;
          — or use a volatile intermediate to prevent LLVM from merging
          the byte loads into an OR.
```

The diagnostic traces the **proof lifecycle** across three sites:

1. **Line 3 — proof established.** The bounds check `data + 4 > data_end`
   establishes `R5.range = 4`, proving that the next 4 bytes of the packet are
   safe to read.

2. **Line 7 — proof lost.** `__bpf_htons()` compiles to two 1-byte loads
   (insns 19-20), a left-shift (insn 21), and a bitwise OR (insn 22).  Before
   the OR, both R0 and R6 have tracked bounds (`umax_value=65280` and
   `umax_value=255` respectively).  After the OR, the verifier's abstract
   domain cannot represent the union: R0 collapses to `inv(id=0)` —
   *unbounded*.  This is the critical state transition.

3. **Line 8 — rejected.** The addition `r5 += r0` attempts to add this
   now-unbounded scalar to a packet pointer.  The verifier requires a proven
   non-negative minimum bound for pointer arithmetic, so it rejects.

The note explains the *mechanism* (OR-based bounds collapse is a known
limitation of the verifier's scalar tracking), and the help suggests the
minimal source fix.


## 2.4 Why This Matters

This example illustrates three properties that distinguish BPFix from
line-oriented error tools:

**Causal chain, not error annotation.**  Pretty Verifier and LLM-based tools
annotate the *rejection site* (line 8) with the verifier's error message.
BPFix traces the full causal chain from proof establishment (line 3) through
proof destruction (line 7) to rejection (line 8).  The developer immediately
sees that the bounds check IS recognized, something at line 7 breaks it, and
exactly what to fix.

**Lowering-artifact diagnosis.**  The error is classified as `lowering_artifact`
(E005), not `source_bug`.  The source is semantically correct — the developer
wrote a valid bounds check, and `__bpf_htons()` is the standard byte-swap
macro.  The failure arises because LLVM's lowering of the byte swap produces
a bitwise-OR instruction pattern that the verifier's abstract domain cannot
track.  This classification guides the developer toward the right kind of
fix: re-establishing the lost proof (a range clamp) rather than "adding a
missing check."

**Empirically prevalent failure class.**  This is not a corner case.  Our
analysis of 591 production verifier-fix commits across five major eBPF
projects (Cilium, Katran, bpftrace, Calico, Tetragon) shows that 64% are
*proof-reshaping workarounds* — source changes that do not fix a real bug
but restructure the code so the verifier can re-derive a proof it lost during
lowering or analysis.  The most common patterns are `__always_inline`
annotations (preventing cross-function state loss), `volatile` temporaries
(preventing LLVM from merging loads), explicit `& MASK` clamps (re-bounding
scalars after destructive operations), and loop unrolling.  These workarounds
are exactly the kind of repairs that BPFix's proof-lifecycle analysis can
diagnose and suggest automatically.
