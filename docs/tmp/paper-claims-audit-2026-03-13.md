# Paper Claims Audit — OBLIGE main.tex vs. Implementation
**Date:** 2026-03-13
**Auditor:** Code review against `/home/yunwei37/workspace/ebpf-verifier-agent/`
**Purpose:** Precise mapping of every technical claim to exact code, with honest assessment. For re-scoping the paper to match reality.

---

## Methodology

Each claim is rated:
- **ACCURATE** — code matches the claim as written
- **OVERSTATED** — code is simpler than the claim implies; claim uses more impressive terminology than warranted
- **MISSING** — claimed but not implemented
- **UNDERSTATED** — code does more than the claim

Files examined:
- `interface/extractor/obligation_inference.py` (~3600 lines, the main engine)
- `interface/extractor/abstract_domain.py` (~788 lines)
- `interface/extractor/value_lineage.py`
- `interface/extractor/proof_engine_parts/_impl.py`
- `interface/extractor/trace_parser_parts/_impl.py`
- `interface/extractor/log_parser.py`
- `interface/extractor/obligation_catalog_formal.py`
- `taxonomy/error_catalog.yaml`

---

## Claim-by-Claim Analysis

---

### CLAIM 1: "Abstract state transition analysis"

**Paper statement (Abstract, §1, §3.4):**
> "analyzing *abstract state transitions* across this trace (bounds collapses, type downgrades, provenance loss), OBLIGE automatically locates where the safety proof broke"

**What the code actually does:**
`obligation_inference.py:evaluate_obligation()` (line 1678) iterates over every `TracedInstruction` in the trace, evaluates each `PredicateAtom` against the pre/post `RegisterState` at that instruction, and returns a list of `PredicateEval` objects. Then `find_loss_transition()` (line 1712) finds the first point where the predicate flips from `"satisfied"` to `"violated"`.

The predicate atoms evaluated are things like:
- `non_null`: checks `"_or_null"` in `state.type` (line 3298+ and `abstract_domain.py:479`)
- `base_is_pkt`: checks `state.type in ("pkt", "pkt_meta")`
- `range_at_least`: computes `ptr.off + access_size <= ptr.range` from parsed fields
- `scalar_bounds_known`: checks `sb.is_bounded()` (whether umin/umax/smin/smax are non-default)
- `type_matches`: prefix-matching on `state.type`
- `offset_non_negative`: checks `state.smin >= 0`

**Rating: ACCURATE, but requires precise terminology**

The claim accurately describes what happens conceptually. However, "abstract state transitions" is doing heavy lifting. What the code literally does is:
1. Evaluate a boolean predicate (a handful of field comparisons) at each instruction's register state
2. Scan the resulting true/false sequence to find the first flip from true→false

This IS analyzing abstract state transitions — the verifier trace contains the abstract states, and the code detects when the predicate's evaluation on those states changes. The claim is accurate.

**However, the word "analysis" may imply more depth than a predicate evaluation sweep.** The code does not symbolically compute why a transition happened (e.g., it does not derive that "OR destroyed bounds" from first principles — it simply observes that bounds went from constrained to unconstrained in the state dump). The **observation** of state change is real; the **causal explanation** ("OR destroys bounds") comes from the human-readable note text, not from code that analyzed the instruction semantics.

**Honest replacement (optional):** "tracking safety predicate satisfaction across per-instruction abstract states" is precise. "Abstract state transition analysis" is fine if the paper is clear that it means evaluating predicates at each logged state, not a symbolic analysis of instruction effects.

---

### CLAIM 2: "Interval arithmetic with tnum"

**Paper statement (§3.4, §2):**
> "scalar bounds ([umin,umax], [smin,smax]), pointer offsets, and packet ranges"
> Background mentions "scalar bounds (umin/umax, smin/smax)... tnum (value/mask pairs)"

**What the code actually does:**

`abstract_domain.py` implements:
- `ScalarBounds` dataclass with `umin`, `umax`, `smin`, `smax`, `var_off_value`, `var_off_mask`
- `tnum_add()`, `tnum_and()`, `tnum_or()`, `tnum_lshift()` — full tnum arithmetic operations (lines 727-763)
- `tnum_upper_bound()`, `tnum_lower_bound()`, `tnum_is_const()`, `tnum_contains()` (lines 64-87)
- `ScalarBounds.upper_bound()` computes `min(umax, tnum_upper_bound)` (line 146)
- `ScalarBounds.lower_bound()` computes `max(umin, tnum_lower_bound)` (line 154)

These functions ARE correctly implemented. The question is: **are they used in the evaluation path?**

Tracing the evaluation path:
- `_eval_atom_on_state()` (line 3298) calls `eval_atom_abstract()` from `abstract_domain.py` for most atom types
- `eval_atom_abstract()` (line 647) calls `scalar_bounds_from_register_state()` which reads `umin/umax/smin/smax/var_off` from the `RegisterState`
- `eval_scalar_upper_bound()` uses `scalar.upper_bound()` which takes `min(umax, tnum_ub)` — so tnum IS consulted

For `offset_bounded` specifically (line 3368):
- The code first tries `eval_atom_abstract("offset_bounded", ...)`
- Falls back to `state.umax` alone if abstract domain returns "unknown"
- Falls back further to `scalar_bounds_from_register_state(state).upper_bound()` which uses tnum

So tnum is consulted but primarily as a fallback, with `umax` being the primary signal.

**Rating: ACCURATE but UNDERSTATED in the paper**

The tnum arithmetic (`tnum_add`, `tnum_or`, etc.) is fully implemented in `abstract_domain.py`. However:
- The arithmetic operations (add, and, or, lshift) are implemented but **not called in the evaluation path** — they exist as utility functions. The paper never claims OBLIGE performs tnum arithmetic on instructions; it claims OBLIGE reads tnum state from the trace. That is correct.
- `var_off` parsing and tnum bounds (`tnum_upper_bound`, `tnum_lower_bound`) ARE used in `ScalarBounds.upper_bound()` which IS in the evaluation path.

The code does more than the paper describes (it has tnum arithmetic functions for future use) but the key claim — reading and using tnum constraints from the verifier trace — is accurate.

**Precise description:** OBLIGE reads `var_off = (value; mask)` tnum pairs from LOG_LEVEL2 state dumps and uses them as constraints in predicate evaluation (`ScalarBounds.upper_bound()` takes `min(umax, tnum_upper_bound)`). It does not recompute tnum arithmetic from instruction semantics.

---

### CLAIM 3: "Backward obligation slice"

**Paper statement (§3.5, formal definition):**
> "The backward obligation slice is: S = {i < w | ∃ r ∈ regs(P). instruction i writes to r}"
> "When mark_precise backtracking information is available in the trace, S is refined to include only instructions on the backtracking chain, yielding a tighter slice."

**What the code actually does:**

`backward_slice()` in `obligation_inference.py` (line 1802):
- Seeds from the transition witness's carrier register
- Uses `value_lineage.get_all_aliases()` to extend seed registers to aliases
- Runs a BFS (`deque`) over the trace IR (Strategy B, line 1880)
- Walks backward via def-use edges: if a register is defined at instruction `i`, add instruction `i`'s uses to the worklist
- Strategy A (line 1857): also seeds all backtrack chain edges upfront for relevant registers

`_backward_obligation_slice_from_ir()` (line 1964):
- Simpler linear scan backward from the witness
- At each instruction, checks if any `tracked_registers` are in `instruction.defs`
- If yes, adds `instruction.uses` to `tracked_registers`
- Also checks `mark_precise` backtrack chain membership via `_matching_backtrack_registers()`

**Rating: ACCURATE**

The formal definition in the paper (S = {i < w | instruction i writes to regs(P)}) matches what `_backward_obligation_slice_from_ir()` does — a backward sweep from the witness tracking def-use of obligation registers. The refinement via `mark_precise` chains is also implemented.

**However**, the paper's formal definition is the simpler function (`backward_obligation_slice()`), while the more sophisticated BFS with value lineage aliases is in `backward_slice()`. Both exist and are used. The paper's formalization is accurate for the simpler version.

**One nuance:** The paper says "path-insensitive slicing" in the limitations section, which is also accurate — the BFS treats the trace as a linearized sequence, not a true CFG.

---

### CLAIM 4: "Formal predicate evaluation"

**Paper statement (§3.4, Definition 2):**
> "the transfer function τ_i : L → L"
> "This predicate instantiation is not pattern matching on error text."
> "formally grounded in the verifier's type system"

**What the code actually does:**

The "predicate" is an `ObligationSpec` containing a list of `PredicateAtom` objects. Each atom has:
- `atom_id`: a string like `"non_null"`, `"range_at_least"`, `"type_matches"`, etc.
- `registers`: tuple of register names
- `expression`: a human-readable string like `"R3.type == pkt"`

Evaluation (`_eval_atom_on_state()`, line 3298) is a dispatch table — a series of `if atom.atom_id == "..."` branches:
- `"non_null"`: `"_or_null" in state.type → "violated"`
- `"range_at_least"`: `ptr.off + access_size <= state.range`
- `"scalar_bounds_known"`: checks umin/umax/smin/smax vs defaults
- `"type_matches"`: `state.type.startswith(expected)`
- `"offset_non_negative"`: `state.smin >= 0`

The `expression` field is a string for human display; it is not parsed as a formal expression by the evaluator. The actual evaluation logic is hard-coded per atom_id.

**Rating: OVERSTATED**

The paper uses the word "formal" and presents a lattice definition with a transfer function τ_i. The mathematical framework is correct conceptually. However:

- The "formal predicate" is not a parsed/interpreted logical formula. It is a string expression used for display, and a string `atom_id` used to dispatch to hard-coded evaluation functions.
- There are ~8 distinct atom evaluators, each a small if-else or comparison.
- The `ObligationSpec.atoms` list is a conjunction; the code checks all atoms and combines with `_combine_results()` (line 3530), which is effectively `all(satisfied) ? satisfied : (any(violated) ? violated : unknown)`.

This is correct and principled engineering. The math in the paper is accurate as a description of the semantics. But "formal predicate evaluation" implies a logic engine, while the code is a dispatch table of field comparisons.

**Honest replacement:** "structured predicate evaluation" or "property-specific register state checks." The paper can still cite the mathematical framework — it accurately describes the semantics of what the code does.

---

### CLAIM 5: "19 obligation families"

**Paper statement (§3.3, Table 1):**
> "OBLIGE supports nineteen obligation families"
> "nineteen obligation families covering 94.3% of the 262-case evaluation corpus"

**What the code actually does:**

`OBLIGATION_FAMILIES` dict in `obligation_inference.py` (line 84) has exactly 19 entries:
1. `packet_access`
2. `packet_ptr_add`
3. `map_value_access`
4. `memory_access`
5. `stack_access`
6. `null_check`
7. `scalar_deref`
8. `helper_arg`
9. `trusted_null_check`
10. `dynptr_protocol`
11. `iterator_protocol`
12. `unreleased_reference`
13. `btf_reference_type`
14. `exception_callback_context`
15. `execution_context`
16. `buffer_length_pair`
17. `exit_return_type`
18. `verifier_limits`
19. `safety_violation`

**Are all 19 meaningfully different?** Not equally. Examining atom_ids:
- Families with `atoms=[]` (no predicate atoms, so no predicate evaluation possible): `unreleased_reference`, `btf_reference_type`, `exception_callback_context`, `execution_context`, `buffer_length_pair`, `verifier_limits`, `safety_violation` — **7 of 19 families cannot detect proof-established or proof-lost events** because they have no atoms.
- These families produce `proof_status="unknown"` and `status_reason="obligation family has no formal predicate atoms"` (line 2038-2049).

The `safety_violation` family is explicitly a catch-all: "The verifier rejected a concrete safety rule, but the specific proof family could not be recovered."

**Rating: ACCURATE count, OVERSTATED capability**

The count of 19 is correct. However, the framing implies 19 meaningfully distinct, evaluable families. In reality:
- 12 families have at least one atom (can produce proof lifecycle labels)
- 7 families have no atoms (produce "unknown" status — they act as classification buckets, not proof analyzers)

The 94.3% "obligation coverage" metric means OBLIGE successfully classified 247/262 cases into one of the 19 families. It does NOT mean 247 cases got proof lifecycle analysis. The batch table (Table 3) shows proof-established in only 115/262 (43.9%) and proof-lost in 99/262 (37.8%).

**Honest replacement:** "OBLIGE recognizes 19 obligation families; 12 support full predicate evaluation (proof-established/proof-lost detection), while the remaining 7 act as classification families with no predicate atoms (producing structured error classification but not lifecycle labels)."

---

### CLAIM 6: "mark_precise chain extraction"

**Paper statement (§3.2, §3.5):**
> "OBLIGE extracts these into a BacktrackChain structure: a sequence of (instruction_index, registers_tracked) pairs. This is the verifier's own root-cause chain, expressed as debug text; OBLIGE is the first tool to extract and structure it."

**What the code actually does:**

In `trace_parser_parts/_impl.py`, the parser recognizes these log line patterns:
```
BACKTRACK_SUMMARY_RE = re.compile(r"^\s*last_idx\s+(?P<last_idx>\d+)\s+first_idx\s+(?P<first_idx>\d+)\s*$")
BACKTRACK_DETAIL_RE = re.compile(r"^\s*regs=(?P<regs>\S+)\s+stack=(?P<stack>\S+)(?:\s+before\s+(?P<before_idx>\d+):\s*(?P<before_insn>.*))?\s*$")
BACKTRACK_PARENT_RE = re.compile(r"^\s*parent didn't have regs=(?P<regs>\S+)\s+stack=(?P<stack>\S+)\s+marks\s*$")
```

These are parsed into `BacktrackChain` objects containing `BacktrackLink` objects with `(insn_idx, regs_bitmask, stack_bitmask)`.

The `regs` field is a bitmask (hex string) that encodes which registers are tracked. `_decode_regs_mask()` decodes this to a list of register names.

In `backward_slice()` (line 1857-1878), these chains are used to seed the BFS worklist with all relevant backtrack edges, labeled as `"backtrack_hint"` kind `SliceEdge` objects.

**Rating: ACCURATE**

The claim is accurate. The parsing is regex-based (matching the actual LOG_LEVEL2 format), and the structural representation is well-defined. The claim that OBLIGE is "the first tool to extract and structure it" is a research contribution claim, not verifiable from the code alone, but the implementation exists.

**One nuance:** "mark_precise backtracking" in the log appears as sparse annotations (`regs=0x6 stack=0x0 before 23: (4f) r0 |= r6`), not as a complete chain for every case. The batch evaluation shows only 24/262 cases (9.2%) have usable causal chains from this, confirming it's a minority path.

---

### CLAIM 7: "Second-order abstract interpretation"

**Paper statement (§3.5):**
> "The state transition detection described above can be understood as a *second-order abstract interpretation*: OBLIGE applies abstract interpretation to the *output* of another abstract interpreter."

**What the code actually does:**

OBLIGE does not implement a second abstract interpreter. It:
1. Reads the verifier's already-computed abstract states from LOG_LEVEL2 text
2. Evaluates predicates over those states (field comparisons)
3. Scans the resulting boolean sequence

**Rating: OVERSTATED as "abstract interpretation"; ACCURATE as a conceptual analogy**

Calling predicate evaluation over a sequence of logged states "abstract interpretation" is a stretch. Abstract interpretation implies:
- A formal abstract domain with join/widen operations
- A transfer function applied at each instruction
- A fixed-point computation

OBLIGE does none of these. It reads pre-computed states and evaluates predicates. The paper's own Definition 2 formalizes this as a "transfer function" τ_i but this is a post-hoc formalization of what is literally a `find_loss_transition()` scan.

The conceptual analogy is illuminating and the paper frames it as "can be understood as" rather than "is." This softens the claim appropriately. The formalization in §3.5 is mathematically sound as a description of the semantics.

**Honest framing:** Keep the "can be understood as" framing. Avoid claiming OBLIGE "implements" second-order abstract interpretation. The mathematical framework accurately characterizes the semantics; the implementation is a forward scan with predicate evaluation.

---

### CLAIM 8: "Proof obligation is not pattern matching on error text"

**Paper statement (§3.3):**
> "This predicate instantiation is not pattern matching on error text. The same error message with different register states at the rejection point produces different predicate instances with different parameters."

**What the code actually does:**

`infer_formal_obligation()` (line 845):
1. Calls `_try_formal_catalog_obligation()` which calls `_catalog_match_error_message(error_line)` — this IS regex pattern matching on the error text
2. Uses the register state at the failing instruction to parameterize the obligation (e.g., reads `state.range` to set `access_size` in the `range_at_least` atom)

So the inference DOES use regex matching on the error text (Step 1), but the predicate parameters come from register state (Step 2). Different register states at the same error message produce different `ObligationSpec` objects with different `const_off` / `access_size` values.

**Rating: ACCURATE, but the paper undersells the role of error text matching**

The claim is technically correct — parameter instantiation uses register state, not just error text. Two cases with the same error message "invalid access to packet" but different `state.range` values produce different `range_at_least` atom bounds.

However, the error text IS used for obligation family selection (which family to use) and the paper somewhat minimizes this. The error text matching is a necessary prerequisite.

**Honest framing:** "Error text identifies the obligation family; register state at the rejection point instantiates the predicate parameters. The same error family with different register states produces different predicate instances." This is accurate and clearer.

---

### CLAIM 9: "Proof propagation analysis" / "Register value lineage"

**Paper statement (§3.4):**
> "OBLIGE tracks value identity across register moves and copies. If R3 is defined as a copy of R0 (r3 = r0), and the obligation predicate references the packet range of R0, OBLIGE continues tracking the range on R3."
> "Proof propagation analysis. For lowering artifact detection, OBLIGE additionally checks whether the proof established at the bounds-check site propagates to the register used at the access site."

**What the code actually does:**

`value_lineage.py` implements `ValueLineage` with:
- `ValueNode` tracking `value_id`, `location`, `defined_at`, `op_kind`, `parent_id`, `offset_delta`, `proof_root`
- `get_all_aliases(trace_pos, location)` returns all locations sharing the same `proof_root` at `trace_pos`
- Handles: `mov` (copies), spill (`store` to `fp-N`), fill (`load` from `fp-N`), `ptr_add` (constant offset), ALU-with-register (destroys lineage)

`build_trace_ir()` (line 309) builds the `ValueLineage` and attaches it to `TraceIR`.

In `_candidate_carriers()` (line 3165), when the primary register is not in the current state map, `value_lineage.get_all_aliases()` is consulted to find equivalent registers.

In `backward_slice()` (line 1834-1845), aliases are added to the seed registers before BFS.

**Rating: ACCURATE**

The value lineage tracking is implemented and used in the evaluation path. The description accurately matches the code.

**One nuance:** The `proof_root` concept (a single canonical ID shared across all copies of a value) is more sophisticated than a simple copy-chain — it correctly handles the case where a value is spilled to stack and reloaded. This is described in the paper and implemented.

---

### CLAIM 10: "Rust-style multi-span diagnostics"

**Paper statement (§3.6, Panel C of Figure 1):**
> "Rust-inspired diagnostics pinpointing exactly where and why the safety proof broke"
> Panel C shows: `error[E005]: lowering_artifact ... proof established ... proof lost ... rejected`

**What the code actually does:**

`rust_diagnostic.py` / `rust_diagnostic_parts/` implement rendering. The output includes:
- `error[E005]: lowering_artifact`
- Source spans with role labels (proof established, proof lost, rejected)
- Register state changes at each span
- `note:` and `help:` annotations

The format matches Rust compiler output structurally.

**Rating: ACCURATE**

The rendering is implemented and produces the format shown in Figure 1. The "Rust-style" claim refers to visual format, not to implementation language (Python), and is accurate.

---

### CLAIM 11: "23 error patterns / 87.1% coverage"

**Paper statement (§3.2, Figure 2 caption):**
> "23 error patterns (OBLIGE-E001 through E023), covering 87.1% of failures in our 302-case corpus"

**What the code actually does:**

`taxonomy/error_catalog.yaml` contains exactly 23 error IDs (OBLIGE-E001 through E023), verified by grep.

`log_parser.py:_match_catalog()` (line 198) performs regex matching against the error catalog's `verifier_messages` patterns.

**Rating: ACCURATE**

Count of 23 is confirmed. The 87.1% coverage is an empirical claim from evaluation.

---

### CLAIM 12: "94% obligation coverage"

**Paper statement (Abstract, §4.2, Table 3):**
> "achieve 94% obligation coverage" / "Proof obligation inferred: 247/262 (94.3%)"

**What the code measures:**

`infer_obligation()` returns `None` if no `ObligationSpec` can be constructed. The 94.3% means 247/262 cases returned a non-None obligation.

This includes families with `atoms=[]` (e.g., `verifier_limits`, `unreleased_reference`) which produce an `ObligationSpec` but cannot evaluate predicates. So "obligation inferred" ≠ "predicate evaluated."

**Rating: ACCURATE count, potentially MISLEADING framing**

The 94.3% is the correct rate for "OBLIGE assigned a case to one of the 19 obligation families." This is meaningful — it means OBLIGE understood what safety property was at stake.

However, actual predicate evaluation (producing proof-established / proof-lost labels) only happens for the ~12 families with atoms, and is reported separately (115/262 proof-established, 99/262 proof-lost). The paper does report these separately in Table 3, so a careful reader can see the distinction.

**Honest framing the paper could make more explicit:** "94.3% of cases are assigned to a recognized obligation family. Of these, 43.9% receive a proof-established label and 37.8% receive a proof-lost label, indicating the full predicate tracking was available."

---

### CLAIM 13: "Pinpoint the exact root cause in 67% of previously undiagnosable compilation-induced failures"

**Paper statement (Abstract, Conclusion):**
> "pinpoint the exact root cause in 67% of previously undiagnosable compilation-induced failures"

**What the code measures:**

From Table 5 (PV comparison), OBLIGE finds "Root-cause localization" in 12/30 (40%) of manually labeled cases. The 67% appears to come from the lowering-artifact subset: 4/6 lowering artifact cases get root-cause localization = 67%.

**Rating: ACCURATE but requires context**

The 67% is specifically for the lowering artifact subclass, not overall. The abstract says "67% of previously undiagnosable compilation-induced failures" which is accurate: of the 6 lowering artifact cases in the 30-case labeled set, 4 get root-cause localization.

This is a small sample (4/6). The paper should be clear this is from the 30-case manually labeled subset, which it is (in the body text of §4.4, though the abstract omits this context).

---

### CLAIM 14: "Boost automated code-repair accuracy by 30 percentage points"

**Paper statement (Abstract, §4.3):**
> "boost automated code-repair accuracy by 30 percentage points"

**What the code measures:**

Table 4 shows: Lowering fix type: A=3/10 (30%), B=6/10 (60%), Δ=+30pp.

This is specifically for the **lowering artifact subclass** within a 54-case A/B experiment. The overall fix-type accuracy is **negative** for OBLIGE: A=46/54 (85.2%), B=43/54 (79.6%), Δ=−6pp.

**Rating: ACCURATE for the subclass, MISLEADING in the abstract**

The abstract says "boost automated code-repair accuracy by 30pp" without qualification. The full picture is:
- Lowering artifacts: +30pp (the specific win case)
- Overall: −6pp (OBLIGE hurts for non-lowering cases)
- Source bugs: −14pp

A systems paper reviewer will notice this gap between abstract and full results. The paper body does address this honestly in §4.3, but the abstract needs qualification.

**Suggested abstract revision:** "boost automated code-repair accuracy for compilation-induced failures by 30 percentage points" (add "for compilation-induced failures").

---

### CLAIM 15: "25.3 ms median latency"

**Paper statement (Abstract, §4.5):**
> "OBLIGE operates entirely in userspace, incurs just 25.3 ms median latency per diagnosis"

**What the code measures:**

`eval/latency_benchmark.py` presumably ran the pipeline on the 262-case corpus. The claim is an empirical measurement.

**Rating: CANNOT VERIFY FROM CODE ALONE**

The number is plausible for a Python pipeline processing ~500-line text files. The code is indeed pure Python without any external calls. The claim is empirically verifiable but the benchmark data is not in-scope for this audit.

---

## Summary Table

| # | Claim | Rating | Code Location |
|---|-------|--------|---------------|
| 1 | Abstract state transition analysis | ACCURATE (precise description needed) | `obligation_inference.py:1678-1799` |
| 2 | Interval arithmetic with tnum | ACCURATE | `abstract_domain.py:64-788`, used in `_eval_atom_on_state()` |
| 3 | Backward obligation slice | ACCURATE | `obligation_inference.py:1802-2028` |
| 4 | Formal predicate evaluation | OVERSTATED ("formal" → "structured") | `obligation_inference.py:3086-3393` |
| 5 | 19 obligation families | ACCURATE count, 7/19 have no atoms | `obligation_inference.py:84-161` |
| 6 | mark_precise chain extraction | ACCURATE | `trace_parser_parts/_impl.py:28-38`, `obligation_inference.py:1857-1878` |
| 7 | Second-order abstract interpretation | OVERSTATED as claim, ACCURATE as analogy | Conceptual framing |
| 8 | Not pattern matching on error text | ACCURATE (error text selects family; state instantiates predicate) | `obligation_inference.py:845-899` |
| 9 | Register value lineage / proof propagation | ACCURATE | `value_lineage.py`, `obligation_inference.py:3165-3214` |
| 10 | Rust-style multi-span diagnostics | ACCURATE | `rust_diagnostic_parts/` |
| 11 | 23 error IDs / 87.1% coverage | ACCURATE | `taxonomy/error_catalog.yaml` (23 confirmed) |
| 12 | 94% obligation coverage | ACCURATE count, MISLEADING framing | Empirical; 7/19 families have no predicate atoms |
| 13 | 67% root-cause localization | ACCURATE for lowering subclass (4/6) | Empirical (30-case manual eval) |
| 14 | +30pp repair accuracy | OVERSTATED in abstract (overall is −6pp) | `eval/` A/B experiment |
| 15 | 25.3 ms median latency | CANNOT VERIFY from code | `eval/latency_benchmark.py` |

---

## Priority Re-scoping Actions

### HIGH PRIORITY: Claims that could mislead reviewers

**1. Abstract should qualify the +30pp claim:**
- Current: "boost automated code-repair accuracy by 30 percentage points"
- Fix: "boost automated code-repair accuracy **for compilation-induced failures** by 30 percentage points"
- Reason: Overall A/B accuracy is −6pp; the +30pp is only for the 10-case lowering artifact subset.

**2. "Formal predicate evaluation" → "structured predicate evaluation":**
- The code is a dispatch table of field comparisons, not a logic engine.
- The math is accurate as a description of the semantics, but calling it "formal" implies a logic engine.
- Fix: "structured property evaluation" in §3.3, keep the mathematical framework as correct formal characterization of the semantics.

**3. 94% coverage should clarify predicate coverage vs. classification coverage:**
- "94.3% obligation coverage" = 247/262 cases assigned to a family.
- 44% (115/262) cases get proof-established labels; 38% (99/262) get proof-lost labels.
- These are the real differentiating numbers and should be highlighted alongside 94%.

**4. "19 obligation families" should note 7 have no predicate atoms:**
- Table 1 only shows 10 representative families, all of which DO have atoms.
- Text should note that 7 of the 19 families are classification-only (no lifecycle labels).
- This is already partially addressed in the discussion section but should be in §3.3.

### MEDIUM PRIORITY: Claims that are accurate but could be more precise

**5. "Abstract state transition analysis" — needs a one-sentence operational description:**
- Add: "Concretely, OBLIGE evaluates a set of predicate atoms against each instruction's logged abstract state and detects the first instruction where the predicate flips from satisfied to violated."
- This is more precise than "analyzing transitions" and removes any ambiguity about whether OBLIGE symbolically computes state transitions.

**6. "Second-order abstract interpretation":**
- Keep the "can be understood as" framing.
- Do not say OBLIGE "implements" or "is" second-order abstract interpretation.
- The math in §3.5 is correct and can stand on its own.

### LOW PRIORITY: Claims that are accurate and don't need changes

- Backward slicing (accurate, well-implemented)
- Register value lineage (accurate, well-implemented)
- mark_precise chain extraction (accurate, genuinely novel)
- Rust-style multi-span diagnostics (accurate)
- 23 error IDs (accurate)
- Pure userspace, no kernel modifications (accurate)

---

## What the Code Does That Is Genuinely Novel and Well-Implemented

For positive framing (the code does more than some claims acknowledge):

1. **Value lineage tracking with spill/fill:** `value_lineage.py` correctly handles the case where a value is spilled to a stack slot (`*(u64 *)(r10 -8) = r0`) and later filled back (`r3 = *(u64 *)(r10 -8)`). This is the primary cause of proof propagation failures in LLVM-lowered code and OBLIGE tracks it correctly.

2. **Tnum integration:** `abstract_domain.py` contains a complete tnum implementation including arithmetic (`tnum_add`, `tnum_or`, etc.) that mirrors the kernel's `lib/tnum.c`. This is used in bound computation and is correctly implemented.

3. **mark_precise chain as BFS seed:** The backward slice seeds its BFS not just from def-use but from the verifier's own `mark_precise` chain, meaning OBLIGE leverages the verifier's own root-cause analysis when available. This is the only tool doing this.

4. **Composite obligation tracking:** `track_composite()` can analyze multiple sub-obligations and find which fails first. This enables analysis of compound safety conditions.

5. **The formal catalog** (`obligation_catalog_formal.py`): Each obligation is traced to a specific function and line number in `kernel/bpf/verifier.c`, with the exact C condition that triggers rejection. This ground-truthing of obligations to kernel source is more rigorous than simply pattern-matching error strings.

---

*Audit complete. 15 claims analyzed; 2 require rewording before submission, 2 require additional qualification, 11 are accurate as-is or accurate with minor precision improvements.*
