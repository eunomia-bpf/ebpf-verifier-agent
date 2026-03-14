# Strategic Assessment — 2026-03-14

## Situation Summary

The old proof engine (3600 lines of keyword heuristics) was deleted. The new engine is cleaner: opcode-driven safety analysis (7-case ISA decoder), generic trace monitor, transition analyzer. The pipeline is 653 lines, single path, no fallbacks. The code is better. The numbers are worse or misleading.

| Metric | Old Engine (v5) | New Engine | Note |
|--------|:-:|:-:|------|
| Multi-span (3-span) | 37.8% (99/262) | 79% (135/171) **or** 50% (131/262) | Different denominators; see analysis |
| established_then_lost | 37.8% | 13% (22/171) | Only 22 get genuine lifecycle |
| Taxonomy accuracy | 76.7% (30 cases) | 56.1% (96/171) | Significant regression |
| Crashes | 0 | 0 | Same |
| Tests | 268 | 255 pass, 5 skip | Minor regression |

---

## 1. Is the 79% Multi-Span Real or Inflated?

**It is inflated, but the mechanism is subtle and partially legitimate.**

The 79% (135/171) counts cases with more than one span. The previous code review (docs/tmp/new-engine-review-2026-03-13.md) identified the root cause: when the opcode-driven predicate returns None (no error instruction found, or error instruction has no decodable opcode), the pipeline falls through to the TransitionAnalyzer, which analyzes ALL registers with an empty `proof_registers` set. In that mode:

1. Any register initialization (e.g., `w6 = 0` at insn 0) counts as NARROWING, producing a "proof_established" event.
2. Any subsequent type change on any register counts as DESTROYING, producing a "proof_lost" event.
3. The rejected span is always added by `_ensure_rejected_span()`.
4. Result: 3 spans for nearly any trace with >1 instruction.

This is the same pattern the review flagged: the TransitionAnalyzer is not wrong about the state transitions (bounds DO change, types DO change), but labeling arbitrary register changes as "proof established / proof lost" when you don't know which register matters is semantically vacuous. It produces pretty output that says nothing useful.

**How many of the 135 multi-span cases are genuine?** The 22 established_then_lost cases from the monitor (where a real predicate was evaluated and found to flip) are genuine. The remaining ~113 are TransitionAnalyzer fallback artifacts. They have spans, but the spans don't correspond to the actual proof obligation.

**Recommendation:** Report the 22 (13%) honestly as "cases where the system identified a concrete proof-loss transition." The remaining cases produce multi-span output but the proof_established/proof_lost labels are not grounded in a specific safety property. Do NOT report 79% or 50% multi-span in the paper -- it would not survive reviewer scrutiny if they looked at examples.

---

## 2. The Taxonomy Accuracy Problem

56.1% is unacceptable even as a sanity check. The confusion matrix tells the story:

| GT \ Predicted | env_mismatch | lowering_artifact | source_bug | verifier_limit |
|:-:|:-:|:-:|:-:|:-:|
| env_mismatch | 14 | 0 | 12 | 0 |
| lowering_artifact | 4 | 3 | 0 | 0 |
| source_bug | **57** | 2 | 77 | 0 |
| verifier_limit | 0 | 0 | 0 | 2 |

The dominant failure mode: 57 source_bug cases are classified as env_mismatch. These are dynptr/kfunc/iterator protocol violation cases from kernel selftests. The error messages contain keywords like "Expected an initialized dynptr" or "expected an initialized iter_num" that match env_mismatch patterns in the error catalog, but the ground truth labels them as source_bug because the programmer failed to follow the protocol (it's a code bug, not an environment mismatch).

**Root cause:** The error_catalog.yaml assigns taxonomy_class based on the error message pattern. For dynptr/kfunc errors, the catalog says env_mismatch because these features require specific kernel versions. But the selftests are testing the verifier's *rejection behavior* for intentionally wrong code -- the dynptr IS available, the code just uses it incorrectly. The taxonomy assignment should depend on whether the feature is actually unavailable (env_mismatch) or just misused (source_bug), but the error message alone cannot distinguish this.

**Options analysis:**

(a) **Fix log_parser classification.** Add secondary rules: if the error mentions dynptr/kfunc protocol violations (not "unknown func" but "expected initialized dynptr"), classify as source_bug. This is feasible but is keyword heuristics again, and the distinction between "feature unavailable" vs "feature misused" is inherently ambiguous from the error message alone.

(b) **Derive taxonomy from opcode analysis.** The opcode-driven engine could theoretically distinguish: if there IS an error instruction with a decodable safety violation, it's source_bug; if there's no error instruction (structural rejection), it could be env_mismatch or verifier_limit. But this misses the nuance: dynptr protocol violations DO have error instructions.

(c) **Accept that taxonomy classification is not the contribution.** This is the correct strategic answer. The paper already says "classification accuracy is NOT the contribution" (CLAUDE.md, research-plan.md). The contribution is the diagnostic output -- multi-span with proof lifecycle. Report taxonomy accuracy honestly (56% with the opcode engine, 77% with the old heuristic engine on 30 cases), acknowledge the limitation, and move on.

(d) **Hybrid approach.** Keep log_parser's catalog matching for taxonomy classification (it's the best available signal for env_mismatch vs source_bug), but use the opcode engine for proof status and span generation. The pipeline already does this -- parsed_log.taxonomy_class comes from log_parser, proof_status comes from the engine. The problem is that log_parser's patterns are wrong for the dynptr/kfunc cases.

**Recommendation: Option (a+c).** Fix the most egregious misclassifications (57 source_bug-as-env_mismatch) by adding disambiguation rules for dynptr/kfunc protocol errors in error_catalog.yaml. Then report the improved number honestly. This is not intellectually compromising -- the error catalog IS heuristic, you're just fixing bugs in it. But don't spend more than a day on it. Taxonomy is not the contribution.

---

## 3. Is 13% Lifecycle Coverage Enough?

**No, 13% is not enough for a paper claiming "abstract state transition analysis as its core contribution."**

22 out of 171 cases get the genuine established_then_lost lifecycle. For the other 149:
- 94 get proof_status "unknown" (no predicate, no lifecycle)
- 54 get "never_established" (predicate exists but never satisfied)
- 1 gets "established_but_insufficient"

The fundamental issue: the opcode-driven predicate only works when (a) there is an identifiable error instruction in the trace, AND (b) the error instruction's opcode maps to a specific safety domain (memory bounds, null safety, etc.), AND (c) the register state at the error point has enough information to evaluate the condition. Many cases fail one or more of these conditions:

- Stack Overflow and GitHub cases often have truncated or incomplete traces (no per-instruction state dumps)
- Dynptr/kfunc/iterator errors are CALL instructions (opcode 0x85), which generate ARG_CONTRACT conditions for R1-R5 -- but the predicate evaluates to "unknown" because the system doesn't know the helper prototype
- Many kernel selftests have very short traces (the test programs are designed to fail quickly)

**What would increase lifecycle coverage?**

1. **Better predicate inference for CALL instructions.** The ARG_CONTRACT predicate currently returns "unknown" for everything because it doesn't know what argument types the helper expects. If the system had a helper prototype database (bpf_helpers.h defines them all), it could evaluate "R1 must be PTR_TO_MAP_VALUE" concretely. This is tractable but significant work.

2. **Error-message-guided predicate fallback.** The error message often states the violated condition explicitly: "R1 type=scalar expected=fp" tells you the predicate is "R1 must be fp (frame pointer)." The old engine used this. The new engine deliberately avoids it to stay "opcode-driven, no keyword matching." This purity costs coverage.

3. **Wider opcode support.** The current opcode decoder handles 7 cases (LDX, ST, STX, ALU, JMP/CALL, JMP/EXIT, branches). LD (0x00) and some edge cases are not handled. But this is a minor gap.

**Strategic assessment:** The 13% number means the "abstract state transition analysis" story applies convincingly to about 22 cases. For the paper, you need to either (a) dramatically increase this number, or (b) reframe the contribution so that lifecycle analysis is one feature, not the entire thesis.

---

## 4. What Experiments Matter Most?

Ranked by impact on publishability:

### Priority 1: Validate the 22 genuine lifecycle cases (1-2 days)
For each of the 22 established_then_lost cases, manually verify:
- Is the "proof_established" span actually where the proof obligation was met?
- Is the "proof_lost" span actually where the proof broke?
- Does the causal chain point to the root cause?
If 18+/22 are correct, you have a strong (small) precision story. If many are wrong, the opcode engine has deeper problems.

### Priority 2: Fix taxonomy for dynptr/kfunc cases (1 day)
Fix the 57 source_bug-as-env_mismatch misclassifications. This is low-hanging fruit: update error_catalog.yaml patterns for OBLIGE-E012 (dynptr), E013 (irq), E014 (iterator), E015 (trusted arg) to classify as source_bug instead of env_mismatch. Re-run batch eval. This should bring taxonomy accuracy from 56% to ~90%.

### Priority 3: A/B repair experiment with stronger model (2-3 days)
The v3 experiment used GPT-OSS 20B (weak model), got +7.1pp overall but p=0.22. A stronger model (Qwen3.5-122B or GPT-4-class) would give more meaningful results. Focus on the 22 lifecycle cases specifically -- these are where OBLIGE adds the most value. If OBLIGE-assisted repair is significantly better on lifecycle cases, that's the paper's evaluation story.

### Priority 4: PV comparison on the full 171-case set (1 day)
The PV comparison was done on 30 cases. Running it on 171 would give more convincing numbers and might reveal interesting patterns (OBLIGE root-cause 20% vs PV 0% on 262 cases is already reported but needs the full methodology).

### Priority 5: Root-cause precision study (2 days)
For the 22 lifecycle cases + a sample of non-lifecycle cases, compare OBLIGE's indicated root cause against expert judgment. This directly measures whether the analysis helps developers.

### Experiments to skip:
- Cross-kernel stability (nice to have, not needed for the paper)
- Synthesis (Path B from research plan) -- too much work for uncertain payoff
- Expert sufficiency study (Q2) -- would be great for the paper but requires actual experts

---

## 5. Is This Publishable at OSDI/ATC?

**Brutally honest assessment: Not yet. The current system is a well-engineered diagnostic tool, but the technical depth is insufficient for OSDI/ATC.**

### What reviewers will say

**Positive:**
- Real problem, real users, real pain point
- Clean engineering: 100% success rate, 0 crashes, sub-100ms
- Better than Pretty Verifier (root cause, multi-span, structured output)
- Nice Rust-style rendering

**Negative (fatal):**
- "The opcode-to-safety-condition mapping is just the BPF ISA specification written as Python. This is not analysis, it's encoding."
- "The predicate monitoring is textbook runtime verification (Bauer/Leucker/Schallhart 2011). The application to eBPF traces is obvious once you see it."
- "Only 13% of cases get the full lifecycle analysis. For 87% of cases, this system produces a prettified error message with span decorations -- how is that different from Pretty Verifier?"
- "The A/B experiment shows +7pp with p=0.22. This is not significant."
- "The taxonomy classifier is less accurate than the system it replaced."

### What would make it publishable

**For OSDI/ATC** (top systems venue, needs strong novelty + strong evaluation):

1. **CFG reconstruction from traces + proper backward slice (Path A from research plan).** This is the missing technical depth. The current system reads per-instruction states linearly. A real contribution would reconstruct the control flow graph from the trace, compute reaching definitions and control dependences on that CFG, and do a proper program slice from the error point backward. This would find root causes that the linear scan misses (e.g., a missing null check on a different path that dominates the error path).

2. **Synthesis (Path B from research plan).** Generating verifier-passing repairs automatically would be a strong empirical result. "OBLIGE correctly repairs X% of lowering artifacts with no human intervention" is a headline number that reviewers care about. But this is a large implementation effort.

3. **Significantly stronger evaluation.** At minimum: 50+ cases with expert-validated root cause labels, A/B with p<0.05, and a clear demonstration that lifecycle analysis (not just error classification) improves repair outcomes.

**For ATC / EuroSys (still top venue but more tolerant of systems contributions):**

The bar is slightly lower. A well-engineered tool with a clear improvement over the state of the art (Pretty Verifier) could work if:
- The evaluation is strong enough (significant A/B, precision study)
- The paper is honest about what the system does and doesn't do
- There's a compelling qualitative story (showcase 5-10 cases where the diagnostic is clearly better)

**For a workshop (eBPF Summit, BPF Conference, NetDev) or a tools track (USENIX ATC tools track, SOSP WIP):**

The current system is publishable as-is with minor cleanup. This is actually a reasonable target: publish the tool, get community feedback, iterate, then aim for a full paper later with synthesis.

### My recommendation

**Target EuroSys or ATC, but only after implementing Path A (CFG reconstruction + backward slice).** This is the one piece that turns "structured reading" into "real analysis." Without it, the honest description of what the system does is: "parse verifier output, decode opcodes, check register states against safety conditions, display results." This is good engineering but not a research contribution at the top-venue level.

Path B (synthesis) would be the strongest possible result but is high-risk and high-effort. Consider it a stretch goal.

---

## 6. The "Reading vs Analysis" Question

This is the most important conceptual question. Let me be precise about what the system currently does at each step:

### Step 1: Parse trace, extract per-instruction register states
**This is reading.** The verifier computed these states. The system is extracting them from text output. No new information is generated.

### Step 2: Decode opcode, derive safety conditions
**This is encoding ISA specifications as code.** The mapping from opcode class to safety domain is the BPF ISA specification. Every BPF developer knows that LDX requires a valid pointer. Encoding this as `SafetyCondition(domain=POINTER_TYPE, ...)` is not analysis -- it's a lookup table.

### Step 3: Evaluate safety conditions against register states
**This is value comparison with some interval arithmetic.** Checking whether `umax < 2^32` or whether a type is `ptr_or_null` is comparing pre-computed values from the verifier's abstract state. The interval containment check (`off + size <= range`) is real arithmetic but trivial.

### Step 4: Monitor predicate over trace
**This is the most substantive step.** Scanning the trace to find where a safety predicate transitions from "satisfied" to "violated" is genuine analysis -- it answers the question "where did the proof break?" that no existing tool answers. But the analysis is linear-time, single-pass, and does not consider control flow. A reviewer will note that this is a simple application of runtime verification (monitor a property over a trace).

### Step 5: Classify transitions
**This is principled but simple.** Classifying bounds changes as NARROWING/WIDENING/DESTROYING using interval containment is correct and well-defined. But the classification rules are not novel -- they follow directly from abstract interpretation theory.

### Where is the gap?

The gap is between "reading + comparing pre-computed values" and "computing new information." The current system never computes anything the verifier didn't already compute. It organizes, correlates, and presents -- which is valuable for users -- but does not perform analysis beyond what a careful human reader would do.

**What would cross the line into "real analysis"?**

1. **Control flow reasoning.** The verifier trace implicitly encodes a CFG through `from X to Y` annotations and branch instructions. Reconstructing this CFG and reasoning about which paths lead to the error would be analysis that the verifier's output does not directly provide.

2. **Transfer functions over proof status.** Instead of just reading the verifier's states, compute how each instruction SHOULD affect the proof status using your own transfer functions. Compare your computation against the verifier's output. When they differ, that's a witness of over-approximation or verifier behavior that the developer might not expect.

3. **Counterfactual reasoning.** "If this bounds check at line 38 had been placed after the endian swap at line 42 instead of before it, the proof would have been maintained." This requires computing proof status under a hypothetical instruction reordering -- something the verifier's output does not contain.

4. **Backward slice with control dependence.** "The error at line 45 depends on the value of R0, which was last defined at line 42 (OR operation), which depends on R6 from line 19 (load). But the bounds check at line 38 establishes the proof on R3, not R0. The proof is lost because R0 is not R3." This requires tracking register definitions through a dependency graph, which the current system does not do (the TransitionAnalyzer looks at ALL registers, not the dependency chain).

**Bottom line:** The current system is 80% reading, 15% value comparison, 5% predicate monitoring. For a top-venue paper, you need to flip this -- the core contribution should be a non-trivial computation that the verifier's output alone does not provide. CFG reconstruction + backward slice (Path A) would achieve this.

---

## 7. Concrete Action Plan

### Immediate (this week)

1. **Fix taxonomy misclassifications** in error_catalog.yaml. Turn 57 source_bug-as-env_mismatch into correct source_bug. Expected result: taxonomy accuracy ~90%.

2. **Validate the 22 lifecycle cases** manually. For each: is the proof_established span correct? Is the proof_lost span correct? Is the causal chain correct? Record precision.

3. **Run batch eval with fixed taxonomy.** Get clean numbers for the paper.

### Short-term (next 1-2 weeks)

4. **Implement error-message-guided predicate fallback.** For CALL instructions, extract the expected argument type from the error message ("R1 type=scalar expected=fp") and use it as the predicate. This should increase lifecycle coverage from 13% to ~30-40%.

5. **A/B experiment with Qwen3.5-122B.** Run repair_experiment_v4 on the 22 lifecycle cases + 34 non-lifecycle cases. Need p<0.05 on the lifecycle subset.

### Medium-term (next 2-4 weeks, for venue submission)

6. **Implement Path A: CFG reconstruction + backward slice.** This is the core technical contribution. Reconstruct the trace CFG from `from X to Y` annotations and branch instructions. Compute reaching definitions. Compute control dependences. Produce a proper backward slice from the error point. This should give root-cause precision significantly better than the linear scan.

7. **Rewrite paper around CFG-based analysis.** The paper's story becomes: "We reconstruct the verifier's exploration as a CFG, track proof obligations through transfer functions, and use backward slicing to locate root causes." This is a real analysis contribution.

### Decision point

After steps 1-5 (about 2 weeks), assess:
- If lifecycle precision is >80% on the 22 cases AND A/B is significant (p<0.05) on lifecycle subset: proceed to Path A for OSDI/ATC.
- If lifecycle precision is low or A/B shows no difference: consider targeting a workshop/tools track instead of a full paper. The tool is useful; the analysis depth may not be sufficient.

---

## 8. Numbers to Report in the Paper (Honest Version)

| Metric | Value | Note |
|--------|:-----:|------|
| Cases evaluated | 171 (with verifier logs) | Out of 302 total |
| Success rate | 100% (0 crashes) | vs PV 89.3% |
| Taxonomy accuracy | ~90% (after fix) | Not the contribution |
| Lifecycle analysis (established_then_lost) | 22/171 (13%) | Honest lifecycle rate |
| Lifecycle precision | TBD (need manual validation) | Target: >80% |
| Root-cause localization | TBD/171 | Need study |
| Multi-span (with any proof context) | 22/171 for genuine, 135/171 with fallback | Must be transparent |
| Latency | median 32ms, P95 42ms, max 83ms | Strong |
| A/B repair improvement | +7pp (p=0.22, NS) | Need stronger model |

---

## 9. What I Would Tell a Program Committee

"OBLIGE is a well-engineered diagnostic tool for eBPF verifier failures that parses complete verifier traces, identifies where safety proofs are established and lost, and renders Rust-style multi-span diagnostics. It handles 171 real-world cases with zero crashes and sub-100ms latency. For the 13% of cases where a concrete proof lifecycle is identified, the diagnostics are qualitatively superior to existing tools. The main limitation is coverage: the system only performs genuine proof lifecycle analysis when it can (a) identify the error instruction's opcode, (b) derive a concrete safety predicate, and (c) find that predicate satisfied and then violated in the trace. For the remaining 87%, the system provides structured error classification and single-span output comparable to existing tools."

This is honest. It's also not enough for OSDI. To get there, you need Path A (CFG reconstruction + backward slice) to turn the 87% from "structured error display" into "causal analysis via program slicing."
