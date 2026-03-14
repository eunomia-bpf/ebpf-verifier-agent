# Fault Localization Literature Survey for OBLIGE
## Date: 2026-03-13

This document surveys the formal methods and program analysis literature for work that OBLIGE relates to, might be reinventing, should cite, or could borrow techniques from. It is organized by research community and intended to answer: **What is the right framing for OBLIGE's contribution?**

---

## Executive Summary

OBLIGE's core operation — evaluating a safety predicate at each step of an abstract interpreter's execution trace to find where the proof broke — maps most cleanly to **runtime verification applied to abstract traces**. The nearest intellectual neighbors are:

1. **Runtime verification / trace monitoring** (Havelund & Rosu 2001; Bauer et al. 2011) — OBLIGE does property monitoring, but over an *abstract* trace rather than a concrete execution.
2. **Counterexample explanation in model checking** (Clarke et al. 2001; Gurfinkel & Chechik 2003) — These papers explain *why* a counterexample is spurious or genuine; OBLIGE explains *where* the proof broke.
3. **Error trace analysis / fault localization** (Zeller 2002; BugAssist 2011; SNIPER 2015) — These localize bugs using delta debugging, MAX-SAT over bounded model checker traces, or UNSAT core extraction.
4. **Compiler diagnostics / multi-span errors** (Rust's diagnostic system; Elm's error messages) — OBLIGE's output format is most similar to the Rust compiler's multi-span approach.
5. **Program slicing for debugging** (Weiser 1981) — OBLIGE's backward slice from the transition point is a simplified version of Weiser slicing.

**Key finding**: OBLIGE is doing something genuinely new *in combination*, but each individual sub-technique is classical. The paper should frame this explicitly: "We apply trace monitoring over abstract states (classical technique) to the novel domain of eBPF verifier output (new application), and show that the resulting lifecycle classification (proof established → proof lost) provides information no existing tool provides for eBPF diagnostics."

---

## Part 1: Fault Localization in Model Checking

### 1.1 BugAssist (CAV 2011)

**Citation**: Jose, Mahesh and Majumdar, Rupak. "Cause Clue Clauses: Error Localization Using Maximum Satisfiability." In *PLDI 2011*, pp. 437–446. ACM.

**Approach**: BugAssist encodes a bounded model checker's error trace as a MAX-SAT problem. Each statement in the program is associated with a Boolean literal. BugAssist finds the *minimum set of statements* that must be "faulty" (i.e., whose semantics need to change) to make the trace infeasible — i.e., to eliminate the error. Statements in the MAX-SAT solution are flagged as likely fault locations.

**Relation to OBLIGE**: BugAssist works on *concrete counterexample traces* from CBMC-style bounded model checkers. OBLIGE works on *abstract execution traces* from an abstract interpreter. Both are "trace-based fault localization," but:
- BugAssist requires a concrete failing execution and computes which statements caused it.
- OBLIGE is given the abstract states at each instruction (already computed by the verifier) and finds the transition where the safety proof breaks.
- BugAssist uses MAX-SAT; OBLIGE uses direct predicate evaluation.

**Should OBLIGE cite this?** Yes. BugAssist is the closest prior work on fault localization from verification tool outputs. The key difference to emphasize: BugAssist operates on *concrete* traces from CBMC (requiring a compilable, runnable program); OBLIGE operates on *abstract* traces already logged by the eBPF verifier (no re-execution needed, pure userspace).

**Could OBLIGE use this technique?** Partially. MAX-SAT localization could be applied if OBLIGE had a formal specification of the verifier's transition function. Currently infeasible because the eBPF verifier's abstract domain is complex and not formalized in a SAT-friendly way. Not a near-term opportunity.

---

### 1.2 SNIPER (2015–2018)

**Citation**: Ermis, Erkan, Martin Schäf, and Thomas Wies. "Error Invariants." In *FM 2012*. Subsequently extended into the SNIPER tool published at *NFM 2015* by the NASA Ames group.

**Approach**: SNIPER computes *error invariants* — predicates that hold at a program point along a failing trace and remain invariant under all "plausible" executions that still lead to the error. An error invariant at point p is a necessary condition for the failure to occur starting from p. The technique is backward: starting from the error, it weakens the precondition needed to reach the error using Craig interpolants from a SAT/SMT solver.

**Relation to OBLIGE**: SNIPER's error invariants are conceptually similar to OBLIGE's "what was the minimal state change that made the proof fail?" But:
- SNIPER uses interpolant-based backward reasoning from a concrete counterexample.
- OBLIGE uses forward predicate evaluation over abstract states logged by the verifier.
- SNIPER requires an SMT solver and a formal program model.
- OBLIGE requires only the verifier's LOG_LEVEL2 text output.

**Should OBLIGE cite this?** Yes, as a contrasting approach. SNIPER requires re-running a model checker over a formal program model; OBLIGE operates on existing verifier output, making it deployable without additional tooling.

**Could OBLIGE use this technique?** The interpolant idea is appealing for generating *explanations* of why the proof broke (not just where). Future work could use interpolants to generate the "why" narrative in the diagnostic. Not tractable for the current paper scope.

---

### 1.3 Zeller's Delta Debugging and Cause-Effect Chains (2002)

**Citation**: Zeller, Andreas and Hildebrandt, Ralf. "Simplifying and Isolating Failure-Inducing Input." *IEEE Transactions on Software Engineering*, 28(2), 2002. Also: Zeller, Andreas. "Isolating Cause-Effect Chains from Computer Programs." *FSE 2002*.

**Approach**: Delta debugging (DD) takes a failing test input and applies a "divide-and-conquer" minimization to find the minimal subset of the input that still triggers the failure. The cause-effect chain approach extends this to program states: by systematically varying the program state at a given program point and observing whether the failure occurs, DD identifies which variables (and which values) are causally responsible for the failure.

**Relation to OBLIGE**: Delta debugging and OBLIGE both ask "which part of the execution is responsible for the failure?" But they work at different levels:
- DD requires re-executing the program repeatedly with modified inputs or states.
- OBLIGE works from a single execution trace (the verifier log) without re-execution.
- For eBPF, re-execution would require loading the program into a kernel — expensive and not always possible. OBLIGE's "no re-execution needed" property is a significant practical advantage.

**Should OBLIGE cite this?** Yes. Delta debugging is foundational. OBLIGE should note that its approach is more like static trace analysis than dynamic failure isolation — it uses the verifier's pre-computed abstract states rather than re-running to probe state changes.

**Could OBLIGE use this technique?** Delta debugging over verifier traces would mean: remove instructions from the eBPF program, resubmit to verifier, observe if failure changes. This is actually feasible and could be a useful complementary technique for identifying the *minimal* program that triggers a given error. Not done currently, but worth noting as future work.

---

### 1.4 Error Explanation and Counterexample Characterization (Clarke et al., Gurfinkel & Chechik)

**Citation**: Clarke, Edmund M. et al. "Counterexample-Guided Abstraction Refinement." *CAV 2000*.
Also: Gurfinkel, Arie and Chechik, Marsha. "Proof-like Counter-Examples." *TACAS 2003*.
And: "A Framework for Counterexample Generation and Exploration." *FASE 2005*.

**Approach**: In CEGAR, counterexamples arise when an abstraction is too coarse — the abstract model contains a spurious trace that doesn't correspond to a real execution. The challenge is distinguishing *real* counterexamples (genuine bugs) from *spurious* ones (abstraction artifacts). Proof-like counterexamples annotate the counterexample with the reason it might be spurious, helping the abstraction refinement choose better predicates.

**Relation to OBLIGE**: There is a deep structural analogy between CEGAR and OBLIGE's framing:
- In CEGAR: abstract model → abstract trace → is this trace real or spurious?
- In OBLIGE: abstract interpreter → abstract state sequence → did the proof actually fail, or did the verifier just not track the invariant?
- OBLIGE's distinction between "proof never established" (verifier correctly rejected a genuinely unsafe program) versus "proof established then lost" (verifier's abstraction lost track of a valid invariant) is analogous to "real counterexample" vs. "spurious counterexample."

**Should OBLIGE cite this?** Strongly yes. This analogy is intellectually precise and worth drawing explicitly in the paper. The "proof established → proof lost" classification maps to "spurious rejection" — the program may be safe, but the verifier's abstract domain lost the proof. The analogy strengthens the framing of OBLIGE's contribution.

**Could OBLIGE use this technique?** CEGAR-style abstraction refinement for eBPF would be a major contribution on its own — each "spurious rejection" would trigger a request to add a verifier hint (BTF annotation, bpf_loop(), explicit cast) to help the verifier recover the proof. This is actually how expert eBPF developers work today (adding hints to guide the verifier). Formalizing this as a CEGAR loop is a major future direction.

---

### 1.5 Bounded Model Checking and Fault Localization (CBMC)

**Citation**: Clarke, Edmund, et al. "Bounded Model Checking." *Advances in Computers*, 2003.

**Approach**: CBMC unrolls program loops up to a bound and encodes the resulting path as a SAT/SMT formula. When the formula is unsatisfiable (no error), the proof is complete up to the bound. When satisfiable, the model returns a concrete counterexample trace showing the failing execution.

**Relation to OBLIGE**: The eBPF verifier is more like a *bounded model checker* than a traditional abstract interpreter in one important way: it explores all paths up to a bounded depth (instruction count limit) and either accepts (proof complete) or rejects (found a potential violation). OBLIGE's analysis of the proof trace is therefore analogous to analyzing a BMC counterexample — finding where the proof diverged from safety.

**Should OBLIGE cite this?** Yes, to establish the relationship between the eBPF verifier's architecture and bounded model checking. This helps reviewers from the formal methods community understand the setting.

---

## Part 2: Counterexample Explanation and Error Trace Analysis

### 2.1 Error Trace Analysis via Slicing

**Citation**: Cleve, Holger and Zeller, Andreas. "Locating Causes of Program Failures." *ICSE 2005*.

**Approach**: Given a failing test case, compute which program variables and statements are causally linked to the failure by modifying program state at each program point and observing whether the failure still occurs. The result is a "cause" (a set of variable assignments) that distinguishes passing from failing runs.

**Relation to OBLIGE**: OBLIGE's backward slice from the proof-loss instruction is essentially static "cause analysis" — which prior instructions wrote to the registers whose values caused the proof to fail? Cleve & Zeller's dynamic version finds the same information by probing state changes. OBLIGE finds it statically by following def-use edges in the logged trace.

**Should OBLIGE cite this?** Yes, briefly. OBLIGE's backward slice is a simpler, static approximation of Cleve & Zeller's dynamic causal analysis.

---

### 2.2 Lightweight Defect Localization

**Citation**: Dallmeier, Valentin, Christian Lindig, and Andreas Zeller. "Lightweight Defect Localization for Java." *ECOOP 2005*.

**Approach**: Uses object field access patterns (Daikon-style invariant mining) at the level of method call sequences to find anomalous object behavior. Defects are identified as deviations from normal method-call patterns.

**Relation to OBLIGE**: Not directly applicable (OBLIGE works at the instruction level, not object level). But the "deviation from normal behavior" framing is analogous — OBLIGE looks for deviations in the abstract state sequence (bounds collapse, type downgrade) as signals of failure.

---

### 2.3 Simplifying Failure-Inducing Input (Delta Debugging for Inputs)

**Citation**: Zeller, Andreas and Hildebrandt, Ralf. "Simplifying and Isolating Failure-Inducing Input." *IEEE TSE*, 28(2), 2002.

**Approach**: Minimize the test input that triggers a failure. The reduced input is easier to analyze. Widely used for compiler bugs (C-Reduce, Perses).

**Relation to OBLIGE**: C-Reduce (Regehr et al., *PLDI 2012*) applies delta debugging to C programs to minimize compiler bugs. There is a direct analog for eBPF: given a failing eBPF program, apply program reduction to find the minimal eBPF program that still triggers the same verifier error. This would be a clean, useful tool. Nobody has built this for eBPF.

**Could OBLIGE use this technique?** Yes. An "eBPF-Reduce" tool that applies structural program reduction while preserving the verifier error ID would help with: (a) documenting minimal reproducer cases, (b) identifying verifier bugs, (c) simplifying diagnostic analysis. This is a concrete, buildable future work item.

---

## Part 3: Abstract Interpretation Diagnostics

### 3.1 Astrée and False Alarm Reporting

**Citation**: Cousot, Patrick, et al. "The ASTRÉE Analyzer." *ESOP 2005*.
Also: Blanchet, Bruno, et al. "A Static Analyzer for Large Safety-Critical Software." *PLDI 2003*.

**Approach**: Astrée is an abstract interpreter for C programs targeting safety-critical embedded software. Its goal is *zero false alarms*: every alarm it raises corresponds to a genuine potential error. When Astrée raises an alarm, it provides: the source location, the abstract state at that location (numerical domain values), and the path sensitivity information showing which branch conditions led to the alarm.

**Relation to OBLIGE**: Astrée's alarm format is the closest analog to what OBLIGE produces. Both:
- Are triggered by an abstract interpreter finding a potential violation.
- Report the source location of the violation.
- Show the abstract state (register values / variable bounds) at the alarm point.

**The key difference**: Astrée raises *potential* violations (the abstract state shows the value might be out of bounds). The eBPF verifier raises *definite* rejections (the abstract domain knows the value is unsafe). OBLIGE's task is not to report the violation (the verifier already does this) but to explain *why* the abstract domain reached the unsafe state.

**Should OBLIGE cite this?** Yes, as the closest static analysis diagnostic system. The framing should be: "Astrée and similar analyzers produce alarms with abstract state context. OBLIGE extends this by adding causal history — tracing the state backward from the alarm to the instruction where the safety property was established and then lost."

**Could OBLIGE use these techniques?** Astrée's approach to presenting alarms (source location + abstract state) is already what OBLIGE does. OBLIGE adds the lifecycle (establish/lost) dimension. Worth citing as evidence that the "abstract state at alarm point" format is established practice.

---

### 3.2 Facebook Infer and Bi-Abduction

**Citation**: Calcagno, Cristiano, Dino Distefano, Peter O'Hearn, and Hongseok Yang. "Compositional Shape Analysis by Means of Bi-Abduction." *JACM*, 58(6), 2011.
Also: Calcagno, Cristiano, et al. "Moving Fast with Software Verification." *NASA FM 2015*.

**Approach**: Infer is a compositional static analyzer based on bi-abduction: it infers preconditions and postconditions for each function separately and then composes them. When a null pointer dereference or resource leak is found, Infer produces an *error trace* — a sequence of program steps from the entry point to the bug, showing what the heap looks like at each step.

**Infer's error format**: Each error has:
- Error type (NULL_DEREFERENCE, RESOURCE_LEAK, etc.)
- Source file and line
- A "trace" showing the call stack and intermediate steps that led to the error
- The specific variable/heap cell that caused the problem

**Relation to OBLIGE**: Infer's error trace format is inspirational for OBLIGE's diagnostic output. The key differences:
- Infer's traces are *interprocedural* (across function calls). OBLIGE's traces are *intrafunction* (within a single eBPF program).
- Infer uses *separation logic* and *heap shapes*. OBLIGE uses *scalar bounds, type lattice, and pointer ranges*.
- Infer provides a *callee summary* approach. OBLIGE has no function call abstraction (eBPF helpers are treated as side-effecting black boxes).

**Should OBLIGE cite this?** Yes, as the state of the art in abstract interpretation error reporting. Infer's error trace format is closer to what OBLIGE targets than most systems.

**Could OBLIGE use these techniques?** OBLIGE could borrow Infer's "trace step" format for explaining the causal chain. Currently, OBLIGE shows "proof established at line 38, proof lost at line 42." Infer would show each intermediate step with the abstract state change. Adopting a step-by-step trace format would make OBLIGE's output more similar to Infer's and easier to validate.

---

### 3.3 Frama-C / Value Analysis Alarms

**Citation**: Cuoq, Pascal, et al. "Frama-C: A Software Analysis Platform." *SEFM 2012*.
Also: Kirchner, Florent, et al. "Frama-C: A Software Analysis Perspective." *FAC 2015*.

**Approach**: Frama-C's Value plugin is an abstract interpreter for C using an interval + congruence domain. It emits *alarms* at program points where the abstract value might violate a safety property (out-of-bounds access, integer overflow, etc.). Each alarm includes the abstract state at the alarm point.

**Relation to OBLIGE**: Same relationship as Astrée. Frama-C's Value produces point-in-time alarms with abstract state context; OBLIGE adds the causal lifecycle.

**One specific Frama-C technique of interest**: Frama-C's *alarm reduction* feature uses abstract interpretation to prove that some alarms are unreachable given additional context. This is analogous to OBLIGE's challenge of distinguishing "proof never established" (genuine missing check) from "proof lost by lowering" (valid check that the verifier can't track). A future OBLIGE could adopt alarm classification to distinguish these more precisely.

---

### 3.4 The Cousot-Cousot Abstract Interpretation Framework

**Citation**: Cousot, Patrick, and Radhia Cousot. "Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs by Construction or Approximation of Fixpoints." *POPL 1977*.

**Approach**: Defines the abstract interpretation framework: abstract domains (lattice-based overapproximations of program states), Galois connections between concrete and abstract domains, transfer functions, and fixpoint computation. The standard reference for any analysis that operates over per-instruction abstract states.

**Relation to OBLIGE**: The eBPF verifier is an abstract interpreter in exactly the Cousot-Cousot sense:
- Abstract domain: {type_tag × scalar_bounds × tnum × pointer_offset × pointer_range}
- Transfer functions: one per BPF opcode
- Fixpoint computation: for loops (with limits)
- Safety property: type safety + memory safety + register type constraints

OBLIGE's "proof obligation evaluation" is monitoring a property over the output of this abstract interpreter. Citing Cousot-Cousot establishes the theoretical foundation.

**Should OBLIGE cite this?** Yes, briefly, to connect the eBPF verifier to the standard abstract interpretation literature.

---

### 3.5 Partial Completeness and Precision Measurement

**Citation**: Campion, Marco, Mila Dalla Preda, and Roberto Giacobazzi. "Partial (In)Completeness in Abstract Interpretation: Limiting the Imprecision in Program Analysis." *POPL 2022*.

**Approach**: Introduces a framework for measuring *how much* imprecision an abstract interpreter introduces — quantifying the gap between what the abstract domain can prove and what the concrete semantics requires. Defines "partial completeness" as a bound on false alarms.

**Relation to OBLIGE**: OBLIGE's "proof established → proof lost" classification is essentially measuring partial completeness: the verifier's domain was *complete enough* to establish the proof at the bounds check, but became *incomplete* (imprecise) after the OR instruction. Citing this work would strengthen the theoretical framing: OBLIGE detects *completeness loss events* in the verifier's abstract interpretation.

**Should OBLIGE cite this?** Yes, for the OSDI/ATC version. This gives OBLIGE a precise theoretical vocabulary: the "proof loss" event is a *completeness loss* in the abstract domain. This is a stronger framing than "abstract state transition."

**Could OBLIGE use this technique?** Yes. Campion et al.'s framework could provide formal language for measuring how often OBLIGE detects completeness loss vs. genuine safety violations. This could be a metric: "OBLIGE identifies N completeness-loss events in our 262-case dataset, corresponding to M lowering artifacts where the verifier's domain is incomplete relative to the compiler's transformations."

---

## Part 4: Runtime Verification and Trace Checking

### 4.1 Runtime Verification Overview (Havelund & Rosu)

**Citation**: Havelund, Klaus, and Grigore Rosu. "Synthesizing Monitors for Safety Properties." *TACAS 2002*.
Also: Rosu, Grigore, and Klaus Havelund. "Rewriting-Based Techniques for Runtime Verification." *Automated Software Engineering*, 2005.
Key survey: Bartocci, Ezio, et al. "Lectures on Runtime Verification." *Springer LNCS*, 2018.

**Approach**: Runtime verification (RV) monitors a single execution trace to check if it satisfies a safety or liveness property. Key concepts:
- A *monitor* is a finite-state automaton (or equivalent formalism) that reads the trace and outputs a verdict: ok, error, or inconclusive.
- *Safety properties*: the monitor catches the first point where the trace violates the property.
- Three-valued semantics (Bauer, Leucker, Schallhart 2006): a trace that hasn't violated a property yet has verdict ⊤ (definitely good), ⊥ (definitely bad), or ? (inconclusive).

**Relation to OBLIGE**: OBLIGE is *exactly* a monitor for a safety property over an abstract trace:
1. The "trace" is the eBPF verifier's LOG_LEVEL2 output: the sequence of per-instruction abstract states.
2. The "property" is a proof obligation P (e.g., `pkt_ptr has established range bound`).
3. The "verdict" is: proof_established (⊤), proof_lost (⊥), or never_established (?).
4. The "transition witness" w (the first instruction where P flips from ⊤ to ⊥) is the classic "first violation point" in RV.

**Critical distinction**: Standard RV monitors *concrete* execution traces. OBLIGE monitors an *abstract* trace. This distinction is what gives OBLIGE Proposition 1 (soundness): because the abstract states overapproximate the concrete states, if P holds on the abstract state at instruction i, it holds on all concrete states in γ(s_i).

**Should OBLIGE cite this?** Strongly yes. This is the most direct technical framing for OBLIGE's core algorithm. The paper should say explicitly: "OBLIGE is a safety property monitor over the abstract trace produced by the eBPF verifier. Monitoring abstract traces rather than concrete ones gives soundness by the Galois connection."

**Novelty over RV**: Applying RV to abstract traces is the novel application. Standard RV assumes concrete traces (every state value is precise). OBLIGE's contribution in this framing is showing that property monitoring over abstract traces (a) is feasible from verifier log output, (b) provides soundness guarantees from abstract interpretation theory, and (c) enables a useful lifecycle classification for eBPF diagnostics.

---

### 4.2 Three-Valued LTL Monitoring

**Citation**: Bauer, Andreas, Martin Leucker, and Christian Schallhart. "Monitoring of Real-Time Properties." *STTT*, 2011.
Also: "Runtime Verification for LTL and TLTL." *ACM TOSEM*, 2011.

**Approach**: Extends LTL monitoring with a three-valued semantics (true, false, inconclusive) where "inconclusive" means the trace so far is consistent with both satisfaction and violation. This is LTL_3 monitoring.

**Relation to OBLIGE**: OBLIGE uses an analogous three-valued status for proof obligations: {unknown, satisfied, violated}. The semantics match: "unknown" is Bauer et al.'s "inconclusive" — the verifier hasn't encountered the relevant instruction yet. "Satisfied" is "currently holding." "Violated" is "property definitively broken."

**Should OBLIGE cite this?** Yes, briefly. The three-valued status in OBLIGE's proof obligation framework has a direct formal analog in LTL_3 monitoring. Citing Bauer et al. provides the theoretical grounding for the {unknown, satisfied, violated} lattice.

---

### 4.3 Abstract Runtime Verification (Pnueli & Zaks)

**Citation**: Pnueli, Amir, and Aleksandr Zaks. "PSL Model Checking and Run-time Verification via Testers." *FM 2006*.
Also: Fischler, Dana, and Orna Grumberg. "Model Checking Abstract Traces." *TACAS 2015*.

**Approach**: Extends runtime verification to work with abstract representations of system behavior. Checks properties against abstractions of concrete traces rather than the concrete traces themselves. The key insight is that abstraction can be exploited to reduce monitoring overhead or to apply verification tools to imprecise trace data.

**Relation to OBLIGE**: Fischler & Grumberg's "model checking abstract traces" is the most directly related work in the RV literature. They check temporal properties against abstract traces (where some states are approximated). OBLIGE's monitoring of the abstract eBPF verifier trace is an instance of this framework.

**Should OBLIGE cite this?** Yes. This establishes that monitoring abstract traces is a recognized research direction, not an ad hoc trick. Citing it gives OBLIGE formal grounding.

**Note**: This work is relatively obscure compared to standard RV. If reviewers from the systems community are the primary audience (OSDI/ATC), this citation adds credibility but should be used concisely.

---

## Part 5: Spectrum-Based Fault Localization

### 5.1 Tarantula and Ochiai

**Citation**: Jones, James A., and Mary Jean Harrold. "Empirical Evaluation of the Tarantula Automatic Fault-Localization Technique." *ASE 2005*.
Also: Abreu, Rui, Peter Zoeteweij, and Arjan JC Van Gemund. "On the Accuracy of Spectrum-Based Fault Localization." *TAICPART 2007* (Ochiai coefficient).

**Approach**: Spectrum-based fault localization (SBFL) uses test coverage information: which tests pass and which fail, and which statements each test executes. Statements executed more often by failing tests and less often by passing tests get higher "suspiciousness" scores. Tarantula and Ochiai are specific metrics for computing this score.

**Relation to OBLIGE**: SBFL requires *multiple test executions* (both passing and failing) to compute coverage statistics. For eBPF:
- There is typically only one "execution" per program submission (the verifier either accepts or rejects).
- There is no "passing run" of a failing eBPF program to contrast with.
- SBFL does not naturally apply to single-execution failure diagnosis.

**Could OBLIGE use this technique?** SBFL could apply if one defines "test executions" as different eBPF programs submitted to the verifier (e.g., systematically varying bounds constants) and observes which paths through the abstract state trace are taken by accepting vs. rejecting programs. This is an interesting research direction but is far from the current OBLIGE scope.

**Should OBLIGE cite this?** Briefly, to acknowledge SBFL exists and explain why it doesn't apply to OBLIGE's setting (single-execution, no passing run available).

---

### 5.2 Spectrum-Based Localization Applied to Abstract Interpretations

There is no known prior work that applies SBFL to abstract interpreter output. This would be a novel application if someone computed "which abstract domain operations are executed more often in failing configurations than in passing ones." Not relevant to OBLIGE currently but a potential gap to claim.

---

## Part 6: Delta Debugging and Program Reduction

### 6.1 C-Reduce (Regehr et al. 2012)

**Citation**: Regehr, John, et al. "Test-Case Reduction for C Compiler Bugs." *PLDI 2012*.

**Approach**: C-Reduce applies a set of Clang-based transformations to reduce a failing C program to a minimal version that still triggers the same compiler bug. Uses the "interesting" predicate (does the reduced program still trigger the same error?).

**Relation to OBLIGE**: Directly analogous to OBLIGE's problem domain. An "eBPF-Reduce" tool would:
1. Start with a failing eBPF program + verifier error.
2. Apply eBPF-specific transformations (remove instructions, simplify expressions, specialize constants).
3. Keep reducing while the verifier still produces the same error ID.
4. Return a minimal eBPF program that isolates the cause.

**Should OBLIGE cite this?** Yes, as evidence that program reduction for compiler/verifier bugs is a validated technique and to position an eBPF reducer as a concrete future work direction.

**Could OBLIGE use this technique?** Building an eBPF-Reduce would be a distinct contribution. The "interesting" predicate would be: `verifier produces error ID X`. Unlike C-Reduce which must respect C semantics, eBPF programs are already simple sequential bytecode — reduction is likely easier.

---

### 6.2 Delta Debugging for eBPF?

Nobody has built delta debugging for eBPF verifier failures. Given the popularity of eBPF and the known pain of understanding verifier errors, this is a real gap. An eBPF delta debugging tool would:
- Take a failing eBPF program
- Systematically minimize it while preserving the verifier failure
- Return a ~10-instruction program that clearly shows the failure

**OBLIGE opportunity**: OBLIGE's error ID classification provides the "interesting" predicate for free — keep reducing while the same OBLIGE-E0xx is produced. This is a concrete future work item worth mentioning in the paper.

---

## Part 7: Compiler Error Message Improvement

### 7.1 Rust's Multi-Span Diagnostic System

**Citation**: The Rust programming language diagnostics system. Key blog post: "Shape of Errors to Come." *Rust Blog*, August 2016. Technical documentation: Rust Compiler Development Guide, Diagnostics chapter.

**Approach**: Rustc's diagnostic system emits errors with *multiple spans* — code ranges highlighted simultaneously, with different labels (primary span = the core issue; secondary spans = contributing context). The key innovation is:
1. **Primary labels**: Answer "what is wrong here?" — bold, with the main error description.
2. **Secondary labels**: Answer "why?" — lighter weight, showing contributing context (e.g., the type was originally declared here, the constraint was introduced there).
3. **Notes**: Additional context below the code snippet.
4. **Help**: Suggested fixes.

The format was explicitly inspired by Elm's error messages (Czaplicki 2015) which emphasized: show the developer's own code, not abstract compiler internals.

**Relation to OBLIGE**: OBLIGE's output format is modeled directly on Rust's multi-span approach. The paper's example:
```
38 │  if (data + ext_len <= data_end) {  ← "proof established"
42 │  __u16 ext_len = __bpf_htons(...)   ← "proof lost: OR destroys bounds"
45 │  void *next = data + ext_len;        ← "rejected: pkt_ptr + unbounded"
```
Is structurally identical to Rust's three-span pattern (where + how + consequence).

**Should OBLIGE cite this?** Yes, explicitly. The diagnostic format is inspired by Rust's multi-span approach. This citation also helps reviewers understand what "structured diagnostics" means concretely.

**Key difference**: Rust's diagnostics are generated by the compiler itself, with full knowledge of the AST and type system. OBLIGE generates its diagnostics by *post-processing* the verifier's external log output. This is harder (must parse unstructured text, must reconstruct the causal chain retroactively) but more general (works with any verifier version, no kernel modifications needed).

---

### 7.2 Elm Compiler Error Messages

**Citation**: Czaplicki, Evan. "Compiler Errors for Humans." *Elm Blog*, 2015. Blog post describing the philosophy behind Elm 0.15.1's improved error messages.

**Approach**: Elm's compiler shows the developer's own code with error annotations rather than abstract compiler state. The key principles:
1. Show the code you wrote, not the compiler's internal representation.
2. Provide a short, specific explanation of what went wrong.
3. Use color and whitespace to make the message scannable.
4. Where possible, suggest a fix.

**Relation to OBLIGE**: OBLIGE follows all four Elm principles:
1. Shows BTF-annotated source lines, not bytecode.
2. Labels like "proof established" and "proof lost" are specific and meaningful.
3. Multi-span format uses visual structure.
4. `= help:` suggestions are generated based on the failure class.

**Should OBLIGE cite this?** Yes, briefly. Positioning OBLIGE as applying "Rust/Elm-quality diagnostics to eBPF verification" is an effective framing that resonates with systems audience.

---

### 7.3 Type Error Message Improvement Literature

**Citation**: Heeren, Bastiaan, Jurriaan Hage, and S. Doaitse Swierstra. "Improving Type Error Messages in Functional Languages." *Haskell Workshop 2003*.
Also: Heeren, Bastiaan, et al. "Helium, for Learning Haskell." *Haskell Workshop 2003*.

**Approach**: Type error messages in Haskell are notoriously difficult to understand. These papers improved them by: (1) using constraint solving with blame assignment to identify the most likely source of the mismatch, (2) using multiple source locations instead of a single error point, (3) reporting which term "introduced" the type constraint rather than just where the constraint is violated.

**Relation to OBLIGE**: The *blame assignment* problem in type inference is structurally similar to OBLIGE's root cause identification: both must find the source of an abstract invariant (type constraint / safety invariant) and explain how it was violated. Heeren et al.'s constraint graph approach (annotating each constraint with its origin) has a direct analog in OBLIGE's proof obligation annotation (labeling each state transition with whether it establishes or violates the obligation).

**Should OBLIGE cite this?** Yes, briefly. The type error improvement literature predates OBLIGE's goal by two decades and establishes that "blame assignment in an abstract interpreter" is a recognized research problem.

---

## Part 8: eBPF-Specific Prior Work

### 8.1 Pretty Verifier (Politecnico di Torino, 2025)

**Citation**: Miano, Sebastiano, Roberto Lezzi, Gabriele Lospinoso, and Fulvio Risso. "Pretty Verifier: Towards Friendly eBPF Verification Errors." 2025. (See existing literature-survey.md §4 for full details.)

**Approach**: Pattern-matches raw verifier strings to 83 handlers; uses `llvm-objdump` to map instruction addresses to source lines; emits human-readable reformatted errors.

**How OBLIGE differs**:
- Pretty Verifier: error message → regex match → handler → reformatted message. Operates only on the error line.
- OBLIGE: full LOG_LEVEL2 trace → abstract state sequence → predicate evaluation → lifecycle classification → multi-span diagnostic. Analyzes the entire proof trace.
- Pretty Verifier is vulnerable to kernel-version wording changes (regex-based). OBLIGE parses the structured per-instruction state format, which is more stable.
- Pretty Verifier requires source file + debuggable object. OBLIGE only requires the verifier log (BTF-annotated for source lines).
- Pretty Verifier does not produce structured machine-readable output. OBLIGE produces JSON-schema diagnostics.

**Key claim**: OBLIGE detects root causes that Pretty Verifier *cannot detect* — specifically, lowering artifacts where the error location is remote from the root cause. In a lowering artifact, the error message points to instruction 45 (memory access), Pretty Verifier reformats that instruction's error, but the root cause is at instruction 42 (the htons() expansion that destroyed bounds). Only analyzing the full trace reveals this.

---

### 8.2 Tristate Numbers (tnum) Formalization (Vishwanathan et al., CGO 2022)

**Citation**: Vishwanathan, Harishankar, et al. "Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers." *CGO 2022*.

**Approach**: Formally specifies the eBPF verifier's `tnum` (tristate number) abstract domain for bitwise uncertainty tracking. Proves soundness of addition, subtraction, and proposes an improved multiplication algorithm. The paper contributed an improved tnum multiplication algorithm that was merged into the Linux kernel.

**Relation to OBLIGE**: The tnum domain is one of the abstract domains OBLIGE reads from the verifier's LOG_LEVEL2 output. Citing Vishwanathan et al. acknowledges that the eBPF verifier's abstract domains are receiving formal treatment. OBLIGE's abstract state parser (`log_parser.py`) must handle tnum-format values (hex masks) in addition to scalar bounds.

**Should OBLIGE cite this?** Yes. As the primary formal treatment of eBPF verifier abstract domains, it establishes the theoretical grounding for OBLIGE's use of abstract state values.

---

### 8.3 BeePL (PLDI 2025): Correct-by-Compilation

**Citation**: Priya, Swarn, et al. "BeePL: Correct-by-compilation Kernel Extensions." *PLDI 2025*.

**Approach**: Domain-specific language that compiles to eBPF bytecode such that the compiled output is guaranteed to pass the verifier. The key design is a type system that matches the verifier's abstract domain, eliminating the need for ad hoc verifier workarounds.

**Relation to OBLIGE**: BeePL takes the opposite approach to OBLIGE — eliminate verifier failures by construction rather than explain them. However, the two are complementary: BeePL addresses new development; OBLIGE addresses existing programs, debugging, and the inevitable cases where BeePL's type system rejects something the developer believes is safe.

---

### 8.4 BRF: eBPF Runtime Fuzzer (USENIX Security 2023)

**Citation**: Hung, Hsin-Wei, and Ardalan Amiri Sani. "BRF: eBPF Runtime Fuzzer." *USENIX Security 2023*.

**Approach**: Fuzzes eBPF programs to find runtime vulnerabilities. Finds 4 CVEs. Key challenge: the verifier rejects most fuzz-generated programs, making it hard to get interesting programs into the kernel.

**Relation to OBLIGE**: BRF and OBLIGE work in opposite directions — BRF tries to bypass the verifier, OBLIGE tries to help developers satisfy it. But BRF's observation that "the verifier rejects most fuzzing inputs" validates the difficulty of the verifier's acceptance conditions. OBLIGE's diagnostics could help fuzzer developers understand *why* their inputs are rejected and generate better test cases.

---

## Part 9: Program Slicing

### 9.1 Weiser's Program Slicing

**Citation**: Weiser, Mark. "Program Slicing." *ICSE 1981*. Also in *IEEE TSE*, 1984.

**Approach**: A program slice is the subset of a program that can affect the value of a variable at a given program point. Backward slices (from a use backward to all definitions that might affect it) use a program dependence graph (PDG) with both data and control dependence edges.

**Relation to OBLIGE**: OBLIGE's backward slice from the proof-loss instruction (collecting all instructions that wrote to registers in the failed predicate) is a simplified backward slice:
- Data dependence: OBLIGE follows def-use chains in the instruction trace (including value lineage tracking for reg copies and stack spills).
- Control dependence: OBLIGE does NOT reconstruct the CFG and does NOT include control dependence.

OBLIGE's slice is weaker than Weiser's because it:
1. Is path-insensitive (no CFG reconstruction)
2. Omits control dependence
3. Works on a flat instruction list, not a PDG

**Should OBLIGE cite this?** Yes, to acknowledge that the backward slice is a simplified version of the classical technique and to clarify its limitations. "Our backward slice follows data dependence edges over the logged instruction trace; we leave CFG reconstruction and control dependence to future work."

---

### 9.2 Mark-Precise Chain as Native Verifier Slicing

**Novel observation**: The eBPF verifier already performs a form of backward slicing internally. The `mark_precise` backtracking mechanism (kernel 5.5+, Alexei Starovoitov, 2019) is a backward pass from a rejected instruction through the `r.id` precision chain, marking registers that must be tracked precisely. OBLIGE extracts and structures this chain from LOG_LEVEL2 output.

**The mark_precise chain IS the verifier's own root-cause analysis**. It is a precision-propagating backward slice that the verifier performs for efficiency reasons (to avoid tracking all registers precisely at all times). OBLIGE's key engineering contribution is parsing this chain from unstructured log text and presenting it as a structured causal annotation.

**Related citation**: Starovoitov, Alexei. "bpf: precise scalar tracking." Linux kernel commit (2019). The first-level design rationale is in the kernel BPF selftest comments and the bpf@ mailing list discussions.

---

## Part 10: Framing Analysis

### What is OBLIGE, precisely?

Based on the literature above, OBLIGE is best described as:

> **A safety property monitor for the abstract execution trace of the eBPF verifier, producing structured multi-span diagnostics with causal lifecycle annotations.**

This framing maps to established concepts:
- "Safety property monitor" → runtime verification (Havelund & Rosu 2002)
- "Abstract execution trace" → abstract interpretation output (Cousot & Cousot 1977)
- "Causal lifecycle annotations" → fault localization via trace analysis (BugAssist 2011, Zeller 2002)
- "Multi-span diagnostics" → compiler error message improvement (Rust 2016, Elm 2015)

### What is genuinely novel?

The **combination** is novel:
1. Nobody has applied safety property monitoring to the output of the eBPF verifier.
2. Nobody has defined proof obligation lifecycle (established/lost/never_established) for eBPF failures.
3. Nobody has structured the mark_precise backtracking chain as a diagnostic output.
4. The equivalence class between "proof established then lost" and "lowering artifact / spurious rejection" (the CEGAR analogy) has not been formalized for eBPF.

Each **individual technique** is well-established:
- Trace monitoring: Havelund & Rosu 2002
- Abstract interpretation: Cousot & Cousot 1977
- Backward slicing: Weiser 1981
- Multi-span diagnostics: Rust 2016

### What should OBLIGE NOT claim?

- "Novel abstract interpretation technique" — OBLIGE does not perform a new abstract interpretation; it reads the verifier's output.
- "Novel fault localization algorithm" — the techniques are adapted from prior work.
- "Proof of correctness" — the soundness claim (Proposition 1) is a consequence of the Galois connection, not a new theorem.

### Recommended framing for the paper

**Section 2 (Background + Related Work)** should include:
1. Abstract interpretation (Cousot 1977) — establish the eBPF verifier as an abstract interpreter.
2. Runtime verification (Havelund & Rosu 2002; Bauer et al. 2011) — OBLIGE's core algorithm is RV over abstract traces.
3. Fault localization in model checking (BugAssist 2011; Zeller 2002) — OBLIGE is a trace-based fault localization tool.
4. CEGAR counterexample classification (Clarke et al. 2000; Gurfinkel & Chechik 2003) — "proof established then lost" = spurious rejection analogy.
5. Compiler diagnostics (Rust 2016; Elm 2015) — OBLIGE's output format.
6. Pretty Verifier (Miano et al. 2025) — direct comparison in the eBPF ecosystem.
7. Infer (Calcagno et al. 2011) — prior work on abstract interpretation diagnostics.
8. Weiser slicing (1981) — OBLIGE's backward slice is a simplified version.

**The key novelty claims** should be:
1. Application: First tool to apply safety property monitoring to the eBPF verifier's abstract trace.
2. Lifecycle classification: First definition of proof obligation lifecycle (established/lost) for eBPF diagnostics.
3. Mark-precise extraction: First tool to structure the verifier's own backtracking chain as a user-facing diagnostic.
4. Empirical: First systematic study showing that X% of eBPF verifier failures involve completeness-loss events (lowering artifacts), with quantification across 262 cases.

---

## Part 11: Additional Techniques Worth Investigating

### 11.1 Incorrectness Logic (O'Hearn 2019)

**Citation**: O'Hearn, Peter W. "Incorrectness Logic." *POPL 2020*.

**Approach**: Extends Hoare logic with "under-approximate" semantics for reasoning about bugs. While Hoare logic proves programs correct (overapproximate), incorrectness logic proves bugs are reachable (underapproximate). Used as the foundation for Meta Infer's "Pulse" analyzer.

**Relation to OBLIGE**: The eBPF verifier uses overapproximation (it may reject safe programs). Incorrectness logic is underapproximation. The interesting connection: OBLIGE's "proof never established" cases correspond to programs that incorrectness logic would prove as reachably unsafe. The "proof established then lost" cases are where the verifier's overapproximation is *too coarse* — it cannot track the invariant. This is not a soundness issue but a precision issue.

**Should OBLIGE cite this?** Briefly, for completeness. The O'Hearn incorrectness logic framing could help explain the distinction between "genuine bug" and "spurious rejection" in a theoretically rigorous way.

---

### 11.2 Verification Condition Generation and Weakest Preconditions

**Citation**: Dijkstra, Edsger W. "Guarded Commands, Nondeterminacy, and Formal Derivation of Programs." *CACM*, 1975.

**Approach**: Weakest precondition calculus computes, for a program S and postcondition Q, the weakest predicate P such that {P} S {Q}. Used in VCGen tools (ESC/Java, Dafny, etc.) to generate verification conditions.

**Relation to OBLIGE**: OBLIGE's proof obligation can be viewed as: given an error state Q (the verifier's rejection condition), what is the weakest precondition that must hold at some earlier instruction for the program to be safe? This is exactly WP(S, Q). OBLIGE finds the instruction where this precondition *stopped holding* by scanning forward.

**Should OBLIGE cite this?** Briefly. The WP connection gives a formal semantics for the "proof obligation" concept and could strengthen the theoretical framing.

---

### 11.3 Abstract Conflict-Driven Learning (ACDL)

**Citation**: Brain, Martin, et al. "Abstract Conflict Driven Clause Learning." *POPL 2013* (and subsequent work on model-checking with abstract CDCL).

**Approach**: Extends DPLL-T/CDCL SAT solving to abstract domains. When a conflict is found in the abstract space, the learned clause corresponds to an abstract constraint rather than a concrete clause.

**Relation to OBLIGE**: The conflict detection analogy: in ACDL, a "conflict" occurs when the abstract state leads to a contradiction. OBLIGE identifies the "conflict point" where the abstract safety predicate becomes violated. The ACDL conflict analysis (generating a learned clause that explains why the conflict occurred) is analogous to OBLIGE's backward slice (finding which earlier instructions contributed to the conflict).

**Should OBLIGE cite this?** For a full OSDI/ATC paper, probably not necessary. For a PL venue (PLDI, OOPSLA), this connection would strengthen the theoretical depth.

---

## Summary Table

| Related Work | Domain | What it does | OBLIGE relationship | Cite? |
|---|---|---|---|---|
| BugAssist (2011) | Model checking | MAX-SAT fault localization from bounded MC trace | Closest prior work; OBLIGE = RV over abstract trace instead of MAX-SAT over concrete trace | Yes |
| SNIPER (2015) | Model checking | Interpolant-based error invariant computation | Same goal (error localization), different mechanism (interpolants vs. predicate eval) | Yes |
| Zeller delta debugging (2002) | Testing | Minimize failure-inducing input via re-execution | OBLIGE analog but no re-execution needed | Yes |
| Clarke et al. CEGAR (2000) | Model checking | Distinguishes real vs. spurious counterexamples | "Proof lost" = spurious rejection analogy | Yes |
| Gurfinkel & Chechik (2003) | Model checking | Proof-like counterexamples | "Proof established" = genuine proof fragment | Yes |
| Havelund & Rosu RV (2002) | Runtime verif. | Safety property monitoring over execution traces | OBLIGE IS this, applied to abstract traces | Strongly yes |
| Bauer et al. LTL_3 (2011) | Runtime verif. | Three-valued LTL monitoring | OBLIGE's {unknown, satisfied, violated} status | Yes |
| Cousot & Cousot (1977) | Abstract interp. | Abstract interpretation framework | eBPF verifier is an abstract interpreter | Yes (brief) |
| Campion et al. (POPL 2022) | Abstract interp. | Partial completeness measurement | "Proof loss" = completeness loss event | Yes |
| Astrée / Frama-C | Abstract interp. | Abstract interpreter alarm reporting | OBLIGE's alarm format is inspired by this | Yes |
| Infer (Calcagno et al. 2011) | Static analysis | Bi-abduction, error traces | Closest existing error trace format | Yes |
| Rust multi-span diagnostics (2016) | Compiler | Multi-span error messages | OBLIGE's output format is modeled on this | Yes |
| Elm error messages (2015) | Compiler | Human-friendly error messages | Philosophy behind OBLIGE's diagnostic design | Brief |
| Weiser slicing (1981) | Program analysis | Program dependence graph slicing | OBLIGE's backward slice is a simplification | Yes |
| C-Reduce (2012) | Testing | Program minimization for compiler bugs | Analogous tool needed for eBPF verifier bugs | Future work |
| Pretty Verifier (2025) | eBPF | Regex-based verifier message reformatter | Direct comparison; OBLIGE analyzes full trace | Yes |
| Vishwanathan tnum (CGO 2022) | eBPF | Formal tnum domain specification | Foundation for eBPF abstract domain theory | Yes |
| O'Hearn incorrectness logic (2020) | Logic | Under-approximate bug reachability | Theoretical grounding for "genuine bug" vs. "spurious rejection" | Brief |
