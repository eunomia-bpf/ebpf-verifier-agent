# BPFix Design Review

Date: 2026-03-18

Scope:
- `docs/research-plan.md` read completely, with focus on `§1.1` and `§2.0`
- current engine code read in:
  - `interface/extractor/engine/monitor.py`
  - `interface/extractor/engine/opcode_safety.py`
  - `interface/extractor/engine/slicer.py`
  - `interface/extractor/pipeline.py`
  - supporting tests and internal review docs
- corpus and repair materials checked in:
  - `case_study/ground_truth_labels.yaml`
  - `docs/tmp/manual-labeling-30cases.md`
  - `docs/tmp/repair-pilot-case-2026-03-18.md`

## Bottom Line

The core idea is interesting, but the plan is not sound as currently stated, and the strongest claims are ahead of both the theory and the implementation.

My blunt assessment:

- The proposed cross-analysis rule in `docs/research-plan.md:48-54` and `docs/research-plan.md:203-212` is not sound without much stronger assumptions than the plan states.
- The plan is mixing three different things that should not be conflated:
  - proof lifecycle status
  - failure taxonomy
  - repairability
- The current engine does not implement the proposed design. In particular, it does not do global monitoring over all candidate proof carriers, and it does not use the backward slice to drive classification.
- The repair story is the weakest part. The pilot repair for `stackoverflow-70760516` is a structural loop rewrite, but Layer 4 is still framed as mostly local template insertion.
- Novelty is real only in the narrow sense of "domain-specific composition over eBPF verifier traces". It is not a new general analysis paradigm.

If this were sent to a top systems venue in its current framing, I would expect reviewers to push back on soundness, novelty inflation, and repair feasibility.

## 1. Cross-Analysis Classification (`§1.1`, `§2.0 Step D`)

### Verdict

The 3-way rule

- `E_global ∩ Slice != ∅ -> established_then_lost`
- `E_global != ∅ and E_global ∩ Slice = ∅ -> lowering_artifact`
- `E_global = ∅ -> source_bug`

is not sound as written.

At best it is a heuristic that may work on a restricted subset of packet-bounds cases under strong assumptions. It is not a generally valid classifier for verifier failures.

### When it would be defensible

The rule only becomes defensible if all of the following hold:

1. There is exactly one relevant safety obligation at the reject site.
2. That obligation can be represented as a register-parametric predicate, not a literal register-specific formula.
3. "Global monitoring" ranges only over proof-compatible carriers, not all registers.
4. The backward slice is exact enough to capture all relevant data/control dependencies, including copies, spill/fill, loop-carried facts, and branch merges.
5. The trace is complete enough to observe the first real establishment.
6. Structural classes such as `verifier_limit`, `env_mismatch`, and `verifier_bug` are filtered out before cross-analysis.
7. The classification uses both establishment and loss, not establishment alone.

The current plan states none of these precisely.

### The main logical problem

Step D only reasons about `Establishment_global`, not `Loss_global` (`docs/research-plan.md:203-212`). That is too weak.

`E_global ∩ Slice != ∅` does not imply "proof was established on the causal chain and later lost". It only implies that somewhere in the slice, at some point, some compatible predicate became satisfied.

That is missing at least three requirements:

- the establishment must be on the right proof carrier
- it must dominate or otherwise actually support the rejected use
- there must be a later loss witness on that same carrier or alias-equivalence class

Without a loss witness, the rule cannot distinguish "proof was once true somewhere" from "proof for this use was actually broken".

### Concrete counterexamples

#### Counterexample A: unrelated proof on another register

Program sketch:

- `R3` is checked and safe for packet access.
- `R5` is used for the rejected access and was never checked.
- both are packet pointers in the same trace.

Then a global monitor over "all registers" will see an establishment on `R3`, while the backward slice from the error on `R5` may not include that check.

The rule returns `lowering_artifact`.

The correct classification is `source_bug`: the programmer checked one pointer and dereferenced another.

This is the most serious problem with the current thesis. Existence of a proof somewhere else in the trace is not evidence of a lowering artifact. It may just be an unrelated proof.

#### Counterexample B: branch-local check, missing check on another path

Program sketch:

```c
if (cond) {
    if (data + 14 > data_end) return;
    p = data;
} else {
    p = data + ext_len;   // unchecked
}
use(p);
```

The verifier merge may contain evidence that the property was established on one path and unavailable on the other. A slice through the merged use can include the checked branch.

The rule can report `established_then_lost`.

The correct interpretation is a path-sensitive source bug: the proof was never established on all paths reaching the use.

This is a standard merge-point failure, not a lowering artifact.

#### Counterexample C: multiple safety conditions

For a load, the reject may depend on a conjunction:

- pointer type is valid
- pointer is non-null
- `off + size <= range`

Suppose bounds were established earlier, but nullability was never discharged. A monitor focusing on bounds may find establishments globally and in-slice.

The rule then moves toward `established_then_lost` or `lowering_artifact`.

The real problem is a missing null check.

This is why collapsing the reject site to one violated condition is dangerous. The current engine already does this in `find_violated_condition()` by picking the first violated condition or, failing that, the first condition at all (`interface/extractor/engine/opcode_safety.py:889-918`).

#### Counterexample D: loops with local checks and loop-carried widening

Inside a loop, each iteration may perform a local check, but the verifier may still widen the loop-carried state at the back-edge.

That can mean at least four very different things:

- real source bug
- verifier precision limit
- lowering artifact
- merely a conservative loop summary that needs a stronger invariant

The proposed rule collapses all of these into "established_then_lost" or "lowering_artifact", depending on whether a local check was observed somewhere.

That is not a sound classification.

#### Counterexample E: partial or vacuous traces

This is not hypothetical. The current codebase already records it.

`tests/test_batch_correctness.py:147-166` explicitly states that the canonical lowering-artifact case `stackoverflow-70750259` has:

- `failure_class == lowering_artifact`
- `proof_status == never_established`

because the trace first observes the relevant register after it is already bounded, so the establishment is treated as vacuous.

That directly breaks the thesis rule:

- thesis says `E_global = ∅ -> source_bug`
- current known-answer test says a real lowering artifact can still have `E_global = ∅`

So as a theorem, the rule is already falsified by the project's own regression test.

### Loops, branch merges, multiple safety conditions, partial traces

#### Loops

The plan needs a loop-aware definition of "establishment" and "loss".

For loops, a single linear trace is not enough. The trace contains:

- repeated local checks
- back-edge widening
- merge summaries

If you monitor naively, you will either:

- count many vacuous re-establishments, or
- call every back-edge widening a proof loss

The correct abstraction is closer to:

- monitor proof facts per SCC/back-edge summary, or
- distinguish intra-iteration checks from loop-summary facts

Without that, the loop-heavy examples will be unstable and the repair logic will overfit.

#### Branch merges

At a merge, "some path established the proof" is not enough.

You need at least:

- path coverage reasoning, or
- a dominance/post-dominance condition, or
- a join-aware notion of "this fact holds on all incoming states"

Otherwise the classifier will turn path-sensitive source bugs into fake proof-loss stories.

#### Multiple safety conditions

The plan currently treats safety condition inference as singular. That is too weak for real verifier failures.

You need an obligation vector or atom set, not one scalar condition:

- `pointer_type(base)`
- `non_null(base)`
- `bounds(base, size)`
- `arg_contract(Ri, role)`

Cross-analysis should operate over atom sets and preserve which atom actually failed.

#### Partial traces

The plan needs an explicit `unknown` or `truncated` outcome.

If the first observed state is already `gap = 0`, or if the relevant prehistory is not visible, the correct answer is not `source_bug`; it is "insufficient evidence to classify from lifecycle alone".

### Is the 3-way classification sufficient?

No.

At minimum, the taxonomy must separate:

- proof-obligation failures that are actually trace-localizable
- structural failures that are not

The project's own taxonomy already has:

- `source_bug`
- `lowering_artifact`
- `verifier_limit`
- `env_mismatch`
- `verifier_bug`

Cross-analysis should only run after structural filtering removes:

- `verifier_limit`
- `env_mismatch`
- `verifier_bug`

Even within proof-obligation failures, I would still want an `ambiguous` bucket.

Examples that do not fit the 3-way story cleanly:

- mixed path cases
- multi-obligation cases
- partial traces
- loop-summary precision collapse
- subprogram/inlining boundary losses

The current 3-way rule is too brittle for a full taxonomy.

### How "global monitoring on all registers" should actually work

As written, Step B is underspecified to the point of type error.

If the failing condition is:

- `R3.off + 1 <= R3.range`

what does it mean to "evaluate this on R5"?

Literal substitution is nonsense. The condition must first be generalized.

The right representation is not:

- "check whether `R3` satisfies this"

but:

- "check whether any compatible register instance satisfies `PacketBounds(size=1)`"

That means safety conditions must become register-parametric schemas with role constraints.

Examples:

- `PacketBounds(size=1, pointer_kind=pkt)`
- `ScalarBound(role=index_for_pointer_arith, upper=2^32-1)`
- `HelperArg(position=2, expected=mem, allow_null=false)`

Then global monitoring can instantiate the schema over candidate proof carriers:

- same pointer kind
- same provenance/alias class
- same role in the rejected instruction

It should not range over unrelated registers just because they exist in the state.

### What I would change

I would replace Step D with something closer to:

1. Filter structural classes first.
2. Infer an obligation as a set of atoms, each with roles.
3. Build candidate proof-carrier equivalence classes.
4. Monitor establishments and losses per atom, per carrier class.
5. Compute backward slice from the reject operands.
6. Classify only if there is a coherent temporal story:
   - `established_then_lost`: `exists establish_on_chain` and `exists later loss_on_chain`
   - `lowering_artifact`: no on-chain establishment, but equivalent off-chain establishment exists on a proof-compatible carrier
   - `source_bug`: no establishment on any proof-compatible carrier
   - otherwise `ambiguous`

That is still a heuristic, but it is a much more honest heuristic.

## 2. Four-Layer Architecture

### Is the layer separation clean?

Conceptually: mostly yes.

Implementation-wise: not yet.

The intended layering

- parse
- analyze
- present
- repair

is sensible.

The problem is that Layer 2 is still underspecified internally, so the clean layer boundaries hide unresolved circularities inside the analysis layer.

### Hidden dependencies inside Layer 2

The plan says B and C are independent.

In practice they are not fully independent.

#### Why C depends on A

For many reject instructions, A is needed to know which operand should seed the slice.

Example:

```text
r5 += r0
```

Which one is the "error register"?

- the pointer destination `R5`?
- the scalar source `R0`?
- both?

If Step C is seeded wrongly, the slice changes materially.

The current pipeline already reflects this. It chooses the slice criterion register from the inferred predicate first, then falls back to the first use/def of the error instruction (`interface/extractor/pipeline.py:155-175`).

So in the real system, A is already informing C.

#### Why B should depend on C, at least weakly

If B truly monitors "all compatible carriers globally", it still needs a candidate set. Otherwise it will fire on irrelevant proofs elsewhere in the trace.

The slice gives one principled way to limit candidate carriers:

- on-chain carriers
- near-chain alias carriers
- off-chain compatible carriers only if they are semantically comparable

That does not mean B must run after C, but it does mean the design should acknowledge shared seed selection.

### Step B is currently ill-typed

Layer 2 Step B says:

- "evaluate safety condition on every register" (`docs/research-plan.md:190-195`)

But safety conditions are currently represented as register-specific objects in code:

- `SafetyCondition.critical_register` is a single concrete register (`interface/extractor/engine/opcode_safety.py:82`)
- `OpcodeConditionPredicate.target_regs` contains exactly one register (`interface/extractor/engine/opcode_safety.py:843-846`)
- `TraceMonitor` stores one `establish_site` and one `loss_site`, not a per-register map (`interface/extractor/engine/monitor.py:24-37`, `interface/extractor/engine/monitor.py:75-143`)

So the current engine cannot even express the Step B design.

### Is the ordering A -> B -> C -> D correct?

Not exactly.

I would make it:

1. A: infer obligation schema and reject-operand roles
2. A': identify slice seeds and candidate proof carriers
3. B and C: run in parallel
4. D: cross-analyze

This is a small but important change.

The analysis is not:

- "infer condition, then independently monitor and slice"

It is:

- "infer condition and operand roles, then use those roles to seed both monitoring and slicing"

### Any circular dependencies?

Not fatal ones, but two are currently blurred:

#### Diagnosis <-> repair

Layer 4 uses diagnosis, then failed repair attempts feed back into re-diagnosis. That is fine, but it should be shown as an outer iterative loop, not as if the stack is purely acyclic.

#### Presentation leaking into repair

If repair instantiation depends on BTF source spans and rendered source locations, then part of Layer 3 becomes operational input to Layer 4. That is okay, but the document should say so explicitly.

### Layer 4 repair and the pilot case

This is where the plan is currently least believable.

The pilot case `stackoverflow-70760516` in `docs/tmp/repair-pilot-case-2026-03-18.md:243-424` is not repaired by a simple local clamp.

The verified repair does all of the following:

- introduces `MAX_EXTENSIONS`
- introduces `MAX_EXTENSION_BYTES`
- introduces a separate `cursor`
- changes the loop structure
- adds a cumulative/budget-style guard
- changes where packet advancement happens

That is a structural transformation, not "insert clamp/mask" and not "insert redundant bounds check at access site".

This directly conflicts with Layer 4 as written:

- `bounds gap -> insert clamp/mask`
- `lowering artifact -> insert redundant bounds check at access site`

Those are not the right templates for the pilot.

### Can template synthesis handle this?

Only if "template synthesis" means something much richer than the document currently suggests.

For the pilot, the template would need to support:

- new variable introduction
- loop skeleton replacement
- multi-location edits
- derived constants
- guards tied to cumulative growth

At that point you are not doing simple local template instantiation. You are doing transformation-based synthesis over structured control flow.

That is possible, but it is a much bigger claim.

### My recommendation on architecture

Keep the 4-layer structure, but narrow Layer 4 honestly:

- Phase 1 repairs:
  - clamp/mask
  - null-check insertion
  - redundant bounds-check insertion
  - `__always_inline`
  - expression reuse / replace dereference with checked pointer
- Phase 2 repairs:
  - loop rewrite templates
  - bounded-cursor conversion
  - multi-location structural rewrites

Do not pretend the pilot is covered by the current Phase 1 template story.

## 3. Novelty Assessment

### Is cross-analysis genuinely novel?

Weakly novel as a domain-specific composition.

Not strongly novel as a general analysis technique.

What is new:

- exploiting eBPF verifier `LOG_LEVEL2` traces as first-class analysis input
- combining obligation monitoring with a backward slice specifically to distinguish proof absence from proof disconnect
- focusing on lowering artifacts as a diagnosable class

What is not new:

- trace monitoring
- backward slicing
- single-trace fault localization
- generate-and-validate repair loops

So the novelty claim should be:

- "a useful composition over a new domain with a specific discriminative insight"

not:

- "a new general analysis paradigm"

### Comparison to BugAssist

BugAssist / "Cause Clue Clauses" localizes faults from failing traces by encoding them as a MAX-SAT problem and finding a small complement set of clauses/statements whose change removes the failure.

Compared to that, BPFix is:

- cheaper
- more lightweight
- deployable from existing verifier logs

but also:

- not minimal
- not solver-backed
- not provably precise

Reviewers who know BugAssist will not see "monitor x slice intersection" as conceptually deeper than MAX-SAT-based fault localization. They may still find it useful for eBPF.

### Comparison to SNIPER / Error Invariants

SNIPER-style work computes error invariants from counterexample traces via backward reasoning and interpolation.

That is closer in spirit to BPFix than the current plan acknowledges:

- both want an explanation of why the failure becomes inevitable
- both work backward from the failure

BPFix is much simpler:

- no interpolants
- no solver-backed invariants
- no formal model of the verifier transfer relation

So again, the honest novelty is domain specialization, not a stronger fault-localization algorithm.

### Comparison to spectrum-based fault localization

BPFix is different from SBFL, not strictly "more novel".

SBFL uses many passing/failing executions and ranks statements statistically.
BPFix uses one failing trace and a semantic obligation.

The good news for BPFix:

- single-trace operation is genuinely useful in this domain
- verifier logs are richer than test coverage

The bad news:

- reviewers will still correctly place this in the broader fault-localization family

### Comparison to delta debugging

BPFix is not doing delta debugging. It is closer to static trace interpretation over a single failure.

That said, a reviewer may ask why the system does not use verifier-oracle-guided reduction or minimization for hard cases. That is a fair question, especially if the repair story is centered on proof-shaping workarounds.

### Is ISA-driven safety condition inference really different from a lookup table?

Yes in engineering terms.
No in novelty terms.

Why it is better engineering:

- opcode/helper-signature dispatch is likely more stable than free-text error messages
- it aligns with the actual semantics of the rejected instruction

Why it is not a strong research contribution on its own:

- it is still a manually curated dispatch table
- it is not discovering obligations from first principles
- calling it "inference" overstates it

The plan itself already hints at this tension in `docs/research-plan.md:44-45`.

My advice:

- present ISA-driven obligation selection as a robustness choice
- do not sell it as a main novelty bullet

### Is the CEGAR-like repair loop comparable to GenProg, SemFix, Angelix?

Absolutely yes.

The proposed loop:

- diagnose
- synthesize repair
- compile/load
- if reject, analyze new trace and try again

is squarely in the same family as existing automated program repair:

- GenProg: search-based generate-and-validate
- SemFix: semantics-guided repair
- Angelix: scalable symbolic patch synthesis

The verifier oracle is a good domain-specific validation oracle, but the loop itself is not novel.

Also, it is not really CEGAR unless you refine an abstraction. Right now the loop refines candidate patches, not the verifier abstraction.

The honest description is:

- diagnosis-guided generate-and-validate with verifier-in-the-loop

not:

- CEGAR-like repair

## 4. Feasibility Concerns

### The pilot repair already contradicts the template story

The plan's flagship repair example is `stackoverflow-70760516`.

But:

- the ground truth file still labels it `source_bug` in `case_study/ground_truth_labels.yaml`
- the pilot write-up argues it is really a loop-carried proof-loss case
- the verified fix is a loop rewrite, not a local clamp

This is a warning sign, not a proof of readiness.

It shows:

- label noise in the key class
- taxonomic ambiguity in hard loop cases
- mismatch between diagnosis and repair mechanism

### How many lowering artifacts are there really?

From `case_study/ground_truth_labels.yaml`:

- total labeled `lowering_artifact`: 44
- total manual `lowering_artifact`: 6

After checking actual case files:

- `34` lowering-artifact cases have logs of at least 50 chars
- `27` have both usable logs and source
- only `5` manual-labeled lowering-artifact cases have both usable log and source

This is enough for exploratory diagnosis work.
It is not enough for a strong repair paper, especially when the important class is both small and noisy.

### The manual lowering-artifact set suggests structural repairs dominate

From `docs/tmp/manual-labeling-30cases.md:22-27`, the six manual-labeled lowering artifacts are:

- `github-aya-rs-aya-1062`: rewrite signed/unwrap lowering, maybe clamp-like
- `stackoverflow-70750259`: unsigned/clamp rewrite
- `stackoverflow-79530762`: reuse the checked pointer/value directly
- `stackoverflow-73088287`: loop rewrite so checked and accessed pointer stay identical
- `stackoverflow-74178703`: recompute and access through the same checked pointer inside the loop
- `stackoverflow-76160985`: `__always_inline` / keep proof in one function

That means:

- maybe `2/6` are truly local clamp-ish fixes
- `4/6` are structural or interprocedural proof-shaping fixes

So the likely hard cases are not local "insert check here" patches.

If the paper's repair story depends on template synthesis, the template catalog must target these structural patterns directly. Otherwise the highest-value class is exactly the class the repair system cannot cover.

### The current implementation does not support the proposed monitor

The answer to "does the current monitor already support global monitoring on all registers?" is: no.

The reasons are concrete:

- safety conditions are tied to one concrete register via `critical_register` (`interface/extractor/engine/opcode_safety.py:82`)
- the predicate adapter exposes exactly one target register (`interface/extractor/engine/opcode_safety.py:843-846`)
- `TraceMonitor` records one lifecycle, not per-register/per-carrier lifecycles (`interface/extractor/engine/monitor.py:24-37`, `interface/extractor/engine/monitor.py:75-143`)
- the pipeline picks one violated condition at the error site (`interface/extractor/pipeline.py:79-89`)
- taxonomy is derived before the backward slice is even computed (`interface/extractor/pipeline.py:98-111` versus `interface/extractor/pipeline.py:155-244`)

So Step D is not "partially implemented". It is structurally absent.

### What must change in code

At minimum:

1. Replace register-specific `SafetyCondition` usage with register-parametric obligation schemas.
2. Add candidate-carrier discovery:
   - compatible registers
   - stack slots
   - alias/provenance classes
   - possibly subprogram-carried carriers
3. Change `TraceMonitor` to return:
   - establishments per carrier
   - losses per carrier
   - temporal ordering across carriers
4. Compute the backward slice before classification, not after.
5. Use slice results in classification, not just as metadata.
6. Represent multiple proof atoms instead of collapsing to one condition.
7. Separate proof lifecycle from taxonomy classification.
8. Filter structural classes before cross-analysis.

### The current pipeline has another conceptual mismatch

`_derive_taxonomy_class()` in `interface/extractor/pipeline.py:288-313` effectively says:

- if there is an opcode/predicate path and `proof_status == established_then_lost`, return `lowering_artifact`
- otherwise return `source_bug`

That is a two-class collapse, not the five-class taxonomy in the plan.

So even the current code path is confirming the design problem: the system is trying to drive taxonomy from lifecycle alone.

## 5. What Is Missing From The Plan

### 1. An explicit scope restriction

The plan needs to say clearly:

- cross-analysis only applies to trace-localizable proof-obligation failures

and does not apply directly to:

- `env_mismatch`
- `verifier_limit`
- `verifier_bug`

Without that, the thesis reads as if one rule explains the full taxonomy.

### 2. A proof-carrier model

The plan talks about "all registers" as if register identity were the right abstraction.

It is not.

The right abstraction is proof carriers or proof-equivalence classes:

- register copies
- spill/fill restoration
- pointer/value aliases
- inlined vs non-inlined subprogram carriers

Without this, off-chain establishment versus on-chain loss cannot be defined properly.

### 3. A multi-atom obligation model

Real verifier failures often involve conjunctions of requirements.

The plan needs:

- atomized obligations
- per-atom monitoring
- per-atom explanation

Otherwise it will keep telling a bounds story for a nullability or type problem.

### 4. An ambiguity bucket

The current plan forces every proof-obligation case into one of three classes.

That is too aggressive.

You need at least:

- `ambiguous`
- `partial_trace`
- or `mixed`

for cases where the evidence does not support a clean lifecycle story.

### 5. A realistic repair grammar

The repair section is currently underpowered relative to the pilot and the manual labels.

If the real hard cases are:

- loop rewrites
- pointer-expression reuse
- `__always_inline`
- multi-location structural edits

then the repair grammar needs to say so.

Otherwise a reviewer will correctly conclude that the synthesis story is a placeholder.

### 6. A stronger evaluation plan for the key class

The important class is `lowering_artifact`, but:

- it is small
- labels are noisy
- kernel drift changes reproducibility
- the pilot case itself is taxonomically disputed

Before making strong claims, I would want:

- 50-100 manual labels total
- at least 20-30 manual lowering-artifact labels
- line- or span-level root-cause annotation for the key class
- repair-type annotations
- kernel-version sensitivity checks for pilot cases

### 7. A clearer separation of contributions

Right now the plan tends to bundle together:

- stable obligation selection
- cross-analysis classification
- rendering
- repair

These are not equally novel.

If forced to rank them:

1. diagnosis of lowering artifacts from verifier state traces
2. structured multi-span diagnostics over verifier logs
3. repair, if and only if the repair story becomes real
4. ISA-driven obligation selection as enabling infrastructure

### 8. Honest threat model for soundness

Top-venue reviewers will ask:

- What exactly is "sound" here?
- Sound for diagnosis?
- Sound for taxonomy?
- Sound only relative to the verifier's own abstract states?
- What if the trace is incomplete or path-merged?
- What if the program is genuinely unsafe on some paths and verifier-hostile on others?

The plan currently speaks in a way that sounds stronger than the actual epistemic position of the system.

The honest answer is:

- the system is analyzing the verifier's proof attempt, not the program semantics
- therefore it can explain verifier rejection mechanisms
- but it cannot, by itself, prove semantic correctness or even uniquely determine source-level blame in all cases

That is still useful. It is just not the same claim.

## What A Top-Venue Reviewer Will Probably Object To

1. The main classification rule is presented as if it were principled, but it ignores multiple obligations, merges, loops, and unrelated proofs on other registers.
2. "Global monitoring on all registers" is underdefined and currently not implementable in the actual engine representation.
3. The architecture implies a much stronger repair capability than the pilot and template design support.
4. The novelty claim overstates standard ingredients:
   - monitoring
   - slicing
   - lookup-table obligation selection
   - generate-and-validate repair
5. The key class is too small and too noisy for strong repair claims.
6. The current code does not match the current thesis.
7. The taxonomy and lifecycle notions are conflated.

## Recommended Direction

If the goal is to make this defensible, I would narrow and sharpen the claim:

- Scope the cross-analysis claim to proof-obligation failures only.
- Reframe it as a domain-specific diagnostic heuristic with strong empirical validation, not as a generally sound classifier.
- Implement proof-carrier-aware monitoring and slice-driven classification before paper claims are updated.
- Be honest that ISA-driven selection is an engineering choice, not a core novelty.
- Either:
  - cut the repair claim to local proof-preserving repairs only, or
  - invest in a real structural rewrite grammar and evaluate it honestly.

Right now the diagnosis story is promising.
The repair story is aspirational.
The paper should not pretend otherwise.
