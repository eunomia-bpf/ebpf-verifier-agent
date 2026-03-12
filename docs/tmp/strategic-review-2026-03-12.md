# Strategic Review (2026-03-12)

## Bottom Line

OBLIGE is no longer a toy parser. It now has a real, technically interesting proof-analysis core, a sizable corpus, a working multi-stage diagnostic pipeline, and enough evidence to support a focused paper. It is **not** ready for a broad ATC/EuroSys/ASPLOS submission under the current full-story framing.

The implementation is ahead of the evaluation. The strongest current paper is a narrower one: **trace-based diagnosis of verifier proof loss, especially lowering-artifact cases, with structured multi-span diagnostics**. The weakest current story is the broad “all verifier failures + LLM repair improvement” claim.

Note on evidence quality:

- I used live workspace counts when they conflict with older docs.
- The repo currently has evidence drift across reports: `44` vs `73` tests, `119` vs `120` one-span outputs, `100/263` vs `101/263` span coverage.
- `docs/research-plan.md` is truncated at the top in the committed version, which is itself a process/reproducibility smell.

## 1. Current State Summary

### What is built

- A full diagnostic pipeline exists in `interface/extractor/`:
  - `log_parser.py`: error-line and catalog seeding.
  - `trace_parser.py`: instruction/state parsing, transition detection, backtrack extraction.
  - `diagnoser.py`: coarse taxonomy/proof-status/root-cause selection.
  - `proof_analysis.py`: old heuristic lifecycle layer.
  - `proof_engine.py`: new formal obligation/predicate/transition/slice engine.
  - `source_correlator.py`: source/bytecode span correlation.
  - `renderer.py`: Rust-style text + JSON output.
  - `rust_diagnostic.py`: top-level orchestration.
- Corpus/data/eval infrastructure also exists:
  - `302` real cases in the main corpus.
  - `535` synthetic cases from `eval_commits`.
  - `776` total cases if you count both.
  - `241` logged cases are eligible for the main batch diagnostic eval.
  - `263` logged cases are used in span-coverage evaluation.
- Code size is substantial:
  - About `27.6K` physical LOC total across source, eval, collectors, taxonomy, schema, scripts, and tests.
  - About `25.6K` physical LOC excluding tests.
  - `interface/`: about `6.6K` LOC.
  - `eval/`: about `12.5K` LOC.
  - `case_study/`: about `5.1K` LOC.
- The core extractor is nontrivial:
  - `proof_engine.py`: `1829` LOC.
  - `trace_parser.py`: `1159` LOC.
  - `rust_diagnostic.py`: `1031` LOC.
  - `diagnoser.py`: `803` LOC.
- Tests:
  - Current live suite is `73` tests across `9` files.
  - `pytest -q` passes: `73 passed`.
  - The largest current test target is `tests/test_proof_engine.py` with `29` tests.
- Coverage:
  - There is **no statement/branch coverage setup** in the repo. No `pytest-cov`, no `.coveragerc`, no coverage artifacts.
  - Domain-specific coverage/eval metrics do exist:
    - Taxonomy coverage: `263/302` (`87.1%`).
    - Batch diagnostic robustness: `241/241` eligible cases succeeded, `0` crashes.
    - Source/BTF correlation: `151/241` (`62.7%`) in batch eval.
    - Proof-engine obligation coverage: `102/241` (`42.3%`) in standalone proof-engine eval.
    - Final surfaced obligation in integrated diagnostics: `169/241`, but that overstates the formal engine because many of those obligations are catalog/fallback surfaced rather than proof-engine-derived.
    - Span coverage: current artifact says `100/263` (`38.0%`) yes, `11` no, `152` unknown; manual subset `12/14` (`85.7%`).

### What works well

- The system is operational and stable. The batch pipeline runs end to end on `241/241` eligible logged cases with no crashes.
- The parser stack is materially beyond regex-on-headline tooling. It reconstructs instruction/state structure, backtracking chains, and source spans when the raw log supports them.
- The new `proof_engine.py` is a meaningful step up from the old heuristic `proof_analysis.py`:
  - It builds a `TraceIR`.
  - It infers formal obligations for supported families.
  - It evaluates predicate atoms over trace state.
  - It finds a transition witness.
  - It builds a bounded backward slice.
- On trace-sensitive cases, especially lowering artifacts, OBLIGE has real differentiation from Pretty Verifier:
  - Manual 30-case PV comparison reports `25/30` vs `19/30` overall.
  - Root-cause localization was `12/30` vs `0/30`.
  - The advantage is concentrated where the final verifier line is only a symptom.
- Source mapping works when the raw logs actually contain file/line annotations. The weak Stack Overflow rate is mostly a corpus problem, not evidence that the correlator is broken.
- Quality-fix work materially improved the old system:
  - `taxonomy_class=unknown` is down to `2` in the live batch artifact.
  - False `proof_status=satisfied` appears eliminated in current live results.

### What does not work yet

- The proof engine is still a minority path. Standalone obligation coverage is only `42.3%` (`102/241`), so most logged cases still do not get the full formal treatment.
- The paper story and the actual evaluation are misaligned:
  - The research plan says the core A/B experiment should measure verifier-passing repair.
  - The implemented A/B experiment does **not** do that. It scores textual fix-type proxies.
- Span localization is still weak at corpus scale:
  - Only `100/263` are marked covered.
  - `152/263` are still `unknown`.
- Helper-argument and protocol-heavy source-bug cases are underexplained. The generic `E023` path is especially weak and can actively mislead downstream repair.
- The final JSON contract is not clean:
  - `generate_diagnostic()` does not match `interface/schema/diagnostic.json`.
  - There is no single canonical machine-readable output.
- The pipeline still carries architectural debt:
  - duplicate parse work
  - repeated YAML loads
  - split “old vs new” proof paths
  - aggressive catalog override behavior
- Project evidence management is sloppier than it should be for a submission:
  - stale counts across docs
  - truncated master plan
  - outdated README structure

## 2. Novelty Assessment

### Is the proof engine now genuinely novel?

Blunt answer: **partially yes, but not yet at the level implied by the broad paper framing**.

- Before `proof_engine.py`, the novelty criticism in `novelty-gap-analysis.md` was fair. The old `proof_analysis.py` was mostly heuristic narration over parsed states.
- Now there is a real novel kernel:
  - obligation inference tied to the failing instruction
  - explicit predicate atoms
  - per-point predicate evaluation over verifier state
  - transition-witness detection
  - bounded backward slice from the violated atom
- That is substantially more defensible than “heuristic event labeling.”

But the reviewer-grade caveat is important:

- It is novel **for the obligation families it actually supports**.
- It is **not yet the dominant behavior of the whole system**.
- With `42.3%` obligation coverage, the current implementation does not justify a broad claim that “OBLIGE performs formal proof-trace analysis for eBPF verifier failures” in general.
- Do not hide behind “Pretty Verifier is unpublished.” Reviewers will treat it as real prior art anyway.

My honest verdict:

- **Novel prototype core**: yes.
- **Novel whole-system story across the corpus**: not yet.
- **ATC/EuroSys/ASPLOS-defensible as currently evaluated**: not yet.

### Defensible paper claims

- OBLIGE shows that existing `LOG_LEVEL2` verifier traces contain enough information to build structured, multi-span diagnostics in userspace, without kernel patches.
- For supported failure families, OBLIGE performs obligation-tracked proof-trace analysis over verifier state traces rather than only matching the final rejection line.
- OBLIGE can identify earlier proof-establish / proof-loss / reject sites and convert them into Rust-style labeled spans.
- On trace-sensitive cases, especially lowering artifacts, OBLIGE provides better root-cause localization than line-oriented prior tooling such as Pretty Verifier.
- Structured diagnostics appear promising as machine-consumable repair input, but the current evidence supports this only as a **class-conditional, preliminary** finding.

### Claims that are still overstated

- “Backward slicing on verifier traces” as a general system claim.
  - The new slice is better, but still bounded, approximate, and path-insensitive.
- “Proof obligation inference from the verifier type system” across the whole verifier space.
  - Current support is still a subset, not a full verifier-semantic model.
- “General multi-span diagnosis for verifier failures.”
  - Many cases are correctly one-span; many others remain unsupported or under-specified.
- “OBLIGE improves repair.”
  - Current A/B does not show overall improvement and does not measure actual verifier success.

### What OBLIGE does that Pretty Verifier, Rex, and Kgent do not

Against Pretty Verifier:

- Pretty Verifier is line-oriented and handler/regex driven on the final error line, with optional object-file-based source mapping.
- OBLIGE parses the full verifier state trace, extracts earlier proof-relevant transitions, and emits structured multi-span diagnostics plus JSON.
- The strongest concrete delta is not “nicer wording”; it is recovering an earlier proof-loss/root-cause site when the rejection line is only a symptom.

Against Rex:

- Rex studies verifier workaround commits and argues the language-verifier gap; it does not diagnose arbitrary verifier failures in existing codebases.
- OBLIGE’s distinct contribution is diagnostic infrastructure for existing eBPF workflows, not a new verifier-friendly language.
- The clean positioning is: **Rex explains why these failures exist; OBLIGE explains an individual failure instance**.

Against Kgent:

- Kgent uses raw verifier output as prompt feedback inside an LLM loop.
- OBLIGE changes the feedback substrate itself by producing structured, source-linked, machine-consumable diagnostics.
- The clean positioning is: **Kgent is a consumer of verifier feedback; OBLIGE is a producer of richer verifier feedback**.

## 3. Evaluation Gaps

### What is complete and what it shows

- Batch diagnostic robustness:
  - `241/241` eligible logged cases succeed.
  - This shows the system is stable enough to evaluate.
- PV comparison on the manual 30-case set:
  - OBLIGE beats Pretty Verifier overall and clearly on lowering artifacts/root-cause localization.
  - This is still one of the best current pieces of evidence.
- Span coverage evaluation:
  - Manual subset is encouraging (`12/14`).
  - Corpus-wide coverage is weak (`100/263`) and dominated by `unknown`.
  - This tells you the localization story is promising but not yet broadly validated.
- Output-quality analysis:
  - Many one-span outputs are legitimate, not a renderer bug.
  - This is useful because it prevents chasing a fake KPI.
- Proof-engine standalone batch eval:
  - No crashes.
  - More conservative than the old diagnoser.
  - Correctness seems improved on some audited cases.
  - Coverage remains the main limiter.
- A/B repair v1:
  - Overall fix-type accuracy is flat at `10/30`.
  - Lowering artifact improves from `0/8` to `2/8`.
  - Source-bug regresses from `9/13` to `6/13`.
  - This is suggestive, not persuasive.

### What is missing for a publishable paper

- An updated evaluation on the **current** proof-engine-integrated system.
  - Right now the A/B result is effectively stale because the model outputs were cached from the old prompts.
- A real evaluation of the new engine’s core claim:
  - proof-loss localization quality
  - obligation correctness
  - slice usefulness
  - source/root-cause span accuracy
- A rigorous comparison against Pretty Verifier on the current integrated output, not just older pipeline snapshots.
- A proper “does this help repair?” study that measures something real:
  - verifier-pass rate
  - or at minimum human-judged patch correctness on executable cases
- A reviewer-proof explanation of the `unknown` bucket and corpus limits.
- At least a small latency/overhead number.

### Is the A/B experiment design sound?

As a pilot: yes. As paper-grade evidence: **no**.

Main reviewer criticisms:

- `n=30` is too small for the claim weight being placed on it.
- The main result is null (`10/30` vs `10/30`, McNemar `p=1.0`).
- The experiment does **not** measure actual repair success. It scores fix-type tags, target location heuristics, and token-overlap “semantic similarity.”
- It mixes taxonomies even though the strongest hypothesized benefit is specifically lowering artifacts.
- It uses one small model family (`gpt-4.1-mini` / `nano` fallback), so reviewers can dismiss results as model-specific noise.
- The current result bundle uses cached responses from before the new proof engine was integrated.
- The prompts sometimes include noisy or answer-rich source context from Stack Overflow/GitHub artifacts, which can swamp or confound the diagnostic effect.
- Fix-type scoring is regex/tag based and sometimes brittle. At least two apparent source-bug “regressions” (`stackoverflow-70091221`, `stackoverflow-79045875`) look partly like normalization artifacts rather than clean semantic failures.

In short: this is useful internal guidance, but not strong evidence for a systems paper.

### Do you need more cases, different metrics, or expert evaluation?

Yes.

- More cases:
  - especially more trace-rich lowering-artifact cases
  - and a cleaner manually curated subset where the ground-truth fix is actually localizable
- Different metrics:
  - actual verifier pass rate on an executable subset
  - root-cause span precision/recall on a gold-labeled set
  - obligation correctness by family
  - proof-status correctness by family
- Expert evaluation:
  - yes, probably necessary
  - at least a small expert/manual assessment of whether the spans and explanation are sufficient and non-misleading

If you want one evaluation that most improves reviewer confidence, it is this:

- a gold-labeled, trace-rich subset
- current proof engine active
- PV vs raw log vs OBLIGE
- root-cause localization + fix-type guidance + explanation sufficiency

## 4. Technical Debt

### Most critical bugs and limitations

- Proof-engine coverage is still too low.
  - `102/241` standalone obligation coverage is not enough for a broad paper claim.
- The diagnoser still over-overrides.
  - `109` catalog-seeded cases are overridden, often from source-bug IDs to lowering-artifact IDs.
  - This is a major correctness risk.
- The generic `E023` / helper-arg path is too weak.
  - It often reduces specific contract failures to bland “re-derive the pointer/reference” advice.
- There is no single stable JSON contract.
  - This is bad engineering and bad paper hygiene.
- The repo has evidence drift.
  - Reviewers will notice when numbers change across tables and reports.
- The master research plan being committed in a truncated state is a warning sign about process discipline.

### Obligation coverage is 42%. Is that enough?

No.

For a paper whose novelty centers on obligation-tracked proof analysis, `42.3%` means the formal engine is still too often absent from the actual diagnosis.

For a paper with a narrower claim like “we support these failure families well,” it could be acceptable, but then the paper must be explicit that it is a subset result, not a general verifier-failure framework.

### Path to 60%+

`60%` of `241` is about `145` cases, so you need roughly `+43` more covered cases.

The fastest path is not “support everything.” It is targeting the biggest uncovered buckets:

- `117` currently fail with `proof obligation could not be inferred`.
- `22` currently fail because the failing instruction could not be identified.
- Missing cases are concentrated in:
  - Stack Overflow: `38`
  - kernel dynptr cases: `33`
  - kernel IRQ protocol cases: `18`
  - Aya/GitHub helper/context cases: `17`

That suggests the fastest path is:

- improve failing-instruction identification on abbreviated/wrapped logs
- add dynptr lifecycle/protocol obligations
- add IRQ/iterator/reference-protocol obligations
- improve helper/kfunc argument typing beyond the current generic helper path
- better subprogram/caller-context handling

That is a credible route to `60%+`. Broadening packet/map/null alone probably is not.

### The 3 source_bug regressions in A/B: root cause

The three A-only wins that B turned into losses are:

- `stackoverflow-61945212`
- `stackoverflow-70091221`
- `stackoverflow-79045875`

All three are source-bug/helper-contract style cases, and all three got generic `E023`-like OBLIGE messaging.

What happened:

- `stackoverflow-61945212` looks like a real OBLIGE-induced regression: Condition A already had enough raw-log/source context to infer the queue-map API fix, while Condition B's generic reject-only `E023` framing pushed the model toward the wrong abstraction.
- `stackoverflow-70091221` and `stackoverflow-79045875` are weaker evidence of true regression. In both cases, the B summaries are semantically close to the right source-bug family, but the experiment's fix-tag normalizer scored them as `other_refactor`.
- So the honest answer is mixed: part diagnostic under-specificity, part evaluator brittleness.

Case-specific pattern:

- `61945212`: raw context pointed to the queue-map API issue; OBLIGE nudged the model toward a map declaration fix.
- `70091221`: raw log exposed `map_value expected=map_ptr`; OBLIGE’s generic helper-arg note did not sharpen the answer, and the scorer likely under-credited a semantically similar map-declaration response.
- `79045875`: the real issue is a stricter kfunc/type contract; OBLIGE’s reject-only generic advice did not help, and the scorer likely under-credited a semantically close pointer-type fix.

So the root cause is **under-specific helper/source-bug diagnostics plus brittle fix-type scoring**, not “source_bug is inherently bad for OBLIGE.”

### Path-insensitive backward slicing: does it matter?

Yes, but not equally for every claim.

- It matters a lot if the paper claims precise slicing/root-cause localization across loops, subprograms, aliasing, helper boundaries, and protocol-heavy traces.
- It matters less if the slice is framed as an explanatory aid after the main predicate/transition detection.

My reviewer view:

- The **transition witness** is the important core.
- The **slice can remain approximate** if you say so explicitly and validate it empirically on a gold set.
- If you keep claiming “precise backward slicing,” path-insensitivity will get attacked.

## 5. Recommended Next Steps (Prioritized)

### 1. Narrow the paper scope now

Effort: `1-2 days`

- Reframe the paper around **trace-rich proof-loss diagnosis**, with lowering artifacts as the headline case.
- Stop leading with “all verifier failures” and stop making LLM repair the center of the paper.

Why this is first:

- It immediately removes the biggest overclaiming risk.
- It makes every subsequent engineering/eval decision sharper.

### 2. Build a paper-grade evaluation on the current engine

Effort: `4-7 days`

- Freeze a curated gold subset of trace-rich cases.
- Re-evaluate raw log vs Pretty Verifier vs current OBLIGE.
- Measure root-cause span accuracy, fix-type guidance accuracy, and explanation sufficiency.

Why this matters:

- This is the single biggest improvement in reviewer perception.
- Right now the implementation is stronger than the evidence.

### 3. Fix the weak source-bug/helper-arg story before rerunning any repair study

Effort: `3-5 days`

- Audit the `E023` / helper-arg path.
- Fix the 3 source-bug A/B regressions explicitly.
- Reduce generic “re-derive pointer/reference” messaging when the raw log already names a specific contract mismatch.

Why:

- This is the most obvious current “OBLIGE can mislead” failure mode.

### 4. Raise proof-engine coverage to at least 60% on the logged corpus

Effort: `1-2 weeks`

- Prioritize dynptr, IRQ/iterator, and helper/kfunc argument families.
- Improve failing-instruction identification and subprogram handling.

Why:

- Without this, the formal engine remains too narrow for the thesis being sold.

### 5. Decide whether to fix the A/B experiment or demote it

Effort:

- `2-4 days` to demote/reframe it honestly.
- `1-2 weeks+` to turn it into a real executable repair evaluation.

Recommendation:

- Fastest path to submission is to **demote it to secondary evidence** unless you can build a real verifier-pass subset quickly.

### 6. Clean up engineering/process debt that affects credibility

Effort: `2-3 days`

- unify JSON contract
- regenerate stale metrics
- fix the truncated research plan
- pin the artifact snapshot used for the paper

Why:

- These are not glamorous, but they prevent self-inflicted reviewer distrust.

### What can be cut without hurting the paper

- Cross-kernel stability as a main experiment.
- Synthetic compilation/repair from diff-only snippets.
- Broad all-taxonomy coverage as a first submission target.
- The older `interface/api` / `BTFMapper` path as part of the paper story.
- Any claim that the paper’s main contribution is the LLM repair loop.

### What would make the biggest difference in reviewer perception

- A tighter claim.
- A current, consistent evaluation on the current engine.
- One or two undeniable motivating cases where OBLIGE finds a root cause the headline-line tools miss.
- Fewer broad claims, more sharply validated subset claims.

## 6. Paper Readiness Assessment

### Readiness score

`4/10`

Reason:

- There is enough real system and enough promising evidence that this is not “start over.”
- But the broad submission story is still under-evaluated, partially fallback-driven, and vulnerable to “overclaimed heuristic system” criticism.

### Minimum viable paper

A viable paper today is:

- focused on trace-rich verifier failures
- centered on proof-loss/root-cause diagnosis
- explicit that the formal proof engine supports a subset of obligation families
- compared directly against raw logs and Pretty Verifier
- validated on a curated, manually checked gold set
- with LLM/repair as a secondary “downstream usefulness” section, not the main proof

I would especially bias toward:

- lowering artifacts
- packet/map/helper-style trace-rich failures
- source-vs-lowering differential diagnosis

### What would make it a strong paper

- `60%+` proof-engine coverage on eligible logged cases, with the remaining unsupported space clearly characterized.
- A clean and current evaluation showing that the new engine improves localization correctness, not just status distributions.
- A rigorous comparison against Pretty Verifier on the current pipeline.
- Either:
  - a credible executable repair study with verifier-pass outcomes, or
  - a strong expert/manual evaluation of diagnostic usefulness.
- Fully consistent artifacts, tables, and claims.

### Final reviewer-style verdict

If submitted now as “a general, novel proof-analysis framework for eBPF verifier failures that improves repair,” I would lean reject.

If narrowed, cleaned up, and re-evaluated around the current proof-engine core and the classes where OBLIGE is genuinely better than headline-line tools, this can become a credible systems paper.
