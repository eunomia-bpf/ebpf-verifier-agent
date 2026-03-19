# BPFix Evaluation Gap Analysis

Date: 2026-03-19

## Bottom Line

BPFix is not ready for an OSDI/EuroSys submission if the paper keeps its current claims about cross-analysis diagnosis, root-cause localization, and repair improvement.

What is real today:

- There is a real logged corpus.
- The pipeline runs reliably and is fast.
- There is now a much better core taxonomy benchmark than the old heuristic label store.

What is still missing:

- A venue-grade ground truth story.
- A validated localization benchmark.
- A real repair benchmark with executable oracles.
- Evidence that cross-analysis materially helps.
- A single reproducible evaluation source of truth.

The harsh version is this: the infrastructure is no longer fake, but the evidence chain still breaks exactly where the paper wants to be strongest.

## What I Read

Repo artifacts:

- `docs/research-plan.md`
- `docs/tmp/labeling-review/ground_truth_v3.yaml`
- `docs/tmp/labeling-review/review_summary.md`
- `docs/tmp/labeling-review/agreement_analysis.md`
- `docs/tmp/eval-readiness-review-2026-03-18.md`
- `docs/tmp/eval-infrastructure-audit-2026-03-18.md`
- `docs/tmp/comparison-report-2026-03-18.md`
- `eval/results/ablation_results.json`
- `eval/results/baseline_results.json`
- `case_study/eval_manifest.yaml`

Additional repo files inspected because they are part of the actual eval path:

- `eval/comparison_report.py`
- `eval/ablation_eval.py`
- `eval/root_cause_validation.py`
- `eval/span_coverage_eval.py`
- `eval/repair_experiment_v3.py`
- `case_study/build_eval_manifest.py`
- `core/baseline/regex_diagnostic.py`
- `docs/tmp/labeling-a/labels.yaml`
- `docs/tmp/labeling-b/labels.yaml`
- `docs/tmp/labeling-review/adjudications.yaml`

External comparison points:

- Rex (USENIX ATC 2025): https://www.usenix.org/system/files/atc25-jia.pdf
- VEP (USENIX NSDI 2025): https://www.usenix.org/system/files/nsdi25-wu-xiwei.pdf
- GenProg (ICSE 2009): https://www.genetic-programming.org/hc2009/1-Forrest/Forrest-Paper-on-Patches.pdf
- SemFix (ICSE 2013): https://abhikrc.com/pdf/ICSE13-SEMFIX.pdf
- Angelix (ICSE 2016): https://www.jooyongyi.com/papers/ICSE16.pdf
- Coverity article (CACM 2010): https://www.cs.columbia.edu/~junfeng/19sp-e6121/papers/coverity.pdf
- Infer deployment writeup: https://engineering.fb.com/2017/09/06/android/finding-inter-procedural-bugs-at-scale-with-infer-static-analyzer/
- Infer deployment slides: https://files.sri.inf.ethz.ch/website/events/workshop2015/calcagno.pdf

## A. Ground Truth v3 Quality Assessment

### A1. Is 139 cases with kappa 0.737 enough?

Short answer: enough for a secondary core benchmark, not enough for the main evaluation backbone of an OSDI/EuroSys paper.

What is good:

- `ground_truth_v3.yaml` is much better than `ground_truth_labels.yaml`.
- All `139` cases are `eligible=true`, `log_quality=trace_rich`, and `eval_split=core`.
- The set is not tiny for a manually curated systems benchmark: `85` kernel selftests, `43` Stack Overflow, `11` GitHub issues.
- Overall agreement is respectable: `124/139 = 89.2%`, `kappa = 0.737`.
- On the `18` cases overlapping the earlier manual-30 set, taxonomy agreement is `18/18`.

What keeps it below top-venue grade:

- The two “independent” labelers are not humans. They are `codex-a` and `codex-b`.
- The file itself says “Independent LLM-labeled ground truth.”
- Only `17/139` final labels are adjudicated.
- Only `18` cases overlap the earlier manual-30 benchmark.
- The benchmark is class-skewed: `100 source_bug`, `20 lowering_artifact`, `15 env_mismatch`, `4 verifier_limit`, `0 verifier_bug`.
- Duplicate control is still incomplete. The v3 set still contains repeated selftest families, and the manifest’s representative logic only covers selftests.
- The file is still taxonomy-only. It has no localization or patch ground truth.
- The current scripts do not yet treat v3 as the canonical label source.

My judgment:

- If you present this as a curated, LLM-assisted, expert-adjudicated taxonomy benchmark for coarse classification, reviewers will accept that it is a serious step up from the old heuristic labels.
- If you present this as “ground truth” for main claims about root-cause diagnosis, localization, or repair, reviewers will attack it immediately.

### A2. Is the `lowering_artifact` agreement acceptable?

No, not for the class the paper most needs to win.

Facts:

- Per-class agreement for `lowering_artifact` is `8/20 = 40%`.
- `12/17` adjudicated cases are lowering artifacts.
- `11/20` final lowering-artifact cases are only `medium` confidence.
- `7/16` adjudication entries are marked `close_call`.

Interpretation:

- Overall kappa `0.737` is in the “respectable/substantial” range by normal annotation standards.
- But that headline is carried by easy, repetitive, high-agreement `source_bug` families.
- The paper’s key discriminative class is exactly where the rubric is unstable.

Compared to other SE/systems papers:

- Many good SE papers report overall agreement in the `0.6` to `0.8` band for manual taxonomies.
- But they usually do not hang the entire paper on the least stable class.
- A top-venue reviewer will tolerate noisy boundary classes if those classes are peripheral.
- They will not tolerate `40%` class-specific agreement on the paper’s flagship distinction without either:
  1. a tighter labeling rubric,
  2. more human adjudication,
  3. an explicit ambiguity bucket in the benchmark, or
  4. a reduction of claims.

The real problem is not the numeric `40%` by itself. The real problem is that `lowering_artifact` is the paper’s differentiator, and the current data says that even annotating it is hard.

### A3. Does template-like `root_cause_description` matter?

For taxonomy evaluation: not much.

For explanation-quality evaluation: yes, a lot.

Facts:

- `root_cause_description` is non-empty for all `139` cases.
- Only `72` descriptions are unique.
- The most common templates repeat `12`, `11`, `8`, `7`, and `5` times.
- `evidence_summary`, `fix_guidance`, and `rationale` are effectively blank in the exported v3 file.

Interpretation:

- If the metric is “did BPFix predict the right taxonomy class or error_id?”, templated descriptions are fine.
- If the metric is “did BPFix produce a good root-cause explanation?” or “does BPFix help an LLM repair better because the explanation is richer?”, template reuse becomes a problem.
- Reused text leaks class identity and inflates any future text-similarity or judge-based metric.

So:

- For current eval needs, template-like descriptions are not the main blocker.
- They become a blocker the moment the paper wants to score explanation quality or use text-based repair labels as if they were rich semantic targets.

### A4. What fields are still missing from v3?

These are the fields reviewers will ask for first:

- Provenance fields: `source`, `language`, `log_quality`, `eval_split`, `case_path` or `source_url`, kernel/program-type context.
- Annotation provenance: annotator type, adjudicator identity, `close_call`, alternate label, evidence snippet, and whether the final label is human-confirmed.
- Localization fields: `root_cause_insn_idx`, `rejected_insn_idx`, `root_cause_file`, `root_cause_line`, `rejected_file`, `rejected_line`, `root_cause_function`.
- Span fields: source span text or canonical span ranges for proof establishment, proof loss, and rejection.
- Repair fields: `fix_file`, `fix_lines`, `fixed_code`, `patch`, `oracle_status`, and whether the fix is compile/load validated.
- Evidence fields: a short machine-readable justification tied to log lines or source lines.
- Benchmark-control fields: `duplicate_group`, representative flag, difficulty tag.

Also missing at the dataset level:

- Any real `verifier_bug` coverage in the final core set.
- A preserved ambiguity signal. The adjudication file records `close_call`; `ground_truth_v3.yaml` does not.

## B. Evaluation Gap Analysis Against the Plan

I recomputed current numbers by joining `docs/tmp/labeling-review/ground_truth_v3.yaml` with `eval/results/ablation_results.json`.

### B1. Taxonomy classification accuracy

Can we measure it now?

- Yes, but only as coarse taxonomy accuracy on a curated trace-rich core subset.

Current evidence:

- BPFix on v3: `109/139 = 78.4%` with Wilson `95% CI 70.9% to 84.4%`.
- Regex baseline on v3: `105/139 = 75.5%` with Wilson `95% CI 67.8% to 81.9%`.
- McNemar exact p-value for BPFix vs baseline on v3: `p = 0.503`.
- On the same `139` cases under old v2 labels, the ranking flips:
  - v2 on same subset: BPFix `74.8%`, baseline `77.0%`
  - v3 on same subset: BPFix `78.4%`, baseline `75.5%`

What this means:

- Taxonomy accuracy is measurable.
- It is not yet stable enough to be the paper’s main selling point.
- The answer is label-version-sensitive.
- The gain over the shallow baseline is not statistically convincing.

The hardest class is still weak:

- BPFix `lowering_artifact` recall on v3: `4/20 = 20.0%` with Wilson `95% CI 8.1% to 41.6%`.
- Baseline `lowering_artifact` recall on v3: `6/20 = 30.0%` with Wilson `95% CI 14.5% to 51.9%`.
- On the `17` adjudicated hard cases, BPFix is only `6/17 = 35.3%`.

Conclusion:

- You can measure taxonomy classification now.
- You cannot claim strong confidence on the key class.
- You definitely cannot claim that cross-analysis classification is already validated.

### B2. Root-cause localization

Can we measure it now?

- No, not credibly.

Current evidence:

- `eval/results/root_cause_validation.json` reports:
  - `line_evaluable = 0`
  - `line_exact = 0`
  - `line_within5 = 0`
  - `line_within10 = 0`
- `eval/results/span_coverage_results.json` reports `152/263` `unknown` span-coverage cases on the older pipeline outputs.
- The script can count whether proof loss appears before the error instruction, but it cannot validate that location against benchmark truth.

Why not:

- v3 has no `root_cause_line`.
- v3 has no `root_cause_insn_idx`.
- v3 has no fix-line or patch-line annotation.
- The case corpus rarely contains explicit buggy/fixed code pairs for the logged cases.

Conclusion:

- The current infrastructure cannot support a localization-accuracy claim.
- At best it supports a qualitative case-study claim that some outputs point earlier than the final error line.

### B3. Repair improvement

Can we measure A/B repair now?

- Not as a paper-grade claim.

Current evidence:

- `repair_experiment_results_v3.json` covers `56` selected cases.
- Aggregate says Condition B beats A by `+7.1pp` on fix-type accuracy (`21.4% -> 28.6%`).
- McNemar exact p-value is `0.21875`.
- The selection target asked for `20` lowering artifacts but only `11` were actually available and selected.
- The selection summary says only `15/56` selected cases are trace-rich.

More serious problem:

- The stored per-case results do not contain oracle outputs.
- The stored per-case results do not contain serialized `semantic_correct` or `fix_tag_correct` flags.
- The aggregate section reports semantic and location accuracies, but the bundle is not rich enough to fully audit or reproduce them from stored per-case data.
- All `139` v3 cases have `no_fixed_code`.

What this means:

- Right now the repair experiment is a prompt-eval pilot, not a convincing repair benchmark.
- It is missing the two things repair reviewers care about most:
  1. executable correctness checks,
  2. canonical buggy/fixed targets.

Conclusion:

- You cannot claim “BPFix improves repair” in a top-venue paper based on current data.
- You can only claim “we ran an early A/B pilot suggesting the diagnostic may help.”

### B4. Cross-analysis value

Does the current data show cross-analysis helps?

- No.

Current evidence:

- On v3, `ablation_a` scores `81.3%`, above full BPFix at `78.4%`.
- On v3, the shallow regex baseline is still close at `75.5%`.
- `cross_class` is missing for `83/139` v3 cases.
- Only `1/139` v3 cases emits `cross_class = established_then_lost`.
- Only `6/262` full-corpus cases show any carrier establishment in `ablation_results.json`.

There are also logical inconsistencies in exported results:

- At least one case (`stackoverflow-70750259`) has `taxonomy = lowering_artifact`, `cross_class = established_then_lost`, and `proof_status = never_established`.
- More generally, exported fields are not yet coherent enough to serve as evidence for a precise mechanism claim.

Conclusion:

- The current data does not show that cross-analysis improves accuracy.
- The current data barely shows that cross-analysis runs at all on more than a small minority of cases.
- If this mechanism stays central in the paper, you need either better implementation evidence or a narrower claim.

### B5. Latency

Is latency sufficient?

- Yes, as a secondary metric.

Current evidence:

- `262/262` successes.
- Median `32.0 ms`.
- P95 `41.9 ms`.
- Max `82.7 ms`.
- Pearson correlation with log lines `r = 0.744`.

What is still missing:

- Rerun on the frozen submission version.
- A clean statement of hardware and environment in the paper.
- Optional memory footprint if you want a fuller systems story.

Conclusion:

- Latency is fine.
- It is not the bottleneck.
- It also will not save the paper if the correctness story stays weak.

## Claim-by-Claim Status

| Planned claim | Can current data support it? | Honest status |
| --- | --- | --- |
| Taxonomy classification accuracy | Partially | Measurable, but benchmark still label-fragile and weak on `lowering_artifact` |
| Root-cause localization | No | No machine-readable localization ground truth; current result says `line_evaluable = 0` |
| Repair improvement | No | Only a pilot prompt experiment; no strong oracle-backed evidence |
| Cross-analysis helps | No | Current ablations do not support this claim |
| Low latency | Yes | Strong enough as a supporting metric |

## C. What a Skeptical Reviewer Will Ask

1. Is this benchmark actually human-labeled?
Now: no. It is two Codex labelers plus adjudication.
Needed: dual-human annotation for the core set, or explicitly frame it as LLM-assisted labels with human adjudication and reduce claims accordingly.

2. Why should I trust the key `lowering_artifact` class if annotators only agree `40%` of the time on it?
Now: you cannot answer this convincingly.
Needed: tighter rubric, more human adjudication, more examples, and an ambiguity policy.

3. Why does the headline change depending on whether you use v2 or v3 labels?
Now: because the ground truth is still moving.
Needed: freeze one benchmark version and rerun every result off that exact version.

4. Does BPFix beat a trivial final-message baseline?
Now: only marginally overall, not significantly, and not on the key class.
Needed: stronger hard-case performance, especially on adjudicated lowering artifacts.

5. Where is the evidence that your cross-analysis mechanism is what causes the gains?
Now: there is none; one ablation is better than the full system.
Needed: corrected implementation, coherent exported fields, and an ablation win on the hard subset.

6. Where is the localization benchmark?
Now: nowhere. The current root-cause validation result literally has `line_evaluable = 0`.
Needed: root-cause source lines and instruction indices for a human-adjudicated core set.

7. Are the repair results real program repairs or just judged text outputs?
Now: mostly judged text outputs with heuristic aggregates.
Needed: compileable buggy/fixed pairs, verifier oracle, and preferably task-level or semantic checks.

8. Is the benchmark deduplicated?
Now: not really. `24` duplicate families still repeat within v3, and the manifest’s `core_representative` logic only applies to selftests.
Needed: actual dedupe for Stack Overflow and GitHub cases, especially for lowering artifacts.

9. Why does your five-class taxonomy have zero `verifier_bug` examples in the final core benchmark?
Now: it cannot be evaluated.
Needed: add real `verifier_bug` cases or treat that class as out-of-scope/open-set.

10. Are the results reproducible from the repository?
Now: not cleanly. Current comparisons still use `ground_truth_v2.yaml`, several scripts still depend on the old manual markdown, and the repair result bundle is not fully auditable from stored per-case fields.
Needed: one canonical benchmark file, one manifest, and result schemas that actually preserve the data needed to recompute tables.

## D. Specific Actionable Recommendations

## P0: Must do before submission

- Build one canonical benchmark file and make every eval script use it.
Effort: `1-2 days` infra work after the schema is decided.
Details: merge manifest metadata, v3 labels, adjudication provenance, and future localization fields into one versioned YAML or JSON.

- Stop calling v3 “ground truth” without qualification.
Effort: `0.5 day`.
Details: in the paper and artifact, call it “LLM-assisted, expert-adjudicated benchmark” unless you add dual-human labels.

- Expand the benchmark with human-adjudicated hard cases.
Effort: `5-10 days`.
Details: target `60-80` trace-rich cases with at least `25-30` lowering artifacts, plus a few real `verifier_limit`, `env_mismatch`, and `verifier_bug` cases.

- Add machine-readable localization annotations.
Effort: `4-7 days`.
Details: for every core case, record `root_cause_insn_idx`, `rejected_insn_idx`, `root_cause_line`, `rejected_line`, and fix span if known.

- Either make cross-analysis win on the hard subset or cut the claim.
Effort: `3-7 days` if fixing the implementation, `0.5 day` if cutting the claim.
Details: current exported evidence does not support the mechanism claim.

- Either build a real repair benchmark or remove repair as a main quantitative claim.
Effort: `7-14 days` to do it properly, `0.5 day` to cut the claim.
Details: you need compile/loadable buggy-fix pairs with verifier oracles. Right now you do not have that.

- Rerun all comparison numbers on the frozen benchmark.
Effort: `1 day`.
Details: taxonomy, ablations, baseline, latency, and any repair tables must be recomputed from the same benchmark version.

- Fix manifest dedupe beyond kernel selftests.
Effort: `1-2 days`.
Details: right now `core_representative` only applies to selftests because `build_eval_manifest.py` only groups selftests by duplicate family.

## P1: Should do, materially strengthens the paper

- Add a real external baseline beyond the trivial regex baseline.
Effort: `1-2 days`.
Details: Pretty Verifier is the obvious one if runnable; otherwise use a clearly defined message-only baseline and keep the regex baseline.

- Add per-source and per-language breakdowns on the final benchmark.
Effort: `0.5-1 day`.
Details: current v3 is `129 C`, `8 Rust`, `2 Go`; reviewers will ask about non-C generality.

- Add a small user-facing usefulness study or blinded diagnostic ranking.
Effort: `3-5 days`.
Details: if localization labels are expensive, a carefully designed usefulness study can help the presentation claim.

- Add cross-kernel spot checks on representative cases.
Effort: `3-5 days`.
Details: not a full matrix, just enough to show the tool is not tuned to one kernel build.

- Make result bundles self-auditing.
Effort: `1 day`.
Details: preserve per-case oracle outputs and judgment fields so aggregates are reproducible.

## P2: Nice to have

- Separate the benchmark into `core_accuracy` and `noisy_robustness`.
Effort: `0.5-1 day`.
Details: do not mix trace-rich diagnosable cases with partial or message-only cases in one headline table.

- Add memory and stage-level profiling to complement latency.
Effort: `0.5 day`.

- Expand or explicitly drop `verifier_bug` as a taxonomy class.
Effort: `1-3 days`.

## Hard Submission Advice

If time is short, the least bad path is:

- keep latency,
- keep coarse taxonomy,
- add a real localization benchmark,
- demote repair to a short pilot or future-work paragraph,
- and stop claiming that cross-analysis is already validated quantitatively.

If you cannot add localization annotations, I would not submit this to OSDI/EuroSys with the current framing.

## E. Comparison With Accepted Papers

### E1. Rex (USENIX ATC 2025)

Important correction:

- Rex ATC 2025 does not report “591 commits” as its paper benchmark.
- The paper manually analyzes `72` verifier-related commits.
- If `591` is your internal mined corpus, do not attribute that number to Rex.

What Rex does well:

- It ties claims to a clean evidence chain.
- It combines a qualitative workload analysis with an end-to-end system and macro/micro benchmarks.
- It has a concrete usability case study: Rex-BMC is `326` lines of Rust versus `513` lines of C for eBPF-BMC, and throughput is `1.98M` versus `1.92M` RPS.

How BPFix compares:

- BPFix has a larger raw failure corpus than Rex’s manual workaround study.
- But BPFix’s evaluation is much weaker in benchmark cleanliness and claim closure.
- Rex’s paper-level evidence is cleaner even with fewer examples because the measurement directly matches the claim.

### E2. Jia et al. or similar eBPF tool papers

The clean comparison here is VEP (USENIX NSDI 2025).

What VEP does well:

- It evaluates exactly the properties it claims: verification accuracy, time cost, and memory efficiency.
- It uses explicit baselines: Linux verifier and PREVAIL.
- It uses a small but clean benchmark: `41` programs across four categories.

How BPFix compares:

- BPFix has more real-world logged cases.
- But VEP’s evaluation is much cleaner because its benchmark is designed around directly measurable outcomes.
- Today BPFix is better on corpus size and realistic failure data, but worse on benchmark control and much worse on localization/repair validation.

Reviewer takeaway:

- A smaller clean benchmark beats a larger weakly grounded benchmark.
- Right now VEP’s style is closer to what OSDI/EuroSys reviewers expect.

### E3. Classic program repair papers

GenProg (ICSE 2009):

- Early benchmark by today’s standards, but it still produced actual executable patches on real C programs.
- The paper is explicit that passing tests is not the same as semantic correctness.

SemFix (ICSE 2013):

- Evaluates on `90` SIR buggy versions and real GNU/coreutils defects.
- Measures actual repair success and time against prior repair techniques.

Angelix (ICSE 2016):

- Evaluates on large real-world software, sizes up to `28,214` KLoC.
- Compares repairability and patch quality against GenProg, AE, and SPR.
- Produces actual patches, including multiline and multi-location repairs.

How BPFix compares:

- As a repair paper, BPFix is not close yet.
- It does not have a canonical executable repair benchmark.
- It does not have stored patches and oracles for the logged corpus.
- Its current repair result is a pilot prompt experiment, not a repair evaluation section.

Bluntly:

- If the submission keeps a main repair claim, reviewers will compare it to GenProg/SemFix/Angelix and reject it.
- The current repair evidence is below even the bar of older repair papers, because those papers at least measured real patches on executable benchmarks.

### E4. Static analysis tool papers

Coverity:

- Optimizes for large real code bases, low manual setup, and low false-positive rate.
- Explicitly says the goal is to check millions of lines of code and keep stable-checker false positives below `20%`.

Infer:

- Emphasizes source-level actionable traces, incremental analysis, and deployment at scale.
- Reports millions of lines of code, thousands of modifications per day, thousands of fixed interprocedural bugs, and sub-minute incremental reruns on changed code.

How BPFix compares:

- BPFix latency is already in the right ballpark for an interactive static-analysis-style tool.
- But it does not yet have static-analysis-style evidence of precision, fix rate, or source-level actionability.
- The missing localization benchmark is the biggest gap relative to this literature.

Bluntly:

- Coverity/Infer-style papers win by showing that the report points to the right place and is useful enough that developers fix things.
- BPFix currently shows speed and some structure, but not validated actionability.

## Concrete Conclusions

1. The new v3 benchmark is a real improvement, but it is not yet top-venue ground truth.
2. The benchmark is strongest for coarse taxonomy, weakest exactly where the paper most needs novelty: `lowering_artifact`, localization, and repair.
3. Current data does not show cross-analysis helps.
4. Current data does not support root-cause localization claims.
5. Current data does not support repair-improvement claims.
6. Latency is already fine.
7. The most important next step is not more model prompts or more case scraping. It is benchmark engineering.

## If You Want an Honest Submission Standard

Minimum bar before I would call this OSDI/EuroSys-submittable:

- one frozen canonical benchmark,
- human-adjudicated hard cases,
- machine-readable localization labels,
- either a real repair benchmark or no repair claim,
- and an ablation story where the claimed mechanism actually helps.

Without that, this is still closer to a strong artifact/prototype than to a top-venue evaluation section.
