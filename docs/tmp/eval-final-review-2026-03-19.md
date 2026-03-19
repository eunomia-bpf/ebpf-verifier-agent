# Final Comprehensive Review of the BPFix Eval Set

Date: 2026-03-19

## Bottom Line

This is materially better than the last review. The benchmark is now real: `case_study/ground_truth.yaml` has `138` labeled cases, `2` quarantined cases are excluded from headline metrics, and the three new evaluation scripts run successfully.

It is still not ATC/EuroSys-ready under the current claim stack. The taxonomy benchmark is close. The localization benchmark is a narrow pilot. The fix-type benchmark is heuristic. The repair benchmark still does not exist in a paper-grade sense.

## Key Numbers Sanity Check

- I ran `eval/comparison_report.py`, `eval/localization_eval.py`, and `eval/fix_type_eval.py`. All three ran successfully.
- `eval/comparison_report.py` reproduces `docs/tmp/comparison-report-2026-03-18.md` exactly.
- The requested key-number block is version-mixed. Some numbers come from the old `139`-case `docs/tmp/labeling-review/ground_truth_v3.yaml`, while others come from the current canonical `138`-case `case_study/ground_truth.yaml` with `2` quarantined cases removed.
- Historical `139`-case benchmark (`ground_truth_v3.yaml`): BPFix `109/139 = 78.4%`, Baseline `105/139 = 75.5%`, McNemar exact `p = 0.503`.
- Current canonical benchmark (`ground_truth.yaml`, non-quarantined `N=136`): BPFix `108/136 = 79.4%`, Baseline `105/136 = 77.2%`, McNemar exact `p = 0.648`.
- Current canonical stratified numbers do verify: external `28/51 = 54.9%` vs `30/51 = 58.8%`, selftest `80/85 = 94.1%` vs `75/85 = 88.2%`, macro-F1 `65.1%` vs `67.5%`.
- Localization numbers verify: `proof_lost` coverage `12/136 = 8.8%`; accuracy when present `8/12 = 66.7%` within `5` instructions.
- Fix-type numbers verify: overall `99/136 = 72.8%`; `lowering_artifact` `5/18 = 27.8%`.

The most important implication is simple: the benchmark needs to be frozen and the paper needs to stop mixing old and current numbers.

## A. What Has Improved Since Last Review?

1. There is now a real canonical benchmark file. `case_study/ground_truth.yaml` is much richer than the old label store: taxonomy, `error_id`, `fix_type`, `fix_direction`, instruction-level localization, confidence, evidence/boundary notes, and quarantine support are all present.
2. The comparison script now works and is reproducible. The earlier “script is broken” problem is fixed.
3. The benchmark is cleaner than before. Two clearly problematic cases are already quarantined from headline metrics: `stackoverflow-76441958` and `github-cilium-cilium-41522`.
4. There is now a machine-readable localization benchmark. `eval/localization_eval.py` runs end-to-end and produces a usable report instead of a placeholder claim.
5. There is now a machine-readable fix-type benchmark. `eval/fix_type_eval.py` runs and gives an auditable confusion matrix.
6. The reporting is more honest than before. The comparison report includes source-stratified results and macro-F1, which exposes the real story instead of hiding it behind one micro-average.
7. The benchmark provenance story is clearer. `ground_truth.yaml` metadata now states the labeling method, agreement, and confidence distribution.

## B. Remaining Problems Ranked by Severity

1. Mixed benchmark versions and mixed headline numbers.
What it is: the repo still mixes the old `139`-case benchmark with the new canonical `138`/`136`-case benchmark. The user’s requested key-number block itself mixes them. The default comparison report also embeds a historical section based on archived labels. It even repeats `Full Corpus` and `Core Set` with the same `136` cases, which adds confusion instead of clarity.
Why it matters for ATC/EuroSys: this is the fastest way to lose reviewer trust. If the same paper cites `78.4/75.5/p=0.503` in one place and `79.4/77.2/p=0.648` in another without a benchmark-version explanation, the artifact looks unstable.
Specific fix: freeze one submission benchmark, give it a version ID or content hash, regenerate every table from that benchmark only, and move all historical analyses into a separate appendix script. Remove the duplicate `Full` vs `Core` tables unless they actually differ.
Estimated effort: `0.5-1.5 days`.

2. The main headline is still selftest-dominated, and the external slice is not a win.
What it is: the current canonical benchmark is `85` kernel selftests and only `51` external cases. BPFix is `94.1%` on selftests but `54.9%` on external, where the baseline is better at `58.8%`.
Why it matters for ATC/EuroSys: reviewers will treat the external slice as the real-world result. The merged micro-average overstates practical performance and hides the most important failure mode.
Specific fix: make source-stratified reporting mandatory in the paper. Use the external real-world slice as the primary table or co-primary table. If one merged headline is still needed, build a smaller submission-core benchmark with no more than `50%` selftests.
Estimated effort: `1 day` for reporting changes, `2-3 days` if you also curate a new submission-core split.

3. The flagship `lowering_artifact` slice is still noisy, small, and not a BPFix win.
What it is: the current canonical set has only `18` non-quarantined `lowering_artifact` cases, all external. Five of them are explicitly `evidence_quality: weak`. BPFix recall is `16.7%` on the current canonical set, versus `33.3%` for the baseline. Fix-type match on this class is only `27.8%`.
Why it matters for ATC/EuroSys: this is the paper’s differentiator. If BPFix loses on the class that is supposed to justify cross-analysis, reviewers will not accept the mechanism claim.
Specific fix: split `lowering_artifact` into `submission-core` and `noisy-robustness`. Keep the `13` strong/medium-evidence cases in the main benchmark, move the `5` weak-evidence cases (`stackoverflow-53136145`, `stackoverflow-60506220`, `stackoverflow-72074115`, `stackoverflow-76637174`, `github-aya-rs-aya-1056`) to appendix/robustness tables, and stop claiming a validated cross-analysis win unless this class improves.
Estimated effort: `1-2 days` for benchmark curation and rerun, `5-10 days` if you want to add new hard cases instead of just tightening the benchmark.

4. The localization benchmark is still too narrow to support a general localization claim.
What it is: `proof_lost` coverage is only `12/136 = 8.8%`. There are only `18` nonzero-distance cases, and `16/18` are `lowering_artifact`. Current accuracy numbers are conditional on the rare cases where `proof_lost` is emitted.
Why it matters for ATC/EuroSys: this is not yet a paper-grade “root-cause localization benchmark.” It is a proof-loss localization pilot on a tiny, highly skewed subset.
Specific fix: rename the current metric to `proof-loss localization` in the paper. Build a dedicated earlier-root subset as the real localization benchmark: at minimum, all `17` earlier-root cases as a separate table, and preferably expand that to `25-30` cross-class cases before submission. Keep end-to-end coverage and conditional accuracy separate.
Estimated effort: `2-4 days` for a clean subset benchmark and paper rewrite, `5-7 days` if you expand the labels.

5. The fix-type benchmark is not independent enough, and it is not a repair benchmark.
What it is: `eval/fix_type_eval.py` classifies fix type from BPFix text plus `predicted_taxonomy`; for example, `env_mismatch` directly biases the output toward `env_fix`. The overall `72.8%` is also inflated by selftests: `89.4%` on selftests versus only `45.1%` on external cases.
Why it matters for ATC/EuroSys: reviewers will see this as rubric-matching, not evidence that BPFix produces repair-useful guidance. It is especially weak on the important class: `27.8%` on `lowering_artifact`.
Specific fix: remove taxonomy leakage from the mapper and rerun. Use only normalized repair action / hint text if this benchmark stays. Better yet, demote fix-type to appendix unless you can score against real patch deltas or executable repairs.
Estimated effort: `1-2 days` to de-leak and rerun, `5-10 days` to convert it into real repair evidence.

6. There is still no real repair benchmark.
What it is: there is no executable buggy/fixed benchmark with verifier or semantic oracles behind the logged cases. The current repair story is still a pilot, not a benchmark.
Why it matters for ATC/EuroSys: reviewers will not accept “improves repair” as a quantitative claim without real patches and real oracles.
Specific fix: either cut repair from the main quantitative claims now, or build a small executable repair subset with stored buggy code, target fix, and verifier/load oracle. Do not keep the current middle ground.
Estimated effort: `0.5 day` to cut the claim, `7-14 days` to build even a small credible repair benchmark.

## C. Noise in the Eval Set

Are there specific cases that should be removed or flagged?

- Keep `github-cilium-cilium-41522` and `stackoverflow-76441958` quarantined. That is the right call.
- Flag these non-quarantined `lowering_artifact` cases as noisy and keep them out of the paper’s headline tables: `stackoverflow-53136145`, `stackoverflow-60506220`, `stackoverflow-72074115`, `stackoverflow-76637174`, `github-aya-rs-aya-1056`. They are all `evidence_quality: weak` and `confidence: low`.
- Flag `stackoverflow-74178703` as a localization outlier. It is the only later-root case and should not be mixed into an “earlier-root proof-loss localization” story.

Is the selftest-dominated composition fixable without more data?

- Partly yes. You do not need more data to stop using the merged selftest-heavy micro-average as the main result. You can stratify now, or build a smaller submission-core benchmark by downsampling selftests.
- Partly no. You do need more external hard cases if you want a balanced five-class benchmark, especially if you want stronger `lowering_artifact` coverage or any real `verifier_bug` evaluation.

What is the minimum viable benchmark composition?

- Main taxonomy benchmark: `60-80` cases, deduplicated, non-quarantined, trace-rich, and no more than `50%` selftests.
- External slice: include all `51` current external non-quarantined cases if possible, or at least `30+` of them.
- `lowering_artifact` coverage: keep all `13` current strong/medium-evidence `lowering_artifact` cases in the main benchmark.
- Selftest slice: use `15-25` representative selftests as sanity cases, not `85` headline cases.
- Localization: separate earlier-root subset, not the whole taxonomy benchmark.
- Repair: separate executable subset, not this benchmark.
- Taxonomy scope: either add real `verifier_bug` cases or explicitly say the quantitative benchmark is four-class today.

## D. Honest ATC/EuroSys Readiness Assessment

1. Taxonomy benchmark: `NEEDS WORK`.
This is the closest to ready, but only after freezing one benchmark version, removing mixed historical/current numbers, and making source-stratified reporting primary. Also, the quantitative benchmark is still effectively four-class because `verifier_bug` has zero coverage.

2. Localization benchmark: `NOT READY`.
Useful pilot. Not yet a general localization benchmark.

3. Fix-type benchmark: `NOT READY`.
Interesting diagnostic appendix material, not venue-grade repair evidence.

4. Repair benchmark: `NOT READY`.
There is no benchmark here yet in the program-repair sense.

5. Overall eval section: `NOT READY`.
If the paper keeps its current claim stack around cross-analysis, localization, and repair, the evaluation section is not submission-ready. If you narrow the paper to taxonomy plus systems performance and demote repair, this could become `NEEDS WORK`.

## E. If I Could Only Do 3 Things Before Submission

1. Freeze the submission benchmark and rerun everything.
Create a versioned canonical benchmark file, regenerate all tables from it, and purge mixed old/current numbers from the paper and reports.

2. Rebuild the headline around the external real-world slice.
Make the external taxonomy table primary, cap selftests in the main benchmark, and move the five weak-evidence `lowering_artifact` cases to a robustness appendix.

3. Cut or sharply demote the claims that the current data does not close.
Keep taxonomy. Reframe localization as a limited proof-loss localization pilot. Move fix-type to appendix unless de-leaked. Drop repair as a main quantitative claim unless you build a real executable benchmark.

## F. What Claims CAN the Paper Make Right Now?

- BPFix now has a real, curated, LLM-assisted, expert-adjudicated trace-rich benchmark: `138` labeled cases in `ground_truth.yaml`, with `2` quarantined from main metrics.
- The current evaluation scripts for taxonomy, localization, and fix-type all run successfully and reproduce the checked-in reports.
- On the current canonical `136`-case non-quarantined benchmark, BPFix is competitive overall on coarse taxonomy classification, but it is not a clear overall win over the baseline: `79.4%` vs `77.2%`, while macro-F1 is worse (`65.1%` vs `67.5%`).
- On the older `139`-case benchmark still cited in earlier review docs, the corresponding numbers are `78.4%` vs `75.5%` with `p = 0.503`. If that number is kept anywhere, it must be labeled historical.
- BPFix is much stronger on kernel selftests than on external real-world cases: `94.1%` vs `54.9%`.
- BPFix does not currently outperform the baseline on the external slice.
- When BPFix emits a `proof_lost` span, that span is often near the labeled root cause (`8/12` within `5` instructions), but it emits such spans rarely (`12/136` cases). That supports a limited conditional claim, not a general localization claim.
- BPFix’s current repair hints align with coarse fix-type labels overall (`72.8%`), but this is not repair success and it is weak on `lowering_artifact` (`27.8%`).
- The current quantitative benchmark is effectively four-class. It does not evaluate `verifier_bug`.
- The current benchmark does not support claims that cross-analysis is validated, that BPFix improves repair, or that BPFix has a general root-cause localization benchmark.

## Final Verdict

This eval set is no longer the mess it was a week ago. The taxonomy benchmark is now real and close to usable. But the paper is still over-reaching relative to what the data actually supports.

If you want an honest ATC/EuroSys submission path, use this benchmark to support a careful taxonomy story, stratify aggressively, and stop pretending the current localization, fix-type, and repair numbers are closed.
