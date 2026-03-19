# BPFix Eval Readiness Review

Date: 2026-03-18

## Bottom Line

Overall verdict: `NOT READY` as a primary ATC/EuroSys evaluation benchmark in its current form.

The good news is that the infrastructure is real: there is a nontrivial logged corpus, the main batch driver works, the engine runs on all eligible cases, and latency is reasonable. The problem is not "no evaluation." The problem is that the current eval set mixes high-signal verifier traces with low-signal wrapper text, relies mostly on weak heuristic labels, has broken advertised rerun paths, and does not contain the machine-readable localization/fix annotations needed for strong diagnosis or repair claims.

If the paper is narrowed to descriptive claims about robustness, output richness, and a few carefully chosen case studies, the current artifact is usable. If the paper wants strong claims about diagnostic accuracy, root-cause localization, or downstream repair improvement, the eval story needs another round of benchmark engineering.

## Evidence Base

Primary repo artifacts read:

- `docs/research-plan.md` Section 5
- `docs/tmp/eval-infrastructure-audit-2026-03-18.md`
- `case_study/ground_truth_labels.yaml`
- `case_study/cases/stackoverflow/stackoverflow-70750259.yaml`
- `case_study/cases/stackoverflow/stackoverflow-70760516.yaml`
- `case_study/cases/kernel_selftests/kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda.yaml`
- `case_study/cases/github_issues/github-aya-rs-aya-1002.yaml`
- `eval/batch_diagnostic_eval.py`
- `eval/results/batch_diagnostic_results.json` summary/top section
- `Makefile` eval targets

Additional internal evidence consulted because the requested files point to them directly or because they are part of the de facto eval path:

- `docs/tmp/manual-labeling-30cases.md`
- `eval/results/root_cause_validation.json`
- `eval/results/span_coverage_results.json`
- `eval/results/pv_comparison_expanded.json`
- `eval/results/latency_benchmark_v3.json`
- `docs/tmp/repair-experiment-v5-results.md`

External comparison points:

- Rex (USENIX ATC 2025): https://www.usenix.org/system/files/atc25-jia.pdf
- Kgent (eBPF 2024): https://github.com/eunomia-bpf/KEN and DOI `10.1145/3672197.3673434`
- BugAssist / Cause Clue Clauses (PLDI 2011): https://bugassist.mpi-sws.org/MJPLDI11.pdf
- SemFix (ICSE 2013): https://www.comp.nus.edu.sg/~abhik/pdf/ICSE13-SEMFIX.pdf
- Angelix (ICSE 2016): https://discovery.ucl.ac.uk/id/eprint/10088929/1/icse16.pdf
- GenProg: original ICSE 2009 paper https://www.genetic-programming.org/hc2009/1-Forrest/Forrest-Paper-on-Patches.pdf and project summary https://squareslab.github.io/genprog-code/

## 1. Does the Eval Set Meet ATC/EuroSys Standards?

| Dimension | Rating | Review |
| --- | --- | --- |
| Corpus size (`302` scanned, `262` eligible) | `READY` | Numerically this is fine. `262` logged cases is already large by systems-paper standards. Size is not the bottleneck here. The bottleneck is signal quality and ground truth. |
| Corpus diversity (selftests vs SO vs GH; C vs Rust vs Go) | `NEEDS WORK` | Source diversity exists, but the benchmark is heavily skewed: `171/262` eligible cases are selftests and about `234/262` are C. Only about `20` eligible Rust cases and `8` Go cases appear. This is a useful spread, but not a balanced one. |
| Ground truth quality (`30` manual, `262` auto) | `NOT READY` | This is the main blocker. Only `30` cases are manually adjudicated. The machine-readable YAML labels are taxonomy-only. `225/255` labeled eligible cases are heuristic auto-labels. There are `7` eligible cases with no label at all. |
| Reproducibility (can a reviewer re-run?) | `NOT READY` | `make eval-batch` is runnable, but the advertised full path is not. `eval-language`, `eval-pv`, and `eval-all` fail because they hardcode missing `batch_diagnostic_results_v4.json`. The richer manual labels live in `docs/tmp/`, not in a versioned benchmark store. There is no frozen manifest. |
| Baselines (Pretty Verifier only) | `NOT READY` | Pretty Verifier is a reasonable existing-tool baseline, but one external baseline is not enough. The raw verifier log is the input, not a competitive automated baseline. The paper also needs a trivial message/regex baseline and at least one ablation or generic summarization baseline. |
| Statistical rigor (McNemar, CIs, effect sizes) | `NOT READY` | There is some McNemar support in repair scripts, but no consistent confidence intervals or effect sizes in the main eval pipeline. The current repair pilot is also not significant. |
| Experiment design (A/B repair, span coverage, latency) | `NEEDS WORK` | The ideas are good, but the current data support is uneven. Latency is clean. Span coverage is mostly `unknown`. Repair is still a pilot, and current results do not support a strong positive claim. |

Overall as an ATC/EuroSys evaluation section: `NOT READY`.

## 2. Noise Sources and Data Quality

### What is actually in the `262` eligible cases?

From the requested audit:

| Source | Eligible | Trace-rich | Partial trace | Message-only | No log |
| --- | ---: | ---: | ---: | ---: | ---: |
| kernel selftests | 171 | 169 | 0 | 2 | 29 |
| Stack Overflow | 65 | 39 | 13 | 14 | 10 |
| GitHub issues | 26 | 11 | 8 | 7 | 0 |
| Total | 262 | 219 | 21 | 23 | 39 |

Independent re-audit on the local corpus reproduced the same picture, with only a one-case boundary difference in a couple of categories.

The key fact is this:

- About `218-219 / 262` eligible cases are genuinely trace-rich.
- About `44 / 262` eligible cases are partial-trace or message-only.

So the corpus is not uniformly bad. But it is not a single clean benchmark either.

### How many cases are actually useful for evaluating the diagnostic engine?

This depends on the claim:

- For log compression / structured rendering robustness: about `218` trace-rich cases are useful.
- For taxonomy accuracy beyond surface-message parroting: only a much smaller subset is really strong. A conservative count is about `37` trace-rich cases whose labels are not directly derived from `msg_pattern`, `keyword`, or `log_msg`.
- For line-level localization: effectively `0` today. `root_cause_validation.json` reports `line_evaluable = 0`.

That is the central distinction the paper currently blurs. The corpus is large enough for descriptive pipeline evaluation. It is not yet large enough, in a cleanly labeled sense, for strong reasoning/localization claims.

### Kernel selftests: full traces or just `__msg()` strings?

Mostly full traces.

The selftest cases do include `expected_verifier_messages`, but that field is only side metadata. The actual `verifier_log` field is usually a full verbose trace. The sample selftest case `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` is exactly what you want in a systems paper: a real log with instruction states, function boundaries, processed-insn count, and source-line markers.

The problem with selftests is not lack of log detail. The problem is repetition:

- `130 / 171` eligible selftests fall into repeated terminal-message families.
- The largest families are things like `JIT does not support calling kfunc ...` (`20` cases), reference leaks (`13` cases), dynptr misuse families (`6-8` cases), IRQ restore families (`7` cases), and trusted-pointer null families (`7` cases).

So selftests are the best source for trace quality, but the worst source for benchmark redundancy.

### Stack Overflow: full logs vs partial logs vs error messages?

Not clean enough to be one bucket.

Using the audit numbers:

- `39` full trace-rich cases
- `13` partial-trace cases
- `14` message-only cases
- `10` no-log cases

So only about `60%` of eligible Stack Overflow cases are actually trace-rich. The rest are wrapper text, excerpts, or loader/runtime prose. Those are still useful as noisy real-world inputs, but they should not be pooled with selftests in a primary diagnosis-accuracy table.

### GitHub issues: same problem?

Yes, slightly worse in a different way.

Using the audit numbers:

- `11` full trace-rich cases
- `8` partial-trace cases
- `7` message-only cases

GitHub issue logs are often mixed with loader failures, permissions, kernel-version mismatches, or issue-comment prose. They are realistic, but they are weakly standardized and weakly labeled.

### Are there trivially easy cases?

Yes, many.

Examples from repeated terminal messages:

- `Possibly NULL pointer passed to trusted arg0`
- `Expected an initialized dynptr as arg #0`
- `expected an initialized iter_num as arg #0`
- `only read from bpf_array is supported`
- `BPF_EXIT instruction in main prog would lead to reference leak`

These are not useless for a product benchmark. They are useful for measuring compression, formatting, and user experience. But as a research benchmark for "diagnosis," they create a very high floor for shallow tools.

### Are there duplicates or near-duplicates?

There are no exact duplicate eligible logs in the current corpus, but there are clear near-duplicate families:

- `35` repeated tail-message clusters cover `152 / 262` eligible cases.
- A clear near-duplicate Stack Overflow pair exists: `stackoverflow-70750259` and `stackoverflow-70760516` have source-snippet similarity `0.869`.
- A clear duplicate GitHub source-snippet pair exists: `github-aya-rs-aya-1056` and `github-aya-rs-aya-1267`.

So the duplication problem is mostly semantic, not byte-for-byte.

### What is the noise floor?

High, if the metric is taxonomy against the current weak labels.

Among the `262` eligible cases:

- `145` labels come from `msg_pattern`
- `48` from `keyword`
- `17` from `log_msg`
- `15` from `log_pattern`
- `30` are manual
- `7` have no label

That means:

- At least `210 / 262` eligible cases have taxonomy labels derived directly from message patterns, keywords, or log-message snippets.
- If you also count `log_pattern`, the number rises to `225 / 262`.

So with the present label store, a shallow tool that extracts the surface verifier complaint can look much stronger than it really is. That is not the true "physics" of the problem. It is the current weakness of the ground truth.

## 3. Ground Truth Problems

### Is the `34.9%` taxonomy match engine error, label error, or both?

Both, but not equally.

Facts:

- Batch results vs eligible labeled cases: `89 / 255 = 34.9%`
- Batch results vs manual `30` cases: `12 / 30 = 40.0%`
- In `docs/tmp/manual-labeling-30cases.md`, the earlier heuristic classifier agrees with manual labels on `23 / 30 = 76.7%` with Cohen's kappa `0.652`

This suggests:

1. The current engine taxonomy is genuinely wrong on many manual cases.
2. The auto-labeling is also noisy, especially outside selftests.
3. The worst failure mode is boundary confusion between `source_bug` and `lowering_artifact`.

The dominant mismatch pattern in the current batch results is:

- gold `source_bug` -> predicted `lowering_artifact`

That appears in both manual and auto-labeled subsets. So this is not just bad labels.

### How reliable are `msg_pattern` / `keyword` / `log_msg` labels?

They are not equally reliable.

Breakdown of the auto-label sources:

- `selftest_auto`: `174 msg_pattern`, `15 log_pattern`
- `so_auto`: `49 keyword`, `9 log_msg`
- `gh_auto`: `7 keyword`, `8 log_msg`

My assessment:

- `msg_pattern` on selftests: often decent precision for narrow verifier-contract failures. But it bakes the surface verifier wording directly into the gold label.
- `log_pattern`: stronger than `keyword`, because it at least uses structural trace cues. Still weak compared with a human root-cause annotation.
- `keyword`: weak. Especially risky on SO/GH because it often fires on wrapper prose, accepted-answer hints, or environment text.
- `log_msg`: weak-to-medium. Better than pure keyword matching, but still mostly surface-message labeling.

In other words: the selftest auto labels are the least bad. The SO/GH auto labels are not a top-venue gold standard.

### Is `30` manual labels enough for a top venue?

No, not for a main quantitative claim.

At `n = 30`, a proportion near `50%` has a rough `95%` confidence half-width around `±18` percentage points. Even the observed `12/30 = 40%` manual-match rate still has a Wilson interval that is very wide. That is fine for a pilot or sanity check. It is not enough for:

- main accuracy claims
- per-taxonomy breakdowns
- per-source breakdowns
- significance against baselines

### The manual labels have taxonomy, rationale, and fix text. Is that enough?

Better than the YAML, but still not enough.

The manual markdown file is richer than the YAML. It has:

- taxonomy class
- error ID
- confidence
- localizability
- specificity
- rationale
- ground-truth fix text

What it still does not have in machine-readable form:

- root-cause instruction index
- rejected instruction index
- root-cause file and line
- fix file and line/range
- actual patch or fixed code
- compilability / verifier-pass oracle

That means the current manual labels support taxonomy-level qualitative discussion, but not line-level localization or repair benchmarking.

### What additional labels are needed?

Minimum machine-readable benchmark fields:

- `case_id`
- `source_bucket`
- `language`
- `log_quality` (`trace_rich`, `partial`, `message_only`)
- `duplicate_group_id`
- `label_provenance`
- `reviewer`
- `taxonomy_class`
- `error_id`
- `root_cause_insn`
- `rejected_insn`
- `root_cause_file`
- `root_cause_line`
- `fix_file`
- `fix_line_start`
- `fix_line_end`
- `fix_type`
- `fix_direction`
- `ground_truth_fix_text`
- `buggy_code`
- `fixed_code`
- `oracle_compiles`
- `oracle_verifier_passes`

Without at least some of those, the paper cannot cleanly separate taxonomy, localization, and repair.

## 4. What Experiments Should Be Run, and What Should Not Be Claimed?

### Claims that are defensible now

These are the claims I would keep:

- BPFix processes the current eligible logged corpus robustly (`262` eligible, `0` batch failures).
- BPFix produces richer structured output than raw logs and than Pretty Verifier in a descriptive sense: more spans, more source anchors, more causal-chain structure.
- BPFix is fast enough for interactive use on this machine: median latency is about `32 ms`, `p95` about `42 ms`.
- A small number of manually audited case studies show that nontrivial verifier failures can be explained more clearly than raw logs allow.

These are descriptive or qualitative claims. They do not require a perfect benchmark.

### Claims that should not be made now

These claims are not supported by the current evidence:

- "BPFix is accurate at diagnosing real-world verifier root causes at scale."
- "BPFix localizes the true root-cause line."
- "BPFix finds the fix location."
- "BPFix improves downstream repair."

The repair point is especially important. The current A/B repair pilot does not support a strong positive story:

- `56` selected cases
- v3 fix-type: A `1/56`, B `3/56`
- McNemar exact on paired fix-type: `p = 0.5000`
- verifier-pass does not improve

That is pilot evidence at best. It is not a headline experiment.

### Claims that need `50-100+` manual labels

- overall taxonomy accuracy
- macro-F1 or per-class recall
- per-source comparisons
- baseline superiority
- paired significance claims

If you want a serious benchmark table in the main paper, I would target:

- `60-80` manually labeled trace-rich cases as the minimum viable core set
- `100+` if you want per-taxonomy breakdowns that do not look fragile

### Claims that need root-cause line annotations

- root-cause line localization accuracy
- top-k source-line localization
- "proof_lost earlier than rejection" as validated accuracy rather than a descriptive property
- span coverage as a localization metric

Right now `root_cause_validation.json` reports:

- `262` evaluated
- `30` with `proof_lost`
- `27` with diff information
- `19` with BTF line info
- `0` line-evaluable cases

That is a complete stop sign for source-line claims.

### Claims that need compilable buggy+fixed code pairs

- repair pass rate
- fix-type accuracy against real repairs
- downstream A/B improvement
- verifier-pass improvement
- semantic patch quality

The current logged corpus is not the right benchmark for that. The `eval_commits/` corpus is closer, but it has no verifier logs. The logged corpus has logs, but rarely has compilable buggy/fixed code.

### Reviewer questions you currently cannot answer well

- What is the gold root-cause line?
- How many cases are truly nontrivial?
- How much of the gain survives on a manually audited subset?
- Does BPFix beat a trivial message-extraction baseline?
- Can a reviewer re-run the exact paper tables from a clean checkout?

## 5. Specific Recommendations

### Which cases should be removed from the primary eval set?

My recommendation is not to delete them from the repo. It is to split the benchmark into a primary core set and secondary noisy sets.

#### Remove from the primary diagnosis-accuracy benchmark: message-only eligible cases

These do not meaningfully test trace reasoning.

Conservative local audit list (`23` cases):

```text
kernel-selftest-exceptions-fail-reject-multiple-exception-cb-tc-fb35b800
stackoverflow-48267671
stackoverflow-56872436
stackoverflow-69192685
stackoverflow-70392721
stackoverflow-76035116
stackoverflow-76994829
stackoverflow-77462271
stackoverflow-77568308
stackoverflow-77713434
stackoverflow-78525670
stackoverflow-78591601
stackoverflow-78633443
stackoverflow-78753911
stackoverflow-79045875
github-aya-rs-aya-1104
github-aya-rs-aya-1324
github-aya-rs-aya-1490
github-aya-rs-aya-546
github-aya-rs-aya-808
github-aya-rs-aya-857
github-cilium-cilium-35182
github-cilium-cilium-44216
```

#### Move to a secondary "partial/noisy log" robustness set: partial-trace cases

These are useful for stress testing and product-quality robustness, but not for the main accuracy benchmark.

Representative cases include:

- `stackoverflow-47591176`
- `stackoverflow-53136145`
- `stackoverflow-60053570`
- `stackoverflow-70091221`
- `stackoverflow-74178703`
- `github-aya-rs-aya-1207`
- `github-aya-rs-aya-458`
- `github-aya-rs-aya-864`
- `github-cilium-cilium-41996`
- `github-facebookincubator-katran-149`

#### Deduplicate the selftest families for the core set

I would not use all `171` eligible selftests in the core accuracy benchmark. I would retain one or two representatives per normalized failure family, helper contract, or fix pattern, and keep the full selftest set only for robustness and latency.

#### Remove obvious near-duplicates from the core set

- Pick one of `stackoverflow-70750259` and `stackoverflow-70760516` for core taxonomy tables.
- Pick one of `github-aya-rs-aya-1056` and `github-aya-rs-aya-1267` if they map to the same fix pattern.

### How to improve ground truth

1. Move all labels into a versioned benchmark directory under `case_study/labels/`.
2. Create one machine-readable label file, not YAML plus markdown in `docs/tmp/`.
3. Expand to at least `60-80` manually adjudicated trace-rich cases.
4. Double-annotate at least `20-30` of those and report agreement.
5. Add line/insn/fix fields, not just taxonomy.

### How to make the eval reproducible

1. Add a canonical manifest, e.g. `case_study/eval_manifest.yaml`, with:
   - case ID
   - source bucket
   - language
   - log quality
   - duplicate group
   - which evals include the case
   - label version/hash
2. Fix `eval-language`, `eval-pv`, and therefore `eval-all`.
3. Record result provenance in every JSON:
   - git SHA
   - input manifest path/hash
   - kernel/toolchain version
   - script version
   - threshold settings
   - model version for LLM experiments
4. Add CI smoke checks for every advertised non-LLM target.

### Minimum viable eval for an ATC/EuroSys submission

I would recommend this minimum:

#### Track A: Core diagnostic benchmark

- `60-80` manually labeled, trace-rich, deduplicated cases
- baselines:
  - Pretty Verifier
  - trivial message/regex baseline
  - BPFix ablations
  - optionally one generic LLM summarizer
- metrics:
  - taxonomy accuracy / macro-F1
  - paired significance
  - confidence intervals

#### Track B: Full-corpus descriptive benchmark

- all trace-rich logged cases (`~218`)
- report:
  - coverage
  - latency
  - output structure
  - source breakdown

This is where the big corpus helps.

#### Track C: Repair / localization

Either:

- demote to pilot / case-study,

or

- build a separate executable benchmark with real buggy/fixed pairs and line annotations.

Trying to make the current logged corpus carry the repair story is the wrong tradeoff.

### Priority-ordered action items

`P0`

- Freeze a canonical eval manifest.
- Fix broken advertised targets.
- Split the corpus into `core_trace_rich`, `partial_noisy`, and `message_only`.
- Move manual labels out of `docs/tmp/` into machine-readable data.

`P1`

- Manually label `30-50` additional trace-rich cases.
- Double-annotate a subset and report agreement.
- Add a trivial message baseline and BPFix ablations.
- Add confidence intervals and paired significance to the main tables.
- Deduplicate the selftest families for the core accuracy set.

`P2`

- Build a proper repair benchmark from compilable buggy/fixed pairs.
- Only then revive strong repair claims.

## 6. Comparison with Other Systems / Repair Papers

### Rex (ATC 2025)

Your raw case count is larger than Rex's manually classified verifier-workaround commit set. But Rex's evaluation is cleaner for publication purposes:

- human-curated
- claim-aligned
- directly tied to source-level workaround commits

BPFix's problem is not lack of examples. It is lack of clean, adjudicated, claim-aligned labels.

### Pretty Verifier

Pretty Verifier is a useful existing-tool baseline, but it does not rescue the paper by itself. There is no published benchmark/eval section behind it that a reviewer can treat as external validation. It is fine as one baseline, not as the baseline story.

### Kgent (eBPF 2024)

Kgent is a different task: natural-language-to-eBPF synthesis. So it is not a direct competitor. But it does one benchmark thing better than BPFix right now:

- it defines a task-specific corpus and a correctness criterion clearly enough to report `80%` correctness and a `2.67x` improvement over GPT-4.

BPFix has more realistic verifier logs. Kgent has a cleaner evaluation contract.

### BugAssist (PLDI 2011)

BugAssist is much smaller, but methodologically cleaner for localization:

- `5` Siemens benchmark programs with injected faults
- TCAS evaluated in detail
- exact cause-localization objective

That is the classic tradeoff. Small benchmark, strong oracle. BPFix is currently taking the opposite tradeoff: large benchmark, weak oracle.

### SemFix

SemFix evaluated on:

- `90` SIR buggy versions
- `9` real Coreutils bugs

It had executable repair oracles and direct comparison against GenProg. That is a much stronger repair story than BPFix currently has.

### Angelix

Angelix reported:

- `28` repairs on large GenProg benchmark subjects
- real-world programs such as `wireshark` and `php`
- multi-location repairs
- a Heartbleed case study

Again, the benchmark is smaller and more curated, but the oracle is much stronger.

### GenProg

The original ICSE 2009 GenProg paper repaired:

- `10` C programs
- about `63 KLOC`

Later GenProg work reported systematic studies like `55 / 105` bugs repaired on large code bases. The headline point is not the exact number. The headline point is that the repair literature converged on executable benchmarks with test or developer-patch oracles.

That is the key gap for BPFix. Right now BPFix looks more like a large corpus collection than a frozen benchmark.

## Final Assessment

The current eval set is promising infrastructure, but not yet a publishable benchmark.

The strongest path to top-venue readiness is:

1. stop treating the entire `262`-case eligible set as one uniform benchmark,
2. create a trace-rich, manually adjudicated, deduplicated core set,
3. keep the full corpus for robustness and latency only,
4. demote repair until there is a proper executable repair benchmark.

If you do that, the corpus becomes an asset. If you do not, reviewers will correctly conclude that the benchmark is large but weakly supervised, and that the strongest claims outrun the evidence.
