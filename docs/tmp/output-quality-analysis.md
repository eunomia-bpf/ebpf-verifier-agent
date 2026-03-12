# OBLIGE Output Quality Analysis

Batch analyzed: `eval/results/batch_diagnostic_results.json`

Eligible cases: 241  
Successes: 241  
Crashes: 0

## Executive Summary

The headline quality problem is not missing 3-span stories for `established_then_lost`. That path is currently consistent: all 97 `established_then_lost` cases already contain `proof_established`, `proof_lost`, and `rejected` spans.

The main correctable issues are:

1. `taxonomy_class=unknown` is mostly a catalog/error-line-selection problem, not a trace problem.
2. `proof_status=unknown` is mostly a zero-trace input problem.
3. The 3 `proof_status=satisfied` results are incorrect and come from zero-trace rejection logs.
4. Stack Overflow BTF correlation is primarily a corpus/input issue: almost all SO logs simply do not contain `@ file:line` annotations.

The 119 single-span cases are mostly legitimate rejected-only outputs:

- 95/119 are `never_established`
- 21/119 are `unknown`
- 3/119 are `satisfied`
- 0/119 are `established_then_lost`

So the single-span rate should not be treated as a primary KPI by itself. Most of it is the expected shape for `never_established`.

## 1. Single-Span Cases

### Distribution

Proof-status distribution for the 119 single-span cases:

| proof_status | count |
| --- | ---: |
| `never_established` | 95 |
| `unknown` | 21 |
| `satisfied` | 3 |

Taxonomy distribution for the 119 single-span cases:

| taxonomy_class | count |
| --- | ---: |
| `source_bug` | 73 |
| `env_mismatch` | 14 |
| `unknown` | 13 |
| `lowering_artifact` | 9 |
| `verifier_limit` | 9 |
| `verifier_bug` | 1 |

### Key findings

- None of the 119 single-span cases are `established_then_lost`.
- All 119 single-span cases are rejected-only outputs at the role level: every one has `rejected`, and none have `proof_established` or `proof_lost`.
- 95/119 single-span cases still have a parsed instruction trace. Those are mostly legitimate single-span outputs.
- 24/119 single-span cases have zero parsed instructions:
  - 21 are `proof_status=unknown`
  - 3 are the incorrect `proof_status=satisfied`
- Among `never_established`, the engine is behaving consistently:
  - 95 cases have 1 span
  - 12 cases have 2 spans
  - all 107 contain `rejected`
  - none contain `proof_established` or `proof_lost`
- The 12 two-span `never_established` cases are `rejected + proof_propagated`; that extra context is already being added when a causal chain is recoverable.

This matches the current implementation:

- [`interface/extractor/diagnoser.py`](../../interface/extractor/diagnoser.py) `_assess_proof(...)` defaults to `never_established` whenever a trace exists but no earlier proof signal or loss transition is found.
- [`interface/extractor/rust_diagnostic.py`](../../interface/extractor/rust_diagnostic.py) `_synthesize_proof_events(...)` only adds `proof_propagated` for `never_established` when `parsed_trace.causal_chain` is present.

### Sample of 10 single-span cases

I read the raw YAML verifier logs for the following 10 representative single-span cases.

| case_id | source | raw-log shape | assessment |
| --- | --- | --- | --- |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type` | selftests | Full verbose trace, BTF `@ dynptr_fail.c:1735`, explicit helper-arg failure | Legitimate single rejected span. Log is good; no missing span bug. |
| `kernel-selftest-dynptr-fail-skb-invalid-ctx` | selftests | Full verbose trace, BTF, 4 instructions, explicit `calling kernel function ... is not allowed` | Legitimate single rejected span. This is an env/helper-context failure, not a span-loss issue. |
| `kernel-selftest-iters-looping-wrong-sized-read-fail` | selftests | Full verbose trace, BTF, backtracking, final `invalid access to memory ... size=8` | Legitimate single rejected span. The log has state and source info; there is no earlier proof-establish site to show. |
| `kernel-selftest-irq-irq-flag-overwrite` | selftests | Full verbose trace, BTF, 8 instructions, final `expected an initialized irq flag as arg#0` | Log is good. Current `unknown` taxonomy is a catalog gap, not a trace-quality problem. |
| `kernel-selftest-dummy-st-ops-fail-dummy-st-ops-fail` | selftests | 167 chars, 0 instructions, only `attach to unsupported member ...` | Degraded single span caused by missing trace, not by rendering. |
| `stackoverflow-75058008` | SO | Short libbpf dump with 2 instructions and source comments, but no `@ file:line` suffixes | Enough for a rejected span. No BTF correlation is expected from this raw log. |
| `stackoverflow-60506220` | SO | Short tc-style verifier snippet, no source annotations | Enough for a rejected span. `unknown` taxonomy comes from missing `PTR_TO_PACKET_END` catalog coverage. |
| `stackoverflow-77568308` | SO | One-line loader message with embedded `9: (79) ...` plus `(16 line(s) omitted)` | Current parser misses the embedded instruction because it is not line-start aligned. This is a parser normalization gap. |
| `stackoverflow-69192685` | SO | libbpf/program-type/BTF metadata failure, `processed 0 insns` | `proof_status=unknown` is appropriate today; there is no instruction/state trace to analyze. |
| `github-cilium-cilium-41996` | GitHub | Large JSON/status blob plus one final verifier line `1074: (71) ... R2 invalid mem access 'inv'` | Only a rejected span is realistically recoverable from the current raw log. |

### Root cause for the 119 single-span cases

There are two very different populations:

1. Legitimate rejected-only cases: 95/119
   - parsed instructions present
   - often BTF/source info present
   - proof lifecycle is truly `never_established`
2. Degraded zero-trace cases: 24/119
   - no parsed instructions
   - placeholder rejected-only output
   - driven by loader errors, abbreviated pasted logs, or parser normalization gaps

Conclusion: the single-span metric is mostly reflecting correct semantics, not a rendering defect. If you optimize this metric directly, you risk fabricating proof context that the verifier log never showed.

## 2. Unknown `taxonomy_class` Cases

Current count: 14

### Root causes

- 8 cases are straightforward catalog misses.
- 4 cases also suffer from bad error-line selection, so the catalog never sees the right line.
- 2 cases are genuinely under-specified from the raw log and should probably remain `unknown` unless the corpus is enriched.

### All 14 unknown-taxonomy cases

| case_id | current selected error line | likely classification | action |
| --- | --- | --- | --- |
| `kernel-selftest-dynptr-fail-dynptr-slice-var-len1` | `arg#2 arg#3 memory, len pair leads to invalid memory access` | likely `OBLIGE-E005` / `lowering_artifact` | Add E005 pattern for `unbounded memory access` and/or the len-pair message. |
| `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly` | `; int invalid_slice_rdwr_rdonly(struct __sk_buff *skb) @ dynptr_fail.c:1391` | likely `OBLIGE-E019` / `source_bug` | Fix error-line scoring. Real line is `the prog does not allow writes to packet data`; add that to E019. |
| `kernel-selftest-irq-irq-flag-overwrite-partial` | `expected an initialized irq flag as arg#0` | `OBLIGE-E020` / `source_bug` | Widen E020 pattern to match full `irq flag as arg#0` message. |
| `kernel-selftest-irq-irq-flag-overwrite` | `expected an initialized irq flag as arg#0` | `OBLIGE-E020` / `source_bug` | Same fix as above. |
| `kernel-selftest-irq-irq-restore-iter` | `expected an initialized irq flag as arg#0` | `OBLIGE-E020` / `source_bug` | Same fix as above. |
| `kernel-selftest-irq-irq-save-invalid` | `; int irq_save_invalid(struct __sk_buff *ctx) @ irq.c:340` | `OBLIGE-E020` / `source_bug` | Fix error-line scoring. Real line is `expected uninitialized irq flag as arg#0`; add full-message regex to E020. |
| `stackoverflow-60506220` | `R2 pointer arithmetic on PTR_TO_PACKET_END prohibited` | likely `OBLIGE-E006` / `lowering_artifact` | Broaden E006 `pkt_end` regex to match `PTR_TO_PACKET_END prohibited`. |
| `stackoverflow-67402772` | `invalid bpf_context access off=92 size=4` | likely `OBLIGE-E023` / `source_bug` | Add `invalid bpf_context access ...` to E023 or add a dedicated source-bug ID. |
| `stackoverflow-68815540` | truncated register-state dump only | still `unknown` | Raw log does not contain a recoverable terminal verifier error line. |
| `stackoverflow-69192685` | `libbpf: load bpf program failed: Invalid argument` | likely `OBLIGE-E021` / `env_mismatch` | Prefer `number of funcs in func_info doesn't match number of subprogs` as the error line; add it to E021. |
| `stackoverflow-71351495` | `R3 pointer comparison prohibited` | likely `OBLIGE-E023` / `source_bug` | Add `pointer comparison prohibited` to E023 or add a dedicated source-bug ID. |
| `stackoverflow-77462271` | `processed 54 insns (limit 1000000) ...` | likely `OBLIGE-E021` / `env_mismatch` | Prefer `failed to find kernel BTF type ID ...`; add that pattern to E021. |
| `stackoverflow-78633443` | `libbpf: failed to load object 'work/switch/switch.o'` | still `unknown` | `Argument list too long` + `processed 0 insns` is too loader-specific to classify confidently from current data. |
| `github-aya-rs-aya-1490` | `[30] UNION MaybeUninit<u8> size=1 vlen=2 Invalid name` | likely `OBLIGE-E021` / `env_mismatch` | Add BTF `Invalid name` / BTF-load invalid-name pattern to E021. |

### Concrete catalog/parser changes

Recommended updates:

- [`interface/extractor/log_parser.py`](../../interface/extractor/log_parser.py) `VerifierLogParser._select_error_line(...)`
  - Penalize comment/source lines beginning with `;`.
  - Penalize loader wrapper lines beginning with `libbpf:` when a more specific verifier line exists later.
  - Penalize `processed ...` summary lines more aggressively.
  - Prefer exact verifier symptom lines over lines that merely contain words like `invalid` inside function names.
- [`taxonomy/error_catalog.yaml`](../../taxonomy/error_catalog.yaml)
  - Expand `OBLIGE-E005`, `OBLIGE-E006`, `OBLIGE-E019`, `OBLIGE-E020`, `OBLIGE-E021`, and `OBLIGE-E023` with the patterns listed above.
- [`interface/extractor/diagnoser.py`](../../interface/extractor/diagnoser.py) `_classify(...)`
  - Add small fallback heuristics for:
    - `invalid bpf_context access`
    - `pointer comparison prohibited`
    - `failed to find kernel BTF type ID`
  - This provides robustness when the catalog lags behind new log wording.

### Expected impact

- Likely reduction of unknown taxonomy from 14 to about 2.
- Expected improvement: about 12 cases in the current corpus.

## 3. Stack Overflow Cases and 1.5% BTF Correlation

Eligible SO cases: 65  
SO cases with file/line correlation: 1  
SO BTF correlation: 1.5%

### Sample of 5 raw SO logs

| case_id | `@ file:line` in raw log? | observation |
| --- | --- | --- |
| `stackoverflow-75058008` | no | Short libbpf verifier dump with source comments but no file/line suffix. |
| `stackoverflow-60506220` | no | tc-style verifier analysis only. No BTF/source annotations present. |
| `stackoverflow-67402772` | no | tc-style verifier analysis only. No BTF/source annotations present. |
| `stackoverflow-77568308` | no | Single-line abbreviated error with omitted lines. No file/line information exists to recover. |
| `stackoverflow-79812509` | yes | Contains `@ provenance_tracing_programs.bpf.c:139/141`, and OBLIGE successfully correlates to file/line. |

### Conclusion

This is primarily a data issue, not a source-correlator bug.

Evidence:

- 64/65 eligible SO cases have no source-location markers in the raw log.
- The only SO case that does contain `@ file:line` markers, `stackoverflow-79812509`, is correctly correlated today.
- Selftests are at 98.7% BTF correlation, which is another sign that the parser/source-correlator path works when the raw log contains usable annotations.

Implication:

- Do not prioritize core BTF parser work to fix SO correlation.
- If higher SO location coverage matters, improve the corpus/ingestion path instead:
  - preserve the best raw verifier block instead of always relying on `combined`
  - optionally feed `source_snippets` into a separate source-hint path

Relevant files:

- [`interface/extractor/source_correlator.py`](../../interface/extractor/source_correlator.py) `SOURCE_LOCATION_SUFFIX_RE` and `_extract_source_fields(...)`
- [`eval/batch_diagnostic_eval.py`](../../eval/batch_diagnostic_eval.py) `extract_verifier_log(...)`
- [`eval/pretty_verifier_comparison.py`](../../eval/pretty_verifier_comparison.py) `select_primary_log(...)`
- [`case_study/collect_stackoverflow.py`](../../case_study/collect_stackoverflow.py)

### Expected impact

- Core parser changes alone: near-zero improvement on the current SO BTF metric.
- Ingestion/API work could improve user-facing source hints, but not true BTF correlation unless better raw logs are collected.

## 4. Proof-Status Distribution Quality

Overall proof-status distribution across the 241 eligible cases:

| proof_status | count | current quality |
| --- | ---: | --- |
| `established_then_lost` | 97 | Good |
| `never_established` | 107 | Mostly good |
| `established_but_insufficient` | 13 | Good |
| `unknown` | 21 | Needs work |
| `satisfied` | 3 | Incorrect |

### `established_then_lost` (97)

- 97/97 have both `proof_established` and `proof_lost` spans.
- 97/97 also include `rejected`.
- Span counts:
  - 87 cases with 3 spans
  - 8 cases with 5 spans
  - 2 cases with 4 spans

Answer to the question: yes, all 97 `established_then_lost` cases already have both established and lost spans.

### `never_established` (107)

- 107/107 include `rejected`.
- 107/107 include no `proof_established` and no `proof_lost`.
- Span counts:
  - 95 cases with 1 span
  - 12 cases with 2 spans
- The 12 two-span cases are `proof_propagated + rejected`, which is reasonable extra context.

Answer to the question: yes, these are behaving consistently. They are not missing hidden 3-span narratives.

### `unknown` (21)

All 21 `unknown` cases have:

- 1 span
- 0 parsed instructions
- 0 critical transitions
- 0 causal chain

What is in their logs:

- loader/BTF metadata failures
- processed-summary-only outputs
- abbreviated one-line verifier summaries
- pasted prose/system output instead of a full verbose verifier trace

Representative examples:

- `stackoverflow-48267671`: man-page text about `EINVAL`, not a trace
- `stackoverflow-69192685`: libbpf/program-type/BTF metadata mismatch, `processed 0 insns`
- `stackoverflow-77568308`: one-line abbreviated verifier failure with omitted lines
- `github-aya-rs-aya-1490`: BTF load/type-name dump, no program trace
- `github-cilium-cilium-44216`: verifier bug warning with no parseable instruction stream

### `satisfied` (3)

These 3 are wrong:

- `stackoverflow-76994829`
- `stackoverflow-77713434`
- `stackoverflow-78591601`

All three are rejection logs with zero parsed instructions. The false label comes from [`interface/extractor/proof_analysis.py`](../../interface/extractor/proof_analysis.py) `analyze_proof_lifecycle(...)`, which currently does:

- `establish_site is None`
- `rejected is None`
- therefore `status = "satisfied"`

That is not valid for a failing verifier log with no parsed trace.

## 5. Recommended Changes

### Priority 0: Fix error-line selection and catalog coverage

Files / functions:

- [`interface/extractor/log_parser.py`](../../interface/extractor/log_parser.py) `VerifierLogParser._select_error_line(...)`
- [`taxonomy/error_catalog.yaml`](../../taxonomy/error_catalog.yaml)
- [`interface/extractor/diagnoser.py`](../../interface/extractor/diagnoser.py) `_classify(...)`

What to change:

- Stop letting source-comment lines and `processed ...` summaries beat real verifier errors.
- Add the missing regexes identified in the 14-case table.
- Add a small fallback classifier for common uncatalogued lines.

Expected impact:

- About 12 unknown-taxonomy cases become classified.
- Unknown taxonomy should drop from 14 to about 2.

### Priority 1: Fix zero-trace proof-status behavior

Files / functions:

- [`interface/extractor/proof_analysis.py`](../../interface/extractor/proof_analysis.py) `analyze_proof_lifecycle(...)`
- [`interface/extractor/rust_diagnostic.py`](../../interface/extractor/rust_diagnostic.py) `_analyze_proof(...)` or `generate_diagnostic(...)`

What to change:

- Never emit `satisfied` for a failing log that has no parsed rejected event.
- Return `unknown` instead, unless there is a conservative direct-rejection fallback.
- Add a fallback: if there are zero parsed instructions but the selected error line is a direct verifier rejection such as `invalid mem access`, `invalid access to map value`, or `pointer type ... must point`, label it `never_established` and render a rejected-only span.

Expected impact:

- Eliminate all 3 incorrect `satisfied` results.
- Reduce `proof_status=unknown` by about 3 to 6 cases, depending on how conservative the fallback is.

### Priority 2: Parse prefixed and abbreviated instruction snippets

Files / functions:

- [`interface/extractor/trace_parser.py`](../../interface/extractor/trace_parser.py) `INSTRUCTION_RE`, `parse_line(...)`, `_normalize_line(...)`, `_collect_error_texts(...)`

What to change:

- Accept instruction patterns that appear after loader prefixes, for example:
  - `...: 9: (79) r3 = ...`
  - `:599: (07) r2 += -16383`
- Strip leading wrapper text before trying `INSTRUCTION_RE`.

Current cases this would help:

- `stackoverflow-77568308`
- `stackoverflow-77713434`

Expected impact:

- Small on current counts, but important for real-world pasted logs.
- Likely improves about 2 current cases and future abbreviated SO/GitHub inputs.

### Priority 3: Reuse best-block selection for multi-block SO/GitHub logs

Files / functions:

- [`eval/batch_diagnostic_eval.py`](../../eval/batch_diagnostic_eval.py) `extract_verifier_log(...)`
- factor out and reuse [`eval/pretty_verifier_comparison.py`](../../eval/pretty_verifier_comparison.py) `select_primary_log(...)`

What to change:

- For YAMLs with `verifier_log.blocks`, select the highest-scoring verbose block instead of always preferring `combined`.

Why:

- 33 eligible cases have multiple log blocks.
- This is already recognized in the Pretty Verifier comparison path, but not in batch eval.

Expected impact:

- Probably small on current headline metrics.
- Worth doing for stability and cleaner downstream parsing.

### Priority 4: Only chase the single-span rate with conservative context synthesis

Files / functions:

- [`interface/extractor/rust_diagnostic.py`](../../interface/extractor/rust_diagnostic.py) `_synthesize_proof_events(...)`
- possibly [`interface/extractor/trace_parser.py`](../../interface/extractor/trace_parser.py) backtrack helpers

What to change:

- If you want to reduce rejected-only outputs, synthesize a `proof_propagated` span from backtracking-only evidence even when no full causal chain is available.

Why this is low priority:

- Only about 5 current single-span `never_established` cases appear to have backtracking but no causal chain.
- This will not fix the main quality problems.

Expected impact:

- At most a handful of single-span cases.
- No major impact on correctness.

### Priority 5: Treat SO source/BTF coverage as an ingestion problem

Files / functions:

- [`case_study/collect_stackoverflow.py`](../../case_study/collect_stackoverflow.py)
- optionally add a new API path that accepts `source_snippets` separately from the raw verifier log

What to change:

- Preserve raw verifier blocks carefully.
- If desired, add non-BTF source hints derived from `source_snippets`.

Expected impact:

- Little to no change to true BTF correlation on the current corpus.
- Could improve user-facing source text for some SO/GitHub cases.

## 6. Updated TODO for the Next Quality Round

1. Fix `log_parser._select_error_line(...)` so comment lines and `processed ...` summaries stop winning.
2. Patch `error_catalog.yaml` with the missing patterns from the 14 unknown-taxonomy cases.
3. Add a regression test for each newly covered unknown-taxonomy case.
4. Fix `proof_analysis.analyze_proof_lifecycle(...)` so zero-trace failures never become `satisfied`.
5. Add a conservative zero-trace `never_established` fallback for direct rejection lines.
6. Extend `trace_parser` to recover embedded instruction snippets from loader-wrapped lines.
7. Reuse `select_primary_log(...)` in batch eval for multi-block SO/GitHub cases.
8. Only after the above, decide whether single-span-rate reduction is worth a small backtrack-to-`proof_propagated` enhancement.
9. If SO location coverage remains important, improve corpus collection or add `source_snippets` as a separate hint channel instead of trying to infer nonexistent BTF.

## Bottom Line

- The 119 single-span cases are mostly correct. They are not hiding broken `established_then_lost` stories.
- The highest-value fixes are taxonomy coverage and zero-trace proof-status handling.
- The SO BTF problem is mostly in the raw logs, not in the correlator.
- A focused next round should improve about 12 taxonomy classifications, remove all 3 false `satisfied` results, and reduce `proof_status=unknown` modestly without fabricating extra spans.
