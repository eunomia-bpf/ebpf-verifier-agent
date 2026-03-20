# Cross-Log Diagnostic Stability

Date: 2026-03-19

- Entry point: `from interface.extractor.pipeline import generate_diagnostic`
- Fresh logs: `case_study/cases/so_gh_verified/{case_id}/verifier_log_captured.txt`
- Original logs: YAML `verifier_log` from `case_study/cases/stackoverflow/{case_id}.yaml` or `case_study/cases/github_issues/{case_id}.yaml`
- Scope note: the task text said 30 cases, but the current on-disk `so_gh_verified` cohort contains 51 cases with `verifier_log_captured.txt`. All 51 had matching YAMLs and non-empty original logs, so this report uses 51/51.

## Method

Compared fields per case:

- taxonomy: `json_data.failure_class`
- error_id: `json_data.error_id`
- proof_status: `json_data.metadata.proof_status`
- span_count: `len(json_data.metadata.proof_spans)`
- root-cause location proxy: last `proof_lost` span; if absent, last `rejected` span

Root-cause exact match rule:

- if both logs have source locations, compare `role + path + line`
- otherwise compare `role + insn_range`

## Summary

| Cohort | Cases | Taxonomy Match | Error ID Match | Proof Match | Span Count Match | Root Match | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Overall | 51 | 38/51 (74.5%) | 16/51 (31.4%) | 25/51 (49.0%) | 28/51 (54.9%) | 6/51 (11.8%) | all five fields matched in 5/51 (9.8%) |
| GitHub | 10 | 5/10 (50.0%) | 1/10 (10.0%) | 5/10 (50.0%) | 0/10 (0.0%) | 0/10 (0.0%) | fresh `BPFIX-UNKNOWN` in 10/10; fresh zero-span outputs in 10/10 |
| Stack Overflow | 41 | 33/41 (80.5%) | 15/41 (36.6%) | 20/41 (48.8%) | 28/41 (68.3%) | 6/41 (14.6%) | fresh `BPFIX-UNKNOWN` in 23/41; fresh zero-span outputs in 4/41 |

## Key Findings

- Taxonomy is the most stable field. The fresh run still drifted on 13/51 cases, but it remained much more stable than `error_id` or root-cause location.
- `error_id` stability is weak. Fresh logs produced `BPFIX-UNKNOWN` in 33/51 cases; the original YAML logs did so in only 1/51.
- All 10 GitHub fresh logs collapsed to `BPFIX-UNKNOWN` with zero proof spans, which dominates the worst-case instability.
- Drift mostly collapses toward `source_bug`. The most common taxonomy changes were `lowering_artifact -> source_bug` (5 cases), `env_mismatch -> source_bug` (3), and `verifier_limit -> source_bug` (1).
- Root-cause location is the least stable field. Even with the fallback-to-instruction-index comparison, only 6/51 cases matched.

Cases with all five fields stable:

- `stackoverflow-61945212`
- `stackoverflow-67402772`
- `stackoverflow-71946593`
- `stackoverflow-78236856`
- `stackoverflow-79348306`

Cases where taxonomy, error_id, proof_status, and span_count all matched but root location still differed:

- `stackoverflow-67679109`
- `stackoverflow-68752893`
- `stackoverflow-71522674`
- `stackoverflow-72560675`
- `stackoverflow-76637174`
- `stackoverflow-77205912`
- `stackoverflow-79812509`

## Per-Case Results

`Spans` is `original->fresh`.

| Case | Taxonomy | Error ID | Proof | Spans | Root | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1002` | diff | diff | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-1056` | same | diff | diff | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-1062` | same | diff | diff | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-1267` | diff | diff | diff | `2->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-407` | diff | diff | diff | `2->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-440` | diff | diff | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-458` | same | diff | diff | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-aya-rs-aya-521` | diff | diff | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-cilium-cilium-41412` | same | same | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `github-facebookincubator-katran-149` | same | diff | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `stackoverflow-53136145` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-60506220` | same | diff | same | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `stackoverflow-61945212` | same | same | same | `1->1` | same | - |
| `stackoverflow-67402772` | same | same | same | `1->1` | same | - |
| `stackoverflow-67679109` | same | same | same | `1->1` | diff | only root differed |
| `stackoverflow-68752893` | same | same | same | `1->1` | diff | only root differed |
| `stackoverflow-69413427` | same | diff | same | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-69767533` | same | diff | same | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-70721661` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-70729664` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-70750259` | diff | diff | same | `2->1` | diff | fresh=UNKNOWN |
| `stackoverflow-70841631` | diff | diff | same | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-70873332` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-71351495` | same | diff | diff | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `stackoverflow-71522674` | same | same | same | `1->1` | diff | only root differed |
| `stackoverflow-71946593` | same | same | same | `1->1` | same | - |
| `stackoverflow-72005172` | diff | same | diff | `1->2` | same | - |
| `stackoverflow-72074115` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-72560675` | same | same | same | `1->1` | diff | only root differed |
| `stackoverflow-72575736` | same | diff | diff | `3->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `stackoverflow-72606055` | diff | diff | same | `1->1` | diff | - |
| `stackoverflow-73088287` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-74178703` | same | diff | diff | `2->1` | diff | fresh=UNKNOWN |
| `stackoverflow-74531552` | diff | same | diff | `1->2` | diff | - |
| `stackoverflow-75294010` | same | diff | diff | `2->1` | diff | fresh=UNKNOWN |
| `stackoverflow-75515263` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-75643912` | same | same | diff | `3->1` | diff | - |
| `stackoverflow-76160985` | diff | diff | diff | `2->1` | diff | fresh=UNKNOWN |
| `stackoverflow-76277872` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-76637174` | same | same | same | `3->3` | diff | only root differed |
| `stackoverflow-76960866` | same | diff | diff | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-77205912` | same | same | same | `1->1` | diff | only root differed |
| `stackoverflow-77673256` | same | diff | same | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-77762365` | diff | diff | diff | `1->1` | diff | - |
| `stackoverflow-78236201` | same | diff | same | `1->1` | diff | fresh=UNKNOWN |
| `stackoverflow-78236856` | same | same | same | `2->2` | same | - |
| `stackoverflow-78958420` | same | diff | diff | `1->0` | diff | fresh=UNKNOWN, fresh=0 spans |
| `stackoverflow-79348306` | same | same | same | `1->1` | same | - |
| `stackoverflow-79485758` | diff | diff | diff | `3->1` | diff | - |
| `stackoverflow-79530762` | same | diff | diff | `3->1` | diff | fresh=UNKNOWN |
| `stackoverflow-79812509` | same | same | same | `1->1` | diff | only root differed |
