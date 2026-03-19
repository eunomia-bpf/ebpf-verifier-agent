# case_study/

Verifier failure case corpus for BPFix evaluation.

## Schema

Two schemas coexist in this directory:

- **`schema.yaml`** — Original aspirational schema. Requires `source_code`,
  `compile_args`, `target_kernel`, `fix_patch`, `semantic_test`, and other
  fields that are unavailable for most collected cases. Not used by the
  evaluation pipeline.
- **`eval_schema.yaml`** — Actual format used by all eval scripts. Input fields
  are `buggy_code` and `verifier_log`; ground truth fields are `fixed_code`,
  `fix_description`, `fix_type`, `source_url`, `commit_hash`. System-generated
  labels (`error_id`, `taxonomy_class`, `root_cause`) are outputs, not ground
  truth.

## Directory Structure

```
cases/
├── kernel_selftests/    200 cases + index.yaml
├── stackoverflow/        76 cases + index.yaml
├── github_issues/        26 cases + index.yaml
├── eval_commits/        591 cases + index.yaml
└── eval_commits_synthetic/  535 cases
```

### kernel_selftests/ (200 cases)

Cases extracted from `tools/testing/selftests/bpf/` using `__msg()` failure
annotations. `verifier_log` is a plain string. Includes
`expected_verifier_messages` and `selftest` metadata (file, section, function,
failure_mode).

### stackoverflow/ (76 cases)

Cases from Stack Overflow questions with verifier log excerpts. `verifier_log`
is a dict with `blocks` (list of raw text blocks) and `combined` (single
concatenated string). Also stores `source_snippets` and `question_body_text`.

### github_issues/ (26 cases)

Cases from Cilium, Aya, and Katran GitHub issues. Same `verifier_log` dict
format as stackoverflow.

### eval_commits/ (591 cases)

Verifier-fix commits collected from Aya, BCC, Cilium, Katran, and Libbpf
repos. Each case has `buggy_code` and `fixed_code` extracted from the commit
diff, plus `commit_hash`, `fix_type`, and `repository`. **No verifier logs** —
the program was rejected by the verifier but the log was not recorded in the
commit.

### eval_commits_synthetic/ (535 cases)

Synthetic cases derived from `eval_commits` by `generate_synthetic_cases.py`.
Same structure as `eval_commits` (no verifier logs). Compilation to obtain
actual verifier logs was attempted but produced 0 successes in a 20-case pilot
(`compile_synthetic_cases.py`).

## The 241-Case Evaluation Corpus

The primary evaluation corpus used in batch_diagnostic_eval is filtered from
the 302 cases in `kernel_selftests/` + `stackoverflow/` + `github_issues/`
where `len(verifier_log) >= 50`. The eval_commits and eval_commits_synthetic
directories are excluded because they have no verifier logs.

## Collection Scripts

| Script | Source |
|--------|--------|
| `collect_kernel_selftests.py` | Kernel selftest `__msg()` annotations |
| `collect_stackoverflow.py` | Stack Overflow API |
| `collect_github_issues.py` | GitHub issues (Cilium, Aya, Katran) |
| `collect_rex_commits.py` / `collect_rex_commits_large_scale.py` | Verifier-fix commits |
| `collect.py` | Unified entry point |

## Data Format

One YAML file per case, plus an `index.yaml` per directory listing all
case IDs. Field `case_id` is stable and used as the join key across
evaluation scripts.
