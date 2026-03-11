# Multi-Model LLM Experiment

Generated at: 2026-03-11T22:30:43+00:00

## Experiment Setup

- Selection strategy: `manual_labels_stratified`
- Selected cases: `22`
- Targets: `{'source_bug': 9, 'lowering_artifact': 6, 'verifier_limit': 4, 'env_mismatch': 3}`
- Manual response file: `eval/results/llm_multi_model_manual_responses.json`
- Manual score file: `eval/results/llm_multi_model_manual_scores.json`

## Cohort

| Case | Taxonomy | Src | Difficulty | Log Lines | Ground Truth |
| --- | --- | --- | --- | ---: | --- |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | KS | easy | 46 | manual_label_doc |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | KS | easy | 24 | manual_label_doc |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | KS | medium | 102 | manual_label_doc |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | KS | easy | 38 | manual_label_doc |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | KS | easy | 44 | manual_label_doc |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | KS | medium | 41 | manual_label_doc |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | KS | medium | 27 | manual_label_doc |
| `stackoverflow-69767533` | `source_bug` | SO | medium | 42 | yaml_selected_answer |
| `stackoverflow-77205912` | `source_bug` | SO | medium | 61 | yaml_selected_answer |
| `github-aya-rs-aya-1062` | `lowering_artifact` | GH | medium | 333 | yaml_issue_fix |
| `stackoverflow-70750259` | `lowering_artifact` | SO | medium | 109 | yaml_selected_answer |
| `stackoverflow-73088287` | `lowering_artifact` | SO | hard | 10 | yaml_selected_answer |
| `stackoverflow-74178703` | `lowering_artifact` | SO | hard | 28 | yaml_selected_answer |
| `stackoverflow-76160985` | `lowering_artifact` | SO | hard | 36 | yaml_selected_answer |
| `stackoverflow-79530762` | `lowering_artifact` | SO | hard | 105 | yaml_selected_answer |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | KS | medium | 513 | manual_label_doc |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | KS | medium | 408 | manual_label_doc |
| `stackoverflow-56872436` | `verifier_limit` | SO | medium | 6 | yaml_selected_answer |
| `stackoverflow-78753911` | `verifier_limit` | SO | medium | 2 | yaml_selected_answer |
| `github-aya-rs-aya-1233` | `env_mismatch` | GH | easy | 39 | yaml_issue_fix |
| `github-aya-rs-aya-864` | `env_mismatch` | GH | easy | 12 | yaml_issue_fix |
| `stackoverflow-76441958` | `env_mismatch` | SO | medium | 25 | yaml_selected_answer |

## Aggregate Results

Combined across both model strengths:

| Condition | Cases | Root Cause | Taxonomy | Fix Direction | Mean Specificity | Mean Response Tokens |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Condition A | 44 | 44/44 | 44/44 | 44/44 | 2.59 | 125.07 |
| Condition B | 44 | 43/44 | 44/44 | 42/44 | 2.64 | 140.18 |
| Condition C | 44 | 43/44 | 44/44 | 43/44 | 2.5 | 128.36 |

Split by model strength:

| Model Strength | Condition | Cases | Root Cause | Taxonomy | Fix Direction | Mean Specificity | Mean Response Tokens |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Strong | Condition A | 22 | 22/22 | 22/22 | 22/22 | 2.73 | 146.0 |
| Strong | Condition B | 22 | 22/22 | 22/22 | 21/22 | 2.86 | 164.82 |
| Strong | Condition C | 22 | 22/22 | 22/22 | 22/22 | 2.59 | 147.59 |
| Weak | Condition A | 22 | 22/22 | 22/22 | 22/22 | 2.45 | 104.14 |
| Weak | Condition B | 22 | 21/22 | 22/22 | 21/22 | 2.41 | 115.55 |
| Weak | Condition C | 22 | 21/22 | 22/22 | 21/22 | 2.41 | 109.14 |

Strong vs weak root-cause accuracy:

| Condition | Strong Root Cause | Weak Root Cause | Delta |
| --- | ---: | ---: | ---: |
| Condition A | 100.0% | 100.0% | 0.0% |
| Condition B | 100.0% | 95.5% | 4.5% |
| Condition C | 100.0% | 95.5% | 4.5% |

## Per-Taxonomy Breakdown

Root-cause correctness counts for the strong model:

| Taxonomy | Condition A | Condition B | Condition C |
| --- | ---: | ---: | ---: |
| `source_bug` | 9/9 | 9/9 | 9/9 |
| `lowering_artifact` | 6/6 | 6/6 | 6/6 |
| `verifier_limit` | 4/4 | 4/4 | 4/4 |
| `env_mismatch` | 3/3 | 3/3 | 3/3 |

Root-cause correctness counts for the weak model:

| Taxonomy | Condition A | Condition B | Condition C |
| --- | ---: | ---: | ---: |
| `source_bug` | 9/9 | 8/9 | 8/9 |
| `lowering_artifact` | 6/6 | 6/6 | 6/6 |
| `verifier_limit` | 4/4 | 4/4 | 4/4 |
| `env_mismatch` | 3/3 | 3/3 | 3/3 |

## Per-Case x Condition x Model Results

| Case | Taxonomy | Model | Condition | Root | Taxonomy | Fix | Specificity |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Strong | Condition B | 1 | 1 | 0 | 1 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Weak | Condition B | 0 | 1 | 0 | 1 |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | Weak | Condition C | 0 | 1 | 0 | 1 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-69767533` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-77205912` | `source_bug` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1062` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-70750259` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-73088287` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-73088287` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-73088287` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-73088287` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-73088287` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-73088287` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-74178703` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-74178703` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-74178703` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-74178703` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `stackoverflow-74178703` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `stackoverflow-74178703` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-76160985` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-76160985` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-76160985` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-76160985` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-76160985` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-76160985` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-79530762` | `lowering_artifact` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-79530762` | `lowering_artifact` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-79530762` | `lowering_artifact` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-79530762` | `lowering_artifact` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `stackoverflow-79530762` | `lowering_artifact` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-79530762` | `lowering_artifact` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Strong | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Weak | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-56872436` | `verifier_limit` | Weak | Condition C | 1 | 1 | 1 | 3 |
| `stackoverflow-78753911` | `verifier_limit` | Strong | Condition A | 1 | 1 | 1 | 2 |
| `stackoverflow-78753911` | `verifier_limit` | Strong | Condition B | 1 | 1 | 1 | 2 |
| `stackoverflow-78753911` | `verifier_limit` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-78753911` | `verifier_limit` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `stackoverflow-78753911` | `verifier_limit` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `stackoverflow-78753911` | `verifier_limit` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-1233` | `env_mismatch` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-864` | `env_mismatch` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-864` | `env_mismatch` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-864` | `env_mismatch` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-864` | `env_mismatch` | Weak | Condition A | 1 | 1 | 1 | 3 |
| `github-aya-rs-aya-864` | `env_mismatch` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `github-aya-rs-aya-864` | `env_mismatch` | Weak | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-76441958` | `env_mismatch` | Strong | Condition A | 1 | 1 | 1 | 3 |
| `stackoverflow-76441958` | `env_mismatch` | Strong | Condition B | 1 | 1 | 1 | 3 |
| `stackoverflow-76441958` | `env_mismatch` | Strong | Condition C | 1 | 1 | 1 | 2 |
| `stackoverflow-76441958` | `env_mismatch` | Weak | Condition A | 1 | 1 | 1 | 2 |
| `stackoverflow-76441958` | `env_mismatch` | Weak | Condition B | 1 | 1 | 1 | 2 |
| `stackoverflow-76441958` | `env_mismatch` | Weak | Condition C | 1 | 1 | 1 | 2 |

## Analysis

Across the full 22-case cohort, Condition C (structured trace) reached root-cause accuracy 100.0% on the strong model versus 100.0% for Condition A and 100.0% for Condition B; on the weak model it reached 95.5% versus 100.0% and 95.5%.

On `lowering_artifact`, which is the main stress test for misleading verifier headlines, Condition C scored 100.0% on the strong model and 100.0% on the weak model. For comparison, Condition A scored 100.0% / 100.0%, and Condition B scored 100.0% / 100.0%.

For the complex subset (6 runs per condition; defined here as log-heavy or causal-chain-bearing cases), Condition C reached 100.0% root-cause accuracy on the strong model and 100.0% on the weak model.

The weak-model simulation is near ceiling: the prompt-only downgrade did reduce answer length and specificity, but it did not create a large correctness gap. That means the strong-vs-weak comparison should be interpreted as a prompt-ablation, not as evidence about a truly weaker base model.

Hypothesis check: not cleanly supported by the aggregate scores; the structured trace did not dominate every baseline where expected.

Most misses concentrated in: kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39 (3 run(s)).

## Notes

- Full prompts and raw responses are stored in the JSON results file.
- Condition tables above use root-cause correctness counts in the key taxonomy breakdown.
- Final scores come from the `codex_judge` pass when available; otherwise the script falls back to heuristic keyword scoring.
