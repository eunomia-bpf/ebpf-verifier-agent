# Ground Truth Expansion v2 Report

Generated: 2026-03-18

## Summary

- Wrote `case_study/ground_truth_v2.yaml` with `302` corpus cases (`298` with non-null taxonomy).
- Preserved all `292` prior labels, merged the richer fields from the 30 manual cases, and added log-quality labels for all `302` cases.
- Auto-enriched `50` additional trace-rich auto-labeled cases (`33` SO/GH with answer/fix text + `17` diverse selftests).
- Added taxonomy for `6` previously unlabeled cases; left `4` cases as null when the signal stayed too weak.

## Field Coverage

| Field | Populated |
| --- | ---: |
| `taxonomy` | 298 |
| `error_id` | 78 |
| `root_cause_description` | 84 |
| `fix_type` | 66 |
| `fix_description` | 66 |
| `fix_text` | 66 |
| `localizability` | 30 |
| `obligation_specificity` | 30 |

## Log Quality

| Quality | Count |
| --- | ---: |
| `message_only` | 25 |
| `no_log` | 39 |
| `partial` | 34 |
| `trace_rich` | 204 |

## Taxonomy Changes vs v1

- Cases whose taxonomy changed from `ground_truth_labels.yaml`: `18`
- Previously unlabeled cases given a non-null taxonomy: `6`

| Case | Old | New | Basis |
| --- | --- | --- | --- |
| `github-aya-rs-aya-1267` | `source_bug` | `lowering_artifact` | diag:established_then_lost |
| `stackoverflow-67402772` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-69192685` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-70760516` | `source_bug` | `lowering_artifact` | diag:established_then_lost |
| `stackoverflow-72074115` | `lowering_artifact` | `source_bug` | text:source_level_fix |
| `stackoverflow-72575736` | `source_bug` | `verifier_bug` | text:kernel_bug_or_regression |
| `stackoverflow-72606055` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-74531552` | `lowering_artifact` | `source_bug` | text:source_level_fix |
| `stackoverflow-75643912` | `source_bug` | `lowering_artifact` | text+diag:lowering_artifact_workaround |
| `stackoverflow-76035116` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-76960866` | `lowering_artifact` | `source_bug` | text:source_level_fix |
| `stackoverflow-77462271` | `lowering_artifact` | `env_mismatch` | diag:structural_env_mismatch |
| `stackoverflow-77673256` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-77967675` | `env_mismatch` | `source_bug` | text:source_level_fix |
| `stackoverflow-78603028` | `lowering_artifact` | `env_mismatch` | text:environment_or_loader_contract |
| `stackoverflow-79045875` | `source_bug` | `verifier_bug` | text:kernel_bug_or_regression |
| `stackoverflow-79348306` | `env_mismatch` | `lowering_artifact` | text+diag:lowering_artifact_workaround |
| `stackoverflow-79485758` | `source_bug` | `lowering_artifact` | text+diag:lowering_artifact_workaround |

## Lowering Artifact Audit

- Candidate cases flagged by diagnostic proof-loss or workaround text: `38`
- Cases labeled `lowering_artifact` in v2: `39`

| Case | Old | New | Error ID | Proof Status | Basis |
| --- | --- | --- | --- | --- | --- |
| `github-aya-rs-aya-1056` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E005` | `never_established` | fix_text_workaround_keyword |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E005` | `never_established` | fix_text_workaround_keyword |
| `github-aya-rs-aya-1267` | `source_bug` | `lowering_artifact` | `BPFIX-E023` | `established_then_lost` | diag_failure_class, proof_established_then_lost |
| `github-aya-rs-aya-407` | `env_mismatch` | `env_mismatch` | `BPFIX-E003` | `established_then_lost` | diag_failure_class, proof_established_then_lost, fix_text_workaround_keyword |
| `github-aya-rs-aya-857` | `lowering_artifact` | `lowering_artifact` | `None` | `unknown` | fix_text_workaround_keyword |
| `github-cilium-cilium-35182` | `env_mismatch` | `env_mismatch` | `BPFIX-E021` | `unknown` | fix_text_workaround_keyword |
| `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E005` | `established_then_lost` | diag_failure_class, proof_established_then_lost |
| `kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `kernel-selftest-dynptr-fail-skb-invalid-data-slice1-tc-0b35a757` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `kernel-selftest-dynptr-fail-skb-invalid-data-slice3-tc-a15c4322` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `kernel-selftest-dynptr-fail-xdp-invalid-data-slice1-xdp-c0fa30d5` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `kernel-selftest-iters-iter-err-too-permissive1-raw-tp-25649784` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `stackoverflow-53136145` | `source_bug` | `source_bug` | `BPFIX-E011` | `never_established` | fix_text_workaround_keyword |
| `stackoverflow-56872436` | `verifier_limit` | `verifier_limit` | `BPFIX-E008` | `unknown` | fix_text_workaround_keyword |
| `stackoverflow-67402772` | `lowering_artifact` | `env_mismatch` | `BPFIX-E023` | `never_established` | fix_text_workaround_keyword |
| `stackoverflow-69192685` | `lowering_artifact` | `env_mismatch` | `BPFIX-E021` | `unknown` | fix_text_workaround_keyword |
| `stackoverflow-70392721` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E023` | `unknown` | fix_text_workaround_keyword |
| `stackoverflow-70729664` | `source_bug` | `source_bug` | `BPFIX-E001` | `never_established` | fix_text_workaround_keyword |
| `stackoverflow-70750259` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E005` | `never_established` | diag_failure_class, fix_text_workaround_keyword |
| `stackoverflow-70760516` | `source_bug` | `lowering_artifact` | `BPFIX-E001` | `established_then_lost` | diag_failure_class, proof_established_then_lost |
| `stackoverflow-72575736` | `source_bug` | `verifier_bug` | `BPFIX-E001` | `established_then_lost` | diag_failure_class, proof_established_then_lost |
| `stackoverflow-72606055` | `lowering_artifact` | `env_mismatch` | `BPFIX-E023` | `unknown` | fix_text_workaround_keyword |
| `stackoverflow-73088287` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E001` | `never_established` | fix_text_workaround_keyword |
| `stackoverflow-74178703` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E017` | `established_but_insufficient` | fix_text_workaround_keyword |
| `stackoverflow-75058008` | `source_bug` | `source_bug` | `BPFIX-E002` | `never_established` | fix_text_workaround_keyword |
| `stackoverflow-75294010` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E011` | `never_established` | diag_failure_class |
| `stackoverflow-75643912` | `source_bug` | `lowering_artifact` | `BPFIX-E001` | `established_then_lost` | diag_failure_class, proof_established_then_lost, fix_text_workaround_keyword |
| `stackoverflow-76035116` | `lowering_artifact` | `env_mismatch` | `None` | `unknown` | fix_text_workaround_keyword |
| `stackoverflow-76160985` | `lowering_artifact` | `lowering_artifact` | `BPFIX-E005` | `established_then_lost` | diag_failure_class, proof_established_then_lost, fix_text_workaround_keyword |
| `stackoverflow-76371104` | `None` | `None` | `None` | `None` | fix_text_workaround_keyword |

## Auto-Enriched 50 Cases

- SO/GH trace-rich cases with answer/fix text (33): `github-aya-rs-aya-1002`, `github-aya-rs-aya-1056`, `github-aya-rs-aya-407`, `github-cilium-cilium-37478`, `github-cilium-cilium-41522`, `stackoverflow-67402772`, `stackoverflow-67679109`, `stackoverflow-68752893`, `stackoverflow-69413427`, `stackoverflow-70721661`, `stackoverflow-70729664`, `stackoverflow-70760516`, `stackoverflow-70841631`, `stackoverflow-70873332`, `stackoverflow-71351495`, `stackoverflow-71946593`, `stackoverflow-72005172`, `stackoverflow-72074115`, `stackoverflow-72575736`, `stackoverflow-72606055`, `stackoverflow-74531552`, `stackoverflow-75515263`, `stackoverflow-75643912`, `stackoverflow-76277872`, `stackoverflow-76637174`, `stackoverflow-76960866`, `stackoverflow-77673256`, `stackoverflow-77762365`, `stackoverflow-78236201`, `stackoverflow-78958420`, `stackoverflow-79348306`, `stackoverflow-79485758`, `stackoverflow-79812509`
- Diverse selftest representatives (17): `kernel-selftest-dynptr-fail-data-slice-missing-null-check1-raw-tp-af2be9c9`, `kernel-selftest-dynptr-fail-add-dynptr-to-map1-raw-tp-2b5ac898`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-unreleased-tp-btf-cgroup-mkdir-0f46d712`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49`, `kernel-selftest-dynptr-fail-clone-invalidate4-raw-tp-0dfbe587`, `kernel-selftest-dynptr-fail-clone-invalid1-raw-tp-b7206632`, `kernel-selftest-exceptions-fail-reject-exception-cb-call-global-func-tc-bd94f6f8`, `kernel-selftest-iters-iter-new-bad-arg-raw-tp-e25f0e76`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-no-null-check-tp-btf-cgroup-mkdir-6484ab95`, `kernel-selftest-dynptr-fail-skb-invalid-ctx-xdp-1a32a21f`, `kernel-selftest-dynptr-fail-dynptr-from-mem-invalid-api-raw-tp-1040be69`, `kernel-selftest-irq-irq-flag-overwrite-partial-tc-51152af8`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84`, `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-fp-tp-btf-cgroup-mkdir-7d3a90fe`, `kernel-selftest-dynptr-fail-data-slice-out-of-bounds-ringbuf-raw-tp-83139460`, `kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb`, `kernel-selftest-iters-iter-err-unsafe-asm-loop-raw-tp-9ee4d943`

## Validation

| Metric | Match | Total | Rate |
| --- | ---: | ---: | ---: |
| Old ground truth vs fresh BPFix diagnostic | 179 | 255 | 70.2% |
| New v2 ground truth vs fresh BPFix diagnostic | 189 | 260 | 72.7% |
| Manual 30-case subset vs fresh BPFix diagnostic | 22 | 30 | 73.3% |

- Compared with the previously reported `34.9%` (`89/255`) match rate, the fresh old-label baseline in this run is `70.2%` (`179/255`) and v2 scores `72.7%` (`189/260`).

## Notes

- The 30 manual labels keep their original taxonomy and now carry `error_id`, `localizability`, `obligation_specificity`, `root_cause_description`, and `fix_text` in machine-readable form.
- Auto-enrichment used BPFix diagnostic output plus case metadata (`source_snippets`, Stack Overflow answers, or GitHub fix comments).
- Cases with weak or non-diagnostic evidence remain `taxonomy: null` rather than forcing a guess.
