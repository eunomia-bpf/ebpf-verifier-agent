# Root-Cause Label Audit

This document audits the 68 replayable benchmark cases whose
`label.root_cause_insn_idx` is currently `null`. The goal is to decide whether
the missing instruction label is a data-quality problem or whether instruction
localization is the wrong metric for that case.

The audit covers only cases already admitted to `bpfix-bench/cases/`; every case
here builds locally and replays to verifier reject under the benchmark harness.

## Summary

| localization target | GitHub issue | Stack Overflow | total | interpretation |
|---|---:|---:|---:|---|
| `instruction_should_label` | 12 | 10 | 22 | Missing `root_cause_insn_idx` is not reasonable; these should get instruction labels. |
| `source_span_should_label` | 2 | 21 | 23 | Missing instruction index is mostly reasonable, but source-span labels are still needed. |
| `declaration_or_metadata_target` | 2 | 12 | 14 | Root cause is a declaration, ABI, map metadata, BTF/build metadata, or context contract. |
| `verifier_scope_target` | 1 | 6 | 7 | Root cause is a proof scope, verifier state, subprogram, or path-level issue. |
| `environment_target` | 1 | 1 | 2 | Root cause is program type, helper availability, kernel feature, or environment. |
| **total** | **18** | **50** | **68** |  |

The current `118/186` `root_cause_insn_idx` coverage is therefore not by itself
a fatal benchmark flaw. A single instruction target appears appropriate for only
22 of the 68 missing cases. However, the remaining 46 are not fully labelled:
23 need source-span labels, and 23 need non-instruction localization labels such
as declaration/metadata, verifier-scope, or environment target.

## Interpretation For Paper Metrics

Do not report instruction localization over all 186 cases. Report it over cases
whose `localization_target_kind` is `instruction`, and separately report coverage
and missing-label counts.

Recommended evaluation split:

- Diagnostic and taxonomy accuracy: all 186 replayable cases.
- Instruction localization: cases with instruction target labels only.
- Source-span localization: cases with source-span target labels only.
- Declaration/environment/verifier-scope routing: scored as diagnostic target
  classification, not as instruction localization.

The paper should say that the benchmark distinguishes root-cause target
granularity. Otherwise a method that repeats the reject instruction will look
unfairly strong on environment/metadata cases and unfairly weak on source-span
or verifier-scope cases.

## Cases That Should Receive Instruction Labels

These 22 cases have parseable rejected instructions and instruction-local
causes such as helper arguments, scalar dereference, pointer arithmetic, or
nullable map value dereference.

| source | cases |
|---|---|
| GitHub issue | `github-aya-rs-aya-1002`, `github-aya-rs-aya-1056`, `github-aya-rs-aya-1062`, `github-aya-rs-aya-1207`, `github-aya-rs-aya-1267`, `github-aya-rs-aya-440`, `github-aya-rs-aya-863`, `github-cilium-cilium-36936`, `github-cilium-cilium-37478`, `github-iovisor-bcc-10`, `github-iovisor-bcc-2463`, `github-iovisor-bcc-3269` |
| Stack Overflow | `stackoverflow-56965789`, `stackoverflow-60506220`, `stackoverflow-61648439`, `stackoverflow-77387582`, `stackoverflow-77613784`, `stackoverflow-77673256`, `stackoverflow-78236201`, `stackoverflow-78266602`, `stackoverflow-78471487`, `stackoverflow-79097886` |

These are the first labels to repair if the paper wants a stronger instruction
localization result.

## Cases That Need Source-Span Labels

These 23 cases are better evaluated with source-level spans than with a single
root instruction. Many are lowering artifacts or source constructs where the
final reject instruction is only the symptom.

| source | cases |
|---|---|
| GitHub issue | `github-cilium-cilium-41522`, `github-iovisor-bcc-5062` |
| Stack Overflow | `stackoverflow-56872436`, `stackoverflow-58978414`, `stackoverflow-60053570`, `stackoverflow-71253472`, `stackoverflow-73088287`, `stackoverflow-73282201`, `stackoverflow-73381767`, `stackoverflow-76371104`, `stackoverflow-76441958`, `stackoverflow-76760635`, `stackoverflow-77174348`, `stackoverflow-77713434`, `stackoverflow-78186253`, `stackoverflow-78196801`, `stackoverflow-78208591`, `stackoverflow-78525670`, `stackoverflow-78591601`, `stackoverflow-78599154`, `stackoverflow-78958420`, `stackoverflow-79095876`, `stackoverflow-79525201` |

For these, the missing `root_cause_insn_idx` is not the main issue. The main
issue is missing `root_cause_source_span` and acceptable alternate spans.

## Non-Instruction Targets

These 23 cases should not be forced into instruction-local metrics.

| target | cases |
|---|---|
| `declaration_or_metadata_target` | `github-aya-rs-aya-521`, `github-orangeopensource-p4rt-ovs-5`, `stackoverflow-56526650`, `stackoverflow-67188440`, `stackoverflow-67441023`, `stackoverflow-69506785`, `stackoverflow-70402992`, `stackoverflow-75300106`, `stackoverflow-76029505`, `stackoverflow-76994829`, `stackoverflow-77568308`, `stackoverflow-78929469`, `stackoverflow-79873405`, `stackoverflow-79878809` |
| `verifier_scope_target` | `github-cilium-cilium-35182`, `stackoverflow-70760516`, `stackoverflow-72575736`, `stackoverflow-74614706`, `stackoverflow-75058008`, `stackoverflow-76035116`, `stackoverflow-77967675` |
| `environment_target` | `github-aya-rs-aya-1233`, `stackoverflow-62171477` |

These cases still matter for the paper because they test whether the system can
avoid a misleading source-fix narrative and instead route the failure to the
right class of cause.

## Labeling Consequences

Current labels are strong enough for taxonomy and diagnostic correctness over
all 186 cases. They are not strong enough for a blanket instruction-localization
claim.

Before a final paper run, update case labels with:

- `localization_target_kind` for every case.
- `root_cause_insn_idx` for the 22 instruction-target cases above.
- `root_cause_source_span` and acceptable alternate spans for the 23 source-span
  cases above.
- Declaration/environment/verifier-scope target labels for the remaining 23.

Until then, localization tables must report the eligible denominator and
coverage explicitly.
