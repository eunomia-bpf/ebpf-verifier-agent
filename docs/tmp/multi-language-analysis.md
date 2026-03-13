# Multi-Language Analysis of OBLIGE's Diagnostic Pipeline

Date: 2026-03-12

## Scope

This run covers the non-C GitHub issue cases under `case_study/cases/github_issues/`:

- Rust / Aya: 18 cases
- Go / Cilium: 7 cases

For comparison, I also included the only C GitHub issue case in the same directory:

- C baseline: 1 case (`github-facebookincubator-katran-149.yaml`)

## Log Scan

All matched non-C cases already have non-empty verifier logs:

| Language | Matched cases | Cases with verifier log |
| --- | ---: | ---: |
| Rust / Aya | 18 | 18 |
| Go / Cilium | 7 | 7 |

## Repository-Specific Adjustment

The literal snippet in the task needed two small fixes to match the current repository state:

- GitHub issue YAMLs store the log under `verifier_log.combined`, not as a top-level string.
- `interface.extractor.rust_diagnostic.generate_diagnostic()` currently has the signature `generate_diagnostic(verifier_log, catalog_path=None)`. Passing source code as the second positional argument would be interpreted as `catalog_path`, so I ran the repository-correct equivalent instead.

## Batch Results

`generate_diagnostic()` succeeded for every logged non-C case.

The table below separates three notions of output quality:

- `Any obligation`: `metadata.obligation` exists.
- `Specific obligation`: obligation is not just a generic fallback like `safety_violation` or `verifier_limits`.
- `BTF/source in log`: `parse_trace(...).has_btf_annotations` is true.
- `Real file path in output`: rendered `source_span.path` or `metadata.proof_spans[*].path` is an actual filename rather than `<bytecode>` or `<source>`.

| Language | Cases with log | Diagnostics succeeded | Any obligation | Specific obligation | BTF/source in log | Real file path in output | Non-empty proof spans | Avg proof spans | Multi-span cases | `OBLIGE-UNKNOWN` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rust / Aya | 18 | 18 | 10/18 (56%) | 5/18 (28%) | 1/18 (6%) | 1/18 (6%) | 18/18 (100%) | 1.61 | 6/18 (33%) | 0/18 |
| Go / Cilium | 7 | 7 | 6/7 (86%) | 5/7 (71%) | 3/7 (43%) | 1/7 (14%) | 7/7 (100%) | 1.29 | 1/7 (14%) | 2/7 (29%) |
| C baseline | 1 | 1 | 1/1 (100%) | 1/1 (100%) | 0/1 (0%) | 0/1 (0%) | 1/1 (100%) | 1.00 | 0/1 (0%) | 0/1 |

Important note: the rendered diagnostic JSON does not currently expose a `metadata.btf_source_file` field at all, so BTF correlation has to be measured indirectly from the parsed trace and the preserved output paths.

## Notable Cases

- Rust `github-aya-rs-aya-1233.yaml` is the best Aya example: the log contains source annotations and the output preserves real file paths (`probes.bpf.c`).
- Go `github-cilium-cilium-41522.yaml` is the best Cilium example: packet-access obligation inference succeeds and the output preserves a real file path (`builtins.h`).
- Go `github-cilium-cilium-37478.yaml` and `github-cilium-cilium-41412.yaml` contain source-style annotations in the log, but the rendered output degrades them to `<source>` instead of a stable filename.
- Go `github-cilium-cilium-41996.yaml` and `github-cilium-cilium-44216.yaml` return `OBLIGE-UNKNOWN`; both logs are wrapped or non-standard enough that classification falls back to a generic result.

## Do Rust/Go Cases Get the Same Quality Diagnostics as C Cases?

At the mechanical level, mostly yes:

- Success rate is identical: 100% for Rust, Go, and the C baseline.
- Proof-span emission is also identical: every output includes `metadata.proof_spans`.

At the informative level, not uniformly:

- Go / Cilium is closest to the C baseline on obligation quality: 6/7 cases get an obligation, and 5/7 of those are specific rather than generic.
- Rust / Aya is weaker on obligation specificity: only 5/18 cases get a specific obligation, and many of the rest collapse to verifier-limit or generic safety diagnostics.
- Go / Cilium is weaker than both Aya and the C baseline on error-id precision because 2/7 cases fall back to `OBLIGE-UNKNOWN`.
- Source correlation is weak across all languages in this GitHub issue corpus, but the limitation tracks log richness more than source language. Aya only has one source-annotated log; Cilium has three; the C baseline has none.

One limitation matters here: the C comparison set in `github_issues/` has only one case, so this is enough to judge rough parity, not enough to claim strong cross-language superiority or inferiority.

## Conclusion

OBLIGE is language-agnostic in execution, but only conditionally language-agnostic in diagnostic quality.

What works across Rust / Aya, Go / Cilium, and the C baseline:

- The parser and diagnoser run successfully on all logged cases.
- `failure_class` and `metadata.proof_spans` are emitted consistently.
- Obligation inference works for many non-C logs without any frontend-language-specific parsing.

What is still not uniformly language-agnostic:

- Diagnostic fidelity drops sharply when logs are thin, wrapped, or non-standard.
- Source correlation depends on verifier-side source annotations and is rarely preserved as a real file path in the final output.
- The output schema does not currently expose explicit BTF-source metadata, which makes BTF correlation hard to measure directly.

The defensible claim from this run is:

- OBLIGE is language-agnostic for trace-driven execution of the diagnostic pipeline.
- OBLIGE is not yet uniformly language-agnostic in realized diagnostic quality; the main driver is verifier-log richness, not the frontend language by itself.
