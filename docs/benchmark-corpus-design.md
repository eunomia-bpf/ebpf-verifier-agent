# Benchmark Corpus Layout Design

Status: draft  
Date: 2026-04-29

## Position

The benchmark should be simple and strict:

> A case is valuable for the primary eval only if it can be reproduced locally
> and its active `verifier.log` is captured by our harness under a pinned
> environment.

Kernel selftests, Stack Overflow, GitHub issues, and commits can all be used as
case discovery sources. They do not define the benchmark input. The benchmark
input is the locally replayed program plus the locally captured verifier log.

If a case cannot be built, loaded, rejected, and captured locally, it is not part
of the primary benchmark. It can be kept as notes or future work, but it should
not affect headline numbers.

## Design Goals

1. Keep one benchmark directory, not separate source/reproducer/capture trees.
2. Put everything needed to audit a case under that case's directory.
3. Use one manifest as the only eval entry point.
4. Require every primary case to have a local `verifier.log`.
5. Bind labels to the exact captured log through `capture_id` and `log_sha256`.
6. Do not preserve legacy layout complexity in the new design.

## Minimal Directory Layout

```
bpfix-bench/
├── README.md
├── manifest.yaml
├── environment.yaml
├── checksums.txt
└── cases/
    └── <case_id>/
        ├── case.yaml
        ├── original.log          # optional raw excerpt from source
        ├── original.md           # optional post/issue/selftest notes
        ├── prog.c                # or prog.bpf.c / main.rs / etc.
        ├── Makefile
        ├── extra/                # optional headers/config
        ├── fixed/                # optional, only for repair eval
        │   ├── prog.c
        │   ├── Makefile
        │   └── extra/
        ├── verifier.log          # required for primary eval
        ├── build.stdout
        ├── build.stderr
        ├── load.stdout
        ├── load.stderr
        └── hashes.txt
```

There are no separate `sources/`, `reproducers/`, or `captures/` folders. Those
concepts are fields inside `case.yaml`.

## Case Rule

Each case directory is self-contained. A reviewer should be able to inspect one
directory and answer:

- where the case came from;
- what code was run;
- what command built it;
- what command loaded it;
- what verifier log was captured;
- how the label was assigned;
- whether the local failure matches the original external report.

## `manifest.yaml`

Path: `bpfix-bench/manifest.yaml`

The manifest is the only file eval scripts should read to discover cases.

```yaml
schema_version: bpfix.benchmark/v1
benchmark_id: bpfix-bench-v1
frozen_at: "2026-04-29"
environment_id: kernel-6.15.11-clang-18-log2
description: "Locally reproducible verifier-log benchmark."

cases:
  - case_id: kernel-selftest-dynptr-invalid-read-2cc2b993
    path: cases/kernel-selftest-dynptr-invalid-read-2cc2b993
    split: main
    source_kind: kernel_selftest
    family_id: dynptr-invalid-read
    representative: true
    capture_id: kernel-selftest-dynptr-invalid-read-2cc2b993__kernel-6.15.11-clang-18-log2
    log_sha256: "<sha256>"

  - case_id: stackoverflow-70750259
    path: cases/stackoverflow-70750259
    split: main
    source_kind: stackoverflow
    family_id: packet-pointer-provenance
    representative: true
    capture_id: stackoverflow-70750259__kernel-6.15.11-clang-18-log2
    log_sha256: "<sha256>"

summary:
  total_cases: 0
  main_cases: 0
  source_counts: {}
  taxonomy_counts: {}
```

`checksums.txt` stores the manifest hash. Do not put `manifest_sha256` inside
`manifest.yaml`, because that creates a self-reference.

## `environment.yaml`

Path: `bpfix-bench/environment.yaml`

```yaml
schema_version: bpfix.environment/v1
environment_id: kernel-6.15.11-clang-18-log2
kernel:
  version: "6.15.11"
  config_sha256: "<sha256>"
  btf_path: /sys/kernel/btf/vmlinux
toolchain:
  clang: "18.1.8"
  llc: "18.1.8"
  bpftool: "v7.5.0"
  libbpf: "1.5.0"
harness:
  name: bpfix-replay
  script: case_study/replay_case.py
  verifier_log_level: 2
  timeout_sec: 30
runtime:
  arch: x86_64
  requires_root_or_cap_bpf: true
```

One frozen benchmark version uses one primary environment. Cross-kernel replay
can be a separate benchmark version or a separate appendix, not the default
layout.

## `case.yaml`

Path: `bpfix-bench/cases/<case_id>/case.yaml`

```yaml
schema_version: bpfix.case/v1
case_id: stackoverflow-70750259

source:
  kind: stackoverflow       # kernel_selftest | stackoverflow | github_issue | commit
  url: https://stackoverflow.com/questions/70750259
  repository: null
  commit: null
  upstream_file: null
  upstream_section: null
  collected_at: "2026-03-13"
  raw_excerpt_files:
    - original.md
    - original.log

reproducer:
  status: ready             # ready | blocked | retired
  reconstruction: original  # original | minimized | reconstructed
  language: C
  program_type: socket_filter
  source_file: prog.c
  fixed_dir: fixed          # optional; absent unless repair eval needs it
  build_command: make
  object_path: prog.o
  load_command: bpftool prog load prog.o /sys/fs/bpf/bpfix_case
  notes: "Build glue added around the original code snippet."

capture:
  capture_id: stackoverflow-70750259__kernel-6.15.11-clang-18-log2
  environment_id: kernel-6.15.11-clang-18-log2
  captured_at: "2026-03-13T18:42:10Z"
  build_status: success
  load_status: verifier_reject
  verifier_pass: false
  exit_code: 255
  verifier_log: verifier.log
  log_sha256: "<sha256>"
  log_quality: trace_rich
  terminal_error: "math between pkt pointer and register with unbounded min value is not allowed"
  rejected_insn_idx: 39
  object_sha256: "<sha256>"
  source_sha256: "<sha256>"

external_match:
  required: true
  status: partial           # exact | partial | semantic | not_applicable
  policy: terminal_error
  matched_messages:
    - "math between pkt pointer and register with unbounded min value is not allowed"
  notes: "Terminal verifier error matches the original post excerpt."

label:
  capture_id: stackoverflow-70750259__kernel-6.15.11-clang-18-log2
  log_sha256: "<sha256>"
  taxonomy_class: lowering_artifact
  error_id: BPFIX-E005
  confidence: high
  label_source: adjudicated
  root_cause_description: "Compiler/verifier-unfriendly lowering loses packet-bound proof before pointer arithmetic."
  rejected_insn_idx: 39
  root_cause_insn_idx: 28
  rejected_line: "..."
  root_cause_line: "..."
  localization_confidence: high
  fix_type: reorder
  fix_direction: "Move the bounds check so the verifier can connect the checked length to the packet access."

reporting:
  split: main
  family_id: packet-pointer-provenance
  duplicate_group: null
  representative: true
  tags:
    - external_user_report
    - reconstructed
```

The label repeats `capture_id` and `log_sha256` on purpose. Localization labels
depend on the exact verifier trace, so a validator must reject a case if the
label hash does not match the captured log hash.

## Primary Case Admission Rules

A case enters `split: main` only if all conditions hold:

1. `reproducer.status == ready`.
2. `reproducer.reconstruction` is `original`, `minimized`, or `reconstructed`.
3. The buggy program builds in the pinned environment.
4. The buggy program is rejected by the verifier in the pinned environment.
5. `verifier.log` was captured locally by the benchmark harness.
6. Harness verifier log level is `2` or an explicitly documented equivalent.
7. `verifier.log` exists, is non-empty, and matches `capture.log_sha256`.
8. The parser can recover a terminal error from `verifier.log`.
9. The parser can recover or validate `capture.rejected_insn_idx`.
10. `capture.source_sha256` and `capture.object_sha256` are present.
11. `label.capture_id == capture.capture_id`.
12. `label.log_sha256 == capture.log_sha256`.
13. For Stack Overflow, GitHub, and commit-derived cases, `external_match.status`
    is `exact`, `partial`, or `semantic`.
14. `semantic` matches require a short auditable policy, not free-form judgment.
15. `reporting.family_id` and `reporting.representative` are present.

No exception path should allow excerpt-only logs, message-only loader errors, or
synthetic no-log cases into `split: main`.

## Non-Primary Cases

Cases that cannot be reproduced locally should not be stored in the primary
benchmark directory. Keep them in a separate scratch or legacy area until they
become reproducible.

Recommended handling:

- Stack Overflow/GitHub excerpt but no buildable reproducer: not in
  `bpfix-bench`.
- Commit diff but no verifier reproduction: not in `bpfix-bench`.
- Synthetic case without verifier log: not in `bpfix-bench`.
- Case accepted by the current verifier: not in `split: main`; optionally keep
  outside the benchmark as cross-version evidence.
- Case with only message-level stderr and no trace-rich verifier log: not in
  `split: main`.

This keeps the benchmark honest: the main number measures diagnosis over local,
auditable verifier traces.

## Validator

Add one validator script before moving eval scripts:

```
python3 tools/validate_benchmark.py bpfix-bench
```

It should fail on:

- missing files referenced by `manifest.yaml`;
- duplicate `case_id`;
- `manifest.log_sha256` mismatch with `cases/<case_id>/case.yaml`;
- `case.yaml` hash mismatch with actual `verifier.log`;
- missing or empty `verifier.log`;
- non-`verifier_reject` primary case;
- missing terminal error;
- missing rejected instruction index;
- label hash/capture mismatch;
- unsupported `source.kind`;
- external case without acceptable `external_match.status`;
- `split: main` case with `reconstruction: synthetic`;
- missing `family_id` or `representative`.

Eval scripts should refuse to run on an invalid benchmark.

## Eval Script Contract

All eval scripts should take a benchmark path:

```
python3 eval/batch_diagnostic_eval.py --benchmark bpfix-bench
python3 eval/ablation_eval.py --benchmark bpfix-bench
python3 eval/localization_eval.py --benchmark bpfix-bench
```

They should:

1. run the validator or require a validator stamp;
2. read `manifest.yaml`;
3. load each case's `verifier.log`;
4. join labels from the same case's `case.yaml`;
5. write result rows with `benchmark_id`, `case_id`, `capture_id`,
   `log_sha256`, `source_kind`, `family_id`, and `representative`.

No eval script should recursively scan `case_study/cases/*` for headline
numbers.

## Import Policy From Current Corpus

Migration cost is not a design constraint. The import rule is:

> Import only cases that can satisfy the new primary admission rules.

Current data should be treated as raw material:

- `case_study/cases/kernel_selftests_verified/<case_id>/`: likely easiest to
  import if it has source, build command, rejection status, and captured log.
- `case_study/cases/so_gh_verified/<case_id>/`: import only when the local
  rejection matches the original report.
- `case_study/cases/eval_commits_verified/<case_id>/`: import only if the buggy
  version is rejected locally and has a captured verifier log. A "verified"
  fixed/buggy pair where both pass is not a diagnostic benchmark case.
- `case_study/cases/stackoverflow/*.yaml` and `github_issues/*.yaml`: use only
  as discovery and original evidence; do not import excerpt-only cases.
- `case_study/cases/eval_commits_synthetic/*.yaml`: do not import unless a real
  local verifier rejection is produced.

Old manifests and old YAML schemas do not need to be preserved inside
`bpfix-bench`. If old results are needed, keep them under legacy docs; they
should not shape the new benchmark.

## Build Order

1. Create `bpfix-bench/environment.yaml`.
2. Pick a small seed set of reproducible cases, preferably 20 selftests and 10
   external SO/GH cases.
3. Convert each seed into one self-contained case directory.
4. Generate `case.yaml`, `verifier.log`, logs, and hashes for each case.
5. Write `manifest.yaml`.
6. Implement `validate_benchmark.py`.
7. Run the validator and fix every failure.
8. Update eval scripts to consume `bpfix-bench`.
9. Freeze the first real benchmark only after validator passes.
10. Expand case count after the structure is proven.

This deliberately favors a small clean benchmark over a large mixed corpus.

## Reporting Requirements

Every paper result using this benchmark should report:

- benchmark ID;
- manifest hash from `checksums.txt`;
- environment ID;
- number of primary cases;
- source composition;
- taxonomy distribution;
- reconstruction distribution: original, minimized, reconstructed;
- external match distribution: exact, partial, semantic, not applicable;
- duplicate-family counts;
- case-weighted and family-weighted metrics.

The main claim should use only `split: main`. There is no headline metric over
unreproduced external excerpts.

## Why This Is Simpler

The design has only one new benchmark directory and one case format. It avoids
maintaining separate source, reproducer, capture, and label trees. The tradeoff
is intentional: any case that cannot be normalized into this format is excluded
from the primary eval.

That tradeoff is appropriate for a systems paper. A smaller benchmark with
uniform local reproduction is more defensible than a larger benchmark with mixed
log provenance.
