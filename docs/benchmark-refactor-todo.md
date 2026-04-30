# Benchmark Refactor TODO

Date: 2026-04-29  
Status: completed

## Goal

Replace the mixed legacy evaluation corpus entry points with a simple
top-level `bpfix-bench/` benchmark layout. A case is eligible for the primary
diagnostic eval only if `tools/validate_benchmark.py --replay bpfix-bench`
can rebuild, reload, recapture, and re-parse the verifier failure locally.

## Acceptance Criteria

- `bpfix-bench/manifest.yaml` exists and is the benchmark discovery entry point.
- Each imported primary case is self-contained under
  `bpfix-bench/cases/<case_id>/`.
- Each primary case has `case.yaml`, source, `Makefile`, and `capture.yaml`.
  Build/load stdout/stderr files are optional retained artifacts when the
  harness stores them.
- `fixed/` is optional and only used when `repair.eligible: true`.
- `tools/validate_benchmark.py --replay bpfix-bench` actually runs build/load
  for every listed benchmark case.
- The validator rejects cases that build but do not reproduce a verifier
  rejection.
- Eval entry points can consume `--benchmark bpfix-bench` without scanning
  `case_study/cases/*` for headline results.
- A reviewer subagent audits the refactor after implementation.

## Work Packages

1. Benchmark scaffold and importer - completed
   - Owner: worker A.
   - Write scope: `bpfix-bench/`, optional importer helper under
     `tools/create_bpfix_bench.py`.
   - Import a small seed set from verified artifacts only.
   - Do not include excerpt-only or synthetic no-log cases.

2. Replay validator - completed
   - Owner: worker B.
   - Write scope: `tools/validate_benchmark.py`, `tools/replay_case.py` if
     needed.
   - Implement `--replay` as the required path.
   - Re-run each case's build/load command and compare terminal error,
     rejected instruction and log quality.

3. Eval benchmark adapter - completed
   - Owner: worker C.
   - Write scope: `eval/benchmark_loader.py` and minimal CLI changes in eval
     scripts.
   - Add `--benchmark bpfix-bench` support without removing legacy behavior.
   - Ensure benchmark-mode rows carry `benchmark_id`, `case_id`, `capture_id`,
     `source_kind`, `family_id`, and `representative`.

4. Integration and review - completed
   - Owner: main agent plus reviewer subagent.
   - Resolve conflicts, run validator, then ask a reviewer subagent to inspect
     the final changes.

## Validation Commands

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Final local result:

```text
passed: 102
failed: 0
total_cases: 102
```

```text
kernel_selftest: 79
stackoverflow: 23
stackoverflow exact/partial: 21
stackoverflow semantic: 2
```

The benchmark is not considered valid on another host until replay passes again
in that host's pinned environment.
