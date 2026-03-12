# Regression Fix Report

Date: 2026-03-12

## Scope

Fixed the `rust_diagnostic.py` fallback path so OBLIGE no longer degrades below the raw verifier message on simple contract/protocol/context failures when the proof engine only returns a thin reject-site result.

Key changes:

- Scan the full verifier log for a better reject line when `parse_log(...)` lands on generic wrappers such as `Invalid argument (os error 22)` or `arg#0 reference type('UNKNOWN ') size cannot be determined: -22`.
- Prefer pattern-specific note/help text for:
  - `type=X expected=Y`
  - `Possibly NULL pointer`
  - iterator protocol violations
  - dynptr protocol violations
  - callback / lock context violations
  - reference leak / unreleased reference
  - helper unavailable / unknown helper environment mismatches
- Ignore proof-engine results that only contribute `proof_status="unknown"` plus a rejected event, so the richer diagnoser proof story still synthesizes established/lost spans.

## Test Run

Command:

```bash
python -m pytest tests/ -x
```

Result:

- `97 passed`

## Five Regression Spot Checks

These five cases were marked as PV regressions in [`docs/tmp/pv-comparison-v2.md`](/home/yunwei37/workspace/ebpf-verifier-agent/docs/tmp/pv-comparison-v2.md). I reran `generate_diagnostic(..., catalog_path="taxonomy/error_catalog.yaml")` on each case after the fix.

| Case | Previously regressed because OBLIGE said... | Preserved raw verifier line now | New note/help outcome | Verdict |
| --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | generic iterator/BTF story + `Regenerate BTF artifacts...` | `expected an initialized iter_num as arg #0` | Note now says the iterator slot was never created; help now says initialize with the matching create/new helper before destroy. | No longer worse than PV. |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | generic env/BTF story | `arg 1 is an unacquired reference` | Note now says the dynptr reference was already released or never acquired; help now says release/discard exactly once and stop using it after release. | No longer worse than PV. |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | generic proof-loss + `Regenerate BTF artifacts...` | `function calls are not allowed while holding a lock` | Note now says the call happens while a lock is still held; help now says move the call out of the locked region or unlock first. | No longer worse than PV. |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | generic lowering-artifact advice (`unsigned clamp...`) | `R1 type=scalar expected=fp` | Note now explains that `R1` is a scalar where a stack pointer is required; help now says pass a real stack pointer instead of a forged scalar value. | No longer worse than PV. |
| `github-aya-rs-aya-1233` | generic verifier-limit advice (`Split the program with tail calls...`) | `program of this type cannot use helper bpf_probe_read#4` | Note now states the helper is not permitted in this program type; help now says use an allowed helper or move the logic to a compatible program type. | No longer worse than PV. |

## Notes

- The report above is a spot check, not a full rerun of the entire 30-case table.
- The fallback is now conservative in the intended direction: when OBLIGE cannot tell a richer proof story, it keeps the specific verifier reject line and derives advice from that line instead of replacing it with a generic environment/verifier-limit repair.
