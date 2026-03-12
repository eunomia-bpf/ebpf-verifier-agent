# Quality Fix Round 2 Report

## Scope

Implemented the requested Priority 0 and Priority 1 fixes in:

- `interface/extractor/log_parser.py`
- `taxonomy/error_catalog.yaml`
- `interface/extractor/diagnoser.py`
- `interface/extractor/proof_analysis.py`
- `interface/extractor/trace_parser.py`

Added focused regressions in:

- `tests/test_log_parser.py`
- `tests/test_trace_parser.py`
- `tests/test_proof_analysis.py`
- `tests/test_diagnoser.py`
- `tests/test_renderer.py`

## What Changed

### Priority 0

- `log_parser._select_error_line(...)`
  - penalizes source comments beginning with `;`
  - penalizes `libbpf:` wrapper lines when a stronger verifier symptom appears later
  - penalizes `processed ...` summaries more aggressively
  - rewards exact verifier symptom lines so function names like `invalid_*` stop winning
  - normalizes leading `:` prefixes from abbreviated tc-style logs

- `taxonomy/error_catalog.yaml`
  - `OBLIGE-E005`: added `unbounded memory access` and len-pair coverage
  - `OBLIGE-E006`: added `PTR_TO_PACKET_END prohibited`
  - `OBLIGE-E019`: added `the prog does not allow writes to packet data` and widened `must be a known constant`
  - `OBLIGE-E020`: added full `irq flag as arg#0` patterns
  - `OBLIGE-E021`: added `func_info/subprogs`, `failed to find kernel BTF type ID`, and BTF `Invalid name`
  - `OBLIGE-E023`: added `invalid bpf_context access` and `pointer comparison prohibited`

- `diagnoser._classify(...)`
  - added fallback heuristics for:
    - `invalid bpf_context access`
    - `pointer comparison prohibited`
    - `failed to find kernel BTF type ID`
  - improved preferred-error-line selection when trace-level error text is more generic than the parsed log line

### Priority 1

- `proof_analysis.analyze_proof_lifecycle(...)`
  - no longer emits `satisfied` for failing logs that lack a parsed rejected event
  - returns `unknown` for failing zero-trace logs without a conservative direct rejection signal
  - returns `never_established` for zero-trace direct rejection lines such as `invalid access ...`, `invalid mem access`, `invalid bpf_context access`, `pointer comparison prohibited`, and `pointer type ... must point`

- `trace_parser.py`
  - recovers embedded instructions after wrapper prefixes like:
    - `...: 9: (79) ...`
    - `:599: (07) ...`
  - strips wrapper text before instruction matching
  - preserves inline rejection text from abbreviated one-line loader logs
  - handles `:;` source annotations

## Validation

Commands run:

```bash
python -m pytest tests/ -v
python eval/batch_diagnostic_eval.py
```

### Test Suite

- `44/44` tests passed

### Batch Eval

- Eligible cases: `241`
- Successes: `241`
- Crashes: `0`

### Headline Metrics

- `taxonomy_class=unknown`: `14 -> 2`
- `proof_status=satisfied`: `3 -> 0`
- Remaining unknown-taxonomy cases:
  - `stackoverflow-68815540`
  - `stackoverflow-78633443`

### The 3 Former False-`satisfied` Cases

- `stackoverflow-76994829` -> `never_established`
- `stackoverflow-77713434` -> `never_established`
- `stackoverflow-78591601` -> `never_established`

### Fixed Case Families Confirmed in Batch Output

- `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly` -> `OBLIGE-E019`
- `kernel-selftest-dynptr-fail-dynptr-slice-var-len1` -> `OBLIGE-E005`
- `kernel-selftest-dynptr-fail-dynptr-slice-var-len2` -> `OBLIGE-E019`
- `kernel-selftest-irq-irq-save-invalid` -> `OBLIGE-E020`
- `stackoverflow-60506220` -> `OBLIGE-E006`
- `stackoverflow-67402772` -> `OBLIGE-E023`
- `stackoverflow-69192685` -> `OBLIGE-E021`
- `stackoverflow-71351495` -> `OBLIGE-E023`
- `stackoverflow-77462271` -> `OBLIGE-E021`
- `stackoverflow-77568308` now parses the embedded instruction and renders a rejected span from `r3 = *(u64 *)(r1 +96)`
- `github-aya-rs-aya-1490` -> `OBLIGE-E021`

## Current Proof-Status Distribution

- `established_then_lost`: `90`
- `never_established`: `119`
- `unknown`: `20`
- `established_but_insufficient`: `12`
- `satisfied`: `0`

## Residuals

- Unknown taxonomy is now down to the 2 cases that were already considered genuinely under-specified from the raw logs.
- The targeted fixes succeeded, but the overall proof-status distribution shifted beyond just removing the 3 false `satisfied` outputs:
  - baseline from `output-quality-analysis.md`: `97 established_then_lost`, `107 never_established`, `21 unknown`, `13 established_but_insufficient`, `3 satisfied`
  - current batch: `90 established_then_lost`, `119 never_established`, `20 unknown`, `12 established_but_insufficient`, `0 satisfied`
- I did not audit all seven `established_then_lost -> never_established` shifts in this round. If that distribution matters, the next pass should diff those specific case IDs and check whether proof-analysis is now more conservative or whether a separate regression slipped in.
