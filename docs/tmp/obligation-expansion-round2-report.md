# Obligation Expansion Round 2 Report

Date: 2026-03-12

## Result

- Start: `297/412` covered (`72.1%`)
- End: `346/412` covered (`84.0%`)
- Net gain: `+49` covered cases
- Remaining uncovered: `66`

This clears the `80%+` target.

## What Changed

Expanded `interface/extractor/proof_engine.py` to cover the highest-frequency remaining families:

- `execution_context`
  - `processed ... insns` summaries that end on `call bpf_throw#...`
  - `function calls are not allowed while holding a lock`
  - `calling kernel function ... is not allowed`
- `packet_access`
  - helper-call failures reported as `invalid access to packet ...`
- `map_value_access`
  - helper-call failures reported as `invalid access to map value ...`
- `dynptr_protocol`
  - fallback inference for `cannot overwrite referenced dynptr` even when the selected failing instruction is `exit`
- `buffer_length_pair`
  - dynptr-slice failures reported as `R4 unbounded memory access ...`
- `scalar_deref`
  - `invalid mem access 'inv'` when the trace does not preserve a useful typed pre-state

Also added regression coverage in `tests/test_proof_engine.py` for both synthetic matcher cases and real-case `parse_verifier_log()` + `parse_verifier_trace()` flows.

## High-Yield Families Recovered

These were the main previously-uncovered groups now covered:

- `24` processed-summary `bpf_throw` cases
- `6` lock-held call rejections
- `5` `calling kernel function ... is not allowed` cases
- `4` `cannot overwrite referenced dynptr` cases
- `3` helper-mediated packet-access failures
- `3` helper-mediated map-value-access failures
- `2` dynptr-slice unbounded-length failures
- `2` `invalid mem access 'inv'` failures from sparse traces

Total recovered from these targeted additions: `49` cases.

## Verification

Command:

```bash
python -m pytest tests/test_proof_engine.py -x
```

Result:

```text
41 passed in 0.43s
```

Coverage check command:

```bash
python3 -c "
import glob, yaml
from interface.extractor.log_parser import parse_verifier_log
from interface.extractor.trace_parser import parse_verifier_trace
from interface.extractor.proof_engine import infer_obligation

no_obl = []
eligible = 0
covered = 0
for f in sorted(glob.glob('case_study/cases/**/*.yaml', recursive=True)):
    with open(f) as fh:
        case = yaml.safe_load(fh)
    vlog = case.get('verifier_log', '')
    if isinstance(vlog, dict): vlog = vlog.get('combined', '')
    if not vlog or len(vlog) < 50: continue
    eligible += 1
    parsed = parse_verifier_log(vlog)
    trace = parse_verifier_trace(vlog)
    el = trace.error_line or parsed.error_line or ''
    obl = infer_obligation(trace, el)
    if obl:
        covered += 1
    else:
        no_obl.append((f.split('cases/')[-1], el[:150]))

print(f'Covered: {covered}/{eligible} ({covered/eligible*100:.1f}%)')
print(f'Uncovered: {len(no_obl)}')
"
```

Result:

```text
Covered: 346/412 (84.0%)
Uncovered: 66
```

## Remaining Repeated Gaps

The largest recurring uncovered groups after this round are:

- `6` cases with only `processed 0 insns ...`
- `4` async-stack verifier-limit cases where the selected error line is still a register dump instead of `combined stack size ...`
- `3` environment-style `Permission denied (os error 13)` cases
- `2` `math between fp pointer and register with unbounded min value is not allowed`
- `2` `attach to unsupported member ...`
- `2` `Unsupported reg type fp for bpf_dynptr_from_mem data`
- `2` `Dynptr has to be an uninitialized dynptr`
- `2` `the prog does not allow writes to packet data`

The next obvious win is improving error-line selection for async-stack/verifier-limit cases and then adding another small dynptr pass.
