# Obligation Expansion Round 3 Report

Date: 2026-03-12

## Result

- Baseline before this round: `346/412 = 84.0%`
- After this round: `392/412 = 95.1%`
- Net gain: `+46` covered cases
- Remaining uncovered: `20`

## What changed

I expanded `interface/extractor/proof_engine.py` in two layers:

1. Conservative direct matching in `infer_formal_obligation()`
   - Packet-helper access failures now map to `packet_access`
   - Helper/kfunc pointer-contract failures now map to `helper_arg`
     - Examples: `must be a rcu pointer`, `has no valid kptr`, `unsupported reg type ... dynptr_from_mem`, `expects refcounted ...`
   - `invalid bpf_context access ...` now maps to `memory_access`
   - BTF metadata failures now map to `btf_reference_type`
   - Dynptr protocol matching now includes `Dynptr has to be an uninitialized dynptr`

2. Aggressive fallback in `infer_obligation()`
   - Tries alternate candidate instructions when the selected failing instruction is noisy
   - Adds error-line-only recovery for:
     - `verifier_limits`
     - `btf_reference_type`
     - `packet_access`
     - `map_value_access`
     - `helper_arg`
     - `scalar_deref`
     - `memory_access`
   - Adds a generic `safety_violation` family for verifier-specific failures where the concrete family cannot be recovered safely

## High-yield groups covered

- Verifier-limit summaries and structure failures
  - `processed ... insns`
  - `combined stack size of ...`
  - `BPF program is too large`
  - `back-edge from insn ...`
- Dynptr-related failures
  - uninitialized dynptr
  - dynptr-from-mem argument type mismatch
  - dynptr packet-write restrictions
- Trusted/rcu/kptr helper contract failures
  - `R1 must be a rcu pointer`
  - `R2 must be a rcu pointer`
  - `R1 has no valid kptr`
  - release/acquire pointer-contract mismatches
- BTF metadata failures
  - missing `btf func_info`
  - `func_info`/subprog count mismatch
  - missing kernel BTF type ID
  - invalid BTF name
- Error-line-only packet/map/memory families

## Validation

- Command: `python -m pytest tests/test_proof_engine.py -x`
- Result: `43 passed`

## Remaining uncovered cases

The remaining 20 cases are mostly not clean verifier obligations:

- Wrapper/environment failures
  - `Permission denied`
  - `Invalid argument (os error 22)`
  - `Failed to run ...`
  - `failed to load object ...`
- Tool/build noise
  - `Finished dev profile ...`
- Kernel/verifier bug report
  - `REG INVARIANTS VIOLATION ...`
- Two dynptr cases where the parser surfaces only the raw call line
  - `call bpf_dynptr_slice_rdwr#71568`

## Files changed

- `interface/extractor/proof_engine.py`
- `tests/test_proof_engine.py`
