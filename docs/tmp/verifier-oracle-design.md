# Verifier-Pass Oracle: Design and Integration Plan

**Date:** 2026-03-13
**Status:** Implemented — `eval/verifier_oracle.py`

## Executive Summary

A functional verifier-pass oracle has been implemented. It compiles LLM-generated eBPF C code and loads it into the kernel verifier via `bpftool`, providing an objective pass/fail signal for the A/B repair experiment. This replaces text-similarity scoring with ground-truth verifier acceptance.

---

## Feasibility Findings

All checks performed on this machine (Linux 6.15.11, Ubuntu):

| Check | Result |
|-------|--------|
| `clang --version` | 18.1.3 — available |
| `bpftool version` | v7.7.0, libbpf v1.7, with llvm + skeletons |
| `/usr/include/vmlinux.h` | Present (system vmlinux.h installed) |
| `/usr/include/bpf/bpf_helpers.h` | Present (libbpf dev headers) |
| Compile BPF with `-I/usr/include` | **Success** |
| `sudo bpftool prog load` | **Success** (sudo passwordless, CAP_BPF in bounding set) |
| Verifier rejection of buggy program | **Success** (correct error, exit 255) |
| Verifier acceptance of good program | **Success** (exit 0) |

**Chosen approach: bpftool prog load (level b)**
- Compile with `clang -target bpf -O2 -I/usr/include`
- Load with `sudo bpftool -d prog load obj.o /sys/fs/bpf/oblige_<pid>_<n>`
- `bpftool -d` captures the full verifier log in stderr (with BEGIN/END PROG LOAD LOG markers)
- Exit code 0 = verifier pass; 255 = verifier rejection
- Pin path cleaned up immediately after load

**Why vmlinux.h over kernel uapi headers:**
Direct inclusion of `linux/bpf.h` from kernel uapi headers fails because `asm/types.h` lookup fails for cross-compiled BPF. Using `/usr/include/vmlinux.h` (generated from kernel BTF by `bpftool btf dump file /sys/kernel/btf/vmlinux format c`) avoids all include-path complications and is the modern libbpf-based approach.

---

## Implementation

**File:** `/home/yunwei37/workspace/ebpf-verifier-agent/eval/verifier_oracle.py`

### Core API

```python
def verify_fix(
    source_code: str,
    prog_type: str | None = None,
    verifier_log_hint: str = "",
    compile_only: bool = False,
) -> OracleResult:
```

**Returns:**
```python
@dataclass
class OracleResult:
    compiles: bool              # True if clang succeeded
    verifier_pass: bool | None  # True/False from kernel verifier; None if compile failed
    error: str | None           # Concise error message
    compile_stderr: str | None  # Raw clang stderr
    verifier_log: str | None    # Verifier output (BEGIN/END PROG LOAD LOG section)
    template_used: str | None   # Which template won
    include_flags_used: list[str]
    was_wrapped: bool           # True if snippet was auto-wrapped
    compile_warnings: list[str]
```

### Handling Incomplete Snippets

SO/GitHub cases provide source snippets that are often incomplete (no `#include`, no `SEC("license")`). The oracle handles this via an auto-wrapping system:

1. **Detect complete programs:** check for `#include` + `SEC("license")` — try as-is first.
2. **Wrap in template:** inject minimal includes (`vmlinux.h`, `bpf_helpers.h`) + license section.
3. **Two include strategies:** `vmlinux.h`-based (modern) and uapi-based (legacy) — tried in order.
4. **Four candidates per call:** `raw-vmlinux`, `raw-uapi`, `wrap-vmlinux`, `wrap-uapi`.

### Program Type Detection

Regex-based detection from source + verifier log: xdp, tc, kprobe, kretprobe, raw_tp, tracepoint, perf_event, cgroup, socket, lwt, fentry, fexit, lsm, iter. Default: `xdp`.

### Case-level API

```python
def verify_case(case_data: dict, compile_only: bool = False) -> OracleResult:
```

Accepts a case YAML dict, tries `source_code` field then `source_snippets` (sorted longest-first), returns first result that compiles.

---

## Test Results

**File:** `/home/yunwei37/workspace/ebpf-verifier-agent/tests/test_verifier_oracle.py`

Tests validated manually during development:

| Test | Expected | Observed |
|------|----------|----------|
| `GOOD_XDP` compile-only | compiles=True | ✓ |
| `BAD_SYNTAX` compile-only | compiles=False | ✓ |
| `SNIPPET_XDP_GOOD` compile-only | compiles=True, was_wrapped=True | ✓ |
| `GOOD_XDP` full verifier | verifier_pass=True | ✓ |
| `BAD_XDP_OOB` full verifier | verifier_pass=False | ✓ |
| Verifier log contains error | "invalid access to packet" in log | ✓ |
| `sudo bpftool prog load` (XDP pass) | exit 0 | ✓ |
| `sudo bpftool prog load` (OOB buggy) | exit 255, log has error | ✓ |

**Key observation:** The verifier correctly catches the OOB access in `BAD_XDP_OOB`:
```
invalid access to packet, off=26 size=4, R1(id=0,off=26,r=0)
R1 offset is outside of the packet
```

---

## Limitations and Mitigations

### 1. Incomplete Source Code (Most Important)

**Problem:** Most SO/GitHub cases provide snippets, not full programs. A snippet cannot be compiled standalone.

**Mitigation:** Auto-wrap in template. This works for:
- Simple XDP/TC/kprobe programs with standard helpers
- Programs that only reference standard kernel structs in vmlinux.h

**Failure cases (oracle returns `compiles=False` even if the logic is correct):**
- Code referencing private kernel structs not in vmlinux.h
- Code using map types that require BTF-typed maps to load
- Programs with external function calls or multi-file dependencies

**Metric:** `compiles` rate separately from `verifier_pass` rate. Even compile-only pass/fail is valuable signal.

### 2. Program Type Mismatch

**Problem:** Wrapping a TC snippet in an XDP context (or vice versa) may cause verifier rejection for context access reasons, not program logic.

**Mitigation:** Extract prog_type from `SEC(...)` annotations in the source before wrapping. For ambiguous cases, report `prog_type_uncertain=True` in the result.

### 3. Map Dependencies

**Problem:** Programs using `bpf_map_lookup_elem` referencing maps declared elsewhere fail compilation.

**Mitigation:** The wrap template does not inject synthetic maps. Programs with external map references will fail to compile (or fail to load). This is an honest signal — if the LLM generates a fix that uses an undeclared map, it's genuinely wrong.

### 4. Helper Availability

**Problem:** Some helpers are only available for specific program types or kernel versions. The oracle runs on kernel 6.15 (recent), so most helpers are available. Older-kernel-specific failures will not be reproduced faithfully.

**Mitigation:** Note kernel version in result metadata; flag env_mismatch taxonomy cases as `oracle_limited=True`.

### 5. sudo Dependency

**Problem:** `sudo bpftool` is required for full verifier testing. In CI or restricted environments, only compile-only mode is available.

**Mitigation:** `compile_only=True` flag provides graceful degradation. `verify_pass` returns `None` (not False) when unavailable, so callers can distinguish "unknown" from "rejected".

---

## Integration into A/B Experiment

### Changes to `eval/repair_experiment_v3.py` (or v4)

**Step 1: Import oracle**
```python
from eval.verifier_oracle import verify_fix, OracleResult
```

**Step 2: Extract generated fix code from LLM response**
The LLM response already contains a "fix" field. Extract the code block:
```python
def extract_code_from_response(response: str) -> str | None:
    """Extract ```c ... ``` code block from LLM markdown response."""
    m = re.search(r'```(?:c|C)?\s*\n(.*?)```', response, re.DOTALL)
    return m.group(1).strip() if m else None
```

**Step 3: Run oracle on LLM output**
```python
oracle_result_a = verify_fix(
    source_code=code_a,
    verifier_log_hint=case.verifier_log,
    compile_only=False,
)
oracle_result_b = verify_fix(
    source_code=code_b,
    verifier_log_hint=case.verifier_log,
    compile_only=False,
)
```

**Step 4: Add oracle fields to ConditionResult**
```python
@dataclass
class ConditionResult:
    ...
    oracle_compiles: bool | None = None
    oracle_verifier_pass: bool | None = None
    oracle_verifier_log: str | None = None
    oracle_error: str | None = None
```

**Step 5: New metrics in results report**

| Metric | Description |
|--------|-------------|
| `compile_rate_A` / `compile_rate_B` | % of LLM fixes that compile |
| `verifier_pass_rate_A` / `verifier_pass_rate_B` | % that pass verifier |
| `oracle_delta` | `verifier_pass_rate_B - verifier_pass_rate_A` (main A/B signal) |
| `source_oracle_agree` | % where text-similarity and verifier agree |

**Step 6: Handle incomplete source gracefully**
Cases where neither A nor B generates code that compiles are logged as `oracle_limited=True` and excluded from verifier pass rate denominator (but included in compile rate denominator).

### Expected Impact on Metrics

Current metric (text similarity) is noisy:
- LLM can output the right *concept* with slightly different wording → false negative
- LLM can output plausible-sounding wrong code → false positive

Oracle provides ground truth:
- A fix that compiles + passes verifier is objectively better than one that doesn't
- Can measure: "does OBLIGE diagnostic actually help the LLM generate code the kernel accepts?"

---

## CLI Usage

```bash
# Verify a single C file
python -m eval.verifier_oracle verify-file path/to/prog.c

# Verify a case YAML
python -m eval.verifier_oracle verify-case case_study/cases/stackoverflow/stackoverflow-70091221.yaml

# Compile-only (no sudo needed)
python -m eval.verifier_oracle verify-case stackoverflow-70091221.yaml --compile-only

# Batch over a directory
python -m eval.verifier_oracle batch case_study/cases/stackoverflow/ --limit 20 --out results.json
```

---

## Next Steps

1. **Run test suite:** `pytest tests/test_verifier_oracle.py -v`
2. **Smoke test on real cases:** `python -m eval.verifier_oracle batch case_study/cases/stackoverflow/ --limit 10 --compile-only`
3. **Integrate into repair_experiment_v4.py:** Add oracle call after LLM fix extraction
4. **Run full A/B v4:** Compare `verifier_pass_rate_A` vs `verifier_pass_rate_B`
5. **Analyze oracle-limited cases:** How many SO snippets can we actually compile and load?
