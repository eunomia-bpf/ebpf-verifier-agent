# New Engine Code Review — 2026-03-13

**Verdict: The reported numbers are misleading. The 50% established_then_lost rate is driven primarily by false positives from the TransitionAnalyzer fallback path, not by genuine lifecycle analysis.**

---

## 1. Engine Code Correctness

### 1.1 monitor.py — Lifecycle Detection

The TraceMonitor is well-designed and its core logic is correct:
- It evaluates a predicate at each instruction's register state
- It tracks the first "satisfied" point and the first subsequent "violated" point
- Lines 97-101: It correctly handles re-establishment (if predicate becomes satisfied again after a loss, the loss is cleared)

**Bug found (moderate severity):** Lines 97-101 clear `loss_site` if the predicate is re-satisfied *after* a violation, but the final classification at line 112 only checks whether `loss_site is not None`. This means a trace like `satisfied -> violated -> satisfied -> violated` will report the *second* loss, not the first. Whether this is desired behavior or a bug depends on interpretation, but it means the monitor can miss the original root-cause loss point.

**No false `established_then_lost` from the monitor itself.** When no predicate is provided, it correctly returns `unknown`. The monitor is sound.

### 1.2 transition_analyzer.py — Classification Rules

The classification logic is generally correct for individual register transitions:
- `_classify_bounds_change` (line 387): Interval containment checks are correct
- `_classify_type_change` (line 484): ptr->scalar=DESTROYING, or_null->ptr=NARROWING, etc. are all correct
- `_classify_range_change` (line 546): range>0 to 0 = DESTROYING is correct

**Critical design flaw: The TransitionAnalyzer does not know which registers are proof-relevant.** When `proof_registers` is an empty set (lines 121-126), it analyzes ALL registers. This means:
- Any register initialization (e.g., `w6 = 0` at insn 0) counts as NARROWING (proof "established")
- Any subsequent type change on *any* register counts as potential DESTROYING (proof "lost")
- Result: almost every trace with >1 instruction will be classified as `established_then_lost`

This is the root cause of the inflated numbers.

**`_is_significant_widening` (line 715)** gates whether a WIDENING event counts as a loss point. It only passes if the reason string contains "unbounded", "bounds lost", "range_loss", or "type_downgrade". This filter is too weak -- any DESTROYING event passes unconditionally (line 718).

### 1.3 predicate.py — Predicate Evaluation

The predicate classes are well-structured. Issues found:

**IntervalContainment (line 38):**
- Line 69-70: When `rng == 0`, it returns `"unknown"` rather than `"violated"`. Comment says "no range tracked yet" but this is the exact condition that should be "violated" for packet access (range=0 means no bytes proven accessible).

**TypeMembership (line 102):**
- Lines 124-126: Uses prefix matching (`allowed.lower() in type_lower or type_lower.startswith(allowed.lower())`). This means `allowed_types={"ptr"}` will match `"ptr_or_null_task"` because `"ptr"` is in `"ptr_or_null_task"`. This could produce false "satisfied" results when the register is actually nullable.

**NullCheckPredicate (line 233):**
- Correctly detects `ptr_or_null` as violated and non-null pointers as satisfied
- Lines 260-261: Returns "violated" for bare "scalar" type, which is correct

**ClassificationOnlyPredicate (line 376):**
- Always returns "unknown" from `evaluate()`. This is correct by design -- these errors don't have register-level safety properties.

### 1.4 ebpf_predicates.py — Error-to-Predicate Mapping

**Predicate coverage:** 75 return statements total; 23 (30.7%) return ClassificationOnlyPredicate. These cover IRQ/lock discipline, verifier limits, JIT restrictions, BTF metadata errors, etc. This is appropriate -- these errors genuinely lack register-level predicates.

**`_extract_register_from_error` (line 387):** Falls back to `["R0", "R1", "R2"]` when no register is mentioned. This is a significant source of noise -- the predicate will check 3 arbitrary registers, which may have no relation to the actual failure.

**`infer_predicate` returns `None` for unmatched errors (line 1019).** When this happens, the pipeline falls through to the TransitionAnalyzer fallback, which analyzes ALL registers and almost always produces a false `established_then_lost`.

**`_is_non_error_line` (line 1022):** Intended to catch register state dumps being misidentified as error messages. But the regex at line 1036 (`re.match(r"R\d+[_=]", s)`) will fail to catch many register dump lines that start with state annotations like `"from 28 to 30: R0=..."`. This means some cases with register-dump "error lines" will not be corrected.

### 1.5 pipeline.py — Orchestration Logic

**`find_instruction` bug (confirmed):** The pipeline calls `find_instruction(parsed_trace.instructions, idx)` at lines 467, 483, 502, 598, 618. But `find_instruction` in `spans.py` does `getattr(parsed_trace, "instructions", [])` where `parsed_trace` is actually a **list** (the instructions themselves). Since a Python list has no `instructions` attribute, `getattr` returns `[]`, and the function always returns `None`. This means:
- All `before_state` and `after_state` fields in ProofEvents are always `None`
- The state context attached to spans is always empty
- **Impact:** Loss of diagnostic richness. Does not affect proof_status classification.

**TransitionAnalyzer fallback path (lines 346-451):**
The condition at line 346 is:
```python
if causal_chain or transition_chain.establish_point is not None or transition_chain.loss_point is not None:
```
This enters the TA fallback whenever the TransitionAnalyzer found *any* non-neutral transition -- which it almost always does. Combined with the TA's tendency to find spurious NARROWING at early instructions, this creates the false positive pipeline:

1. `infer_predicate` returns `None` (37 cases) or `ClassificationOnlyPredicate` (66 cases)
2. Monitor returns `unknown` (because pred is None or COP)
3. TA analyzes ALL registers (since `proof_registers` is empty)
4. TA finds `w6 = 0` at insn 0 -> NARROWING -> "established"
5. TA finds a type change on any register -> DESTROYING -> "lost"
6. Pipeline reports `established_then_lost`

**Backtracking-artifact override (lines 357-383):** Good defensive code that overrides `established_then_lost` to `never_established` when the establish point is after the loss point, or when the taxonomy is `verifier_limit`. But this doesn't catch the far more common case of vacuous establishment at insn 0.

---

## 2. Evaluation Quality

### 2.1 The 131/262 (50.0%) established_then_lost Rate is Inflated

**Empirical analysis** (run during this review):

| Source | Count | Share |
| --- | ---: | ---: |
| From Monitor (real predicate, genuine lifecycle) | 14 | 12% |
| From TransitionAnalyzer fallback (no predicate) | 37 | 32% |
| From TransitionAnalyzer fallback (ClassificationOnly) | 66 | 56% |
| **Total** | **117** | |

Of these 117 cases, **68 (58%) have the establishment point at instruction 0 or 1**. Instruction 0 is typically the first register initialization. A proof "established" at the first instruction is almost certainly vacuously true -- the register just appeared with its initial type/value, not because a bounds check or null check was performed.

**Conclusion:** Only ~14 cases (12%) have genuine, predicate-driven lifecycle analysis. The remaining ~103 cases are false positives from the TransitionAnalyzer analyzing irrelevant registers.

### 2.2 Multi-Span (52.7%) is Similarly Inflated

Since every `established_then_lost` case gets 3 spans (established, lost, rejected), the 50% 3-span rate directly mirrors the inflated `established_then_lost` rate. If we restrict to genuine lifecycle analysis (14 cases), the real multi-span rate is approximately 14/262 = 5.3%, compared to the v5 baseline of 37.8% which used the monitor path.

The v5 baseline had 99 established_then_lost cases. The Monitor alone now produces only 14. The difference may be due to the v5 engine using a different TA integration path, or the v6 refactor changed how predicates are matched.

### 2.3 Taxonomy Shift (lowering_artifact: 33 -> 141) is an Artifact

In `renderer.py` line 210-216, `_normalize_failure_class` unconditionally overrides taxonomy_class to `"lowering_artifact"` whenever proof_status is `"established_then_lost"`. Since the inflated established_then_lost includes cases that are clearly `env_mismatch` (IRQ violations, JIT issues) or `verifier_limit` (stack depth, complexity), the taxonomy distribution is now meaningless.

### 2.4 Temporal Ordering Sanity

The review found **0 cases where loss_site > error_insn** in the final output. However, many cases have `error=None` in the ProofEvents, which means the temporal check was never triggered. The pipeline's defensive code at lines 280-317 handles the case where monitor's loss_site is after the error by finding a DESTROYING event before the error. This is good.

### 2.5 Reference Case (stackoverflow-70750259) Verification

The reference case produces **correct** output:
- Proof established at insn 19 (byte read from packet, R0 becomes bounded scalar)
- Proof lost at insn 22 (`r0 |= r6`, OR operation destroys scalar bounds)
- Rejected at insn 24 (`r5 += r0`, math between pkt pointer and unbounded register)

This matches the Stack Overflow expert answer exactly. The issue is not that the engine CAN'T produce correct output -- it does for cases where a real predicate is inferred. The issue is that the fallback path produces false positives for the majority of cases.

---

## 3. Test Quality

### 3.1 test_transition_analyzer.py

**35 tests total.** The tests are well-structured and cover:
- Individual transition classification (11 tests)
- Bounds change classification (7 tests)
- Type change classification (7 tests)
- Range change classification (6 tests)
- Reason inference from opcodes (9 tests)
- TransitionChain proof status (5 tests)
- Integration with real case data (5 tests)

**Strengths:**
- Tests real verifier logs from stackoverflow-70750259
- Tests edge cases (None states, absent registers)
- Tests the full chain: narrowing -> destroying = established_then_lost

**Weaknesses:**
- **No tests for the Monitor or predicates.** The TraceMonitor, all predicate classes, and `infer_predicate` have zero test coverage in the test suite.
- **No test for the pipeline integration.** The `try_proof_engine` function (the critical orchestrator) has no dedicated tests.
- **No test for the false-positive scenario.** There is no test that verifies: "when proof_registers is empty and we analyze all registers, does the TA produce a false established_then_lost?" This is the bug that inflates the numbers, and it's completely untested.
- **No test verifying find_instruction correctness** -- and it's actually broken (see Section 1.5).
- **Real case integration tests check only one case** (stackoverflow-70750259). They verify the chain has transitions and effects but don't check whether the CORRECT register was analyzed or whether the establish/loss points are semantically meaningful.

### 3.2 What's NOT Tested

1. **TraceMonitor.monitor()** -- zero tests
2. **infer_predicate()** -- zero tests for error->predicate mapping
3. **Predicate.evaluate()** -- zero tests for any predicate class
4. **Pipeline orchestration (try_proof_engine)** -- zero tests
5. **find_instruction** -- zero tests (and it's broken)
6. **ClassificationOnlyPredicate fallback path** -- zero tests
7. **_normalize_failure_class** -- zero tests for the taxonomy override

---

## 4. Compatibility Stubs

### 4.1 proof_engine.py

A compatibility stub that delegates to the new engine. The `analyze_proof` function creates a `TraceMonitor` and runs it. Harmless. Should be deprecated but does not interfere.

### 4.2 diagnoser.py

A compatibility stub that delegates to `log_parser` and `trace_parser`. Uses the OLD transition types (BOUNDS_COLLAPSE, TYPE_DOWNGRADE, etc.) from `trace_parser.critical_transitions`, not the new engine. This means `diagnosis.proof_status` is computed from the OLD path, while the new engine computes its own. The pipeline at line 66 uses `proof_result.proof_status or diagnosis.proof_status`, preferring the new engine's result. This is correct -- the new engine's result takes priority.

### 4.3 proof_analysis.py

A compatibility stub providing `ProofEvent` and `ProofObligation` dataclasses. Still used by the pipeline. Not deletable.

### 4.4 spans.py

Provides `find_instruction`, `make_proof_event`, `register_from_error`. All still in use. The `find_instruction` bug is here. Not deletable.

### 4.5 obligation_refinement.py

Provides `infer_catalog_obligation` (returns None), `infer_obligation_from_engine_result` (delegates to `proof_analysis.infer_obligation`), `obligation_type`, and `refine_obligation_with_specific_reject`. All still in use. Not deletable.

**Recommendation:** None of these stubs should be deleted -- they're all still actively called. But `find_instruction` needs a fix: it should accept either a list of instructions or an object with an `instructions` attribute.

---

## 5. Specific Concerns

### 5.1 Does the TransitionAnalyzer correctly identify WHICH registers are proof-relevant?

**No.** When `proof_registers` is empty (which happens for 103 of the 117 established_then_lost cases), the TA analyzes ALL registers. At line 122-126:

```python
relevant_regs = (
    proof_registers
    if proof_registers
    else (
        {r for r in set(insn.pre_state) | set(insn.post_state) if r.startswith("R")}
    )
)
```

This means R0 through R10 are all analyzed. R6 being set to 0 counts as "proof established", R1 losing its ctx type after a helper call counts as "proof lost". These transitions are real but irrelevant to the actual failure.

### 5.2 Does infer_predicate correctly identify the failing register?

**Partially.** When the error message explicitly mentions a register (e.g., "R2 invalid mem access 'scalar'"), the regex correctly extracts it. But the fallback at `_extract_register_from_error` line 390 returns `["R0", "R1", "R2"]` when no register is mentioned. For many errors (e.g., "math between pkt pointer and register with unbounded min value"), no specific register is mentioned, so the predicate checks three arbitrary registers.

### 5.3 Can a predicate return "satisfied" at early instructions because the register hasn't been loaded yet?

**Yes, this is the vacuous truth problem.** Consider a `ScalarBound(target_regs=["R0"], umax_limit=1000000)` predicate. At instruction 0, R0 might not exist in the state (so evaluate returns "unknown"). But at instruction 1, R0 might be set to `scalar(umax=0)` (initial value 0), which satisfies `umax <= 1000000`. This counts as "established" even though no bounds check was performed. The real bounds check might be 50 instructions later.

The MonitorResult correctly records this as `establish_site=1`, but the pipeline doesn't distinguish between "established because a bounds check was done" and "established because the initial value happens to satisfy the predicate".

---

## 6. Summary of Findings

### Critical Issues (must fix before publication)

1. **88% of established_then_lost classifications are false positives** from the TransitionAnalyzer fallback analyzing irrelevant registers. The real predicate-driven lifecycle rate is ~5.3%, not 50.0%.

2. **`find_instruction` bug:** Called with a list but expects an object with an `.instructions` attribute. All state context in ProofEvents is `None`.

3. **Taxonomy override:** `_normalize_failure_class` unconditionally sets taxonomy to `lowering_artifact` for all `established_then_lost` cases, producing meaningless taxonomy statistics (33 -> 141 is an artifact, not a real signal).

### Moderate Issues

4. **No tests for Monitor, predicates, or pipeline orchestration.** The most critical code paths have zero test coverage.

5. **TypeMembership prefix matching** can produce false "satisfied" for nullable pointers when `"ptr"` is in `allowed_types`.

6. **Error line extraction failures** cause `infer_predicate` to return `None`, triggering the false-positive TA fallback path.

### Recommendations

1. **Guard the TA fallback:** When `predicate is None` or `ClassificationOnlyPredicate`, do NOT use the TransitionAnalyzer's proof_status. Return `unknown` or `never_established` instead. The TA should only contribute to `established_then_lost` when it operates on the same registers as a real predicate.

2. **Fix `find_instruction`:** Accept a list directly, or have the pipeline pass the correct argument type.

3. **Remove the taxonomy override** or restrict it to cases where the Monitor (not TA) determined `established_then_lost`.

4. **Add establishment-site validation:** Require that the establishment point corresponds to a genuine bounds check, null check, or type assertion -- not just a register initialization at insn 0.

5. **Add test coverage:** At minimum, test TraceMonitor, infer_predicate, and the pipeline's orchestration logic. Test specifically for the false-positive scenario where TA analyzes all registers with no predicate.

6. **Report honest numbers:** The genuine lifecycle analysis rate should be reported as ~14/262 (5.3%) or at best the Monitor's contribution. The TA's contribution should be reported separately with a caveat about the all-register analysis.
