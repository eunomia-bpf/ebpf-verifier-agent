# Feature Verification Report
Date: 2026-03-12

All checks run from `/home/yunwei37/workspace/ebpf-verifier-agent`.
Real verifier logs used from `case_study/cases/stackoverflow/` (66 cases with logs).

---

## 1. Backward Obligation Slicing

**Status: WORKS — but causal_chain is NOT wired into the final JSON output.**

### What actually works

`backward_obligation_slice()` in `interface/extractor/proof_engine.py` (line 1684) produces genuine, meaningful causal chains on real data. Tested directly:

```python
from interface.extractor.proof_engine import backward_obligation_slice, infer_obligation
# Case: stackoverflow-70750259 (packet pointer arithmetic failure)
# Causal chain: 21 entries, e.g.:
#   insn 19: mark_precise backtrack target for R6; writes to R6 (predicate register)
#   insn 20: mark_precise backtrack target for R0; mark_precise backtrack target for R6; writes to R0 (obligation index register)
#   insn 22: mark_precise backtrack target for R0; writes to R0 (obligation index register)
#   insn 28: branch narrowing R0 bounds
```

The chain correctly identifies backtrack targets from `mark_precise` annotations, register writes to obligation-relevant registers, and branch-narrowing instructions. For `stackoverflow-70729664` (a large trace with 2948+ instructions), slicing returned 4 tightly relevant entries pointing directly to the branch join that lost the packet range.

### The critical gap

`ProofAnalysisResult.causal_chain` is populated (confirmed with `analyze_proof()` returning a 21-entry chain), but it is **never serialized into the final JSON output**. The path is:

- `analyze_proof()` → `ProofAnalysisResult.causal_chain` ✓
- `_try_proof_engine()` → `_FallbackProofResult` — **causal_chain field missing**
- `_attach_proof_analysis_metadata()` only writes `fallback_reasons`, not `causal_chain`
- `metadata.causal_chain` in `json_data` is always `None`

The task's batch test `md.get('causal_chain')` always returns `None` because `causal_chain` is never put into `metadata`. However, `proof_spans` with roles `proof_established`/`proof_lost`/`rejected` ARE populated for the 14 `established_then_lost` cases out of 66 total.

### Batch results (all 66 SO cases)

```
Total: 66, Success: 66
proof_status distribution:
  never_established: 39
  unknown: 11
  established_but_insufficient: 2
  established_then_lost: 14
Has causal info (proof_established span present): 16/66
```

The task's exact batch test (first 10 alphabetically) returns `Has causal info: 0` because those 10 cases all have `never_established` or `unknown` status — none trigger the `established_then_lost` path where proof_spans include `proof_established`.

---

## 2. bpftool Parser

**Status: WORKS.**

`interface/extractor/bpftool_parser.py` correctly parses both formats:

**Format 1 — inline source without file annotation:**
```
; if (skb->len < 20)
   0: (61) r1 = *(u32 *)(r1 +0)
   1: (55) if r1 != 0x14 goto pc+3
```
→ insn 0: `source_text='if (skb->len < 20)'`, file=None, line=None ✓

**Format 2 — with `@ file:line` annotation:**
```
; int ret = bpf_probe_read(...); @ /home/user/prog.bpf.c:42
   0: (85) call bpf_probe_read#4
```
→ insn 0: `source_file='/home/user/prog.bpf.c'`, `source_line=42` ✓

The parser correctly assigns the most recent `;`-prefixed source annotation to subsequent instructions. The `SOURCE_ANNOTATION_RE` regex handles the optional `@file:line:col` suffix cleanly.

---

## 3. CLI Entry Point

**Status: WORKS.**

```bash
$ python3 -m oblige --help
usage: oblige [-h] [--format {text,json,both}] [--catalog CATALOG]
              [--bpftool-xlated PATH] [--indent INDENT] [--version]
              [input]
Generate OBLIGE diagnostics from a verifier log or case manifest.
```

Running on a real YAML case produces correct Rust-style output:
```
$ python3 -m oblige case_study/cases/stackoverflow/stackoverflow-70750259.yaml --format text
error[OBLIGE-E005]: lowering_artifact — packet access with lost proof
  ┌─ <source>
  │
22 │     __u16 ext_len = __bpf_htons(ext->len);
   │     ──────────────────────────────────── proof established
   │     R5: pkt(range=6, off=6) → pkt(range=6, off=6)
22 │     __u16 ext_len = __bpf_htons(ext->len);
   │     ──────────────────────────────────── proof lost: OR operation destroys bounds
   │     R0: scalar(umax=65280, var_off=(0x0; 0xff00)) → scalar(unbounded)
24 │     if (data_end < (data + ext_len)) {
   │     ────────────────────────────────── rejected
   │     R5: pkt(range=6, off=6)
  = note: A verifier-visible proof existed earlier, but arithmetic lowering widened the offset...
  = help: Add an explicit unsigned clamp and keep the offset calculation in a separate verified register
```

JSON output also works correctly (`--format json`). The CLI correctly handles YAML case files by extracting `verifier_log`, injecting `case_id` and `kernel_release` from case metadata.

---

## 4. Public API

**Status: WORKS.**

`interface/api/__init__.py` exposes `build_diagnostic()` which wraps `generate_diagnostic()`:

```python
from interface.api import build_diagnostic
result = build_diagnostic(log, case_id='stackoverflow-70750259')
# result keys: ['diagnostic_version', 'error_id', 'failure_class', 'message',
#               'source_span', 'missing_obligation', 'evidence', 'candidate_repairs',
#               'verifier_site', 'expected_state', 'observed_state', 'confidence',
#               'raw_log_excerpt', 'metadata', 'case_id']
# result['error_id'] = 'OBLIGE-E005'
# result['failure_class'] = 'lowering_artifact'
# result['confidence'] = 0.98
# result['metadata']['proof_status'] = 'established_then_lost'
```

The `source_path` override logic and `kernel_release` passthrough work correctly. The API returns a plain dict (not a `DiagnosticOutput` dataclass), suitable for schema validation.

---

## 5. Batch Impact

**Status: PARTIALLY WORKS — meaningful for established_then_lost cases, zero coverage for never_established.**

The batch eval script from the task spec returns `Has causal info: 0/8` for the first 10 SO cases because those cases all have `proof_status = 'never_established'` or `'unknown'` — the backward slicing path (`_analyze_obligation` line 1845) is only reached when `proof_status == 'established_then_lost'`.

Over all 66 SO cases: 14 reach `established_then_lost`, all 14 get non-empty `proof_spans` with `proof_established` and `proof_lost` roles. However, the underlying `causal_chain` list from `ProofAnalysisResult` is not propagated to `metadata.causal_chain` in the JSON output — that field is always absent.

The backward slicing itself changes the chain quality measurably:
- `established_then_lost` cases now get 3 structured spans (established, lost, rejected) vs 1 span (rejected only) previously
- `mark_precise` backtracking is correctly identified in chains (e.g., insn 19-22 in the SO-70750259 case)

---

## 6. CompositeObligation / track_composite

**Status: WORKS.**

`track_composite()` (proof_engine.py line 1914) runs each sub-obligation through `_analyze_obligation()` independently and returns the earliest failure:

```python
from interface.extractor.proof_engine import CompositeObligation, track_composite, infer_obligation
ob = infer_obligation(parsed_trace, error_line, symptom_insn)
composite = CompositeObligation(sub_obligations=[ob])
result = track_composite(parsed_trace, composite)
# result = {
#   'sub_results': [ProofAnalysisResult(...)],
#   'first_failed_index': 0,
#   'first_failed_obligation': <ObligationSpec>,
#   'first_failure_site': 22,
#   'first_failure_status': 'established_then_lost'
# }
# sub_results[0].causal_chain = [(19, 'mark_precise...'), (20, ...), (21, ...), (22, ...)]
```

The causal chain is populated in the sub-results (4 entries for the SO-70750259 case). `track_composite` correctly ranks failures and selects the earliest observed loss site. The API is functional for multi-obligation tracking.

---

## Overall Assessment

**These are real improvements, not scaffolding.** The proof engine produces genuine, meaningful analysis — the backward slicing correctly uses `mark_precise` backtracking chains, identifies branch narrowing instructions, and traces register provenance backward through the trace.

### What's genuinely working end-to-end
- Backward slicing (`backward_obligation_slice`): real causal chains on real data
- bpftool parser: both annotation formats parsed correctly
- CLI entry point: clean Rust-style output, JSON mode, YAML case file support
- Public API: schema-valid dicts, case_id / kernel_release injection
- CompositeObligation / track_composite: sub-obligation ranking functional
- 114/114 unit tests pass

### Critical gap to fix
**`causal_chain` is computed but never serialized.** `ProofAnalysisResult.causal_chain` is a real list populated in `_analyze_obligation()` and `analyze_proof()`. It needs to be threaded through `_FallbackProofResult` and `_attach_proof_analysis_metadata()` to appear in `metadata.causal_chain` in the final JSON output. Without this fix, the task's batch test will always count `has_causal = 0` even for established_then_lost cases. This is a wiring bug, not an algorithmic one.

### Secondary issue
`infer_obligation` returns `None` for some cases (e.g., `stackoverflow-74531552`), causing a crash in `backward_obligation_slice` when called directly. The `analyze_proof` path handles this gracefully via None checks, but direct callers of `infer_obligation` need to check for None.
