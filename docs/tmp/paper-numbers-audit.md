# Paper Numbers Audit — BPFix `docs/paper/main.tex`

**Audit date:** 2026-03-12
**Auditor:** Claude (automated)
**Method:** Ran commands against actual data files and code; compared against paper text.

---

## Summary Table

| # | Claim in paper | Actual value | Status | Line(s) in main.tex |
|---|---|---|---|---|
| 1 | "120 unit tests" | **268 tests** | DISCREPANCY | 392, 708 |
| 2 | "~6,600 lines of Python" | **~14,613 lines** (extractor dir); **~4,184** (5 named modules only) | DISCREPANCY | 392, 706 |
| 3 | "eighteen obligation families" | **19 families** in `OBLIGATION_FAMILIES` dict | DISCREPANCY | 446, 455, 711, 835, 982, 987 |
| 4 | Corpus table Total BTF = **62.7%** | **65.6%** (172/262) in v4 data | DISCREPANCY | 787 |
| 5 | Batch table: "Proof-established span 96/262 (36.6%)" | **112/262 (42.7%)** in v4 data | DISCREPANCY | 821 |
| 6 | PV table: "Causal chain 96/262 (36.6%)" | 96 = `proof_established_then_lost` count, not backward-slicing chains | LABEL INCONSISTENCY | 939 |
| 7 | "23 error IDs (BPFIX-E001 through E023)" | **23 error IDs** confirmed | OK | 405, 711 |
| 8 | "94.3% obligation coverage" (247/262) | **247/262 = 94.27%** from v4 data | OK | 455, 818, 831 |
| 9 | "BTF source correlation 172/262 (65.6%)" | **172/262 = 65.6%** confirmed | OK | 819 |
| 10 | "27 ms median latency" | **26.977 ms** median (generate_diagnostic) | OK (rounds correctly) | 139, 287, 399, 969 |
| 11 | "P95: 43 ms" | **42.61 ms** P95 | OK (rounds correctly) | 969 |
| 12 | "302 cases … 200 kernel selftests, 76 Stack Overflow … 26 GitHub" | v4 corpus: selftests=200, SO=76, GitHub=26, total=302 | OK | 135, 767–770, 783–785 |
| 13 | "87.1% of failures" covered by 23 error IDs | **263/302 = 87.09%** → 87.1% | OK | 406 |
| 14 | Repair experiment: A=53/54 (98.1%), B=48/54 (88.9%) location | Confirmed from `repair-experiment-v2-results.md` | OK | 878 |
| 15 | Repair experiment: A=46/54 (85.2%), B=43/54 (79.6%) fix-type | Confirmed from `repair-experiment-v2-results.md` | OK | 879 |
| 16 | Lowering fix type: A=3/10 (30%), B=6/10 (60%), +30 pp | Confirmed from `repair-experiment-v2-results.md` | OK | 880 |
| 17 | PV comparison: PV=19/30 (63%), BPFix=25/30 (83%) | Confirmed from `pretty-verifier-comparison.md` | OK | 928 |
| 18 | Root-cause localization: PV=0/30 (0%), BPFix=12/30 (40%) | Confirmed from `pretty-verifier-comparison.md` | OK | 930 |
| 19 | PV crashes on 28/262 (10.7%) | **28/262 = 10.7%** confirmed | OK | 953 |
| 20 | PV recognized output 75/262 (28.6%) | **75/262 = 28.6%** confirmed | OK | 936 |
| 21 | BPFix multi-span 113/262 (43.1%) | **113/262 = 43.1%** confirmed | OK | 938, 956 |
| 22 | BPFix root-cause earlier 53/262 (20.2%) | **53/262 = 20.2%** confirmed | OK | 937, 957 |
| 23 | Batch table causal chain 21/262 (8.0%) | **21/262 = 8.02%** confirmed | OK | 823 |
| 24 | All \cite{} keys present in references.bib | **16 citations, 16 bib entries, no missing/extra** | OK | throughout |

---

## Detailed Discrepancies

### Discrepancy 1 — Unit test count

**Paper says (lines 392 and 708):**
```
The full implementation is ~6,600 lines of Python with 120 unit tests.
```

**Actual value:**
```
$ python -m pytest tests/ --co -q 2>/dev/null | tail -1
268 tests collected in 0.73s
```

**Verdict:** Paper says 120, actual is **268**. The count was last updated when the paper was drafted; the test suite has since grown by 148 tests.

**Lines to update:** 392 (`120 unit tests`) and 708 (`120 unit tests`).

---

### Discrepancy 2 — Lines of Python

**Paper says (lines 392 and 706):**
```
~6,600 lines of Python across five modules: log_parser, trace_parser,
proof_engine, source_correlator, and rust_diagnostic
```

**Actual values:**
```
$ find interface/extractor -name "*.py" | xargs wc -l | tail -1
14613 total   (entire extractor directory, excluding __pycache__)

Five named modules + their _parts/ subdirectories:
  log_parser:          339 lines
  trace_parser + parts: 51 + 1,209 = 1,260 lines
  proof_engine + parts: 45 + 121  = 166 lines
  source_correlator:   511 lines
  rust_diagnostic + parts: 9 + 1,899 = 1,908 lines
  ─────────────────────────────────────────────
  Five-module total:   4,184 lines

Supporting modules (obligation_inference, obligation_catalog_formal,
diagnoser, spans, renderer, reject_info, etc.): ~10,429 additional lines
```

**Verdict:** The five modules cited total ~4,184 lines, not 6,600. The entire extractor is ~14,613 lines. The "~6,600" figure appears to predate a large expansion of `obligation_inference.py` (3,941 lines alone). The paper should either update the number or clarify scope (e.g., "~14,600 lines total including supporting modules").

**Lines to update:** 392 and 706.

---

### Discrepancy 3 — Obligation family count

**Paper says (lines 446, 455, 711, 835, 982, 987):**
```
\sys supports eighteen obligation families
```

**Actual value:**
```python
# interface/extractor/obligation_inference.py — OBLIGATION_FAMILIES top-level keys:
['packet_access', 'packet_ptr_add', 'map_value_access', 'memory_access',
 'stack_access', 'null_check', 'scalar_deref', 'helper_arg', 'trusted_null_check',
 'dynptr_protocol', 'iterator_protocol', 'unreleased_reference', 'btf_reference_type',
 'exception_callback_context', 'execution_context', 'buffer_length_pair',
 'exit_return_type', 'verifier_limits', 'safety_violation']
# Count: 19
```

The `obligation_catalog_formal.py` `FAMILY_INDEX` contains 10 families (the subset with formal predicate atoms). The obligation_catalog.yaml has 23 templates (O001–O023).

**Verdict:** `OBLIGATION_FAMILIES` has **19** entries, not 18. All six occurrences of "eighteen" in the paper need to change to "nineteen" (or the code needs to be trimmed to 18).

**Lines to update:** 446, 455, 711, 835, 982, 987.

---

### Discrepancy 4 — Corpus table total BTF percentage

**Paper says (line 787, Table "Evaluation corpus"):**
```latex
\textbf{Total}   & \textbf{302} & \textbf{262} & \textbf{62.7\%} & \textbf{281} \\
```

**Actual value:**
```
$ # From batch_diagnostic_results_v4.json (the canonical eval dataset):
Eligible: 262 cases; BTF-annotated: 172 → 172/262 = 65.6%

$ # 62.7% comes from the older v3 dataset (241 eligible, 151 BTF):
151/241 = 62.7%
```

**Verdict:** The corpus table's BTF column (62.7%) was computed from the v3 dataset. The batch evaluation table (line 819) uses v4 and correctly shows 65.6%. The corpus table needs to be updated to match the current evaluation dataset: **65.6% (172/262)**.

**Line to update:** 787 (`\textbf{62.7\%}` → `\textbf{65.6\%}`).

---

### Discrepancy 5 — Proof-established span count in batch table

**Paper says (line 821, Table "Batch diagnostic evaluation"):**
```latex
Proof-established span          & 96/262 (36.6\%) \\
```

**Actual value:**
```
$ # From batch_diagnostic_results_v4.json:
has_proof_established_span: 112/262 = 42.7%
has_proof_lost_span:         96/262 = 36.6%
```

**Verdict:** The "Proof-established span" row in the batch table has the wrong number. The value 96 (36.6%) is the count for **proof-lost spans** (i.e., `established_then_lost` proof status), not proof-established spans. The correct number for proof-established spans is **112/262 (42.7%)**.

This appears to be a copy-paste error: both "Proof-established span" and "Proof-lost span" are listed as 96/262 (36.6%), but only the latter is correct.

**Line to update:** 821 (`96/262 (36.6\%)` → `112/262 (42.7\%)`).

---

### Discrepancy 6 — "Causal chain" label inconsistency between two tables

**Paper line 823 (batch table):**
```
Causal chain extracted          & 21/262 (8.0\%) \\
```

**Paper line 939 (PV comparison table):**
```
Causal chain  & 0/262 (0\%)  & 96/262 (36.6\%) \\
```

**What the data actually shows:**
- `21/262 (8.0%)` = cases with a real `mark_precise` backward-slicing causal chain in `diagnostic_json.metadata.causal_chain` (verified from v4 data).
- `96/262 (36.6%)` = `bpfix_causal_chain` field in `pv_comparison_expanded.json`, which equals `bpfix_proof_established_then_lost` (also 96) — the count of cases with `proof_status == established_then_lost`, not backward-slicing chains.

**Verdict:** The two tables use the same label ("Causal chain") for different quantities. Line 939's "96/262 (36.6%)" is actually the count of cases with a proof-established-then-lost transition (i.e., multi-span diagnostics showing where the proof was established and where it was lost), not backward-slicing dependency chains. This should be relabeled in the PV table to something like "Proof-loss transitions" or "Multi-span (established+lost)."

**Line to update:** 939 (relabel the row, not just the number; the 96/262 figure itself is correct for what it measures).

---

## Reference Check

All 16 `\cite{}` keys in `main.tex` have matching entries in `references.bib`:

```
cousot1977, deokar2024, depsurf2025, ebpfverifdict, errormessages2014,
gershuni2019simple, hotos2023verif, k22023, kgent2024, linuxbtf,
nccaudit2024, prettyverifier2025, rex2025, rustdiag2016, simplebpf2025,
weiser1981
```

No undefined citations, no unused bib entries. BibTeX log has 18 warnings (all about missing optional fields like `publisher`, `address`, `number`—not errors).

The LaTeX log has one font warning (`Font shape T1/zi4/m/it undefined`) but no undefined reference or undefined label warnings.

---

## Numbers That Are Correct

These claims were verified against actual data files and are accurate:

| Claim | Data source |
|---|---|
| 23 error IDs (E001–E023) | `taxonomy/error_catalog.yaml` |
| 87.1% error coverage (263/302) | `eval/results/taxonomy_coverage.json` |
| 94.3% obligation coverage (247/262) | `eval/results/batch_diagnostic_results_v4.json` |
| BTF 65.6% (172/262) in batch table | `eval/results/batch_diagnostic_results_v4.json` |
| 27 ms median latency (actual: 26.977 ms) | `eval/results/latency_benchmark_v2.json` |
| P95 43 ms (actual: 42.61 ms) | `eval/results/latency_benchmark_v2.json` |
| 302 corpus cases (200/76/26) | `eval/results/batch_diagnostic_results_v4.json` |
| Repair experiment table (54 cases, all rows) | `docs/tmp/repair-experiment-v2-results.md` |
| PV comparison 30 cases (19/30 vs 25/30) | `docs/tmp/pretty-verifier-comparison.md` |
| PV crashes 28/262 (10.7%) | `eval/results/pv_comparison_expanded.json` |
| PV recognized 75/262 (28.6%) | `eval/results/pv_comparison_expanded.json` |
| BPFix multi-span 113/262 (43.1%) | `eval/results/pv_comparison_expanded.json` |
| BPFix root-cause earlier 53/262 (20.2%) | `eval/results/pv_comparison_expanded.json` |
| Causal chain extracted 21/262 (8.0%) in batch table | `eval/results/batch_diagnostic_results_v4.json` |
| Proof-lost span 96/262 (36.6%) | `eval/results/batch_diagnostic_results_v4.json` |
| never_established 129/262 (49.2%) | `eval/results/batch_diagnostic_results_v4.json` |
| established_then_lost 96/262 (36.6%) | `eval/results/batch_diagnostic_results_v4.json` |

---

## Fixes Required (No Changes to Paper Have Been Made)

| Priority | Line(s) | Current text | Correct text |
|---|---|---|---|
| High | 821 | `Proof-established span & 96/262 (36.6\%)` | `112/262 (42.7\%)` |
| High | 787 | `\textbf{62.7\%}` (corpus table BTF total) | `\textbf{65.6\%}` |
| High | 392, 708 | `120 unit tests` | `268 unit tests` |
| Medium | 392, 706 | `$\sim$6,600 lines` | `$\sim$14,600 lines` (or clarify scope) |
| Medium | 446, 455, 711, 835, 982, 987 | `eighteen obligation families` | `nineteen obligation families` |
| Low | 939 | Row label `Causal chain` | Relabel to `Proof-loss transitions` (or `Established-then-lost`) |
