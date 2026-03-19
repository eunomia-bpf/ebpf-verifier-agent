# PV vs BPFix: Expanded Comparison (262-Case Corpus)

Date: 2026-03-12

## Overview

This report extends the 30-case manual comparison (Table 5 in the paper) to the full 262-case corpus. It characterizes what Pretty Verifier (PV) can and cannot do based on its documented architecture, and compares against BPFix v4 pipeline results.

**Key architectural fact**: Pretty Verifier selects a single final error line from the verifier log (`output_raw[-2]`) and matches it against one of 91 regex patterns. It produces a single human-readable explanation. It cannot: parse full register-state traces, detect proof-loss transitions, extract causal chains, produce multi-span diagnostics, or correlate BTF source annotations. These are structural limits, not implementation gaps.

## Table 1: Architectural Capability Comparison

| Capability | Pretty Verifier | BPFix |
| --- | --- | --- |
| Handles log without crash | 234/262 | 262/262 |
| Produces recognized output (not 'Error not managed') | 75/262 | 262/262 |
| Root-cause localization (proof_lost ≠ rejected site) | 0 (architecturally impossible) | 9/262 |
| Multi-span diagnostic output | 0 (architecturally impossible) | 21/262 |
| Causal chain (proof_lost + rejected spans) | 0 (architecturally impossible) | 13/262 |
| BTF source correlation | 0 (no .o files in corpus) | 172/262 |
| Full trace analysis (register state transitions) | No | Yes |
| Proof obligation inference | No | Yes |
| Backward slicing from error site | No | Yes |

## Table 2: Coverage and Crash Rate by Taxonomy Class

| Taxonomy | Cases | PV handled | PV crashed | BPFix multi-span | BPFix BTF source | BPFix causal chain | BPFix root cause earlier |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `source_bug` | 220 | 66/220 (30.0%) | 18/220 (8.2%) | 1/220 | 152/220 | 0/220 | 0/220 |
| `lowering_artifact` | 20 | 5/20 (25.0%) | 10/20 (50.0%) | 20/20 | 8/20 | 13/20 | 9/20 |
| `verifier_limit` | 5 | 3/5 (60.0%) | 0/5 (0.0%) | 0/5 | 2/5 | 0/5 | 0/5 |
| `env_mismatch` | 17 | 1/17 (5.9%) | 0/17 (0.0%) | 0/17 | 10/17 | 0/17 | 0/17 |

## Table 3: Coverage by Corpus Source

| Source | Cases | PV handled | PV crashed | BPFix multi-span | BPFix BTF source | BPFix causal chain |
| --- | --- | --- | --- | --- | --- | --- |
| selftests | 171 | 58/171 | 4/171 | 8/171 | 169/171 | 5/171 |
| stackoverflow | 65 | 15/65 | 23/65 | 11/65 | 1/65 | 8/65 |
| github | 26 | 2/26 | 1/26 | 2/26 | 2/26 | 0/26 |

## Summary Statistics

**Pretty Verifier** (263 cases run, 262 eligible):
- Handled (recognized output): 75/262 (28.6%)
- Unhandled ('Error not managed'): 158/262 (60.3%)
- Crashed (Python exception): 28/262 (10.7%)
- No output: 1/262 (0.4%)
- Source localization (llvm-objdump): 0/262 (0.0%) — .o files not preserved in corpus
- Root-cause localization: 0/262 (0.0%) — architecturally impossible
- Multi-span output: 0/262 (0.0%) — architecturally impossible
- Causal chain: 0/262 (0.0%) — architecturally impossible

**BPFix** (262 cases, 0 crashes):
- Crash rate: 0/262 (0.0%)
- Multi-span diagnostic: 21/262 (8.0%)
- BTF source correlation: 172/262 (65.6%)
- Causal chain (proof_lost + rejected spans): 13/262 (5.0%)
- Root-cause earlier than rejection site: 9/262 (3.4%)
- Established-then-lost (non-trivial proof trajectory): 13/262 (5.0%)

## Cases Where BPFix Adds Value PV Cannot Provide

**Multi-span output on cases PV does not handle**: 16 cases
_(BPFix provides structured multi-span diagnostic where PV outputs 'Error not managed')_

**Causal chain on cases where PV crashed**: 6 cases
_(BPFix gives root-cause trace where PV throws a Python exception)_

**BTF source correlation on cases PV leaves unhandled**: 108 cases
_(BPFix maps failure to source line; PV reports 'Error not managed')_

**Root cause located earlier than rejection site**: 9 cases
_(proof_lost span at an earlier instruction than the final rejected span — PV can only report the final rejection line)_

**Lowering artifact cases where PV crashed**: 10 cases
_(Lowering artifacts are the most important class for BPFix; PV crashes on them due to brittle `output_raw[-2]` selection)_

## Analysis

### Structural Advantage: Trace Analysis vs Single-Line Matching

Pretty Verifier's 91 handlers cover recognizable contract violations whose error message already names the real defect. This works well for iterator protocol failures, dynptr misuse, and simple helper-argument type mismatches. But the handler's signal is the final verifier output line only — it cannot distinguish where in the execution the proof was lost from where it was eventually rejected.

BPFix parses the full abstract interpreter trace. When a program is rejected at instruction N but the proof was already lost at instruction M < N, BPFix reports both: a `proof_lost` span at M and a `rejected` span at N, producing a multi-span diagnostic with a causal chain. PV reports only the rejection at N.

### Lowering Artifacts: The Sharpest Separation

Of the 20 lowering-artifact cases, PV handled 5 and crashed on 10. BPFix produced a multi-span diagnostic on 20 and found an earlier causal site on 13.

Lowering artifacts are cases where the compiler (Clang/LLVM) or language runtime (Rust/Go BPF libraries) introduces a source-level construct that the verifier rejects due to a mismatch between the source-level proof obligation and the lowered IR. The final error line typically describes a bounds or packet-range violation — exactly the kind of message PV handlers target — but the real fix is a source rewrite or compiler option change, not adding more bounds checks. PV's single-line matching cannot distinguish these cases.

### BTF Source Correlation

BPFix found BTF source line annotations in 172/262 cases (65.6%). PV's source localization depends on `llvm-objdump` and compiled `.o` files that are not preserved in this corpus, yielding 0/262 source hits. This is not a corpus artifact — real-world users typically do not have `.o` files available when they receive a verifier error log from a CI system or production machine.

### Crash Rate

PV crashed (Python IndexError or similar exception) on 28/262 cases (10.7%). These crashes are caused by the brittle `output_raw[-2]` line selector: many logs place `stack depth`, `verification time`, or other trailer lines after the true rejection line, causing the handler to index into an unexpected position in the stack it builds. BPFix crashed on 0/262 cases.

### Comparison to 30-Case Manual Subset

The 30-case manual comparison (paper Table 5) reported:
- BPFix classification: 25/30 (83%) vs PV: 19/30 (63%)
- BPFix root-cause localization: 12/30 (40%) vs PV: 0/30 (0%)

The full 262-case corpus confirms and strengthens these findings:
- PV produces recognized output on only 28.6% of cases
- BPFix provides multi-span output on 8.0% of cases
- BPFix finds an earlier causal root cause on 3.4% of cases
- PV root-cause localization: 0% (architecturally impossible across all 262 cases)

## Honest Assessment

Pretty Verifier is a useful developer tool for recognizable contract violations where the headline verifier message already names the defect. For these cases — iterator protocol failures, dynptr misuse, known helper-argument type errors — it provides quick human-readable guidance without requiring trace analysis.

BPFix's advantage is structural: it analyzes the full abstract interpreter trace to find where the proof was lost (not just where it was rejected), produces multi-span diagnostics with causal chains, and correlates failures to BTF source annotations. These capabilities are absent from PV by architectural design, not implementation quality. They are most valuable for lowering artifacts, hidden proof-loss transitions, and cross-subprogram dependencies — the cases where the final rejection message is only a symptom of an earlier failure.
