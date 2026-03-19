# interface/extractor

Proof trace analysis pipeline for the BPFix system. Takes a raw eBPF verifier
verbose log (LOG_LEVEL2) and produces Rust-style multi-span diagnostics: a
stable error ID, taxonomy class, proof obligation, source/bytecode spans, and
structured JSON output. Pure Python, no kernel involvement.

## Pipeline

```
raw log text
    │
    ▼
log_parser.py          → ParsedLog (error line, catalog error ID, taxonomy class)
    │
    ▼
trace_parser_parts/    → ParsedTrace (TracedInstruction list with pre/post register state,
                          backtrack chains, causal chain, critical transitions)
    │
    ▼
proof_engine_parts/    → ProofAnalysisResult (ObligationSpec, PredicateEvals, obligation
  obligation_inference    establish/loss/reject sites, backward slice)
  predicate_tracking
  backward_slicing
    │
    ▼
source_correlator.py   → SourceSpan list (bytecode range → source file:line via BTF)
    │
    ▼
renderer.py            → DiagnosticOutput (text + json_data)
```

## Entry Point

```python
from interface.extractor.pipeline import generate_diagnostic

output = generate_diagnostic(verifier_log: str) -> DiagnosticOutput
# output.text  — Rust-style text diagnostic
# output.json_data — structured dict with error_id, spans, obligation, etc.
```

`generate_diagnostic` is also re-exported from `rust_diagnostic.py` for
backward compatibility.

## File Map

| File | Role |
|------|------|
| `pipeline.py` | Top-level orchestrator; calls all stages and assembles `DiagnosticOutput` |
| `log_parser.py` | Stage 1 — regex + catalog matching → `ParsedLog` |
| `trace_parser.py` | Compatibility facade; re-exports from `trace_parser_parts/` |
| `trace_parser_parts/` | Stage 2 implementation — per-instruction state parsing, backtrack chains, causal chain |
| `proof_engine.py` | Compatibility facade; re-exports from `proof_engine_parts/` |
| `proof_engine_parts/` | Stage 3 implementation — obligation inference, predicate tracking, backward slicing, IR builder |
| `obligation_inference.py` | Top-level proof analysis entrypoint used by the facade |
| `obligation_refinement.py` | Refines raw engine obligation against catalog and specific reject info |
| `source_correlator.py` | Stage 4 — maps proof events to source spans via BTF line info |
| `spans.py` | Span normalization and synthesis helpers |
| `renderer.py` | Stage 5 — renders `SourceSpan` list + obligation as text + JSON |
| `rust_diagnostic.py` | Compatibility facade; re-exports `DiagnosticOutput` and `generate_diagnostic` |
| `diagnoser.py` | Differential diagnosis layer (proof_status, taxonomy, root-cause heuristics) |
| `bpftool_parser.py` | Parse `bpftool prog dump xlated linum` output for source mapping |
| `reject_info.py` | Extract specific contract mismatch details from error lines |
| `shared_utils.py` | Register parsing and verifier type family helpers used across modules |
| `backward_slicing.py` | Top-level backward slice entrypoint (re-exported via proof_engine) |
| `ir_builder.py` | Build SSA-style trace IR from `ParsedTrace` |
| `causal_chain.py` | Causal chain extraction helpers |
| `transitions.py` | Critical state transition detection |

## Notes

- `trace_parser.py`, `proof_engine.py`, and `rust_diagnostic.py` are
  re-export facades kept for backward compatibility; the real implementations
  live in their respective `*_parts/` sub-packages.
- `shared_utils.py` provides register extraction and pointer-type predicates
  used by multiple stages.
- The optional `bpftool_xlated` argument to `generate_diagnostic` enables
  richer source mapping when `bpftool prog dump xlated linum` output is
  available alongside the verifier log.
