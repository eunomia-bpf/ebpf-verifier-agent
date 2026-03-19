# bpftool xlated linum Integration Report

Date: 2026-03-12

## Scope

Added optional support for `bpftool prog dump xlated linum` as a supplementary source-location input for BPFix. The goal was to preserve source correlation when verifier logs contain instruction traces but lack inline BTF source annotations.

## Implemented Changes

### 1. New bpftool parser

Added `interface/extractor/bpftool_parser.py`.

- Parses `bpftool prog dump xlated linum` instruction lines of the form `IDX: (OP) BODY`
- Parses source annotation comment lines of the form `; SOURCE_TEXT @ file:line[:col]`
- Tracks the active source annotation and applies it to subsequent instructions until the next annotation
- Returns an instruction-indexed mapping with:
  - instruction index
  - bytecode text
  - source text
  - source file
  - source line
  - source column

### 2. Source correlation fallback

Updated `interface/extractor/source_correlator.py`.

- `correlate_to_source()` now accepts an optional `bpftool_source_map`
- When proof events and parsed verifier instructions do not carry source annotations, the correlator now falls back to bpftool-derived source text and file/line information
- Source-range expansion now groups adjacent instructions by bpftool source metadata when verifier-log BTF annotations are absent
- Source suffix parsing now accepts both `@ file:line` and `@ file:line:col`

### 3. Diagnostic pipeline integration

Updated `interface/extractor/rust_diagnostic.py`.

- `generate_diagnostic()` now accepts `bpftool_xlated: str | None = None`
- When provided, the string is parsed once with `parse_bpftool_xlated_linum()`
- The resulting mapping is passed into both:
  - the primary proof-event correlation path
  - the synthesized-span fallback path inside span normalization

### 4. Tests

Added and updated tests:

- `tests/test_bpftool_parser.py`
  - validates parsing of instruction index, bytecode, file, line, and column
- `tests/test_source_correlator.py`
  - validates source correlation fallback using bpftool mappings when the trace lacks verifier-log BTF annotations
- `tests/test_renderer.py`
  - validates the end-to-end `generate_diagnostic(..., bpftool_xlated=...)` path on a verifier log with stripped inline BTF annotations

## Validation

Executed:

```bash
python -m pytest tests/ -x -q
```

Result:

```text
107 passed in 2.88s
```

## Notes

- This integration is intentionally supplemental. BPFix still relies on verifier logs for proof-state reasoning; bpftool data only restores source correlation when inline log annotations are unavailable.
- Source columns are parsed and retained in the bpftool mapping but are not yet rendered in `SourceSpan`, which currently remains line-granular.
