# Regex Baseline Design

Date: 2026-03-18

## What the baseline does

The regex baseline is a straw-man diagnostic under `core/baseline/`.
It takes the same input as BPFix: raw verifier log text.

Its pipeline is intentionally shallow:

1. Extract the final verifier-style error message line from the raw log.
2. Match that message against regexes loaded from `taxonomy/error_catalog.yaml`.
3. Map the matched pattern to a taxonomy class.
4. Emit a schema-compatible diagnostic JSON with exactly one rejected span.

There is no trace parsing, no state reconstruction, no lifecycle monitoring, no backward slicing, and no opcode-driven reasoning.

## How it differs from BPFix

The baseline is message-only.
BPFix is trace-driven.

Baseline:

- uses only the final verifier complaint
- classifies by regex match
- always emits a single rejected span
- sets `metadata.proof_status = "unknown"`

BPFix:

- parses the full verifier trace
- infers safety conditions from ISA/opcodes
- monitors proof establishment and loss
- computes richer multi-span diagnostics
- carries structural evidence in metadata

This separation is deliberate for evaluation: the baseline measures what error-message parsing alone can recover.

## How to compare them in eval

Run both systems on the same `verifier_log` string.
Because the baseline emits the same diagnostic schema, evaluation scripts can compare:

- `error_id`
- `failure_class`
- `message`
- `source_span`
- `metadata.proof_status`
- `metadata.proof_spans`

The baseline should be treated as the lower bound.
Any gain from BPFix over this baseline reflects the value of full trace analysis rather than simple surface-pattern matching.
