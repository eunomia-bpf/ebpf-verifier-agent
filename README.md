# OBLIGE

OBLIGE stands for Obligation-Oriented Diagnostics for eBPF Verifier Failures. The project treats verifier feedback as a systems interface problem: instead of relying on unstable free-text logs, it aims to build a stable, structured diagnostic layer that exposes what proof obligation failed, where it failed, and what kind of repair is appropriate.

The repository contains the current extractor pipeline, taxonomy/catalog data, case-study corpus utilities, and evaluation scripts used to analyze verifier failures.

## Install

Create a virtual environment and install OBLIGE in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

If you only want the raw dependencies without packaging metadata, `pip install -r requirements.txt` still works.

## Repository Layout

```text
case_study/
  schema.yaml        Benchmark case schema
  collect.py         Case acquisition utilities
  reproduce.py       Per-case rerun helpers
taxonomy/
  taxonomy.yaml      Five-class failure taxonomy
  error_catalog.yaml Stable verifier error catalog
  obligation_catalog.yaml Repair-oriented obligation templates
interface/extractor/
  rust_diagnostic.py End-to-end diagnostic pipeline
  proof_engine.py    Formal proof analysis engine
  trace_parser.py    LOG_LEVEL2 trace parser
interface/schema/
  diagnostic.json    Structured diagnostic output schema
oblige/
  cli.py             `python -m oblige` / `oblige` entry point
tests/
  test_*.py          Extractor, renderer, schema, and CLI coverage
docs/
  research-plan.md   Longer-lived project notes
  tmp/               Ephemeral review and experiment reports
```

## CLI Usage

Generate a human-readable diagnostic from a raw verifier log:

```bash
python -m oblige path/to/verifier.log
```

Generate JSON instead:

```bash
python -m oblige path/to/verifier.log --format json
```

The CLI also accepts a case-study YAML manifest and extracts its `verifier_log` automatically:

```bash
python -m oblige case_study/cases/stackoverflow/stackoverflow-60053570.yaml --format both
```

You can also pipe a log over stdin:

```bash
cat verifier.log | python -m oblige --format json
```

## Python Usage

```python
from pathlib import Path

from oblige import build_diagnostic, generate_diagnostic

raw_log = Path("verifier.log").read_text()

schema_valid_payload = build_diagnostic(raw_log, case_id="demo-case")
rich_output = generate_diagnostic(raw_log)
print(rich_output.text)
```

The JSON schema for emitted diagnostics lives in [diagnostic.json](/home/yunwei37/workspace/ebpf-verifier-agent/interface/schema/diagnostic.json).

## Quick Start

Run the test suite:

```bash
python -m pytest tests/ -q
```

Inspect the CLI:

```bash
python -m oblige --help
```

## Project Scope

The current focus is the Python-based diagnostic/extraction pipeline plus the corpus and evaluation tooling around it. Some surrounding directories still contain research scripts and experiment harnesses; `docs/tmp/` is intentionally reserved for temporary reports rather than permanent documentation.
