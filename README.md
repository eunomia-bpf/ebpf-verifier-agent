# OBLIGE

OBLIGE stands for Obligation-Oriented Diagnostics for eBPF Verifier Failures. The project treats verifier feedback as a systems interface problem: instead of relying on unstable free-text logs, it aims to build a stable, structured diagnostic layer that exposes what proof obligation failed, where it failed, and what kind of repair is appropriate.

This repository is an early scaffold for that workflow. It defines the benchmark case schema, the five-class failure taxonomy, the structured diagnostic schema, and lightweight script skeletons for collection, reproduction, repair-loop planning, and evaluation.

## Goals

- Build a reproducible benchmark of real verifier failure cases.
- Label each case with a compact taxonomy that reflects root cause, not just symptom.
- Emit structured diagnostics that are consumable by humans, tools, and repair agents.
- Evaluate repair performance under different feedback conditions while checking semantic correctness, not just verifier acceptance.

## Repository Layout

```text
benchmark/
  schema.yaml        Benchmark case schema
  collect.py         Collector skeleton for case acquisition
  reproduce.py       Reproduction skeleton for per-case reruns
taxonomy/
  taxonomy.yaml      Five-class failure taxonomy
interface/schema/
  diagnostic.json    Structured diagnostic output schema
agent/
  repair_loop.py     Planning-only repair loop skeleton
eval/
  metrics.py         Aggregate metric utilities
tests/
  test_smoke.py      Basic repository smoke tests
```

## Core Data Models

### Benchmark cases

Each benchmark case represents one verifier failure instance and records:

- provenance and a stable `case_id`
- failing source path and exact compile flags
- canonical target-kernel assumptions
- raw verifier output
- root-cause explanation and reference fix
- semantic oracle for validating that the repaired program is still correct

The canonical schema lives in [benchmark/schema.yaml](/home/yunwei37/workspace/ebpf-verifier-agent/benchmark/schema.yaml).

### Failure taxonomy

OBLIGE uses a deliberately small five-class taxonomy:

1. `source_bug`
2. `lowering_artifact`
3. `verifier_limit`
4. `env_mismatch`
5. `verifier_bug`

The detailed class definitions, inclusion rules, and ambiguity notes live in [taxonomy/taxonomy.yaml](/home/yunwei37/workspace/ebpf-verifier-agent/taxonomy/taxonomy.yaml).

### Structured diagnostics

The structured interface is centered on a few stable fields:

- `error_id`
- `source_span`
- `expected_state`
- `observed_state`
- `missing_obligation`

The JSON schema for these records lives in [diagnostic.json](/home/yunwei37/workspace/ebpf-verifier-agent/interface/schema/diagnostic.json).

## Quick Start

Create a virtual environment, install dependencies, and run the smoke tests:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

You can inspect the current script skeletons with `--help`:

```bash
python benchmark/collect.py --help
python benchmark/reproduce.py --help
python agent/repair_loop.py --help
python eval/metrics.py --help
```

## Current Status

The current repository state is intentionally lightweight. The Python entry points are planning-oriented skeletons rather than full integrations with LLVM, bpftool, libbpf, or kernel instrumentation. They are meant to lock down interfaces early so collection, extraction, and evaluation work can proceed against stable artifacts.

## Near-Term Next Steps

- add concrete case manifests under `benchmark/cases/`
- implement source-specific collectors for selftests, public bug reports, and project fix commits
- connect reproduction to real loaders and captured verifier logs
- populate the structured extractor that maps raw logs to stable `error_id` records
- add semantic oracles and end-to-end evaluation harnesses
