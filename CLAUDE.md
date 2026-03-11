# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**OBLIGE** — Obligation-Oriented Diagnostics for eBPF Verifier Failures.

Research project studying the eBPF verifier's diagnostic interface and building a structured, machine-consumable diagnostic layer that enables both human developers and LLM agents to efficiently repair verification failures. Target: OSDI-level systems publication.

### Core Thesis

The eBPF verifier is an admission controller that only exposes free-text logs, not typed failure semantics. This is a **systems interface problem**, not a cosmetic error-message problem. By extracting proof obligations, cross-layer source mappings, and stable failure taxonomies from the verifier, we can dramatically improve both human and automated repair.

## Using Codex CLI as Subagent

OpenAI Codex CLI is available on this machine (`codex-cli 0.113.0`, default model: `gpt-5.4`).

### Division of Labor (IMPORTANT)
- **Codex handles**: ALL code implementation, benchmark collection, data analysis, experiment scripts, literature search/summarization, prototype building, test writing
- **Claude Code handles**: scheduling/dispatching codex tasks, document writing (non-tmp), CLAUDE.md/memory updates, architectural decisions, reviewing codex output, paper framing
- **Claude Code must NEVER**: write analysis code directly, run experiments directly, or manually collect data — always delegate to codex

### Workflow Rules
- **Codex output goes to `docs/tmp/`** — codex writes analysis/research/design docs into `docs/tmp/`
- **Claude maintains non-tmp docs** — Claude directly edits `CLAUDE.md`, `docs/research-plan.md`, and other non-tmp documents
- **Codex runs in background** — use `run_in_background: true` for all codex tasks; Claude dispatches and moves on
- **Review cycle** — when codex produces a new document, dispatch another codex to review it; iterate until quality is sufficient
- **Never ask for confirmation** — just keep going, do all work, iterate multiple rounds autonomously

### Usage
```bash
# Non-interactive execution — no sandbox, no prompts
codex exec --dangerously-bypass-approvals-and-sandbox "your prompt here"

# With a specific working directory
codex exec --dangerously-bypass-approvals-and-sandbox -C /path/to/dir "your prompt here"
```

## Repository Structure

```
ebpf-verifier-agent/
├── CLAUDE.md                    # This file
├── README.md                    # Project overview
├── benchmark/                   # Verifier failure benchmark corpus
│   ├── cases/                   # Individual failure cases (YAML + source + expected)
│   ├── schema.yaml              # Benchmark case schema definition
│   ├── collect.py               # Scripts to collect cases from various sources
│   └── reproduce.py             # Reproduce verifier failures across kernel versions
├── taxonomy/                    # Failure taxonomy and error classification
│   ├── taxonomy.yaml            # The 5-class failure taxonomy
│   ├── error_catalog.yaml       # Enumerated verifier error types with stable IDs
│   └── obligation_catalog.yaml  # Proof obligation templates
├── interface/                   # Structured diagnostic interface prototype
│   ├── schema/                  # JSON schema for structured diagnostics
│   ├── extractor/               # Extract structured diagnostics from verifier output
│   │   ├── log_parser.py        # Parse raw verifier logs
│   │   ├── btf_mapper.py        # BTF/line_info source mapping
│   │   └── obligation.py        # Proof obligation extraction
│   └── api/                     # Agent-facing API
├── agent/                       # LLM agent evaluation harness
│   ├── baselines/               # Baseline conditions (raw log, enhanced log, etc.)
│   ├── repair_loop.py           # Agent repair loop driver
│   ├── oracle.py                # Semantic correctness oracle (not just verifier pass)
│   └── eval.py                  # Evaluation metrics computation
├── eval/                        # Evaluation infrastructure
│   ├── metrics.py               # Metric definitions
│   ├── cross_kernel.py          # Cross-kernel stability evaluation
│   └── results/                 # Experiment results
├── docs/
│   ├── research-plan.md         # Master research plan
│   ├── paper-outline.md         # Paper outline
│   └── tmp/                     # Codex-generated working documents
├── scripts/                     # Utility scripts
│   ├── setup_kernels.sh         # Set up multiple kernel versions for testing
│   └── run_eval.sh              # Run full evaluation pipeline
└── tests/                       # Test suite
```

## Research Phases

### Phase 1: Benchmark Construction (CURRENT)
- Collect 80-150 reproducible verifier failure cases from:
  - Stack Overflow eBPF questions (743-question dataset)
  - ebpf-verifier-errors community repo
  - Kernel selftests (tools/testing/selftests/bpf/)
  - Cilium/Aya/Katran verifier-fix commits (Rex dataset)
  - Synthetic cases for coverage
- Label each case with 5-class taxonomy:
  1. **source_bug**: missing bounds/null/refcount/type checks
  2. **lowering_artifact**: LLVM generated verifier-unfriendly bytecode
  3. **verifier_limit**: safe program exceeds verifier analysis capacity
  4. **env_mismatch**: helper/kfunc/BTF/attach target incompatibility
  5. **verifier_bug**: internal verifier defect

### Phase 2: Taxonomy & Semantic Choke Points
- Map verifier source (kernel/bpf/verifier.c) check functions to failure classes
- Identify the ~20 most impactful check points
- Define stable error_id namespace

### Phase 3: Structured Interface
- Implement diagnostic extractor (userspace first, kernel patch later)
- Four required fields: error_id, source_span, expected/observed state, missing_obligation
- JSON schema with backward compatibility guarantees

### Phase 4: Minimal Slice & Action Space
- Compute minimal failing program slice
- Define discrete repair action space (ADD_BOUNDS_GUARD, ADD_NULL_CHECK, etc.)

### Phase 5: Agent Evaluation
- 4-condition comparison: raw log / enhanced log / structured interface / DSL-guided
- Both human and LLM agent evaluation
- Metrics: success rate, iterations, wall-clock time, patch correctness, cross-kernel stability

## Key Design Decisions
- **Agent is application, not contribution** — the paper's contribution is the interface, not the agent
- **Passing verifier ≠ semantic correctness** — always include task-level semantic oracle
- **In-kernel instrumentation preferred** over userspace log parsing for OSDI credibility
- **Stability over expressiveness** — error_ids must be stable across kernel versions
