# Paper Outline

## 1. Introduction

- Verifier failures are a tooling bottleneck for eBPF development.
- Existing interfaces expose logs, not typed diagnostics.
- OBLIGE introduces a structured diagnostic layer centered on proof obligations.

## 2. Problem Statement

- Free-text logs are unstable and hard to consume automatically.
- Passing the verifier is not the same as preserving program semantics.
- Cross-kernel drift makes naive log-driven tooling brittle.

## 3. Design

- Stable failure taxonomy and error identifiers.
- Structured interface with source spans and missing obligations.
- Compatibility path from userspace extraction to kernel instrumentation.

## 4. Implementation

- Benchmark corpus construction.
- Log parsing and source mapping.
- Agent-facing API and evaluation harness.

## 5. Evaluation

- Benchmark coverage and taxonomy distribution.
- Human or agent repair under multiple feedback conditions.
- Patch correctness and cross-kernel stability.

## 6. Discussion

- Limits of userspace parsing.
- Tradeoffs between expressiveness and stability.
- Applicability to other admission-controller style systems.

