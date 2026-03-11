# Research Plan

## Project Thesis

The eBPF verifier exposes free-text failures but not stable, typed failure semantics. OBLIGE treats this as a systems interface problem: extract proof obligations, source mappings, and stable error identifiers so both humans and repair agents can act on verifier feedback efficiently.

## Phase 1: Benchmark Construction

Current target: build 80-150 reproducible verifier failure cases.

Primary collection sources:

- Stack Overflow eBPF verifier questions.
- Community verifier-error repositories.
- Kernel selftests under `tools/testing/selftests/bpf/`.
- Verifier-fix commits from projects such as Cilium, Aya, and Katran.
- Synthetic cases added to close coverage gaps.

Each case should carry:

- a stable `case_id`;
- failing source and compile arguments;
- target kernel assumptions;
- canonical verifier output;
- a taxonomy label;
- a reference fix patch;
- a semantic oracle beyond verifier acceptance.

## Phase 2: Taxonomy and Semantic Choke Points

Goals:

- map verifier check sites to a compact five-class taxonomy;
- identify the highest-value verifier checkpoints for structured extraction;
- define a stable `error_id` namespace that can survive kernel evolution.

## Phase 3: Structured Diagnostic Interface

Implement a prototype userspace extractor first, with a later path toward in-kernel instrumentation.

Required fields for the structured interface:

- `error_id`
- `source_span`
- `expected_state` and `observed_state`
- `missing_obligation`

Backward compatibility matters more than maximal expressiveness. The interface should remain stable enough for longitudinal evaluation across kernels.

## Phase 4: Minimal Slice and Action Space

Add the machinery needed for repair:

- compute a minimal failing slice or localize the failing region;
- define a discrete repair action space such as `ADD_BOUNDS_GUARD` or `ADD_NULL_CHECK`;
- connect structured diagnostics to those repair actions.

## Phase 5: Agent Evaluation

Compare at least four conditions:

- raw verifier log;
- enhanced log with light annotations;
- structured diagnostic interface;
- structured interface plus repair DSL guidance.

Primary metrics:

- success rate;
- iterations to success;
- wall-clock time;
- patch correctness under a semantic oracle;
- cross-kernel stability.

