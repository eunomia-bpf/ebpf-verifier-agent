# Paper Outline: OBLIGE

**Working Title**: OBLIGE: Proof-Oriented Diagnostics for eBPF Verifier Failures

---

## Abstract (~200 words)

The eBPF verifier is the kernel's admission controller for safe extensibility, yet its only diagnostic channel is a free-text log buffer whose content is unstable across kernel versions, conflates symptoms with root causes, and lacks source-level actionability. We present OBLIGE, a structured diagnostic interface that extracts proof obligations, cross-layer source mappings, and a stable failure taxonomy from the verifier's internal state. Through a study of N real-world verification failures drawn from Stack Overflow, kernel selftests, and production eBPF projects, we show that raw verifier logs fail to identify the correct source location in X% of cases, conflate distinct failure classes in Y% of cases, and produce inconsistent diagnostics across kernel versions in Z% of cases. OBLIGE's structured interface reduces median repair iterations by A× for human developers and B× for LLM-based repair agents, while adding less than C% load-time overhead. Our results demonstrate that the verifier debugging bottleneck is fundamentally an interface problem: the verifier already computes the information needed for effective diagnosis, but exposes it as unstructured text rather than typed failure semantics.

## 1. Introduction (2.5 pages)

### Opening: A Concrete Motivating Example
- Show a real XDP program that fails verification
- Show the raw verifier log (20+ lines of register states, insn offsets)
- Show that the actual fix is a 2-line null check
- Point: the verifier *knew* what was wrong (nullable pointer not discharged) but communicated it as "R3 invalid mem access 'scalar'"

### The Interface Gap
- eBPF verifier = admission controller at kernel boundary
- An admission controller that only produces free-text denial reasons is a broken interface
- This matters more now than ever: eBPF is in production at scale, and LLM agents are becoming eBPF program generators

### Contributions (3 bullets)
1. First systematic study of verifier diagnostic quality across N failure cases, establishing that the bottleneck is interface-level, not analysis-level
2. OBLIGE: a structured diagnostic interface that extracts proof obligations, stable failure IDs, and cross-layer mappings from verifier state
3. End-to-end evaluation showing A× fewer repair iterations for humans and B× for agents, with <C% load-time overhead

## 2. Background and Motivation (2 pages)

### 2.1 eBPF Verification Pipeline
- Source → LLVM → bytecode → verifier → JIT → execution
- Key: each layer transformation can introduce or obscure failure information
- Verifier maintains rich abstract state (register types, ranges, nullability, reference counts) but only exposes it as verbose() text

### 2.2 The Diagnostic Channel Today
- BPF_PROG_LOAD: log_buf, log_size, log_level
- BTF line_info: exists but underutilized in diagnostics
- What verbose() actually prints: register state dumps, not proof obligations
- Example: same program, 3 kernel versions, 3 different log messages for same root cause

### 2.3 Who Consumes Verifier Diagnostics?
- Human developers (Cilium, Aya, custom programs)
- CI/CD pipelines (detect regressions)
- LLM-based generators (Kgent, SimpleBPF, ad-hoc ChatGPT use)
- Each consumer needs different things; none is well-served today

### 2.4 Why This Is a Systems Problem
- Not solvable by better documentation or prettier printing
- Requires capturing semantic state at the point of failure
- Requires stability guarantees across kernel evolution

## 3. A Study of Verifier Diagnostic Quality (3 pages)

### 3.1 Methodology
- Corpus: N cases from Stack Overflow (76), kernel selftests (200), GitHub issues (26)
- Labeling: failure class (5 classes), root cause, ground-truth fix

### 3.2 Five-Class Failure Taxonomy
- source_bug, lowering_artifact, verifier_limit, env_mismatch, verifier_bug
- Distribution in our corpus (from taxonomy_coverage analysis)
- Decision order for ambiguous cases

### 3.3 Measuring Diagnostic Quality
Three dimensions:
- **Source localizability**: does the log point to the right source location?
- **Obligation specificity**: does it state what proof is missing?
- **Kernel stability**: same cause → same diagnostic across versions?

### 3.4 Findings
- Raw logs fail source localization in X% of cases
- Obligation specificity is near-zero for most failure classes
- Key finding: verifier *computes* the right information internally but *reports* at the wrong abstraction level

## 4. OBLIGE Design (4 pages)

### 4.1 Design Goals
- **Fidelity**: diagnostics must be semantically faithful to verifier state
- **Stability**: same root cause → same error_id across kernel versions
- **Actionability**: diagnostics should directly inform repair actions
- **Low overhead**: negligible impact on verifier load time
- **Backward compatibility**: opt-in; existing log interface unchanged

### 4.2 Structured Diagnostic Schema
- Three layers: failure semantics (error_id), proof obligations, cross-layer mappings
- Schema definition with examples (see interface/schema/diagnostic.json)
- Error_id namespace design and versioning (OBLIGE-Exxx)

### 4.3 Obligation Extraction from Verifier State
- Key insight: verifier's check_* functions already evaluate proof conditions
- We instrument these to emit structured failure events, not parse text
- Walk through 3-4 major check points:
  - check_mem_access → bounds obligation
  - check_helper_call → argument type obligation
  - reference tracking → lifetime obligation
  - path exploration → complexity report

### 4.4 Cross-Layer Source Mapping
- Combine BTF line_info with verifier insn offset
- Compute minimal failing slice (control + data dependency)
- Handle cases where LLVM optimizations obscure source mapping

### 4.5 Discrete Action Space
- Map failure classes to repair action templates (ADD_BOUNDS_GUARD, ADD_NULL_CHECK, etc.)
- Why discrete actions matter for agents: bounded search space

### 4.6 Implementation
- Kernel-side: lightweight hooks in verifier check points
- Userspace: libbpf extension to consume structured output
- Hybrid fallback: userspace parser for kernels without kernel-side support

## 5. Agent Repair on OBLIGE (1.5 pages)

### 5.1 Repair Loop Architecture
- Structured diagnostic → action selection → patch generation → re-verify → semantic check
- Key: agent is a *consumer* of OBLIGE, not part of the contribution

### 5.2 Baseline Configurations
- raw_log: Kgent-style, feed verifier text to LLM
- enhanced_log: Pretty Verifier style
- structured: OBLIGE JSON
- structured+retrieval: OBLIGE + similar past fixes

### 5.3 Semantic Oracle
- Why "passes verifier" is insufficient
- Test-based and reference-behavior checking

## 6. Evaluation (4 pages)

### 6.1 Diagnostic Fidelity
- Error class accuracy, source localization, obligation precision/recall
- Minimal-slice reduction ratio
- Comparison with raw log and Pretty Verifier

### 6.2 Repair Effectiveness
- 4 conditions × 2 consumers (human, agent)
- Primary metrics: success rate, iterations, wall-clock time
- Secondary: patch size, semantic correctness

### 6.3 Cross-Kernel Stability
- ≥3 kernel versions
- Error_id stability vs raw text similarity
- Repair transferability

### 6.4 Overhead
- Verifier load latency (microbenchmark + real programs)
- Diagnostic object size
- Kernel patch footprint (lines changed)

### 6.5 Case Studies
- 2-3 detailed walkthroughs showing the full pipeline

## 7. Discussion (1 page)

- vs Pretty Verifier/Rex/DSL positioning
- Upstream path for kernel adoption
- Generalization to other admission-controller systems
- Limitations

## 8. Related Work (1.5 pages)

- **Verifier complexity and bugs**: HotOS '23, Rex
- **eBPF developer experience**: Deokar et al. (743 SO questions), NCC audit
- **Enhanced diagnostics**: Pretty Verifier
- **LLM-based eBPF**: Kgent, SimpleBPF, Gao et al., verifier-safe DSLs
- **Kernel dependency management**: DepSurf
- **Program repair**: general APR, LLM-based repair
- **Proof-carrying code**: PCC analogy

## 9. Conclusion

The eBPF verifier already possesses the semantic information needed for effective failure diagnosis — it just doesn't expose it. OBLIGE transforms the verifier from a text-producing black box into a typed diagnostic oracle.

---

## Key Figures (8)

1. Motivating example (source → raw log → structured diagnostic → fix)
2. eBPF pipeline with information loss at each layer
3. OBLIGE architecture diagram
4. Failure taxonomy distribution in corpus
5. Source localization accuracy comparison
6. Repair iterations across 4 conditions × 2 consumers
7. Cross-kernel error_id stability
8. Load-time overhead

## Key Tables (5)

1. Failure taxonomy with examples
2. Error_id catalog (representative subset)
3. Diagnostic fidelity metrics
4. Repair effectiveness results
5. Overhead measurements
