# Paper Outline: OBLIGE

**Working Title**: OBLIGE: Proof-Aware Diagnosis of eBPF Verifier Failures

---

## Abstract (~200 words)

The eBPF verifier rejects programs with free-text error messages that name the symptom instruction but not the root cause. When a compiler transformation breaks the verifier's proof, the same error message ("invalid access to packet") can mean "your source code is missing a bounds check" or "your bounds check exists but LLVM moved it away from the access." Existing diagnostic tools pattern-match the final error line and cannot distinguish these cases. We present OBLIGE, a userspace diagnostic engine that analyzes the complete instruction-level abstract state trace emitted by the verifier's verbose mode. OBLIGE performs differential diagnosis — detecting where proofs are established, where they are lost, and whether the loss is a source bug, a lowering artifact, or a verifier limitation — and locates the root-cause instruction, which is often distinct from the symptom instruction. Across 30 manually labeled cases spanning 5 failure classes, OBLIGE classifies 83% correctly vs. 63% for the state-of-the-art Pretty Verifier, and localizes the root cause in 40% of cases vs. 0% for Pretty Verifier. On lowering artifacts — the class most confusing to developers — OBLIGE achieves 67% accuracy vs. 17%. We validate these findings against 591 real verifier-fix commits from 5 production eBPF projects.

## 1. Introduction (2.5 pages)

### Opening: A Concrete Lowering Artifact

Show `stackoverflow-79530762`: an XDP program with packet bounds checks present in source, but the compiler reuses different registers for the checked pointer and the dereferenced pointer.

- **What the verifier says**: "invalid access to packet, off=33 size=1, R4(id=10,off=33,r=0)"
- **What Pretty Verifier says**: (crashes with IndexError)
- **What OBLIGE says**: TYPE_DOWNGRADE and PROVENANCE_LOSS on packet registers before the store; causal root at insn 15, key transitions at 20/22/26, error at 36
- **What the actual fix is**: rewrite the loop so checked and dereferenced pointers use the same verifier-visible value — NOT "add another bounds check"

### The Diagnostic Gap

Three observations:
1. **Same message, different problems**: "invalid access to packet" can be source_bug or lowering_artifact, requiring completely different fixes
2. **Developers are confused**: 25% of eBPF StackOverflow questions contain explicit confusion language ("the check is right there, why does the verifier reject?")
3. **Most workarounds aren't bug fixes**: 64% of verifier-fix commits (376/591) are proof-reshaping workarounds (`__always_inline`, `volatile`, loop rewrites), not source safety fixes

### Contributions (3 bullets)

1. **Proof lifecycle analysis**: a diagnostic technique that traces where verifier proofs are established, propagated, and lost across the instruction stream, enabling differential diagnosis of source bugs vs. lowering artifacts
2. **OBLIGE tool**: a userspace diagnostic engine that parses LOG_LEVEL2 verifier traces, detects critical state transitions, extracts causal chains, and produces structured diagnoses with root-cause localization
3. **Empirical study**: 30 manually labeled cases + 591 verifier-fix commits showing that (a) OBLIGE outperforms line-oriented tools on classification (83% vs 63%) and root-cause localization (40% vs 0%), and (b) lowering artifacts are far more prevalent than recognized (64% of production fixes)

## 2. Background and Motivation (2 pages)

### 2.1 eBPF Verification Pipeline

- Source → LLVM → bytecode → verifier → JIT → execution
- Key: each layer can introduce or obscure proof information
- Verifier maintains rich abstract state (register types, scalar bounds, pointer offsets, var_off, reference tracking) but only exposes it via verbose text log

### 2.2 The Diagnostic Channel Today

- `BPF_PROG_LOAD` syscall: `log_buf`, `log_size`, `log_level`
- LOG_LEVEL1: final error line only
- LOG_LEVEL2: full per-instruction register state evolution (500+ lines typical)
- BTF `line_info`: maps bytecode instructions to source file/line
- **Critical gap**: existing tools only use LOG_LEVEL1 (the headline error line)

### 2.3 Why Current Tools Fall Short

| Feature | Raw error | Pretty Verifier | OBLIGE |
|---------|-----------|-----------------|--------|
| Error message parsing | partial | Yes (91 regex branches) | Yes (23 error IDs) |
| Full state trace analysis | No | No | Yes |
| Proof-loss detection | No | No | Yes |
| Root-cause localization | No | No | Yes |
| Lowering artifact detection | No | No | Yes |

### 2.4 Motivating Evidence

- 6 categories of developer pain points with real examples and URLs
- 376/591 (64%) eval commits are proof-reshaping workarounds
- 19/76 (25%) SO questions contain explicit confusion language
- Pretty Verifier crashes on 11% (28/263) of our corpus cases

## 3. The OBLIGE Diagnostic Engine (4 pages)

### 3.1 Architecture Overview

```
verifier_log (LOG_LEVEL2)
    │
    ├── Error Catalog Matching ──→ error_id, error_class
    │
    ├── State Trace Parser ──→ per-instruction register state
    │       │
    │       ├── Critical Transition Detection
    │       │   (BOUNDS_COLLAPSE, TYPE_DOWNGRADE,
    │       │    PROVENANCE_LOSS, RANGE_LOSS)
    │       │
    │       └── Causal Chain Extraction
    │           (backward register dependency tracing)
    │
    └── Differential Diagnosis Engine
            │
            ├── Proof Presence Detection
            ├── Loss Context Classification
            └── Fix Recommendation
                    │
                    ▼
            Diagnosis {error_id, taxonomy_class,
                       symptom_insn, root_cause_insn,
                       proof_status, recommended_fix}
```

### 3.2 State Trace Parsing

Parse LOG_LEVEL2 output into structured per-instruction records:
- Instruction lines: `idx: (opcode) bytecode_text`
- Register state lines: `Rx=type(attrs)`
- BTF source annotations: `; source_line @ file:line`
- Backtracking annotations: `last_idx N first_idx M regs=... stack=...`

Group into `TracedInstruction` objects with pre/post register state.

### 3.3 Critical Transition Detection

Four transition types that indicate proof-state change:

- **BOUNDS_COLLAPSE**: scalar range widens (umax increases, range proof weakened)
- **TYPE_DOWNGRADE**: pointer type degrades to scalar or less-precise type
- **PROVENANCE_LOSS**: tracked register becomes untracked (id changes)
- **RANGE_LOSS**: packet range proof `r` drops to 0

Detection is per-register across instruction boundaries. Each transition records (insn_idx, register, before_state, after_state).

### 3.4 Causal Chain Extraction

Given the error instruction, trace backward through register dependencies:
- Follow register-to-register copies (mov, add with regs)
- Follow load sources (memory reads from stack/map)
- Identify the earliest instruction that "set up" the failing state
- Integrate verifier backtracking annotations when present

### 3.5 Differential Diagnosis

The core novelty: map (error_id × transitions × context) → taxonomy_class.

**Decision procedure**:
1. If error matches `env_mismatch` patterns (unknown helper/kfunc, BTF mismatch, attach type) → `env_mismatch`
2. If error matches `verifier_limit` patterns (complexity, stack depth, program size) → `verifier_limit`
3. If critical transitions exist before error instruction:
   - Proof was established then lost → `lowering_artifact`
   - Loss context (arithmetic, function boundary, register spill) confirms
4. If no transitions (proof was never established) → `source_bug`
5. Kernel crash/warning in log → `verifier_bug`

### 3.6 Fix Recommendation

Map (taxonomy_class, error_id, loss_context) → fix strategy:
- `source_bug` + packet: "Add bounds check before access"
- `lowering_artifact` + function_boundary: "Add `__always_inline`"
- `lowering_artifact` + arithmetic: "Add explicit unsigned clamp"
- `lowering_artifact` + register_reuse: "Rewrite loop to use same variable for check and access"
- `verifier_limit` + complexity: "Split into tail calls"

## 4. Failure Taxonomy and Error Catalog (1.5 pages)

### 4.1 Five-Class Taxonomy

| Class | Meaning | Prevalence |
|-------|---------|------------|
| source_bug | Missing safety check in source code | 88.1% |
| lowering_artifact | Compiler broke verifier proof | 4.0% |
| verifier_limit | Safe program exceeds verifier capacity | 1.3% |
| env_mismatch | Kernel/helper/BTF version incompatibility | 6.3% |
| verifier_bug | Internal verifier defect | 0.3% |

### 4.2 Error Catalog

23 stable error IDs (OBLIGE-E001 through E023) covering 87.1% of 302 cases.
Each ID maps to: regex pattern, taxonomy class, recommended fix template.

### 4.3 Lowering Artifacts: The Hidden Class

- 64% of production verifier-fix commits are proof-reshaping workarounds
- Developers think they have source bugs when they actually have lowering artifacts
- Three main lowering mechanisms: signed/unsigned, inlining, register reuse

## 5. Evaluation (4 pages)

### 5.1 Corpus

| Source | Cases | With verifier log | With fix |
|--------|-------|--------------------|----------|
| StackOverflow | 76 | 66 | 66 |
| Kernel selftests | 321 | 321 | 321 |
| GitHub issues | 26 | 26 | 15 |
| Production commits | 591 | 93 | 591 |

30 cases manually labeled with ground-truth taxonomy class by domain expert.

### 5.2 Classification Accuracy (OBLIGE vs Pretty Verifier)

| Metric | Pretty Verifier | OBLIGE |
|--------|----------------|--------|
| Overall classification | 19/30 (63%) | 25/30 (83%) |
| Lowering artifact | 1/6 (17%) | 4/6 (67%) |
| Root cause localization | 0/30 (0%) | 12/30 (40%) |
| Actionable diagnosis | 5/30 (17%) | 20/30 (67%) |

### 5.3 Lowering Artifact Deep-Dive

6 confirmed lowering-artifact cases. Message-line-only baseline: 2/6 (33%). Trace analysis: 4/5 (80%) on analyzable cases.

Key finding: on 4/4 successful trace cases, the root-cause instruction differs from the error instruction. This is the proof-loss site that explains the actual fix.

### 5.4 LLM Experiment

22 cases × 3 conditions × 2 model strengths. All conditions near ceiling (95-100% accuracy).

**Interpretation**: Strong LLMs already understand verifier logs well from training data. OBLIGE's value is not "helping LLMs" but providing deterministic, reproducible, tool-speed diagnosis without LLM latency/cost.

### 5.5 Production Commit Analysis

591 verifier-fix commits from Cilium, Aya, Katran, bcc, libbpf:
- 229 `inline_hint` (39%) — lowering artifact signal
- 18 `volatile_hack` (3%) — lowering artifact signal
- 32 `alignment` (5%) — mixed
- 64% are proof-reshaping workarounds, not source safety fixes

### 5.6 Cross-Kernel Stability (TODO)

Same cases on 3+ kernel versions: OBLIGE error_id stability vs raw message text drift.

## 6. Case Studies (1.5 pages)

### 6.1 stackoverflow-79530762: Packet Pointer Reuse

Bounds check exists but compiler uses different register paths for check vs access. Message says "add bounds check." OBLIGE finds PROVENANCE_LOSS, points to proof-loss site. Fix: rewrite loop.

### 6.2 stackoverflow-74178703: Hoisted Guard Computation

Loop guard hoisted away from map access. Message says "tighten bounds." OBLIGE finds BOUNDS_COLLAPSE at insn 204. Fix: restructure loop.

### 6.3 github-aya-rs-aya-1062: Signed Arithmetic Lowering

Rust `unwrap()` lowers to sign-extension that creates negative range. Message correctly hints at lowering but doesn't localize. OBLIGE finds damage at insns 4-8, before helper call at 39.

## 7. Discussion (1 page)

### 7.1 Positioning vs Related Work
- Pretty Verifier: complementary (line-level) vs OBLIGE (trace-level)
- Rex: studies workaround patterns; OBLIGE diagnoses them automatically
- SimpleBPF/Kgent: consumers of diagnostics; OBLIGE is the diagnostic producer

### 7.2 Limitations
- Requires LOG_LEVEL2 (verbose mode), which adds load-time overhead
- Subprogram-boundary artifacts not yet fully recovered
- 30-case manual label set is small (though backed by 591 production commits)
- Kernel-side integration would be more robust than userspace log parsing

### 7.3 Upstream Potential
- Structured diagnostic output could be proposed as kernel patch
- error_id stability across versions would benefit all eBPF tooling

## 8. Related Work (1.5 pages)

- **Verifier complexity**: HotOS '23 ("kernel extension verification is untenable"), PREVAIL
- **Developer experience**: Deokar et al. (743 SO questions), NCC audit
- **Enhanced diagnostics**: Pretty Verifier (2025, line-oriented), DepSurf (dependency surface)
- **LLM-based eBPF**: Kgent (SIGCOMM '24), SimpleBPF (2025), verifier-safe DSLs
- **Workaround patterns**: Rex (ATC '25, 72 commits from 3 projects)
- **Program repair**: general APR, LLM-based repair

## 9. Conclusion

The eBPF verifier's verbose mode already emits rich proof-state information, but existing tools only parse the final error line. OBLIGE demonstrates that full proof-trace analysis enables differential diagnosis — distinguishing source bugs from lowering artifacts, locating proof-loss sites rather than symptom sites, and recommending class-appropriate fixes. As eBPF moves to increasingly complex use cases, the gap between what the verifier computes and what developers see will only widen.

---

## Key Figures (7)

1. Motivating example: lowering artifact with source check present but proof lost
2. eBPF pipeline with proof information flow (established → propagated → lost → error)
3. OBLIGE architecture diagram (trace parser → transition detector → causal chain → diagnoser)
4. Failure taxonomy distribution in manual-30 + production-591 corpora
5. OBLIGE vs Pretty Verifier comparison on 30-case manual set
6. Lowering artifact case study: proof timeline showing establishment, transitions, and loss
7. Production commit analysis: 64% proof-reshaping vs 36% source fixes

## Key Tables (5)

1. Five-class failure taxonomy with examples and prevalence
2. OBLIGE vs Pretty Verifier accuracy comparison (overall, per-class, root-cause)
3. Pretty Verifier handler → OBLIGE error ID cross-mapping (showing PV's coarser granularity)
4. Lowering artifact deep-dive: message-line vs trace analysis comparison
5. Production commit fix-type distribution across 591 commits from 5 projects
