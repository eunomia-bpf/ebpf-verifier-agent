# Remaining "No Novelty" Issues: Post-Cleanup Critical Review

**Date**: 2026-03-13
**Reviewer perspective**: Senior program analysis researcher, OSDI/ATC PC member
**Context**: The old 3600-line keyword-matching proof engine was deleted. A new engine is being built with opcode-driven safety condition inference (`opcode_safety.py`). This review identifies what OTHER parts of the system still have "no novelty" problems.

---

## Q1: log_parser.py -- Is This a Problem?

### Current state

`log_parser.py` uses regex to:
1. **Select the error line** from the log via a weighted scoring heuristic (lines 156-196). Keywords like "invalid", "unknown", "unreleased" get positive weight; instruction lines and summary prefixes get negative weight.
2. **Match the error line against the error catalog** (`error_catalog.yaml`) via regex patterns to assign an error ID (OBLIGE-E001 through E023) and a taxonomy class.
3. **Extract source line numbers** from the log via regex.
4. **Collect evidence lines** by keyword-matching for tokens like "R0", "stack", "packet", "helper".

### Verdict: Still necessary, but the taxonomy classification path is a problem

The error catalog matching is needed for a different purpose than `opcode_safety.py`. The opcode-driven approach tells you *what safety condition was violated at the error instruction*. The log parser tells you *what class of error the verifier reported*. These are complementary:

- **opcode_safety.py**: "This is a LDX instruction. The base register R3 must be a non-null pointer with off + 4 <= range."
- **log_parser.py**: "The verifier said 'invalid access to packet'. This is OBLIGE-E001, taxonomy class source_bug."

The problem is **who gets to set the taxonomy class**. Currently, the taxonomy class comes from `log_parser.py` (regex on error message), and `renderer.py` uses it authoritatively (line 215: `_normalize_failure_class` trusts the taxonomy from log_parser). The opcode-driven lifecycle analysis could *derive* the taxonomy class from the proof lifecycle (never_established -> source_bug, established_then_lost -> lowering_artifact), which would be principled. But the system currently does not do this -- it uses the regex-matched taxonomy and explicitly avoids letting TransitionAnalyzer override it (pipeline.py lines 542-594, the large comment block).

**Specific problems**:

1. **Error line selection (lines 156-196)**: This is a heuristic scoring function. It assigns weights to keywords to pick the "most error-like" line. This is fragile: a new kernel version could change the error format and break the scoring. The opcode-driven approach does not need this -- it finds the error instruction in the trace via the `is_error` flag.

2. **Evidence collection (lines 267-291)**: This is pure keyword matching. It scans all lines for tokens like "R0", "stack", "packet" and collects matching lines. This is not analysis; it is grep. It should either be replaced by structured extraction from the parsed trace, or acknowledged as a cosmetic feature.

3. **Catalog matching confidence system (lines 198-253)**: The tiered confidence system (high/medium/low based on which line matched and whether it was the primary or alternate pattern) is engineering, not analysis. A reviewer would note that this is essentially a regex cascade with priority levels.

### Recommendation

**Keep log_parser.py but narrow its role**:
- It should be the *input normalizer* (find the error line, parse the raw log into lines).
- The error_id assignment can stay (stable IDs are useful for tooling).
- The taxonomy_class assignment should be demoted to a *fallback* -- the primary taxonomy classification should come from the proof lifecycle analysis (opcode-driven conditions + monitor result + transition analysis). Only when the engine cannot determine the taxonomy (structural errors with no instruction) should the regex-based taxonomy be used.
- The evidence collection should be replaced by extracting register states and backtracking information from the parsed trace, which is already available.

---

## Q2: pipeline.py -- How Much Heuristic Logic Remains?

### Current state

`pipeline.py` is the single largest file in the system (1200+ lines). After reading it thoroughly, here is the breakdown:

### Principled components (good):
- `try_proof_engine()` (lines 379-684): Runs the TraceMonitor and TransitionAnalyzer. The core flow (decode predicate -> monitor -> analyze transitions) is principled.
- `_monitor_result_to_events()` and `_transition_chain_to_events()`: Convert engine results to ProofEvents. Straightforward data transformation.

### Heuristic components (problems):

1. **`diagnose()` function (lines 47-95)**: Still uses the OLD critical transition types (`NULL_CHECK_ESTABLISHED`, `BOUNDS_ESTABLISHED`, `BOUNDS_COLLAPSE`, `TYPE_DOWNGRADE`, `PROVENANCE_LOSS`) from `trace_parser_parts/_impl.py`. These are detected by the old heuristic functions `_is_bounds_collapse`, `_is_type_downgrade`, etc. in the trace parser. This is a *parallel, redundant proof lifecycle detection system* that exists alongside the new engine. The `diagnose()` function should be deleted or replaced by the engine result.

2. **`_infer_loss_context()` (lines 98-107)**: Pure keyword matching on transition descriptions. Checks if the description contains "spill", "fill", "stack", "arithmetic", "alu", "call", "function". This is exactly the kind of heuristic the opcode-driven approach was meant to eliminate.

3. **`should_ignore_engine_result()` (lines 348-358)**: A heuristic that decides when to throw away the engine's result and fall back to the diagnosis. This is an "if this doesn't work, try that" chain.

4. **`analyze_proof()` (lines 318-345)**: Contains a fallback path where if the engine result is ignored, it synthesizes proof events from the old diagnose() function. This means the old heuristic path is still active as a fallback.

5. **The massive `try_proof_engine()` decision tree (lines 379-684)**: This function has at least 5 different paths:
   - Path A: No instructions in trace -> fallback to engine obligation inference
   - Path B: Predicate inferred, monitor result valid, not classification-only -> use monitor result
   - Path B': Same as B but with temporal ordering correction (loss site after error)
   - Path C: Predicate is None or ClassificationOnly -> use taxonomy from log_parser, NOT from TransitionAnalyzer
   - Path D: Real predicate but monitor returned "unknown" -> use TransitionAnalyzer if it found meaningful transitions
   - Path D': Same as D but with backtracking artifact detection
   - Path E: Real predicate, no transitions found -> final fallback

   This is a 300-line decision tree with multiple fallback levels. Each fallback silently degrades quality. A reviewer would call this "a cascade of heuristics with a principled core."

6. **`build_note()` and `build_help_text()` (lines 894-975)**: These contain keyword matching on `diagnosis.error_id` (e.g., `if diagnosis.error_id == "OBLIGE-E002"`) and on `diagnosis.loss_context` (e.g., `if diagnosis.loss_context == "arithmetic"`). The help text even loads from `obligation_catalog.yaml` via error_id pattern matching.

7. **`_normalize_spans()` (lines 1134-1199)**: Synthesizes a "rejected" span when none exists by finding the last error instruction or the last instruction. This is reasonable engineering but includes heuristics like calling `_extract_source_fields` as a fallback.

### The fundamental architectural problem

Pipeline.py runs THREE parallel analysis systems and merges their results:
1. **log_parser.py** (regex on error message) -> error_id, taxonomy_class
2. **diagnose()** (old critical transition detection) -> proof_status, loss_context
3. **try_proof_engine()** (new engine: predicate + monitor + transition analyzer) -> proof_status, proof_events, obligation

The merging logic (lines 258-315 of `generate_diagnostic()`) prefers the engine result but falls back to diagnose(), and uses log_parser for taxonomy. This three-way merge is the root cause of the complexity.

### Recommendation

**Eliminate the three-way merge**:
1. Delete `diagnose()` and `_infer_loss_context()`. They are redundant with the engine.
2. Make the engine the single source of truth for proof_status. If the engine returns "unknown", report "unknown" -- do not fall back to a heuristic.
3. Make taxonomy_class derivable from the engine result (proof lifecycle + violated condition domain). Use the regex-based taxonomy from log_parser only as a fallback for structural errors (no instruction, no opcode).
4. Simplify `try_proof_engine()` from 300 lines to ~80 lines: decode opcode -> derive conditions -> find violated condition -> monitor -> analyze transitions -> return result. One path, no fallbacks.

---

## Q3: transition_analyzer.py -- Is the Classification Principled?

### Current state

The `TransitionAnalyzer` classifies each instruction's effect on proof-relevant registers into four categories: `NARROWING`, `WIDENING`, `DESTROYING`, `NEUTRAL`.

### Analysis

The bounds classification (`_classify_bounds_change`, lines 387-482) IS principled. It uses proper interval containment:
- Post interval subset of pre interval -> NARROWING
- Pre interval subset of post interval -> WIDENING
- Bounded -> unbounded -> DESTROYING
- The signed bounds checking is also correct.

The type classification (`_classify_type_change`, lines 484-544) IS principled. It uses the correct lattice relationships:
- pointer -> scalar = DESTROYING (TYPE_DOWNGRADE)
- nullable -> non-nullable = NARROWING (NULL_RESOLVED)
- non-nullable -> nullable = WIDENING (NULL_INTRODUCED)

The range classification (`_classify_range_change`, lines 546-581) IS principled:
- range 0 -> positive = NARROWING
- positive -> 0 = DESTROYING (RANGE_LOSS)

The tnum classification (`_classify_tnum_change`, lines 583-611) IS principled:
- Mask grew = WIDENING (more unknown bits)
- Mask shrank = NARROWING

### Problems

1. **`_infer_reason()` (lines 613-713)**: This function uses regex on the bytecode text to explain WHY a transition happened. It pattern-matches stack spill/fill operations, ALU operations, function calls, branches, etc. This is exactly the kind of keyword matching that `opcode_safety.py` was designed to replace. The opcode byte already tells you the instruction class -- you do not need regex on "r0 |= r6" to know it is an OR operation. With the opcode decoder, this function should be replaced by `decode_opcode(hex_str, bytecode)` -> `OpcodeInfo` -> structured reason.

2. **`_is_significant_widening()` (lines 715-727)**: This function decides whether a WIDENING is significant enough to mark as a loss point. It uses keyword matching on the reason string: `"unbounded" in detail.reason.lower()`, `"bounds lost" in detail.reason.lower()`, `"RANGE_LOSS" in detail.reason.upper()`. This is fragile -- it depends on the exact strings produced by earlier classification functions. The determination should be structural: a WIDENING is significant if the post-state makes the predicate evaluate to "violated" when it previously evaluated to "satisfied".

3. **The `_PRECISION_DESTROYING_OPS` set (lines 85-91)**: A hard-coded set of opcode mnemonics that "commonly" destroy precision. This is exactly a keyword heuristic. The opcode-driven approach should replace this: the opcode byte tells you the operation class, and the actual bounds change (pre vs post state) tells you whether precision was actually destroyed. You don't need a list of operations that "commonly" destroy precision -- you can observe whether precision was actually destroyed.

### Recommendation

1. Replace `_infer_reason()` with opcode-driven reason generation. Given a decoded `OpcodeInfo`, generate the reason string from the opcode class + operand registers + the observed state change. No regex needed.
2. Replace `_is_significant_widening()` with predicate-based significance: a WIDENING is significant if evaluating the safety predicate on the post-state yields "violated".
3. Delete the `_PRECISION_DESTROYING_OPS` set. The actual state change (pre vs post bounds) is the ground truth, not a list of "dangerous" operations.

---

## Q4: renderer.py -- Does It Add Bias?

### Current state

The taxonomy override bug was already fixed (the comment at line 211-214 documents this). The renderer now uses the taxonomy from log_parser as authoritative and does NOT let proof_status override it.

### Remaining issues

1. **`_normalize_failure_class()` (lines 210-217)**: If the taxonomy_class from the log_parser is not in `VALID_FAILURE_CLASSES`, it defaults to `"source_bug"`. This is a silent default that could mask classification errors.

2. **`_headline_summary()` (lines 140-161)**: Contains hard-coded logic like `if taxonomy_class == "lowering_artifact" and proof_status == "established_then_lost"` -> "proof established, then lost before rejection". And `if taxonomy_class == "source_bug" and obligation_type == "helper_arg"` -> calls `_helper_contract_headline()`. These are editorial decisions baked into the rendering layer. They should be generated by the analysis layer and passed through to the renderer.

3. **`_helper_contract_headline()` (lines 594-606)**: Keyword matching on the required condition string to generate human-readable headlines. For example, `if "expected=fp" in lowered` -> "helper expected a stack pointer". This is rendering logic that makes decisions about the content of the diagnostic. It should be generated by the analysis, not inferred by the renderer.

4. **`_repair_action_for()` (lines 447-478)**: Determines the repair action (ADD_NULL_CHECK, ADD_BOUNDS_GUARD, TIGHTEN_RANGE, etc.) based on keyword matching on the help_text string. This is analysis masquerading as rendering.

5. **`_evidence_kind_for_detail()` (lines 420-424)**: Classifies evidence items as "kernel_capability" or "heuristic" based on keyword matching for "kernel", "btf", "helper", "kfunc", "attach". Again, this is classification inside the renderer.

### Verdict

The renderer is doing too much classification. Multiple functions make content decisions based on keyword matching. The renderer should be a pure data-to-text/JSON transformation: given structured analysis results, format them. It should not be inferring repair actions, classifying evidence, or generating headlines from keyword matching.

### Recommendation

1. Move `_repair_action_for()` to the engine or synthesizer (which already exists: `engine/synthesizer.py`).
2. Move `_helper_contract_headline()` to the analysis layer -- the obligation should carry a human-readable headline.
3. Make `_headline_summary()` a pure lookup on structured fields, not a keyword-matching function.
4. Change `_evidence_kind_for_detail()` to use structured evidence types from the analysis, not keyword matching on strings.

---

## Q5: What's Missing for OSDI/ATC?

### 5.1 Formal soundness claims

**Missing**: The system cannot prove anything about its analysis. The "soundness" claim (Proposition 1 in the paper) is trivially inherited from the verifier's own soundness -- if the verifier says a bound holds, it holds. OBLIGE does not add soundness.

**What a reviewer would want**: A formal statement of what OBLIGE guarantees. For example: "If OBLIGE classifies a failure as `established_then_lost`, then there exists an instruction i_e < i_l < i_r in the trace such that the safety predicate P holds at s_{i_e} and fails at s_{i_l}." This is provable from the TraceMonitor's algorithm, but the paper needs to state and prove it.

**Principled solution**: Define the analysis formally. The opcode-driven condition derivation can be stated as a function from opcode bytes to safety condition schemas. The TraceMonitor is a standard three-valued trace monitor. The TransitionAnalyzer computes interval containment between consecutive abstract states. All of these are formalizable.

### 5.2 Completeness

**Missing**: No analysis of what fraction of real eBPF failures the system can meaningfully analyze (not just classify, but provide establish/loss lifecycle).

**The numbers that exist** (from the existing eval):
- 262 cases total
- 115 proof_established (43.9%)
- 99 proof_lost (37.8%)
- ~56.5% produce only a single span

**What a reviewer would want**: For the 56.5% of single-span cases, what is the fundamental barrier? Is it that the error is structural (no instruction to analyze)? Is it that the predicate could not be inferred? Is it that the trace is too short? Breaking down the "not analyzable" cases into root causes would show the system's fundamental coverage limits.

**Principled solution**: Run the opcode-driven analysis on all 262 cases and report:
- How many have an error instruction with a decodable opcode? (expected: ~80%)
- How many can derive a safety condition from the opcode? (expected: ~70%)
- How many can find a violated condition at the error instruction? (expected: ~60%)
- How many have an establish/loss lifecycle? (expected: ~40%)

### 5.3 Evaluation experiments needed

**Beyond the current A/B eval**:

1. **Root-cause accuracy evaluation**: For N cases (N >= 50) with manually labeled root causes, does OBLIGE identify the correct root-cause instruction? This requires ground truth.

2. **Cross-kernel stability**: Run the same buggy program on kernel 5.15, 6.1, and 6.6. Does OBLIGE produce the same diagnosis across all three? The opcode-driven approach should be kernel-version-independent; this needs to be demonstrated.

3. **Comparison with state-of-the-art LLMs**: Give GPT-4/Claude the raw verifier log and the OBLIGE diagnostic. Measure whether the diagnostic improves repair accuracy. The existing eval with a 20B local model is underpowered.

4. **Synthesis evaluation**: For the cases where OBLIGE identifies a proof loss, can the synthesizer produce a fix that passes the verifier? This directly demonstrates the practical value of the lifecycle analysis.

### 5.4 Baselines needed

1. **Pretty Verifier**: Already compared (regex on final line). Show that OBLIGE provides strictly more information.
2. **GPT-4 zero-shot**: Give GPT-4 the raw verifier log and ask it to diagnose + fix. This is the "is the tool better than an LLM?" baseline.
3. **Verifier error message alone**: Just the final error line + the register state at the error point. How much does the lifecycle analysis add over this?
4. **No-lifecycle OBLIGE**: OBLIGE with the lifecycle analysis disabled (just classification + source mapping). This isolates the contribution of the lifecycle analysis from the contribution of structured parsing.

### 5.5 Missing components a reviewer would expect

1. **CFG reconstruction from the trace**: The current system treats the trace as a linear sequence. But the verifier explores multiple paths (branching, backtracking). Reconstructing at least a partial CFG from the "from X to Y" annotations would enable path-sensitive analysis and proper join-point detection.

2. **Helper prototype database**: For CALL instructions, the opcode-driven approach knows R1-R5 are arguments but does not know which argument has which type requirement. A static table of the ~200 most common BPF helpers' prototypes would enable precise argument contract checking.

3. **Stack slot tracking**: The trace parser does not track stack slot types. The verifier does (spill/fill with type information). Parsing and tracking stack slot states would enable detecting spill/fill-induced proof loss precisely, rather than heuristically.

4. **Integration with bpftool**: The system should demonstrate it can consume bpftool output directly, making it usable in a real development workflow.

---

## Q6: The "Reading vs Analysis" Test

For each module, the critical question: does this module COMPUTE something that doesn't exist in the verifier's output? Or does it only READ and REFORMAT?

### Modules that COMPUTE (genuine analysis):

| Module | What it computes | Why it's not in the verifier output |
|--------|-----------------|--------------------------------------|
| `engine/transition_analyzer.py` (bounds classification) | Interval containment relationship between consecutive abstract states | The verifier knows bounds changed but does not classify the change as narrowing/widening/destroying |
| `engine/transition_analyzer.py` (type classification) | Lattice ordering between type transitions | Same as above |
| `engine/monitor.py` | Proof lifecycle status (establish/loss sites) | The verifier checks safety forward and stops at the first failure; it does not report where the property was previously satisfied |
| `engine/opcode_safety.py` | Safety conditions from opcode semantics | The verifier computes these internally but does not expose them in the log; OBLIGE re-derives them from the ISA |
| `engine/synthesizer.py` | Repair suggestions from proof-loss analysis | Does not exist in verifier output |
| `value_lineage.py` | Register copy/spill/fill chains | The verifier tracks this internally but does not expose it (except via mark_precise) |
| `trace_parser_parts/_impl.py` (causal chain) | Backward def-use chain from error register | Not in verifier output |
| `trace_parser_parts/_impl.py` (backtrack extraction) | Structured mark_precise chains | Exists in verifier output as unstructured text; OBLIGE structures it |

### Modules that READ/REFORMAT (engineering, not contribution):

| Module | What it does | Why it's not novel |
|--------|-------------|-------------------|
| `log_parser.py` | Regex-matches error line against 23 patterns | Reading and classifying the verifier's own error message |
| `log_parser.py` (evidence collection) | Keyword-scans for "R0", "stack", "packet" | Grep |
| `trace_parser_parts/_impl.py` (state parsing) | Parses "R0=scalar(umin=0,umax=255)" into RegisterState | Reading the verifier's pre-computed abstract states |
| `renderer.py` | Formats analysis results as text/JSON | Pure formatting |
| `source_correlator.py` | Maps instruction indices to BTF source annotations | Reading BTF line_info that the verifier already emits |
| `bpftool_parser.py` | Parses bpftool xlated output | Reading bpftool's output |
| `reject_info.py` | Regex-matches specific verifier rejection patterns | Reading and reformatting verifier error messages |
| `engine/predicate.py` | Evaluates predicates against logged register states | Reading the verifier's pre-computed values and comparing against thresholds |
| `engine/ebpf_predicates.py` | Maps error messages to predicates via 70+ regex | Reading error messages, not analyzing |

### The critical observation

The predicate evaluation classes (`predicate.py`) and the predicate inference module (`ebpf_predicates.py`) are in the READ/REFORMAT category, not the COMPUTE category. They read the verifier's pre-computed bounds/types and compare them against thresholds. This is the same observation from the `novelty-deep-analysis-2026-03-13.md`: "checking if `pkt.off + size <= pkt.range` by reading the verifier's printed values is not novel analysis."

The modules that genuinely COMPUTE are:
1. The transition analyzer's **classification of state changes** (narrowing/widening/destroying)
2. The monitor's **lifecycle detection** (establish/loss)
3. The opcode decoder's **ISA-driven condition derivation**
4. The value lineage's **copy/spill tracking**
5. The causal chain's **backward def-use tracing**

These are the components the paper should emphasize. Everything else is infrastructure.

---

## Summary: Priority-Ordered Action Items

### P0 (Blocks publishability):

1. **Delete `diagnose()` and the old critical transition system**. The trace parser's `_detect_critical_transitions()` and the pipeline's `diagnose()` are a redundant, heuristic-based lifecycle detection system that runs in parallel with the new engine. They create the three-way merge problem in pipeline.py. Delete them and use the engine as the single source of truth.

2. **Wire opcode_safety.py into the pipeline as the primary condition inference path**. Currently `ebpf_predicates.py` (70+ regex) is still the active path (`pipeline.py` line 13: `from .engine.ebpf_predicates import infer_predicate`). The opcode-driven approach needs to replace this, with `ebpf_predicates.py` kept only as a fallback for structural errors.

3. **Replace `_infer_reason()` in transition_analyzer.py with opcode-driven reason generation**. The transition analyzer already has the pre/post register states. Adding the opcode byte (from `InstructionLine.opcode`, already parsed by trace_parser) would eliminate all the regex in `_infer_reason()`.

### P1 (Significantly improves paper quality):

4. **Derive taxonomy_class from proof lifecycle, not from regex on error messages**. The mapping is clear: never_established -> source_bug, established_then_lost -> lowering_artifact (unless the transition cause indicates verifier_limit). Only use regex-based taxonomy for structural errors (no instruction).

5. **Move classification logic out of renderer.py**. The functions `_repair_action_for()`, `_helper_contract_headline()`, `_headline_summary()`, and `_evidence_kind_for_detail()` should not do keyword matching. They should receive structured data from the analysis layer.

6. **Simplify pipeline.py's `try_proof_engine()` from 300 lines to ~80 lines**. One path: opcode -> condition -> monitor -> transition -> result. No fallback cascades.

### P2 (Would strengthen the paper):

7. **Add the opcode byte to TracedInstruction**. The trace parser already parses `InstructionLine.opcode` (the hex string), but `TracedInstruction` does not carry it. Adding a field would enable opcode-driven analysis everywhere without regex on bytecode text.

8. **Build a helper prototype lookup table** for CALL instructions. Even a table of the top 50 helpers would enable precise argument contract checking for the most common cases.

9. **Implement stack slot state tracking** in the trace parser. The verifier's log includes stack slot types (e.g., `fp-8=map_value_or_null`). Tracking these would enable precise spill/fill-induced proof loss detection.

10. **Build a completeness breakdown**: For each case that produces only a single span, identify why the lifecycle analysis did not activate (no instruction, no predicate, trace too short, etc.).

---

## Appendix: Module-by-Module Novelty Assessment

| Module | Lines | Novelty | Status | Action |
|--------|-------|---------|--------|--------|
| `engine/opcode_safety.py` | 668 | HIGH (ISA-driven) | Being built | P0: Wire into pipeline |
| `engine/transition_analyzer.py` | 828 | HIGH (interval arithmetic) | Working | P0: Replace `_infer_reason()` with opcode-driven |
| `engine/monitor.py` | 130 | HIGH (lifecycle detection) | Working | Keep as-is |
| `engine/synthesizer.py` | 446 | MEDIUM (template-based) | Working | Could be stronger with opcode info |
| `engine/predicate.py` | 427 | LOW (reads verifier values) | Working | Needed as evaluation layer; not a contribution |
| `engine/ebpf_predicates.py` | 1105 | ZERO (70+ regex) | Active, should be replaced | P0: Replace with opcode_safety.py |
| `pipeline.py` | 1200+ | MIXED (principled core + heuristic fallbacks) | Working | P0-P1: Major simplification needed |
| `log_parser.py` | 340 | LOW (regex classification) | Working | P1: Narrow role to input normalization |
| `trace_parser_parts/_impl.py` | 1143 | MEDIUM (parsing) + HIGH (backtrack extraction) | Working | P2: Add opcode to TracedInstruction |
| `renderer.py` | 607 | ZERO (formatting) | Working | P1: Remove classification logic |
| `source_correlator.py` | 536 | LOW (BTF mapping) | Working | Keep as-is |
| `reject_info.py` | 624 | LOW (regex refinement) | Working | Keep (useful for helper contract messages) |
| `shared_utils.py` | 125 | N/A (utility) | Working | Keep as-is |
| `value_lineage.py` | ~300 | HIGH (copy/spill tracking) | Working | Keep, strengthen |

**Bottom line**: The system has a principled core (opcode decoder + transition analyzer + monitor + value lineage) surrounded by a thick layer of regex-based heuristics (ebpf_predicates, log_parser evidence collection, transition_analyzer reason inference, renderer classification, pipeline fallback cascades). The cleanup task is to shrink the heuristic layer and make the principled core the primary analysis path.
