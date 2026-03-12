# Critical Novelty Gap Analysis of `proof_analysis.py`

## Bottom line

Bluntly: the current `proof_analysis.py` is useful engineering, but it is not yet a defensible implementation of the paper's strongest novelty claims.

What exists today is:

- structured parsing of verifier verbose logs into per-instruction register states
- heuristic detection of "interesting" state transitions
- heuristic event labeling (`established`, `propagated`, `lost`, `rejected`)
- heuristic or catalog-driven obligation templates
- multi-span rendering on top of those heuristics

What does **not** exist today is:

- a formal proof obligation model tied to the failing instruction
- predicate evaluation over the trace
- a single exact "loss point" derived from predicate truth values
- a real backward slice anchored at that loss point
- type-system-level obligation inference in any strong sense

The strongest seed of real novelty in the current codebase is the extraction and structuring of verifier backtracking / `mark_precise` text. The rest of the "proof analysis" is mostly post-hoc heuristic labeling over parsed states.

## Scope and Method

I read these files completely:

- `interface/extractor/proof_analysis.py` (732 lines)
- `interface/extractor/trace_parser.py` (1135 lines)
- `interface/extractor/diagnoser.py` (803 lines)
- `interface/extractor/rust_diagnostic.py` (911 lines)

I also ran the current pipeline on concrete eval cases to see what the code produces now, rather than relying on cached docs alone.

## Current Pipeline, As Implemented

The actual pipeline is:

1. `trace_parser.parse_trace()` reconstructs `TracedInstruction`, `CriticalTransition`, optional `CausalChain`, and `BacktrackChain` objects from raw log text (`interface/extractor/trace_parser.py:281-302`).
2. `diagnoser.diagnose()` classifies the case, chooses `proof_status`, selects symptom/root instructions, and recommends a fix (`interface/extractor/diagnoser.py:100-203`).
3. `rust_diagnostic.generate_diagnostic()` optionally calls `proof_analysis`, correlates events to source spans, normalizes/prunes spans, and renders the final output (`interface/extractor/rust_diagnostic.py:78-107`).

Important consequence: `diagnoser.py` computes the main `proof_status` and taxonomy **without using** `proof_analysis.py`. `proof_analysis.py` is not the core decision engine today; it is mainly an event/lifecycle enrichment layer for rendering.

Even worse for the novelty claim, `rust_diagnostic._analyze_proof()` explicitly bypasses lifecycle analysis for `source_bug + never_established` and falls back to synthesized events (`interface/extractor/rust_diagnostic.py:110-136`, `139-171`). So on many cases, the pipeline does not even try to use "real" proof analysis.

## Claim-by-Claim Assessment

### 1. Claim: "Meta-analysis of abstract interpretation output"

### What the code actually does

The closest thing to this claim is:

- `parse_trace()` building structured instruction/state objects from the log (`trace_parser.py:281-302`)
- `_aggregate_instructions()` merging state lines into `pre_state` / `post_state` (`trace_parser.py:382-486`)
- `_detect_critical_transitions()` comparing adjacent states and emitting `BOUNDS_COLLAPSE`, `TYPE_DOWNGRADE`, `PROVENANCE_LOSS`, and `RANGE_LOSS` (`trace_parser.py:489-566`)
- `diagnoser._assess_proof()` mapping "any relevant transition" to `established_then_lost`, else scanning for branch/narrowing hints (`diagnoser.py:360-394`)

This is not abstract interpretation over the trace. It is heuristic post-processing of the verifier's already-computed abstract states.

Concrete signs that it is heuristic rather than semantic:

- `_is_bounds_collapse()` uses hand-written thresholds, including `after.umax > before.umax` with a hard cutoff `> max(255, before.umax)` (`trace_parser.py:782-796`).
- `_is_pointer_type()` uses a small hard-coded set plus prefix matching (`trace_parser.py:820-823`).
- `_instruction_proof_signal()` treats a branch as proof-establishing if it "looks like" a comparison and optionally if a range narrowed (`diagnoser.py:412-439`).
- `_state_has_useful_proof()` treats any pointer-like or bounded scalar shape as "useful proof" (`proof_analysis.py:634-645`).

### Novelty assessment

This is **not** a convincing implementation of "meta-analysis of abstract interpretation output" in a research-paper sense.

It is a structured trace parser plus state-diff heuristics. That is worthwhile engineering, but the claim currently overstates it.

### What would be needed to make the claim real

At minimum:

- define formal proof obligations per failing access/helper/use
- evaluate those obligations directly on the parsed abstract states
- derive proof lifecycle from predicate truth values, not from generic "interesting transitions"
- use transition explanations only as secondary evidence, not as the primary proof logic

### 2. Claim: "Backward slicing on verifier trace"

### What the code actually does

There are two distinct mechanisms here:

1. Verifier backtracking extraction:
   - `extract_backtrack_chains()` parses `last_idx`, `first_idx`, `regs=`, `before N:` into `BacktrackChain` / `BacktrackLink` (`trace_parser.py:305-379`)
   - `proof_analysis._select_relevant_chain()` picks a chain by matching `error_insn` (`proof_analysis.py:310-324`)
   - `proof_analysis._events_from_backtrack_chain()` walks the chain backward and labels events from mask changes and transition lookups (`proof_analysis.py:346-438`)

2. Home-grown "causal chain":
   - `_extract_causal_chain()` starts from the error register parsed from the final error text (`trace_parser.py:569-620`)
   - `_trace_register_chain()` recursively follows prior definitions up to depth 5 (`trace_parser.py:623-680`)
   - `_find_previous_definition()` uses state similarity and destination-register regexes (`trace_parser.py:683-703`)
   - `_extract_source_registers()` finds RHS registers by regex over bytecode text (`trace_parser.py:717-740`)

This is not a real backward slice in the usual program-analysis sense.

Key limitations:

- it only works when an error register can be parsed from the final error text (`trace_parser.py:579-581`, `1076-1080`)
- recursion is capped at depth 5 (`trace_parser.py:631-632`)
- "state relatedness" is only `type`, `id`, `off`, and `range` equality (`trace_parser.py:773-779`)
- there is no CFG, dominance, SSA, phi, alias analysis, or control dependence
- the slice is not anchored on a violated proof predicate; it is anchored on a register and/or verifier backtrack text

### Novelty assessment

This is best described as **heuristic backtracking reconstruction**, not backward slicing.

The `mark_precise` extraction itself is the most interesting piece and may be publishable as a systems/diagnostic insight. The rest of the slicing claim is too strong for what is implemented.

### What would be needed to make the claim real

- reconstruct CFG edges from jumps
- version registers per instruction (`pre` / `post`) and build def-use edges
- add control-dependence edges from proof-establishing branches
- start the slice from the exact predicate atom that flips from satisfied to violated
- slice the registers that appear in that atom, not just whichever register the final error text mentions

### 3. Claim: "Proof obligation inference from verifier type system"

### What the code actually does

The implemented logic is:

- `infer_obligation()` picks an obligation type from error-line substrings (`packet`, `map value`, `or_null`, `helper`, `stack`) (`proof_analysis.py:64-103`)
- `_describe_obligation()` returns canned English/formula strings for each obligation kind (`proof_analysis.py:222-248`)
- `_select_obligation_register()` picks a register by scanning type markers or just the first register appearing in the failing bytecode (`proof_analysis.py:251-275`)
- `_instruction_has_type()` and `_first_register_with_type()` decide type matches with substring markers (`proof_analysis.py:277-307`)
- `rust_diagnostic._infer_obligation()` falls back to a YAML catalog plus keyword checks when proof analysis does not provide an obligation (`rust_diagnostic.py:732-759`)

This is not type-system inference. It is template lookup over:

- error-message substrings
- coarse register-type markers
- catalog mappings from error IDs

The weakness is obvious on `stackoverflow-70721661`: `_first_register_with_type()` searches for marker `"pkt"` and therefore treats `pkt_end` as a packet access register, so the obligation register becomes `R2` instead of the actually failing pointer `R1`. That comes directly from substring matching, not type reasoning.

### Novelty assessment

This claim is currently the weakest one.

The code does not infer obligations "from verifier's type system." It maps message patterns to hand-written templates.

### What would be needed to make the claim real

- infer the obligation from the failing opcode, addressing mode, access size, register states, and helper signature
- distinguish pointer kinds semantically (`pkt` vs `pkt_end` vs `map_value` vs `*_or_null`) instead of substring matching
- represent the obligation as machine-checkable atoms over trace state
- only use error text as a fallback when bytecode/state information is insufficient

### 4. Claim: "Proof propagation analysis"

### What the code actually does

`proof_analysis.py` builds a timeline of events:

- `analyze_proof_lifecycle()` sets status based on the presence/absence of `established`, `lost`, and `rejected` events (`proof_analysis.py:106-154`)
- `build_proof_events()` combines backtrack-chain events and state-evolution events (`proof_analysis.py:157-219`)
- `_events_from_backtrack_chain()` marks registers as `established` when they enter the chain or have "useful proof-like" state, `lost` when a selected transition is seen, and `propagated` otherwise (`proof_analysis.py:346-438`)
- `_events_from_state_evolution()` marks the first "useful" state as `established`, any narrowing as `narrowed`, and selected transitions as `lost` (`proof_analysis.py:441-512`)
- `_event_counts_as_established()` treats `propagated` as establishment if the register shape still looks "useful" (`proof_analysis.py:665-670`)

This is not proof propagation in a formal sense. It is event labeling over selected registers.

There is no:

- obligation-specific predicate being tracked
- proof token / fact being propagated across instructions
- distinction between incidental state change and loss of the actual required proof
- single consistent loss-site definition across the pipeline

The last point is important. On `stackoverflow-70750259`, the current system produces three different "loss sites" from three different heuristics:

- `diagnoser._assess_proof()` says proof was lost at insn 20 because it uses the first relevant transition (`diagnoser.py:366-376`)
- `diagnoser._select_root_transition()` picks insn 21 as the root cause because of a hand-written transition priority (`diagnoser.py:452-460`)
- `rust_diagnostic._build_lost_event()` / `_select_loss_transition()` render loss at insn 22 because they maximize a different scoring function (`rust_diagnostic.py:296-313`, `631-639`, `701-704`)

That is strong evidence that the code has no formal propagation model today.

### Novelty assessment

This is best described as **heuristic proof-lifecycle narration**, not proof propagation analysis.

### What would be needed to make the claim real

- track a concrete obligation predicate over time
- define propagation as preservation of that predicate across register versions
- define loss as the first instruction where a predicate atom changes from satisfied to violated/unknown
- emit exactly one lifecycle based on that predicate, then use that lifecycle everywhere in the pipeline

## What Real Proof Analysis Should Look Like

The right model is:

1. infer the exact obligation at the failing instruction
2. express it as formal predicate atoms over register state
3. evaluate those atoms at every instruction state
4. find the precise instruction where the predicate stops holding
5. backward-slice from that exact transition point to the definitions and guards that established the proof earlier

### Core data structures

```python
@dataclass(slots=True)
class TraceIR:
    instructions: list[InstructionNode]
    cfg_edges: list[tuple[int, int]]
    reg_versions: dict[tuple[int, str, str], RegisterVersion]  # (insn, reg, phase)
    backtrack_chains: list[BacktrackChain]  # reused as hints, not ground truth

@dataclass(slots=True)
class InstructionNode:
    insn_idx: int
    bytecode: str
    source_line: str | None
    pre_state: dict[str, RegisterState]
    post_state: dict[str, RegisterState]
    defs: list[str]
    uses: list[str]
    preds: list[int]
    succs: list[int]

@dataclass(slots=True)
class ObligationSpec:
    kind: str                    # packet_access, map_access, null_check, helper_arg, ...
    failing_insn: int
    base_reg: str | None
    index_reg: str | None
    const_off: int
    access_size: int
    atoms: list["PredicateAtom"]

@dataclass(slots=True)
class PredicateAtom:
    atom_id: str                 # non_negative_offset, range_at_least, non_null, type_matches, ...
    registers: tuple[str, ...]
    expression: str

@dataclass(slots=True)
class PredicateEval:
    insn_idx: int
    phase: str                   # pre or post
    atom_id: str
    result: str                  # satisfied, violated, unknown
    witness: str

@dataclass(slots=True)
class TransitionWitness:
    atom_id: str
    insn_idx: int
    before_result: str
    after_result: str
    witness: str

@dataclass(slots=True)
class SliceEdge:
    src: tuple[int, str]
    dst: tuple[int, str]
    kind: str                    # def_use, control, backtrack_hint
    reason: str
```

### Obligation examples

Packet load/store from `rX + const_off`:

```text
packet_access(rX, const_off, size):
  A1: rX.type == pkt
  A2: const_off + size <= rX.range
```

Packet pointer arithmetic `rPtr += rOff`:

```text
packet_ptr_add(rPtr, rOff):
  A1: rPtr.type == pkt
  A2: rOff.smin >= 0
  A3: rOff.umax is bounded
  A4: rPtr.off + rOff.umax <= rPtr.off + rPtr.range
```

Map value access:

```text
map_value_access(rBase, const_off, size, value_size):
  A1: rBase.type in {map_value, map_value_or_null? after non-null discharge}
  A2: const_off + size <= value_size
  A3: if indexed, index.smin >= 0 and index.umax <= value_size - const_off - size
```

Nullable dereference:

```text
non_null_deref(rX):
  A1: rX.type not in {*_or_null}
```

Helper argument:

```text
helper_arg(helper_id, arg_idx, rX):
  A1: type(rX) in helper_signature[helper_id][arg_idx].allowed_types
  A2: if mem arg, referenced range/initialization obligations also hold
```

### Algorithm

#### Step 1: Build `TraceIR`

Reuse `parse_trace()` and extend it with:

- CFG edges from conditional/unconditional jumps
- operand parsing for defs/uses
- register versions for every `(insn, reg, pre/post)` state

#### Step 2: Infer a formal obligation at the failing instruction

Do this from:

- failing opcode
- bytecode operands
- error-line details such as `off=`, `size=`, `value_size=`
- register states at the failing instruction
- helper signature table when the failing instruction is a helper call

Do **not** infer the core obligation from broad text categories like `"packet"` or `"or_null"` alone.

#### Step 3: Evaluate the predicate at each instruction

For each instruction `I` and each atom `A`:

- evaluate `A` on `I.pre_state` and `I.post_state`
- emit `satisfied`, `violated`, or `unknown`
- record a witness string using concrete state fields (`range=14`, `smin=-2147483648`, etc.)

#### Step 4: Detect the transition

Find the last instruction before rejection where the full predicate was satisfied, then the first instruction where any required atom became violated/unknown.

That instruction is the real proof-loss point.

#### Step 5: Backward slice from the violated atoms

Slice from the registers participating in the failed atoms:

- def-use edges for scalar/index registers
- def-use edges for base pointer registers
- control edges from branches that changed predicate truth
- backtrack-chain edges as hints when they agree with the semantic slice

The slice ends at:

- the guard that last established the proof
- the instruction that destroyed it
- the reject site

### Pseudocode

#### Obligation inference

```python
def infer_formal_obligation(trace: TraceIR, fail: InstructionNode, error_line: str) -> ObligationSpec | None:
    op = parse_bytecode(fail.bytecode)

    if op.kind in {"load", "store"} and is_packet_ptr(fail.pre_state.get(op.base_reg)):
        return ObligationSpec(
            kind="packet_access",
            failing_insn=fail.insn_idx,
            base_reg=op.base_reg,
            index_reg=None,
            const_off=op.offset,
            access_size=op.size,
            atoms=[
                PredicateAtom("base_is_pkt", (op.base_reg,), f"{op.base_reg}.type == pkt"),
                PredicateAtom("range_at_least", (op.base_reg,), f"{op.offset} + {op.size} <= {op.base_reg}.range"),
            ],
        )

    if op.kind == "ptr_add" and is_packet_ptr(fail.pre_state.get(op.dst_reg)):
        return ObligationSpec(
            kind="packet_ptr_add",
            failing_insn=fail.insn_idx,
            base_reg=op.dst_reg,
            index_reg=op.src_reg,
            const_off=0,
            access_size=0,
            atoms=[
                PredicateAtom("base_is_pkt", (op.dst_reg,), f"{op.dst_reg}.type == pkt"),
                PredicateAtom("offset_non_negative", (op.src_reg,), f"{op.src_reg}.smin >= 0"),
                PredicateAtom("offset_bounded", (op.src_reg,), f"{op.src_reg}.umax is not None"),
            ],
        )

    if error_line_contains_null(error_line):
        reg = extract_error_register(error_line)
        return ObligationSpec(
            kind="null_check",
            failing_insn=fail.insn_idx,
            base_reg=reg,
            index_reg=None,
            const_off=0,
            access_size=0,
            atoms=[PredicateAtom("non_null", (reg,), f"{reg}.type not nullable")],
        )

    return None
```

#### Predicate evaluation and transition detection

```python
def evaluate_obligation(trace: TraceIR, obligation: ObligationSpec) -> list[PredicateEval]:
    evals = []
    for insn in trace.instructions:
        for phase, state_map in [("pre", insn.pre_state), ("post", insn.post_state)]:
            for atom in obligation.atoms:
                result, witness = eval_atom(atom, state_map, obligation)
                evals.append(PredicateEval(insn.insn_idx, phase, atom.atom_id, result, witness))
    return evals


def find_loss_transition(evals: list[PredicateEval], fail_insn: int) -> TransitionWitness | None:
    grouped = group_by_atom_then_instruction(evals)
    winners = []
    for atom_id, timeline in grouped.items():
        previous = None
        for entry in timeline:
            if entry.insn_idx > fail_insn:
                continue
            if previous and previous.result == "satisfied" and entry.result in {"violated", "unknown"}:
                winners.append(
                    TransitionWitness(
                        atom_id=atom_id,
                        insn_idx=entry.insn_idx,
                        before_result=previous.result,
                        after_result=entry.result,
                        witness=entry.witness,
                    )
                )
            previous = entry
    return pick_earliest_semantically_required_transition(winners)
```

#### Real backward slice

```python
def backward_slice(trace: TraceIR, obligation: ObligationSpec, transition: TransitionWitness) -> list[SliceEdge]:
    worklist = registers_used_by_atom(obligation, transition.atom_id)
    seen = set()
    edges = []

    while worklist:
        insn_idx, reg = worklist.pop()
        if (insn_idx, reg) in seen:
            continue
        seen.add((insn_idx, reg))

        def_site = previous_semantic_definition(trace, insn_idx, reg)
        if def_site is not None:
            edges.append(SliceEdge(def_site, (insn_idx, reg), "def_use", explain_def_use(def_site, reg)))
            worklist.extend(input_registers_of_definition(trace, def_site, reg))

        guard_site = last_guard_that_changed_atom(trace, obligation, reg, insn_idx)
        if guard_site is not None:
            edges.append(SliceEdge(guard_site, (insn_idx, reg), "control", explain_guard(guard_site, reg)))

        for hint in matching_backtrack_edges(trace.backtrack_chains, insn_idx, reg):
            edges.append(SliceEdge(hint.src, hint.dst, "backtrack_hint", hint.reason))

    return topo_sort(edges)
```

## How This Differs from the Current Code

Current code:

- starts from error text and generic transitions
- calls anything "proof-like" an establishment
- calls any relevant loss transition a proof loss
- uses unrelated heuristics in different modules for proof status, root cause, and rendered loss span

Real design:

- starts from the failing instruction's exact obligation
- evaluates that obligation directly on the trace
- identifies one exact state transition that changed the answer
- slices backward from that exact transition
- uses the same transition witness for status, spans, note text, and fix reasoning

## What Can Be Reused

These parts are worth keeping:

- `trace_parser._aggregate_instructions()` / `_parse_register_state()` / `_populate_state_attrs()` as the raw trace front end
- `BacktrackChain` extraction as supplemental evidence
- `RegisterState` and `TracedInstruction` data structures, possibly extended rather than replaced
- source correlation and renderer machinery after better `ProofEvent`s are produced

These parts should be demoted to fallback-only:

- `CriticalTransition` heuristics as weak hints, not as the core proof engine
- `diagnoser._instruction_proof_signal()` branch/comparison token heuristics
- `proof_analysis._state_has_useful_proof()` and `_is_narrowing()` as proof-establish/loss criteria
- catalog/keyword obligation inference in `rust_diagnostic._infer_obligation()`

## Expected Impact on the 241-Case Eval

This needs to be estimated carefully; the current reports already show that many single-span outputs are semantically legitimate, not missing-analysis bugs.

Relevant facts from existing eval reports:

- current 241-case distribution: `90 established_then_lost`, `119 never_established`, `12 established_but_insufficient`, `20 unknown`, `0 satisfied` (`docs/tmp/quality-fix-round2-report.md:109-123`)
- `119` outputs are single-span, but `95/119` of those are already considered legitimate `never_established` cases and `24/119` are degraded zero-trace cases (`docs/tmp/output-quality-analysis.md:20-27`, `54-71`, `89-102`)

So a real proof analysis will **not** magically convert the corpus into rich multi-span stories. The majority of single-span cases should remain single-span.

Realistic improvements are more modest and more important:

1. Reduce false `established_then_lost` decisions caused by incidental transitions.
   - The 30-case audit shows 4 clear `source_bug -> lowering_artifact` errors where the current system over-read a generic transition as proof loss (`docs/tmp/diagnoser-30case-evaluation.md:86-93`).
2. Recover some missed loss sites in trace-rich lowering cases that currently stay at `never_established` because no atom-specific transition is tracked.
3. Make root-cause localization internally consistent.
   - Today the same case can produce different loss sites in `diagnoser`, `proof_analysis`, and `rust_diagnostic`.
4. Improve obligation precision.
   - Especially packet-vs-`pkt_end`, helper-arg type obligations, and direct offset/range predicates.

My estimate:

- meaningful output changes on roughly `15-25` of the `241` cases
- most of those changes would be **correctness** improvements, not span-count inflation
- little or no change on the `24` zero-trace degraded cases
- little change on the `95` legitimate single-span `never_established` cases

On the curated 30-case audit, an obligation-anchored slice would plausibly recover most of the 4 obvious false `source_bug -> lowering_artifact` flips immediately. That does **not** justify extrapolating a huge gain to all 241 cases, but it does suggest the current proof engine is leaving non-trivial correctness on the table.

## Concrete Case Walkthroughs

## 1. `stackoverflow-70750259` (`lowering_artifact`)

### What the current implementation produces

Current output from the live pipeline:

- taxonomy: `lowering_artifact`
- `diagnoser` symptom insn: `24`
- `diagnoser` root cause insn: `21`
- `diagnoser` proof status: `established_then_lost`
- `proof_analysis` lifecycle events:
  - `13 established R5`
  - `13 narrowed R0`
  - `19 established R6`
  - `20 established R0`
  - `21 propagated R0`
  - `22 lost R0`
  - `23 propagated R0`
  - `24 rejected R5`
- rendered `proof_lost` span: insn `22`, `r0 |= r6`

So the current system already disagrees with itself:

- proof lost at `20` in `diagnoser` evidence
- root cause `21` in `diagnoser`
- proof lost at `22` in `proof_analysis` / rendered output

That inconsistency is a direct consequence of using different heuristics in different modules.

### What a real proof analysis would produce

Formal obligation at the failing add:

```text
packet_ptr_add(R5, R0):
  R5.type == pkt
  R0.smin >= 0
  R0.umax is bounded
```

Predicate evaluation over the trace:

- insn `13`: packet proof for `R5` established by `if r5 > r2 goto ...`
- insn `20`: `R0` becomes scalar, but `0 <= R0 <= 255` still satisfies the scalar-offset atoms
- insn `21`: `R0 <<= 8`, still bounded (`0 <= R0 <= 65280`)
- insn `22`: `r0 |= r6`, scalar bounds become unknown; this is the first point where the required offset predicate stops holding
- insn `24`: verifier rejects `r5 += r0`

Real slice:

- establish site: guard at `13`
- loss site: `22`
- backward slice for loss: `19 -> 20 -> 21 -> 22`
- reject site: `24`

### Does the difference matter?

Yes.

Current output is directionally right on taxonomy and roughly right on the loss neighborhood, but it is not rigorous enough to support a strong novelty claim. A real analysis would give one exact transition witness instead of three competing roots. That matters for paper credibility and for any claim of precise localization.

## 2. `stackoverflow-70721661` (`source_bug`)

### What the current implementation produces

Current output:

- taxonomy: `source_bug`
- proof status: `established_but_insufficient`
- lifecycle events:
  - `5 established R1`
  - `5 established R2`
  - `6 rejected R2`
- rendered spans:
  - proof established at the guard `if ((void *)eth + sizeof(*eth) <= data_end)`
  - rejected at `memcpy(&me.dest_ip,ip,sizeof(struct iphdr));`

The obligation/register inference is visibly off here:

- the verifier error is about `R1(id=0,off=30,r=14)`
- `infer_obligation()` picks `R2` because `_first_register_with_type()` matches `"pkt"` against `pkt_end`, so `R2` looks like the first packet-ish register
- `proof_analysis` therefore narrates rejection on the wrong register

Even more importantly, the proof-status decision is wrong in spirit. The branch at insn `5` establishes only that Ethernet header bytes are safe. It does **not** establish the later `iphdr` read.

### What a real proof analysis would produce

Formal obligation at insn `6`:

```text
packet_access(R1, const_off=16, size=4):
  R1.type == pkt
  16 + 4 <= R1.range
```

At insn `6`, the state is `R1(pkt, off=14, r=14)`.

So:

```text
16 + 4 <= 14   =>   false
```

The required proof was never established.

Real output:

- taxonomy: still `source_bug`
- proof status: `never_established`
- failing atom: `range_at_least(R1, 20)`
- first insufficient site: the guard at insn `5` / pointer advance at insn `4` only proved L2 bounds, not IP bounds
- rejected register: `R1`, not `R2`

### Does the difference matter?

Yes.

The current output tells the user "a proof exists but is insufficient," which is weaker and less precise than the real diagnosis: the program never established the required proof for the IP-header access at all. That changes both the explanation and the justification for the fix.

## 3. `stackoverflow-76994829` (`never_established`, single-span)

### What the current implementation produces

Current output:

- taxonomy: `lowering_artifact`
- error id: `OBLIGE-E005`
- proof status: `never_established`
- spans: one rejected placeholder span
- help: `Restructure lowering so the verifier can preserve the earlier proof across the transformed code`

But the raw case has **no instruction/state trace at all**. The "analysis" is effectively:

- catalog/error-line match
- direct obligation template: `reg.off + access_size <= map_value_size`
- zero events
- placeholder rejected span

This is not proof analysis. It is a line-based fallback pretending to be a proof result.

### What a real proof analysis would produce

It should refuse to overclaim.

Correct behavior:

- infer a weak direct obligation from the error line if useful:
  - `map_value_access(...): off + size <= value_size`
- mark proof analysis as `insufficient_trace`
- do **not** claim `lowering_artifact` from proof analysis
- do **not** emit lifecycle events
- do **not** recommend a proof-loss/lowering rewrite on proof-analysis grounds

If classification still happens elsewhere, that should be explicitly labeled as a catalog/error-line fallback, not as proof reasoning.

### Does the difference matter?

Yes, a lot.

This case is exactly where overclaiming is most dangerous. With no trace, there is no novelty in the proof-analysis story. The honest output is "no trace available, cannot analyze proof lifecycle." The current output instead fabricates a proof-flavored diagnosis and a lowering-artifact fix hint.

## Estimated Implementation Effort

For a real version that is strong enough to defend in a paper:

1. Trace IR / CFG / operand parsing: `3-5` engineering days
2. Formal obligation model for packet/map/null/helper-arg cases: `3-5` days
3. Predicate evaluator and transition detector: `4-6` days
4. Real backward slicer with control edges and backtrack hints: `5-7` days
5. Integration into diagnoser + renderer + tests + 241-case rerun: `4-6` days

Rough total:

- MVP for the main obligation families: `~3 weeks`
- hardened version suitable for paper claims and eval refresh: `~4-6 weeks`

## Impact on the Paper Claims

If the code stays as-is, I would **not** claim:

- "meta-analysis of abstract interpretation output"
- "backward slicing on verifier trace"
- "proof obligation inference from verifier type system"
- "proof propagation analysis"

at face value.

I would instead claim something narrower and true:

- structured parsing of verbose verifier traces into instruction/state objects
- extraction of `mark_precise` / backtracking text into structured chains
- heuristic transition detection over parsed abstract states
- heuristic multi-span diagnostics built from those structures

If the real design above is implemented, then the stronger claims become defensible, but only for the obligation families actually supported by the evaluator.

## Final Assessment

As of now, the novelty gap is real.

The current system is not "fake" in the sense of being useless; it does meaningful trace parsing and produces better diagnostics than message-line tools on some cases. But the research novelty is currently overstated. The code is closer to a strong heuristic diagnostic system than to a new proof-analysis method.

If the paper is submitted without closing this gap, reviewers can reasonably say:

- the "proof analysis" is mostly rule-based event labeling
- the "backward slicing" is mostly structured backtrack parsing and regex-based def-use walking
- the "obligation inference" is a lookup table dressed up as type-system reasoning
- the strongest claims are not backed by the implementation

That criticism would be fair.
