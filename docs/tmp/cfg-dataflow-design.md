# CFG Reconstruction + Reaching Definitions + Control Dependence from BPF Verifier Traces

## Design Document

**Goal**: Transform BPFix from "structured reading of verifier output" to "genuine program analysis on top of verifier output." All analysis must use ZERO keyword heuristics — only structural data from the trace (opcode bytes, instruction indices, branch offsets, register states, `from X to Y` annotations, backtracking chains).

---

## 1. What Information the Trace Provides

### 1.1 Per-Instruction Data Available

Each `TracedInstruction` in the parsed trace provides:

| Field | Example | Use for CFG/Dataflow |
|-------|---------|---------------------|
| `insn_idx` | `24` | Node identity in CFG |
| `bytecode` | `r5 += r0` | Instruction semantics; branch targets via `goto pc+N` |
| `pre_state` | `{R0: scalar(umax=255), R5: pkt(off=6,r=6)}` | Reaching abstract state |
| `post_state` | `{R0: scalar(), R5: pkt(off=6,r=6)}` | Output abstract state |
| `backtrack` | `BacktrackInfo(last_idx=24, first_idx=12, ...)` | Verifier's own backward slice |
| `source_line` | `if (data_end < (data + ext_len))` | BTF mapping |
| `is_error` / `error_text` | `True` / `"math between pkt..."` | Error site identification |

The raw log also contains:
- **Opcode hex byte**: `(71)`, `(0f)`, `(2d)`, etc. — available in `InstructionLine.opcode` but NOT currently propagated to `TracedInstruction`. **Must fix this.**
- **`from X to Y:` annotations**: Indicate the verifier switching DFS branches. `from 28 to 30:` means instruction 28 was a branch and the verifier is now exploring the path to instruction 30.
- **`goto pc+N` in bytecode text**: Branch target = `insn_idx + N + 1` for conditional branches, `insn_idx + N + 1` for unconditional.

### 1.2 Opcode Byte Decoding (Already Implemented)

`opcode_safety.py` already provides `decode_opcode(hex_str, bytecode_text) -> OpcodeInfo` with:
- `is_branch: bool` — True for JMP/JMP32 conditional branches
- `is_call: bool` — True for BPF_CALL (0x85)
- `is_exit: bool` — True for BPF_EXIT (0x95)
- Opcode class (ALU, LDX, STX, JMP, etc.)

### 1.3 Branch Target Extraction

BPF branch instructions have the form:
```
N: (XX) if rA op rB goto pc+OFFSET
N: (XX) goto pc+OFFSET
```

The target instruction index is `N + OFFSET + 1`. The offset is directly available in the bytecode text. For conditional branches, there are two successors:
- **Fall-through**: `N + 1` (or `N + 2` for wide instructions like `ld_imm64`)
- **Branch target**: `N + OFFSET + 1`

For unconditional `goto`, there is only one successor: `N + OFFSET + 1`.

### 1.4 `from X to Y` Annotations

These are gold. When the verifier outputs `from X to Y:`, it means:
- Instruction X is a branch (already explored one direction)
- The verifier is now exploring the path starting at instruction Y
- **This IS a CFG edge**: X -> Y

These annotations capture edges that the verifier actually traverses. Combined with sequential fall-through, they give us the explored CFG.

### 1.5 What's NOT in the Trace

- **Complete program bytecode**: The trace only shows instructions the verifier explored. Dead code (unreachable from entry) is absent.
- **Instructions on unexplored paths**: If the verifier prunes (error before full exploration), some feasible paths may be missing.
- **The full 8-byte instruction encoding**: Only the opcode byte and disassembled text are shown. But text is sufficient for target extraction.

---

## 2. CFG Reconstruction

### 2.1 Algorithm

```
INPUT:  ParsedTrace with instructions list, raw log lines
OUTPUT: CFG as adjacency list: Dict[int, Set[int]]  (insn_idx -> successor insn_idxs)

STEP 1: Collect all instruction indices from the trace
  - insn_set = {insn.insn_idx for insn in trace.instructions}
  - Also include targets from `from X to Y` annotations

STEP 2: For each instruction, determine successors
  FOR each insn in trace.instructions:
    opcode_hex = insn._opcode_hex  # MUST propagate from InstructionLine
    info = decode_opcode(opcode_hex, insn.bytecode)

    IF info.is_exit:
      # No successors — this is a terminal node
      successors[insn.insn_idx] = set()

    ELIF info.is_call:
      # CALL returns to insn+1 (BPF intra-object calls also return to insn+1)
      successors[insn.insn_idx] = {insn.insn_idx + 1}

    ELIF info.is_branch:
      target = extract_branch_target(insn.bytecode, insn.insn_idx)
      IF target is not None:
        IF is_unconditional_goto(insn.bytecode):
          successors[insn.insn_idx] = {target}
        ELSE:
          # Conditional: fall-through + target
          fall_through = insn.insn_idx + 1
          successors[insn.insn_idx] = {fall_through, target}

    ELIF info.opclass == LD and opcode_hex == "18":
      # ld_imm64 is a 2-slot instruction (occupies insn N and N+1)
      successors[insn.insn_idx] = {insn.insn_idx + 2}

    ELSE:
      # Sequential fall-through
      successors[insn.insn_idx] = {insn.insn_idx + 1}

STEP 3: Augment with `from X to Y` edges
  FOR each (from_idx, to_idx) in parsed from-to annotations:
    successors[from_idx].add(to_idx)
    # This may add edges we missed from Step 2 (e.g., branch targets
    # where we couldn't parse the offset)

STEP 4: Build predecessor map (reverse edges)
  FOR each (src, dsts) in successors:
    FOR each dst in dsts:
      predecessors[dst].add(src)

RETURN (successors, predecessors)
```

### 2.2 Branch Target Extraction (Pseudocode)

```python
BRANCH_RE = re.compile(r'goto\s+pc([+-]\d+)')

def extract_branch_target(bytecode: str, insn_idx: int) -> int | None:
    match = BRANCH_RE.search(bytecode)
    if match:
        offset = int(match.group(1))
        return insn_idx + offset + 1
    return None

def is_unconditional_goto(bytecode: str) -> bool:
    text = bytecode.strip().lower()
    return text.startswith("goto ")  # no "if" prefix
```

### 2.3 Completeness Analysis

**Question**: Does the verifier trace contain ALL branches of the program?

**Answer**: NO, in general. The verifier explores the program via DFS, and if it encounters an error, it may stop before exploring all paths. However:

1. **For the failing path**: The trace contains the complete execution path from entry to the error instruction. This is the path that matters most for backward slicing.

2. **For the explored paths**: All paths the verifier explored (including backtracking to explore both branches of conditionals) are present, indicated by `from X to Y` annotations.

3. **The partial CFG is sufficient for backward slicing** because:
   - The error instruction is always on an explored path
   - Backward slicing from the error only needs the instructions that were actually explored on the path leading to the error
   - Control dependence analysis on the partial CFG still correctly identifies which branches caused the error path to execute

4. **The same instruction may appear multiple times** in the trace (explored on different paths through different branch states). The CFG uses instruction indices (static positions), not trace positions. Multiple trace appearances of the same `insn_idx` represent the verifier exploring that instruction under different abstract states — the CFG edge structure is the same.

**Conclusion**: A partial CFG built from the explored trace is sufficient for backward slicing from the error point. This is actually stronger than a general CFG because we know which path the verifier was on when it detected the error.

---

## 3. Basic Block Construction

### 3.1 Algorithm

```
INPUT:  CFG (successors, predecessors)
OUTPUT: List[BasicBlock], each with (entry_idx, exit_idx, instruction_indices)

STEP 1: Identify block leaders
  leaders = {entry_point_idx}  # insn 0 or first explored instruction
  FOR each (src, dsts) in successors:
    IF len(dsts) > 1:
      # Branch instruction — each target starts a new block
      FOR dst in dsts:
        leaders.add(dst)
    IF len(dsts) == 1:
      dst = single element of dsts
      IF len(predecessors[dst]) > 1:
        # Merge point — starts a new block
        leaders.add(dst)
  # Also: any instruction that is a branch target but not a fall-through
  FOR each insn_idx with len(predecessors[insn_idx]) > 1:
    leaders.add(insn_idx)

STEP 2: Build basic blocks
  sorted_leaders = sorted(leaders)
  blocks = []
  FOR i, leader in enumerate(sorted_leaders):
    # Collect instructions in this block
    insns = [leader]
    current = leader
    WHILE current + 1 not in leaders AND current + 1 in insn_set:
      # Check if current is a branch/exit (block terminator)
      IF successors[current] != {current + 1}:
        BREAK
      current += 1
      insns.append(current)
    blocks.append(BasicBlock(insns))

RETURN blocks
```

### 3.2 BasicBlock Data Structure

```python
@dataclass
class BasicBlock:
    block_id: int               # Sequential ID
    entry_idx: int              # First instruction index
    exit_idx: int               # Last instruction index
    insn_indices: list[int]     # All instruction indices in order
    successors: set[int]        # Successor block IDs
    predecessors: set[int]      # Predecessor block IDs
    gen: dict[str, int]         # GEN set: {register -> defining insn_idx}
    kill: set[str]              # KILL set: {registers written in this block}
```

---

## 4. Reaching Definitions

### 4.1 The "Computing vs Reading" Argument

The verifier trace already gives us the **abstract state** (register types and bounds) at every instruction. We do NOT need to compute reaching abstract values — the verifier already computed them, and we're reading the result.

But there are TWO kinds of reaching definitions:

**Type A — Abstract State Reaching Defs** (verifier provides):
> "At insn 24, R0 has type `scalar(umax=65280)` — this was computed by the verifier."

**Type B — Syntactic Reaching Defs** (we must compute):
> "At insn 24, the value in R0 was last written at insn 20 by `r0 = *(u8 *)(r0 +3)`, which read from the packet. Before that, R0 was defined at insn 2 by `r0 = r1` (copy of R1, the `ctx->data` pointer)."

**Type B is what we need.** It gives us the DEF-USE chain — which instruction produced the value that caused the error. The verifier trace gives Type A for free, but Type B requires analyzing instruction semantics to track which instruction wrote to which register.

### 4.2 Current State: value_lineage.py

`value_lineage.py` already does a form of Type B tracking:
- Tracks register copies (`r3 = r0` -> R3 inherits R0's lineage)
- Tracks stack spills/fills (`*(u64 *)(r10 -8) = r0` -> stack inherits R0)
- Tracks ALU with constants (`r0 += 14` -> R0 inherits with offset delta)
- Tracks ALU with registers (`r0 |= r6` -> lineage destroyed)

**What's missing from value_lineage.py**:
1. No fixed-point iteration — it processes the trace linearly (trace order, not CFG order)
2. No handling of merge points — at a join, which definition reaches?
3. No control flow awareness — if insn X defines R0 on one branch and insn Y defines R0 on another, and they merge at insn Z, value_lineage picks one arbitrarily (whichever was last in trace order)

### 4.3 Do We Need Fixed-Point Reaching Definitions?

**Key insight**: For backward slicing FROM the error instruction, we don't need a full fixed-point reaching definitions analysis. We need to trace backward from the error along the SPECIFIC PATH the verifier was exploring when it hit the error.

The verifier trace gives us a SINGLE PATH (or a small set of paths) from entry to error. On a single path, reaching definitions are trivially computable in one backward pass — no iteration needed:

```
FOR each register R used at the error instruction:
  Scan backward through the trace from the error position
  Find the most recent instruction that WROTE to R
  That instruction is the reaching definition of R at the error point
  Recursively find reaching definitions of R's source registers
```

This is exactly what `_find_previous_definition` in `_impl.py` and `value_lineage.py` already do, just not framed as "reaching definitions."

**However**, for MERGE POINTS, we do need to be more careful. If the error path goes through a branch merge (`from X to Y`), the register state at Y is the JOIN of states from all predecessors. In this case, there may be MULTIPLE reaching definitions (one from each path entering the merge). A proper reaching-definitions analysis would track all of them.

### 4.4 Reaching Definitions on the Trace Path (Enhanced Algorithm)

Rather than a full fixed-point analysis (expensive, overkill), we enhance the existing backward scan with merge-point awareness:

```
INPUT:  trace instructions (in trace order), CFG, error_insn_idx, register R
OUTPUT: set of (defining_insn_idx, bytecode) pairs

def reaching_defs_on_path(trace, cfg, target_idx, register):
    """Find all instructions that could have defined `register` when
    execution reached `target_idx` on the explored path."""

    defs = set()

    # Walk backward through the trace from target_idx
    for pos in range(trace_position_of(target_idx), -1, -1):
        insn = trace[pos]

        # Check if this instruction writes to the target register
        if register in extract_destination_registers(insn.bytecode):
            defs.add(insn.insn_idx)
            # For a MOV (r3 = r0), also track the source register
            source_regs = extract_source_registers(insn.bytecode, register)
            for src in source_regs:
                defs |= reaching_defs_on_path(trace, cfg, insn.insn_idx, src)
            break  # Found the most recent definition on this path

        # If this is a merge point (multiple predecessors in CFG),
        # we should also check the other incoming path. But since
        # the verifier trace is a single DFS path, we only see one
        # predecessor's state. The `from X to Y` annotation tells us
        # which predecessor the verifier came from.
        # For backward slicing, the explored path is sufficient.

    return defs
```

### 4.5 When Full Fixed-Point IS Needed

Full fixed-point reaching definitions would be needed if we wanted to answer: "across ALL possible paths, what could have defined R0 at instruction 24?" This is relevant for:
- Static analysis that considers all paths (not just the verifier's explored path)
- Detecting if the bug is path-specific (would the other branch have the same problem?)

For the paper, the explored-path-only approach is sufficient and much simpler. We can note full fixed-point as future work.

---

## 5. Control Dependence

### 5.1 Why Control Dependence Matters

Control dependence answers: **"Why did instruction B execute?"**

If instruction B is control-dependent on branch instruction A, then B executed BECAUSE branch A took a particular direction. This is crucial for understanding verifier failures because many bugs are path-dependent:

> "The verifier rejected this access because the `if (ptr)` check at insn 6 took the non-null branch, but the `be16` at insn 23 destroyed the scalar bounds, and the subsequent `r5 += r0` at insn 24 tried to add an unbounded scalar to a packet pointer."

The control dependence tells us that insn 24 executed because the branch at insn 13 (`if r5 > r2 goto pc+28`) took the fall-through (meaning the bounds check passed), AND the branch at insn 18 (`if r7 == 0x0 goto pc+23`) took the fall-through (meaning the type check matched).

**This IS genuinely new analysis** — the verifier doesn't output control dependence. Neither does value_lineage.py nor the transition_analyzer.

### 5.2 Post-Dominator Tree Algorithm

Control dependence requires the post-dominator tree.

**Post-dominator**: Instruction B post-dominates instruction A if every path from A to the exit passes through B.

**Algorithm** (Lengauer-Tarjan, simplified for small CFGs):

```
INPUT:  CFG with designated EXIT node(s)
OUTPUT: pdom[n] = immediate post-dominator of n

STEP 1: Reverse the CFG (swap successors/predecessors)
  Create a unified EXIT node
  For each exit instruction in the program:
    Add edge: exit_insn -> EXIT

STEP 2: Compute dominators on the reversed CFG
  (This gives post-dominators on the original CFG)

  # Simple iterative algorithm (sufficient for BPF programs, typically <1000 insns):
  pdom = {n: ALL_NODES for n in nodes}
  pdom[EXIT] = {EXIT}

  changed = True
  WHILE changed:
    changed = False
    FOR n in reverse_postorder(reverse_cfg):
      IF n == EXIT: CONTINUE
      new_pdom = intersection(pdom[s] for s in reverse_cfg.successors[n])
      new_pdom.add(n)
      IF new_pdom != pdom[n]:
        pdom[n] = new_pdom
        changed = True

STEP 3: Extract immediate post-dominator
  ipdom[n] = closest element of pdom[n] - {n}
```

For the partial CFG from the verifier trace (typically <200 instructions), this converges in a few iterations. Complexity: O(N^2) worst case, where N is the number of explored instructions. Entirely feasible.

### 5.3 Control Dependence Graph

**Definition**: Instruction B is control-dependent on branch A if:
1. A is a branch with two successors (conditional)
2. B is reachable from one successor of A
3. B does not post-dominate A

**Algorithm**:

```
INPUT:  CFG, ipdom tree
OUTPUT: cdg: Dict[int, Set[int]]  (insn_idx -> set of branches it depends on)

FOR each branch instruction A with successors {S1, S2}:
  FOR each successor S:
    runner = S
    WHILE runner != ipdom[A]:
      cdg[runner].add(A)
      runner = ipdom[runner]
```

### 5.4 What Control Dependence Adds to Diagnostics

Given the error at instruction E, the control dependence graph tells us:
- Which branches caused E to execute
- For each such branch, what condition was true/false

This enables diagnostics like:
> "The error at insn 39 (`r5 += r0`) was control-dependent on branch at insn 36 (`if r3 s>= r1 goto pc+5`), which fell through because `R3.smin = -2147483648` (loop counter unbounded from below). The loop body was entered without proving that the iteration count is non-negative."

This is more precise than "there's a loop" — it identifies the SPECIFIC branch that let the error path execute.

---

## 6. Backward Slice

### 6.1 Definition

A backward slice from criterion `(instruction N, register R)` is the minimal set of instructions that could influence the value of R at N. It combines:

1. **Data dependence**: Follow DEF-USE chains backward from N
2. **Control dependence**: For each instruction in the data slice, add the branches it's control-dependent on
3. **Transitively**: For each added branch, also add its data dependencies (the registers used in the branch condition)

### 6.2 Algorithm

```
INPUT:  CFG, CDG, trace, error_insn_idx, error_register
OUTPUT: set of instruction indices in the backward slice

def backward_slice(cfg, cdg, trace, target_idx, target_reg):
    worklist = [(target_idx, target_reg)]
    slice_insns = set()
    visited = set()

    while worklist:
        (idx, reg) = worklist.pop()
        if (idx, reg) in visited:
            continue
        visited.add((idx, reg))
        slice_insns.add(idx)

        # Data dependence: find the defining instruction for reg at idx
        def_insn_idx = find_reaching_def(trace, idx, reg)
        if def_insn_idx is not None:
            slice_insns.add(def_insn_idx)
            # Add source registers of the defining instruction
            def_insn = get_insn(trace, def_insn_idx)
            for src_reg in extract_source_registers(def_insn.bytecode, reg):
                worklist.append((def_insn_idx, src_reg))

        # Control dependence: add branches that idx depends on
        for branch_idx in cdg.get(idx, set()):
            if branch_idx not in slice_insns:
                slice_insns.add(branch_idx)
                # Add the registers used in the branch condition
                branch_insn = get_insn(trace, branch_idx)
                for branch_reg in extract_branch_registers(branch_insn.bytecode):
                    worklist.append((branch_idx, branch_reg))

    return slice_insns
```

### 6.3 How This Differs from Current System

**Current system**:
- `value_lineage.py` tracks data flow forward through the trace (no backward slice)
- `_trace_register_chain` in `_impl.py` does backward tracing but: limited depth (5), no control dependence, no merge-point awareness
- `BacktrackChain` uses the verifier's own `mark_precise` backtracking — this is a backward data dependence chain computed BY the verifier, but only for the precision-relevant registers at the error point

**New system**:
- Combines data AND control dependence
- No arbitrary depth limit
- Merge-point aware (tracks multiple potential definitions)
- Does not rely on mark_precise (works even when backtracking info is absent)
- Uses mark_precise as VALIDATION: the verifier's backward chain should be a subset of our computed backward slice

### 6.4 Integration with mark_precise

The verifier's `mark_precise` backtracking chain (`BacktrackChain`) is essentially a backward DATA dependence slice, but only for registers that the verifier itself identified as needing precision. Our backward slice should be a SUPERSET of mark_precise, because:

1. mark_precise only tracks registers relevant to the specific bounds check that triggered it
2. Our slice also includes control dependence
3. Our slice may include additional data dependencies that mark_precise deemed unnecessary

We can use this as validation:
```
assert mark_precise_chain ⊆ backward_slice
# If not, we have a bug in our slice computation
```

---

## 7. Connection to Existing Engine

### 7.1 Integration Points

The new analyses slot into the existing pipeline as follows:

```
                    ┌──────────────────────┐
                    │   trace_parser       │
                    │   (ParsedTrace)      │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
               ┌────│   cfg_builder  (NEW) │────┐
               │    │   (CFG, BasicBlocks) │    │
               │    └──────────┬───────────┘    │
               │               │                │
    ┌──────────▼──────┐ ┌──────▼───────┐ ┌──────▼──────────┐
    │  value_lineage  │ │ reaching_def │ │ postdom + CDG   │
    │  (existing)     │ │ (NEW)        │ │ (NEW)           │
    └──────────┬──────┘ └──────┬───────┘ └──────┬──────────┘
               │               │                │
               └───────────────┼────────────────┘
                               │
                    ┌──────────▼───────────┐
                    │  backward_slice (NEW)│
                    │  (SliceResult)       │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  opcode_safety       │
                    │  (SafetyConditions)  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  monitor + analyzer  │
                    │  (existing)          │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  synthesizer         │
                    │  (RepairSuggestion)  │
                    └──────────────────────┘
```

### 7.2 Required Changes to Existing Code

**trace_parser_parts/_impl.py**:
- Add `opcode_hex: str` field to `TracedInstruction` (currently only in `InstructionLine`)
- Propagate the opcode hex from `InstructionLine` through `_aggregate_instructions`
- Parse and store `from X to Y` annotations in `ParsedTrace` as `cfg_edges: list[tuple[int, int]]`

**opcode_safety.py**:
- Already has `decode_opcode` and `OpcodeInfo.is_branch` — no changes needed
- Already has `_infer_opcode_class_from_bytecode` for when raw opcode is unavailable

**engine/monitor.py**:
- Add optional `backward_slice: set[int]` parameter to `monitor()` to focus monitoring on slice-relevant instructions only

**engine/transition_analyzer.py**:
- Accept optional `slice_insns: set[int]` to analyze only instructions in the backward slice
- Add control-dependence annotations to `TransitionDetail` (which branch caused this instruction to execute)

### 7.3 New Modules

| Module | Location | Lines (est.) | Purpose |
|--------|----------|-------------|---------|
| `cfg_builder.py` | `interface/extractor/` | ~200 | CFG reconstruction, basic blocks |
| `dataflow.py` | `interface/extractor/` | ~200 | Reaching definitions, backward slice |
| `control_dependence.py` | `interface/extractor/` | ~150 | Post-dominator tree, CDG |

Total new code: ~550 lines (plus ~50 lines of changes to existing files).

---

## 8. Data Structures

### 8.1 CFG

```python
@dataclass
class TraceCFG:
    """Control flow graph reconstructed from verifier trace."""
    successors: dict[int, set[int]]     # insn_idx -> successor insn_idxs
    predecessors: dict[int, set[int]]   # insn_idx -> predecessor insn_idxs
    entry: int                          # Entry instruction index
    exits: set[int]                     # Exit instruction indices
    branch_targets: dict[int, int]      # branch insn_idx -> branch target idx
    explored_edges: list[tuple[int, int]]  # from-to edges from verifier DFS
```

### 8.2 Basic Block

```python
@dataclass
class BasicBlock:
    block_id: int
    insn_indices: list[int]             # Ordered instruction indices
    entry_idx: int                      # First instruction
    exit_idx: int                       # Last instruction
    successor_blocks: set[int]          # Successor block IDs
    predecessor_blocks: set[int]        # Predecessor block IDs
```

### 8.3 Backward Slice Result

```python
@dataclass
class BackwardSliceResult:
    """Result of backward slicing from error criterion."""
    criterion_insn: int                 # Error instruction index
    criterion_register: str             # Error register
    data_slice: set[int]                # Instructions in data-dependence slice
    control_slice: set[int]             # Branch instructions in control-dependence slice
    full_slice: set[int]                # Union of data + control slice
    slice_chain: list[SliceLink]        # Ordered chain from root cause to error
    mark_precise_validated: bool        # True if mark_precise ⊆ full_slice
```

```python
@dataclass
class SliceLink:
    insn_idx: int
    register: str
    dep_type: str                       # 'data' or 'control'
    bytecode: str
    source_line: str | None
    description: str                    # Why this instruction is in the slice
```

---

## 9. Expected Impact on the 171-Case Eval

### 9.1 Cases That Benefit

Based on the current eval categories:

| Category | Current Count | Expected Improvement | Why |
|----------|--------------|---------------------|-----|
| `proof_lost` | ~99 | +15-20% precision in root-cause identification | Control dependence identifies WHICH BRANCH caused the bad path |
| `proof_established` | ~115 | Minimal change | These already work well |
| `no_trace` / `parse_error` | ~48 | No change | Need trace data to do analysis |

Specific improvements:

1. **Loop-related failures** (~30 cases): Control dependence identifies the loop-continuation branch as the cause. Currently, the system knows the scalar is unbounded but doesn't explain that it's because a loop counter wasn't properly bounded at the loop entry.

2. **Path-dependent failures** (~40 cases): Cases where a bounds check exists on one branch but not another. Backward slice + control dependence shows the specific path that lacks the check.

3. **Spill/fill losses** (~15 cases): The backward slice traces through stack spills/fills more precisely than the current linear scan, because it follows the actual data flow path rather than the trace order.

4. **Multi-register interactions** (~20 cases): The backward slice correctly identifies when the error register's value depends on ANOTHER register that was improperly bounded. Currently, the causal chain sometimes misses these transitive dependencies.

### 9.2 Estimated Quantitative Impact

- **Root-cause identification accuracy**: ~65% -> ~78% (based on the 30 manually-labeled cases)
- **Backward slice precision**: Currently value_lineage provides ~40% overlap with manually-identified root causes. With proper backward slice: ~70% expected.
- **Control dependence adds new diagnostic content**: For ~25% of cases, the control dependence analysis provides information that is NOT available from any current analysis (which branch caused this path to execute).

### 9.3 Validation Strategy

1. Run the new backward slice on all 262 cases
2. Compare with mark_precise chains (should be subset)
3. Compare with manually-labeled root causes for the 30 ground-truth cases
4. Measure: Does the slice include the root-cause instruction? Is the slice small enough to be useful (not >50% of the program)?

---

## 10. Honest Assessment: Is This Sufficient for OSDI/ATC?

### 10.1 What This Adds to the Contribution Story

The current system does:
- Parse verifier traces (engineering, not novel)
- Detect abstract state transitions (bounds collapse, type downgrade) — this is essentially structured pattern matching on register state changes
- Use mark_precise chains from verifier output — this is reading verifier-computed data
- Produce multi-span diagnostics — this is presentation, not analysis

The new system adds:
- **CFG reconstruction from traces** — straightforward but necessary infrastructure
- **Backward slice with data + control dependence** — this IS a genuine program analysis contribution
- **Control dependence identification** — genuinely new information not available from the verifier
- **Principled root-cause localization** — the backward slice is the PRINCIPLED version of what the current heuristic causal chain tries to do

### 10.2 Novelty Assessment

**Strong points**:
- Reconstructing a CFG and performing dataflow analysis ON TOP OF an abstract interpreter's output trace is unusual. Most work either (a) re-implements the abstract interpretation, or (b) uses the verifier as a black box. Using the verifier's own trace as input to a second layer of analysis is a different approach.
- The control dependence analysis provides information that helps explain WHY a particular path was taken, which is genuinely useful for debugging.
- The backward slice gives a formal, principled answer to "what caused this failure" — unlike the current heuristic chain.

**Weak points**:
- CFG reconstruction, reaching definitions, post-dominator trees, and backward slicing are all textbook algorithms (Aho, Lam, Sethi, Ullman; Cytron et al.; Ferrante, Ottenstein, Warren). The algorithms themselves are not novel.
- The claim "we perform program analysis on verifier output" could be countered with "the verifier already did the hard analysis; you're just post-processing it."
- The practical impact may be incremental: going from ~65% to ~78% root-cause accuracy is meaningful but not dramatic.

### 10.3 Sufficient for OSDI/ATC?

**Assessment: This alone is not sufficient.** The algorithms are standard. The novelty must come from:

1. **The insight** that the verifier trace is a structured intermediate representation amenable to secondary analysis — and that this secondary analysis can provide information the verifier itself doesn't (control dependence, principled slicing).

2. **The evaluation** showing that this secondary analysis materially improves root-cause identification and repair guidance compared to (a) raw verifier output, (b) regex-based tools like Pretty Verifier, (c) LLM agents without structured analysis.

3. **The end-to-end impact**: Does better root-cause identification lead to better repairs? If the backward slice consistently identifies the root cause, and the repair synthesizer uses this to produce correct fixes, that's a systems result.

For OSDI/ATC, the CFG + dataflow analysis is necessary infrastructure but needs to be combined with:
- Strong evaluation against baselines (PV, raw LLM, BPFix without slice)
- Demonstrated impact on repair quality (not just diagnostic quality)
- Scale (302 cases, multiple kernel versions, multiple LLM backends)
- Possibly: a user study or integration with real development tools

### 10.4 Recommendation

Implement the CFG + backward slice as the next engineering step. It makes the system genuinely principled rather than heuristic. But for the paper, frame it as:

> "The verifier trace is a complete record of the abstract interpretation. We show that standard program analysis techniques (CFG reconstruction, reaching definitions, control dependence) applied to this trace produce diagnostic information that is (a) not available from the verifier alone, and (b) significantly improves root-cause identification and repair guidance. The key insight is that the verifier's proof trace is structured enough to serve as input to a second layer of analysis."

This positions the contribution as the insight + the system, not the algorithms.

---

## 11. Implementation Plan

### Phase 1: Infrastructure (1-2 days)
1. Add `opcode_hex` field to `TracedInstruction`
2. Parse `from X to Y` annotations into structured data in `ParsedTrace`
3. Implement `cfg_builder.py`: CFG reconstruction + basic blocks
4. Tests for CFG construction on the reference case (stackoverflow-70750259)

### Phase 2: Dataflow (1-2 days)
5. Implement reaching-definitions on the trace path (enhance value_lineage)
6. Implement backward slice (data dependence only, no control dependence yet)
7. Validate backward slice against mark_precise chains

### Phase 3: Control Dependence (1 day)
8. Implement post-dominator tree
9. Implement control dependence graph
10. Add control dependence to backward slice

### Phase 4: Integration + Eval (1-2 days)
11. Integrate backward slice into the engine pipeline
12. Add slice-based annotations to `TransitionDetail`
13. Run on 262-case eval, compare with current system
14. Measure root-cause accuracy on 30 ground-truth cases

**Total estimate**: 5-7 days of focused implementation.

---

## 12. Appendix: Worked Example (stackoverflow-70750259)

### The Error

```
39: (0f) r5 += r0
value -2147483648 makes pkt pointer be out of bounds
```

R0 is a scalar with `smin=-2147483648`, being added to R5 (packet pointer). The verifier rejects because R0 could be negative.

### CFG Fragment (Reconstructed)

```
  [28] if r0 s> 0xffffffff goto pc+1
       │                           │
       ▼ (fall-through: r0 <= -1)  ▼ (target: insn 30, r0 >= 0)
  [29] goto pc+11 ──────┐    [30] r0 = *(u32 *)(r10 -4)
                         │    [31] r6 = *(u32 *)(r10 -4)
                         │    [32] r3 += r6
                         │    [33] r3 <<= 32
                         │    [34] r3 += r4
                         │    [35] r3 s>>= 32
                         │    [36] if r3 s>= r1 goto pc+5
                         │         │ (fall-through)
                         │    [37] r0 <<= 32
                         │    [38] r0 s>>= 32
                         │    [39] r5 += r0  ← ERROR
                         │         │
                         │    [40] if r1 s> r3 goto pc-29
                         │         │
                         └────►[41] r0 = 2
                              [42] exit
```

### Backward Slice from (insn 39, R0)

**Data dependence chain**:
- insn 39: `r5 += r0` — uses R0
- insn 38: `r0 s>>= 32` — defines R0, uses R0
- insn 37: `r0 <<= 32` — defines R0, uses R0
- insn 30: `r0 = *(u32 *)(r10 -4)` — defines R0 from stack slot fp-4
- insn 24: `*(u32 *)(r10 -4) = r0` — defines fp-4 from R0
- insn 23: `r0 = be16 r0` — defines R0, uses R0
- insn 22: `r0 |= r6` — defines R0, uses R0, R6  ← **bounds collapse here!**
- insn 21: `r0 <<= 8` — defines R0
- insn 20: `r0 = *(u8 *)(r0 +3)` — defines R0 from packet
- insn 19: `r6 = *(u8 *)(r0 +2)` — defines R6 from packet

**Control dependence**:
- insn 39 is control-dependent on branch at insn 36 (`if r3 s>= r1 goto pc+5`) — the loop continuation
- insn 30-39 are control-dependent on branch at insn 28 (`if r0 s> 0xffffffff goto pc+1`) — the `ext_len >= 0` check

**Full slice**: {19, 20, 21, 22, 23, 24, 28, 30, 36, 37, 38, 39} — 12 instructions out of 42 total (29%)

**Diagnostic from slice**:
> R0 at the error site (insn 39) was loaded from stack at insn 30, where it had been stored at insn 24 after a `be16` conversion (insn 23). The bounds were lost at insn 22 (`r0 |= r6`): the OR operation destroyed scalar tracking, causing the verifier to lose the umax bound on R0. After sign-extension (insns 37-38), R0 has smin=-2147483648, which the verifier rejects for packet pointer arithmetic. The error path is control-dependent on branch 28 (the `ext_len >= 0` check) and branch 36 (the loop continuation), confirming this is a loop iteration where the scalar was not re-bounded.

This is significantly more precise than the current diagnostic, which says "bounds collapse at insn 22, error at insn 39" without explaining the control flow path.
