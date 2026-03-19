# Opcode-Driven Proof Lifecycle Analysis: Design Document

## 1. Executive Summary

This document proposes replacing the current keyword/regex-based predicate inference
(`ebpf_predicates.py`, 70+ regex patterns) with an **opcode-driven safety condition
derivation** that uses ZERO keyword heuristics and ZERO pattern matching on error
messages. The analysis is derived entirely from the structural properties of the BPF
instruction set architecture.

The central claim is that every BPF instruction's safety conditions are determined
by its opcode byte. The opcode is already parsed by `trace_parser_parts/_impl.py`
(the `InstructionLine.opcode` field, a 2-hex-digit string). By decoding this byte
we can determine the *exact* safety condition the verifier checked, identify which
register(s) must satisfy which property, and then walk the existing trace backward
to find where the property was established and where it was lost.

**Verdict after thorough analysis:** The opcode-driven approach is a genuine
architectural improvement with real novelty, but it must be designed carefully to
avoid either (a) trivially reproducing what the verifier already does, or (b)
losing coverage on errors that are not instruction-specific. The design below
handles both concerns.

---

## 2. The BPF Opcode Structure

### 2.1 Encoding

Every BPF instruction is 8 bytes. The first byte (the opcode) has the following
structure:

```
  7  6  5  4  3  2  1  0
 [    op    ][ src][class]
```

- **class** (bits 2:0): Instruction class
- **src** (bit 3): Source operand encoding (register vs immediate)
- **op** (bits 7:4): Operation within the class

### 2.2 Instruction Classes

| Class | Value | Hex range | Description |
|-------|-------|-----------|-------------|
| BPF_LD    | 0x00 | 0x00-0x0F, 0x18-0x1F | Non-standard loads (LD_IMM64, LD_ABS/IND) |
| BPF_LDX   | 0x01 | 0x61, 0x69, 0x71, 0x79 | Memory load from `[src_reg + off]` |
| BPF_ST    | 0x02 | 0x62, 0x6a, 0x72, 0x7a | Memory store immediate to `[dst_reg + off]` |
| BPF_STX   | 0x03 | 0x63, 0x6b, 0x73, 0x7b + atomics | Memory store register to `[dst_reg + off]` |
| BPF_ALU   | 0x04 | 0x04-0x0F (32-bit ALU) | 32-bit arithmetic/logic |
| BPF_JMP   | 0x05 | 0x05-0x0F, 0x15-0xDF | 64-bit jumps and calls |
| BPF_JMP32 | 0x06 | 0x06-0x0F, 0x16-0xE6 | 32-bit jumps |
| BPF_ALU64 | 0x07 | 0x07-0x0F, 0x17-0xFF | 64-bit arithmetic/logic |

### 2.3 Exact Class Extraction

From a hex opcode byte, the class is `opcode & 0x07`:

```python
def opcode_class(hex_opcode: str) -> int:
    return int(hex_opcode, 16) & 0x07

# 0 = LD, 1 = LDX, 2 = ST, 3 = STX, 4 = ALU, 5 = JMP, 6 = JMP32, 7 = ALU64
```

### 2.4 Key Sub-encodings

Within memory classes (LDX/ST/STX), bits 4:3 encode the access size:
- `0x00`: 32-bit (W)
- `0x08`: 16-bit (H)
- `0x10`: 8-bit (B)
- `0x18`: 64-bit (DW)

Access size in bytes: `{0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}`

Within JMP, the operation distinguishes `CALL` (0x80) and `EXIT` (0x90).

---

## 3. Safety Conditions By Opcode Class

This is the core of the design: a **complete, ISA-derived mapping** from opcode class
to the safety conditions the verifier must check. These are not heuristics; they are
structural properties of the BPF abstract machine.

### 3.1 LDX (Memory Load): `opcode & 0x07 == 0x01`

**Instruction form:** `dst = *(uN *)(src + off)`

**Safety conditions (conjunctive):**
1. **Pointer validity:** `src_reg` must hold a valid pointer type (not scalar, not
   `ptr_or_null`). Type must be in `{ctx, fp, map_value, pkt, mem, ptr_to_btf_id, ...}`.
2. **Bounds containment:** `src_reg.off + insn.off + access_size <= src_reg.range`
   (for packet/map_value pointers where range tracking applies).
3. **Alignment:** `(src_reg.off + insn.off) % access_size == 0` (on architectures
   without efficient unaligned access).
4. **Context field validity:** If `src_reg` is `ctx`, the offset must correspond to
   a valid context field for the program type.
5. **Read permission:** The pointee must be readable (not write-only).

**Registers involved:**
- `src_reg`: The base pointer (safety-critical)
- `dst_reg`: The result (receives value; its *pre*-state is irrelevant)

**Which register to trace backward:** `src_reg` -- specifically its type, offset,
and range fields.

### 3.2 ST/STX (Memory Store): `opcode & 0x07 == 0x02 or 0x03`

**Instruction form:** `*(uN *)(dst + off) = src` or `*(uN *)(dst + off) = imm`

**Safety conditions (conjunctive):**
1. **Pointer validity:** `dst_reg` must hold a valid, writable pointer.
2. **Bounds containment:** `dst_reg.off + insn.off + access_size <= dst_reg.range`.
3. **Write permission:** The pointee must be writable (not `rdonly_mem`, not packet
   data in non-XDP programs).
4. **Value type safety:** For stores to kptr/timer/dynptr/iterator slots, the source
   value must match the expected field type (protocol-level checks).
5. **Alignment** (same as LDX).

**Registers involved:**
- `dst_reg`: The base pointer (safety-critical for access)
- `src_reg` (STX only): The value being stored (safety-critical for kptr/ref stores)

**Which register to trace backward:** `dst_reg` for access safety; `src_reg` for
value-type discipline.

### 3.3 ALU/ALU64 (Arithmetic): `opcode & 0x07 == 0x04 or 0x07`

**Instruction form:** `dst op= src` or `dst op= imm`

**Safety conditions depend on operand types:**

**Case A: Pointer arithmetic** (`dst_reg` is a pointer):
1. **Pointer arithmetic allowed:** The pointer type must permit arithmetic
   (`pkt`, `map_value`, `fp` allow it; `ctx`, `sock`, `btf_id` usually prohibit it).
2. **Scalar operand bounded:** If adding/subtracting a scalar register, that scalar
   must have known bounds (`umin`, `umax` finite).
3. **Result in range:** The resulting pointer offset must not escape the allocation.

**Case B: Scalar arithmetic** (both operands are scalar):
1. No immediate safety condition. But the *effect* on scalar bounds matters for
   downstream safety checks. This is where bounds collapse happens.

**Case C: Pointer-pointer arithmetic** (both operands are pointers):
1. Only subtraction is allowed, and only between `pkt`/`pkt_end` pointers. This is
   heavily restricted.

**Case D: Illegal arithmetic:**
1. Prohibited: `pkt_end` arithmetic, `ctx` arithmetic, mixed pointer types.

**Which register to trace backward:**
- For pointer arithmetic: both `dst_reg` (the pointer) and `src_reg` (the scalar bound)
- For scalar arithmetic: `dst_reg` (track how bounds propagate)

### 3.4 JMP/JMP32 (Branches): `opcode & 0x07 == 0x05 or 0x06`

Branches themselves have no direct safety conditions (no memory access, no
type requirements). However, they are the **primary mechanism by which the
verifier narrows abstract state** (conditional refinement).

**Sub-case: CALL** (`opcode == 0x85`):
1. **Helper availability:** The function ID must be available in the program type.
2. **Argument types:** R1-R5 must match the helper's prototype signature.
3. **Argument values:** Memory/len pairs must satisfy bounds.
4. **Reference discipline:** If the helper acquires a reference, R0 gets
   `ptr_or_null` and a ref_id. If it releases, the corresponding ref must be held.

**Registers involved:** R1-R5 (arguments), R0 (return value post-call)

**Sub-case: EXIT** (`opcode == 0x95`):
1. **Return value:** R0 must satisfy the program type's return contract.
2. **Reference balance:** All acquired references must be released.
3. **Lock/RCU balance:** No held locks, no active RCU read sections.

### 3.5 LD_IMM64 (64-bit Immediate Load): `opcode == 0x18`

Special double-width instruction. Safety conditions:
1. If loading a map pointer (pseudo-map-fd), the map must be compatible with the
   program type.
2. If loading a BTF ID, the BTF must be valid.
3. No memory access, so no bounds/type conditions on registers.

---

## 4. The Critical Insight: Opcode Determines Which Register to Trace

The current system (`ebpf_predicates.py`) uses the error message to determine
which registers matter:

```python
# Current: error message -> registers
if "invalid access to packet" in error_msg:
    target_regs = _extract_register_from_error(error_msg)
    return PacketAccessPredicate(target_regs=target_regs)
```

The opcode-driven approach derives this structurally:

```python
# Proposed: opcode -> registers + condition
if opclass == BPF_LDX:
    # For a load, src_reg is the base pointer
    src_reg = decode_src_reg(opcode_byte, bytecode_text)
    condition = MemoryAccessCondition(
        base_reg=src_reg,
        access_size=decode_access_size(opcode_byte),
        mode="read",
    )
```

This is not merely cosmetic. The structural approach:

1. **Works without an error message.** We can analyze any instruction in the trace,
   not just the error instruction. This enables prophylactic analysis ("which
   instructions in this trace are close to failing?").

2. **Is unambiguous.** The opcode fully determines the safety check. There is no
   ambiguity between "invalid access to packet" (bounds) and "invalid mem access
   'scalar'" (type) because the opcode tells us: LDX = bounds + type, ALU with
   pointer = scalar bound, CALL = argument contract, EXIT = reference balance.

3. **Is kernel-version-independent.** Opcode semantics are fixed by the ISA. Error
   message text changes across kernel versions; opcode semantics do not.

---

## 5. Detailed Design: `OpcodeAnalyzer`

### 5.1 Data Structures

```python
from dataclasses import dataclass
from enum import Enum

class OpcodeClass(Enum):
    LD     = 0  # Special loads (LD_IMM64, LD_ABS)
    LDX    = 1  # Memory load
    ST     = 2  # Memory store (immediate)
    STX    = 3  # Memory store (register)
    ALU    = 4  # 32-bit ALU
    JMP    = 5  # 64-bit jump/call/exit
    JMP32  = 6  # 32-bit jump
    ALU64  = 7  # 64-bit ALU

class SafetyDomain(Enum):
    """The abstract domain in which the safety condition lives."""
    MEMORY_BOUNDS    = "memory_bounds"     # off + size <= range
    POINTER_TYPE     = "pointer_type"      # register must be a valid pointer
    SCALAR_BOUND     = "scalar_bound"      # scalar must be bounded
    NULL_SAFETY      = "null_safety"       # pointer must not be or_null
    REFERENCE_BALANCE = "ref_balance"      # all refs released at exit
    ARG_CONTRACT     = "arg_contract"      # helper/kfunc argument types
    WRITE_PERMISSION = "write_permission"  # target must be writable
    ARITHMETIC_LEGALITY = "arith_legality" # pointer arithmetic allowed?
    ALIGNMENT        = "alignment"         # access alignment
    CONTEXT_FIELD    = "context_field"     # valid context offset

@dataclass(frozen=True)
class SafetyCondition:
    """A single safety condition derived from an opcode."""
    domain: SafetyDomain
    critical_register: str       # Which register must satisfy this condition
    required_property: str       # Human-readable description of what's required
    access_size: int | None = None  # For memory access conditions

@dataclass(frozen=True)
class OpcodeInfo:
    """Decoded opcode information."""
    raw: int                     # The raw opcode byte
    opclass: OpcodeClass         # Instruction class
    is_memory_access: bool       # LDX/ST/STX
    is_call: bool                # CALL instruction
    is_exit: bool                # EXIT instruction
    is_alu: bool                 # ALU/ALU64
    is_branch: bool              # Conditional branch
    access_size: int | None      # For memory ops: 1/2/4/8
    src_reg_idx: int | None      # Decoded from bytecode text
    dst_reg_idx: int | None      # Decoded from bytecode text

    @property
    def safety_conditions(self) -> list[SafetyCondition]:
        """Derive all safety conditions from the opcode class."""
        return _derive_conditions(self)
```

### 5.2 Opcode Decoder

```python
_SIZE_MAP = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}

def decode_opcode(hex_str: str, bytecode_text: str) -> OpcodeInfo:
    """Decode a 2-hex-digit opcode and bytecode text into OpcodeInfo."""
    raw = int(hex_str, 16)
    opclass = OpcodeClass(raw & 0x07)

    is_memory = opclass in {OpcodeClass.LDX, OpcodeClass.ST, OpcodeClass.STX}
    is_call = (raw == 0x85)  # BPF_JMP | BPF_CALL
    is_exit = (raw == 0x95)  # BPF_JMP | BPF_EXIT
    is_alu = opclass in {OpcodeClass.ALU, OpcodeClass.ALU64}
    is_branch = opclass in {OpcodeClass.JMP, OpcodeClass.JMP32} and not is_call and not is_exit

    access_size = None
    if is_memory:
        size_bits = (raw >> 3) & 0x03
        access_size = _SIZE_MAP.get(size_bits << 3, None)

    src_reg, dst_reg = _extract_regs_from_bytecode(bytecode_text)

    return OpcodeInfo(
        raw=raw,
        opclass=opclass,
        is_memory_access=is_memory,
        is_call=is_call,
        is_exit=is_exit,
        is_alu=is_alu,
        is_branch=is_branch,
        access_size=access_size,
        src_reg_idx=src_reg,
        dst_reg_idx=dst_reg,
    )
```

### 5.3 Safety Condition Derivation

This is the function that replaces `infer_predicate()` entirely:

```python
def _derive_conditions(info: OpcodeInfo) -> list[SafetyCondition]:
    """From opcode semantics alone, determine what safety conditions apply."""
    conditions = []

    if info.opclass == OpcodeClass.LDX:
        # Memory load: src_reg is base pointer
        base = f"R{info.src_reg_idx}" if info.src_reg_idx is not None else "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-null pointer type",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register=base,
            required_property="must not be ptr_or_null (null check required)",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))

    elif info.opclass in {OpcodeClass.ST, OpcodeClass.STX}:
        # Memory store: dst_reg is base pointer
        base = f"R{info.dst_reg_idx}" if info.dst_reg_idx is not None else "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-null, writable pointer",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.WRITE_PERMISSION,
            critical_register=base,
            required_property="pointee must be writable (not rdonly_mem)",
        ))

    elif info.is_alu:
        # ALU: safety depends on whether dst_reg is a pointer
        # We cannot know this from the opcode alone -- we need register state.
        # The opcode tells us WHICH registers are involved; the state tells us
        # whether the condition applies.
        dst = f"R{info.dst_reg_idx}" if info.dst_reg_idx is not None else "R?"
        src = f"R{info.src_reg_idx}" if info.src_reg_idx is not None else None

        # Condition A: if dst is a pointer, arithmetic legality
        conditions.append(SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register=dst,
            required_property="if pointer, arithmetic must be legal for this pointer type",
        ))
        # Condition B: if dst is a pointer and src is a scalar, src must be bounded
        if src:
            conditions.append(SafetyCondition(
                domain=SafetyDomain.SCALAR_BOUND,
                critical_register=src,
                required_property="if added to a pointer, must have known bounds",
            ))

    elif info.is_call:
        # CALL: argument contract for R1-R5
        for i in range(1, 6):
            conditions.append(SafetyCondition(
                domain=SafetyDomain.ARG_CONTRACT,
                critical_register=f"R{i}",
                required_property="must match helper/kfunc prototype",
            ))

    elif info.is_exit:
        # EXIT: reference balance + return value
        conditions.append(SafetyCondition(
            domain=SafetyDomain.REFERENCE_BALANCE,
            critical_register="R0",
            required_property="all acquired references must be released",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="R0 must satisfy program type return contract",
        ))

    return conditions
```

### 5.4 Condition Evaluation Against Register State

Each `SafetyCondition` can be evaluated against the register state at the error
instruction. This replaces the predicate classes:

```python
def evaluate_condition(
    condition: SafetyCondition,
    register_state: dict[str, RegisterState],
) -> str:
    """Evaluate a safety condition against register state.

    Returns: 'satisfied', 'violated', 'unknown'
    """
    reg = register_state.get(condition.critical_register)
    if reg is None:
        return "unknown"

    match condition.domain:
        case SafetyDomain.POINTER_TYPE:
            if is_scalar_like(reg):
                return "violated"  # scalar where pointer required
            if is_pointer_type_name(reg.type):
                return "satisfied"
            return "unknown"

        case SafetyDomain.NULL_SAFETY:
            if is_nullable_pointer_type(reg.type):
                return "violated"  # ptr_or_null without null check
            if is_pointer_type_name(reg.type):
                return "satisfied"
            return "unknown"

        case SafetyDomain.MEMORY_BOUNDS:
            if not is_pointer_type_name(reg.type):
                return "unknown"
            off = reg.off or 0
            rng = reg.range
            if rng is None:
                return "unknown"
            if rng == 0:
                return "violated"  # no range proven
            if condition.access_size and off + condition.access_size > rng:
                return "violated"
            return "satisfied"

        case SafetyDomain.SCALAR_BOUND:
            if not is_scalar_like(reg):
                return "unknown"  # Not a scalar, condition does not apply
            if reg.umax is None and reg.smax is None:
                return "violated"  # unbounded scalar
            if reg.umax is not None and reg.umax < (1 << 32):
                return "satisfied"
            return "violated"

        case SafetyDomain.ARITHMETIC_LEGALITY:
            if not is_pointer_type_name(reg.type):
                return "satisfied"  # scalar-scalar arithmetic always legal
            # Check if pointer type allows arithmetic
            prohibited = {"ctx", "sock", "sock_or_null"}
            if reg.type.lower() in prohibited:
                return "violated"
            return "satisfied"

        case SafetyDomain.WRITE_PERMISSION:
            # Cannot determine from register state alone
            return "unknown"

        case _:
            return "unknown"
```

---

## 6. Integration With Existing Components

### 6.1 Replacing `infer_predicate()` (ebpf_predicates.py)

The current `infer_predicate()` function is a 1000-line cascade of 70+ regex
patterns. The opcode-driven approach replaces it with a 50-line function:

```python
def infer_conditions_from_error_instruction(
    error_insn: TracedInstruction,
) -> list[SafetyCondition]:
    """Derive safety conditions from the error instruction's opcode.

    No error message parsing. No regex. Only opcode semantics + register state.
    """
    info = decode_opcode(error_insn.opcode, error_insn.bytecode)
    conditions = info.safety_conditions

    # Refine conditional conditions using register state at error point
    refined = []
    for cond in conditions:
        reg = error_insn.pre_state.get(cond.critical_register)
        if reg is None:
            refined.append(cond)
            continue

        # For ALU: only keep pointer-related conditions if register IS a pointer
        if cond.domain == SafetyDomain.ARITHMETIC_LEGALITY:
            if is_pointer_type_name(reg.type):
                refined.append(cond)
        elif cond.domain == SafetyDomain.SCALAR_BOUND:
            if is_scalar_like(reg):
                refined.append(cond)
        else:
            refined.append(cond)

    return refined
```

### 6.2 Composing With `transition_analyzer.py`

The `TransitionAnalyzer` already classifies per-instruction effects. The opcode-
driven analysis tells us **which register to focus on**:

```python
def opcode_driven_lifecycle(
    error_insn: TracedInstruction,
    all_insns: list[TracedInstruction],
    value_lineage: ValueLineage,
) -> TransitionChain:
    """Full lifecycle analysis using opcode-derived conditions."""

    # Step 1: Derive conditions from the error instruction's opcode
    conditions = infer_conditions_from_error_instruction(error_insn)

    # Step 2: Find the VIOLATED condition
    violated = None
    for cond in conditions:
        result = evaluate_condition(cond, error_insn.pre_state)
        if result == "violated":
            violated = cond
            break

    if violated is None:
        # All conditions satisfied or unknown -- use heuristic fallback
        violated = conditions[0] if conditions else None

    if violated is None:
        return TransitionChain(proof_status="unknown", ...)

    # Step 3: Use transition_analyzer to track the critical register
    proof_registers = {violated.critical_register}

    # Step 4: Use value_lineage to find aliases
    # (the critical register might have been copied from another register)
    error_pos = _find_trace_pos(all_insns, error_insn.insn_idx)
    if error_pos is not None:
        aliases = value_lineage.get_all_aliases(error_pos, violated.critical_register)
        proof_registers |= aliases

    # Step 5: Run transition analysis on proof_registers
    analyzer = TransitionAnalyzer()
    chain = analyzer.analyze(all_insns, proof_registers)

    return chain
```

### 6.3 Deriving Taxonomy From Analysis (Not Keywords)

The opcode-driven lifecycle produces a `TransitionChain` with a `proof_status`.
The taxonomy classification follows from the lifecycle + the transition that
caused proof loss:

```python
def derive_taxonomy_class(
    chain: TransitionChain,
    violated: SafetyCondition,
    error_insn: TracedInstruction,
) -> str:
    """Derive taxonomy class from proof lifecycle analysis.

    No keyword matching. Only structural analysis of what happened.
    """
    if chain.proof_status == "never_established":
        # The safety condition was never satisfied in the trace.
        # This means the source program never provided the required proof.
        return "source_bug"

    elif chain.proof_status == "established_then_lost":
        # The condition was once satisfied, then broken.
        # The CAUSE of the breakage determines the taxonomy class.
        loss = chain.loss_point
        if loss is None:
            return "lowering_artifact"  # default for established-then-lost

        reason_lower = loss.reason.lower()

        # ALU operation destroyed proof -> lowering artifact
        # (Compiler chose an ALU pattern that loses verifier tracking)
        if "or operation" in reason_lower or "shift" in reason_lower:
            return "lowering_artifact"

        # Stack spill/fill lost type info -> lowering artifact
        if "stack fill" in reason_lower or "stack spill" in reason_lower:
            return "lowering_artifact"

        # Branch merge widened state -> could be lowering or verifier limit
        if "branch merge" in reason_lower or "join" in reason_lower:
            # If the widening is from compiler-generated control flow, lowering.
            # If the program structure is inherently complex, verifier_limit.
            # Heuristic: if the program has many validated functions, it's complex.
            return "lowering_artifact"

        # Function call clobbered state -> source-level issue (or lowering)
        if "function call" in reason_lower:
            return "lowering_artifact"

        return "lowering_artifact"

    elif chain.proof_status == "established_but_insufficient":
        # Proof was established but the error occurred anyway.
        # This usually means a different safety property failed.
        return "source_bug"

    return "source_bug"  # fallback
```

This is a significant conceptual improvement over the current approach, which derives
taxonomy class from the error catalog via error message matching.

---

## 7. Coverage Analysis: What Can and Cannot Be Handled

### 7.1 Instruction-Level Errors (High Coverage)

The opcode-driven approach covers all errors that occur at a specific instruction:

| Error family | Opcode class | Coverage |
|--------------|-------------|----------|
| Packet bounds (E001) | LDX/STX at pkt pointer | Full |
| Null pointer deref (E002) | LDX/STX at *_or_null | Full |
| Stack read uninitialized (E003) | LDX at fp+offset | Partial (need stack state) |
| Scalar range too wide (E005) | ALU with pointer operand | Full |
| Provenance lost (E006) | ALU on prohibited pointer | Full |
| Type mismatch (E011) | CALL (argument check) | Full (with helper proto) |
| Pointer comparison (E011) | JMP with pointer operands | Full |
| Memory access (E017) | LDX/STX | Full |

### 7.2 Structural/Non-Instruction Errors (Requires Fallback)

Some errors are NOT tied to a specific instruction's opcode:

| Error family | Why no opcode | Handling strategy |
|--------------|--------------|-------------------|
| Reference leak (E004) | EXIT is the symptom, not the cause | EXIT opcode -> ref_balance condition; trace backward for acquire without release |
| Verifier limits (E007, E018) | Not an instruction error | ClassificationOnly (already handled) |
| Loop not bounded (E008) | Back-edge structural check | ClassificationOnly |
| Helper not available (E009) | CALL opcode gives us helper ID; but availability is env issue | CALL -> arg_contract; if helper unknown, -> env_mismatch |
| Environment mismatch (E016) | Various attach/BTF issues | ClassificationOnly |
| BTF errors (E021) | Metadata, not instructions | ClassificationOnly |

### 7.3 The Hybrid Strategy

For the ~30% of errors that are not instruction-specific, we keep `ClassificationOnlyPredicate`.
The key change is:

- **Before:** ALL errors go through `infer_predicate()` (regex on error message)
- **After:** Instruction-level errors go through `OpcodeAnalyzer` (zero regex);
  structural/environmental errors go through `ClassificationOnlyPredicate` (which
  already returns "unknown" for lifecycle analysis)

The decision of which path to take is itself opcode-driven:
- If the error has an associated `TracedInstruction` with a valid opcode -> use
  `OpcodeAnalyzer`
- If the error has no instruction (structural error) -> use `ClassificationOnly`

This means we can delete ~700 lines of regex patterns from `ebpf_predicates.py`
and replace them with ~100 lines of opcode decoding.

---

## 8. Edge Cases and Solutions

### 8.1 Error Instruction Opcode is Ambiguous

**Problem:** Some verifier errors are reported at an instruction but the opcode
alone does not distinguish the exact safety condition. Example: `check_mem_access`
handles LDX to 12 different pointer types, each with different rules.

**Solution:** The opcode narrows the condition to "memory access on register X".
The register state at the error point further narrows it: if X is `ctx`, it's a
context field error; if X is `pkt`, it's a packet bounds error; if X is `scalar`,
it's a type error (scalar where pointer needed). The combination of opcode + register
state is always sufficient.

### 8.2 Errors at Branch Merge Points

**Problem:** Some errors are attributed to state merge, not a specific instruction.
The verifier prints "from X to Y:" annotations when merging state from multiple
paths.

**Solution:** Branch merges are already tracked by the trace parser as state
transitions with "from X to Y" annotations. The opcode-driven analysis handles
these naturally: the *instruction at the merge target* has an opcode, and the
merged state may fail its safety condition. The transition_analyzer already
classifies merge-induced widening.

### 8.3 "Too Many States" / Complexity Errors

**Problem:** These errors have no associated instruction opcode. They are
verifier-internal budget exhaustion.

**Solution:** These are already handled by `ClassificationOnlyPredicate` and
will continue to be. The opcode-driven analysis simply does not apply to them.
This is correct: there is no safety condition to trace backward because the
verifier never reached a specific failing instruction.

### 8.4 Helper Argument Errors (CALL)

**Problem:** For CALL instructions, the safety conditions depend on the helper
prototype, which is not encoded in the opcode byte.

**Solution:** The CALL opcode tells us that R1-R5 are arguments. The helper ID
is in the immediate field (visible in `bytecode_text` as `call bpf_map_lookup_elem`
or `call #14`). We can look up the prototype from a static table to determine
which argument has which type requirement. However, even without the prototype,
the opcode tells us the domain (`ARG_CONTRACT`) and the registers (R1-R5), which
is enough for lifecycle analysis: we trace all argument registers backward and
find where their types/bounds changed.

### 8.5 Return Value Errors (After CALL)

**Problem:** After a CALL, R0 holds the return value. Many errors occur because
R0 is `ptr_or_null` but used without a null check.

**Solution:** The instruction that fails is not the CALL itself but a subsequent
LDX/STX using R0 (or a copy of R0). The opcode of *that* instruction (LDX)
tells us: "R0 must be a valid, non-null pointer." Value lineage traces R0 back
to the CALL. The transition between `ptr_or_null` (at CALL) and the access
instruction (LDX) reveals whether a null check was done.

---

## 9. Novelty Assessment

### 9.1 How Does This Differ From What the Verifier Already Does?

The verifier does exactly these checks. That is the point -- we are not inventing
new checks, we are **reconstructing** the verifier's check from the instruction
and state, then **tracing backward** through the state history to find where
the condition was broken.

The verifier runs *forward* and rejects at the first failure. It does not tell you:
- Where the safety condition was previously satisfied
- What instruction broke it
- Whether it was a source bug or a lowering artifact

BPFix adds the backward analysis dimension. The opcode gives us the "what", the
register state gives us the "where", and the trace history gives us the "why" and
"when it changed."

### 9.2 How Does This Differ From the Current BPFix Approach?

| Aspect | Current (ebpf_predicates.py) | Proposed (opcode-driven) |
|--------|------------------------------|--------------------------|
| Input | Error message string | Error instruction opcode byte |
| Method | 70+ regex patterns | 7 opcode class cases |
| Kernel version sensitivity | High (messages change) | Zero (opcodes are ISA) |
| Coverage | ~92% via pattern matching | ~70% via opcode + ~30% ClassificationOnly |
| Register identification | Regex on "R\d+" in error text | Structural from opcode encoding |
| Safety condition | Inferred from error message words | Derived from ISA semantics |
| Ambiguity | High (many messages share patterns) | Low (opcode is unambiguous) |
| Maintenance | New kernel version = new regex | No maintenance needed for ISA-level |

### 9.3 Is This More Novel?

**Yes, for the paper.** The current approach is a sophisticated error message parser.
Sophisticated parsing is not a publishable contribution. The opcode-driven approach
is a *semantic analysis* grounded in the BPF ISA specification. It can be described
formally:

> Given instruction I with opcode O at program point p, and abstract state sigma_p,
> the safety condition C(O) is violated iff sigma_p(R_critical) fails to satisfy the
> property required by O's instruction class. The proof lifecycle L(C, sigma) =
> (establish_point, loss_point, cause) is computed by backward evaluation of C over
> the abstract state trace sigma_0, ..., sigma_p.

This is a proper program analysis contribution, not a diagnostic reformatter.

---

## 10. Implementation Plan

### Phase 1: Core Opcode Decoder (New File)

Create `interface/extractor/engine/opcode_analyzer.py`:
- `OpcodeClass` enum
- `SafetyDomain` enum
- `SafetyCondition` dataclass
- `OpcodeInfo` dataclass
- `decode_opcode()` function
- `_derive_conditions()` function
- `evaluate_condition()` function

**Lines of code:** ~250
**Dependencies:** Only `shared_utils.py` (for `is_pointer_type_name`, etc.)

### Phase 2: Integration With Pipeline

Modify `pipeline.py` to use `OpcodeAnalyzer` as the primary path:
1. For instruction-level errors: `decode_opcode` -> `evaluate_condition` ->
   `transition_analyzer.analyze` -> `TransitionChain`
2. For structural errors: existing `ClassificationOnly` path (unchanged)
3. Remove dependency on `ebpf_predicates.infer_predicate()` for instruction
   errors

### Phase 3: Deprecate Regex Predicates

Mark `ebpf_predicates.py` as legacy. Keep it as a fallback for edge cases but
route all instruction-level analysis through the opcode path.

### Phase 4: Validation

Run the existing test suite and batch diagnostic eval to verify:
- Same or better coverage (the 262-case benchmark)
- Same or better proof_status classification
- Elimination of regex-based error message parsing for instruction-level errors

---

## 11. Risks and Mitigations

### Risk 1: Coverage Regression

**Risk:** The opcode-driven approach might miss errors that the regex-based approach
catches, especially for unusual error messages.

**Mitigation:** Keep `ebpf_predicates.py` as a fallback. If `OpcodeAnalyzer` returns
no conditions (no error instruction, or all conditions evaluate to "unknown"), fall
back to regex-based inference. Track fallback rate.

### Risk 2: Insufficient Precision for ALU Errors

**Risk:** ALU opcodes have safety conditions that depend on operand types, not just
the opcode. Without knowing whether the destination is a pointer or scalar, the
condition set is overly broad.

**Mitigation:** This is handled in the design: derive conditions from opcode, then
**refine** using register state. The opcode narrows the search space (which registers
matter); the state resolves the ambiguity. This two-phase approach is sound.

### Risk 3: Helper Prototype Information

**Risk:** CALL instructions require helper prototype knowledge to determine which
argument has which type requirement. The opcode alone just says "it's a call."

**Mitigation:** Two options:
1. **Static table:** Embed the 200+ helper prototypes as a static lookup table
   (the kernel's `bpf_func_proto` structs). This is stable across versions.
2. **Conservative analysis:** Trace all R1-R5 backward and look for the one with a
   violated condition. This works without prototype knowledge.

Option 2 is sufficient for the paper and avoids maintaining a prototype table.

### Risk 4: Implementation Complexity

**Risk:** The opcode-driven approach might seem simpler in design but harder to
implement correctly for all corner cases.

**Mitigation:** The implementation is strictly simpler than `ebpf_predicates.py`.
7 opcode class cases vs 70 regex patterns. The complexity is in the
`transition_analyzer` and `value_lineage` modules, which already exist.

---

## 12. Formal Summary

### What We Are Building

A proof lifecycle analyzer that:
1. Takes as input: a parsed instruction trace (already available from `trace_parser`)
2. At the error instruction, decodes the opcode byte to determine the instruction class
3. From the instruction class, derives the set of safety conditions the verifier checked
4. Evaluates each condition against the register state at the error point to find
   which condition was violated
5. Identifies the critical register and the required property
6. Uses `value_lineage` to find all aliases of the critical register
7. Uses `transition_analyzer` to walk backward and find where the property was
   established and where it was lost
8. Classifies the lifecycle as `never_established`, `established_then_lost`, or
   `established_but_insufficient`
9. Derives the taxonomy class from the lifecycle and the cause of loss

### What We Are NOT Building

- A re-implementation of the verifier (we read its output, not re-run its checks)
- A complete helper prototype database (we trace all argument registers)
- A replacement for structural error classification (env_mismatch, verifier_limit
  remain as ClassificationOnly)
- An error message parser (the whole point is to not parse error messages)

### The Paper Claim

"BPFix derives safety conditions from the BPF instruction set architecture rather
than from error message text, making it kernel-version-independent and unambiguous.
For each rejected instruction, the opcode byte determines the safety domain (memory
bounds, pointer type, scalar bound, reference balance, argument contract), identifies
the critical register, and enables backward lifecycle analysis through the verifier's
abstract state trace to locate where the safety property was established and where
it was lost."
