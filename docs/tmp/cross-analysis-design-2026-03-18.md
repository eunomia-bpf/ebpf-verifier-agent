# Cross-Analysis Design

Date: 2026-03-18

Scope:
- concrete Step D design for proof-carrier-aware cross-analysis
- grounded in the current code:
  - `interface/extractor/engine/opcode_safety.py`
  - `interface/extractor/engine/monitor.py`
  - `interface/extractor/engine/slicer.py`
  - `interface/extractor/pipeline.py`
- satisfies the 2026-03-18 design review constraints

## Bottom Line

The minimal sound-enough design is:

1. infer a small set of register-parametric safety atoms from the reject opcode
2. instantiate each atom on the reject-site operand role
3. discover only proof-compatible carriers from the reject-site abstract state
4. monitor each instantiated atom on each compatible carrier, but only while that register remains in the same alias class as the reject-site carrier
5. slice backward from the reject operand register
6. classify per atom using both temporal witnesses and structural witnesses
7. aggregate atom classifications conservatively

The key constraints are:

- no error-message matching
- no regex-based classification logic
- no “any proof anywhere in the trace” rule
- no loop story unless the slice is acyclic
- no single-obligation collapse

All decisions come from:

- opcode byte and decoded operand roles
- parsed abstract state values (`type`, `id`, `off`, `range`, `umax`, ...)
- CFG / backward-slice structure

The existing infrastructure is enough. `slicer.py` stays unchanged. The only real additions are:

- register-parametric schema objects in `opcode_safety.py`
- carrier-aware monitor wrapper in `monitor.py`
- carrier discovery + per-atom cross-analysis in `pipeline.py`

## A. Register-Parametric Safety Schema

### A.1 Problem

Current `SafetyCondition` is register-specific:

```python
SafetyCondition(domain=MEMORY_BOUNDS, critical_register="R0", access_size=1)
```

That is sufficient for single-register monitoring, but ill-typed for cross-analysis. Step D needs the abstract obligation first, then concrete instantiations on:

- the reject-site register
- any proof-compatible carrier registers

So the representation must split into:

- a register-parametric schema
- a concrete instantiation on one carrier

### A.2 Minimal schema model

Keep the current `SafetyCondition` as the instantiated form used by `compute_condition_gap()` and `evaluate_condition()`.

Add a new register-parametric layer:

```python
from dataclasses import dataclass
from enum import Enum


class OperandRole(Enum):
    BASE_PTR = "base_ptr"
    OFFSET_SCALAR = "offset_scalar"
    HELPER_ARG = "helper_arg"
    RETURN_VALUE = "return_value"
    REF_OBJECT = "ref_object"


@dataclass(frozen=True)
class SafetySchema:
    domain: SafetyDomain
    role: OperandRole
    access_size: int | None = None
    pointer_kind: str | None = None
    expected_types: tuple[str, ...] = ()
    allow_null: bool = False
    requires_range: bool = False
    requires_writable: bool = False
    helper_id: int | None = None
    helper_name: str | None = None
    helper_arg_index: int | None = None
    constraint: str | None = None


@dataclass(frozen=True)
class CarrierSpec:
    register: str
    role: OperandRole
    pointer_kind: str | None
    provenance_id: int | None
    reject_type: str | None
    is_primary: bool = False


@dataclass(frozen=True)
class BoundAtom:
    schema: SafetySchema
    carrier: CarrierSpec
```

`pointer_kind` is not free text inference. It is a normalized value derived from the parsed verifier type token through a closed mapping table, for example:

- `pkt` -> `pkt`
- `map_value` / `map_value_or_null` -> `map_value`
- `sock` / `sock_or_null` / `ptr_sock` -> `sock`
- `ctx` -> `ctx`
- `fp` -> `fp`

That is a typed lookup over the verifier’s structured abstract-state token, not regex matching on log text.

### A.3 Schema types

We already have the right atom universe in `SafetyDomain`. Step D should reuse it directly.

| Domain | Schema name | Typical role |
|---|---|---|
| `MEMORY_BOUNDS` | `PacketBounds` / `MemoryBounds` | `BASE_PTR` |
| `POINTER_TYPE` | `PointerType` | `BASE_PTR`, `HELPER_ARG` |
| `NULL_SAFETY` | `NullCheck` | `BASE_PTR`, `HELPER_ARG` |
| `SCALAR_BOUND` | `ScalarBound` | `OFFSET_SCALAR`, `RETURN_VALUE` |
| `ARG_CONTRACT` | `HelperArgType` | `HELPER_ARG` |
| `WRITE_PERMISSION` | `WritePermission` | `BASE_PTR` |
| `ARITHMETIC_LEGALITY` | `ArithmeticLegality` | `BASE_PTR` |
| `REFERENCE_BALANCE` | `ReferenceBalance` | `REF_OBJECT`, `RETURN_VALUE` |

The important change is not adding many new domains. It is making each domain role-parametric.

### A.4 Schema inference from opcode

`opcode_safety.py` already decodes enough structured data:

- opcode class
- `src_reg`
- `dst_reg`
- access size
- helper id

So `infer_safety_schemas_from_error_insn()` should produce schemas, not concrete `SafetyCondition`s.

Examples:

1. `LDX r6 = *(u8 *)(r0 +0)`

```python
[
    SafetySchema(domain=POINTER_TYPE, role=BASE_PTR, pointer_kind="pkt"),
    SafetySchema(domain=NULL_SAFETY, role=BASE_PTR, pointer_kind="pkt"),
    SafetySchema(domain=MEMORY_BOUNDS, role=BASE_PTR, pointer_kind="pkt", access_size=1),
]
```

2. `ALU64 r5 += r0`

```python
[
    SafetySchema(domain=ARITHMETIC_LEGALITY, role=BASE_PTR, pointer_kind=<from R5 pre-state>),
    SafetySchema(domain=SCALAR_BOUND, role=OFFSET_SCALAR),
]
```

3. `CALL helper`

One schema per helper argument constraint from `helper_signatures.py`, each with `helper_arg_index`.

### A.5 Instantiation

Instantiation is intentionally thin:

```python
def instantiate_schema(schema: SafetySchema, carrier: CarrierSpec) -> SafetyCondition:
    return SafetyCondition(
        domain=schema.domain,
        critical_register=carrier.register,
        required_property=_required_property(schema),
        access_size=schema.access_size,
        expected_types=schema.expected_types,
        allow_null=schema.allow_null,
        requires_range=schema.requires_range,
        requires_writable=schema.requires_writable,
        helper_id=schema.helper_id,
        helper_name=schema.helper_name,
        constraint=schema.constraint,
    )
```

That preserves the existing gap logic.

### A.6 Which schemas expand to candidate carriers?

Not every domain should do global carrier search.

- Pointer-bearing atoms expand:
  - `MEMORY_BOUNDS`
  - `POINTER_TYPE`
  - `NULL_SAFETY`
  - `WRITE_PERMISSION`
  - `ARITHMETIC_LEGALITY`
  - pointer-valued `ARG_CONTRACT`
- Singleton atoms stay on the primary register only:
  - `SCALAR_BOUND`
  - scalar `ARG_CONTRACT`
  - `REFERENCE_BALANCE`

This keeps the implementation minimal and avoids pretending that scalar aliasing is as stable as pointer provenance.

## B. Proof-Compatible Carrier Discovery

### B.1 Carrier definition

For pointer-bearing atoms, a proof-compatible carrier is a register in the reject-site `pre_state` that is in the same alias class as the primary reject operand.

For v1, define alias class as:

```text
(pointer_kind, provenance_id)
```

where:

- `pointer_kind` comes from the parsed verifier type token via a closed lookup table
- `provenance_id` is the parsed verifier `id` field

Compatibility requires:

1. same operand family for the schema
2. same `pointer_kind`
3. same `provenance_id`

This directly handles counterexample A. A proof on another packet pointer with a different `id` is not a carrier for the rejected pointer.

### B.2 Why reject-site discovery, not global discovery

Carrier discovery is anchored at the rejection point, not over the whole trace.

Algorithm:

1. determine the primary register for the atom from opcode roles
2. read its `RegisterState` from `error_insn.pre_state`
3. build `CarrierSpec(primary)`
4. scan only `error_insn.pre_state` for other registers with the same alias class

This means:

- the candidate set is small
- the candidate set is typed
- carrier identity is derived from verifier state, not source names

### B.3 Primary-register selection

Derived only from decoded opcode roles:

- `LDX`: primary = `src_reg`
- `ST` / `STX`: primary = `dst_reg`
- `ALU` / `ALU64`:
  - `ARITHMETIC_LEGALITY`: primary = `dst_reg`
  - `SCALAR_BOUND`: primary = `src_reg`
- `CALL`: primary = `R<arg_index>`
- `EXIT`: primary = `R0`

No text matching on the error string is needed.

### B.4 Carrier discovery function

Minimal shape:

```python
def discover_compatible_carriers(
    schema: SafetySchema,
    primary: CarrierSpec,
    reject_state: dict[str, RegisterState],
) -> list[CarrierSpec]:
    if schema.domain in {SCALAR_BOUND, REFERENCE_BALANCE}:
        return [primary]

    if primary.pointer_kind is None or primary.provenance_id is None:
        return [primary]

    carriers = []
    for reg, st in reject_state.items():
        if normalize_pointer_kind(st.type) != primary.pointer_kind:
            continue
        if st.id != primary.provenance_id:
            continue
        carriers.append(
            CarrierSpec(
                register=reg,
                role=primary.role,
                pointer_kind=primary.pointer_kind,
                provenance_id=primary.provenance_id,
                reject_type=st.type,
                is_primary=(reg == primary.register),
            )
        )
    return carriers
```

Important conservative rule:

- if the reject-site primary carrier has no usable provenance id, do not expand to other registers
- degrade to the singleton primary carrier

That avoids false lowering-artifact stories when alias identity is unavailable.

### B.5 Time-varying compatibility

Reject-site carrier discovery is not enough by itself. The same register name may hold a different pointer provenance earlier in the trace.

Example from `stackoverflow-70760516`:

- reject site: `R0=pkt(id=22,off=90,range=0)`
- earlier loop iterations: `R0` held `pkt(id=14..21,...)`

Those earlier `R0` states are not compatible carriers for the reject-site pointer, even though the register name is the same.

So monitoring must re-check compatibility at every instruction:

```text
current register state is compatible iff
  normalize_pointer_kind(current.type) == carrier.pointer_kind
  and current.id == carrier.provenance_id
```

If not compatible, the monitor treats that instruction as `gap=None` for that carrier.

This is the critical fix for both:

- counterexample A
- loop-carried false proof stories on reused registers

## C. Per-Carrier Monitoring

### C.1 Design choice

Run N monitors, one per instantiated carrier atom.

Do not rewrite `TraceMonitor` into a global multi-register engine.

Reason:

- candidate carriers per atom are tiny
- current `TraceMonitor` gap logic is already correct
- N-monitor wrapper is much smaller than a new state machine

So the minimal design is:

1. keep the current gap computation
2. add a carrier-compatible predicate wrapper
3. add an event-collecting monitor result
4. wrap the existing monitor in a per-carrier loop

### C.2 Carrier-aware predicate wrapper

```python
@dataclass(frozen=True)
class CarrierBoundPredicate:
    condition: SafetyCondition
    carrier: CarrierSpec

    @property
    def target_regs(self) -> list[str]:
        return [self.carrier.register]

    def compute_gap(self, state: dict, insn=None) -> int | None:
        reg = state.get(self.carrier.register)
        if reg is None:
            return None
        if self.carrier.pointer_kind is not None:
            if normalize_pointer_kind(reg.type) != self.carrier.pointer_kind:
                return None
            if reg.id != self.carrier.provenance_id:
                return None
        return compute_condition_gap(self.condition, state)

    def describe_violation(self, state: dict, insn=None) -> str:
        return OpcodeConditionPredicate(self.condition).describe_violation(state, insn)
```

This is where alias filtering happens. The gap computation itself stays unchanged.

### C.3 Event-rich result type

Current `MonitorResult` only stores one establish site and one loss site. For cross-analysis we need the timeline, especially for loops and repeated carrier episodes.

Minimal extension:

```python
@dataclass(frozen=True)
class LifecycleEvent:
    kind: str                 # "establish" | "loss"
    trace_pos: int
    insn_idx: int
    gap_before: int
    gap_after: int
    reason: str | None = None


@dataclass
class CarrierLifecycle:
    carrier: CarrierSpec
    events: list[LifecycleEvent]
    establish_site: int | None
    loss_site: int | None
    last_satisfied_insn: int | None
    final_gap: int | None
    proof_status: str
```

And the per-atom wrapper result:

```python
@dataclass
class AtomMonitoringResult:
    schema: SafetySchema
    primary: CarrierSpec
    carriers: dict[str, CarrierLifecycle]   # key = carrier.register
```

`trace_pos` is necessary because loop traces repeat the same `insn_idx`. Temporal reasoning must use linear trace order, not instruction number alone.

### C.4 Monitor implementation strategy

Recommended minimal change in `monitor.py`:

- keep `TraceMonitor.monitor()` for backward compatibility
- add `TraceMonitor.monitor_events()` that records all `gap > 0 -> 0` and `gap == 0 -> gap > 0` transitions with `trace_pos`
- add a small wrapper:

```python
def monitor_carriers(schema, carriers, traced_insns) -> AtomMonitoringResult:
    out = {}
    for carrier in carriers:
        cond = instantiate_schema(schema, carrier)
        pred = CarrierBoundPredicate(cond, carrier)
        out[carrier.register] = TraceMonitor().monitor_events(pred, traced_insns)
    return AtomMonitoringResult(schema=schema, primary=..., carriers=out)
```

### C.5 Gap semantics

Gap semantics remain unchanged:

- establishment only when gap transitions from positive to zero
- vacuous satisfaction does not count
- loss only after a real establishment

This directly handles counterexample E:

- if a carrier is first observed with `gap == 0`, no establishment witness is created
- therefore vacuous satisfaction cannot incorrectly trigger `lowering_artifact` or `established_then_lost`

## D. Cross-Analysis Classification Algorithm

### D.1 Per-atom algorithm

Cross-analysis must operate per unsatisfied atom, not on a single “violated condition”.

For each schema:

1. instantiate the primary carrier from the reject operand role
2. evaluate the atom on `error_insn.pre_state`
3. if the atom is already satisfied, drop it
4. if the atom is `violated` or `unknown`, keep it active
5. discover compatible carriers
6. monitor per carrier
7. slice backward from `(error_insn.insn_idx, primary.register)`
8. classify the atom conservatively

### D.2 Structural side conditions

Two structural filters are required before interpreting a proof story:

1. Back-edge filter

- build CFG once with `build_cfg()`
- compute `back_edges = {(src, dst) | dst <= src}`
- if the atom’s backward slice contains a back-edge, classify that atom as `ambiguous`

This is the required handling for counterexample D.

2. Path-stability filter

An establishment or loss witness only counts if it is path-stable for the rejected use.

Minimal rule:

- compute forward dominators on the CFG in `pipeline.py`
- a witness at `site` only counts if `site` dominates `error_insn`

If a non-dominating establishment exists but no dominating one exists, classify the atom as `ambiguous`.

This is the required handling for counterexample B.

### D.3 On-chain vs off-chain

For a given atom:

- `on-chain` means the witness instruction is in that atom’s backward slice
- `off-chain` means the witness instruction is not in that atom’s backward slice

This keeps Step D grounded in the existing slicer.

### D.4 Precise pseudocode

```python
def classify_atom(
    schema: SafetySchema,
    error_insn: TracedInstruction,
    traced_insns: list[TracedInstruction],
    cfg: TraceCFG,
    dominators: dict[int, set[int]],
) -> AtomClassification:
    primary = instantiate_primary_carrier(schema, error_insn)
    if primary is None:
        return AtomClassification("ambiguous", reason="no_primary_carrier")

    primary_cond = instantiate_schema(schema, primary)
    reject_eval = evaluate_condition(primary_cond, error_insn.pre_state)
    if reject_eval == "satisfied":
        return AtomClassification("inactive", reason="atom_satisfied_at_reject")

    carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)
    monitoring = monitor_carriers(schema, carriers, traced_insns)
    bslice = backward_slice(
        traced_insns,
        criterion_insn=error_insn.insn_idx,
        criterion_register=primary.register,
        cfg=cfg,
    )

    if slice_contains_back_edge(bslice, cfg):
        return AtomClassification("ambiguous", reason="loop_back_edge")

    any_establish = False
    any_non_dominating_establish = False
    any_off_chain_establish = False

    for lifecycle in monitoring.carriers.values():
        establishes = [e for e in lifecycle.events if e.kind == "establish"]
        losses = [e for e in lifecycle.events if e.kind == "loss"]

        if establishes:
            any_establish = True

        dominating_establishes = []
        for e in establishes:
            if error_insn.insn_idx in dominators.get(e.insn_idx, set()):
                dominating_establishes.append(e)
            else:
                any_non_dominating_establish = True

        dominating_losses = [
            l for l in losses
            if error_insn.insn_idx in dominators.get(l.insn_idx, set())
        ]

        for e in dominating_establishes:
            if e.insn_idx not in bslice.full_slice:
                any_off_chain_establish = True
                continue

            later_on_chain_loss = first(
                l for l in dominating_losses
                if l.trace_pos > e.trace_pos and l.insn_idx in bslice.full_slice
            )
            if later_on_chain_loss is not None:
                return AtomClassification(
                    "established_then_lost",
                    establish=e,
                    loss=later_on_chain_loss,
                    carrier=lifecycle.carrier,
                )

    if any_non_dominating_establish:
        return AtomClassification("ambiguous", reason="branch_local_establish")

    if any_off_chain_establish:
        return AtomClassification("lowering_artifact")

    if not any_establish:
        return AtomClassification("source_bug")

    return AtomClassification("ambiguous", reason="incomplete_temporal_story")
```

Important notes:

- “same carrier” is enforced by per-carrier monitoring
- temporal order uses `trace_pos`
- loop ambiguity is explicit, not inferred after the fact
- lowering-artifact requires an off-chain compatible establishment, not just any establishment anywhere

### D.5 Aggregation across atoms

Only aggregate active atoms, where active means `evaluate_condition(...) != "satisfied"` at the reject site.

Conservative aggregation:

```python
def aggregate_atom_classes(atom_classes: list[str]) -> str:
    active = [c for c in atom_classes if c != "inactive"]
    if not active:
        return "ambiguous"
    if "ambiguous" in active:
        return "ambiguous"
    if "source_bug" in active:
        return "source_bug"
    if len(set(active)) == 1:
        return active[0]
    return "ambiguous"
```

This is the required handling for counterexample C.

Why `source_bug` outranks non-ambiguous mixed results:

- if one active atom truly has no compatible establishment, the reject is still explained by a missing source-level proof obligation
- we should not mask that with a separate proof-loss story on another atom

### D.6 Counterexample handling summary

| Counterexample | Failure mode in old plan | New handling |
|---|---|---|
| A. unrelated proof on another register | false `lowering_artifact` | carrier discovery requires same `(pointer_kind, id)` |
| B. branch-local check | false `established_then_lost` | non-dominating witness -> `ambiguous` |
| C. multiple obligations | wrong single-atom story | classify per active atom, aggregate conservatively |
| D. loop-carried widening | false proof-loss story | any back-edge in atom slice -> `ambiguous` |
| E. vacuous satisfaction | false establishment | current gap transition rule already prevents witness creation |

### D.7 Four-way output

Step D outputs one of:

- `established_then_lost`
- `lowering_artifact`
- `source_bug`
- `ambiguous`

For implementation, this should be stored as a dedicated field such as `cross_analysis_class`.

Whether presentation maps `established_then_lost` into a broader user-facing `lowering_artifact` bucket is a separate rendering decision, not part of the analysis algorithm.

## E. Integration into Pipeline

### E.1 New order in `pipeline.py`

Recommended order:

1. parse log
2. parse trace
3. find reject instruction
4. structural filtering by `error_id`
5. infer safety schemas and primary operand roles
6. activate unsatisfied atoms at the reject site
7. build CFG once
8. run per-atom carrier discovery + per-carrier monitoring
9. run per-atom backward slices
10. cross-analyze per atom
11. aggregate atom classes
12. attach metadata and render

This is slightly different from the current pipeline. The important change is that Step A now seeds both monitoring and slicing.

### E.2 Structural filtering interaction

Structural classes stay outside cross-analysis:

- `env_mismatch`
- `verifier_limit`
- `verifier_bug`

Only proof-obligation failures enter Step A-D.

That means the current `_STRUCTURAL_TAXONOMY_BY_ERROR_ID` check should happen before:

- `infer_conditions_from_error_insn()`
- `TraceMonitor`
- `backward_slice()`

### E.3 Concrete pipeline changes

`pipeline.py` should stop doing:

- `find_violated_condition()` as the sole atom selector
- single-register `TraceMonitor()` result as the classifier
- `loss_site != None -> lowering_artifact`

Instead it should do:

```python
schemas = infer_safety_schemas_from_error_insn(error_insn)
active_atoms = instantiate_active_atoms(schemas, error_insn)
cfg = build_cfg(instructions)
dominators = compute_forward_dominators(cfg)

per_atom = []
for atom in active_atoms:
    per_atom.append(classify_atom(atom.schema, error_insn, instructions, cfg, dominators))

cross_class = aggregate_atom_classes([r.classification for r in per_atom])
```

Attach at least:

- `metadata["cross_analysis_class"]`
- `metadata["active_atoms"]`
- `metadata["carrier_lifecycles"]`
- `metadata["backward_slices"]`
- `metadata["ambiguous_reason"]` when relevant

### E.4 Module-by-module changes

`interface/extractor/engine/opcode_safety.py`

- add `SafetySchema`, `OperandRole`, `CarrierSpec`
- add schema inference and schema instantiation helpers
- keep existing `SafetyCondition` and gap evaluation

Estimated change: 80-120 LOC

`interface/extractor/engine/monitor.py`

- add `LifecycleEvent`
- add event-rich monitoring result
- add carrier-aware wrapper while keeping current gap logic

Estimated change: 60-100 LOC

`interface/extractor/engine/slicer.py`

- no changes

Estimated change: 0 LOC

`interface/extractor/pipeline.py`

- structural filter earlier
- active-atom handling instead of single violated condition
- carrier discovery
- forward-dominator helper
- per-atom classification and aggregation

Estimated change: 120-180 LOC

Total new / modified analysis code:

- approximately 260-400 LOC

That matches the implementation budget.

## F. Concrete Example Walkthrough

### F.1 Pilot case: `stackoverflow-70760516`

This case is useful precisely because it shows why the new algorithm must be conservative.

Reject instruction:

```text
14: r6 = *(u8 *)(r0 +0)
```

Reject-site `pre_state` includes:

```text
R0 = pkt(id=22, off=90, range=0)
R5 = pkt(id=22, off=94, range=0)
```

#### Step A: infer atoms

From opcode `LDX` with access size 1:

- `PointerType(role=BASE_PTR, pointer_kind=pkt)`
- `NullCheck(role=BASE_PTR, pointer_kind=pkt)`
- `PacketBounds(role=BASE_PTR, pointer_kind=pkt, access_size=1)`

Evaluation on `error_insn.pre_state`:

- `PointerType(R0)` = satisfied
- `NullCheck(R0)` = satisfied
- `PacketBounds(R0)` = violated because `off + 1 > range`

So only `PacketBounds` is active.

#### Step B: discover compatible carriers

Primary carrier:

```text
CarrierSpec(register="R0", pointer_kind="pkt", provenance_id=22, is_primary=True)
```

Reject-site compatible carriers:

- `R0` with `(pkt, id=22)`
- `R5` with `(pkt, id=22)`

Crucially, earlier loop iterations with `R0/R5` carrying `id=14..21` are not compatible carriers for this reject-site pointer.

#### Step C: per-carrier monitoring

Under the alias filter `(pointer_kind="pkt", id=22)`:

- `R0` is only observed as the reject-site alias near the final loop iteration
- `R5` is also only observed as the reject-site alias near the final loop iteration

Observed gaps for the active atom are never `>0 -> 0` for the `id=22` carrier episode:

- `R0`: still out of bounds when `id=22` first appears
- `R5`: also out of bounds when `id=22` first appears

So there is no establishment witness on any compatible carrier for the reject-site alias class.

This is the point where the old single-register monitor goes wrong: it tracks `R0` across changing ids and invents a proof story from earlier iterations.

#### Step C: backward slice

Backward slice from `(14, R0)` includes loop instructions and contains the CFG back-edge:

```text
31 -> 12
```

#### Step D: classify

Because the atom slice contains a back-edge, this case is explicitly:

```text
ambiguous
```

That is the intended conservative result:

- there is no same-alias establishment for the reject-site carrier
- earlier established ranges belong to earlier loop iterations with different provenance ids
- the slice is loopy, so a linear proof-loss story is not trustworthy

This is exactly the counterexample-D policy.

### F.2 Counterexample A: unrelated proof on another register

Structured state at reject site:

```text
error insn: r0 = *(u8 *)(r5 +0)

R5 = pkt(id=7, off=20, range=0)    # rejected base pointer
R3 = pkt(id=3, off=20, range=32)   # unrelated checked pointer
```

#### Step A

Active atom:

```text
PacketBounds(role=BASE_PTR, pointer_kind=pkt, access_size=1)
```

Primary carrier:

```text
CarrierSpec(register="R5", pointer_kind="pkt", provenance_id=7)
```

#### Step B

Carrier discovery scans the reject-site state:

- `R5` matches `(pkt, id=7)` -> included
- `R3` has different `id` -> excluded

So the compatible carrier set is:

```text
{R5}
```

#### Step C

Per-carrier monitoring sees no establishment on `R5`.

#### Step D

There is:

- no on-chain establish/loss pair
- no off-chain compatible establishment
- no ambiguity flag

So the result is:

```text
source_bug
```

This is the correct outcome. The new algorithm does not confuse “some packet pointer was checked” with “the rejected pointer was proved safe”.

## Recommended Implementation Notes

- Keep `find_violated_condition()` for legacy callers, but do not use it for Step D.
- Do not use `TransitionAnalyzer` for cross-analysis classification. It is still useful for presentation, but Step D should be driven only by:
  - schema atoms
  - alias-filtered carrier monitoring
  - backward slice
  - CFG dominance / back-edge checks
- Store internal proof classes separately from the renderer’s current coarse taxonomy if compatibility matters.

## Conclusion

The minimal proof-carrier-aware design is not “monitor every register globally”. It is:

- infer atom schemas from opcode roles
- instantiate them only on reject-compatible carriers
- require same alias class over time
- require a coherent temporal story on the causal chain
- bail out to `ambiguous` on merges and loops

That is implementable in roughly 300 LOC of engine changes, uses the current parser/monitor/slicer stack, and directly addresses the five counterexamples from the design review.
