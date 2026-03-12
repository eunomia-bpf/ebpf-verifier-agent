# Proof Engine Review Round 2

## What Was Fixed

1. Register-version-aware proof tracking
   - Added value-lineage tracking on top of the trace IR.
   - Each definition now gets its own version, while copy-like moves preserve a proof root and same-register arithmetic keeps a lineage edge.
   - Obligation evaluation now only counts states that are on the failing value's lineage or an equivalent copy lineage before the failing register version exists.
   - Confirmed by `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39`, which now returns `null_check / never_established` instead of the previous false `established_then_lost`.

2. Offset-aware `range_at_least`
   - Packet accesses now use the verifier's reported effective `off=` when present, so negative fixed-offset loads are evaluated against the right packet range witness.
   - Non-packet memory families now account for pointer fixed offsets and available variable upper bounds.
   - This preserves the earlier correct `stackoverflow-79530762` regression while fixing the synthetic negative-offset packet case.

3. Generic `memory_access` obligation family
   - Added inference for `invalid access to memory, mem_size=...` failures.
   - This eliminates the old `obligation=None` fallback for cases like `stackoverflow-76160985`.
   - Current limitation: obligation inference is better than classification quality here; `76160985` is still mis-modeled as `never_established`.

4. Multi-register split tracking
   - Atom evaluation now allows establishment on an equivalent lineage register before the failing register version is live, but once the failing version exists it must satisfy the obligation itself.
   - This keeps real split-driven behavior like `stackoverflow-79530762` and the new synthetic split regression defensible.

## New Real-Case Regression Tests

Added 5 more corpus cases to `tests/test_proof_engine.py`:

| Case | Expected output | Notes |
| --- | --- | --- |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `null_check`, `never_established`, reject `15` | Round-1 false-loss case; now fixed |
| `stackoverflow-61945212` | `helper_arg`, `never_established`, reject `8` | `R2 type=inv expected=fp` |
| `github-aya-rs-aya-864` | `obligation=None`, `unknown`, reject `1` | helper unavailable / env mismatch |
| `github-cilium-cilium-41412` | `obligation=None`, `unknown`, reject `1738` | verifier-limit style budget failure |
| `github-cilium-cilium-44216` | `obligation=None`, `unknown`, reject `None` | verifier bug / kernel oops trace |

Real-case regression coverage in `tests/test_proof_engine.py` is now 14 cases.

## Remaining Wrong Results

These still need work after round 2:

| Case | Current output | Why it is still wrong | Likely next fix |
| --- | --- | --- | --- |
| `stackoverflow-73088287` | `packet_access`, `never_established` | Trace is only a short final snippet with no useful state lines; the split proof is still unrecoverable | Add state-poor provenance heuristics or require richer logs |
| `stackoverflow-74178703` | `map_value_access`, `never_established` | The checked value is a hoisted scalar/index proof, not just a copied pointer; current atoms do not connect that guard to the failing map-value pointer | Model scalar-index obligations and checked-vs-dereferenced map splits |
| `stackoverflow-76160985` | `memory_access`, `never_established` | Obligation family is now correct, but the missing proof is across a subprogram boundary and caller-side facts are still lost | Add caller/callee proof transfer or subprogram-aware trace reconstruction |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `helper_arg`, `established_then_lost` | The call-site argument error is being turned into a synthetic loss at the failing instruction because the post-call state is absent | Special-case subprog/helper arg failures so missing post-state does not fabricate loss |

## Updated Assessment

The narrow novelty claim is stronger now and defensible:

- The engine is no longer register-name-based for proof establishment. It is lineage-aware for the supported obligation families.
- It can distinguish `never_established` from `established_then_lost` more credibly on real packet/null/helper cases, including register reuse and copy-split artifacts.
- It now covers a generic memory-access family instead of dropping those cases to `obligation=None`.

The broader claim is still not defensible yet:

- It is not a general proof-loss engine across sparse traces, hoisted scalar guards, and subprogram-boundary artifacts.
- Backward slicing is still path-insensitive.
- Multi-register equivalence is still strongest for copy-lineage packet cases, not for all packet/map lowering patterns.

Practical restatement:

- Defensible: a narrow obligation-driven proof engine for packet access, packet pointer arithmetic, helper/type/null cases, stack access, and generic memory access with lineage-sensitive establishment tracking.
- Not yet defensible: full generality over the lowering-artifact corpus.
