# Manual Labeling of 30 Benchmark Cases

Selection summary: 30 cases total (`KS` 11, `SO` 12, `GH` 7), with 27 catalog-matched labels and 3 `unmatched` labels. Difficulty mix: 10 easy, 14 medium, 6 hard.

## Labeled Cases

| Case | Src | Diff | Taxonomy class | Error ID | Conf | Localizability | Specificity | Rationale | Ground truth fix |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | KS | easy | `source_bug` | `OBLIGE-E014` | high | no | yes | Calls iterator destroy on a slot that was never initialized, so the verifier is enforcing a real iterator-state obligation. | Initialize the iterator with the proper creation helper before destroy, or avoid destroy on an uninitialized slot. |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | KS | medium | `source_bug` | `OBLIGE-E003` | high | no | yes | Reads bytes from the stack-backed iterator slot before the slot is fully initialized. | Initialize the stack slot first or stop reading raw bytes out of the iterator object. |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | KS | easy | `source_bug` | `OBLIGE-E019` | high | no | yes | The dynptr is released twice; the second release happens after ownership has already been consumed. | Release the dynptr exactly once and avoid reusing it after release. |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | KS | easy | `source_bug` | `OBLIGE-E013` | high | no | yes | A function call occurs while a lock is held, which violates the verifier-enforced execution-context discipline. | Move the call outside the locked region or unlock before calling the subprogram. |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | KS | easy | `source_bug` | `OBLIGE-E015` | high | no | yes | A helper receives a possibly NULL trusted pointer on one path, so the missing proof is a dominating null check. | Null-check the created cpumask before passing it to the helper. |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | KS | medium | `source_bug` | `OBLIGE-E019` | high | no | yes | The program passes a dynptr at a non-zero offset, violating the fixed-stack-slot dynptr contract. | Pass the dynptr object at its exact stack slot / constant base address. |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | KS | medium | `source_bug` | `OBLIGE-E004` | high | partial | yes | An iterator/reference created in a callee can escape without destroy, so the root defect is a reference leak. | Destroy or release the iterator on every exit path, including the callee path. |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | KS | easy | `source_bug` | `OBLIGE-E023` | high | no | partial | The code fabricates a scalar constant and passes it where a real stack/object pointer is required. | Use a valid destination object of the required type instead of a forged scalar address. |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | KS | medium | `source_bug` | `OBLIGE-E019` | high | no | yes | A task pointer is cast and passed as a dynptr pointer, violating the helper argument contract. | Pass an actual dynptr stored on stack, not an unrelated pointer type. |
| `stackoverflow-69767533` | SO | medium | `source_bug` | `OBLIGE-E003` | high | partial | yes | The stack buffer given to `bpf_probe_read()` is uninitialized, so the verifier blocks a potential indirect read/leak. | Initialize `tmp_buffer` before the helper call and keep the copy length explicitly bounded. |
| `stackoverflow-61945212` | SO | easy | `source_bug` | `OBLIGE-E023` | high | partial | partial | The program uses `bpf_map_update_elem()` with a NULL/inv key on a queue map, which violates the helper contract. | Use `bpf_map_push_elem`/`pull`/`peek` for queue maps instead of `bpf_map_update_elem()`. |
| `stackoverflow-77205912` | SO | medium | `source_bug` | `OBLIGE-E023` | high | partial | partial | After helper calls and packet mutation, the code reuses stale packet-pointer facts instead of rebuilding them. | Re-read packet pointers from `skb` after the helper calls, or compute the checksum work before mutating the packet. |
| `stackoverflow-70091221` | SO | easy | `source_bug` | `OBLIGE-E023` | high | partial | partial | The object is missing correct map metadata, so the verifier sees a map value where a map pointer should be passed. | Declare the map in `SEC("maps")` and preserve the loader-generated map pointer relocation. |
| `github-aya-rs-aya-1062` | GH | medium | `lowering_artifact` | `OBLIGE-E005` | medium | partial | yes | The intent is safe, but `ctx.ret().unwrap()` lowers into verifier-hostile signed arithmetic that loses the range proof. | Avoid `unwrap`/panic paths in eBPF and rewrite to explicit error handling or unsigned/clamped arithmetic. |
| `stackoverflow-79530762` | SO | hard | `lowering_artifact` | `OBLIGE-E005` | medium | partial | partial | The source has packet bounds checks, but compiler-optimized pointer recomputation means the verifier no longer sees the checked proof. | Rewrite the code so the checked pointer/value is reused directly and the proof survives lowering. |
| `stackoverflow-73088287` | SO | hard | `lowering_artifact` | `OBLIGE-E005` | high | partial | partial | The checked `payload + i + 1` expression and the dereference are lowered through different registers, so the verifier loses equivalence. | Use a verifier-friendly loop rewrite that keeps the checked pointer and accessed pointer identical. |
| `stackoverflow-74178703` | SO | hard | `lowering_artifact` | `OBLIGE-E005` | high | partial | partial | Loop lowering hoists `b + offset` away from the check, so the bytecode no longer preserves the source-level range proof. | Recompute and access through the same checked pointer expression inside the loop body. |
| `stackoverflow-76160985` | SO | hard | `lowering_artifact` | `OBLIGE-E005` | high | partial | partial | A separate BPF subprogram loses caller-side allocation/range facts; the logic verifies again once the helper is forced inline. | Mark the helper `__always_inline` or otherwise keep the proof within one function. |
| `stackoverflow-70750259` | SO | medium | `lowering_artifact` | `OBLIGE-E005` | high | partial | yes | Signed/unsigned transformation widens the scalar range after lowering, so pointer arithmetic can no longer be proved safe. | Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an unsigned form. |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | KS | medium | `verifier_limit` | `OBLIGE-E018` | high | no | yes | The rejection is aggregate stack-budget exhaustion across async calls, not a missing safety guard in the source. | Reduce combined stack use, split call structure, or shrink frame sizes. |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | KS | medium | `verifier_limit` | `OBLIGE-E018` | high | no | yes | Like the paired async case, the program is rejected because the verifier budget for combined stack depth is exceeded. | Refactor the call tree or reduce per-frame stack use so the aggregate depth stays within limits. |
| `stackoverflow-56872436` | SO | medium | `verifier_limit` | `OBLIGE-E008` | high | partial | yes | The verifier explicitly reports a back-edge; the problem is proving the loop shape, not a concrete unsafe access. | Use a loop form the verifier can fully unroll or otherwise make the bound/invariant explicit. |
| `stackoverflow-78753911` | SO | medium | `verifier_limit` | `OBLIGE-E007` | high | no | yes | `8193 jumps is too complex` is a direct state-explosion signal, so the failure is analysis-budget rather than source unsafety. | Reduce branching/state fan-out, hoist common checks, or split the logic into simpler stages. |
| `github-cilium-cilium-41412` | GH | hard | `verifier_limit` | `unmatched` | medium | no | no | The test only fails once verifier complexity grows too far under `bpf_jit_harden=2`; the fix discussed is to reduce exponential proof growth. | Backport the memmove simplification patch or refactor the test so verifier complexity stays below the budget. |
| `github-cilium-cilium-35182` | GH | medium | `env_mismatch` | `OBLIGE-E021` | high | partial | yes | The failure is missing/incorrect BTF reference metadata (`UNKNOWN` reference size), not a safety bug in the program logic. | Regenerate/align BTF artifacts and use the toolchain/kernel combination that emits valid reference metadata. |
| `github-aya-rs-aya-1233` | GH | easy | `env_mismatch` | `OBLIGE-E009` | high | partial | yes | `bpf_probe_read` is simply unavailable in this program type, so the program/environment contract is wrong. | Use a helper allowed in `cgroup_skb`, or move the logic to a program type that permits the read helper. |
| `github-aya-rs-aya-864` | GH | easy | `env_mismatch` | `OBLIGE-E009` | high | partial | yes | The helper is unavailable in this context and the correct value should come from the program context instead. | Read the PID from `TcContext`/`skb` instead of calling the unavailable helper. |
| `stackoverflow-76441958` | SO | medium | `env_mismatch` | `unmatched` | medium | partial | partial | The issue depends on target-architecture alignment rules for atomic operations, so the mismatch is between runtime assumptions and deployment environment. | Align the user-space data/struct layout or target an architecture/context that satisfies the atomic access requirements. |
| `github-cilium-cilium-44216` | GH | easy | `verifier_bug` | `OBLIGE-E010` | high | no | no | The kernel emits an explicit `verifier bug` warning and maintainers confirm it is a known upstream verifier issue. | Backport/upgrade to a kernel with the verifier fix, or carry a kernel-version workaround until then. |
| `github-cilium-cilium-41996` | GH | hard | `verifier_bug` | `unmatched` | low | no | no | This is the weakest label in the set: the same workload reportedly starts working after a kernel upgrade, which suggests a kernel-side false rejection/regression rather than a source fix. | Upgrade to a newer kernel (6.8+) or minimize the reproducer to confirm and isolate the kernel regression. |

## Distribution Across Taxonomy Classes

| Class | Count | Share |
| --- | ---: | ---: |
| `source_bug` | 13 | 43.3% |
| `lowering_artifact` | 6 | 20.0% |
| `verifier_limit` | 5 | 16.7% |
| `env_mismatch` | 4 | 13.3% |
| `verifier_bug` | 2 | 6.7% |

Additional selection checks:
- Sources: `KS` 11, `SO` 12, `GH` 7
- Catalog-matched vs unmatched: 27 matched, 3 unmatched
- Difficulty mix: easy 10, medium 14, hard 6

## Inter-class Agreement with Heuristic Classifier

- Exact agreement: **23/30** (76.7%)
- Cohen's kappa: **0.652**

Confusion matrix (manual rows, heuristic columns):

| Manual \ Heuristic | `source_bug` | `lowering_artifact` | `verifier_limit` | `env_mismatch` | `verifier_bug` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `source_bug` | 13 | 0 | 0 | 0 | 0 |
| `lowering_artifact` | 4 | 2 | 0 | 0 | 0 |
| `verifier_limit` | 0 | 0 | 4 | 1 | 0 |
| `env_mismatch` | 1 | 0 | 0 | 3 | 0 |
| `verifier_bug` | 1 | 0 | 0 | 0 | 1 |

## Source Localizability and Obligation Specificity Statistics

| Metric | yes | partial | no |
| --- | ---: | ---: | ---: |
| Source localizability | 0 (0.0%) | 16 (53.3%) | 14 (46.7%) |
| Obligation specificity | 18 (60.0%) | 9 (30.0%) | 3 (10.0%) |

Note: the three `obligation_specificity = no` cases are the two verifier-bug labels plus the generic `operation not supported` complexity case, where the log does not describe a missing proof obligation directly.

## Notable Cases Where the Heuristic Classifier Was Wrong

- `stackoverflow-79530762`: manual `lowering_artifact` vs heuristic `source_bug`. Compiler optimization hides an already-present packet-bounds proof, so the raw packet-access text is misleading.
- `stackoverflow-73088287`: manual `lowering_artifact` vs heuristic `source_bug`. The failing packet access is caused by a checked-vs-dereferenced register split introduced by lowering.
- `stackoverflow-74178703`: manual `lowering_artifact` vs heuristic `source_bug`. The heuristic follows the surface map-bounds message, but the accepted fix is a loop/codegen rewrite.
- `stackoverflow-76160985`: manual `lowering_artifact` vs heuristic `source_bug`. The true fix is `__always_inline`, which is a classic lowering artifact rather than a real memory bug.
- `github-cilium-cilium-41412`: manual `verifier_limit` vs heuristic `env_mismatch`. The heuristic sees `operation not supported` and drifts toward environment, but the issue discussion is about verifier complexity growth.
- `stackoverflow-76441958`: manual `env_mismatch` vs heuristic `source_bug`. The surface type/misalignment error is architecture-dependent; the root cause is environment/ABI alignment mismatch.
- `github-cilium-cilium-41996`: manual `verifier_bug` vs heuristic `source_bug`. Low-confidence boundary case: the heuristic calls it source_bug, but the only reported fix is a kernel upgrade.
