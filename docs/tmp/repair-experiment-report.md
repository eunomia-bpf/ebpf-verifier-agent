# Repair Experiment: Raw Logs vs Raw Logs + OBLIGE

- Generated: `2026-03-12T03:49:10+00:00`
- Model: `gpt-4.1-mini` with fallback `gpt-4.1-nano`
- Cases: `30`
- API delay: `1.0` seconds between calls

## Selection Summary

| Taxonomy | Cases |
| --- | ---: |
| `lowering_artifact` | 8 |
| `source_bug` | 13 |
| `verifier_limit` | 4 |
| `env_mismatch` | 5 |

| Source | Cases |
| --- | ---: |
| `stackoverflow` | 26 |
| `github_issues` | 3 |
| `kernel_selftests` | 1 |

## Fix-Type Success Rate

| Condition | Fix type match | Root-cause targeting | Semantic similarity |
| --- | ---: | ---: | ---: |
| A (raw log only) | 10/30 (33.3%) | 15/30 (50.0%) | 23/30 (76.7%) |
| B (raw log + OBLIGE) | 10/30 (33.3%) | 17/30 (56.7%) | 25/30 (83.3%) |

## Per-Taxonomy Breakdown

| Taxonomy | Cases | A fix-type | B fix-type | Delta |
| --- | ---: | ---: | ---: | ---: |
| `lowering_artifact` | 8 | 0/8 (0.0%) | 2/8 (25.0%) | +25.0 pp |
| `source_bug` | 13 | 9/13 (69.2%) | 6/13 (46.2%) | -23.1 pp |
| `verifier_limit` | 4 | 1/4 (25.0%) | 2/4 (50.0%) | +25.0 pp |
| `env_mismatch` | 5 | 0/5 (0.0%) | 0/5 (0.0%) | +0.0 pp |

## Concrete Cases Where OBLIGE Helped

### `stackoverflow-70750259`

- Taxonomy: `lowering_artifact`
- Expected fix: `add unsigned clamp`
- Condition A predicted: `refactor or rewrite`
- Condition B predicted: `add unsigned clamp`
- Ground truth fix: Add an explicit non-negative/upper-bound clamp or rewrite the arithmetic in an unsigned form.
- B response summary: The verifier rejects the arithmetic on 'data' pointer with unbounded offset after OR operation. The fix is to clamp 'ext_len' to a bounded unsigned value before adding it to 'data' and 'i', preserving verifier proof.

### `stackoverflow-79485758`

- Taxonomy: `lowering_artifact`
- Expected fix: `add unsigned clamp`
- Condition A predicted: `add or tighten bounds check`
- Condition B predicted: `add unsigned clamp`
- Ground truth fix: The verifier complains on the packet access because the access seems to be out of the known packet bounds. The access is at offset 0, with a size of 2 bytes. The known packet length is 0 (r=0). Hence the program is rejected. You did check the packet bounds above, but it wasn't enough because of this corner-case limitation in the verifier: than pkt_end, but that's because it's also less than pkt.
- B response summary: The verifier loses track of the packet bounds proof because the offset calculation (field_offset) is done with arithmetic that the verifier cannot track precisely. To fix this, clamp field_offset to a verified range before using it for packet access, preserving the verifier's proof of safety.

### `stackoverflow-78753911`

- Taxonomy: `verifier_limit`
- Expected fix: `reduce branching/state fan-out`
- Condition A predicted: `refactor or rewrite`
- Condition B predicted: `reduce branching/state fan-out`
- Ground truth fix: Reduce branching/state fan-out, hoist common checks, or split the logic into simpler stages.
- B response summary: The verifier error is caused by excessive complexity due to a large loop with many jumps. The fix is to limit the loop iterations by adding a maximum iteration count to reduce branching complexity.

## Statistical Comparison

- Condition A fix-type accuracy: `10/30` (33.3%).
- Condition B fix-type accuracy: `10/30` (33.3%).
- McNemar exact test on paired fix-type correctness: `A-only=3`, `B-only=3`, `p=1.0000`.

## Raw Results

| Case | Taxonomy | Expected fix | Condition A fix | Condition B fix | A correct | B correct |
| --- | --- | --- | --- | --- | --- | --- |
| `stackoverflow-70750259` | `lowering_artifact` | `add unsigned clamp` | `refactor or rewrite` | `add unsigned clamp` | no | yes |
| `stackoverflow-73088287` | `lowering_artifact` | `reuse checked pointer` | `refactor or rewrite` | `add or tighten bounds check` | no | no |
| `stackoverflow-74178703` | `lowering_artifact` | `reuse checked pointer` | `refactor or rewrite` | `add or tighten bounds check` | no | no |
| `stackoverflow-75058008` | `lowering_artifact` | `add __always_inline` | `add null check` | `add null check` | no | no |
| `stackoverflow-76160985` | `lowering_artifact` | `add __always_inline` | `refactor or rewrite` | `add unsigned clamp` | no | no |
| `stackoverflow-79485758` | `lowering_artifact` | `add unsigned clamp` | `add or tighten bounds check` | `add unsigned clamp` | no | yes |
| `stackoverflow-79530762` | `lowering_artifact` | `reuse checked pointer` | `add or tighten bounds check` | `add or tighten bounds check` | no | no |
| `github-aya-rs-aya-1062` | `lowering_artifact` | `remove unwrap/panic` | `add unsigned clamp` | `add __always_inline` | no | no |
| `stackoverflow-61945212` | `source_bug` | `use the queue-map helper API` | `use the queue-map helper API` | `fix map declaration / 'SEC("maps")'` | yes | no |
| `stackoverflow-69767533` | `source_bug` | `initialize stack buffer` | `initialize stack buffer` | `initialize stack buffer` | yes | yes |
| `stackoverflow-70091221` | `source_bug` | `fix map declaration / 'SEC("maps")'` | `fix map declaration / 'SEC("maps")'` | `refactor or rewrite` | yes | no |
| `stackoverflow-70721661` | `source_bug` | `add or tighten bounds check` | `add or tighten bounds check` | `add or tighten bounds check` | yes | yes |
| `stackoverflow-70760516` | `source_bug` | `add or tighten bounds check` | `add or tighten bounds check` | `add or tighten bounds check` | yes | yes |
| `stackoverflow-70873332` | `source_bug` | `add or tighten bounds check` | `add or tighten bounds check` | `add or tighten bounds check` | yes | yes |
| `stackoverflow-74531552` | `source_bug` | `add or tighten bounds check` | `refactor or rewrite` | `refactor or rewrite` | no | no |
| `stackoverflow-75294010` | `source_bug` | `pass the value, not a pointer/unsupported type` | `refactor or rewrite` | `refactor or rewrite` | no | no |
| `stackoverflow-75643912` | `source_bug` | `add or tighten bounds check` | `add or tighten bounds check` | `add unsigned clamp` | yes | yes |
| `stackoverflow-76637174` | `source_bug` | `add or tighten bounds check` | `add or tighten bounds check` | `add or tighten bounds check` | yes | yes |
| `stackoverflow-77205912` | `source_bug` | `reuse checked pointer` | `avoid spill/reload proof loss` | `refactor or rewrite` | no | no |
| `stackoverflow-78958420` | `source_bug` | `initialize stack buffer` | `add or tighten bounds check` | `add or tighten bounds check` | no | no |
| `stackoverflow-79045875` | `source_bug` | `use a valid pointer/object` | `use a valid pointer/object` | `refactor or rewrite` | yes | no |
| `stackoverflow-56872436` | `verifier_limit` | `unroll or strengthen loop bound` | `unroll or strengthen loop bound` | `unroll or strengthen loop bound` | yes | yes |
| `stackoverflow-70841631` | `verifier_limit` | `reduce branching/state fan-out` | `add or tighten bounds check` | `add or tighten bounds check` | no | no |
| `stackoverflow-78753911` | `verifier_limit` | `reduce branching/state fan-out` | `refactor or rewrite` | `reduce branching/state fan-out` | no | yes |
| `kernel-selftest-async-stack-depth-pseudo-call-check` | `verifier_limit` | `reduce stack depth` | `refactor or rewrite` | `refactor or rewrite` | no | no |
| `stackoverflow-69413427` | `env_mismatch` | `regenerate or align BTF` | `fix map declaration / 'SEC("maps")'` | `refactor or rewrite` | no | no |
| `stackoverflow-76441958` | `env_mismatch` | `fix data alignment` | `add null check` | `refactor or rewrite` | no | no |
| `stackoverflow-78236201` | `env_mismatch` | `switch helper or program type` | `add or tighten bounds check` | `refactor or rewrite` | no | no |
| `github-aya-rs-aya-1233` | `env_mismatch` | `switch helper or program type` | `refactor or rewrite` | `refactor or rewrite` | no | no |
| `github-aya-rs-aya-864` | `env_mismatch` | `switch helper or program type` | `refactor or rewrite` | `refactor or rewrite` | no | no |
