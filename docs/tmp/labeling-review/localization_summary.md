# Localization Summary

- Cases analyzed: `139`
- Cases with BTF annotations: `114/139` (82.0%)
- Cases with `root_cause_insn_idx != rejected_insn_idx`: `20/139` (14.4%)
- Cases with strictly earlier root-cause instruction index: `18/139` (12.9%)
- Cases whose causal root has a higher numeric insn index due to loop/back-edge structure: `2`

## Distance Distribution

| `distance_insns` bucket | Count |
| --- | ---: |
| `0` | `119` |
| `1` | `1` |
| `2-5` | `5` |
| `6-20` | `13` |
| `>20` | `1` |

## Interesting Patterns

- **Pointer-merge / checked-vs-dereferenced split**: `stackoverflow-53136145` and `stackoverflow-79530762` both reject at the final dereference, but the earlier root is where the verifier-visible pointer path diverges from the checked one.
- **Loop-latch / cursor-evolution losses**: `stackoverflow-70760516`, `stackoverflow-74178703`, and `stackoverflow-76637174` lose the proof on loop cursor or latch instructions rather than at the final memory access.
- **Cross-function proof loss**: `stackoverflow-76160985` localizes to the callee entry, because the caller's fixed-size buffer proof is not visible inside the separately verified subprogram.
- **Reference-lifetime bugs**: `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` and `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` reject at `exit`, but the root cause is the earlier acquire/ref-return site.
- **Verifier-limit cases**: `github-cilium-cilium-41412` and the async stack-depth cases do not expose an earlier semantic bug in the trace; the last visible instruction is only the point where the verifier gives up.

## Example Cases

| Case | Rejected | Root Cause | Distance | Note |
| --- | ---: | ---: | ---: | --- |
| `github-cilium-cilium-41412` | `1738` | `1738` | `0` | The log reports a verifier budget/complexity limit at the last visible traced instruction rather than at an earlier semantic bug site. |
| `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` | `80` | `67` | `13` | The original crypto context returned by `bpf_crypto_ctx_create()` is never released; the later acquire/release only balances a secondary reference. |
| `stackoverflow-53136145` | `109` | `105` | `4` | The merged UDP pointer is checked through a derived alias (`r4`) but the dereference still uses the original merged pointer (`r0`), so verifier provenance is lost before the final load. |
| `stackoverflow-70729664` | `2948` | `2940` | `8` | Packet-range/provenance collapses at the loop-side packet check before the later byte load at insn 2948. |
| `stackoverflow-70760516` | `14` | `31` | `17` | The running extension cursor loses packet-range precision at the loop latch; its instruction number is later because it is the back-edge for the next iteration. |
| `stackoverflow-76160985` | `195` | `189` | `6` | This is a cross-function proof-loss case: the callee `find_substring` begins without the caller's fixed-size buffer fact, so the function entry is the best visible root in the log. |
