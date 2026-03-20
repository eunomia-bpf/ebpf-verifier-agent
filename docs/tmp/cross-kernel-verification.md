# Cross-Kernel Verification: 5.10 QEMU vs 6.15 Host

Date: 2026-03-19

## Environment

- Host reference status came from the existing `so_gh_verified` and `eval_commits_verified` verification artifacts collected on kernel `6.15`.
- Guest retest environment: Debian 11 QEMU guest, kernel `5.10.0-39-amd64`.
- Guest access path: `ssh -p 2222 root@127.0.0.1`.
- Raw 5.10 logs for this run are under `.cache/qemu/debian-11-5.10/cross-kernel-results/`.

## Scope

- `so_gh_verified` lowering-artifact cases with an existing buggy `prog.o`: `13`
- Matching `fixed.o` in that bucket: `2`
- `eval_commits_verified` objects that had previously passed on `6.15`: `15`

## Executive Summary

- Confirmed `5.10 reject / 6.15 pass` lowering artifacts in the current `so_gh_verified` compiled-object set: `0/13`
- `so_gh_verified` buggy `prog.o` pass on both kernels: `4/13`
- `so_gh_verified` buggy `prog.o` reject on both kernels: `9/13`
- `so_gh_verified` fixed objects that pass on `5.10`: `0/2`
- `eval_commits_verified` objects that passed on `6.15` but failed on `5.10`: `6/15`

Main finding: the currently compiled `so_gh_verified` lowering-artifact `.o` files did not produce any clean `pass on 6.15, reject on 5.10` confirmation. The strongest version-sensitive signal instead came from the `eval_commits_verified` retest set, where a few objects that loaded on `6.15` failed on `5.10`, but several of those failures were due to older-kernel CO-RE or loader incompatibilities rather than the verifier rejecting the same object for the same reason.

## `so_gh_verified` Lowering-Artifact `prog.o` Results

### Pass on both `6.15` and `5.10`

| Case | 6.15 | 5.10 | 5.10 log note |
| --- | --- | --- | --- |
| `stackoverflow-53136145` | accepted | accepted | verifier completed, `processed 22 insns` |
| `stackoverflow-70729664` | accepted | accepted | verifier completed, `processed 23 insns` |
| `stackoverflow-77762365` | accepted | accepted | verifier completed, `processed 2 insns` |
| `stackoverflow-79530762` | accepted | accepted | verifier completed, `processed 1267 insns` |

### Reject on both `6.15` and `5.10`

| Case | 6.15 | 5.10 | 5.10 headline | Note |
| --- | --- | --- | --- | --- |
| `stackoverflow-70750259` | rejected | rejected | `value -2147483648 makes pkt pointer be out of bounds` | genuine 5.10 verifier rejection |
| `stackoverflow-70873332` | rejected | rejected | `invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0)` | genuine 5.10 verifier rejection |
| `stackoverflow-71522674` | rejected | rejected | `invalid access to packet, off=0 size=60, R3(id=0,off=0,r=20)` | genuine 5.10 verifier rejection |
| `stackoverflow-72074115` | rejected | rejected | `Error loading BTF: Invalid argument(22)` | older-kernel loader/BTF incompatibility before a useful verifier dump |
| `stackoverflow-72560675` | rejected | rejected | `invalid access to map value, value_size=2048 off=0 size=65535` | genuine 5.10 verifier rejection |
| `stackoverflow-73088287` | rejected | rejected | `failed to guess program type from ELF section 'WriteBuffer'` | loader/section-name incompatibility on 5.10 |
| `stackoverflow-76160985` | rejected | rejected | `load bpf program failed: Invalid argument` | rejected, but 5.10 did not emit a useful verifier line |
| `stackoverflow-76637174` | rejected | rejected | `invalid access to packet, off=0 size=1, R0(id=3,off=0,r=0)` | genuine 5.10 verifier rejection |
| `stackoverflow-79485758` | rejected | rejected | `invalid access to map value, value_size=100 off=100 size=2` | genuine 5.10 verifier rejection |

### Confirmed `5.10 reject / 6.15 pass`

None in this `so_gh_verified` compiled-object subset.

## `so_gh_verified` Fixed-Object Check

Only two lowering-artifact case directories currently contain a `fixed.o`:

| Case | 6.15 fixed status | 5.10 fixed status | 5.10 headline |
| --- | --- | --- | --- |
| `stackoverflow-70729664` | already rejected on `6.15` | not loadable | `object file doesn't contain any bpf program` |
| `stackoverflow-76637174` | already rejected on `6.15` | rejected | `The sequence of 8193 jumps is too complex.` |

So the available fixed objects do not add a `5.10 pass` confirmation for this bucket.

## `eval_commits_verified` Retest

I retried every `buggy.o` or `fixed.o` under `case_study/cases/eval_commits_verified/` whose corresponding `verification_status.txt` already recorded a `6.15` pass.

### Still pass on `5.10`

- `eval-bcc-118bf168f9f6`: buggy, fixed
- `eval-bcc-799acc7ca2c6`: buggy
- `eval-bcc-89c7f409b4a6`: fixed
- `eval-bcc-952415e490bd`: fixed
- `eval-bcc-a75f0180b714`: buggy, fixed
- `eval-bcc-f2006eaa5901`: buggy, fixed

### Passed on `6.15`, failed on `5.10`

| Case | Variant | 5.10 headline | Interpretation |
| --- | --- | --- | --- |
| `eval-bcc-89c7f409b4a6` | buggy | `math between map_value pointer and register with unbounded min value is not allowed` | genuine older-kernel verifier rejection |
| `eval-bcc-952415e490bd` | buggy | `relo #5/#9/#21/#25/#31: no matching targets found ... substituting insn ... invalid insn` | older-kernel CO-RE target-layout mismatch; fixed object still passes |
| `eval-bcc-d4e505c1e4ed` | buggy | `relo #3: no matching targets found ... substituting insn #17 w/ invalid insn` | older-kernel CO-RE target-layout mismatch |
| `eval-bcc-d4e505c1e4ed` | fixed | `relo #3: no matching targets found ... substituting insn #17 w/ invalid insn` | same older-kernel CO-RE target-layout mismatch |
| `stackoverflow-76160985` | buggy | `object file doesn't contain any bpf program` | object-format / section-layout issue, not a useful cross-kernel verifier comparison |
| `stackoverflow-76160985` | fixed | `object file doesn't contain any bpf program` | object-format / section-layout issue, not a useful cross-kernel verifier comparison |

`eval-bcc-89c7f409b4a6` is the cleanest example in this run of an object that loaded on `6.15` but was rejected by the `5.10` verifier for a proof-losing arithmetic pattern.

## Verifier Log Comparison

Representative `6.15 -> 5.10` differences from the retest:

- `stackoverflow-70750259`
  `6.15`: rejected
  `5.10`: rejected with the more explicit packet-pointer bound failure `value -2147483648 makes pkt pointer be out of bounds`
- `stackoverflow-70873332`
  `6.15`: rejected
  `5.10`: rejected with `invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0)`
- `stackoverflow-71522674`
  `6.15`: rejected
  `5.10`: rejected with `invalid access to packet, off=0 size=60, R3(id=0,off=0,r=20)`
- `stackoverflow-76637174` buggy
  `6.15`: rejected
  `5.10`: rejected with `invalid access to packet, off=0 size=1, R0(id=3,off=0,r=0)`
- `stackoverflow-76637174` fixed
  `6.15`: already rejected
  `5.10`: rejected differently, hitting `The sequence of 8193 jumps is too complex.`
- `eval-bcc-89c7f409b4a6` buggy
  `6.15`: passed
  `5.10`: rejected with `math between map_value pointer and register with unbounded min value is not allowed`
- `eval-bcc-952415e490bd` buggy
  `6.15`: passed
  `5.10`: failed earlier at CO-RE relocation time because the older kernel BTF did not match the expected targets

## Bottom Line

- For the currently materialized `so_gh_verified` lowering-artifact `.o` files, this `5.10` QEMU run did not confirm any clean `reject on 5.10, pass on 6.15` cases.
- The `so_gh_verified` subset split into `4` pass-on-both and `9` reject-on-both.
- Cross-kernel sensitivity does appear in `eval_commits_verified`, but part of that signal is older-kernel loader/CO-RE incompatibility rather than a pure verifier-only change.
