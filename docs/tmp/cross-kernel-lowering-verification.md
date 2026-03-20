# Cross-Kernel Lowering Verification

Date: 2026-03-19

## Environment

- Host kernel: `6.15.11-061511-generic`
- Guest kernel: `5.10.0-39-amd64`
- Guest access check: `ssh -i .cache/qemu/debian-11-5.10/id_ed25519 -p 2222 root@127.0.0.1 uname -r`
- Raw logs for this run: `.cache/qemu/debian-11-5.10/cross-kernel-lowering-results/`

## Method

For each selected `case_study/cases/so_gh_verified/<case>/prog.o`:

1. On the host, run `sudo bpftool prog load <obj> /sys/fs/bpf/test 2>&1`, then `sudo rm -f /sys/fs/bpf/test`.
2. `scp` the object to the guest as `/tmp/prog.o`.
3. In the guest, run `sudo bpftool prog load /tmp/prog.o /sys/fs/bpf/test 2>&1`, then `sudo rm -f /sys/fs/bpf/test`.
4. Keep the full stdout/stderr log for both kernels.

## Executive Summary

- Current direct host retest does not reproduce a `6.15 pass` result for all seven suspected lowering-artifact cases.
- Among compiled `lowering_artifact` `prog.o` files currently present in `so_gh_verified`, only these four pass a direct `bpftool prog load` on `6.15`: `stackoverflow-72074115`, `stackoverflow-73088287`, `stackoverflow-76160985`, `stackoverflow-79530762`.
- All four of those also pass on `5.10`.
- Confirmed cross-kernel lowering artifacts in the current workspace: `0`.
- One non-lowering accepted case, `stackoverflow-76960866`, passes on `6.15` but fails on `5.10` due to an older-kernel libbpf/object-format issue (`bad map relo against '.rodata.str1.1'`), not a lowering-artifact verifier rejection.

## Targeted Lowering-Artifact Cases

These are the seven lowering-artifact cases I checked from the user-suspect set plus the archived `verification_status.txt` accepted/pass set.

| Case | Why included | Archived `verifier_status` | Current 6.15 direct load | 5.10 direct load | 5.10 note |
| --- | --- | --- | --- | --- | --- |
| `stackoverflow-53136145` | user-suspect | `rejected` | rejected | rejected | `R5 invalid mem access 'inv'` |
| `stackoverflow-70729664` | user-suspect | `rejected` | rejected | rejected | `invalid access to packet, off=26 size=1, R2(id=4,off=26,r=0)` |
| `stackoverflow-72074115` | archived `accepted` | `accepted` | accepted | accepted | accepted |
| `stackoverflow-73088287` | archived `accepted` | `accepted` | accepted | accepted | accepted |
| `stackoverflow-76160985` | archived `accepted` | `accepted` | accepted | accepted | accepted |
| `stackoverflow-77762365` | user-suspect | `rejected` | rejected | rejected | `invalid access to map value, value_size=4108 off=4107 size=4095` |
| `stackoverflow-79530762` | user-suspect + archived `accepted` | `accepted` | accepted | accepted | accepted |

### Result

No case in this seven-case lowering-artifact target set is a confirmed `6.15 pass / 5.10 reject` lowering artifact.

## Remaining Compiled Lowering-Artifact `prog.o` Cases

To avoid missing a current host-pass case, I also swept the rest of the compiled `lowering_artifact` objects present under `so_gh_verified`.

| Case | Archived `verifier_status` | Current 6.15 direct load | 5.10 direct load | 5.10 note |
| --- | --- | --- | --- | --- |
| `stackoverflow-70750259` | `rejected` | rejected | rejected | `value -2147483648 makes pkt pointer be out of bounds` |
| `stackoverflow-70873332` | `rejected` | rejected | rejected | `invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0)` |
| `stackoverflow-71522674` | `rejected` | rejected | rejected | `invalid access to packet, off=14 size=60, R3(id=0,off=14,r=34)` |
| `stackoverflow-72560675` | `rejected` | rejected | rejected | `invalid access to map value, value_size=2048 off=0 size=65535` |
| `stackoverflow-76637174` | `rejected` | rejected | rejected | `invalid access to packet, off=0 size=1, R0(id=3,off=0,r=0)` |
| `stackoverflow-79485758` | `rejected` | rejected | rejected | `invalid access to packet, off=0 size=2, R5(id=6243,off=0,r=0)` |

### Full Lowering-Artifact Bucket Summary

- Compiled lowering-artifact `prog.o` present: `13`
- Current `6.15` direct-load pass: `4/13`
- Current `5.10` direct-load pass among those same 13: `4/13`
- Current confirmed `6.15 pass / 5.10 reject` lowering artifacts: `0/13`

## Extra `so_gh_verified` Cases With Archived `accepted`/`pass`

Per request, I also checked the other `so_gh_verified` cases whose `verification_status.txt` recorded `accepted`.

| Case | Taxonomy | Archived `verifier_status` | Current 6.15 direct load | 5.10 direct load | 5.10 note |
| --- | --- | --- | --- | --- | --- |
| `stackoverflow-69767533` | `source_bug` | `accepted` | accepted | accepted | accepted |
| `stackoverflow-72606055` | `env_mismatch` | `accepted` | accepted | accepted | accepted |
| `stackoverflow-76960866` | `source_bug` | `accepted` | accepted | rejected | `bad map relo against '.rodata.str1.1'` |
| `stackoverflow-77673256` | `env_mismatch` | `accepted` | accepted | accepted | accepted, with `libbpf: elf: skipping unrecognized data section(4) .rodata.str1.1` warning |
| `stackoverflow-78236201` | `source_bug` | `accepted` | accepted | accepted | accepted |

## Notes On The Mismatch

- The requested “7 lowering-artifact cases that pass on 6.15” does not match the current workspace when using a direct `bpftool prog load` on the on-disk `prog.o` files.
- In particular, `stackoverflow-53136145`, `stackoverflow-70729664`, and `stackoverflow-77762365` are currently rejected on both kernels even though earlier notes in the repo treated them as host-pass compiled objects.
- `stackoverflow-69767533` is not labeled `lowering_artifact` in `case_study/ground_truth.yaml`; it is currently labeled `source_bug`.

## Bottom Line

There is no confirmed cross-kernel lowering artifact in the current `so_gh_verified` compiled-object set. The present direct-load results show four lowering-artifact `prog.o` files that pass on both `6.15` and `5.10`, and nine that reject on both kernels. The only observed `6.15 pass / 5.10 reject` difference in this run is `stackoverflow-76960866`, and that one is a non-lowering object-format/libbpf compatibility failure rather than a clean verifier-only lowering artifact.
