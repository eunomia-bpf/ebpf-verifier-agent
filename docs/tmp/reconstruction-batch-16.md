# Reconstruction Batch 16

Date: 2026-04-30

Scope:

- Assigned Batch 16 raw records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- Successful case directories created:
  - `bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/`
  - `bpfix-bench/cases/github-commit-cilium-caf84595d9cb/`
  - `bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/`

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 3
- Not admitted: 17

The successful cases were admitted only after local `make clean`, `make`, and
`make replay-verify` produced fresh verifier reject logs that parse as
`trace_rich`. The parsed terminal error, rejected instruction index, and log
quality match each `case.yaml`.

## Successful Replays

### `github-commit-cilium-c3b65fce8b84`

Files:

- `bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/Makefile`
- `bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/prog.c`
- `bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/capture.yaml`

Verifier outcome:

- terminal error: `R3 !read_ok`
- rejected instruction index: `12`
- parser check: `trace_rich`

Reconstruction basis: the commit describes an XDP inline-assembly output
register that is initialized only on the fall-through path. The standalone
program preserves that join and shared spill, reproducing the uninitialized
register read that the upstream offset-masking change avoids.

### `github-commit-cilium-caf84595d9cb`

Files:

- `bpfix-bench/cases/github-commit-cilium-caf84595d9cb/Makefile`
- `bpfix-bench/cases/github-commit-cilium-caf84595d9cb/prog.c`
- `bpfix-bench/cases/github-commit-cilium-caf84595d9cb/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-caf84595d9cb/capture.yaml`

Verifier outcome:

- terminal error: `Caller passes invalid args into func#1 ('mock_fib_lookup')`
- rejected instruction index: `26`
- parser check: `trace_rich`

Reconstruction basis: the commit says clang 18 optimized out passing an unused
ctx argument to `mock_fib_lookup`, causing BTF argument validation to reject the
call. The standalone case keeps arg0 clobbered before the global subprogram
call, so the verifier sees a stack pointer where it expects ctx.

### `github-commit-cilium-ceaa4c42b010`

Files:

- `bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/Makefile`
- `bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/prog.c`
- `bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/case.yaml`
- `bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/capture.yaml`

Verifier outcome:

- terminal error: `invalid access to packet, off=8 size=4, R1(id=1,off=8,r=0)`
- rejected instruction index: `10`
- parser check: `trace_rich`

Reconstruction basis: the commit reports an IPv6 packet-builder auth-header
write beyond the verifier-proven packet range. The standalone case checks only
a short prefix, then writes a later 32-bit field, reproducing the packet access
class fixed by adding direct bounds checks.

## Record Results

| raw_id | result | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-c36986184bff` | no case | `environment_required` | Reduces full `bpf_host` verifier complexity for kernel 4.19 using `relax_verifier()` checkpoints; faithful replay depends on the historical generated Cilium datapath and old verifier behavior. |
| `github-commit-cilium-c3b65fce8b84` | case created | `replay_valid` | Reconstructed the inline-assembly uninitialized output-register spill; fresh local replay rejects with `R3 !read_ok` and parses as `trace_rich`. |
| `github-commit-cilium-c46c0ed0e7d0` | no case | `out_of_scope_non_verifier` | Stores NodePort client MAC addresses in LRU maps to avoid runtime FIB/ARP lookup misses; no verifier-load failure is present. |
| `github-commit-cilium-c525c7555fc6` | no case | `out_of_scope_non_verifier` | Changes policy enforcement behavior for source endpoints; the diff is datapath semantics, not a verifier rejection. |
| `github-commit-cilium-c5836de699b1` | no case | `environment_required` | Moves packet capture behind an ELF templating knob so verifier dead-code elimination removes unused capture paths; replay depends on full Cilium templating and generated program shape. |
| `github-commit-cilium-c69d8cb801e5` | no case | `environment_required` | Removes an older-kernel NAT temporary-stack workaround after the minimum kernel bump; no standalone terminal reject is isolated from the diff. |
| `github-commit-cilium-c6fe6b8e2546` | no case | `out_of_scope_non_verifier` | Fixes a conntrack test assertion timeout expectation for a clang update; this is test logic, not a kernel verifier load failure. |
| `github-commit-cilium-c7083543e993` | no case | `environment_required` | Deduplicates Cilium host-firewall conntrack lookups and adjusts error checks because the full program could confuse the verifier; no isolated current-kernel terminal log is available. |
| `github-commit-cilium-c85648b24a08` | no case | `environment_required` | Replaces hash recalculation with `get_prandom_u32()` to reduce load-balancer instruction complexity on older/full datapath builds. |
| `github-commit-cilium-c85b4c4c834c` | no case | `out_of_scope_non_verifier` | Defines `EGRESS_MAP` in a dummy config for verifier-test/K8sVerifier build configuration; no rejected instruction or verifier terminal message is present. |
| `github-commit-cilium-c862a7157bb0` | no case | `environment_required` | Bumps SNAT collision retries after IPv4/IPv6 tail-call splitting; replaying the prior limit depends on historical full Cilium complexity constraints. |
| `github-commit-cilium-ca6e1cba7262` | no case | `environment_required` | Adds `relax_verifier()` checkpoints in conntrack code to avoid older-kernel complexity limits; no standalone verifier operation is isolated. |
| `github-commit-cilium-caf0bb657e50` | no case | `environment_required` | Removes a test macro and excludes a coverage object to avoid Cilium coverage-test "potential missed tailcall" failures; reproducing it requires that coverage/test harness. |
| `github-commit-cilium-caf84595d9cb` | case created | `replay_valid` | Reconstructed the clang 18 unused-ctx-argument failure; fresh local replay rejects with the BTF subprogram argument error and parses as `trace_rich`. |
| `github-commit-cilium-ccadfc77a635` | no case | `out_of_scope_non_verifier` | Increases `lxc_config.h` verifier-test complexity so CI is more likely to catch future complexity issues; it is not itself a verifier-reject fix. |
| `github-commit-cilium-ccf7965e28a7` | no case | `environment_required` | Reuses IPv6 NAT tuples for conntrack lookup to reduce full-program complexity and prepare a later functional fix; no terminal reject is isolated. |
| `github-commit-cilium-cd5cdc35b9cd` | no case | `out_of_scope_non_verifier` | Removes a DNS monitor-aggregation quirk; the change is observability behavior, not verifier admission. |
| `github-commit-cilium-cdd6694c94ac` | no case | `out_of_scope_non_verifier` | Changes encrypted-packet trace notification aggregation and includes a clang workaround note, but the patch target is runtime trace behavior rather than a verifier reject. |
| `github-commit-cilium-ce6f2c7729df` | no case | `out_of_scope_non_verifier` | Adds compiler warnings and explicit casts to forbid implicit int conversions; this is compile-time hygiene, not a verifier replay. |
| `github-commit-cilium-ceaa4c42b010` | case created | `replay_valid` | Reconstructed the IPv6 packet-builder missing-bounds-check failure; fresh local replay rejects with a packet access error and parses as `trace_rich`. |

## Verification Commands

Successful cases:

```bash
cd bpfix-bench/cases/github-commit-cilium-c3b65fce8b84
make clean
make
make replay-verify

cd bpfix-bench/cases/github-commit-cilium-caf84595d9cb
make clean
make
make replay-verify

cd bpfix-bench/cases/github-commit-cilium-ceaa4c42b010
make clean
make
make replay-verify
```

Parser comparison:

```bash
python3 - <<'PY'
# Parsed each fresh replay-verifier.log with tools.replay_case.parse_verifier_log
# and compared terminal_error, rejected_insn_idx, and log_quality to case.yaml.
PY
```

Parsed replay results:

```text
github-commit-cilium-c3b65fce8b84: terminal="R3 !read_ok" rejected_insn_idx=12 quality=trace_rich
github-commit-cilium-caf84595d9cb: terminal="Caller passes invalid args into func#1 ('mock_fib_lookup')" rejected_insn_idx=26 quality=trace_rich
github-commit-cilium-ceaa4c42b010: terminal="invalid access to packet, off=8 size=4, R1(id=1,off=8,r=0)" rejected_insn_idx=10 quality=trace_rich
```

## Review

- Fresh review pass run on 2026-04-30:
  - `make -C bpfix-bench/cases/github-commit-cilium-c3b65fce8b84 clean`
  - `make -C bpfix-bench/cases/github-commit-cilium-c3b65fce8b84`
  - `make -C bpfix-bench/cases/github-commit-cilium-c3b65fce8b84 replay-verify`
  - `make -C bpfix-bench/cases/github-commit-cilium-caf84595d9cb clean`
  - `make -C bpfix-bench/cases/github-commit-cilium-caf84595d9cb`
  - `make -C bpfix-bench/cases/github-commit-cilium-caf84595d9cb replay-verify`
  - `make -C bpfix-bench/cases/github-commit-cilium-ceaa4c42b010 clean`
  - `make -C bpfix-bench/cases/github-commit-cilium-ceaa4c42b010`
  - `make -C bpfix-bench/cases/github-commit-cilium-ceaa4c42b010 replay-verify`
  - parsed each fresh `replay-verifier.log` with
    `tools.replay_case.parse_verifier_log` and compared it to `case.yaml`.
- All three builds succeeded. Each `replay-verify` command exited nonzero
  because `bpftool` rejected the load and produced the expected verifier log.
- `case.yaml` and `capture.yaml` use capture IDs ending in
  `__kernel-6.15.11-clang-18-log2`.
- `source.kind` is `github_commit`.
- `reproducer.reconstruction` is `reconstructed`.
- `external_match.status` is `not_applicable`.
- Fresh parser output matches `case.yaml` for terminal error, rejected
  instruction index, and log quality on all three admitted cases.
- The record-results table covers all 20 assigned raw IDs, all 20 local raw
  records exist, and every non-admitted raw has a concrete final
  classification.
