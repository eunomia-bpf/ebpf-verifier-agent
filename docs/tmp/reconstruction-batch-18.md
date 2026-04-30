# Reconstruction Batch 18

Date: 2026-04-30

Scope:

- Assigned Batch 18 records only.
- Shared benchmark files, raw YAML records, `raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- No successful case directory was created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Missing local raw records: 0
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

All assigned raw records are Cilium commit-derived records without captured
verifier logs. The promising verifier-adjacent records were probed locally, but
none produced an admissible root-cause-matched replay on
`kernel-6.15.11-clang-18-log2`.

## Attempted Not Admitted

- `github-commit-cilium-e38a92115620`: a tc probe modeled the proxy hairpin
  pattern of validating packet data, writing `ctx->cb[0]`, then reading packet
  data. On the pinned 6.15 kernel the program was accepted, so no verifier-reject
  case was admitted.
- `github-commit-cilium-e607d0c161dc`: an exact-shape `cgroup/connect4` probe
  calling `bpf_get_netns_cookie(ctx)` was accepted on the pinned kernel. This is
  expected for the raw fix, which only guards the helper for pre-5.8 kernels.
- `github-commit-cilium-e80be9ebffd4`: a 129-byte `__builtin_memcmp()` probe
  built and loaded successfully. The raw scapy/builtin issue did not yield a
  current-kernel verifier rejection from the standalone shape.
- `github-commit-cilium-e62eb70cf03d`: a generic tail-call-split alternative
  probe can reject locally with `combined stack size of 3 calls is 576. Too
  large`, but that is a combined-stack reproducer, not the raw commit's
  historical full-Cilium datapath complexity failure. It was not admitted.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-dfa8bb8ab3f0` | no case | `out_of_scope_non_verifier` | Narrows external-IP service translation based on netns-cookie availability; the snippets describe datapath behavior gating, not a verifier-load failure. |
| `github-commit-cilium-e2760e62db78` | no case | `out_of_scope_non_verifier` | Changes egress-gateway FIB handling for `BPF_FIB_LKUP_RET_NO_NEIGH` when no neighbor resolver exists; this is runtime forwarding behavior with no terminal verifier error. |
| `github-commit-cilium-e30c54909554` | no case | `environment_required` | Reorders hairpin handling before remote-endpoint lookup to reduce/avoid full datapath work; a faithful verifier failure depends on generated Cilium LXC policy paths and no standalone log is present. |
| `github-commit-cilium-e325ed469bf6` | no case | `out_of_scope_non_verifier` | Remaps `MARK_MAGIC_SNAT_DONE` to avoid mark-bit conflicts; no verifier rejection is implicated by the diff. |
| `github-commit-cilium-e336073818b6` | no case | `environment_required` | Adjusts generated Cilium builtin `memcmp()` test sizes/runs; any verifier pressure is tied to the generated test harness and no terminal verifier log anchors a standalone case. |
| `github-commit-cilium-e38a92115620` | no case | `attempted_accepted` | Local tc proxy-hairpin-style probe was accepted on kernel 6.15; the raw record targets an old verifier workaround with no captured reject log. |
| `github-commit-cilium-e4316b9d044e` | no case | `out_of_scope_non_verifier` | Removes an obsolete `barrier_data(ctx)` workaround for Clang 10; this is cleanup of a compiler workaround, not a current verifier-reject reproducer. |
| `github-commit-cilium-e43c2fff3749` | no case | `out_of_scope_non_verifier` | Fixes a pointer-to-int cast warning in the `__fetch` macro by casting through `__u64`; the raw failure is a compiler diagnostic, not verifier rejection. |
| `github-commit-cilium-e44296eda6e8` | no case | `out_of_scope_non_verifier` | Adds a missing test interface MAC assignment for IPv6 ND tests; this is test setup/runtime behavior, not a verifier-load failure. |
| `github-commit-cilium-e4c1ec7f9123` | no case | `out_of_scope_non_verifier` | Adds DSR remote NodePort RevNAT support and propagates NAT address/port state; the commit is feature work with no verifier terminal error. |
| `github-commit-cilium-e5279874229c` | no case | `out_of_scope_non_verifier` | Resets queue mapping on pod egress to fix physical device queue selection; this is packet scheduling behavior, not verifier rejection. |
| `github-commit-cilium-e5df587754e0` | no case | `environment_required` | Splits SNAT skip predicates for NAT and RevNAT paths; any verifier benefit is tied to Cilium's full NAT/NodePort datapath and no isolated failing operation is present. |
| `github-commit-cilium-e607d0c161dc` | no case | `attempted_accepted` | Standalone `bpf_get_netns_cookie()` sock_addr probe accepted locally; reproducing the raw failure requires a pre-5.8 kernel where the helper is unavailable. |
| `github-commit-cilium-e62eb70cf03d` | no case | `environment_required` | Adds tail calls for IPv4-only/IPv6-only setups to control generated datapath complexity; a generic stack-limit reject was not admitted because it does not match the raw complexity failure. |
| `github-commit-cilium-e80be9ebffd4` | no case | `attempted_accepted` | Standalone 129-byte `__builtin_memcmp()` probe accepted locally; the raw scapy builtin-limit issue lacks a verifier log and did not reproduce on the pinned toolchain/kernel. |
| `github-commit-cilium-e83e21a9c7af` | no case | `out_of_scope_non_verifier` | Adds/adjusts complexity-test configuration for `bpf_network`; the raw snippet is test configuration, not a verifier-rejecting program. |
| `github-commit-cilium-e847d0184902` | no case | `environment_required` | Introduces config-dependent tail-call emission in the LXC fast path to manage full-program complexity; faithful replay requires historical Cilium program generation. |
| `github-commit-cilium-e9438c20e7d1` | no case | `out_of_scope_non_verifier` | Changes loader/program-map management so policy programs are explicit entry programs; this is loader/attachment organization, not a standalone verifier failure. |
| `github-commit-cilium-e96c42ce4c73` | no case | `environment_required` | Adds `relax_verifier()` in conntrack/debug slow paths; any failure is old full-datapath verifier complexity without a captured standalone terminal log. |
| `github-commit-cilium-e9bf184e3ddc` | no case | `environment_required` | The commit explicitly targets complexity on kernels `<5.3`; replay depends on historical verifier limits and the full Cilium conntrack/LXC datapath. |

## Commands Run

Context and raw inspection:

```bash
git status --short
sed -n '1,260p' bpfix-bench/raw/gh/<assigned-id>.yaml
python3 - <<'PY'
# Loaded assigned raw YAML and summarized title, date, fix_type, files,
# verifier-log presence, and diff summary.
PY
```

Local probe attempts:

```bash
# github-commit-cilium-e38a92115620
make -C /tmp/bpfix-b18-probes/e38a clean
make -C /tmp/bpfix-b18-probes/e38a
make -C /tmp/bpfix-b18-probes/e38a replay-verify

# github-commit-cilium-e607d0c161dc
make -C /tmp/bpfix-b18-probes/e607 clean
make -C /tmp/bpfix-b18-probes/e607
make -C /tmp/bpfix-b18-probes/e607 replay-verify

# github-commit-cilium-e80be9ebffd4
make -C /tmp/bpfix-b18-probes/e80 clean
make -C /tmp/bpfix-b18-probes/e80
make -C /tmp/bpfix-b18-probes/e80 replay-verify

# github-commit-cilium-e62eb70cf03d generic non-admitted probe
make -C /tmp/bpfix-b18-probes/e62 clean
make -C /tmp/bpfix-b18-probes/e62
make -C /tmp/bpfix-b18-probes/e62 replay-verify
```

No `bpfix-bench/cases/<assigned raw id>/` directory was created because no
candidate satisfied the admission rule with a root-cause-matched fresh
`trace_rich` verifier rejection.

## Review

- Parsed the Record Results table: 20 rows and 20 unique assigned raw IDs, with
  no duplicate table entries.
- Cross-checked the assigned IDs against `bpfix-bench/raw/index.yaml` and local
  `bpfix-bench/raw/gh/*.yaml` records; all 20 assigned raw records are present.
- Checked `bpfix-bench/cases/` for each assigned raw ID; no matching case
  directory exists.
- Sanity-checked the non-admitted results: every row has `outcome` = `no case`,
  a concrete final classification, and a specific reason tied to the raw
  commit/diff, local accepted probe, missing verifier log, or environment-bound
  full-Cilium replay requirement. No rationale gaps found.
