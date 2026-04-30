# Reconstruction Batch 26

## Summary

Reviewed 20 assigned Cilium commit raw records:

- 0 admitted as local replayable verifier-reject benchmark cases.
- 1 standalone reconstruction was attempted locally and accepted by the verifier, so it was not admitted.
- 19 records were classified without case creation because the raw records lack captured verifier logs and the diffs either depend on full Cilium generated datapath / historical kernel or compiler behavior, or are not verifier-reject candidates.

No `bpfix-bench/cases/<assigned-raw-id>/` directories were created.

## Successful Replays

None.

## Record Results

| raw_id | Case | Classification | Notes |
| --- | --- | --- | --- |
| `github-commit-cilium-1e0778b33d67` | no case | `environment_required` | Complexity-test `EVENTS_MAP_RATE_LIMIT` config override change. The raw record has no verifier log or concrete rejected program; faithful replay would require the generated Cilium complexity-test datapath and its load-time configuration. |
| `github-commit-cilium-1e25adb69b44` | no case | `attempted_accepted` | Tested a standalone tc reconstruction of the historical `skb->cb[0]` write followed by packet revalidation. Local verifier accepted it, and the parsed fresh log had no terminal error. |
| `github-commit-cilium-1eb1c18fdf76` | no case | `environment_required` | Removes source MAC validation from older full LXC IPv4/IPv6 paths to reduce verifier complexity. No terminal verifier log or isolated rejected operation is present; replay depends on the historical generated datapath. |
| `github-commit-cilium-1f3025b4ea56` | no case | `out_of_scope_non_verifier` | BPF unit-test macro fix changes a mocked tail-call argument from `b` to `NULL`; it is test harness correctness, not a verifier-rejected program. |
| `github-commit-cilium-210b5866e0f5` | no case | `environment_required` | Netkit runtime-check/loadtime-check refactor spans policy tail calls and local-delivery paths. No verifier log is captured, and the behavior depends on Cilium load-time feature selection. |
| `github-commit-cilium-220c397a6a0b` | no case | `out_of_scope_non_verifier` | Limits an L3 local-delivery kube-proxy workaround to overlay mode; this is datapath behavior/feature gating with no captured verifier rejection. |
| `github-commit-cilium-227ed483633c` | no case | `environment_required` | Introduces SRv6 tail-call structure across host, LXC, overlay, XDP, and egress policy code. Reproduction requires full Cilium build/tail-call environment and no standalone verifier log is available. |
| `github-commit-cilium-22af6b5c8c09` | no case | `out_of_scope_non_verifier` | Fixes IPv4 source address validation semantics (`saddr` comparison/byte order), not verifier load rejection. The raw record has no terminal verifier log. |
| `github-commit-cilium-2320674d4101` | no case | `out_of_scope_non_verifier` | Adds `bpf/verifier-test.sh` to ginkgo and changes feature defines; this is test integration/helper feature gating, not a concrete verifier-rejected program. |
| `github-commit-cilium-239711b71174` | no case | `environment_required` | Replaces direct builtin `memcmp` use with Cilium's custom small-size implementation for compiler/verifier compatibility. Faithful replay depends on historical clang code generation and Cilium builtins context. |
| `github-commit-cilium-275856b1650f` | no case | `environment_required` | Adds macros for loading IPv6 nodeport/direct-routing constants to shape verifier-visible state. No captured rejection exists, and replay depends on the full nodeport datapath and compile-time config. |
| `github-commit-cilium-27eda2c934dd` | no case | `environment_required` | Changes `relax_verifier()` gating from `NEEDS_RELAX_VERIFIER` to `HAVE_LARGE_INSN_LIMIT`; the issue is historical complexity pruning in generated programs, not an isolated current-kernel reject. |
| `github-commit-cilium-28dfbaaeaeaf` | no case | `environment_required` | Moves IPv4 fragmentation/L4 port extraction into `lb4_extract_tuple()`. The raw record lacks a verifier log and requires the surrounding LB/fragmentation datapath for a faithful replay. |
| `github-commit-cilium-291b9ef0ba68` | no case | `out_of_scope_non_verifier` | Fixes a test macro name from `ETH_LEN` to `ETH_HLEN` in WireGuard helper tests; this is test source correctness, not a verifier-reject case. |
| `github-commit-cilium-2a0bc762c095` | no case | `out_of_scope_non_verifier` | Fixes the ifindex used in TO_OVERLAY trace notification. The changed code is tracing metadata behavior with no verifier log or rejected source. |
| `github-commit-cilium-2a1db392b3ca` | no case | `out_of_scope_non_verifier` | Fixes mark/magic handling before retrieving cluster ID from `skb->mark`; this is datapath semantics rather than verifier rejection. |
| `github-commit-cilium-2a6780cf8afb` | no case | `environment_required` | IPv6 tunneling checksum workaround touches policy, LB, nodeport, and nodeport egress paths. No verifier log is present; a faithful replay would require the full Cilium datapath and checksum/tunnel configuration. |
| `github-commit-cilium-2b27408ef937` | no case | `out_of_scope_non_verifier` | Fixes user-space ELF map migration logic for newer LLVM symbol types; the failure is a Cilium userspace panic/map metadata issue, not a BPF verifier rejection. |
| `github-commit-cilium-2b9eac22f8c8` | no case | `environment_required` | Enables monitor aggregation in complexity-test node configuration. No verifier log or concrete rejected BPF program is available outside the generated complexity-test environment. |
| `github-commit-cilium-2ba0b4fd4bff` | no case | `environment_required` | BPF_PROG_TEST_RUN framework/map definition changes depend on Cilium's libbpf/BTF map-loading environment; no verifier-rejected program or terminal verifier log is captured. |

## Commands Run

- Confirmed assigned raw files exist:
  - `for id in ...; do test -f bpfix-bench/raw/gh/$id.yaml ...; done`
- Inspected existing case/replay format:
  - `sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/{Makefile,case.yaml,capture.yaml,prog.c}`
  - `sed -n '1,240p' tools/replay_case.py`
- Inspected assigned raw record content:
  - `sed -n '1,220p' bpfix-bench/raw/gh/<id>.yaml`
  - `rg -n "title:|commit_message:|commit_date:|fix_type:|has_verifier_log:|source_snippet_count:|diff_summary:|// FILE:|verifier|invalid|too large|processed|panic|test|complexity" bpfix-bench/raw/gh/<id>.yaml`
- Checked that none of the assigned case directories already existed:
  - `for id in ...; do test -d bpfix-bench/cases/$id && echo CASE_EXISTS $id || true; done`
- Attempted standalone replay for `github-commit-cilium-1e25adb69b44` in `/tmp/batch26-1e25`:
  - `make -C /tmp/batch26-1e25 clean`
  - `make -C /tmp/batch26-1e25`
  - `make -C /tmp/batch26-1e25 replay-verify`
- Parsed the attempted fresh verifier log:
  - `python3 - <<'PY' ... parse_verifier_log(Path('/tmp/batch26-1e25/replay-verifier.log').read_text(...)) ... PY`

## Parsed Verifier Outcomes

| Raw ID | Command | Build | Load | Parser outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-1e25adb69b44` | `/tmp` standalone `make clean && make && make replay-verify` | success | accepted (`make replay-verify` returned 0) | `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=11` |

No admitted case produced a fresh verifier-reject log, so no `trace_rich` parsed verifier outcome with both `terminal_error` and `rejected_insn_idx` was available for this batch.

## Review

- Verified Record Results has exactly the 20 assigned Batch 26 raw IDs from the Cilium raw-index slice, once each:
  - `python3 - <<'PY' ... parse_batch_report(Path('docs/tmp/reconstruction-batch-26.md')) ... PY`
  - Result: `row_count 20`, `unique_count 20`, `duplicates []`, `missing_from_table []`, `unexpected_in_table []`.
- Confirmed no assigned `bpfix-bench/cases/<raw_id>/` directories were created:
  - `find bpfix-bench/cases -maxdepth 1 -type d \( -name 'github-commit-cilium-1e0778b33d67' -o ... -name 'github-commit-cilium-2ba0b4fd4bff' \) -print`
  - Result: no output.
- Confirmed all non-admitted classifications are canonical statuses accepted by `tools/integrate_reconstruction_batch.py`:
  - `python3 - <<'PY' ... from tools.integrate_reconstruction_batch import parse_batch_report, NON_REPLAY_STATUSES, ALLOWED_STATUSES ... PY`
  - Result: all 20 classifications are in `ALLOWED_STATUSES` and `NON_REPLAY_STATUSES`.
- Ran integration dry run:
  - `python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-26.md --bench-root bpfix-bench`
  - Result: `errors: []`.

No blockers. Safe to integrate.
