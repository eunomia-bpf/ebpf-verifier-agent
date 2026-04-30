# Reconstruction Batch 34

Date: 2026-04-30

Scope:

- Assigned Batch 34 raw records only.
- Edited this report and `bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any raw YAML file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Raw records with captured verifier logs: 0
- Successful standalone verifier-reject reconstructions: 1
- Not admitted: 19

`github-commit-cilium-b4a0fa7425c7` was admitted. Its raw diff changes
`struct ipv4_ct_tuple tuple = {}` to `struct ipv4_ct_tuple tuple __align_stack_8 = {}`
in `snat_v4_rev_nat()`. The reconstructed case reproduces the corresponding
unaligned 8-byte stack access and parses as a fresh trace-rich verifier reject.

The remaining records lack raw verifier logs. They are full-Cilium datapath,
historical-kernel, helper-signature, compiler-lowering, generated-config, or
runtime data-layout changes without an isolated rejected instruction and terminal
verifier error that can be faithfully replayed from the collected diff alone.

## Successful Replays

- `github-commit-cilium-b4a0fa7425c7`: admitted at
  `bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7/`. Local `make clean`,
  `make`, and `make replay-verify` ran. `tools.replay_case.parse_verifier_log`
  classified the fresh `replay-verifier.log` as `trace_rich` with
  `terminal_error="misaligned stack access off 0+-15+0 size 8"` and
  `rejected_insn_idx=3`.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-a7625471733f` | no case | `environment_required` | Raw title is "bpf, nat: bump collision retries on newer kernels"; snippets move `SNAT_COLLISION_RETRIES` into `nat.h` and vary retry counts by `HAVE_LARGE_INSN_LIMIT`. Rejection evidence depends on historical generated NAT program size and kernel instruction limits, with no verifier log. |
| `github-commit-cilium-a78f75e1eb1d` | no case | `environment_required` | Raw title is "bpf: reduce complexity of logic to handle IPv4 fragments"; snippets span `conntrack.h`, `ipv4.h`, and `lb.h` fragmentation control flow. Faithful replay requires Cilium fragment maps, CT/LB call paths, and old complexity behavior, with no terminal log. |
| `github-commit-cilium-a9679280e805` | no case | `environment_required` | Raw title is "bpf: remove deterministic retries on lru"; snippets remove deterministic SNAT retries under LRU map handling. Any reject is tied to NAT map type, retry unrolling, and historical verifier complexity rather than an isolated local operation. |
| `github-commit-cilium-aa4031c0c08c` | no case | `environment_required` | Raw diff changes `redirect_neigh(DIRECT_ROUTING_DEV_IFINDEX, 0)` and the helper declaration to the four-argument `bpf_redirect_neigh()` signature. Reproduction depends on kernel helper ABI/support and Cilium LXC fast-redirect context, not a standalone current-kernel verifier log. |
| `github-commit-cilium-aa7180eb3463` | no case | `environment_required` | Raw title is "bpf: Optimize complexity of ipcache lookup"; snippets rewrite non-LPM trie prefix iteration into one mutable `ipcache_key`. The reject requires generated `IPCACHE*_PREFIXES`, map shape, and full verifier path pressure. |
| `github-commit-cilium-ab329d2efb46` | no case | `not_reconstructable_from_diff` | Raw fix adds `barrier_data(*state)` and separates `*state = tmp` from the `snat_v{4,6}_new_mapping()` call to prevent clang from moving address calculations before a NULL check. The snippets identify the compiler hazard but not a replayable rejected instruction or terminal verifier error. |
| `github-commit-cilium-abd3a3c88c14` | no case | `not_reconstructable_from_diff` | Raw diff removes `key.ip6.p4 = 0` from an IPv6 endpoint-key path before `encap_and_redirect()`. It is described as reducing complexity, but the collected snippet lacks the surrounding datapath path or a verifier message to reconstruct a strict reject. |
| `github-commit-cilium-ac40ff4cfc11` | no case | `out_of_scope_non_verifier` | Raw title is a revert of "bpf: Relax the verifier in CT slow paths"; snippets remove `relax_verifier()` from debug no-op helpers. This is removing a workaround, not a captured verifier-load failure to replay. |
| `github-commit-cilium-acac0dcf71af` | no case | `out_of_scope_non_verifier` | Raw title is "ipcache: Stop populating node IDs in ipcache"; snippets replace `node_id` fields with padding in tunnel and remote endpoint map values. This is runtime map-value layout behavior, not a verifier rejection. |
| `github-commit-cilium-ad0d3cf34140` | no case | `environment_required` | Raw title is "bpf: Fixes to support mattr=+alu32"; snippets span skb/xdp context helpers, checksum, encap, metrics, NAT, and NodePort, changing several 32-bit lengths to 64-bit forms. Reproduction depends on clang `+alu32` lowering and full Cilium feature composition. |
| `github-commit-cilium-ad936f16d68f` | no case | `out_of_scope_non_verifier` | Raw title is "bpf: add option for debug output to raw_main"; snippets are in the user-space `bpf/probes/raw_main.c` harness and add debug reporting around `bpf_prog_load()`. This is collection/debug tooling, not a standalone BPF verifier bug case. |
| `github-commit-cilium-aea89d0c429f` | no case | `out_of_scope_non_verifier` | Raw title is "complexity-tests: add bpf_network configuration"; snippet only changes `TRACE_NOTIFY` guarding in `bpf_alignchecker.c`. It is test/config generation, not a rejected BPF program. |
| `github-commit-cilium-b156a3abae71` | no case | `environment_required` | Raw title is "bpf, nat46x64: move RFC6052 prefix into node config"; snippets add a node config value and copy prefix bytes through an unrolled loop. Any verifier effect depends on Cilium config-map access and NAT46x64 generated paths, with no log. |
| `github-commit-cilium-b25ef7c325b5` | no case | `out_of_scope_non_verifier` | Duplicate shape to `acac0dcf71af`: raw snippets stop storing node IDs in tunnel and remote endpoint map values by replacing fields with padding. This is runtime data layout, not verifier rejection evidence. |
| `github-commit-cilium-b4a0fa7425c7` | admitted case | `replay_valid` | Raw fix aligns `struct ipv4_ct_tuple tuple` with `__align_stack_8`; reconstructed replay built locally and produced fresh trace-rich reject `misaligned stack access off 0+-15+0 size 8` at instruction 3. |
| `github-commit-cilium-b7af6e8ffda1` | no case | `environment_required` | Raw title explicitly says "work around verifier issue in __ct_update_timeout"; snippets replace pointer dereferences with `READ_ONCE`/`WRITE_ONCE` and add a barrier for a modified skb ctx pointer. Reproduction depends on historical verifier handling of Cilium CT map-value pointers and skb context arithmetic. |
| `github-commit-cilium-b80ac08f6259` | no case | `out_of_scope_non_verifier` | Raw title is "ipcache: Populate ipcache with node IDs"; snippet adds `node_id` to `remote_endpoint_info`. This is map-value/runtime datapath state rather than a verifier-load failure. |
| `github-commit-cilium-b8e041db503b` | no case | `environment_required` | Raw title is "bpf: Add send_trace_notify hook for redirect_direct_{v4,v6}"; snippets change LXC host-routing calls and FIB redirect helpers to return `oif`. Any verifier pressure depends on full redirect, FIB, trace, and host-routing composition. |
| `github-commit-cilium-bb0126fdafcf` | no case | `environment_required` | Raw title is "bpf: dsr: fix IPIP health-encap on older kernels"; snippets change `ctx_set_tunnel_key()` size from `sizeof(key)` to `TUNNEL_KEY_WITHOUT_SRC_IP`. This is explicitly older-kernel helper/verifier behavior and lacks a local current-kernel reject log. |
| `github-commit-cilium-bb0f6d8213aa` | no case | `environment_required` | Raw title is "bpf:classifiers: accept L3 protocol in ctx_classify"; snippets propagate `proto` through LXC, drop, trace, and classifier helpers and initialize `proto = 0`. Reproduction requires generated L3-device/trace/drop program context and no terminal verifier log is present. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files | head -200
git status --short
rg -n "github-commit-cilium-(a7625471733f|a78f75e1eb1d|a9679280e805|aa4031c0c08c|aa7180eb3463|ab329d2efb46|abd3a3c88c14|ac40ff4cfc11|acac0dcf71af|ad0d3cf34140|ad936f16d68f|aea89d0c429f|b156a3abae71|b25ef7c325b5|b4a0fa7425c7|b7af6e8ffda1|b80ac08f6259|b8e041db503b|bb0126fdafcf|bb0f6d8213aa)" bpfix-bench docs -S
for id in github-commit-cilium-a7625471733f ... github-commit-cilium-bb0f6d8213aa; do
  if test -d bpfix-bench/cases/$id; then echo $id; fi
done
```

Raw inspection:

```bash
python3 - <<'PY'
# Loaded each assigned bpfix-bench/raw/gh/<raw_id>.yaml and printed:
# source title/url, raw commit_date, fix_type, diff_summary, buggy_code,
# fixed_code, content.has_verifier_log, and reproduction metadata.
PY
```

Replay-contract and template inspection:

```bash
sed -n '1,260p' tools/replay_case.py
sed -n '1,260p' tools/integrate_reconstruction_batch.py
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/prog.c
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/Makefile
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/case.yaml
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-489da3e3f924/capture.yaml
clang --version && bpftool version || true && uname -a
```

Admitted replay for `github-commit-cilium-b4a0fa7425c7`:

```bash
cd bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("replay-verifier.log").read_text(errors="replace"), "replay-verifier.log"))
PY
```

Replay helper verification:

```bash
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
import yaml
from tools.replay_case import replay_case
case_dir = Path("bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7")
case_data = yaml.safe_load((case_dir / "case.yaml").read_text())
res = replay_case(case_dir, case_data, timeout_sec=30)
print(res.build.returncode, res.load.returncode, res.parsed_log, len(res.verifier_log_captured or ""))
PY
```

## Parsed Verifier Outcomes

| raw_id | command context | build | load | parsed outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-b4a0fa7425c7` | `bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7` | success (`returncode=0`) | verifier reject (`make replay-verify` returned make rc 2 after bpftool rc 255) | `log_quality=trace_rich`; `terminal_error="misaligned stack access off 0+-15+0 size 8"`; `rejected_insn_idx=3`; fresh captured log length 1430 bytes |

## Review

Reviewed on 2026-04-30.

Validation commands:

```bash
python3 - <<'PY'
# Parsed Record Results and verified exactly 20 unique assigned IDs in order.
PY

python3 - <<'PY'
# Parsed classifications with tools.integrate_reconstruction_batch and verified
# all are canonical/allowed; replay_valid is only github-commit-cilium-b4a0fa7425c7.
PY

python3 - <<'PY'
# Verified the only assigned case directory is
# bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7 and that it contains
# prog.c, Makefile, case.yaml, and capture.yaml.
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-34.md --bench-root bpfix-bench
```

Results:

- Record Results contains exactly the 20 assigned Batch 34 IDs, once each.
- Non-admitted classifications are canonical: `environment_required`,
  `not_reconstructable_from_diff`, and `out_of_scope_non_verifier`.
- Integration dry run completed with `errors: []` and admitted only
  `github-commit-cilium-b4a0fa7425c7`.
- Blockers: none.

## Review

Fresh review on 2026-04-30.

Commands run:

```bash
python3 - <<'PY'
# Parsed Record Results with tools.integrate_reconstruction_batch.parse_batch_report
# and checked exactly 20 unique assigned IDs, no missing/extra IDs, canonical
# classifications, and only github-commit-cilium-b4a0fa7425c7 as replay_valid.
PY

python3 - <<'PY'
# Checked github-commit-cilium-b4a0fa7425c7 case.yaml/capture.yaml metadata:
# source.kind == github_commit, external_match.status == not_applicable, and
# source_artifact.verifier_error_match == not_applicable.
PY

cd bpfix-bench/cases/github-commit-cilium-b4a0fa7425c7
make clean
make
make replay-verify

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
# Parsed fresh replay-verifier.log with tools.replay_case.parse_verifier_log
# and compared log_quality, terminal_error, and rejected_insn_idx to case.yaml.
PY

PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
# Replayed the case through tools.replay_case.replay_case and confirmed the
# fresh parsed verifier result remained trace-rich with rejected_insn_idx 3.
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-34.md --bench-root bpfix-bench
```

Outcome:

- Pass: Record Results has exactly the 20 assigned IDs once each.
- Pass: classifications are accepted by `tools/integrate_reconstruction_batch.py`.
- Pass: admitted case fresh replay matches `case.yaml`: `trace_rich`,
  `terminal_error="misaligned stack access off 0+-15+0 size 8"`,
  `rejected_insn_idx=3`.
- Pass: github_commit metadata uses `not_applicable` for external/capture
  verifier matching.
- Pass: dry-run integration completed with `errors: []`.
- Blockers: none. No case fix applied.
