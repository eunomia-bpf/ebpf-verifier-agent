# Reconstruction Batch 32

## Summary

Batch 32 reviewed 20 Cilium GitHub commit raw records. No record was admitted
to `bpfix-bench/cases` because none produced the required fresh local
trace-rich verifier rejection with both `terminal_error` and
`rejected_insn_idx`.

Two records had concrete standalone verifier-shaped snippets worth attempting:

- `github-commit-cilium-7a07e58a7620`: reconstructed the pre-fix tunnel-key
  helper call that omitted `key.tunnel_ttl`; local `make clean && make &&
  make replay-verify` succeeded and loaded the program. Parsed outcome:
  `log_quality=no_terminal_error`, `terminal_error=None`, `rejected_insn_idx=11`.
- `github-commit-cilium-80a3023ddb74`: reconstructed the IPv6 prefilter source
  address copy into an LPM trie key, including explicit unaligned 64-bit packet
  loads; local `make clean && make && make replay-verify` succeeded and loaded
  the program. Parsed outcome: `log_quality=no_terminal_error`,
  `terminal_error=None`, `rejected_insn_idx=27`.

The remaining records contain commit-derived before/after snippets without raw
verifier logs. Most are large Cilium datapath control-flow, tail-call,
configuration, or type/layout changes where the collected diff is insufficient
to derive a strict standalone replay that rejects on the local verifier.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-78a771f361f5` | no case | `not_reconstructable_from_diff` | WireGuard host-delivery redirect/ingress changes require the broader Cilium datapath and no raw verifier log identifies a failing instruction or terminal verifier error. |
| `github-commit-cilium-7a07e58a7620` | attempted local replay accepted | `attempted_accepted` | Standalone tunnel-key reconstruction built and loaded; parsed local verifier output had `terminal_error=None`, so it fails strict admission. |
| `github-commit-cilium-7a98029b6b2c` | no case | `not_reconstructable_from_diff` | Tail-call split for ingress L3 handlers is a large control-flow/complexity refactor with no raw verifier log or minimal failing instruction. |
| `github-commit-cilium-7b72cc4d60e4` | no case | `not_reconstructable_from_diff` | `relax_verifier()` removal around IPv6-from-LXC drop handling lacks a raw verifier rejection and depends on surrounding Cilium helper state. |
| `github-commit-cilium-7c2ace918c2f` | no case | `not_reconstructable_from_diff` | IPsec trace-event aggregation changes affect monitor/trace state across host/network datapath paths; no standalone verifier terminal error is present. |
| `github-commit-cilium-7c37b20cfa8b` | no case | `environment_required` | Geneve/VXLAN macro selection affects Cilium XDP complexity-test configuration and requires the upstream Cilium test matrix rather than a local snippet-only replay. |
| `github-commit-cilium-7c3ba66895f8` | no case | `not_reconstructable_from_diff` | `csum_diff()` size type changes are embedded in Cilium checksum/helper wrappers; raw record has no verifier log to pin down an admissible failing helper call. |
| `github-commit-cilium-7c9a45a2fd28` | no case | `out_of_scope_non_verifier` | Commit fixes a C compile diagnostic by adding an explicit `int` return type for `handle_srv6`, not a verifier rejection. |
| `github-commit-cilium-7de434985f89` | no case | `not_reconstructable_from_diff` | Early ethertype rejection changes SNAT/datapath control flow but the raw record lacks a verifier log or minimal failing access pattern. |
| `github-commit-cilium-7e0d0745e27f` | no case | `out_of_scope_non_verifier` | NAT test constant change addresses test flakiness, not a verifier rejection. |
| `github-commit-cilium-7e5035d565fb` | no case | `not_reconstructable_from_diff` | XDP complexity workaround adds `relax_verifier()` in a large LB path; no raw verifier terminal error or bounded standalone reproducer is available from the snippet. |
| `github-commit-cilium-7e8aee152484` | no case | `not_reconstructable_from_diff` | NodePort/L7 redirect changes span host, sock, LB, nodeport, and proxy hairpin code; the diff is too broad for strict standalone reconstruction without a verifier log. |
| `github-commit-cilium-7efa7b837646` | no case | `not_reconstructable_from_diff` | Host firewall nodeport ingress split depends on Cilium tail-call topology and configuration; no local verifier terminal error is present. |
| `github-commit-cilium-7fa2782adde0` | no case | `not_reconstructable_from_diff` | Conntrack field clarification changes struct-field propagation in Cilium CT helpers; the raw diff does not expose a standalone verifier reject. |
| `github-commit-cilium-80a3023ddb74` | attempted local replay accepted | `attempted_accepted` | Standalone IPv6 prefilter/LPM key copy reconstruction built and loaded locally, including explicit unaligned loads; parsed output had no terminal verifier error. |
| `github-commit-cilium-80ebd70cbfa1` | no case | `not_reconstructable_from_diff` | IPv6 LXC tunnel metadata toleration removal depends on Cilium metadata conventions and upgrade paths; no raw verifier log identifies a replayable failure. |
| `github-commit-cilium-814d3c797589` | no case | `not_reconstructable_from_diff` | `remote_endpoint_info` layout change lacks a verifier log and requires surrounding map-value users to infer any verifier-visible failure. |
| `github-commit-cilium-81da0ceeda66` | no case | `not_reconstructable_from_diff` | Alignment/layout changes in Cilium map/NAT structs are not enough to derive a strict local rejecting program without the original failing verifier log. |
| `github-commit-cilium-81f68d69ca95` | no case | `out_of_scope_non_verifier` | Bind-helper rename/refactor is a source/API naming change and no verifier rejection is captured. |
| `github-commit-cilium-854473726b50` | no case | `not_reconstructable_from_diff` | Netkit/L7 redirect workaround is a broad datapath behavior change without a raw verifier log or minimal failing verifier pattern. |

## Commands Run

Repository/context checks:

```sh
pwd && rg --files docs bpfix-bench | head -200
git status --short
rg -n "reconstruction-batch|replay_valid|terminal_error|external_match|source_artifact" docs bpfix-bench/cases -g '*.md' -g '*.yaml' | head -200
for id in github-commit-cilium-78a771f361f5 ... github-commit-cilium-854473726b50; do test -f bpfix-bench/raw/gh/$id.yaml; done
python3 - <<'PY'
# loaded assigned raw YAML files and printed source metadata, fix_type,
# diff_summary, buggy_code, and fixed_code excerpts
PY
```

Template/parser checks:

```sh
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-46024c6c4a30/Makefile
sed -n '1,140p' bpfix-bench/cases/github-commit-cilium-46024c6c4a30/case.yaml
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-46024c6c4a30/capture.yaml
sed -n '1,220p' tools/replay_case.py
sed -n '1,260p' tools/integrate_reconstruction_batch.py
```

Standalone attempt for `github-commit-cilium-7a07e58a7620`:

```sh
rm -rf /tmp/bpfix-batch32-7a07 && mkdir -p /tmp/bpfix-batch32-7a07
cp bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/Makefile /tmp/bpfix-batch32-7a07/Makefile
# wrote /tmp/bpfix-batch32-7a07/prog.c with the pre-fix partial bpf_tunnel_key initialization
make clean && make && make replay-verify
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/bpfix-batch32-7a07/replay-verifier.log").read_text(), "/tmp/bpfix-batch32-7a07/replay-verifier.log"))
PY
```

Standalone attempt for `github-commit-cilium-80a3023ddb74`:

```sh
rm -rf /tmp/bpfix-batch32-80a && mkdir -p /tmp/bpfix-batch32-80a
cp bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/Makefile /tmp/bpfix-batch32-80a/Makefile
# wrote /tmp/bpfix-batch32-80a/prog.c with the pre-fix IPv6 prefilter LPM key copy
make clean && make && make replay-verify
sudo rm -f /sys/fs/bpf/bpfix-batch32-80a
make replay-verify
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("/tmp/bpfix-batch32-80a/replay-verifier.log").read_text(), "/tmp/bpfix-batch32-80a/replay-verifier.log"))
PY
```

Report validation:

```sh
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-32.md --bench-root bpfix-bench
```

## Parsed Verifier Outcomes

| raw_id | command context | build | load | parsed outcome |
| --- | --- | --- | --- | --- |
| `github-commit-cilium-7a07e58a7620` | `/tmp/bpfix-batch32-7a07` standalone tunnel-key attempt | success | accepted (`make replay-verify` rc 0) | `log_quality=no_terminal_error`; `terminal_error=None`; `rejected_insn_idx=11` |
| `github-commit-cilium-80a3023ddb74` | `/tmp/bpfix-batch32-80a` standalone IPv6 prefilter attempt | success | accepted (`make replay-verify` rc 0) | `log_quality=no_terminal_error`; `terminal_error=None`; `rejected_insn_idx=27` |

## Review

Reviewed on 2026-04-29.

Commands run:

```sh
python3 - <<'PY'
from pathlib import Path
import re, yaml
report=Path('docs/tmp/reconstruction-batch-32.md')
text=report.read_text()
in_rr=False
rows=[]
for line in text.splitlines():
    if line.startswith('## '):
        in_rr=line.strip()=='## Record Results'
        continue
    if in_rr and line.startswith('|'):
        cells=[c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells)>=4 and cells[0].lower()!='raw_id' and not set(cells[0]) <= {'-'}:
            rows.append(re.sub(r'`','',cells[0]))
idx=yaml.safe_load(Path('bpfix-bench/raw/index.yaml').read_text())
entries=idx['entries']
start=next(i for i,e in enumerate(entries) if e.get('raw_id')==rows[0])
assigned=[]
for e in entries[start:]:
    if e.get('source_kind')=='github_commit' and e.get('raw_id','').startswith('github-commit-cilium-') and e.get('reproduction_status')=='needs_manual_reconstruction':
        assigned.append(e['raw_id'])
    if len(assigned)==20:
        break
print('rows', len(rows))
print('unique', len(set(rows)))
print('matches_assigned_needs_manual_window', rows==assigned)
print('missing_from_report', sorted(set(assigned)-set(rows)))
print('extra_in_report', sorted(set(rows)-set(assigned)))
print('case_dirs_created', [r for r in rows if Path('bpfix-bench/cases', r).exists()])
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-32.md --bench-root bpfix-bench
```

Review findings:

- Record Results contains exactly the 20 assigned Batch 32 `needs_manual_reconstruction` IDs, once each.
- No assigned `bpfix-bench/cases/<raw_id>/` directories were created.
- Non-admitted classifications are canonical statuses accepted by `tools/integrate_reconstruction_batch.py`.
- Integration dry run reported `errors: []`.
- No blockers.
