# Reconstruction Batch 31

Date: 2026-04-30

Scope:

- Assigned Batch 31 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any
  `bpfix-bench/raw/*.yaml` file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at start.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records lack captured verifier
logs. Two high-signal shapes were probed locally in `/tmp`: the Clang/session
affinity key initialization change and the `mock_fib_lookup()` null-parameter
change. Both accepted on the local pinned environment, so they fail the strict
admission rule. The remaining records either describe runtime datapath behavior,
map-loader/test-tooling changes, historical kernel/compiler verifier behavior,
or broad full-Cilium complexity changes without enough source/log context to
derive a faithful standalone verifier-rejecting `prog.c`.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-697b6d18ce17` | no case | `out_of_scope_non_verifier` | Fixes IPv4 redirect checksum byte order by changing `LXC_IPV4` to `bpf_htonl(LXC_IPV4)`. No verifier-load failure or rejected instruction is present. |
| `github-commit-cilium-6af5d7995e6d` | no case | `out_of_scope_non_verifier` | Refactors `from_host`/`#ifdef` placement in `do_netdev()` host-firewall metadata paths. The record has no verifier log and reads as datapath cleanup, not a verifier reject. |
| `github-commit-cilium-6bf5e4e65121` | no case | `environment_required` | Addresses 4.9-kernel complexity around conntrack/LB pruning and map-value adjustment. Faithful replay requires the old kernel verifier and full Cilium program shape. |
| `github-commit-cilium-6c91da4815a5` | no case | `environment_required` | Host-reachable-services protocol gating and inlining changes depend on generated Cilium socket programs and feature macros; no isolated verifier log is available. |
| `github-commit-cilium-6da3cb628d63` | no case | `environment_required` | Explicitly targets complexity on kernels `<5.3` by adding `relax_verifier()`/inlining changes in full LXC and conntrack paths. |
| `github-commit-cilium-6e18eb020b68` | no case | `attempted_accepted` | A minimal affinity-key stack-initialization probe based on the diff built and loaded locally; no fresh verifier reject was produced. The original issue is Clang/Cilium-shape dependent. |
| `github-commit-cilium-6e343142bf22` | no case | `environment_required` | Splits IPv4 nodeport NAT into tail calls to reduce full-program complexity. Replay requires generated nodeport/NAT/FIB datapath and historical complexity behavior. |
| `github-commit-cilium-717a4683f507` | no case | `environment_required` | Adds verifier relaxation on an IPv6 drop path. The snippets are full LXC control flow with no terminal log or standalone rejected operation. |
| `github-commit-cilium-724a101aed68` | no case | `out_of_scope_non_verifier` | Adjusts overlay delivery to `cilium_host` ingress; no verifier-load failure evidence is captured. |
| `github-commit-cilium-7350d08e9059` | no case | `environment_required` | Avoids `bpf_redirect_neigh()` from overlay programs and updates related tests. Any verifier/helper issue depends on Cilium overlay program type and feature configuration. |
| `github-commit-cilium-737262d8d52d` | no case | `not_reconstructable_from_diff` | Adds trace-notify hooks across direct redirect helpers and LXC paths. The verifier-visible shape is broad and no log isolates a terminal reject. |
| `github-commit-cilium-737401365a39` | no case | `environment_required` | Removes ARP responder code from old netdev datapath, apparently to reduce complexity. Faithful replay would need the 2016 full datapath and verifier behavior. |
| `github-commit-cilium-746fb2a17d4c` | no case | `out_of_scope_non_verifier` | Removes a kube-proxy workaround in to-container paths. The diff does not identify a verifier-load rejection. |
| `github-commit-cilium-74f7fd1d40bc` | no case | `not_reconstructable_from_diff` | Caches `ctx_data()`/`ctx_data_end()` in BPF tests before inline-asm context access changes. The raw snippets lack the local macro/test harness needed to reproduce a faithful reject. |
| `github-commit-cilium-7582619a6195` | no case | `out_of_scope_non_verifier` | Adds a check-complexity script and shared constants. This is verifier-complexity tooling, not a replayable rejected BPF program. |
| `github-commit-cilium-7600599e8d7e` | no case | `environment_required` | Encryption/FIB helper fallback fixes depend on helper availability, IPsec/IP_POOLS feature macros, and full LXC/netdev generation. |
| `github-commit-cilium-7684efd186f9` | no case | `environment_required` | Moves an ARP protocol check in old netdev code. Any verifier behavior depends on the 2016 Cilium datapath and historical verifier. |
| `github-commit-cilium-77685c2280ae` | no case | `attempted_accepted` | A minimal `mock_fib_lookup()` subprogram dereference probe loaded successfully locally; reproducing the comment's separate BTF function verification would need Cilium's test harness. |
| `github-commit-cilium-783648c20626` | no case | `environment_required` | Adds `__align_stack_8` for a Geneve DSR option object to satisfy LLVM 18 stack-alignment behavior in full nodeport code. The snippet lacks the memcpy/use path needed for a standalone reject. |
| `github-commit-cilium-789eef0d148d` | no case | `out_of_scope_non_verifier` | Converts Maglev maps from legacy loader definitions to BTF map definitions. This is map-definition/loader compatibility, not a verifier-rejected program body. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | head -200
git status --short
ls -la bpfix-bench && find bpfix-bench/cases -maxdepth 2 -name case.yaml | head -30
ls -la docs/tmp || true && find docs/tmp -maxdepth 1 -type f -name 'reconstruction-batch-*.md' | sort | tail -10
```

Raw-record and case-directory checks:

```bash
for id in github-commit-cilium-697b6d18ce17 ... github-commit-cilium-789eef0d148d; do
  find bpfix-bench/raw -path "*${id}.yaml" -print
done

for id in github-commit-cilium-697b6d18ce17 ... github-commit-cilium-789eef0d148d; do
  test -e bpfix-bench/cases/$id && printf '%s exists\n' "$id"
done
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"))
    print(d["raw"].get("diff_summary", ""))
PY

rg -n "verifier|invalid|R[0-9]|permission|processed|Load|load|BPF|bpf" \
  bpfix-bench/raw/gh/github-commit-cilium-{697b6d18ce17,...,789eef0d148d}.yaml

python3 - <<'PY'
from pathlib import Path
import yaml
for id in [...]:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["raw"].get("buggy_code", ""))
    print(d["raw"].get("fixed_code", ""))
PY
```

Replay-contract and tool inspection:

```bash
sed -n '1,220p' bpfix-bench/README.md
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-50c319d0cbfe/case.yaml
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-50c319d0cbfe/capture.yaml
sed -n '1,200p' bpfix-bench/cases/github-commit-cilium-50c319d0cbfe/Makefile
rg -n "def parse_verifier_log|trace_rich|terminal_error|rejected_insn_idx" tools -S
clang --version && bpftool version || true && uname -a
```

Local probes in `/tmp`:

```bash
cd /tmp/bpfix-b31/nullparam
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
text = Path("replay-verifier.log").read_text(errors="replace")
print(parse_verifier_log(text))
PY

cd /tmp/bpfix-b31/affinity
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
text = Path("replay-verifier.log").read_text(errors="replace")
print(parse_verifier_log(text))
PY
```

## Parsed Verifier Outcomes

No admitted case produced a fresh verifier-reject log.

Local probe outcomes:

| probe | related raw_id | load result | parsed outcome |
| --- | --- | --- | --- |
| `nullparam` | `github-commit-cilium-77685c2280ae` | accepted | `terminal_error=None`, `rejected_insn_idx=7`, `log_quality=no_terminal_error` |
| `affinity` | `github-commit-cilium-6e18eb020b68` | accepted | `terminal_error=None`, `rejected_insn_idx=19`, `log_quality=no_terminal_error` |

Admission validation result:

```text
admitted cases: 0
make clean / make / make replay-verify: not run in any assigned case directory
because no faithful standalone verifier-reject reconstruction was available.
```

## Review

Review date: 2026-04-30

Commands run:

```bash
git status --short
sed -n '1,260p' docs/tmp/reconstruction-batch-31.md
sed -n '1,170p' tools/integrate_reconstruction_batch.py
python3 - <<'PY'
from pathlib import Path
p = Path("docs/tmp/reconstruction-batch-31.md")
text = p.read_text()
sec = text.split("## Record Results", 1)[1].split("\n## ", 1)[0]
ids = []
classes = []
for line in sec.splitlines():
    if line.startswith("| `"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        ids.append(cells[0].strip("`"))
        classes.append(cells[2].strip("`"))
print("count", len(ids))
print("unique", len(set(ids)))
print("duplicates", sorted({x for x in ids if ids.count(x) > 1}))
print("classes", sorted(set(classes)))
PY
python3 - <<'PY'
from pathlib import Path
ids = [
    "github-commit-cilium-697b6d18ce17",
    "github-commit-cilium-6af5d7995e6d",
    "github-commit-cilium-6bf5e4e65121",
    "github-commit-cilium-6c91da4815a5",
    "github-commit-cilium-6da3cb628d63",
    "github-commit-cilium-6e18eb020b68",
    "github-commit-cilium-6e343142bf22",
    "github-commit-cilium-717a4683f507",
    "github-commit-cilium-724a101aed68",
    "github-commit-cilium-7350d08e9059",
    "github-commit-cilium-737262d8d52d",
    "github-commit-cilium-737401365a39",
    "github-commit-cilium-746fb2a17d4c",
    "github-commit-cilium-74f7fd1d40bc",
    "github-commit-cilium-7582619a6195",
    "github-commit-cilium-7600599e8d7e",
    "github-commit-cilium-7684efd186f9",
    "github-commit-cilium-77685c2280ae",
    "github-commit-cilium-783648c20626",
    "github-commit-cilium-789eef0d148d",
]
for rid in ids:
    d = Path("bpfix-bench/cases") / rid
    if d.exists():
        print(rid)
PY
python3 - <<'PY'
import re
from pathlib import Path
tool = Path("tools/integrate_reconstruction_batch.py").read_text()
allowed = set(re.findall(r'"([^"]+)"', re.search(r"NON_REPLAY_STATUSES = \{(.*?)\}", tool, re.S).group(1)))
report = Path("docs/tmp/reconstruction-batch-31.md").read_text()
sec = report.split("## Record Results", 1)[1].split("\n## ", 1)[0]
classes = []
for line in sec.splitlines():
    if line.startswith("| `"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        classes.append(cells[2].strip("`"))
print("report_statuses", sorted(set(classes)))
print("all_canonical", all(c in allowed for c in classes))
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-31.md --bench-root bpfix-bench
```

Review results:

- `Record Results` contains exactly 20 rows, with 20 unique raw IDs and no duplicates.
- The 20 assigned Batch 31 raw IDs are present once each in the table.
- No assigned `bpfix-bench/cases/<raw_id>/` directories exist.
- Non-admitted classifications are canonical statuses accepted by `tools/integrate_reconstruction_batch.py`: `attempted_accepted`, `environment_required`, `not_reconstructable_from_diff`, and `out_of_scope_non_verifier`.
- Integration dry run returned `rows: 20`, `admitted: []`, `missing_raw: []`, `skipped_index: []`, and `errors: []`.
- Blockers: none.
