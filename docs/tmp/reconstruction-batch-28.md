# Reconstruction Batch 28

Date: 2026-04-30

Scope:

- Assigned Batch 28 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records lack captured verifier logs.
The stored snippets are either runtime datapath fixes, historical
kernel/compiler/full-Cilium-environment compatibility changes, or broad
multi-file changes without enough surrounding source to derive a faithful
standalone verifier-rejecting `prog.c`. Because the admission rule requires a
fresh local verifier reject parsed as `trace_rich` with both `terminal_error`
and `rejected_insn_idx`, no `bpfix-bench/cases/<id>/` directory was created.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-47bd87551277` | no case | `environment_required` | IPsec destination-IP handling depends on Cilium IPsec/IP_POOLS configuration, mark/cb metadata propagation, and full LXC/netdev datapath generation. The raw record has no verifier log or isolated rejected operation. |
| `github-commit-cilium-47eae08f915e` | no case | `out_of_scope_non_verifier` | Changes socket-hook return values and `try_set_retval()` error reporting for health-check paths; no verifier-load failure or rejected BPF source is identified. |
| `github-commit-cilium-48486304df0f` | no case | `out_of_scope_non_verifier` | Fixes east/west wildcard service lookup semantics by skipping wildcard lookup when `east_west` is set. The raw record has no verifier log and no verifier-rejected source pattern. |
| `github-commit-cilium-4856e3829193` | no case | `out_of_scope_non_verifier` | Removes/stops using node IDs in ipcache-related map values. This is datapath data-layout/runtime behavior, not an isolated verifier rejection. |
| `github-commit-cilium-4866264f77d1` | no case | `not_reconstructable_from_diff` | The trace-notification API change spans many Cilium programs and helper wrappers. Without a verifier log or complete generated program, the snippets do not isolate a faithful standalone reject. |
| `github-commit-cilium-4b8ad8fa6bd8` | no case | `out_of_scope_non_verifier` | Adds IPv4 reverse-tuple address helper accessors in conntrack code; the raw record contains no verifier log and does not describe a verifier-load failure. |
| `github-commit-cilium-4cba4f153b9b` | no case | `not_reconstructable_from_diff` | Moves checksum-offset initialization into policy paths, but the verifier-visible behavior depends on surrounding Cilium policy, NAT, and checksum helper control flow. No terminal verifier log is present. |
| `github-commit-cilium-4dbbe2aa8c90` | no case | `out_of_scope_non_verifier` | Changes a session-affinity timeout comparison from `< now` to `<= now` to fix a test flake; this is runtime timing behavior, not verifier rejection. |
| `github-commit-cilium-4dee1580a096` | no case | `environment_required` | Reduces supported IPv6 extension-header skip count from 10 to 4 for historical verifier complexity. Replay would require the old full IPv6 parser and historical verifier behavior; no raw verifier log is present. |
| `github-commit-cilium-4fa26a4105eb` | no case | `environment_required` | Enables session affinity on older kernels by changing netns-cookie conditional paths. Faithful replay depends on old-kernel helper/configuration behavior and Cilium LB generation. |
| `github-commit-cilium-4ff4a0ee93fa` | no case | `not_reconstructable_from_diff` | Replaces the IPv6 SNAT ingress rewrite path with a shared rewrite helper. The snippets omit the full NAT/CT/helper context needed to reproduce any verifier-visible failure, and no log is captured. |
| `github-commit-cilium-50831aee16a9` | no case | `out_of_scope_non_verifier` | Prevents RevSNAT from creating new conntrack entries on ingress. The change is runtime conntrack semantics, with no verifier-load failure evidence. |
| `github-commit-cilium-515b99559972` | no case | `environment_required` | Fine-tunes the `neigh_resolver_available()` workaround across egress-gateway/FIB code. Any failure depends on helper availability and generated Cilium feature configuration; no standalone verifier log is present. |
| `github-commit-cilium-52b565fa30cb` | no case | `out_of_scope_non_verifier` | Fixes C undefined behavior in metadata encoding by casting before a shift. The raw record does not identify a kernel verifier rejection. |
| `github-commit-cilium-5322af54a581` | no case | `not_reconstructable_from_diff` | Makes `ct_state` optional for `ct_create*()` across conntrack, NAT, and host firewall paths. The diff is too broad to derive a faithful rejected standalone program without a verifier log. |
| `github-commit-cilium-53339a8f44e3` | no case | `environment_required` | Fixes IPv4 CIDR prefix matching on older kernels by replacing a variable-shift mask with `GET_PREFIX(prefix)`. The target is historical verifier/kernel behavior and no local terminal log is available. |
| `github-commit-cilium-536ad0c9a322` | no case | `environment_required` | Splits IPv6 nodeport NAT into a tail call to manage full-datapath verifier complexity. Replay requires historical generated Cilium nodeport programs rather than an isolated snippet. |
| `github-commit-cilium-53e1f373abf8` | no case | `environment_required` | Removes destination-MAC verification from LXC paths to reduce old full-program verifier pressure. The raw snippets depend on full Cilium packet parsing, conntrack, and policy paths. |
| `github-commit-cilium-5600ef0b0462` | no case | `out_of_scope_non_verifier` | Adds support for using `ctx->mark` as metadata transfer in host programs. This is datapath metadata behavior, not a verifier-reject case. |
| `github-commit-cilium-56ccb2a9d3bb` | no case | `environment_required` | Adds `relax_verifier()` on old error paths to help historical full-program verifier complexity. No isolated rejected instruction or captured log is available. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files bpfix-bench docs/tmp | sed -n '1,160p'
git status --short
rg -n "reconstruction-batch|replay_valid|attempted_accepted|environment_required|missing_source|missing_verifier_log|not_reconstructable_from_diff|out_of_scope_non_verifier|attempted_unknown" docs/tmp bpfix-bench/cases -g '*.md' -g 'case.yaml' | sed -n '1,220p'
```

Raw-record presence and local replay contract inspection:

```bash
for id in github-commit-cilium-47bd87551277 ... github-commit-cilium-56ccb2a9d3bb; do
  test -f bpfix-bench/raw/gh/$id.yaml && echo "$id present" || echo "$id MISSING"
done
sed -n '1,220p' bpfix-bench/README.md
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/Makefile
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/case.yaml
sed -n '1,160p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/capture.yaml
rg -n "def parse_verifier_log|parse_verifier_log|trace_rich|terminal_error|rejected_insn" -S .
```

Assigned raw inspection:

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

python3 - <<'PY'
from pathlib import Path
import yaml
for id in [
    "github-commit-cilium-48486304df0f",
    "github-commit-cilium-4b8ad8fa6bd8",
    "github-commit-cilium-52b565fa30cb",
    "github-commit-cilium-53339a8f44e3",
    "github-commit-cilium-5600ef0b0462",
    "github-commit-cilium-4856e3829193",
    "github-commit-cilium-4dee1580a096",
    "github-commit-cilium-53e1f373abf8",
    "github-commit-cilium-56ccb2a9d3bb",
]:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["raw"].get("buggy_code", "")[:5000])
    print(d["raw"].get("fixed_code", "")[:3000])
PY
```

Case-directory check:

```bash
for id in github-commit-cilium-47bd87551277 ... github-commit-cilium-56ccb2a9d3bb; do
  test -d bpfix-bench/cases/$id && echo "case:$id"
done
```

Result: no assigned case directories existed before this batch, and no new case
directories were created.

## Parsed Verifier Outcomes

No fresh verifier replay was produced for an admitted case in this batch, so
there are no `tools.replay_case.parse_verifier_log` outcomes to report.

Admission validation result:

```text
admitted cases: 0
make clean / make / make replay-verify: not run for assigned IDs because no
faithful standalone verifier-reject reconstruction was available.
```

## Review

Review commands:

```bash
python3 - <<'PY'
from pathlib import Path
p=Path('docs/tmp/reconstruction-batch-28.md')
text=p.read_text()
in_table=False
rows=[]
for line in text.splitlines():
    if line.startswith('## '):
        in_table=line.strip()=='## Record Results'
        continue
    if in_table and line.startswith('|'):
        cells=[c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells)>=4 and cells[0] not in ('raw_id','---') and not set(cells[0]) <= {'-'}:
            rows.append(tuple(c.replace('`','') for c in cells[:4]))
ids=[r[0] for r in rows]
print('rows', len(rows))
print('unique', len(set(ids)))
print('duplicates', sorted({x for x in ids if ids.count(x)>1}))
print('\n'.join(ids))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
ids = [
'github-commit-cilium-47bd87551277','github-commit-cilium-47eae08f915e','github-commit-cilium-48486304df0f','github-commit-cilium-4856e3829193','github-commit-cilium-4866264f77d1','github-commit-cilium-4b8ad8fa6bd8','github-commit-cilium-4cba4f153b9b','github-commit-cilium-4dbbe2aa8c90','github-commit-cilium-4dee1580a096','github-commit-cilium-4fa26a4105eb','github-commit-cilium-4ff4a0ee93fa','github-commit-cilium-50831aee16a9','github-commit-cilium-515b99559972','github-commit-cilium-52b565fa30cb','github-commit-cilium-5322af54a581','github-commit-cilium-53339a8f44e3','github-commit-cilium-536ad0c9a322','github-commit-cilium-53e1f373abf8','github-commit-cilium-5600ef0b0462','github-commit-cilium-56ccb2a9d3bb']
existing=[i for i in ids if (Path('bpfix-bench/cases')/i).is_dir()]
print('assigned_case_dirs', existing)
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import ast
script=Path('tools/integrate_reconstruction_batch.py').read_text()
mod=ast.parse(script)
non=None
for node in mod.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == 'NON_REPLAY_STATUSES':
                non=ast.literal_eval(node.value)
statuses=[]
text=Path('docs/tmp/reconstruction-batch-28.md').read_text()
in_table=False
for line in text.splitlines():
    if line.startswith('## '):
        in_table=line.strip()=='## Record Results'
        continue
    if in_table and line.startswith('|'):
        cells=[c.strip().replace('`','') for c in line.strip().strip('|').split('|')]
        if len(cells)>=4 and cells[0] not in ('raw_id','---') and not set(cells[0]) <= {'-'}:
            statuses.append(cells[2])
allowed={'replay_valid', *non}
print('table_statuses', sorted(set(statuses)))
print('unsupported', sorted(set(statuses)-allowed))
PY
```

```bash
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-28.md --bench-root bpfix-bench
```

Review results:

- Record Results has exactly 20 Batch 28 IDs, once each.
- No assigned `bpfix-bench/cases/<raw_id>/` directories exist.
- Non-admitted classifications are canonical integration statuses:
  `environment_required`, `not_reconstructable_from_diff`, and
  `out_of_scope_non_verifier`.
- Integration dry run reported `rows: 20`, `admitted: []`, `missing_raw: []`,
  `skipped_index: []`, and `errors: []`.
- Blockers: none.
