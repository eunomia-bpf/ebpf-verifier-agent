# Reconstruction Batch 30

Date: 2026-04-30

Scope:

- Assigned Batch 30 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Existing assigned case directories before this batch: 0
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 raw records lack captured verifier logs.
Most records are full-Cilium datapath complexity, old-kernel compatibility,
compiler/code-generation, feature-probe, or runtime-behavior changes. The only
record whose title directly names a verifier error,
`github-commit-cilium-5d882fdd1f8a`, has only a small `skb->tc_index` snippet
and no terminal verifier log; reproducing it faithfully would require the
historical Cilium debug-mode program and newer-LLVM code generation that
produced the original rejection. Because the admission rule requires local
`make clean`, `make`, and `make replay-verify` to produce a fresh verifier
reject parsed as `trace_rich` with both `terminal_error` and
`rejected_insn_idx`, no `bpfix-bench/cases/<id>/` directory was created.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-5745846a5212` | no case | `environment_required` | Local Redirect Policy socket translation is gated on `HAVE_NETNS_COOKIE` for pre-5.8 kernels. Replaying the verifier behavior requires that historical helper/kernel capability matrix and the generated Cilium socket program; no verifier log is present. |
| `github-commit-cilium-58aaaf61a6c5` | no case | `environment_required` | Adds `relax_verifier()` in an IPv6 drop path to manage old full-datapath verifier complexity. The snippet does not isolate a current standalone rejection and has no terminal verifier log. |
| `github-commit-cilium-5af1f5715e6d` | no case | `out_of_scope_non_verifier` | Adds IPv6 address-construction macros to avoid LLVM relocations. The failure mode is compiler/relocation handling, not a captured kernel verifier rejection. |
| `github-commit-cilium-5b05cc92dd66` | no case | `environment_required` | Splits host-firewall LXC traffic handling into tail calls to reduce full-program complexity. Faithful replay depends on Cilium feature flags, generated tail-call maps, and historical verifier limits. |
| `github-commit-cilium-5b3a32131da6` | no case | `environment_required` | Adds verifier relaxation and conntrack inline changes for kernels older than 5.3. The rejection is tied to old-kernel full-Cilium complexity and no standalone rejected instruction is available. |
| `github-commit-cilium-5bb58205d955` | no case | `environment_required` | Uses caller-provided output interface information for old FIB behavior in compat mode. Reproducing verifier-visible behavior requires the historical kernel FIB helper behavior and broad NodePort/LXC datapath context. |
| `github-commit-cilium-5c10bcda5ffd` | no case | `out_of_scope_non_verifier` | Splits a generated `__builtin_memmove` test to work around a clang bug. This is compiler/test-code generation behavior, and the raw record has no verifier-load failure log. |
| `github-commit-cilium-5cdd3258dca5` | no case | `not_reconstructable_from_diff` | Makes `ct_state` optional across conntrack, NAT, host-firewall, NodePort, and tests. The diff is too broad to derive a faithful standalone verifier-rejecting program without the original generated program or log. |
| `github-commit-cilium-5d882fdd1f8a` | no case | `missing_verifier_log` | The title names a debug-mode verifier error fixed by forcing a volatile `skb->tc_index` load, but the raw record contains no terminal verifier log or rejected instruction. A generic repro would not be faithful to the LLVM/Cilium debug-mode failure. |
| `github-commit-cilium-5ddedadc81f2` | no case | `environment_required` | Optimizes IPv6 fragmentation handling to reduce verifier complexity. The available snippet lacks the full parser/control-flow context and no captured verifier log is available. |
| `github-commit-cilium-5e0fc3ae8178` | no case | `environment_required` | Reduces `SECLABEL_IPV{4,6}` plumbing complexity through loader/config changes across several generated programs. Faithful replay depends on Cilium loader substitution and generated objects, not an isolated snippet. |
| `github-commit-cilium-5e1139d09b2d` | no case | `not_reconstructable_from_diff` | Changes NodePort tunnel-encap source-IP handling across XDP/TC paths. The snippets require the surrounding NodePort, DSR, and tunnel configuration to make verifier-visible behavior meaningful, and no log is present. |
| `github-commit-cilium-5f9c8fbbe2d3` | no case | `out_of_scope_non_verifier` | Works around `skb->mark` scrubbing across veth transitions by changing metadata propagation. This is datapath runtime behavior, not an isolated verifier rejection. |
| `github-commit-cilium-657d0f585afd` | no case | `out_of_scope_non_verifier` | Extends a BPF feature probe for larger instruction/complexity limits. It is capability detection infrastructure, not a replayable verifier-reject benchmark case. |
| `github-commit-cilium-6693e11d50c9` | no case | `out_of_scope_non_verifier` | Fixes NodePort IPIP forward-path translation behavior. The raw record has no verifier log and does not identify a verifier-rejected source operation. |
| `github-commit-cilium-66b60bcad811` | no case | `environment_required` | Optimizes classifier computation by observation point to control full-datapath complexity. Replaying any verifier benefit requires generated trace/drop/classifier programs and Cilium feature configuration. |
| `github-commit-cilium-66c49a71a670` | no case | `out_of_scope_non_verifier` | Populates ipcache values with node IDs. This is map value layout/runtime datapath state, not a kernel verifier-load failure. |
| `github-commit-cilium-66dda3ae3c00` | no case | `environment_required` | Enables monitor aggregation in complexity tests by changing generated test config defaults. Any verifier effect is tied to Cilium complexity-test configuration, with no standalone terminal rejection. |
| `github-commit-cilium-66ed510cf832` | no case | `out_of_scope_non_verifier` | Stops storing node IDs in tunnel/ipcache-related map values. This reverses runtime data layout, not a verifier rejection. |
| `github-commit-cilium-68772ba85b15` | no case | `out_of_scope_non_verifier` | Adds a dummy `CALLS_MAP` symbol for compile-tested binaries. The failure mode is test/build symbol replacement rather than a parsed verifier rejection. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files | rg '^(docs/tmp/reconstruction-batch-30.md|bpfix-bench/(cases|raw|tools|.*README|Makefile)|tools)'
git status --short
rg -n "reconstruction-batch|replay-verify|parse_verifier_log|external_match|verifier_error_match|replay_valid|attempted_accepted|environment_required|missing_source|missing_verifier_log|not_reconstructable_from_diff|out_of_scope_non_verifier|attempted_unknown" -S .
```

Raw-record presence and replay-contract inspection:

```bash
for id in github-commit-cilium-5745846a5212 ... github-commit-cilium-68772ba85b15; do
  rg --files bpfix-bench/raw | rg "$id"
done
sed -n '1,220p' bpfix-bench/README.md
sed -n '1,260p' tools/replay_case.py
sed -n '1,220p' docs/tmp/reconstruction-batch-28.md
```

Assigned raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"))
    print(textwrap.shorten(" ".join(d["raw"].get("diff_summary", "").split()), width=900))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
for id in [
    "github-commit-cilium-5d882fdd1f8a",
    "github-commit-cilium-5c10bcda5ffd",
    "github-commit-cilium-5af1f5715e6d",
    "github-commit-cilium-5bb58205d955",
    "github-commit-cilium-5745846a5212",
]:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"])
    print(d["raw"].get("buggy_code", "")[:6000])
    print(d["raw"].get("fixed_code", "")[:6000])
PY
```

Assigned case-directory check:

```bash
python3 - <<'PY'
from pathlib import Path
ids = [...]
for id in ids:
    print(id, (Path("bpfix-bench/cases") / id).is_dir())
PY
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
p = Path("docs/tmp/reconstruction-batch-30.md")
text = p.read_text()
rows = []
in_table = False
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] not in ("raw_id", "---") and not set(cells[0]) <= {"-"}:
            rows.append(tuple(c.replace("`", "") for c in cells[:4]))
ids = [r[0] for r in rows]
print("rows", len(rows))
print("unique", len(set(ids)))
print("duplicates", sorted({x for x in ids if ids.count(x) > 1}))
print("\n".join(ids))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
ids = [...]
existing = [i for i in ids if (Path("bpfix-bench/cases") / i).is_dir()]
print("assigned_case_dirs", existing)
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import re
text = Path("docs/tmp/reconstruction-batch-30.md").read_text()
rows = []
in_table = False
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0].lower() != "raw_id" and set(cells[0]) > {"-"}:
            rows.append(tuple(re.sub(r"`", "", c) for c in cells[:4]))
ids = [r[0] for r in rows]
allowed = {
    "attempted_accepted",
    "attempted_failed",
    "attempted_unknown",
    "candidate_for_replay",
    "environment_required",
    "missing_source",
    "missing_verifier_log",
    "not_reconstructable_from_diff",
    "out_of_scope_non_verifier",
    "replay_reject_no_rejected_insn",
    "replay_valid",
}
print("rows", len(rows))
print("unique", len(set(ids)))
print("duplicates", sorted({i for i in ids if ids.count(i) > 1}))
print("bad_classifications", sorted({r[2] for r in rows if r[2] not in allowed}))
print("classifications", sorted({r[2] for r in rows}))
print("assigned_case_dirs", [i for i in ids if (Path("bpfix-bench/cases") / i).is_dir()])
PY
```

```bash
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-30.md --bench-root bpfix-bench
```

Review results:

- Record Results has exactly 20 Batch 30 IDs, once each.
- No assigned `bpfix-bench/cases/<raw_id>/` directories exist.
- Non-admitted classifications are canonical statuses:
  `environment_required`, `missing_verifier_log`,
  `not_reconstructable_from_diff`, and `out_of_scope_non_verifier`.
- Integration dry run completed with `errors: []`.
- Blockers: none.
