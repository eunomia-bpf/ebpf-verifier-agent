# Reconstruction Batch 33

Date: 2026-04-30

Scope:

- Assigned Batch 33 raw records only.
- Edited only this report.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or any `bpfix-bench/raw/*.yaml` file.
- No assigned `bpfix-bench/cases/<raw_id>/` directories existed at start.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

No assigned record was admitted. All 20 records lack captured verifier logs.
Most records are full-Cilium datapath, historical-kernel, helper-availability,
or runtime-behavior changes without an isolated terminal verifier error. The
highest-signal record, `github-commit-cilium-8dd5de960167`, was probed locally
because its snippet describes verifier-sensitive stack pointer arithmetic in
`__corrupt_mem`; the standalone reconstruction accepted on the pinned
environment, so it failed the strict admission rule.

## Successful Replays

None.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-87855a957541` | no case | `environment_required` | Outer-source-IP propagation touches host, LXC, overlay, and context structures. Any verifier effect depends on generated Cilium tunnel/IPsec datapath state and old-kernel verifier behavior, with no terminal log. |
| `github-commit-cilium-889fd1d0c40a` | no case | `out_of_scope_non_verifier` | Conditionally defines `IPV4_MASK` in generated node config when IPv4 is enabled. This is compile/config hygiene rather than a captured verifier-load rejection. |
| `github-commit-cilium-8a2b370692cd` | no case | `environment_required` | Changes IPsec monitor aggregation fields across host/network programs. Faithful replay requires Cilium feature macros and generated datapath paths; no verifier log isolates a reject. |
| `github-commit-cilium-8be6990e265e` | no case | `environment_required` | NodePort ICMP/revSNAT bypass logic spans IPv6 tuple extraction, service lookup, CT state, and FIB paths. The snippets are full datapath control flow without a standalone rejected operation. |
| `github-commit-cilium-8c8459f42308` | no case | `environment_required` | Moves FIB helper plumbing to `bpf_fib_lookup_padded`. Reproduction depends on helper struct layout, Cilium FIB wrappers, and generated datapath context rather than an isolated verifier error. |
| `github-commit-cilium-8cfe6efe6aa2` | no case | `out_of_scope_non_verifier` | The change only drops IPv6 proxy redirects when `proxy_port` is nonzero instead of dropping all TCP/UDP L4 traffic. This is datapath policy semantics, not a verifier rejection. |
| `github-commit-cilium-8d19819f3bfa` | no case | `missing_verifier_log` | The commit only documents an existing RHEL 8.6 verifier workaround around a null NAT state check. It provides no terminal verifier error, rejected instruction, or new source change to reconstruct. |
| `github-commit-cilium-8dd5de960167` | no case | `attempted_accepted` | A local standalone probe of the `__corrupt_mem` stack pointer arithmetic and conditional byte increment built and loaded successfully. Parsed log had no terminal verifier error, so no case was admitted. |
| `github-commit-cilium-8f9bab723dd5` | no case | `environment_required` | Converts `snat_v6_needs_masquerade()` from always-inline to weak noinline/global form. Any verifier effect depends on Cilium NAT map storage and program composition, with no captured reject. |
| `github-commit-cilium-8fcfad917bde` | no case | `out_of_scope_non_verifier` | Corrects pod-to-node encapsulation behavior with kube-proxy and host firewall. The diff changes routing/encap semantics and has no verifier-load failure evidence. |
| `github-commit-cilium-90c99481743f` | no case | `environment_required` | Adds a probe and fallback for `set_hash_invalid()` on kernels lacking the helper. Replay would require historical helper availability and Cilium LB program context. |
| `github-commit-cilium-90ddfb3fcf3f` | no case | `environment_required` | Reduces SNAT collision retries to avoid nodeport instruction-limit regressions. Faithful rejection depends on full generated netdev/overlay programs and historical instruction limits. |
| `github-commit-cilium-911ccd86df5f` | no case | `environment_required` | LB loopback with ingress policy changes many local-delivery call signatures across host, LXC, overlay, and L3 helpers. No isolated verifier-rejected snippet or log is present. |
| `github-commit-cilium-9141129561ff` | no case | `out_of_scope_non_verifier` | Works around `skb->mark` scrubbing during veth transition by changing metadata propagation and IPsec/encap calls. This is runtime datapath behavior, not a verifier-load failure. |
| `github-commit-cilium-93dee7abedea` | no case | `environment_required` | Adds `relax_verifier()` before returning CT lookup errors to reduce old full-datapath verifier pressure. Reproduction requires the historical Cilium LXC program shape and verifier. |
| `github-commit-cilium-94313fc7c9bb` | no case | `out_of_scope_non_verifier` | Makes monitor aggregation flags configurable in complexity-test node config. This is test/config generation, not a replayable rejected BPF program. |
| `github-commit-cilium-959b24a8135e` | no case | `environment_required` | Client/ingress inter-cluster SNAT changes span host, LXC, overlay, L3, and NAT helpers. Any verifier effect is tied to generated multi-feature Cilium datapath context. |
| `github-commit-cilium-95bc719aede5` | no case | `out_of_scope_non_verifier` | Adds graceful-close connection-tracking timeout behavior. The snippet updates map value fields and timers; it does not identify a verifier rejection. |
| `github-commit-cilium-97283583e26c` | no case | `environment_required` | Removes a redundant null check after an IPCache lookup once an earlier guard proves non-null. The verifier comment is tied to Cilium's catch-all IPCache assumption and full from-host path, with no log. |
| `github-commit-cilium-a495abda8528` | no case | `environment_required` | Duplicate IPsec monitor aggregation shape to `8a2b370692cd`; replay requires the generated Cilium IPsec/host/network programs and no terminal verifier log is present. |

## Commands Run

Context and ownership checks:

```bash
pwd && rg --files docs bpfix-bench | head -200
git status --short
rg -n "reconstruction-batch|Successful Replays|Record Results|external_match|replay-verify|terminal_error|rejected_insn_idx" docs bpfix-bench -g '!bpfix-bench/raw/*.yaml'
```

Raw-record presence and case-directory checks:

```bash
for id in github-commit-cilium-87855a957541 ... github-commit-cilium-a495abda8528; do
  ls bpfix-bench/raw/gh/$id.yaml
done

for id in github-commit-cilium-87855a957541 ... github-commit-cilium-a495abda8528; do
  if test -d bpfix-bench/cases/$id; then echo $id; fi
done
```

Raw inspection:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, textwrap
ids = [...]
for id in ids:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"], d["raw"].get("commit_date"),
          d["raw"].get("fix_type"), d["content"].get("has_verifier_log"))
    print(textwrap.shorten(" ".join(d["raw"].get("diff_summary", "").split()), width=1000))
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
for id in [
    "github-commit-cilium-8dd5de960167",
    "github-commit-cilium-8d19819f3bfa",
    "github-commit-cilium-90c99481743f",
    "github-commit-cilium-97283583e26c",
    "github-commit-cilium-8cfe6efe6aa2",
    "github-commit-cilium-95bc719aede5",
    "github-commit-cilium-8f9bab723dd5",
    "github-commit-cilium-8fcfad917bde",
    "github-commit-cilium-90ddfb3fcf3f",
    "github-commit-cilium-911ccd86df5f",
]:
    d = yaml.safe_load((Path("bpfix-bench/raw/gh") / f"{id}.yaml").read_text())
    print(id, d["source"]["title"])
    print(d["raw"].get("buggy_code", "")[:6000])
    print(d["raw"].get("fixed_code", "")[:4000])
PY
```

Replay-contract and environment inspection:

```bash
sed -n '1,220p' tools/integrate_reconstruction_batch.py
sed -n '1,220p' bpfix-bench/README.md
sed -n '1,140p' bpfix-bench/cases/github-commit-cilium-4d36cac2ee63/prog.c
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-4d36cac2ee63/Makefile
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-4d36cac2ee63/case.yaml
sed -n '1,120p' bpfix-bench/cases/github-commit-cilium-4d36cac2ee63/capture.yaml
clang --version && bpftool version || true && uname -a
```

Local probe in `/tmp`:

```bash
cd /tmp/bpfix-b33/corrupt_mem
make clean && make && make replay-verify
PYTHONPATH=/home/yunwei37/workspace/ebpf-verifier-agent python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
print(parse_verifier_log(Path("replay-verifier.log").read_text(errors="replace")))
PY
```

## Parsed Verifier Outcomes

No admitted case produced a fresh verifier-reject log.

Local probe outcome:

| probe | related raw_id | load result | parsed outcome |
| --- | --- | --- | --- |
| `corrupt_mem` | `github-commit-cilium-8dd5de960167` | accepted | `terminal_error=None`, `rejected_insn_idx=17`, `log_quality=no_terminal_error` |

Admission validation result:

```text
admitted cases: 0
make clean / make / make replay-verify: not run in any assigned case directory
because no faithful standalone verifier-reject reconstruction was available.
```

## Review

Reviewed on 2026-04-30.

Commands:

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter

text = Path("docs/tmp/reconstruction-batch-33.md").read_text()
rows = []
in_table = False
for line in text.splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] not in ("raw_id", "---") and not set(cells[0]) <= {"-"}:
            rows.append(cells[0])

expected = """
github-commit-cilium-87855a957541
github-commit-cilium-889fd1d0c40a
github-commit-cilium-8a2b370692cd
github-commit-cilium-8be6990e265e
github-commit-cilium-8c8459f42308
github-commit-cilium-8cfe6efe6aa2
github-commit-cilium-8d19819f3bfa
github-commit-cilium-8dd5de960167
github-commit-cilium-8f9bab723dd5
github-commit-cilium-8fcfad917bde
github-commit-cilium-90c99481743f
github-commit-cilium-90ddfb3fcf3f
github-commit-cilium-911ccd86df5f
github-commit-cilium-9141129561ff
github-commit-cilium-93dee7abedea
github-commit-cilium-94313fc7c9bb
github-commit-cilium-959b24a8135e
github-commit-cilium-95bc719aede5
github-commit-cilium-97283583e26c
github-commit-cilium-a495abda8528
""".strip().splitlines()

print("row_count:", len(rows))
print("unique_count:", len(set(rows)))
print("duplicates:", [k for k, v in Counter(rows).items() if v > 1])
print("missing:", sorted(set(expected) - set(rows)))
print("extra:", sorted(set(rows) - set(expected)))
print("order_matches_expected:", rows == expected)
PY

python3 - <<'PY'
from pathlib import Path

ids = """
github-commit-cilium-87855a957541
github-commit-cilium-889fd1d0c40a
github-commit-cilium-8a2b370692cd
github-commit-cilium-8be6990e265e
github-commit-cilium-8c8459f42308
github-commit-cilium-8cfe6efe6aa2
github-commit-cilium-8d19819f3bfa
github-commit-cilium-8dd5de960167
github-commit-cilium-8f9bab723dd5
github-commit-cilium-8fcfad917bde
github-commit-cilium-90c99481743f
github-commit-cilium-90ddfb3fcf3f
github-commit-cilium-911ccd86df5f
github-commit-cilium-9141129561ff
github-commit-cilium-93dee7abedea
github-commit-cilium-94313fc7c9bb
github-commit-cilium-959b24a8135e
github-commit-cilium-95bc719aede5
github-commit-cilium-97283583e26c
github-commit-cilium-a495abda8528
""".strip().splitlines()

print("assigned_case_dirs:", [i for i in ids if (Path("bpfix-bench/cases") / i).is_dir()])
PY

python3 - <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, str(Path(".").resolve()))
from tools.integrate_reconstruction_batch import NON_REPLAY_STATUSES, parse_batch_report

rows = parse_batch_report(Path("docs/tmp/reconstruction-batch-33.md"))
classes = sorted({r.classification for r in rows if r.classification != "replay_valid"})
print("non_admitted_classifications:", ", ".join(classes))
print("all_canonical:", all(c in NON_REPLAY_STATUSES for c in classes))
PY

python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-33.md --bench-root bpfix-bench
```

Results:

- Record Results contains exactly the 20 assigned Batch 33 IDs, once each.
- No assigned `bpfix-bench/cases/<raw_id>/` directories exist.
- Non-admitted classifications are canonical: `attempted_accepted`, `environment_required`, `missing_verifier_log`, `out_of_scope_non_verifier`.
- Integration dry run completed with `errors: []`.
- Blockers: none.
