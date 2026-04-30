# Reconstruction Batch 24

Date: 2026-04-30

Scope:

- Assigned Batch 24 raw records only.
- Edited only this report and the admitted case directory under
  `bpfix-bench/cases/<assigned raw id>/`.
- Did not edit `bpfix-bench/manifest.yaml`, `bpfix-bench/raw/index.yaml`, or
  any `bpfix-bench/raw/*.yaml` file.

## Summary

- Assigned records inspected: 20
- Local raw records present: 20
- Successful standalone verifier-reject reconstructions: 1
- Attempted but accepted by the local verifier: 1
- Not admitted: 19

One record produced a local replayable verifier reject on
`kernel-6.15.11-clang-18-log2`:

- `github-commit-cilium-06c6520c57ad`: Cilium packet data revalidation around
  `skb_pull_data()`. Fresh replay rejects with `invalid access to packet,
  off=14 size=1, R1(id=0,off=14,r=0)`.

Most remaining records have no raw verifier log and depend on historical Cilium
macro expansion, kernel-version complexity behavior, LLVM code generation, or
large multi-file context that cannot be faithfully reduced from the stored diff
snippets. The `0cf109933350` stack-alignment pattern was probed locally and
accepted on the current kernel.

## Successful Replays

| case_id | command result | parsed verifier outcome |
| --- | --- | --- |
| `github-commit-cilium-06c6520c57ad` | `make clean` 0; `make` 0; `make replay-verify` 2 (`bpftool` 255 verifier reject) | `log_quality=trace_rich`; `terminal_error="invalid access to packet, off=14 size=1, R1(id=0,off=14,r=0)"`; `rejected_insn_idx=24` |

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-01af42293701` | no case | `out_of_scope_non_verifier` | Commit removes an ICMPv6 debug `printk`; raw record has no verifier log and the change is not a verifier-rejected program shape. |
| `github-commit-cilium-0279a19a34bd` | no case | `environment_required` | Commit describes a 4.19 complexity issue when IPv6 is disabled; replay requires Cilium's historical tail-call/macro environment and no raw verifier log is present. |
| `github-commit-cilium-02e696c855cf` | no case | `out_of_scope_non_verifier` | Commit fixes an LLVM signed-division/codegen failure in port clamping, not a kernel verifier rejection; no replayable verifier log is present. |
| `github-commit-cilium-036e5b2998c7` | no case | `not_reconstructable_from_diff` | Large nodeport/conntrack control-flow rewrite with no verifier log; stored snippets do not preserve enough surrounding Cilium state to build a faithful standalone reject. |
| `github-commit-cilium-040d264ebcd7` | no case | `not_reconstructable_from_diff` | Service-type macro cleanup touches socket programs and inline expansion; no verifier log, and the raw snippets are insufficient for a local semantic replay. |
| `github-commit-cilium-064b947efb86` | no case | `not_reconstructable_from_diff` | 16-bit ifindex fix spans Cilium common state and generated program context; no verifier log and no faithful standalone source could be derived from the excerpt. |
| `github-commit-cilium-06751f2adeb1` | no case | `not_reconstructable_from_diff` | Conntrack `ct_state` forwarding change lacks the full map/value and caller context needed to reproduce the verifier-visible behavior. |
| `github-commit-cilium-06c6520c57ad` | admitted | `replay_valid` | Added local TC replay for packet data revalidation after `skb_pull_data()`; fresh verifier rejection is trace-rich and parser reports terminal error plus rejected instruction index. |
| `github-commit-cilium-06efc21b8c4f` | no case | `environment_required` | Prefix-length reduction is a historical verifier-complexity/configuration issue; no concrete verifier log or standalone failing source is present. |
| `github-commit-cilium-08b8b1b383bb` | no case | `out_of_scope_non_verifier` | Marker remapping avoids semantic conflicts with other skb marks; raw record has no verifier log and does not identify a verifier-rejected source pattern. |
| `github-commit-cilium-0a4a393d6554` | no case | `environment_required` | SO_NETNS_COOKIE helper/configuration change depends on Cilium socket-program build settings and helper availability; no raw verifier log is present. |
| `github-commit-cilium-0aa0f68b0765` | no case | `not_reconstructable_from_diff` | Large load-balancer/conntrack change mentions separate verifier rejects, but the stored snippets do not isolate a faithful rejected program. A simple null-lookup probe was rejected locally but did not match the upstream state-propagation change, so it was not admitted. |
| `github-commit-cilium-0ab817e77209` | no case | `not_reconstructable_from_diff` | Nodeport local-backend tracking change depends on Cilium tail-call/test harness context; no verifier log and no standalone faithful reducer. |
| `github-commit-cilium-0ae984552b8f` | no case | `environment_required` | Builtin memcpy/address-copy codegen behavior depends on compiler and Cilium program layout; raw record has no verifier log. |
| `github-commit-cilium-0b4ddce50b57` | no case | `environment_required` | Helper/config default change depends on historical supported-helper configuration; no concrete verifier log or replayable source. |
| `github-commit-cilium-0bb85f7e805d` | no case | `environment_required` | Potential nodeport complexity issue depends on Cilium feature matrix and generated control flow; no local standalone reject was derived. |
| `github-commit-cilium-0bf33f653d79` | no case | `out_of_scope_non_verifier` | LLVM 7 migration/API macro change is a compiler/build-environment update, not a specific verifier reject with a replayable log. |
| `github-commit-cilium-0cf109933350` | no case | `attempted_accepted` | A local probe for the packed `union v6addr old_daddr` stack-alignment pattern built and loaded without a verifier terminal error on kernel 6.15.11. |
| `github-commit-cilium-0d513f3ae2a2` | no case | `not_reconstructable_from_diff` | Security-identity mark rewrite and policy snippets do not identify a standalone verifier-rejected access; no raw verifier log is present. |
| `github-commit-cilium-0d89f055806d` | no case | `environment_required` | Encryption/FIB-helper fallback behavior depends on helper support and Cilium build configuration; no concrete verifier log or standalone replay source is present. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg --files docs bpfix-bench
find bpfix-bench/cases -maxdepth 2 -type f
rg -n "<assigned-id>|<short-sha>" bpfix-bench/raw docs/evaluation docs/tmp
python3 - <<'PY'
# loaded each assigned bpfix-bench/raw/gh/<id>.yaml and printed commit title,
# date, fix_type, content flags, snippet lengths, and diff summary
PY
sed -n '1,220p' docs/tmp/reconstruction-batch-23.md
sed -n '1,140p' bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/{Makefile,prog.c,case.yaml,capture.yaml}
curl -L --max-time 20 -s https://github.com/cilium/cilium/commit/<sha>.patch
```

Temporary local probes:

```bash
# 06c packet data revalidation probe in /tmp/bpfix-b24-probes/06c
make -C /tmp/bpfix-b24-probes/06c clean
make -C /tmp/bpfix-b24-probes/06c
make -C /tmp/bpfix-b24-probes/06c replay-verify

# 0cf packed union stack-alignment probe in /tmp/bpfix-b24-probes/0cf
make -C /tmp/bpfix-b24-probes/0cf clean
make -C /tmp/bpfix-b24-probes/0cf
make -C /tmp/bpfix-b24-probes/0cf replay-verify

# 0aa null-map probe, rejected locally but not faithful to the upstream diff
make -C /tmp/bpfix-b24-probes/0aa clean
make -C /tmp/bpfix-b24-probes/0aa
make -C /tmp/bpfix-b24-probes/0aa replay-verify
```

Admitted case validation:

```bash
cd bpfix-bench/cases/github-commit-cilium-06c6520c57ad
make clean
make
make replay-verify

python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("bpfix-bench/cases/github-commit-cilium-06c6520c57ad/replay-verifier.log")
print(parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
PY
```

Parser result:

```text
github-commit-cilium-06c6520c57ad ParsedVerifierLog(terminal_error='invalid access to packet, off=14 size=1, R1(id=0,off=14,r=0)', rejected_insn_idx=24, log_quality='trace_rich', source='bpfix-bench/cases/github-commit-cilium-06c6520c57ad/replay-verifier.log')
```

## Review

Reviewed on 2026-04-30.

Commands run:

```bash
rg -n "Batch 24|Record Results|github-commit-cilium-06c6520c57ad|^\|" docs/tmp/reconstruction-batch-24.md
sed -n '1,170p' tools/integrate_reconstruction_batch.py
sed -n '1,180p' docs/tmp/reconstruction-batch-24.md
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/case.yaml
sed -n '1,220p' bpfix-bench/cases/github-commit-cilium-06c6520c57ad/capture.yaml
python3 - <<'PY'
from pathlib import Path
from collections import Counter
p = Path("docs/tmp/reconstruction-batch-24.md")
rows = []
in_table = False
for line in p.read_text().splitlines():
    if line.startswith("## "):
        in_table = line.strip() == "## Record Results"
        continue
    if in_table and line.startswith("|"):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] not in ("raw_id", "---") and not set(cells[0]) <= {"-"}:
            rows.append(cells[0])
print("rows", len(rows))
print("unique", len(set(rows)))
print("duplicates", [x for x, n in Counter(rows).items() if n > 1])
for row in rows:
    print(row)
PY
python3 tools/integrate_reconstruction_batch.py docs/tmp/reconstruction-batch-24.md --bench-root bpfix-bench
cd bpfix-bench/cases/github-commit-cilium-06c6520c57ad
make clean
make
make replay-verify
cd -
python3 - <<'PY'
from pathlib import Path
from tools.replay_case import parse_verifier_log
p = Path("bpfix-bench/cases/github-commit-cilium-06c6520c57ad/replay-verifier.log")
print(parse_verifier_log(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
PY
tail -n 80 bpfix-bench/cases/github-commit-cilium-06c6520c57ad/replay-verifier.log
git status --short
```

Findings:

- Record Results contains exactly 20 rows and 20 unique raw IDs, with no duplicates.
- The admitted case `github-commit-cilium-06c6520c57ad` rebuilt cleanly: `make clean` exited 0, `make` exited 0, and `make replay-verify` exited 2 from `bpftool` verifier rejection.
- Parsed verifier output is trace-rich and matches `case.yaml`: `terminal_error="invalid access to packet, off=14 size=1, R1(id=0,off=14,r=0)"`, `rejected_insn_idx=24`, `log_quality=trace_rich`.
- `case.yaml` has `source.kind=github_commit`, `reproducer.reconstruction=reconstructed`, `external_match.status=not_applicable`, and `capture.log_quality=trace_rich`.
- Non-admitted classifications are canonical statuses accepted by `tools/integrate_reconstruction_batch.py`.
- Integration dry run completed with `errors: []`.

Post-review fix:

- `bpfix-bench/cases/github-commit-cilium-06c6520c57ad/capture.yaml` now uses
  `source_artifact.verifier_error_match: not_applicable`. The metadata blocker
  is resolved.
