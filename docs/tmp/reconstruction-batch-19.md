# Reconstruction Batch 19

Date: 2026-04-30

Scope:

- Assigned Batch 19 records only.
- Shared benchmark files, raw YAML records, `bpfix-bench/raw/index.yaml`, and
  `bpfix-bench/manifest.yaml` were not edited.
- No successful case directory was created.

## Summary

- Assigned records inspected: 20
- Local raw records present: 2
- Missing local raw records: 18
- Successful standalone verifier-reject reconstructions: 0
- Not admitted: 20

Only two assigned raw records are present in `bpfix-bench/raw/gh/` and
`bpfix-bench/raw/index.yaml`. Both available records lack captured verifier
logs and describe datapath behavior changes rather than an isolated
verifier-rejecting operation. The remaining assigned IDs have no local raw YAML
record and cannot be reconstructed under the batch raw-record rules.

## Record Results

| raw_id | outcome | classification | reason |
| --- | --- | --- | --- |
| `github-commit-cilium-e9da2245f9db` | no case | `out_of_scope_non_verifier` | Fixes hairpin flow behavior when `ENABLE_ROUTING` is disabled by tracking loopback service state and allowing local endpoint delivery; the raw record has no verifier log and the diff is runtime forwarding behavior, not a verifier-load failure. |
| `github-commit-cilium-ea389c71d4dd` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ea389c71d4dd.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-eb20259ef114` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-eb20259ef114.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-eb4f190c3c3d` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-eb4f190c3c3d.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ebff6fe1d724` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ebff6fe1d724.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ec11bbad050e` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ec11bbad050e.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ecd779a186fd` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ecd779a186fd.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ecdc494d15b1` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ecdc494d15b1.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ed031dac8f27` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ed031dac8f27.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-ed809e2943be` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-ed809e2943be.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-efd1ad80bd4e` | no case | `out_of_scope_non_verifier` | Changes NAT handling for unknown IPv4/IPv6 protocols from `DROP_NAT_UNSUPP_PROTO` to `NAT_PUNT_TO_STACK`; the raw record has no verifier log and the changed branch is packet-processing behavior, not verifier rejection. |
| `github-commit-cilium-efdff37aaabf` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-efdff37aaabf.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f1f8614fec32` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f1f8614fec32.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f2ca2cd847d8` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f2ca2cd847d8.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f31a2fc8d683` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f31a2fc8d683.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f61c1f66c34f` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f61c1f66c34f.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f63a3dadc379` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f63a3dadc379.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f6d58aab7ada` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f6d58aab7ada.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f94e1b5c8835` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f94e1b5c8835.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |
| `github-commit-cilium-f9fc987ba23b` | no case | `missing_source` | No local `bpfix-bench/raw/gh/github-commit-cilium-f9fc987ba23b.yaml` record exists and the ID is absent from `bpfix-bench/raw/index.yaml`. |

## Commands Run

Context and raw inspection:

```bash
git status --short
rg -n "github-commit-cilium-..." bpfix-bench/raw bpfix-bench/cases docs/tmp
git ls-files bpfix-bench/raw/gh/<assigned-id>.yaml
sed -n '1,260p' bpfix-bench/raw/gh/github-commit-cilium-e9da2245f9db.yaml
sed -n '1,260p' bpfix-bench/raw/gh/github-commit-cilium-efd1ad80bd4e.yaml
python3 - <<'PY'
# Loaded the two present raw YAML records and summarized title, date, fix_type,
# verifier-log presence, source snippet count, and diff summary.
PY
```

No `make clean`, `make`, or `make replay-verify` commands were run for an
admitted case because no assigned record produced a candidate standalone
verifier-reject reconstruction.

## Review

- Confirmed the report covers 20 assigned raw IDs exactly once; no duplicate
  table entries were found.
- Confirmed no `bpfix-bench/cases/<raw_id>` directory exists for any assigned
  Batch 19 ID.
- Confirmed only `github-commit-cilium-e9da2245f9db` and
  `github-commit-cilium-efd1ad80bd4e` have local raw YAML and
  `bpfix-bench/raw/index.yaml` entries; the other 18 IDs are absent from both.
- Sanity-checked all non-admitted rows have a concrete final classification and
  reason. The two local raw records are classified as
  `out_of_scope_non_verifier` because they have no captured verifier log and
  their diffs describe runtime datapath behavior; the 18 absent records are
  classified as `missing_source`.
