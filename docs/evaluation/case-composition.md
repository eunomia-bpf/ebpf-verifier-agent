# bpfix-bench Case Composition

This document is limited to benchmark case composition. It describes the
snapshot rooted at `bpfix-bench/manifest.yaml` and the raw metadata under
`bpfix-bench/raw/` as present on 2026-04-29.

## Audit Commands

All counts below were computed from local YAML metadata, not from filenames.

Replayable cases, labels, and log quality:

```bash
python - <<'PY'
from pathlib import Path
from collections import Counter
import yaml

root = Path("bpfix-bench")
manifest = yaml.safe_load((root / "manifest.yaml").read_text())
cases = manifest["cases"]
case_docs = [
    yaml.safe_load((root / case["path"] / "case.yaml").read_text())
    for case in cases
]

print("manifest cases", len(cases))
print("manifest source_kind", dict(sorted(Counter(c["source_kind"] for c in cases).items())))
print("case source.kind", dict(sorted(Counter(d["source"]["kind"] for d in case_docs).items())))
print("log_quality", dict(sorted(Counter(d["capture"].get("log_quality", "<missing>") for d in case_docs).items())))
print("taxonomy_class", dict(sorted(Counter(d["label"].get("taxonomy_class", "<missing>") for d in case_docs).items())))
print("error_id", dict(sorted(Counter(d["label"].get("error_id", "<missing>") for d in case_docs).items())))
print("reproducer status", dict(sorted(Counter(d["reproducer"].get("status", "<missing>") for d in case_docs).items())))
print("load_status", dict(sorted(Counter(d["capture"].get("load_status", "<missing>") for d in case_docs).items())))
for field in ["taxonomy_class", "error_id", "fix_type"]:
    print("missing label." + field, sum(1 for d in case_docs if not d.get("label", {}).get(field)))
PY
```

External raw records and reproduction status:

```bash
python - <<'PY'
from pathlib import Path
from collections import Counter, defaultdict
import yaml

root = Path("bpfix-bench")
idx = yaml.safe_load((root / "raw/index.yaml").read_text())
entries = idx["entries"]

print("raw entries", len(entries))
print("raw by source_kind", dict(sorted(Counter(e["source_kind"] for e in entries).items())))
by = defaultdict(Counter)
for e in entries:
    by[e["source_kind"]][e["reproduction_status"]] += 1
for source_kind in sorted(by):
    print(source_kind, dict(sorted(by[source_kind].items())))
print("raw status total", dict(sorted(Counter(e["reproduction_status"] for e in entries).items())))
print("raw index counts", idx["counts"])
PY
```

Error names were joined from `taxonomy/error_catalog.yaml`:

```bash
python - <<'PY'
from pathlib import Path
from collections import Counter, defaultdict
import yaml

root = Path("bpfix-bench")
catalog = yaml.safe_load(Path("taxonomy/error_catalog.yaml").read_text())
names = {e["error_id"]: e["short_name"] for e in catalog["error_types"]}
manifest = yaml.safe_load((root / "manifest.yaml").read_text())
case_docs = [
    yaml.safe_load((root / case["path"] / "case.yaml").read_text())
    for case in manifest["cases"]
]
by_error = Counter(d["label"]["error_id"] for d in case_docs)
by_taxonomy = defaultdict(Counter)
for d in case_docs:
    by_taxonomy[d["label"]["error_id"]][d["label"]["taxonomy_class"]] += 1
for error_id, count in sorted(by_error.items()):
    print(error_id, names.get(error_id, "<missing>"), dict(by_taxonomy[error_id]), count)
PY
```

## Replayable Cases

`bpfix-bench/manifest.yaml` lists 186 replayable cases. Every listed case had a
loadable `case.yaml`, `reproducer.status: ready`, and
`capture.load_status: verifier_reject`.

| source_kind | replayable cases |
|---|---:|
| github_issue | 18 |
| kernel_selftest | 85 |
| stackoverflow | 83 |
| **total** | **186** |

All 186 manifest entries are marked `representative: true`.

## Log Quality

The replayable corpus currently has one log-quality class.

| log_quality | cases |
|---|---:|
| trace_rich | 186 |

No replayable `case.yaml` is missing `capture.log_quality`.

## Taxonomy Composition

Every replayable case has `label.taxonomy_class`, `label.error_id`, and
`label.fix_type`.

| taxonomy_class | cases |
|---|---:|
| source_bug | 141 |
| lowering_artifact | 29 |
| env_mismatch | 12 |
| verifier_limit | 4 |

Breakdown by source:

| source_kind | env_mismatch | lowering_artifact | source_bug | verifier_limit | total |
|---|---:|---:|---:|---:|---:|
| github_issue | 3 | 3 | 12 | 0 | 18 |
| kernel_selftest | 6 | 0 | 77 | 2 | 85 |
| stackoverflow | 3 | 26 | 52 | 2 | 83 |

## Error Categories

Error IDs are defined in `taxonomy/error_catalog.yaml`.

| error_id | short_name | case-label taxonomy_class | cases |
|---|---|---|---:|
| BPFIX-E001 | packet_bounds_missing | source_bug | 6 |
| BPFIX-E002 | nullable_map_value_dereference | source_bug | 4 |
| BPFIX-E003 | uninitialized_stack_read | source_bug | 3 |
| BPFIX-E004 | reference_lifetime_violation | source_bug | 3 |
| BPFIX-E005 | scalar_range_too_wide_after_lowering | lowering_artifact 28, source_bug 1 | 29 |
| BPFIX-E006 | provenance_lost_across_spill | lowering_artifact | 1 |
| BPFIX-E011 | scalar_pointer_dereference | source_bug | 48 |
| BPFIX-E012 | dynptr_protocol_violation | source_bug | 8 |
| BPFIX-E013 | execution_context_discipline_violation | source_bug | 13 |
| BPFIX-E014 | iterator_state_protocol_violation | source_bug | 6 |
| BPFIX-E015 | trusted_arg_nullability | source_bug | 9 |
| BPFIX-E016 | helper_or_kfunc_context_restriction | env_mismatch | 7 |
| BPFIX-E017 | map_value_bounds_violation | source_bug | 8 |
| BPFIX-E018 | verifier_analysis_budget_limit | verifier_limit | 4 |
| BPFIX-E019 | dynptr_storage_or_release_contract_violation | source_bug | 13 |
| BPFIX-E020 | irq_flag_state_protocol_violation | source_bug | 3 |
| BPFIX-E021 | btf_reference_metadata_missing | env_mismatch | 5 |
| BPFIX-E023 | register_or_stack_contract_violation | source_bug | 16 |

The taxonomy column above uses the labels in each `case.yaml`, not only the
default taxonomy in `taxonomy/error_catalog.yaml`. One `BPFIX-E005` case is
labelled `source_bug`; the other 28 are labelled `lowering_artifact`.

Notable concentration: `BPFIX-E011` accounts for 48 of 186 replayable cases,
and `BPFIX-E005` accounts for 29. Together they make up 77 cases, or 41.4% of
the replayable corpus.

## External Raw Records

`bpfix-bench/raw/index.yaml` is the audit surface for external Stack Overflow,
GitHub issue, and GitHub commit records. It contains 736 records.

| source_kind | raw records |
|---|---:|
| github_commit | 591 |
| github_issue | 31 |
| stackoverflow | 114 |
| **total** | **736** |

Reproduction status by external source:

| source_kind | replay_valid | replay_reject_no_rejected_insn | attempted_accepted | attempted_unknown | not_attempted | total |
|---|---:|---:|---:|---:|---:|---:|
| github_commit | 0 | 0 | 0 | 30 | 561 | 591 |
| github_issue | 18 | 3 | 0 | 4 | 6 | 31 |
| stackoverflow | 83 | 0 | 4 | 1 | 26 | 114 |
| **total** | **101** | **3** | **4** | **35** | **593** | **736** |

For this table, `replay_valid` is reproduced and admitted to
`bpfix-bench/cases/`. The other statuses are not admitted as strict replayable
cases in this snapshot. There are no `replay_valid_pending_import` or
`attempted_failed` records in `raw/index.yaml`.

The top-level raw directory also contains 201 YAML files under
`bpfix-bench/raw/kernel_selftests/`, but those files do not use the
`bpfix.raw_external/v1` schema and do not carry `reproduction.status`. Their
reproduced/unreproduced counts cannot be computed from the available raw
metadata. The replayable kernel selftest count is therefore taken from
`manifest.yaml` and `cases/*/case.yaml`: 85.

## Gaps and Biases

The replayable corpus is dominated by `source_bug` labels: 141 of 186 cases
(75.8%). `verifier_limit` has only 4 cases, and no replayable case is labeled
`verifier_bug`.

Kernel selftests are strongly represented in the admitted corpus: 85 of 186
cases. They are useful because they are reproducible and trace-rich, but they
are not independent user reports. They also skew toward selftest families visible
in case IDs, especially `dynptr` with 37 admitted cases and `irq` with 14.

External raw collection is much larger than the admitted external subset. Only
101 of 736 external raw records are `replay_valid`; 593 are `not_attempted`.
Most of that backlog is GitHub commit-derived material: 561 of 591
`github_commit` records are `not_attempted`, and none are `replay_valid`.

Stack Overflow contributes 83 replayable cases, but its admitted taxonomy is
concentrated: 25 Stack Overflow cases are `BPFIX-E005`, and 33 are
`BPFIX-E011`. This makes Stack Overflow valuable for scalar-range and
scalar-pointer failures, but less balanced for reference lifetime, dynptr
protocol, context discipline, and environment-mismatch categories.

All replayable logs are `trace_rich`. That is good for diagnostic evaluation,
but it means this snapshot does not measure behavior on sparse, truncated, or
terminal-error-only logs.

The raw external metadata records reproduction status for SO/GH/commit records,
but the kernel selftest raw fixtures do not. Because those fixture files lack
`reproduction.status`, this document cannot compute a reproduced/unreproduced
kernel-raw denominator from raw metadata.
