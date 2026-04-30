# External Raw Corpus

This directory stores every collected external SO/GH candidate, including cases
that do not yet replay locally. Replayable verifier rejects are still admitted
only under `bpfix-bench/cases/`.

Layout:

- `so/stackoverflow-<question_id>.yaml`: Stack Overflow questions.
- `gh/github-<owner>-<repo>-<issue>.yaml`: GitHub issues.
- `gh/eval-<repo>-<commit>.yaml`: GitHub commit-derived candidates.
- `kernel_selftests/*.yaml`: kernel selftest verifier-log fixtures retained from the same unified bench root.
- `index.yaml`: generated summary linking raw records to replayable cases.

Each raw record uses `schema_version: bpfix.raw_external/v1`:

```yaml
raw_id: stackoverflow-70750259
source_kind: stackoverflow        # stackoverflow | github_issue | github_commit
source:
  url: https://stackoverflow.com/questions/70750259
  title: ...
collector:
  original_path: bpfix-bench/raw/so/stackoverflow-70750259.yaml
content:
  has_verifier_log: true
  source_snippet_count: 2
reproduction:
  status: replay_valid
  case_path: cases/stackoverflow-70750259
  artifact_path: null
raw:
  ...
```

`reproduction.status` values:

- `replay_valid`: admitted to `bpfix-bench/cases/`.
- `replay_valid_pending_import`: locally rebuilds and rejects with a trace-rich
  verifier log, but is not yet in `cases/`.
- `replay_reject_no_rejected_insn`: locally rejects before any instruction is
  processed; useful raw evidence, but excluded from strict case admission.
- `attempted_accepted`: reconstructed artifact builds and loads successfully on
  the pinned environment.
- `attempted_failed` / `attempted_unknown`: reconstruction was tried but did not
  produce a strict replayable verifier-reject case.
- `not_attempted`: collected raw material with no local reconstruction attempt.

Policy:

- Raw inclusion means only “collected external evidence”, not benchmark
  admission.
- `cases/` inclusion requires fresh local replay that builds and is rejected by
  the pinned verifier/toolchain.
- `raw/index.yaml` is the audit surface for counting collected, reproduced, and
  unreproduced external material.

Regenerate:

```bash
python3 tools/sync_external_raw_bench.py --apply
```
