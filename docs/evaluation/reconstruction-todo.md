# Reconstruction Todo

This is the working queue for turning raw external backlog records into strict
`bpfix-bench/cases/` entries. A record is admitted only if it can be rebuilt
locally and replayed to a verifier rejection with a captured verifier log.

Current queue:

- 591 non-admitted raw records to inspect for possible replay.
- 566 are `needs_manual_reconstruction`.
- 8 are `candidate_for_replay` and should be handled first.
- 17 are other non-admitted statuses worth checking opportunistically:
  `missing_source`, `missing_verifier_log`, or `environment_required`.

Because 591 records at 20 records per batch require 30 batches, the work is run
in waves of 3-4 reconstruction workers, followed by one review/fix worker per
wave. The user-requested 20-agent pass is therefore a first phase, not the full
queue.

## Admission Rule

A reconstructed case must contain at least:

```text
bpfix-bench/cases/<case_id>/
  Makefile
  prog.c
  case.yaml
```

and must pass local replay:

```bash
make
make replay-verify
python3 tools/validate_benchmark.py --replay bpfix-bench
```

The final validator may be run after manifest/index integration. During worker
batches, each new case must at least run its own `make` and `make replay-verify`
and capture `replay-verifier.log`.

## Worker Rules

- Do not edit `bpfix-bench/manifest.yaml`.
- Do not edit `bpfix-bench/raw/index.yaml`.
- Do not edit existing raw YAML records during worker batches.
- Write a batch report to `docs/tmp/reconstruction-batch-XX.md`.
- If a case is successfully reconstructed, create only
  `bpfix-bench/cases/<raw_id>/`.
- If a record cannot become a strict replayable verifier reject, record the
  proposed final status and reason in the batch report.
- Do not revert or overwrite edits from other workers.

## Review Rules

After each wave, a reviewer checks:

- every created case builds;
- every created case verifier-rejects locally;
- generated logs are trace-rich or at least contain a terminal verifier error;
- failed records have a defensible final status;
- shared files can be updated safely after review.

Only after review should the parent update `manifest.yaml`, raw records,
`raw/index.yaml`, and evaluation docs.

## Wave 1 Assignments

### Batch 01

Report: `docs/tmp/reconstruction-batch-01.md`

Records:

- `github-aya-rs-aya-864`
- `stackoverflow-48267671`
- `stackoverflow-62936008`
- `stackoverflow-68460177`
- `stackoverflow-70392721`
- `stackoverflow-77191387`
- `stackoverflow-77225068`
- `stackoverflow-79513583`
- `github-commit-aya-05c1586202ce`
- `github-commit-aya-11c227743de9`
- `github-commit-aya-1f3acbcfe0fb`
- `github-commit-aya-223e2f4ea1ef`
- `github-commit-aya-28abaece2af7`
- `github-commit-aya-29d539751a6d`
- `github-commit-aya-2ac433449cde`
- `github-commit-aya-2d79f22b4022`
- `github-commit-aya-2e0702854b0e`
- `github-commit-aya-32350f81b756`
- `github-commit-aya-3569c9afc3dc`
- `github-commit-aya-3cfd886dc512`

### Batch 02

Report: `docs/tmp/reconstruction-batch-02.md`

Records:

- `github-commit-aya-42c4d5c3af90`
- `github-commit-aya-628b473e0937`
- `github-commit-aya-62c6dfd764ce`
- `github-commit-aya-88f5ac31142f`
- `github-commit-aya-9be90f8a74de`
- `github-commit-aya-bce3c4fb1d0c`
- `github-commit-aya-bdb2750e66f9`
- `github-commit-aya-ca0c32d1076a`
- `github-commit-aya-d5e4e9270ae4`
- `github-commit-aya-f6606473af43`
- `github-commit-aya-fc69a0697274`
- `github-commit-bcc-02daf8d84ecd`
- `github-commit-bcc-0ae562c8862f`
- `github-commit-bcc-0cfd665b49d8`
- `github-commit-bcc-42c00adb4181`
- `github-commit-bcc-60b0166f8ed4`
- `github-commit-bcc-61230b2396f3`
- `github-commit-bcc-661711344d57`
- `github-commit-bcc-6ab97976d8fc`
- `github-commit-bcc-6cf0299ae5f8`

### Batch 03

Report: `docs/tmp/reconstruction-batch-03.md`

Records:

- `github-commit-bcc-7962f1389a96`
- `github-commit-bcc-80b1e778aa72`
- `github-commit-bcc-81a783a8f992`
- `github-commit-bcc-82f4302a651a`
- `github-commit-bcc-8cbc816aea77`
- `github-commit-bcc-93fad89ca457`
- `github-commit-bcc-ae6ed35ccf5c`
- `github-commit-bcc-b0b4239a6c3c`
- `github-commit-bcc-b9545a5ca101`
- `github-commit-bcc-b9a318729754`
- `github-commit-bcc-c6a3f0298ebf`
- `github-commit-bcc-ed827decb985`
- `github-commit-cilium-01af42293701`
- `github-commit-cilium-0279a19a34bd`
- `github-commit-cilium-02e696c855cf`
- `github-commit-cilium-036e5b2998c7`
- `github-commit-cilium-040d264ebcd7`
- `github-commit-cilium-064b947efb86`
- `github-commit-cilium-06751f2adeb1`
- `github-commit-cilium-06c6520c57ad`

### Batch 04

Report: `docs/tmp/reconstruction-batch-04.md`

Records:

- `github-commit-cilium-06efc21b8c4f`
- `github-commit-cilium-08b8b1b383bb`
- `github-commit-cilium-0a4a393d6554`
- `github-commit-cilium-0aa0f68b0765`
- `github-commit-cilium-0ab817e77209`
- `github-commit-cilium-0ae984552b8f`
- `github-commit-cilium-0b4ddce50b57`
- `github-commit-cilium-0bb85f7e805d`
- `github-commit-cilium-0bf33f653d79`
- `github-commit-cilium-0cf109933350`
- `github-commit-cilium-0d513f3ae2a2`
- `github-commit-cilium-0d89f055806d`
- `github-commit-cilium-0e7436369925`
- `github-commit-cilium-0f11ce8d87c2`
- `github-commit-cilium-1085ae269e71`
- `github-commit-cilium-108aa4212f8e`
- `github-commit-cilium-1119f7856f0c`
- `github-commit-cilium-11e5f5936631`
- `github-commit-cilium-126cc503abab`
- `github-commit-cilium-12e29221d278`
