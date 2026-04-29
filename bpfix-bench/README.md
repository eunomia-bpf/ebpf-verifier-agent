# bpfix-bench

Top-level replayable benchmark for verifier-failure diagnosis.

The only discovery entry point is `manifest.yaml`. A case is in `split: main`
only if it has a self-contained case directory and passes replay validation in
the pinned environment.

Current snapshot:

- 100 main cases
- 79 kernel selftest cases
- 21 exact/partial Stack Overflow cases
- 1 replay-valid commit-derived candidate case excluded from headline eval pending
  stronger provenance review

Required admission check:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Expected local result for this snapshot:

```text
passed: 100
failed: 0
```
