# bpfix-bench

Top-level replayable benchmark for verifier-failure diagnosis.

The only discovery entry point is `manifest.yaml`. Every listed case has a
self-contained case directory and must pass replay validation in the pinned
environment. Non-primary candidates stay outside `bpfix-bench`.

Current snapshot:

- 102 replayable cases
- 79 kernel selftest cases
- 23 Stack Overflow cases: 21 exact/partial matches and 2 replay-valid semantic
  matches

Required admission check:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Expected local result for this snapshot:

```text
passed: 102
failed: 0
```
