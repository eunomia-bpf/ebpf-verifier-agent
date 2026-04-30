# bpfix-bench

Top-level replayable benchmark for verifier-failure diagnosis.

The only discovery entry point is `manifest.yaml`. Every listed case has a
self-contained case directory and must pass replay validation in the pinned
environment. External SO/GH/commit material, including unreproduced candidates,
is archived under `raw/`.

Current snapshot:

- 186 replayable cases
- 85 kernel selftest cases
- 83 Stack Overflow cases
- 18 GitHub issue cases
- 736 raw external SO/GH/commit records under `raw/so` and `raw/gh`
- 200 kernel-selftest raw log fixtures under `raw/kernel_selftests`

Required admission check:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Expected local result for this snapshot:

```text
passed: 186
failed: 0
```

External raw audit:

```bash
python3 tools/sync_external_raw_bench.py --apply
```

`raw/index.yaml` records how many collected external records are replay-valid,
not attempted, accepted on the pinned environment, or rejected without a
rejected instruction index.
