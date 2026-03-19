# v3 Eval Integration Summary

## Duplicate Analysis

- Reviewed all `43` Stack Overflow v3-core cases and all `11` GitHub v3-core cases listed in `docs/tmp/labeling_case_ids.txt`.
- Added a reproducible analyzer at `docs/tmp/labeling-review/analyze_dedup.py`.
- Wrote the pairwise review to `docs/tmp/labeling-review/dedup_analysis.md`.
- Confirmed `1` Stack Overflow near-duplicate pair over the `0.70` threshold:
  - `stackoverflow-70750259`
  - `stackoverflow-70760516`
- Confirmed `0` GitHub near-duplicate pairs over the threshold.

## Eval Pipeline Changes

- Copied `docs/tmp/labeling-review/ground_truth_v3.yaml` to `case_study/ground_truth_v3.yaml`.
- Updated `eval/comparison_report.py` so the default labels resolution now prefers `ground_truth_v3.yaml`, then falls back to `ground_truth_v2.yaml`, then to the legacy `ground_truth_labels.yaml`.
- Updated the CLI help text and input-section note in `eval/comparison_report.py` so the report reflects the v3 default.
- Checked `eval/batch_diagnostic_eval.py`; it does not reference any ground-truth file, so no code change was required there.

## Manifest Changes

- Added the same `duplicate_group` value to the confirmed Stack Overflow duplicate pair in `case_study/eval_manifest.yaml`:
  - `TLS SNI XDP parser near-duplicate (collect_ips_prog / server_name extraction)`
- Left `core_representative` unchanged because the current manifest-generation logic only auto-manages representatives for `kernel_selftests`.

## Verification

- `make eval-batch`: passed.
  - Rebuilt `eval/results/batch_diagnostic_results.json`
  - Rebuilt `docs/tmp/batch-diagnostic-eval.md`
- `python -m pytest tests/ -x -q`: passed with `391 passed, 5 skipped in 22.65s`.
- Extra sanity check: `python eval/comparison_report.py` passed and wrote `docs/tmp/comparison-report-2026-03-18.md` using the new default-label resolution.
