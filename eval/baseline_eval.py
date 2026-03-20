#!/usr/bin/env python3
"""Run the regex baseline over the labeled benchmark slice."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.baseline import generate_baseline_diagnostic
from eval.ablation_eval import (
    DEFAULT_MANIFEST_PATH,
    build_case_path_index,
    extract_verifier_log,
    iter_eligible_entries,
    load_yaml,
)


DEFAULT_LABELS_PATH = ROOT / "case_study" / "ground_truth.yaml"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "baseline_results.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--labels-path", type=Path, default=DEFAULT_LABELS_PATH)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument(
        "--print-every",
        type=int,
        default=25,
        help="Progress logging interval.",
    )
    return parser.parse_args()


def labeled_case_ids(labels_path: Path) -> set[str]:
    payload = load_yaml(labels_path) or {}
    rows = payload.get("cases", []) if isinstance(payload, dict) else payload
    return {
        str(row["case_id"])
        for row in rows
        if isinstance(row, dict) and row.get("case_id") and not row.get("quarantined")
    }


def _metadata(json_data: dict[str, Any]) -> dict[str, Any]:
    metadata = json_data.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _proof_span_count(json_data: dict[str, Any]) -> int:
    proof_spans = _metadata(json_data).get("proof_spans")
    return len(proof_spans) if isinstance(proof_spans, list) else 0


def main() -> int:
    args = parse_args()
    labeled_ids = labeled_case_ids(args.labels_path)
    case_paths = build_case_path_index()
    entries = [
        entry
        for entry in iter_eligible_entries(args.manifest_path)
        if str(entry.get("case_id")) in labeled_ids
    ]

    results: list[dict[str, Any]] = []
    total = len(entries)
    for idx, entry in enumerate(entries, start=1):
        case_id = str(entry["case_id"])
        case_path = case_paths.get(case_id)
        if case_path is None:
            raise FileNotFoundError(f"unable to locate case file for {case_id}")

        case_data = load_yaml(case_path) or {}
        verifier_log = extract_verifier_log(case_data)
        output = generate_baseline_diagnostic(verifier_log)
        json_data = output.json_data if isinstance(output.json_data, dict) else {}
        metadata = _metadata(json_data)
        candidate_repairs = json_data.get("candidate_repairs")
        primary_repair = candidate_repairs[0] if isinstance(candidate_repairs, list) and candidate_repairs else {}

        results.append(
            {
                "case_id": case_id,
                "case_path": str(case_path),
                "source": str(entry.get("source") or ""),
                "error_id": str(json_data.get("error_id") or "BPFIX-UNKNOWN"),
                "taxonomy": str(
                    json_data.get("taxonomy_class")
                    or json_data.get("failure_class")
                    or "source_bug"
                ),
                "message": str(json_data.get("message") or ""),
                "proof_status": str(metadata.get("proof_status") or "unknown"),
                "spans": _proof_span_count(json_data),
                "source_span": json_data.get("source_span"),
                "repair_hint": (
                    str(primary_repair.get("patch_hint") or primary_repair.get("rationale") or "")
                    if isinstance(primary_repair, dict)
                    else ""
                ),
            }
        )

        if args.print_every > 0 and (idx % args.print_every == 0 or idx == total):
            print(f"[baseline] {idx}/{total} cases")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "results": results,
    }
    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    with args.results_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")

    print(f"Wrote {args.results_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
