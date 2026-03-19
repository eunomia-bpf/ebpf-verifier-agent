#!/usr/bin/env python3
"""Merge localization annotations into the canonical ground-truth file."""

from __future__ import annotations

import argparse
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LABELS_PATH = ROOT / "case_study" / "ground_truth.yaml"
DEFAULT_LOCALIZATION_PATH = ROOT / "docs" / "tmp" / "labeling-review" / "localization_annotations.yaml"
TAXONOMY_ORDER = ("source_bug", "lowering_artifact", "verifier_limit", "env_mismatch", "verifier_bug")
CONFIDENCE_ORDER = ("high", "medium", "low")
LOCALIZATION_FIELDS = (
    "rejected_insn_idx",
    "root_cause_insn_idx",
    "rejected_line",
    "root_cause_line",
    "has_btf_annotations",
    "distance_insns",
    "localization_confidence",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels-path", type=Path, default=DEFAULT_LABELS_PATH)
    parser.add_argument("--localization-path", type=Path, default=DEFAULT_LOCALIZATION_PATH)
    parser.add_argument(
        "--drop-case",
        action="append",
        default=[],
        help="Case ID to remove from the merged ground truth. May be repeated.",
    )
    parser.add_argument(
        "--quarantine-case",
        action="append",
        default=[],
        metavar="CASE_ID=REASON",
        help="Mark a case as quarantined with the provided reason. May be repeated.",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def dump_yaml(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=False)


def parse_quarantine_args(values: list[str]) -> dict[str, str]:
    quarantines: dict[str, str] = {}
    for value in values:
        case_id, sep, reason = value.partition("=")
        if not sep or not case_id or not reason:
            raise ValueError(f"Invalid --quarantine-case value: {value!r}")
        quarantines[case_id] = reason
    return quarantines


def ordered_counter(counter: Counter[str], order: tuple[str, ...]) -> dict[str, int]:
    result = {key: int(counter.get(key, 0)) for key in order}
    extras = sorted(key for key in counter if key not in result)
    for key in extras:
        result[key] = int(counter[key])
    return result


def merge_cases(
    labels_cases: list[dict[str, Any]],
    localization_cases: list[dict[str, Any]],
    dropped_cases: set[str],
    quarantines: dict[str, str],
) -> list[dict[str, Any]]:
    localization_by_id = {
        str(row["case_id"]): row
        for row in localization_cases
        if isinstance(row, dict) and row.get("case_id")
    }

    merged: list[dict[str, Any]] = []
    for case in labels_cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id"))
        if not case_id:
            continue
        if case_id in dropped_cases:
            continue

        localization = localization_by_id.get(case_id)
        if localization is None:
            raise KeyError(f"Missing localization annotation for {case_id}")

        merged_case = dict(case)
        for field in LOCALIZATION_FIELDS:
            if field not in localization:
                raise KeyError(f"Missing localization field {field!r} for {case_id}")
            merged_case[field] = localization[field]

        if case_id in quarantines:
            merged_case["quarantined"] = True
            merged_case["quarantine_reason"] = quarantines[case_id]

        merged.append(merged_case)

    return merged


def build_metadata(
    base_metadata: dict[str, Any],
    merged_cases: list[dict[str, Any]],
    localization_metadata: dict[str, Any],
    localization_path: Path,
) -> dict[str, Any]:
    metadata = dict(base_metadata)
    metadata["total_cases"] = len(merged_cases)

    taxonomy_counts = Counter(str(case.get("taxonomy_class") or "unknown") for case in merged_cases)
    metadata["taxonomy_counts"] = ordered_counter(taxonomy_counts, TAXONOMY_ORDER)

    confidence_counts = Counter(str(case.get("confidence") or "unknown") for case in merged_cases)
    metadata["confidence_counts"] = ordered_counter(confidence_counts, CONFIDENCE_ORDER)
    metadata["intentional_negative_test_cases"] = sum(
        1 for case in merged_cases if bool(case.get("is_intentional_negative_test"))
    )
    metadata["quarantined_cases"] = sum(1 for case in merged_cases if bool(case.get("quarantined")))

    distances = [int(case["distance_insns"]) for case in merged_cases if case.get("distance_insns") is not None]
    localization_confidence_counts = Counter(
        str(case.get("localization_confidence") or "unknown") for case in merged_cases
    )
    metadata["localization_stats"] = {
        "source": (
            str(localization_path.relative_to(ROOT))
            if localization_path.is_relative_to(ROOT)
            else str(localization_path)
        ),
        "date": localization_metadata.get("date"),
        "total_cases": len(merged_cases),
        "cases_with_btf": sum(1 for case in merged_cases if bool(case.get("has_btf_annotations"))),
        "cases_with_root_cause_before_reject": sum(
            1
            for case in merged_cases
            if case.get("root_cause_insn_idx") is not None
            and case.get("rejected_insn_idx") is not None
            and int(case["root_cause_insn_idx"]) < int(case["rejected_insn_idx"])
        ),
        "cases_with_nonzero_distance": sum(1 for case in merged_cases if int(case.get("distance_insns") or 0) > 0),
        "median_distance": int(statistics.median_low(distances)) if distances else 0,
        "localization_confidence_counts": ordered_counter(
            localization_confidence_counts, CONFIDENCE_ORDER
        ),
        "source_total_cases": localization_metadata.get("total_cases"),
        "source_cases_with_btf": localization_metadata.get("cases_with_btf"),
        "source_cases_with_root_cause_before_reject": localization_metadata.get(
            "cases_with_root_cause_before_reject"
        ),
        "source_median_distance": localization_metadata.get("median_distance"),
    }
    return metadata


def main() -> int:
    args = parse_args()
    dropped_cases = set(args.drop_case)
    quarantines = parse_quarantine_args(args.quarantine_case)

    labels_payload = load_yaml(args.labels_path) or {}
    localization_payload = load_yaml(args.localization_path) or {}

    labels_cases = list(labels_payload.get("cases") or [])
    localization_cases = list(localization_payload.get("cases") or [])

    merged_cases = merge_cases(labels_cases, localization_cases, dropped_cases, quarantines)
    labels_payload["metadata"] = build_metadata(
        dict(labels_payload.get("metadata") or {}),
        merged_cases,
        dict(localization_payload.get("metadata") or {}),
        args.localization_path,
    )
    labels_payload["cases"] = merged_cases
    dump_yaml(args.labels_path, labels_payload)

    print(f"Merged {len(merged_cases)} cases into {args.labels_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
