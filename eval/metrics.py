#!/usr/bin/env python3
"""Skeleton metrics utilities for BPFix evaluation."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TrialResult:
    case_id: str
    condition: str
    verifier_pass: bool
    semantic_pass: bool
    iterations: int
    wall_clock_seconds: float
    failure_class: str | None = None


def load_results(path: Path) -> list[TrialResult]:
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix == ".jsonl":
            rows = [json.loads(line) for line in handle if line.strip()]
        else:
            payload = json.load(handle)
            rows = payload if isinstance(payload, list) else payload.get("results", [])

    return [
        TrialResult(
            case_id=row["case_id"],
            condition=row["condition"],
            verifier_pass=bool(row["verifier_pass"]),
            semantic_pass=bool(row["semantic_pass"]),
            iterations=int(row["iterations"]),
            wall_clock_seconds=float(row["wall_clock_seconds"]),
            failure_class=row.get("failure_class"),
        )
        for row in rows
    ]


def success_rate(results: list[TrialResult]) -> float:
    if not results:
        return 0.0
    return sum(1 for result in results if result.verifier_pass) / len(results)


def semantic_pass_rate(results: list[TrialResult]) -> float:
    if not results:
        return 0.0
    return sum(1 for result in results if result.semantic_pass) / len(results)


def mean_iterations_to_success(results: list[TrialResult]) -> float:
    successful = [result.iterations for result in results if result.verifier_pass]
    if not successful:
        return 0.0
    return statistics.mean(successful)


def median_wall_clock(results: list[TrialResult]) -> float:
    if not results:
        return 0.0
    return statistics.median(result.wall_clock_seconds for result in results)


def summarize(results: list[TrialResult], group_by: str) -> dict[str, Any]:
    grouped: dict[str, list[TrialResult]] = {}
    for result in results:
        key = getattr(result, group_by) or "unknown"
        grouped.setdefault(key, []).append(result)

    summary: dict[str, Any] = {}
    for key, bucket in sorted(grouped.items()):
        summary[key] = {
            "count": len(bucket),
            "success_rate": success_rate(bucket),
            "semantic_pass_rate": semantic_pass_rate(bucket),
            "mean_iterations_to_success": mean_iterations_to_success(bucket),
            "median_wall_clock_seconds": median_wall_clock(bucket),
        }
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compute aggregate metrics for BPFix evaluations.")
    parser.add_argument("results", type=Path, help="Path to a JSON or JSONL results file.")
    parser.add_argument(
        "--group-by",
        choices=("condition", "failure_class"),
        default="condition",
        help="Field used to aggregate results.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    results = load_results(args.results)
    summary = summarize(results, args.group_by)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
