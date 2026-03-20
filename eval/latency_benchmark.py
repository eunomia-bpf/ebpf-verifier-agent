#!/usr/bin/env python3
"""Benchmark end-to-end BPFix diagnostic latency."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from batch_diagnostic_eval import MIN_LOG_CHARS, extract_verifier_log, iter_case_files, read_yaml
from interface.extractor import rust_diagnostic


DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "latency_benchmark.json"
EXPECTED_ELIGIBLE_CASES = 262
TOTAL_STAGE = "generate_diagnostic"
STAGE_ORDER: tuple[str, ...] = (TOTAL_STAGE,)


@dataclass(slots=True)
class CaseLatency:
    case_id: str
    case_path: str
    source: str
    source_dir: str
    verifier_log_chars: int
    verifier_log_lines: int
    success: bool
    exception: str | None
    timings_ms: dict[str, float | None]
    stage_call_counts: dict[str, int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help=f"Where to write raw JSON results (default: {DEFAULT_RESULTS_PATH})",
    )
    parser.add_argument(
        "--min-log-chars",
        type=int,
        default=MIN_LOG_CHARS,
        help=f"Minimum verifier log length to benchmark (default: {MIN_LOG_CHARS})",
    )
    return parser.parse_args()


def ns_to_ms(duration_ns: int | None) -> float | None:
    if duration_ns is None:
        return None
    return duration_ns / 1_000_000.0


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def pearson_correlation(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    centered_x = [value - mean_x for value in xs]
    centered_y = [value - mean_y for value in ys]
    denom_x = math.sqrt(sum(value * value for value in centered_x))
    denom_y = math.sqrt(sum(value * value for value in centered_y))
    if denom_x == 0.0 or denom_y == 0.0:
        return None
    numerator = sum(x * y for x, y in zip(centered_x, centered_y))
    return numerator / (denom_x * denom_y)


def compute_stage_stats(values: list[float]) -> dict[str, float | int | None]:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min_ms": ordered[0] if ordered else None,
        "max_ms": ordered[-1] if ordered else None,
        "mean_ms": statistics.fmean(ordered) if ordered else None,
        "median_ms": statistics.median(ordered) if ordered else None,
        "p95_ms": percentile(ordered, 0.95),
        "p99_ms": percentile(ordered, 0.99),
    }


def benchmark_case(
    source: str,
    source_dir: str,
    path: Path,
    min_log_chars: int,
) -> CaseLatency | None:
    case_data = read_yaml(path)
    case_id = str(case_data.get("case_id") or path.stem)
    verifier_log = extract_verifier_log(case_data)
    verifier_log_chars = len(verifier_log)
    verifier_log_lines = len(verifier_log.splitlines())

    if verifier_log_chars < min_log_chars:
        return None

    stage_call_counts: dict[str, int] = {TOTAL_STAGE: 1}
    start_ns = perf_counter_ns()

    try:
        rust_diagnostic.generate_diagnostic(verifier_log)
    except Exception as exc:  # pragma: no cover - benchmark should continue on failures.
        total_elapsed_ns = perf_counter_ns() - start_ns
        timings_ms = {TOTAL_STAGE: ns_to_ms(total_elapsed_ns)}
        return CaseLatency(
            case_id=case_id,
            case_path=str(path),
            source=source,
            source_dir=source_dir,
            verifier_log_chars=verifier_log_chars,
            verifier_log_lines=verifier_log_lines,
            success=False,
            exception=f"{type(exc).__name__}: {exc}",
            timings_ms=timings_ms,
            stage_call_counts=dict(stage_call_counts),
        )

    total_elapsed_ns = perf_counter_ns() - start_ns
    timings_ms = {TOTAL_STAGE: ns_to_ms(total_elapsed_ns)}
    return CaseLatency(
        case_id=case_id,
        case_path=str(path),
        source=source,
        source_dir=source_dir,
        verifier_log_chars=verifier_log_chars,
        verifier_log_lines=verifier_log_lines,
        success=True,
        exception=None,
        timings_ms=timings_ms,
        stage_call_counts=dict(stage_call_counts),
    )


def build_stage_summary(results: list[CaseLatency]) -> dict[str, dict[str, float | int | None]]:
    successful = [result for result in results if result.success]
    return {
        stage: compute_stage_stats(
            [
                value
                for result in successful
                for value in [result.timings_ms.get(stage)]
                if value is not None
            ]
        )
        for stage in STAGE_ORDER
    }


def format_ms(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.3f}"


def build_summary_table(stage_summary: dict[str, dict[str, float | int | None]]) -> str:
    headers = ("Stage", "min", "median", "mean", "p95", "p99", "max")
    rows = [
        (
            stage,
            format_ms(stats["min_ms"]),
            format_ms(stats["median_ms"]),
            format_ms(stats["mean_ms"]),
            format_ms(stats["p95_ms"]),
            format_ms(stats["p99_ms"]),
            format_ms(stats["max_ms"]),
        )
        for stage, stats in ((stage, stage_summary[stage]) for stage in STAGE_ORDER)
    ]
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * widths[index] for index in range(len(headers))),
    ]
    lines.extend(
        "  ".join(
            value.ljust(widths[index]) if index == 0 else value.rjust(widths[index])
            for index, value in enumerate(row)
        )
        for row in rows
    )
    return "\n".join(lines)


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    args = parse_args()
    generated_at = datetime.now(timezone.utc).isoformat()
    case_files = iter_case_files()
    benchmarked: list[CaseLatency] = []
    skipped = 0

    total = len(case_files)
    for index, (source, source_dir, path) in enumerate(case_files, start=1):
        result = benchmark_case(source, source_dir, path, args.min_log_chars)
        if result is None:
            skipped += 1
        else:
            benchmarked.append(result)
        if index % 50 == 0 or index == total:
            print(f"[latency_benchmark] processed {index}/{total} cases", flush=True)

    eligible = len(benchmarked)
    if eligible != EXPECTED_ELIGIBLE_CASES:
        print(
            f"[latency_benchmark] warning: expected {EXPECTED_ELIGIBLE_CASES} eligible cases, got {eligible}",
            flush=True,
        )

    successes = [result for result in benchmarked if result.success]
    failures = [result for result in benchmarked if not result.success]
    stage_summary = build_stage_summary(benchmarked)
    correlation_pairs = [
        (float(result.verifier_log_lines), float(result.timings_ms[TOTAL_STAGE]))
        for result in successes
        if result.timings_ms[TOTAL_STAGE] is not None
    ]
    correlation = pearson_correlation(
        [lines for lines, _ in correlation_pairs],
        [latency for _, latency in correlation_pairs],
    )
    slowest_cases = sorted(
        (
            result
            for result in successes
            if result.timings_ms[TOTAL_STAGE] is not None
        ),
        key=lambda item: float(item.timings_ms[TOTAL_STAGE]),
        reverse=True,
    )[:10]

    print(
        f"[latency_benchmark] eligible={eligible} successes={len(successes)} failures={len(failures)} skipped={skipped}",
        flush=True,
    )
    print("[latency_benchmark] stage latency summary (ms)", flush=True)
    print(build_summary_table(stage_summary), flush=True)
    if correlation is None:
        print("[latency_benchmark] log-lines vs total-latency Pearson r = n/a", flush=True)
    else:
        print(
            f"[latency_benchmark] log-lines vs total-latency Pearson r = {correlation:.4f}",
            flush=True,
        )
    if slowest_cases:
        print("[latency_benchmark] slowest cases by total latency", flush=True)
        for result in slowest_cases[:5]:
            total_ms = result.timings_ms[TOTAL_STAGE]
            print(
                f"  - {result.case_id}: {total_ms:.3f} ms ({result.verifier_log_lines} lines)",
                flush=True,
            )

    payload = {
        "generated_at": generated_at,
        "min_log_chars": args.min_log_chars,
        "totals": {
            "scanned": len(case_files),
            "eligible": eligible,
            "successes": len(successes),
            "failures": len(failures),
            "skipped": skipped,
        },
        "stage_summary_ms": stage_summary,
        "correlation": {
            "metric": "pearson_r",
            "x": "verifier_log_lines",
            "y": TOTAL_STAGE,
            "value": correlation,
        },
        "slowest_cases": [
            {
                "case_id": result.case_id,
                "source": result.source,
                "case_path": result.case_path,
                "verifier_log_lines": result.verifier_log_lines,
                "timings_ms": result.timings_ms,
            }
            for result in slowest_cases
        ],
        "results": [asdict(result) for result in benchmarked],
    }
    save_json(args.results_path, payload)
    print(f"[latency_benchmark] wrote results to {args.results_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
