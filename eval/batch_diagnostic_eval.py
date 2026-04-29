#!/usr/bin/env python3
"""Batch-evaluate the Rust diagnostic renderer across all case-study corpora."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.rust_diagnostic import generate_diagnostic
from eval.benchmark_loader import load_benchmark_rows


CASE_DIRS: tuple[tuple[str, str, Path], ...] = (
    (
        "selftests",
        "kernel_selftests",
        ROOT / "case_study" / "cases" / "kernel_selftests",
    ),
    (
        "stackoverflow",
        "stackoverflow",
        ROOT / "case_study" / "cases" / "stackoverflow",
    ),
    (
        "github",
        "github_issues",
        ROOT / "case_study" / "cases" / "github_issues",
    ),
)
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "batch_diagnostic_results.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "batch-diagnostic-eval.md"
MIN_LOG_CHARS = 50
SOURCE_MARKER_RE = re.compile(r"@\s*[^:\n]+:\d+")
OUTPUT_HEADLINE_RE = re.compile(r"^error\[(?P<error_id>[^\]]+)\]:\s+(?P<taxonomy>[^—]+?)\s+—\s+(?P<headline>.+)$")
SPAN_BUCKETS: tuple[str, ...] = ("0", "1", "2", "3", "4", "5", "6+")


@dataclass(slots=True)
class CaseResult:
    case_id: str
    case_path: str
    source: str
    source_dir: str
    success: bool
    skipped: bool
    skip_reason: str | None
    verifier_log_chars: int
    log_has_source_locations: bool
    error_id: str | None
    taxonomy_class: str | None
    proof_status: str | None
    num_spans: int
    has_btf_file_line: bool
    has_proof_lost_span: bool
    has_proof_established_span: bool
    has_rejected_span: bool
    output_text_length: int
    compression_ratio: float | None
    exception: str | None
    headline: str | None
    diagnostic_text: str | None
    diagnostic_json: dict[str, Any] | None
    benchmark_id: str | None = None
    verifier_log_path: str | None = None
    verifier_log: str | None = None
    capture_id: str | None = None
    source_kind: str | None = None
    family_id: str | None = None
    representative: bool | None = None
    label: Any = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help=f"Where to save the raw JSON results (default: {DEFAULT_RESULTS_PATH})",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"Where to save the markdown report (default: {DEFAULT_REPORT_PATH})",
    )
    parser.add_argument(
        "--min-log-chars",
        type=int,
        default=MIN_LOG_CHARS,
        help=f"Minimum verifier log length to evaluate (default: {MIN_LOG_CHARS})",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        help="Optional benchmark directory such as bpfix-bench. When set, cases are loaded via eval/benchmark_loader.py.",
    )
    return parser.parse_args()


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined", "")
        if isinstance(combined, str) and combined.strip():
            return combined
        blocks = verifier_log.get("blocks", [])
        if isinstance(blocks, list):
            return "\n".join(block for block in blocks if isinstance(block, str))
    return ""


def iter_case_files() -> list[tuple[str, str, Path]]:
    files: list[tuple[str, str, Path]] = []
    for source_key, source_dir, case_dir in CASE_DIRS:
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            files.append((source_key, source_dir, path))
    return files


def log_has_source_locations(verifier_log: str) -> bool:
    return bool(SOURCE_MARKER_RE.search(verifier_log))


def compute_compression_ratio(output_text_length: int, verifier_log_chars: int) -> float | None:
    if verifier_log_chars <= 0:
        return None
    return output_text_length / verifier_log_chars


def extract_headline(diagnostic_text: str | None) -> str | None:
    if not diagnostic_text:
        return None
    first_line = diagnostic_text.splitlines()[0].strip()
    match = OUTPUT_HEADLINE_RE.match(first_line)
    if match:
        return match.group("headline").strip()
    return first_line or None


def role_set(spans: list[dict[str, Any]]) -> set[str]:
    return {
        str(span.get("role", "")).strip()
        for span in spans
        if isinstance(span, dict) and span.get("role")
    }


def has_file_line(span: dict[str, Any]) -> bool:
    return bool(span.get("path")) and span.get("line") is not None


def evaluate_case(
    source: str,
    source_dir: str,
    path: Path,
    min_log_chars: int,
    benchmark_row: dict[str, Any] | None = None,
) -> CaseResult:
    benchmark_fields = benchmark_result_fields(benchmark_row)
    if benchmark_row is None:
        case_data = read_yaml(path)
        case_id = str(case_data.get("case_id") or path.stem)
        verifier_log = extract_verifier_log(case_data)
    else:
        case_data = {}
        case_id = str(benchmark_row.get("case_id") or path.parent.name)
        verifier_log = str(benchmark_row.get("verifier_log") or "")
    verifier_log_chars = len(verifier_log)
    has_source_markers = log_has_source_locations(verifier_log)

    if verifier_log_chars < min_log_chars:
        reason = f"verifier_log shorter than {min_log_chars} chars"
        return CaseResult(
            case_id=case_id,
            case_path=str(path),
            source=source,
            source_dir=source_dir,
            success=False,
            skipped=True,
            skip_reason=reason,
            verifier_log_chars=verifier_log_chars,
            log_has_source_locations=has_source_markers,
            error_id=None,
            taxonomy_class=None,
            proof_status=None,
            num_spans=0,
            has_btf_file_line=False,
            has_proof_lost_span=False,
            has_proof_established_span=False,
            has_rejected_span=False,
            output_text_length=0,
            compression_ratio=None,
            exception=None,
            headline=None,
            diagnostic_text=None,
            diagnostic_json=None,
            **benchmark_fields,
        )

    try:
        output = generate_diagnostic(verifier_log)
    except Exception as exc:  # pragma: no cover - batch eval must keep going on failures.
        return CaseResult(
            case_id=case_id,
            case_path=str(path),
            source=source,
            source_dir=source_dir,
            success=False,
            skipped=False,
            skip_reason=None,
            verifier_log_chars=verifier_log_chars,
            log_has_source_locations=has_source_markers,
            error_id=None,
            taxonomy_class=None,
            proof_status=None,
            num_spans=0,
            has_btf_file_line=False,
            has_proof_lost_span=False,
            has_proof_established_span=False,
            has_rejected_span=False,
            output_text_length=0,
            compression_ratio=None,
            exception=f"{type(exc).__name__}: {exc}",
            headline=None,
            diagnostic_text=None,
            diagnostic_json=None,
            **benchmark_fields,
        )

    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    metadata = json_data.get("metadata", {}) if isinstance(json_data.get("metadata"), dict) else {}
    spans = json_data.get("spans") or metadata.get("proof_spans") or []
    if not isinstance(spans, list):
        spans = []

    roles = role_set(spans)
    output_text = output.text or ""
    output_text_length = len(output_text)

    taxonomy_class = (
        _as_str_or_none(json_data.get("taxonomy_class"))
        or _as_str_or_none(json_data.get("failure_class"))
    )
    proof_status = (
        _as_str_or_none(json_data.get("proof_status"))
        or _as_str_or_none(metadata.get("proof_status"))
    )

    return CaseResult(
        case_id=case_id,
        case_path=str(path),
        source=source,
        source_dir=source_dir,
        success=True,
        skipped=False,
        skip_reason=None,
        verifier_log_chars=verifier_log_chars,
        log_has_source_locations=has_source_markers,
        error_id=_as_str_or_none(json_data.get("error_id")),
        taxonomy_class=taxonomy_class,
        proof_status=proof_status,
        num_spans=len(spans),
        has_btf_file_line=any(has_file_line(span) for span in spans if isinstance(span, dict)),
        has_proof_lost_span="proof_lost" in roles,
        has_proof_established_span="proof_established" in roles,
        has_rejected_span="rejected" in roles,
        output_text_length=output_text_length,
        compression_ratio=compute_compression_ratio(output_text_length, verifier_log_chars),
        exception=None,
        headline=extract_headline(output_text),
        diagnostic_text=output_text,
        diagnostic_json=json_data,
        **benchmark_fields,
    )


def benchmark_result_fields(row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "benchmark_id": _as_str_or_none(row.get("benchmark_id")),
        "verifier_log_path": _as_str_or_none(row.get("verifier_log_path")),
        "verifier_log": _as_str_or_none(row.get("verifier_log")),
        "capture_id": _as_str_or_none(row.get("capture_id")),
        "source_kind": _as_str_or_none(row.get("source_kind")),
        "family_id": _as_str_or_none(row.get("family_id")),
        "representative": bool(row.get("representative")),
        "label": row.get("label"),
    }


def _as_str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def ratio_cell(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator} ({percentage(numerator, denominator):.1f}%)"


def counter_markdown(counter: Counter[str], order: tuple[str, ...] | None = None) -> list[str]:
    keys = list(order or ())
    for key in counter:
        if key not in keys:
            keys.append(key)
    if not keys:
        return ["_None_"]
    lines = ["| Value | Count | Share |", "| --- | ---: | ---: |"]
    total = sum(counter.values())
    for key in keys:
        count = counter.get(key, 0)
        if count == 0:
            continue
        lines.append(f"| `{key}` | {count} | {percentage(count, total):.1f}% |")
    return lines


def span_histogram(results: list[CaseResult]) -> Counter[str]:
    histogram: Counter[str] = Counter()
    for result in results:
        if result.num_spans >= 6:
            histogram["6+"] += 1
        else:
            histogram[str(result.num_spans)] += 1
    for bucket in SPAN_BUCKETS:
        histogram.setdefault(bucket, 0)
    return histogram


def missing_expected_roles(result: CaseResult) -> list[str]:
    missing: list[str] = []
    if not result.success:
        return missing
    if result.proof_status == "established_then_lost":
        if not result.has_proof_established_span:
            missing.append("proof_established")
        if not result.has_proof_lost_span:
            missing.append("proof_lost")
        if not result.has_rejected_span:
            missing.append("rejected")
        return missing
    if result.proof_status == "established_but_insufficient":
        if not result.has_proof_established_span:
            missing.append("proof_established")
        if not result.has_rejected_span:
            missing.append("rejected")
        return missing
    if result.proof_status in {"never_established", "unknown", None} and not result.has_rejected_span:
        missing.append("rejected")
    return missing


def quality_score(result: CaseResult) -> float:
    ratio = result.compression_ratio if result.compression_ratio is not None else 1.0
    core_roles = (
        int(result.has_proof_established_span)
        + int(result.has_proof_lost_span)
        + int(result.has_rejected_span)
    )
    score = 0.0
    score += core_roles * 30.0
    score += 20.0 if result.has_btf_file_line else 0.0
    score += 10.0 if not missing_expected_roles(result) else 0.0
    score += 6.0 if result.proof_status not in {None, "unknown"} else 0.0
    score += max(0.0, 10.0 - abs(result.num_spans - 3) * 3.0)
    score += max(0.0, 10.0 - (min(ratio, 1.0) * 10.0))
    if result.num_spans == 0:
        score -= 30.0
    if not result.has_rejected_span:
        score -= 15.0
    if result.output_text_length < 80:
        score -= 5.0
    return score


def summarize_issue_examples(results: list[CaseResult], predicate: Any, limit: int = 5) -> str:
    matches = [result.case_id for result in results if predicate(result)]
    if not matches:
        return "0"
    preview = ", ".join(f"`{case_id}`" for case_id in matches[:limit])
    extra = "" if len(matches) <= limit else f", +{len(matches) - limit} more"
    return f"{len(matches)} ({preview}{extra})"


def format_source_name(source: str) -> str:
    mapping = {
        "selftests": "Selftests",
        "stackoverflow": "Stack Overflow",
        "github": "GitHub",
    }
    return mapping.get(source, source)


def top_results(results: list[CaseResult], reverse: bool) -> list[CaseResult]:
    return sorted(
        results,
        key=lambda result: (
            quality_score(result),
            result.has_btf_file_line,
            result.has_proof_established_span,
            result.has_proof_lost_span,
            result.has_rejected_span,
            -result.num_spans,
            -(result.compression_ratio if result.compression_ratio is not None else 1.0),
            result.case_id,
        ),
        reverse=reverse,
    )[:5]


def results_markdown_table(results: list[CaseResult]) -> list[str]:
    lines = [
        "| Case | Source | Score | Spans | Roles | BTF | Compression | Headline |",
        "| --- | --- | ---: | ---: | --- | --- | ---: | --- |",
    ]
    for result in results:
        roles = []
        if result.has_proof_established_span:
            roles.append("est")
        if result.has_proof_lost_span:
            roles.append("lost")
        if result.has_rejected_span:
            roles.append("rej")
        role_text = ",".join(roles) if roles else "none"
        compression = (
            f"{result.compression_ratio:.3f}"
            if result.compression_ratio is not None
            else "n/a"
        )
        headline = result.headline or "_no headline_"
        lines.append(
            f"| `{result.case_id}` | {format_source_name(result.source)} | "
            f"{quality_score(result):.1f} | {result.num_spans} | {role_text} | "
            f"{'yes' if result.has_btf_file_line else 'no'} | {compression} | {headline} |"
        )
    return lines


def build_report(
    results: list[CaseResult],
    generated_at: str,
    min_log_chars: int,
) -> str:
    eligible = [result for result in results if not result.skipped]
    successes = [result for result in eligible if result.success]
    failures = [result for result in eligible if not result.success]
    skipped = [result for result in results if result.skipped]

    taxonomy_distribution = Counter(
        result.taxonomy_class or "unknown" for result in successes
    )
    proof_distribution = Counter(result.proof_status or "unknown" for result in successes)
    span_distribution = span_histogram(successes)

    btf_count = sum(result.has_btf_file_line for result in successes)
    established_count = sum(result.has_proof_established_span for result in successes)
    lost_count = sum(result.has_proof_lost_span for result in successes)
    rejected_count = sum(result.has_rejected_span for result in successes)

    successful_with_source_markers = [
        result for result in successes if result.log_has_source_locations
    ]
    missing_btf_despite_source = [
        result for result in successful_with_source_markers if not result.has_btf_file_line
    ]
    too_many_spans = [result for result in successes if result.num_spans >= 6]
    zero_span = [result for result in successes if result.num_spans == 0]
    single_span = [result for result in successes if result.num_spans == 1]
    missing_rejected = [result for result in successes if not result.has_rejected_span]
    incomplete_role_sets = [
        result for result in successes if missing_expected_roles(result)
    ]

    best_outputs = top_results(successes, reverse=True)
    worst_outputs = top_results(successes, reverse=False)

    per_source_lines = [
        "| Source | Total | Eligible | Success | Failure | Skipped | Success Rate | BTF Rate | Avg Spans |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    legacy_source_order = [source for source, _, _case_dir in CASE_DIRS]
    source_order = legacy_source_order + sorted(
        source for source in {result.source for result in results} if source not in legacy_source_order
    )
    for source in source_order:
        source_results = [result for result in results if result.source == source]
        if not source_results:
            continue
        source_eligible = [result for result in source_results if not result.skipped]
        source_successes = [result for result in source_eligible if result.success]
        avg_spans = (
            sum(result.num_spans for result in source_successes) / len(source_successes)
            if source_successes
            else 0.0
        )
        per_source_lines.append(
            f"| {format_source_name(source)} | {len(source_results)} | {len(source_eligible)} | "
            f"{len(source_successes)} | {len(source_eligible) - len(source_successes)} | "
            f"{len(source_results) - len(source_eligible)} | "
            f"{percentage(len(source_successes), len(source_eligible)):.1f}% | "
            f"{percentage(sum(r.has_btf_file_line for r in source_successes), len(source_successes)):.1f}% | "
            f"{avg_spans:.2f} |"
        )

    failure_lines = ["_None_"]
    if failures:
        failure_lines = [
            "| Case | Source | Error |",
            "| --- | --- | --- |",
        ]
        for result in failures:
            failure_lines.append(
                f"| `{result.case_id}` | {format_source_name(result.source)} | "
                f"{result.exception or 'Unknown error'} |"
            )

    issue_lines = [
        f"- `{len(too_many_spans)}` successful cases emitted `6+` spans; these outputs risk becoming noisy.",
        f"- `{len(zero_span)}` successful cases emitted zero correlated spans.",
        f"- `{len(single_span)}` successful cases emitted only one span, which often reduces causal context.",
        f"- `{len(missing_btf_despite_source)}` successful cases had source markers in the verifier log but no `file:line` in emitted spans.",
        f"- `{len(incomplete_role_sets)}` successful cases were missing role(s) expected by their `proof_status`.",
        f"- `{len(missing_rejected)}` successful cases were missing an explicit rejected span.",
    ]

    recommendation_lines = []
    if missing_btf_despite_source:
        recommendation_lines.append(
            f"- Improve source correlation fallback for logs that already contain `@ file:line` markers; "
            f"{len(missing_btf_despite_source)} cases currently drop that metadata."
        )
    if too_many_spans:
        recommendation_lines.append(
            f"- Cap or merge redundant spans after per-role/source-line grouping; {len(too_many_spans)} cases still render `6+` spans."
        )
    if single_span or zero_span:
        recommendation_lines.append(
            f"- Strengthen fallback proof-event synthesis for sparse outputs; {len(zero_span) + len(single_span)} successful cases render at most one span."
        )
    if incomplete_role_sets:
        recommendation_lines.append(
            "- Enforce a minimal role set from `proof_status` during rendering so `established_then_lost` always includes established/lost/rejected context when recoverable."
        )
    if failures:
        failure_types = Counter((result.exception or "Unknown").split(":", 1)[0] for result in failures)
        top_failure_type = failure_types.most_common(1)[0][0]
        recommendation_lines.append(
            f"- Harden `generate_diagnostic()` against `{top_failure_type}` failures first; it is the most common batch exception."
        )
    if not recommendation_lines:
        recommendation_lines.append(
            "- No structural failures were observed; focus next on increasing source correlation coverage and reducing low-context one-span outputs."
        )

    lines: list[str] = [
        "# Batch Diagnostic Evaluation",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Minimum verifier log length: `{min_log_chars}` chars",
        f"- Case files scanned: `{len(results)}`",
        f"- Eligible for evaluation: `{len(eligible)}`",
        f"- Skipped: `{len(skipped)}`",
        f"- Successful runs: `{len(successes)}`",
        f"- Failed runs: `{len(failures)}`",
        "",
        "## Overall Success Rate",
        "",
        f"- Success rate: `{ratio_cell(len(successes), len(eligible))}`",
        f"- BTF source correlation: `{ratio_cell(btf_count, len(successes))}`",
        f"- Span role coverage: established `{ratio_cell(established_count, len(successes))}`, "
        f"lost `{ratio_cell(lost_count, len(successes))}`, rejected `{ratio_cell(rejected_count, len(successes))}`",
        "",
        "## Distribution of taxonomy_class",
        "",
        *counter_markdown(taxonomy_distribution),
        "",
        "## Distribution of proof_status",
        "",
        *counter_markdown(proof_distribution),
        "",
        "## Number of Spans Histogram",
        "",
        *counter_markdown(span_distribution, order=SPAN_BUCKETS),
        "",
        "## Per-Source Breakdown",
        "",
        *per_source_lines,
        "",
        "## Failure Cases",
        "",
        *failure_lines,
        "",
        "## Top 5 Best Outputs",
        "",
        "_Ranking heuristic rewards complete established/lost/rejected role coverage, BTF correlation, and concise output._",
        "",
        *results_markdown_table(best_outputs),
        "",
        "## Top 5 Worst Outputs",
        "",
        "_Ranking heuristic penalizes sparse spans, missing roles, missing BTF, and bloated output._",
        "",
        *results_markdown_table(worst_outputs),
        "",
        "## Quality Issues Found",
        "",
        *issue_lines,
        "",
        "Examples:",
        f"- Missing BTF despite source markers: {summarize_issue_examples(successes, lambda item: item.log_has_source_locations and not item.has_btf_file_line)}",
        f"- Too many spans: {summarize_issue_examples(successes, lambda item: item.num_spans >= 6)}",
        f"- Missing expected roles: {summarize_issue_examples(successes, lambda item: bool(missing_expected_roles(item)))}",
        "",
        "## Recommendations",
        "",
        *recommendation_lines,
    ]
    return "\n".join(lines).rstrip() + "\n"


def save_json(results_path: Path, payload: dict[str, Any]) -> None:
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    generated_at = datetime.now(timezone.utc).isoformat()
    benchmark_rows: list[dict[str, Any]] | None = None
    if args.benchmark:
        benchmark_rows = load_benchmark_rows(args.benchmark)
        case_files = [
            (
                str(row.get("source_kind") or "benchmark"),
                str(row.get("benchmark_id") or args.benchmark),
                Path(str(row["case_path"])),
                row,
            )
            for row in benchmark_rows
        ]
    else:
        case_files = [
            (source, source_dir, path, None)
            for source, source_dir, path in iter_case_files()
        ]
    results: list[CaseResult] = []

    total = len(case_files)
    for index, (source, source_dir, path, benchmark_row) in enumerate(case_files, start=1):
        results.append(evaluate_case(source, source_dir, path, args.min_log_chars, benchmark_row))
        if index % 50 == 0 or index == total:
            print(f"[batch_diagnostic_eval] processed {index}/{total} cases", flush=True)

    report = build_report(results, generated_at=generated_at, min_log_chars=args.min_log_chars)
    payload = {
        "generated_at": generated_at,
        "min_log_chars": args.min_log_chars,
        "benchmark": str(args.benchmark) if args.benchmark else None,
        "benchmark_cases": len(benchmark_rows) if benchmark_rows is not None else None,
        "totals": {
            "scanned": len(results),
            "eligible": sum(not result.skipped for result in results),
            "successes": sum(result.success for result in results),
            "failures": sum((not result.success) and (not result.skipped) for result in results),
            "skipped": sum(result.skipped for result in results),
        },
        "results": [asdict(result) for result in results],
    }

    save_json(args.results_path, payload)
    save_text(args.report_path, report)

    print(f"[batch_diagnostic_eval] wrote results to {args.results_path}", flush=True)
    print(f"[batch_diagnostic_eval] wrote report to {args.report_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
