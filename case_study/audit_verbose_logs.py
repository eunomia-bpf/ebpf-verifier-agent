#!/usr/bin/env python3
"""Audit collected case YAMLs for verbose verifier-log richness."""

from __future__ import annotations

import argparse
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS = (
    "case_study/cases/stackoverflow",
    "case_study/cases/github_issues",
    "case_study/cases/kernel_selftests*",
)
OUTPUT_PATH = ROOT / "docs" / "tmp" / "verbose-log-audit.md"

REGISTER_STATE_RE = re.compile(r"(?:^|[ ;])(?:frame\d+:\s+)?R[0-9](?:_w)?=")
BACKTRACK_TOKENS = ("last_idx", "first_idx", "regs=", "stack=")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pattern",
        action="append",
        default=list(DEFAULT_PATTERNS),
        help="Directory glob(s) to scan for YAML case files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Markdown report path.",
    )
    return parser.parse_args()


def source_bucket(path: Path) -> str:
    parent = path.parent.name
    if parent == "stackoverflow":
        return "SO"
    if parent == "github_issues":
        return "GH"
    if parent.startswith("kernel_selftests"):
        return "KS"
    return parent


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        return {}
    return payload


def iter_case_files(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(ROOT.glob(pattern)):
            if not path.exists():
                continue
            if path.is_dir():
                candidates = sorted(
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file() and candidate.suffix in {".yaml", ".yml"} and candidate.name != "index.yaml"
                )
            else:
                candidates = [path]
            for candidate in candidates:
                if candidate not in seen:
                    files.append(candidate)
                    seen.add(candidate)
    return sorted(files)


def stringify_source_snippet(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in ("code", "snippet", "body_text", "text"):
            value = entry.get(key)
            if isinstance(value, str):
                return value
    return ""


def has_extractable_source(payload: dict[str, Any]) -> bool:
    snippets = payload.get("source_snippets")
    if not isinstance(snippets, list):
        return False
    return any(stringify_source_snippet(entry).strip() for entry in snippets)


def texty(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        pieces = []
        for key in ("summary", "body_text", "fix_description", "description", "text"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                pieces.append(item.strip())
        return "\n".join(pieces)
    return ""


def has_fix_description(payload: dict[str, Any]) -> bool:
    selected_answer = payload.get("selected_answer")
    if isinstance(selected_answer, dict):
        if any(
            isinstance(selected_answer.get(key), str) and selected_answer.get(key).strip()
            for key in ("body_text", "fix_description", "summary")
        ):
            return True
    fix = payload.get("fix")
    if isinstance(fix, dict):
        if texty(fix):
            return True
        selected_comment = fix.get("selected_comment")
        if isinstance(selected_comment, dict) and texty(selected_comment):
            return True
    return False


def get_log_text(payload: dict[str, Any]) -> str:
    verifier_log = payload.get("verifier_log")
    if isinstance(verifier_log, str):
        return verifier_log
    if not isinstance(verifier_log, dict):
        return ""
    combined = verifier_log.get("combined")
    if isinstance(combined, str):
        return combined
    blocks = verifier_log.get("blocks")
    if isinstance(blocks, list):
        return "\n\n".join(block for block in blocks if isinstance(block, str))
    return ""


def line_count(text: str) -> int:
    if not text:
        return 0
    return len(text.splitlines())


def register_state_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if REGISTER_STATE_RE.search(line)]


def btf_annotation_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if line.lstrip().startswith(";")]


def backtracking_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if any(token in line for token in BACKTRACK_TOKENS)]


def percentile(sorted_values: list[int], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(sorted_values[lower])
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def format_num(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.1f}"


def render_markdown(
    records: list[dict[str, Any]],
    per_bucket: dict[str, list[dict[str, Any]]],
    top_cases: list[dict[str, Any]],
) -> str:
    total_cases = len(records)
    lengths = sorted(record["log_lines"] for record in records)
    nonzero_lengths = sorted(record["log_lines"] for record in records if record["log_lines"] > 0)
    rich_triples = sum(1 for record in records if record["has_source"] and record["has_log"] and record["has_fix"])
    rich_triplets_by_bucket = {
        bucket: sum(1 for record in bucket_records if record["has_source"] and record["has_log"] and record["has_fix"])
        for bucket, bucket_records in per_bucket.items()
    }

    lines: list[str] = []
    lines.append("# Verbose Log Audit")
    lines.append("")
    lines.append("Run date: 2026-03-11")
    lines.append("")
    lines.append("Scope:")
    lines.append("")
    lines.append("- Scanned YAML case files under `case_study/cases/{stackoverflow,github_issues,kernel_selftests*}/`.")
    lines.append("- Excluded `index.yaml` manifests.")
    lines.append("- Treated both `kernel_selftests` directories as the `KS` source bucket for summary statistics.")
    lines.append("")
    lines.append("## Corpus Summary")
    lines.append("")
    lines.append("| Bucket | Directories | Cases | With verifier_log | With register-state dumps | With BTF annotations | With backtracking annotations | With source snippets | With fix description | Log lines min / median / max |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")

    dir_labels = {
        "SO": "`stackoverflow`",
        "GH": "`github_issues`",
        "KS": "`kernel_selftests*`",
    }
    for bucket in ("SO", "GH", "KS"):
        bucket_records = per_bucket.get(bucket, [])
        if not bucket_records:
            continue
        bucket_lengths = sorted(record["log_lines"] for record in bucket_records)
        lines.append(
            "| {bucket} | {dirs} | {cases} | {has_log} | {reg} | {btf} | {bt} | {src} | {fix} | {min_} / {median_} / {max_} |".format(
                bucket=bucket,
                dirs=dir_labels[bucket],
                cases=len(bucket_records),
                has_log=sum(1 for record in bucket_records if record["has_log"]),
                reg=sum(1 for record in bucket_records if record["has_register_state"]),
                btf=sum(1 for record in bucket_records if record["has_btf_annotations"]),
                bt=sum(1 for record in bucket_records if record["has_backtracking"]),
                src=sum(1 for record in bucket_records if record["has_source"]),
                fix=sum(1 for record in bucket_records if record["has_fix"]),
                min_=min(bucket_lengths) if bucket_lengths else 0,
                median_=format_num(median(bucket_lengths) if bucket_lengths else 0),
                max_=max(bucket_lengths) if bucket_lengths else 0,
            )
        )

    lines.append("")
    lines.append("## Summary Statistics")
    lines.append("")
    lines.append("### Feature Coverage by Source")
    lines.append("")
    lines.append("| Metric | SO | GH | KS | Total |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")

    def count_metric(metric: str, bucket: str) -> int:
        return sum(1 for record in per_bucket.get(bucket, []) if record[metric])

    feature_rows = [
        ("Per-instruction register state", "has_register_state"),
        ("BTF source annotations", "has_btf_annotations"),
        ("Backtracking annotations", "has_backtracking"),
        ("Code + verbose_log + fix_description triples", "rich_triple"),
    ]
    for label, metric in feature_rows:
        if metric == "rich_triple":
            so = rich_triplets_by_bucket.get("SO", 0)
            gh = rich_triplets_by_bucket.get("GH", 0)
            ks = rich_triplets_by_bucket.get("KS", 0)
            total = rich_triples
        else:
            so = count_metric(metric, "SO")
            gh = count_metric(metric, "GH")
            ks = count_metric(metric, "KS")
            total = so + gh + ks
        lines.append(f"| {label} | {so} | {gh} | {ks} | {total} |")

    lines.append("")
    lines.append("### Log Length Distribution")
    lines.append("")
    lines.append("| Statistic | Lines |")
    lines.append("| --- | ---: |")
    lines.append(f"| Cases | {total_cases} |")
    lines.append(f"| Min | {min(lengths) if lengths else 0} |")
    lines.append(f"| Q1 | {format_num(percentile(lengths, 0.25))} |")
    lines.append(f"| Median | {format_num(percentile(lengths, 0.50))} |")
    lines.append(f"| Q3 | {format_num(percentile(lengths, 0.75))} |")
    lines.append(f"| Max | {max(lengths) if lengths else 0} |")

    lines.append("")
    lines.append("### Non-Empty Log Length Distribution")
    lines.append("")
    lines.append("| Statistic | Lines |")
    lines.append("| --- | ---: |")
    lines.append(f"| Cases with logs | {len(nonzero_lengths)} |")
    lines.append(f"| Min | {min(nonzero_lengths) if nonzero_lengths else 0} |")
    lines.append(f"| Q1 | {format_num(percentile(nonzero_lengths, 0.25))} |")
    lines.append(f"| Median | {format_num(percentile(nonzero_lengths, 0.50))} |")
    lines.append(f"| Q3 | {format_num(percentile(nonzero_lengths, 0.75))} |")
    lines.append(f"| Max | {max(nonzero_lengths) if nonzero_lengths else 0} |")

    lines.append("")
    lines.append("## Richest Prototype Targets")
    lines.append("")
    lines.append("Ranking heuristic: longest logs first, then register-state density, then presence of BTF annotations and backtracking markers.")
    lines.append("")
    lines.append("| Rank | Case ID | Bucket | Dir | Log lines | Register-state lines | BTF lines | Backtracking lines | Has source | Has fix |")
    lines.append("| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |")
    for idx, record in enumerate(top_cases, start=1):
        lines.append(
            f"| {idx} | `{record['case_id']}` | {record['bucket']} | `{record['dir_name']}` | "
            f"{record['log_lines']} | {record['register_state_lines']} | {record['btf_annotation_lines']} | "
            f"{record['backtracking_lines']} | {'yes' if record['has_source'] else 'no'} | {'yes' if record['has_fix'] else 'no'} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- `BTF source annotations` only counts log lines whose trimmed form starts with `;`, matching the requested signal.")
    lines.append("- `Per-instruction register state` counts logs containing explicit register facts such as `R1=ctx()` or `R0_w=inv(...)`.")
    lines.append("- `Backtracking annotations` counts presence of `last_idx`, `first_idx`, `regs=`, or `stack=` markers anywhere in the combined log.")
    lines.append("- Selftest YAMLs often omit a captured `verifier_log`; those cases remain in the denominator with log length `0`.")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    case_files = iter_case_files(args.pattern)
    records: list[dict[str, Any]] = []
    per_bucket: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for path in case_files:
        payload = load_yaml(path)
        log_text = get_log_text(payload)
        lines = log_text.splitlines()
        reg_lines = register_state_lines(lines)
        btf_lines = btf_annotation_lines(lines)
        bt_lines = backtracking_lines(lines)

        record = {
            "path": path,
            "case_id": payload.get("case_id", path.stem),
            "bucket": source_bucket(path),
            "dir_name": path.parent.name,
            "log_lines": line_count(log_text),
            "has_log": bool(log_text.strip()),
            "has_register_state": bool(reg_lines),
            "register_state_lines": len(reg_lines),
            "has_btf_annotations": bool(btf_lines),
            "btf_annotation_lines": len(btf_lines),
            "has_backtracking": bool(bt_lines),
            "backtracking_lines": len(bt_lines),
            "has_source": has_extractable_source(payload),
            "has_fix": has_fix_description(payload),
        }
        record["rich_triple"] = record["has_source"] and record["has_log"] and record["has_fix"]
        records.append(record)
        per_bucket[record["bucket"]].append(record)

    top_cases = sorted(
        records,
        key=lambda item: (
            item["log_lines"],
            item["register_state_lines"],
            item["btf_annotation_lines"],
            item["backtracking_lines"],
            int(item["has_source"]),
            int(item["has_fix"]),
            item["case_id"],
        ),
        reverse=True,
    )[:20]

    markdown = render_markdown(records, per_bucket, top_cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    print(f"Wrote {args.output} with {len(records)} cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
