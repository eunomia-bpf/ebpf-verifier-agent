#!/usr/bin/env python3
"""Build the evaluation manifest for the logged 302-case corpus."""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CASE_DIRS: tuple[tuple[str, Path], ...] = (
    ("kernel_selftests", ROOT / "case_study" / "cases" / "kernel_selftests"),
    ("stackoverflow", ROOT / "case_study" / "cases" / "stackoverflow"),
    ("github_issues", ROOT / "case_study" / "cases" / "github_issues"),
)
DEFAULT_OUTPUT_PATH = ROOT / "case_study" / "eval_manifest.yaml"
MIN_LOG_CHARS = 50
INSTRUCTION_LINE_RE = re.compile(r"^\d+: \(")
SELFTEST_FOOTER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^processed \d+ insns"),
    re.compile(r"^verification time "),
    re.compile(r"^stack depth "),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Where to write the manifest YAML (default: {DEFAULT_OUTPUT_PATH})",
    )
    return parser.parse_args()


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def iter_case_files() -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for source, case_dir in CASE_DIRS:
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            files.append((source, path))
    return files


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    verifier_log = case_data.get("verifier_log", "")
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined", "")
        if isinstance(combined, str) and combined:
            return combined
        blocks = verifier_log.get("blocks", [])
        if isinstance(blocks, list):
            return "\n".join(block for block in blocks if isinstance(block, str))
    return ""


def infer_language(case_id: str) -> str:
    if "aya-" in case_id:
        return "Rust"
    if "cilium-" in case_id:
        return "Go"
    return "C"


def classify_log_quality(verifier_log: str) -> str:
    instruction_lines = sum(
        1 for line in verifier_log.splitlines() if INSTRUCTION_LINE_RE.match(line)
    )
    if instruction_lines >= 3:
        return "trace_rich"
    if instruction_lines >= 1:
        return "partial"
    return "message_only"


def eval_split(log_chars: int, log_quality: str) -> str:
    if log_chars < MIN_LOG_CHARS:
        return "excluded"
    if log_quality == "trace_rich":
        return "core"
    return "noisy"


def extract_terminal_rejection_line(verifier_log: str) -> str | None:
    lines = [line.rstrip() for line in verifier_log.splitlines() if line.strip()]
    for line in reversed(lines):
        if any(pattern.match(line) for pattern in SELFTEST_FOOTER_PATTERNS):
            continue
        return line
    return None


def sort_group_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda entry: (-entry["log_chars"], entry["case_id"]))


def build_manifest() -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []

    for source, path in iter_case_files():
        case_data = read_yaml(path)
        case_id = str(case_data.get("case_id") or path.stem)
        verifier_log = extract_verifier_log(case_data)
        log_chars = len(verifier_log)
        log_quality = classify_log_quality(verifier_log)
        duplicate_group = None
        if source == "kernel_selftests":
            duplicate_group = extract_terminal_rejection_line(verifier_log)

        manifest.append(
            {
                "case_id": case_id,
                "source": source,
                "language": infer_language(case_id),
                "log_chars": log_chars,
                "eligible": log_chars >= MIN_LOG_CHARS,
                "log_quality": log_quality,
                "eval_split": eval_split(log_chars, log_quality),
                "duplicate_group": duplicate_group,
                "core_representative": False,
            }
        )

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in manifest:
        if entry["source"] != "kernel_selftests":
            continue
        duplicate_group = entry["duplicate_group"]
        if not duplicate_group:
            continue
        groups[str(duplicate_group)].append(entry)

    for grouped_entries in groups.values():
        core_entries = [
            entry for entry in grouped_entries if entry["eval_split"] == "core"
        ]
        for entry in sort_group_entries(core_entries)[: min(2, len(core_entries))]:
            entry["core_representative"] = True

    return manifest


def print_summary(manifest: list[dict[str, Any]]) -> None:
    split_counts: dict[str, Counter[str]] = defaultdict(Counter)
    families = Counter(
        str(entry["duplicate_group"])
        for entry in manifest
        if entry["source"] == "kernel_selftests" and entry["duplicate_group"]
    )
    representatives = sum(
        1
        for entry in manifest
        if entry["source"] == "kernel_selftests" and entry["core_representative"]
    )
    for entry in manifest:
        split_counts[str(entry["source"])][str(entry["eval_split"])] += 1

    total = len(manifest)
    eligible = sum(1 for entry in manifest if entry["eligible"])
    print(
        f"Manifest: {total} cases, {eligible} eligible, "
        f"{sum(1 for entry in manifest if entry['eval_split'] == 'core')} core, "
        f"{sum(1 for entry in manifest if entry['eval_split'] == 'noisy')} noisy, "
        f"{sum(1 for entry in manifest if entry['eval_split'] == 'excluded')} excluded"
    )
    for source, counts in split_counts.items():
        print(
            f"  {source}: core={counts['core']} noisy={counts['noisy']} "
            f"excluded={counts['excluded']}"
        )
    print(
        f"Selftest duplicate families: {len(families)} non-empty groups, "
        f"{representatives} core representatives kept"
    )


def main() -> int:
    args = parse_args()
    manifest = build_manifest()
    args.output_path.parent.mkdir(parents=True, exist_ok=True)
    with args.output_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            manifest,
            handle,
            sort_keys=False,
            allow_unicode=False,
            width=120,
        )
    print_summary(manifest)
    print(f"Wrote {args.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
