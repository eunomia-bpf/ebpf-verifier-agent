#!/usr/bin/env python3
"""Replace case YAML verifier logs with locally captured fresh logs.

This migration keeps the original YAML log under ``original_verifier_log``,
updates the active ``verifier_log`` field to the captured host log, and records
the host/date provenance requested for the 6.15.11 capture run.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.scalarstring import LiteralScalarString


ROOT = Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "case_study" / "cases"
SELFTESTS_CAPTURE_ROOT = CASES_ROOT / "kernel_selftests_verified"
SO_GH_CAPTURE_ROOT = CASES_ROOT / "so_gh_verified"
SELFTESTS_YAML_ROOT = CASES_ROOT / "kernel_selftests"
STACKOVERFLOW_YAML_ROOT = CASES_ROOT / "stackoverflow"
GITHUB_YAML_ROOT = CASES_ROOT / "github_issues"

SOURCE_TAG = "captured_on_6.15.11"
CAPTURE_DATE = "2026-03-20"


yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 1000
yaml.indent(mapping=2, sequence=2, offset=0)


def represent_none(representer: Any, value: None) -> Any:
    return representer.represent_scalar("tag:yaml.org,2002:null", "null")


yaml.representer.add_representer(type(None), represent_none)


@dataclass(frozen=True)
class MigrationCandidate:
    case_id: str
    case_yaml: Path
    captured_log_path: Path
    corpus: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Restrict migration to one or more explicit case IDs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned migration summary without rewriting YAML files.",
    )
    return parser.parse_args()


def normalize_log_text(log_text: str) -> str:
    lines = [line.rstrip() for line in log_text.splitlines()]
    return "\n".join(lines).rstrip()


def read_captured_log(path: Path) -> str:
    return normalize_log_text(path.read_text(encoding="utf-8"))


def extract_log_text(value: Any) -> str:
    if isinstance(value, str):
        return normalize_log_text(value)
    if isinstance(value, dict):
        combined = value.get("combined")
        if isinstance(combined, str) and combined.strip():
            return normalize_log_text(combined)
        blocks = value.get("blocks")
        if isinstance(blocks, list):
            return normalize_log_text("\n".join(block for block in blocks if isinstance(block, str)))
    return ""


def parse_status_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith(" "):
            continue
        if ": " not in raw_line:
            continue
        key, value = raw_line.split(": ", 1)
        result[key.strip()] = value.strip()
    return result


def is_selftest_candidate(case_dir: Path) -> bool:
    status_path = case_dir / "verification_status.txt"
    log_path = case_dir / "verifier_log_captured.txt"
    if not status_path.exists() or not log_path.exists():
        return False
    status = parse_status_file(status_path)
    if status.get("compile_ok") != "yes":
        return False
    if status.get("verifier_rejected") != "yes":
        return False
    return bool(read_captured_log(log_path))


def is_so_gh_candidate(case_dir: Path) -> tuple[bool, str | None]:
    status_path = case_dir / "verification_status.txt"
    log_path = case_dir / "verifier_log_captured.txt"
    if not status_path.exists() or not log_path.exists():
        return False, None
    status = parse_status_file(status_path)
    if status.get("compile_ok") != "True":
        return False, None
    if status.get("verifier_status") != "rejected":
        return False, None
    if not read_captured_log(log_path):
        return False, None
    bucket = status.get("source_bucket")
    if bucket in {"stackoverflow", "github_issues"}:
        return True, bucket
    if case_dir.name.startswith("stackoverflow-"):
        return True, "stackoverflow"
    if case_dir.name.startswith("github-"):
        return True, "github_issues"
    return False, None


def collect_candidates(case_ids: set[str]) -> list[MigrationCandidate]:
    candidates: list[MigrationCandidate] = []

    for case_dir in sorted(SELFTESTS_CAPTURE_ROOT.iterdir()):
        if not case_dir.is_dir():
            continue
        if case_ids and case_dir.name not in case_ids:
            continue
        if not is_selftest_candidate(case_dir):
            continue
        case_yaml = SELFTESTS_YAML_ROOT / f"{case_dir.name}.yaml"
        candidates.append(
            MigrationCandidate(
                case_id=case_dir.name,
                case_yaml=case_yaml,
                captured_log_path=case_dir / "verifier_log_captured.txt",
                corpus="kernel_selftests",
            )
        )

    for case_dir in sorted(SO_GH_CAPTURE_ROOT.iterdir()):
        if not case_dir.is_dir():
            continue
        if case_ids and case_dir.name not in case_ids:
            continue
        is_candidate, bucket = is_so_gh_candidate(case_dir)
        if not is_candidate or bucket is None:
            continue
        yaml_root = STACKOVERFLOW_YAML_ROOT if bucket == "stackoverflow" else GITHUB_YAML_ROOT
        case_yaml = yaml_root / f"{case_dir.name}.yaml"
        candidates.append(
            MigrationCandidate(
                case_id=case_dir.name,
                case_yaml=case_yaml,
                captured_log_path=case_dir / "verifier_log_captured.txt",
                corpus=bucket,
            )
        )

    return candidates


def ensure_inserted_after(doc: CommentedMap, anchor_key: str, key: str, value: Any) -> None:
    if key in doc:
        doc[key] = value
        return
    keys = list(doc.keys())
    if anchor_key in doc:
        doc.insert(keys.index(anchor_key) + 1, key, value)
    else:
        doc[key] = value


def ensure_inserted_before(doc: CommentedMap, anchor_key: str, key: str, value: Any) -> None:
    if key in doc:
        return
    keys = list(doc.keys())
    if anchor_key in doc:
        doc.insert(keys.index(anchor_key), key, value)
    else:
        doc[key] = value


def update_verifier_log_field(doc: CommentedMap, captured_log: str) -> None:
    current_value = doc.get("verifier_log")
    fresh_literal = LiteralScalarString(captured_log)
    if isinstance(current_value, CommentedMap):
        current_value["combined"] = fresh_literal
        return
    if isinstance(current_value, dict):
        current_value["combined"] = fresh_literal
        doc["verifier_log"] = current_value
        return
    doc["verifier_log"] = fresh_literal


def already_migrated(doc: CommentedMap, captured_log: str) -> bool:
    return (
        doc.get("verifier_log_source") == SOURCE_TAG
        and doc.get("verifier_log_captured_at") == CAPTURE_DATE
        and "original_verifier_log" in doc
        and extract_log_text(doc.get("verifier_log")) == captured_log
    )


def migrate_case(candidate: MigrationCandidate, *, dry_run: bool) -> tuple[bool, int, int]:
    if not candidate.case_yaml.exists():
        raise FileNotFoundError(f"Missing canonical case YAML for {candidate.case_id}: {candidate.case_yaml}")

    captured_log = read_captured_log(candidate.captured_log_path)
    with candidate.case_yaml.open("r", encoding="utf-8") as handle:
        doc = yaml.load(handle)
    if not isinstance(doc, CommentedMap):
        raise TypeError(f"{candidate.case_yaml} did not contain a top-level mapping")

    current_value = doc.get("verifier_log")
    old_log = extract_log_text(current_value)
    if already_migrated(doc, captured_log):
        return False, len(old_log), len(captured_log)

    ensure_inserted_before(doc, "verifier_log", "original_verifier_log", deepcopy(current_value))
    update_verifier_log_field(doc, captured_log)
    ensure_inserted_after(doc, "verifier_log", "verifier_log_source", SOURCE_TAG)
    ensure_inserted_after(doc, "verifier_log_source", "verifier_log_captured_at", CAPTURE_DATE)

    if not dry_run:
        with candidate.case_yaml.open("w", encoding="utf-8") as handle:
            yaml.dump(doc, handle)

    return True, len(old_log), len(captured_log)


def main() -> int:
    args = parse_args()
    case_ids = set(args.case_id)
    candidates = collect_candidates(case_ids)
    if case_ids:
        found = {candidate.case_id for candidate in candidates}
        missing = sorted(case_ids - found)
        if missing:
            raise SystemExit(f"Requested case IDs were not eligible migration candidates: {', '.join(missing)}")

    updated = 0
    skipped = 0
    old_chars_total = 0
    new_chars_total = 0

    for candidate in candidates:
        changed, old_chars, new_chars = migrate_case(candidate, dry_run=args.dry_run)
        if changed:
            updated += 1
        else:
            skipped += 1
        old_chars_total += old_chars
        new_chars_total += new_chars

    print(
        "\n".join(
            [
                f"eligible_cases: {len(candidates)}",
                f"updated_cases: {updated}",
                f"already_migrated_cases: {skipped}",
                f"old_log_chars_total: {old_chars_total}",
                f"new_log_chars_total: {new_chars_total}",
                f"dry_run: {'yes' if args.dry_run else 'no'}",
            ]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
