#!/usr/bin/env python3
"""Normalize existing case YAMLs into the unified eval schema and validate them."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "case_study" / "cases"
SCHEMA_PATH = ROOT / "case_study" / "eval_schema.yaml"
EXACT_CASE_DIRS = ("stackoverflow", "github_issues", "eval_commits")
KERNEL_SELFTEST_GLOB = "kernel_selftests*"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--cases-root", type=Path, default=CASES_ROOT)
    parser.add_argument(
        "--show-errors",
        type=int,
        default=20,
        help="Maximum number of validation errors to print.",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def iter_case_dirs(cases_root: Path) -> list[Path]:
    case_dirs: list[Path] = []
    for name in EXACT_CASE_DIRS:
        path = cases_root / name
        if path.exists():
            case_dirs.append(path)
    case_dirs.extend(sorted(path for path in cases_root.glob(KERNEL_SELFTEST_GLOB) if path.is_dir()))
    return case_dirs


def iter_case_paths(cases_root: Path) -> list[Path]:
    paths: list[Path] = []
    for case_dir in iter_case_dirs(cases_root):
        paths.extend(sorted(path for path in case_dir.glob("*.yaml") if path.name != "index.yaml"))
    return paths


def read_kernel_index(case_path: Path) -> dict[str, Any]:
    index_path = case_path.parent / "index.yaml"
    if not index_path.exists():
        return {}
    payload = load_yaml(index_path)
    if not isinstance(payload, dict):
        return {}
    source_details = payload.get("source_details")
    return source_details if isinstance(source_details, dict) else {}


def as_string(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def join_nonempty(parts: list[str | None], separator: str = "\n\n") -> str | None:
    values = [part for part in parts if part]
    if not values:
        return None
    return separator.join(values)


def normalize_source_snippets(payload: dict[str, Any]) -> str | None:
    snippets = payload.get("source_snippets")
    if not isinstance(snippets, list):
        return None

    blocks: list[str] = []
    for snippet in snippets:
        if isinstance(snippet, str):
            text = snippet.strip()
            if text:
                blocks.append(text)
            continue
        if isinstance(snippet, dict):
            code = as_string(snippet.get("code"))
            file_path = as_string(snippet.get("file"))
            if code and file_path:
                blocks.append(f"// FILE: {file_path}\n{code}")
            elif code:
                blocks.append(code)
    return join_nonempty(blocks)


def normalize_verifier_log(payload: dict[str, Any]) -> str | None:
    verifier_log = payload.get("verifier_log")
    if isinstance(verifier_log, str):
        return as_string(verifier_log)
    if isinstance(verifier_log, dict):
        combined = as_string(verifier_log.get("combined"))
        if combined:
            return combined
        blocks = verifier_log.get("blocks")
        if isinstance(blocks, list):
            return join_nonempty([as_string(block) for block in blocks])
    verifier_logs = payload.get("verifier_logs")
    if isinstance(verifier_logs, list):
        return join_nonempty([as_string(block) for block in verifier_logs])
    if isinstance(verifier_logs, dict):
        return as_string(verifier_logs.get("combined"))
    return None


def normalize_expected_verifier_message(payload: dict[str, Any]) -> str | None:
    expected = payload.get("expected_verifier_messages")
    if isinstance(expected, dict):
        combined = expected.get("combined")
        if isinstance(combined, list):
            return join_nonempty([as_string(item) for item in combined], separator="\n")
        return as_string(combined)
    if isinstance(expected, list):
        return join_nonempty([as_string(item) for item in expected], separator="\n")
    return as_string(expected)


def normalize_source_url(payload: dict[str, Any], case_path: Path) -> str | None:
    source = as_string(payload.get("source"))
    if source == "stackoverflow":
        selected_answer = payload.get("selected_answer")
        if isinstance(selected_answer, dict):
            answer_url = as_string(selected_answer.get("url"))
            if answer_url:
                return answer_url
        question = payload.get("question")
        if isinstance(question, dict):
            return as_string(question.get("url"))
        return None

    if source == "github_issues":
        fix = payload.get("fix")
        if isinstance(fix, dict):
            selected_comment = fix.get("selected_comment")
            if isinstance(selected_comment, dict):
                comment_url = as_string(selected_comment.get("url"))
                if comment_url:
                    return comment_url
        issue = payload.get("issue")
        if isinstance(issue, dict):
            return as_string(issue.get("url"))
        return None

    if source == "eval_commits":
        repository = as_string(payload.get("repository"))
        commit_hash = as_string(payload.get("commit_hash"))
        if repository and commit_hash:
            repo_base = repository[:-4] if repository.endswith(".git") else repository
            return f"{repo_base}/commit/{commit_hash}"
        return repository

    if source == "kernel_selftests":
        selftest = payload.get("selftest")
        if not isinstance(selftest, dict):
            return None
        file_path = as_string(selftest.get("file"))
        if not file_path:
            return None
        source_details = read_kernel_index(case_path)
        repo_url = as_string(source_details.get("repo_url")) or "https://github.com/torvalds/linux"
        repo_base = repo_url[:-4] if repo_url.endswith(".git") else repo_url
        commit = as_string(source_details.get("commit")) or as_string(source_details.get("ref")) or "master"
        return f"{repo_base}/blob/{commit}/{file_path}"

    return None


def normalize_fix_description(payload: dict[str, Any]) -> str | None:
    source = as_string(payload.get("source"))
    if source == "eval_commits":
        return as_string(payload.get("commit_message"))

    if source == "stackoverflow":
        selected_answer = payload.get("selected_answer")
        if isinstance(selected_answer, dict):
            return as_string(selected_answer.get("fix_description")) or as_string(selected_answer.get("body_text"))
        return None

    if source == "github_issues":
        fix = payload.get("fix")
        if not isinstance(fix, dict):
            return None
        selected_comment = fix.get("selected_comment")
        if isinstance(selected_comment, dict):
            return as_string(selected_comment.get("body_text")) or as_string(fix.get("summary"))
        return as_string(fix.get("summary"))

    return None


def normalize_case(payload: dict[str, Any], case_path: Path) -> tuple[dict[str, Any], list[str]]:
    raw_source = as_string(payload.get("source"))
    errors: list[str] = []
    if raw_source not in {"kernel_selftests", "stackoverflow", "github_issues", "eval_commits"}:
        errors.append(f"{case_path}: unsupported source {raw_source!r}")
        raw_source = raw_source or "<missing>"

    normalized: dict[str, Any] = {
        "case_id": as_string(payload.get("case_id")),
        "source": raw_source,
        "input_fields": {},
        "ground_truth_fields": {},
        "eval_levels": [],
    }

    if raw_source == "eval_commits":
        buggy_code = as_string(payload.get("buggy_code"))
        fixed_code = as_string(payload.get("fixed_code"))
    else:
        buggy_code = normalize_source_snippets(payload)
        fixed_code = None

    verifier_log = normalize_verifier_log(payload)
    fix_description = normalize_fix_description(payload)
    expected_verifier_message = normalize_expected_verifier_message(payload)
    source_url = normalize_source_url(payload, case_path)
    commit_hash = as_string(payload.get("commit_hash")) if raw_source == "eval_commits" else None

    if buggy_code:
        normalized["input_fields"]["buggy_code"] = buggy_code
    if verifier_log:
        normalized["input_fields"]["verifier_log"] = verifier_log

    if fixed_code:
        normalized["ground_truth_fields"]["fixed_code"] = fixed_code
    if fix_description:
        normalized["ground_truth_fields"]["fix_description"] = fix_description
    if expected_verifier_message:
        normalized["ground_truth_fields"]["expected_verifier_message"] = expected_verifier_message
    if source_url:
        normalized["ground_truth_fields"]["source_url"] = source_url
    if commit_hash:
        normalized["ground_truth_fields"]["commit_hash"] = commit_hash

    # Intentionally do not normalize raw `fix_type` from eval_commits: current values are
    # collector-generated labels, not independently authoritative ground truth.

    eval_levels: list[str] = []
    if verifier_log or expected_verifier_message:
        eval_levels.append("classification")
    if buggy_code and verifier_log:
        eval_levels.append("localization")
    if fix_description:
        eval_levels.append("fix_description")
    if buggy_code and fixed_code:
        eval_levels.append("fix_code")
    normalized["eval_levels"] = eval_levels

    if not normalized["case_id"]:
        errors.append(f"{case_path}: missing case_id")
    if raw_source == "eval_commits" and not commit_hash:
        errors.append(f"{case_path}: eval_commits case is missing commit_hash")

    return normalized, errors


def validate_case(normalized: dict[str, Any], schema: dict[str, Any], case_path: Path) -> list[str]:
    errors: list[str] = []
    required_fields = schema.get("required_fields") or {}
    source_spec = required_fields.get("source") or {}
    allowed_sources = set(source_spec.get("values") or [])

    case_id = normalized.get("case_id")
    source = normalized.get("source")
    if not isinstance(case_id, str) or not case_id:
        errors.append(f"{case_path}: case_id must be a non-empty string")
    if source not in allowed_sources:
        errors.append(f"{case_path}: source {source!r} is not in eval schema")

    input_fields = normalized.get("input_fields")
    ground_truth_fields = normalized.get("ground_truth_fields")
    eval_levels = normalized.get("eval_levels")
    if not isinstance(input_fields, dict):
        errors.append(f"{case_path}: input_fields must be a mapping")
        input_fields = {}
    if not isinstance(ground_truth_fields, dict):
        errors.append(f"{case_path}: ground_truth_fields must be a mapping")
        ground_truth_fields = {}
    if not isinstance(eval_levels, list):
        errors.append(f"{case_path}: eval_levels must be a list")
        eval_levels = []

    for section_name, section in (("input_fields", input_fields), ("ground_truth_fields", ground_truth_fields)):
        for key, value in section.items():
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{case_path}: {section_name}.{key} must be a non-empty string")

    allowed_eval_levels = set(schema.get("eval_levels") or [])
    for level in eval_levels:
        if level not in allowed_eval_levels:
            errors.append(f"{case_path}: unsupported eval level {level!r}")

    if "fix_code" in eval_levels and "fixed_code" not in ground_truth_fields:
        errors.append(f"{case_path}: fix_code eval level requires ground_truth_fields.fixed_code")
    if "fix_description" in eval_levels and "fix_description" not in ground_truth_fields:
        errors.append(f"{case_path}: fix_description eval level requires ground_truth_fields.fix_description")
    if "classification" in eval_levels and not (
        "verifier_log" in input_fields or "expected_verifier_message" in ground_truth_fields
    ):
        errors.append(f"{case_path}: classification eval level requires verifier evidence")
    if "localization" in eval_levels and not (
        "buggy_code" in input_fields and "verifier_log" in input_fields
    ):
        errors.append(f"{case_path}: localization eval level requires buggy_code and verifier_log")

    return errors


def print_summary(
    normalized_cases: list[dict[str, Any]],
    validation_errors: list[str],
    ignored_fix_type_cases: int,
) -> None:
    by_source = Counter(case["source"] for case in normalized_cases)
    level_counts = Counter()
    level_counts_by_source: dict[str, Counter[str]] = defaultdict(Counter)
    for case in normalized_cases:
        for level in case["eval_levels"]:
            level_counts[level] += 1
            level_counts_by_source[case["source"]][level] += 1

    print("Unified eval schema migration summary")
    print(f"- Cases discovered: {len(normalized_cases)}")
    print(f"- Validation errors: {len(validation_errors)}")
    if ignored_fix_type_cases:
        print(
            "- Ignored raw `fix_type` labels for "
            f"{ignored_fix_type_cases} eval_commits cases because they are collector-generated, not authoritative ground truth."
        )

    print("")
    print("Cases by source")
    for source, count in sorted(by_source.items()):
        print(f"- {source}: {count}")

    print("")
    print("Eval level support")
    for level in ("classification", "localization", "fix_description", "fix_code"):
        print(f"- {level}: {level_counts[level]}")

    print("")
    print("Eval level support by source")
    for source in sorted(by_source):
        counts = level_counts_by_source[source]
        print(
            f"- {source}: classification={counts['classification']}, "
            f"localization={counts['localization']}, "
            f"fix_description={counts['fix_description']}, "
            f"fix_code={counts['fix_code']}"
        )


def main() -> int:
    args = parse_args()
    schema = load_yaml(args.schema)
    if not isinstance(schema, dict):
        raise SystemExit(f"Invalid eval schema: {args.schema}")

    normalized_cases: list[dict[str, Any]] = []
    validation_errors: list[str] = []
    ignored_fix_type_cases = 0

    for case_path in iter_case_paths(args.cases_root):
        payload = load_yaml(case_path)
        if not isinstance(payload, dict):
            validation_errors.append(f"{case_path}: payload must be a mapping")
            continue

        normalized, normalize_errors = normalize_case(payload, case_path)
        normalized_cases.append(normalized)
        validation_errors.extend(normalize_errors)
        if normalized.get("source") == "eval_commits" and "fix_type" in payload:
            ignored_fix_type_cases += 1
        validation_errors.extend(validate_case(normalized, schema, case_path))

    print_summary(normalized_cases, validation_errors, ignored_fix_type_cases)

    if validation_errors:
        print("")
        print("Validation errors")
        for error in validation_errors[: args.show_errors]:
            print(f"- {error}")
        remaining = len(validation_errors) - args.show_errors
        if remaining > 0:
            print(f"- ... {remaining} more")
        return 1

    print("")
    print("All cases validated against the unified eval schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
