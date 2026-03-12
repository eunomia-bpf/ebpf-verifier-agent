#!/usr/bin/env python3
"""Generate synthetic eval cases from eval_commit buggy snippets."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT / "case_study" / "cases" / "eval_commits"
OUTPUT_DIR = ROOT / "case_study" / "cases" / "eval_commits_synthetic"
REPORT_PATH = ROOT / "docs" / "tmp" / "synthetic-cases-report.md"

STRICT_EXTENSIONS = {".c", ".h"}
RELAXED_EXTENSIONS = {".c", ".h", ".cc"}

TAXONOMY_BY_FIX_TYPE = {
    "inline_hint": "lowering_artifact",
    "volatile_hack": "lowering_artifact",
    "bounds_check": "source_bug",
    "null_check": "source_bug",
    "type_cast": "source_bug",
    "loop_rewrite": "verifier_limit",
    "helper_switch": "env_mismatch",
    "alignment": "source_bug",
    "attribute_annotation": "lowering_artifact",
    "refactor": "source_bug",
    "other": "source_bug",
}

FILE_PATH_RE = re.compile(r"^// FILE: (?P<path>.+)$", re.MULTILINE)
SCOPE_PREFIX_RE = re.compile(r"^[A-Za-z0-9_./+-]+:\s+")

STRUCTURAL_C_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("sec_macro", re.compile(r"\bSEC\s*\(")),
    (
        "function_decl",
        re.compile(
            r"\b(?:static\s+)?(?:__always_inline\s+|inline\s+|__noinline\s+)?"
            r"(?:unsigned\s+|signed\s+)?"
            r"(?:int|void|bool|char|long|short|size_t|ssize_t|u8|u16|u32|u64|"
            r"__u8|__u16|__u32|__u64|enum\s+\w+|struct\s+\w+|union\s+\w+)"
            r"\s+[*\w\s]*\([^;{}]*\)\s*\{"
        ),
    ),
    ("aggregate_decl", re.compile(r"\b(?:struct|union|enum|typedef)\s+\w")),
    ("control_flow", re.compile(r"\b(?:if|for|while|switch)\s*\(")),
    ("return_stmt", re.compile(r"\breturn\b[^\n;]*;")),
    ("bpf_call", re.compile(r"\bbpf_[A-Za-z0-9_]+\s*\(")),
]

AUXILIARY_C_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("include", re.compile(r"#include\s+[<\"]")),
    ("inline_attr", re.compile(r"\b__always_inline\b|\b__noinline\b")),
    (
        "c_types",
        re.compile(
            r"\b(?:int|void|bool|char|long|short|unsigned|signed|size_t|ssize_t|"
            r"u8|u16|u32|u64|__u8|__u16|__u32|__u64)\b"
        ),
    ),
    ("sizeof", re.compile(r"\bsizeof\s*\(")),
    ("null", re.compile(r"\bNULL\b")),
    ("pointer_arrow", re.compile(r"->")),
]

RUST_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("rust_file", re.compile(r"^// FILE: .+\.rs$", re.MULTILINE)),
    ("fn_keyword", re.compile(r"\bfn\s+\w")),
    ("impl_block", re.compile(r"\bimpl(?:<[^>\n]+>)?\b")),
    ("pub_keyword", re.compile(r"\bpub\s+(?:fn|struct|enum|mod|use|trait|unsafe|crate)\b")),
    ("use_crate", re.compile(r"\buse\s+crate\b")),
    ("mod_decl", re.compile(r"\bmod\s+\w")),
    ("cfg_attr", re.compile(r"#\[(?:cfg|allow|doc|expect)")),
    ("extern_crate", re.compile(r"\bextern\s+crate\b")),
    ("let_binding", re.compile(r"\blet\s+\w")),
    ("match_expr", re.compile(r"\bmatch\s+")),
    ("result_generic", re.compile(r"\bResult<")),
    ("option_generic", re.compile(r"\bOption<")),
    ("trait_decl", re.compile(r"\btrait\s+\w")),
    ("unsafe_block", re.compile(r"\bunsafe\s*\{")),
]


class BlockStyleDumper(yaml.SafeDumper):
    """YAML dumper that keeps code blobs readable."""


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


BlockStyleDumper.add_representer(str, _represent_str)


@dataclass(frozen=True)
class EvalCommitCase:
    path: Path
    case_id: str
    repository: str
    commit_hash: str
    commit_message: str
    fix_type: str
    buggy_code: str
    fixed_code: str


@dataclass(frozen=True)
class FilterDecision:
    accepted: bool
    reason: str
    extension: str
    structural_hits: tuple[str, ...]
    auxiliary_hits: tuple[str, ...]
    rust_hits: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=INPUT_DIR)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--report-path", type=Path, default=REPORT_PATH)
    parser.add_argument(
        "--min-buggy-chars",
        type=int,
        default=30,
        help="Minimum buggy_code length for the first pass.",
    )
    parser.add_argument(
        "--fallback-min-buggy-chars",
        type=int,
        default=15,
        help="Minimum buggy_code length for the fallback pass.",
    )
    parser.add_argument(
        "--target-min-cases",
        type=int,
        default=200,
        help="Retry with a looser filter if the first pass generates fewer cases.",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def load_eval_commit(path: Path) -> EvalCommitCase:
    payload = load_yaml(path)
    return EvalCommitCase(
        path=path,
        case_id=str(payload.get("case_id") or "").strip(),
        repository=str(payload.get("repository") or "").strip(),
        commit_hash=str(payload.get("commit_hash") or "").strip(),
        commit_message=str(payload.get("commit_message") or "").strip(),
        fix_type=str(payload.get("fix_type") or "other").strip() or "other",
        buggy_code=str(payload.get("buggy_code") or "").strip(),
        fixed_code=str(payload.get("fixed_code") or "").strip(),
    )


def extract_extension(code: str) -> str:
    match = FILE_PATH_RE.search(code)
    if not match:
        return ""
    return Path(match.group("path").strip()).suffix.lower()


def collect_hits(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> tuple[str, ...]:
    return tuple(name for name, pattern in patterns if pattern.search(text))


def classify_buggy_code(code: str, min_chars: int, relaxed: bool) -> FilterDecision:
    text = code.strip()
    if len(text) < min_chars:
        return FilterDecision(False, "too_short", "", (), (), ())

    extension = extract_extension(text)
    allowed_extensions = RELAXED_EXTENSIONS if relaxed else STRICT_EXTENSIONS
    if extension and extension not in allowed_extensions:
        if extension == ".rs":
            return FilterDecision(False, "rust_source", extension, (), (), ("rust_file",))
        return FilterDecision(False, "unsupported_extension", extension, (), (), ())

    structural_hits = collect_hits(text, STRUCTURAL_C_HINTS)
    auxiliary_hits = collect_hits(text, AUXILIARY_C_HINTS)
    rust_hits = collect_hits(text, RUST_HINTS)

    c_score = (2 * len(structural_hits)) + len(auxiliary_hits)
    has_c_structure = bool(structural_hits)
    min_c_score = 2 if relaxed else 3

    if not has_c_structure and c_score < min_c_score:
        return FilterDecision(False, "not_c_like", extension, structural_hits, auxiliary_hits, rust_hits)

    if rust_hits and c_score < 4:
        return FilterDecision(False, "rust_source", extension, structural_hits, auxiliary_hits, rust_hits)

    return FilterDecision(True, "accepted", extension, structural_hits, auxiliary_hits, rust_hits)


def normalize_fix_description(commit_message: str, fix_type: str) -> str:
    subject = " ".join(commit_message.split())
    if not subject:
        subject = f"{fix_type.replace('_', ' ')} fix from original eval_commit"
    subject = SCOPE_PREFIX_RE.sub("", subject, count=1)
    if subject and subject[-1] not in ".!?":
        subject = f"{subject}."
    if subject:
        subject = subject[0].upper() + subject[1:]
    return subject


def build_synthetic_payload(case: EvalCommitCase) -> dict[str, Any]:
    original_fix_type = case.fix_type or "other"
    return {
        "case_id": f"synth-{case.case_id}",
        "source": "eval_commits_synthetic",
        "original_case_id": case.case_id,
        "original_repository": case.repository,
        "original_commit": case.commit_hash,
        "original_commit_message": case.commit_message,
        "original_fix_type": original_fix_type,
        "fix_type": original_fix_type,
        "taxonomy_class": TAXONOMY_BY_FIX_TYPE.get(original_fix_type, "source_bug"),
        "source_snippets": [case.buggy_code],
        "fixed_code": case.fixed_code,
        "fix_description": normalize_fix_description(case.commit_message, original_fix_type),
        "verifier_log": "",
    }


def write_yaml(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.dump(
            payload,
            handle,
            Dumper=BlockStyleDumper,
            sort_keys=False,
            allow_unicode=False,
            width=1000,
        )


def format_counter_table(counter: Counter[str], header: str) -> str:
    lines = [f"| {header} | Count |", "| --- | ---: |"]
    for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{key}` | {count} |")
    return "\n".join(lines)


def snippet_preview(code: str, line_count: int = 10) -> str:
    return "\n".join(code.splitlines()[:line_count]).rstrip()


def remove_stale_outputs(output_dir: Path, keep_files: set[Path]) -> int:
    removed = 0
    for path in output_dir.glob("synth-*.yaml"):
        if path not in keep_files:
            path.unlink()
            removed += 1
    return removed


def select_example_payloads(generated_payloads: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen_repositories: set[str] = set()
    seen_fix_types: set[str] = set()
    seen_case_ids: set[str] = set()

    for payload in generated_payloads:
        if len(examples) >= limit:
            break
        repository = payload["original_repository"]
        if repository in seen_repositories:
            continue
        examples.append(payload)
        seen_case_ids.add(payload["case_id"])
        seen_repositories.add(repository)
        seen_fix_types.add(payload["original_fix_type"])

    if len(examples) < limit:
        for payload in generated_payloads:
            if len(examples) >= limit:
                break
            if payload["case_id"] in seen_case_ids:
                continue
            fix_type = payload["original_fix_type"]
            if fix_type in seen_fix_types:
                continue
            examples.append(payload)
            seen_case_ids.add(payload["case_id"])
            seen_fix_types.add(fix_type)

    if len(examples) < limit:
        for payload in generated_payloads:
            if len(examples) >= limit:
                break
            if payload["case_id"] in seen_case_ids:
                continue
            examples.append(payload)
            seen_case_ids.add(payload["case_id"])

    return examples


def write_report(
    report_path: Path,
    total_inputs: int,
    generated_payloads: list[dict[str, Any]],
    examples: list[dict[str, Any]],
    skip_reasons: Counter[str],
    relaxed_used: bool,
    stale_removed: int,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)

    taxonomy_counts = Counter(payload["taxonomy_class"] for payload in generated_payloads)
    fix_type_counts = Counter(payload["original_fix_type"] for payload in generated_payloads)
    repository_counts = Counter(payload["original_repository"] for payload in generated_payloads)

    issues: list[str] = []
    skipped_total = total_inputs - len(generated_payloads)
    issues.append(
        f"Skipped {skipped_total} of {total_inputs} eval_commit inputs based on the C-like/Rust filter."
    )
    for reason, count in sorted(skip_reasons.items(), key=lambda item: (-item[1], item[0])):
        if reason == "accepted" or count == 0:
            continue
        issues.append(f"Skip reason `{reason}` affected {count} case(s).")
    if relaxed_used:
        issues.append("The fallback relaxed filter was used because the strict pass landed below the target.")
    else:
        issues.append("The strict filter already exceeded the 200-case target, so no fallback pass was needed.")
    issues.append("All synthetic cases leave `verifier_log` empty because the source eval_commit corpus does not carry logs.")
    if stale_removed:
        issues.append(f"Removed {stale_removed} stale synthetic YAML file(s) from a prior run.")

    lines = [
        "# Synthetic Eval Cases Report",
        "",
        f"- Generated at: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Total input eval_commits: `{total_inputs}`",
        f"- Total generated synthetic cases: `{len(generated_payloads)}`",
        f"- Output directory: `case_study/cases/eval_commits_synthetic/`",
        "",
        "## Breakdown by taxonomy_class",
        "",
        format_counter_table(taxonomy_counts, "taxonomy_class"),
        "",
        "## Breakdown by fix_type",
        "",
        format_counter_table(fix_type_counts, "fix_type"),
        "",
        "## Breakdown by repository",
        "",
        format_counter_table(repository_counts, "repository"),
        "",
        "## Example cases",
        "",
    ]

    for payload in examples:
        lines.extend(
            [
                f"### `{payload['case_id']}`",
                "",
                f"- Original commit: `{payload['original_commit']}`",
                f"- Repository: `{payload['original_repository']}`",
                f"- Fix type: `{payload['original_fix_type']}`",
                "",
                "```c",
                snippet_preview(payload["source_snippets"][0]),
                "```",
                "",
            ]
        )

    lines.extend(["## Issues encountered", ""])
    for issue in issues:
        lines.append(f"- {issue}")
    lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def select_cases(
    cases: list[EvalCommitCase],
    min_chars: int,
    relaxed: bool,
) -> tuple[list[EvalCommitCase], Counter[str]]:
    selected: list[EvalCommitCase] = []
    skip_reasons: Counter[str] = Counter()
    for case in cases:
        decision = classify_buggy_code(case.buggy_code, min_chars=min_chars, relaxed=relaxed)
        skip_reasons[decision.reason] += 1
        if not decision.accepted:
            continue
        selected.append(case)
    return selected, skip_reasons


def main() -> None:
    args = parse_args()
    input_dir = args.input_dir
    output_dir = args.output_dir

    cases = [load_eval_commit(path) for path in sorted(input_dir.glob("*.yaml"))]
    total_inputs = len(cases)

    selected_cases, skip_reasons = select_cases(
        cases,
        min_chars=args.min_buggy_chars,
        relaxed=False,
    )
    relaxed_used = False

    if len(selected_cases) < args.target_min_cases:
        relaxed_used = True
        selected_cases, skip_reasons = select_cases(
            cases,
            min_chars=args.fallback_min_buggy_chars,
            relaxed=True,
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    generated_payloads: list[dict[str, Any]] = []
    written_files: set[Path] = set()
    for case in selected_cases:
        payload = build_synthetic_payload(case)
        output_path = output_dir / f"{payload['case_id']}.yaml"
        write_yaml(output_path, payload)
        written_files.add(output_path)
        generated_payloads.append(payload)

    stale_removed = remove_stale_outputs(output_dir, written_files)

    write_report(
        args.report_path,
        total_inputs=total_inputs,
        generated_payloads=generated_payloads,
        examples=select_example_payloads(generated_payloads),
        skip_reasons=skip_reasons,
        relaxed_used=relaxed_used,
        stale_removed=stale_removed,
    )

    taxonomy_counts = Counter(payload["taxonomy_class"] for payload in generated_payloads)
    fix_type_counts = Counter(payload["original_fix_type"] for payload in generated_payloads)

    print(f"Loaded {total_inputs} eval_commit cases from {input_dir}")
    print(f"Generated {len(generated_payloads)} synthetic cases into {output_dir}")
    print(f"Report written to {args.report_path}")
    print(f"Filter mode: {'relaxed' if relaxed_used else 'strict'}")
    print(f"Taxonomy breakdown: {dict(sorted(taxonomy_counts.items()))}")
    print(f"Fix type breakdown: {dict(sorted(fix_type_counts.items()))}")


if __name__ == "__main__":
    main()
