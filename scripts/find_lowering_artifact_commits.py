#!/usr/bin/env python3
"""Find likely lowering-artifact cases in eval_commits and try to capture verifier logs."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.verifier_oracle import verify_fix


DEFAULT_CASES_DIR = ROOT / "case_study" / "cases" / "eval_commits"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "lowering-artifact-candidates.md"
STRONG_FIX_TYPES = {"inline_hint", "volatile_hack", "attribute_annotation"}
SECONDARY_FIX_TYPES = {"alignment", "type_cast", "bounds_check"}
COMMIT_KEYWORD_PATTERNS: dict[str, re.Pattern[str]] = {
    "bounds": re.compile(r"\bbounds?\b", re.IGNORECASE),
    "range": re.compile(r"\brange\b", re.IGNORECASE),
    "clamp": re.compile(r"\bclamp(?:ing|ed)?\b", re.IGNORECASE),
    "mask": re.compile(r"\bmask(?:ing|ed)?\b", re.IGNORECASE),
    "volatile": re.compile(r"\bvolatile\b", re.IGNORECASE),
    "__always_inline": re.compile(r"__always_inline|always_inline", re.IGNORECASE),
    "lowering": re.compile(r"\blowering\b", re.IGNORECASE),
    "compiler": re.compile(r"\bcompiler\b", re.IGNORECASE),
    "LLVM": re.compile(r"\bllvm\b", re.IGNORECASE),
    "spill": re.compile(r"\bspill(?:ed|ing)?\b", re.IGNORECASE),
    "reload": re.compile(r"\breload(?:ed|ing)?\b", re.IGNORECASE),
    "htons": re.compile(r"\b(?:__bpf_)?htons\b", re.IGNORECASE),
    "ntohs": re.compile(r"\b(?:__bpf_)?ntohs\b", re.IGNORECASE),
    "endian": re.compile(r"\bendian\b", re.IGNORECASE),
    "bitwise": re.compile(r"\bbitwise\b", re.IGNORECASE),
    "OR operation": re.compile(r"\bor operation\b|\bbitwise or\b", re.IGNORECASE),
}
DIFF_SIGNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "clamp_or_mask": re.compile(r"\bclamp\b|\bmask\b", re.IGNORECASE),
    "verifier_visible_bound": re.compile(
        r"verifier-visible|bounded value|restoring a verifier-visible bound|keep precise track",
        re.IGNORECASE,
    ),
    "codegen_workaround": re.compile(
        r"older kernels accept|verifier-friendly code generation|inlining annotations|__always_inline|always_inline",
        re.IGNORECASE,
    ),
    "proof_reshaping": re.compile(
        r"\bproof\b|bounds check|explicit .*bound|unsigned range|signed range",
        re.IGNORECASE,
    ),
}
INSTRUCTION_LINE_RE = re.compile(r"^\d+: \(")
STATE_LINE_RE = re.compile(r"\bR\d[\w]*=")


@dataclass(slots=True)
class CandidateRecord:
    case_id: str
    path: Path
    fix_type: str | None
    taxonomy_class: str | None
    commit_message: str
    keyword_hits: list[str]
    diff_hits: list[str]
    reasons: list[str]
    score: int
    promising: bool
    compile_attempted: bool = False
    compiles: bool = False
    verifier_pass: bool | None = None
    verifier_log_quality: str | None = None
    verifier_log_chars: int = 0
    instruction_lines: int = 0
    state_lines: int = 0
    verifier_log_saved: bool = False
    error: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--min-score",
        type=int,
        default=4,
        help="Minimum heuristic score for invoking the verifier oracle (default: 4)",
    )
    return parser.parse_args()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def save_yaml(path: Path, payload: dict[str, Any]) -> None:
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=False, width=1000)
    path.write_text(text, encoding="utf-8")


def complete_program_shape(source: str) -> bool:
    return "#include" in source and "SEC(" in source


def matched_patterns(text: str, patterns: dict[str, re.Pattern[str]]) -> list[str]:
    return [label for label, pattern in patterns.items() if pattern.search(text)]


def score_case(case_path: Path, payload: dict[str, Any], min_score: int) -> CandidateRecord:
    case_id = str(payload.get("case_id") or case_path.stem)
    fix_type = str(payload.get("fix_type") or "").strip() or None
    taxonomy_class = str(payload.get("taxonomy_class") or "").strip() or None
    commit_message = str(payload.get("commit_message") or "")
    diff_summary = str(payload.get("diff_summary") or "")
    buggy_code = str(payload.get("buggy_code") or "")

    keyword_hits = matched_patterns(commit_message, COMMIT_KEYWORD_PATTERNS)
    diff_hits = matched_patterns(diff_summary, DIFF_SIGNAL_PATTERNS)

    score = 0
    reasons: list[str] = []
    if taxonomy_class == "lowering_artifact":
        score += 6
        reasons.append("taxonomy_class=lowering_artifact")
    if fix_type in STRONG_FIX_TYPES:
        score += 4
        reasons.append(f"strong lowering-like fix_type={fix_type}")
    elif fix_type in SECONDARY_FIX_TYPES:
        score += 2
        reasons.append(f"possible lowering-like fix_type={fix_type}")
    if keyword_hits:
        score += min(3, len(keyword_hits))
        reasons.append("commit_message keywords: " + ", ".join(keyword_hits))
    if diff_hits:
        score += 2
        reasons.append("diff_summary signals: " + ", ".join(diff_hits))
    if complete_program_shape(buggy_code):
        score += 1
        reasons.append("buggy_code looks like a standalone BPF object")

    promising = (
        score >= min_score
        or taxonomy_class == "lowering_artifact"
        or fix_type in STRONG_FIX_TYPES
        or complete_program_shape(buggy_code)
    )
    return CandidateRecord(
        case_id=case_id,
        path=case_path,
        fix_type=fix_type,
        taxonomy_class=taxonomy_class,
        commit_message=commit_message,
        keyword_hits=keyword_hits,
        diff_hits=diff_hits,
        reasons=reasons,
        score=score,
        promising=promising,
    )


def extract_verifier_log(payload: dict[str, Any]) -> str:
    verifier_log = payload.get("verifier_log")
    if isinstance(verifier_log, str):
        return verifier_log.strip()
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            joined = "\n".join(str(block).strip() for block in blocks if str(block).strip())
            return joined.strip()
    return ""


def classify_log_quality(verifier_log: str) -> tuple[str, int, int]:
    instruction_lines = sum(
        1 for line in verifier_log.splitlines() if INSTRUCTION_LINE_RE.match(line.strip())
    )
    state_lines = sum(
        1 for line in verifier_log.splitlines() if STATE_LINE_RE.search(line)
    )
    if instruction_lines >= 3 and state_lines >= 1:
        return "trace_rich", instruction_lines, state_lines
    if instruction_lines >= 1 or state_lines >= 1:
        return "partial", instruction_lines, state_lines
    return "message_only", instruction_lines, state_lines


def update_case_with_log(case_path: Path, payload: dict[str, Any], verifier_log: str) -> bool:
    normalized = verifier_log.strip()
    if not normalized:
        return False
    current = extract_verifier_log(payload)
    if current == normalized:
        return False
    payload["verifier_log"] = normalized
    save_yaml(case_path, payload)
    return True


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_report(records: list[CandidateRecord]) -> str:
    promising = [record for record in records if record.promising]
    compile_attempted = [record for record in promising if record.compile_attempted]
    compile_ok = [record for record in compile_attempted if record.compiles]
    with_logs = [record for record in compile_attempted if record.verifier_log_chars > 0]
    trace_rich = [record for record in with_logs if record.verifier_log_quality == "trace_rich"]
    saved = [record for record in with_logs if record.verifier_log_saved]

    fix_type_counts = Counter(record.fix_type or "None" for record in promising)
    compile_errors = Counter(record.error or "unknown error" for record in compile_attempted if not record.compiles)

    log_rows = [
        [
            f"`{record.case_id}`",
            f"`{record.fix_type or 'None'}`",
            str(record.score),
            "pass" if record.verifier_pass else "fail" if record.verifier_pass is False else "unknown",
            f"`{record.verifier_log_quality}`",
            str(record.instruction_lines),
            str(record.state_lines),
            "yes" if record.verifier_log_saved else "no",
        ]
        for record in sorted(with_logs, key=lambda item: (-item.score, item.case_id))
    ]
    top_without_logs = [
        [
            f"`{record.case_id}`",
            f"`{record.fix_type or 'None'}`",
            str(record.score),
            ", ".join(record.keyword_hits) or "none",
            ", ".join(record.diff_hits) or "none",
            record.error or "not attempted",
        ]
        for record in sorted(
            (record for record in promising if record.verifier_log_chars == 0),
            key=lambda item: (-item.score, item.case_id),
        )[:25]
    ]
    fix_type_rows = [
        [f"`{fix_type}`", str(count)]
        for fix_type, count in fix_type_counts.most_common()
    ]
    error_rows = [
        [message, str(count)]
        for message, count in compile_errors.most_common(10)
    ]

    lines = [
        "# Lowering-Artifact Candidate Scan",
        "",
        f"- Generated at: `{now_iso()}`",
        f"- Cases scanned: `{len(records)}`",
        f"- Promising candidates: `{len(promising)}`",
        f"- Oracle compile attempts: `{len(compile_attempted)}`",
        f"- Oracle compile successes: `{len(compile_ok)}`",
        f"- Verifier logs captured: `{len(with_logs)}`",
        f"- Trace-rich logs: `{len(trace_rich)}`",
        f"- YAML files updated with verifier logs: `{len(saved)}`",
        "",
        "## Promising Candidate Mix",
        "",
        markdown_table(["Fix Type", "Count"], fix_type_rows),
        "",
        "## Cases With Captured Verifier Logs",
        "",
    ]
    if log_rows:
        lines.append(
            markdown_table(
                [
                    "Case ID",
                    "Fix Type",
                    "Score",
                    "Verifier Result",
                    "Log Quality",
                    "Insn Lines",
                    "State Lines",
                    "YAML Updated",
                ],
                log_rows,
            )
        )
    else:
        lines.append("No promising candidate produced a verifier log on this host/toolchain.")

    lines.extend(
        [
            "",
            "## High-Scoring Candidates Without Logs",
            "",
        ]
    )
    if top_without_logs:
        lines.append(
            markdown_table(
                ["Case ID", "Fix Type", "Score", "Commit Keywords", "Diff Signals", "Last Oracle Error"],
                top_without_logs,
            )
        )
    else:
        lines.append("Every promising candidate with an oracle attempt produced a verifier log.")

    lines.extend(
        [
            "",
            "## Top Compile Failures",
            "",
        ]
    )
    if error_rows:
        lines.append(markdown_table(["Error", "Count"], error_rows))
    else:
        lines.append("No compile failures recorded.")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    case_paths = sorted(path for path in args.cases_dir.glob("*.yaml") if path.name != "index.yaml")
    records: list[CandidateRecord] = []

    for idx, case_path in enumerate(case_paths, start=1):
        payload = load_yaml(case_path)
        record = score_case(case_path, payload, args.min_score)
        if record.promising:
            existing_log = extract_verifier_log(payload)
            if existing_log:
                quality, instruction_lines, state_lines = classify_log_quality(existing_log)
                record.verifier_log_quality = quality
                record.verifier_log_chars = len(existing_log)
                record.instruction_lines = instruction_lines
                record.state_lines = state_lines
            else:
                buggy_code = str(payload.get("buggy_code") or "")
                if buggy_code.strip():
                    record.compile_attempted = True
                    result = verify_fix(buggy_code)
                    record.compiles = result.compiles
                    record.verifier_pass = result.verifier_pass
                    record.error = result.error
                    verifier_log = (result.verifier_log or "").strip()
                    if verifier_log:
                        quality, instruction_lines, state_lines = classify_log_quality(verifier_log)
                        record.verifier_log_quality = quality
                        record.verifier_log_chars = len(verifier_log)
                        record.instruction_lines = instruction_lines
                        record.state_lines = state_lines
                        record.verifier_log_saved = update_case_with_log(case_path, payload, verifier_log)
        records.append(record)

        if idx % 50 == 0:
            print(f"[progress] scanned {idx}/{len(case_paths)} eval_commits cases", file=sys.stderr)

    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(render_report(records), encoding="utf-8")

    with_logs = [record for record in records if record.verifier_log_chars > 0]
    print(f"Scanned {len(records)} cases; promising={sum(record.promising for record in records)}; logs={len(with_logs)}")
    if with_logs:
        print("Cases with verifier logs:")
        for record in sorted(with_logs, key=lambda item: (-item.score, item.case_id)):
            print(f"  {record.case_id}: {record.verifier_log_quality}")
    else:
        print("Cases with verifier logs: none")
    print(f"Report written to {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
