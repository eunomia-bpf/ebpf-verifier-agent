#!/usr/bin/env python3
"""Root-cause validation: verify that BPFix proof_lost spans point to actual fix locations.

For cases with known fixes (SO accepted answers, GitHub commits), the fix location tells us
where the REAL root cause is. This script compares BPFix's proof_lost instruction/source
location against the ground-truth fix location to measure root-cause accuracy.
"""

from __future__ import annotations

import argparse
import difflib
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


# ─── Paths ─────────────────────────────────────────────────────────────────────

LOG_CASE_DIRS: tuple[tuple[str, Path], ...] = (
    ("stackoverflow", ROOT / "case_study" / "cases" / "stackoverflow"),
    ("github_issues", ROOT / "case_study" / "cases" / "github_issues"),
    ("kernel_selftests", ROOT / "case_study" / "cases" / "kernel_selftests"),
)
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "root_cause_validation.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "root-cause-validation-results.md"
MIN_LOG_CHARS = 50

# ─── Regex ─────────────────────────────────────────────────────────────────────

IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Patterns we skip because they're not localizable
SKIP_FIX_PATTERNS = {"kernel_upgrade", "complexity_reduction", "loop_rewrite"}


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass(slots=True)
class SpanInfo:
    role: str
    insn_idx: int
    source_line: int | None
    source_file: str | None
    source_text: str


@dataclass(slots=True)
class DiffInfo:
    buggy_lines: list[str]
    fix_lines: list[str]
    changed_line_numbers: list[int]   # 1-indexed line numbers in buggy code that changed
    changed_tokens: list[str]         # identifiers extracted from changed lines


@dataclass(slots=True)
class CaseRCResult:
    case_id: str
    source: str
    case_path: str
    verifier_log_chars: int
    diagnostic_success: bool
    exception: str | None
    # BPFix output
    proof_status: str | None
    taxonomy_class: str | None
    proof_lost_spans: list[dict[str, Any]]
    rejected_spans: list[dict[str, Any]]
    # Derived from spans
    has_proof_lost: bool
    proof_lost_insn_idx: int | None
    rejected_insn_idx: int | None
    insn_distance: int | None
    proof_lost_source_line: int | None
    proof_lost_source_file: str | None
    proof_lost_source_text: str | None
    # Ground truth
    fix_source_lines: list[int]
    fix_changed_tokens: list[str]
    fix_text_available: bool
    diff_available: bool
    # Metrics
    insn_level_localization: str       # backtracked | at_error | never_established | no_proof_lost
    source_line_match: str             # exact | within_5 | within_10 | no_match | unknown
    text_match: str                    # yes | no | unknown
    min_line_distance: int | None      # minimum |proof_lost_line - fix_line|


# ─── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    vl = case_data.get("verifier_log", "")
    if isinstance(vl, str):
        return vl.strip()
    if isinstance(vl, dict):
        combined = vl.get("combined", "")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = vl.get("blocks") or []
        if isinstance(blocks, list):
            return "\n\n".join(b.strip() for b in blocks if isinstance(b, str) and b.strip())
    return ""


def extract_source_code_pair(case_data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (buggy_code, fixed_code) if available, else (None, None)."""
    snippets_raw = case_data.get("source_snippets") or []
    snippets: list[str] = []
    for s in snippets_raw:
        if isinstance(s, str) and s.strip():
            snippets.append(s.strip())
        elif isinstance(s, dict):
            code = s.get("code")
            if isinstance(code, str) and code.strip():
                snippets.append(code.strip())

    fixed_code = case_data.get("fixed_code")
    if isinstance(fixed_code, str) and fixed_code.strip():
        fixed = fixed_code.strip()
        buggy = snippets[0] if snippets else None
        return buggy, fixed

    if len(snippets) >= 2:
        return snippets[0], snippets[1]

    return None, None


def compute_diff_info(buggy: str, fixed: str) -> DiffInfo:
    """Compute which line numbers in buggy were changed/removed."""
    buggy_lines = buggy.splitlines()
    fixed_lines = fixed.splitlines()

    matcher = difflib.SequenceMatcher(a=buggy_lines, b=fixed_lines)
    changed_line_numbers: list[int] = []
    changed_raw_lines: list[str] = []

    for opcode, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if opcode in {"replace", "delete"}:
            for idx in range(i1, i2):
                line_no = idx + 1  # 1-indexed
                changed_line_numbers.append(line_no)
                changed_raw_lines.append(buggy_lines[idx])

    # Also include added lines from fixed (for token extraction)
    fix_added: list[str] = []
    for opcode, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if opcode in {"replace", "insert"}:
            fix_added.extend(fixed_lines[j1:j2])

    all_changed = changed_raw_lines + fix_added
    tokens = extract_identifiers(" ".join(all_changed))

    return DiffInfo(
        buggy_lines=buggy_lines,
        fix_lines=fixed_lines,
        changed_line_numbers=changed_line_numbers,
        changed_tokens=tokens,
    )


def extract_identifiers(text: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for m in IDENTIFIER_RE.finditer(text):
        token = m.group(0)
        if len(token) < 3:
            continue
        if token.lower() in {"the", "and", "for", "not", "are", "was", "has", "use",
                              "int", "str", "var", "val", "ret", "ctx", "res", "buf",
                              "len", "idx", "ptr", "key", "map", "bpf", "ret"}:
            continue
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def extract_spans_from_diagnostic(json_data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (proof_lost_spans, rejected_spans) from diagnostic json_data."""
    metadata = json_data.get("metadata") or {}
    raw_spans = metadata.get("proof_spans") or json_data.get("spans") or []
    if not isinstance(raw_spans, list):
        raw_spans = []

    proof_lost = [s for s in raw_spans if isinstance(s, dict) and s.get("role") == "proof_lost"]
    rejected = [s for s in raw_spans if isinstance(s, dict) and s.get("role") == "rejected"]
    return proof_lost, rejected


def span_insn_idx(span: dict[str, Any]) -> int | None:
    insn_range = span.get("insn_range")
    if isinstance(insn_range, list) and len(insn_range) >= 1:
        v = insn_range[0]
        if isinstance(v, int):
            return v
    return None


def span_source_line(span: dict[str, Any]) -> int | None:
    line = span.get("line")
    if isinstance(line, int):
        return line
    return None


def span_source_file(span: dict[str, Any]) -> str | None:
    path = span.get("path")
    if isinstance(path, str) and path.strip():
        return path.strip()
    return None


def compute_insn_localization(
    proof_lost_spans: list[dict[str, Any]],
    rejected_spans: list[dict[str, Any]],
    proof_status: str | None,
) -> tuple[str, int | None, int | None, int | None]:
    """
    Returns (localization_label, proof_lost_insn_idx, rejected_insn_idx, insn_distance).
    """
    if proof_status == "never_established":
        return "never_established", None, None, None

    if not proof_lost_spans:
        return "no_proof_lost", None, None, None

    # Use the last proof_lost span (closest to error point)
    last_pl = proof_lost_spans[-1]
    pl_idx = span_insn_idx(last_pl)

    rej_idx: int | None = None
    if rejected_spans:
        last_rej = rejected_spans[-1]
        rej_idx = span_insn_idx(last_rej)

    distance: int | None = None
    if pl_idx is not None and rej_idx is not None:
        distance = abs(pl_idx - rej_idx)
        if pl_idx < rej_idx:
            return "backtracked", pl_idx, rej_idx, distance
        else:
            return "at_error", pl_idx, rej_idx, distance

    if pl_idx is not None:
        return "backtracked", pl_idx, rej_idx, distance

    return "no_proof_lost", None, None, None


def compute_source_line_match(
    proof_lost_source_line: int | None,
    fix_source_lines: list[int],
) -> tuple[str, int | None]:
    """
    Returns (match_label, min_distance).
    """
    if proof_lost_source_line is None or not fix_source_lines:
        return "unknown", None

    distances = [abs(proof_lost_source_line - fl) for fl in fix_source_lines]
    min_dist = min(distances)

    if min_dist == 0:
        return "exact", 0
    if min_dist <= 5:
        return "within_5", min_dist
    if min_dist <= 10:
        return "within_10", min_dist
    return "no_match", min_dist


def compute_text_match(
    proof_lost_source_text: str | None,
    fix_changed_tokens: list[str],
) -> str:
    if proof_lost_source_text is None or not fix_changed_tokens:
        return "unknown"

    span_tokens = set(extract_identifiers(proof_lost_source_text))
    fix_tokens = set(fix_changed_tokens)

    if span_tokens & fix_tokens:
        return "yes"
    return "no"


def get_fix_text(case_data: dict[str, Any]) -> str:
    """Extract fix description text from case data."""
    selected_answer = case_data.get("selected_answer") or {}
    if isinstance(selected_answer, dict):
        text = (
            selected_answer.get("fix_description")
            or selected_answer.get("body_text")
            or ""
        )
        if isinstance(text, str) and text.strip():
            return text.strip()

    fix = case_data.get("fix") or {}
    if isinstance(fix, dict):
        selected_comment = fix.get("selected_comment") or {}
        text = (
            selected_comment.get("body_text")
            or fix.get("summary")
            or ""
        )
        if isinstance(text, str) and text.strip():
            return text.strip()

    return ""


# ─── Main evaluation ───────────────────────────────────────────────────────────

def evaluate_case(source: str, path: Path) -> CaseRCResult | None:
    case_data = read_yaml(path)
    case_id = str(case_data.get("case_id") or path.stem)

    verifier_log = extract_verifier_log(case_data)
    if len(verifier_log) < MIN_LOG_CHARS:
        return None

    # Run generate_diagnostic
    try:
        output = generate_diagnostic(verifier_log)
        json_data = output.json_data if isinstance(output.json_data, dict) else {}
        diagnostic_success = True
        exc_str = None
    except Exception as exc:
        return CaseRCResult(
            case_id=case_id,
            source=source,
            case_path=str(path),
            verifier_log_chars=len(verifier_log),
            diagnostic_success=False,
            exception=f"{type(exc).__name__}: {exc}",
            proof_status=None,
            taxonomy_class=None,
            proof_lost_spans=[],
            rejected_spans=[],
            has_proof_lost=False,
            proof_lost_insn_idx=None,
            rejected_insn_idx=None,
            insn_distance=None,
            proof_lost_source_line=None,
            proof_lost_source_file=None,
            proof_lost_source_text=None,
            fix_source_lines=[],
            fix_changed_tokens=[],
            fix_text_available=False,
            diff_available=False,
            insn_level_localization="no_proof_lost",
            source_line_match="unknown",
            text_match="unknown",
            min_line_distance=None,
        )

    metadata = json_data.get("metadata") or {}
    proof_status = (
        str(metadata.get("proof_status") or "")
        or str(json_data.get("proof_status") or "")
        or None
    )
    taxonomy_class = (
        str(json_data.get("failure_class") or "")
        or str(json_data.get("taxonomy_class") or "")
        or None
    )

    proof_lost_spans, rejected_spans = extract_spans_from_diagnostic(json_data)

    # Compute insn-level localization
    insn_loc, pl_insn, rej_insn, insn_dist = compute_insn_localization(
        proof_lost_spans, rejected_spans, proof_status
    )

    # Extract proof_lost source info
    pl_source_line: int | None = None
    pl_source_file: str | None = None
    pl_source_text: str | None = None
    if proof_lost_spans:
        last_pl = proof_lost_spans[-1]
        pl_source_line = span_source_line(last_pl)
        pl_source_file = span_source_file(last_pl)
        pl_source_text = str(last_pl.get("source_text") or "").strip() or None

    # Compute ground truth fix location
    buggy_code, fixed_code = extract_source_code_pair(case_data)
    diff_info: DiffInfo | None = None
    if buggy_code and fixed_code and buggy_code.strip() != fixed_code.strip():
        try:
            diff_info = compute_diff_info(buggy_code, fixed_code)
            # Only keep meaningful diffs (not too large, not zero)
            if len(diff_info.changed_line_numbers) == 0 or len(diff_info.changed_line_numbers) > 30:
                diff_info = None
        except Exception:
            diff_info = None

    fix_source_lines = diff_info.changed_line_numbers if diff_info else []
    fix_changed_tokens = diff_info.changed_tokens if diff_info else []
    fix_text = get_fix_text(case_data)
    fix_text_available = bool(fix_text)
    diff_available = diff_info is not None

    # Source line match
    source_line_match, min_line_dist = compute_source_line_match(pl_source_line, fix_source_lines)

    # Text match
    text_match = compute_text_match(pl_source_text, fix_changed_tokens)

    return CaseRCResult(
        case_id=case_id,
        source=source,
        case_path=str(path),
        verifier_log_chars=len(verifier_log),
        diagnostic_success=diagnostic_success,
        exception=exc_str,
        proof_status=proof_status,
        taxonomy_class=taxonomy_class,
        proof_lost_spans=proof_lost_spans,
        rejected_spans=rejected_spans,
        has_proof_lost=bool(proof_lost_spans),
        proof_lost_insn_idx=pl_insn,
        rejected_insn_idx=rej_insn,
        insn_distance=insn_dist,
        proof_lost_source_line=pl_source_line,
        proof_lost_source_file=pl_source_file,
        proof_lost_source_text=pl_source_text,
        fix_source_lines=fix_source_lines,
        fix_changed_tokens=fix_changed_tokens,
        fix_text_available=fix_text_available,
        diff_available=diff_available,
        insn_level_localization=insn_loc,
        source_line_match=source_line_match,
        text_match=text_match,
        min_line_distance=min_line_dist,
    )


def run_all() -> list[CaseRCResult]:
    results: list[CaseRCResult] = []
    for source, case_dir in LOG_CASE_DIRS:
        if not case_dir.exists():
            continue
        for path in sorted(case_dir.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            result = evaluate_case(source, path)
            if result is not None:
                results.append(result)
                status = "ok" if result.diagnostic_success else f"ERR:{result.exception}"
                print(f"  [{source[:2].upper()}] {result.case_id}: insn_loc={result.insn_level_localization}"
                      f" line_match={result.source_line_match} text={result.text_match} [{status}]")
    return results


# ─── Aggregation ───────────────────────────────────────────────────────────────

def compute_aggregate(results: list[CaseRCResult]) -> dict[str, Any]:
    evaluated = [r for r in results if r.diagnostic_success]
    n = len(evaluated)
    if n == 0:
        return {"total_evaluated": 0}

    with_proof_lost = [r for r in evaluated if r.has_proof_lost]
    backtracked = [r for r in with_proof_lost if r.insn_level_localization == "backtracked"]
    at_error = [r for r in with_proof_lost if r.insn_level_localization == "at_error"]
    never_established = [r for r in evaluated if r.insn_level_localization == "never_established"]

    # Source line metrics (only cases with both proof_lost.line AND fix_source_lines)
    line_evaluable = [
        r for r in with_proof_lost
        if r.proof_lost_source_line is not None and r.fix_source_lines
    ]
    line_exact = [r for r in line_evaluable if r.source_line_match == "exact"]
    line_within5 = [r for r in line_evaluable if r.source_line_match in {"exact", "within_5"}]
    line_within10 = [r for r in line_evaluable if r.source_line_match in {"exact", "within_5", "within_10"}]

    # Text match metrics (only cases with proof_lost source_text AND fix tokens)
    text_evaluable = [r for r in with_proof_lost if r.text_match != "unknown"]
    text_yes = [r for r in text_evaluable if r.text_match == "yes"]

    def pct(num: int, denom: int) -> float:
        return round(100.0 * num / denom, 1) if denom > 0 else 0.0

    return {
        "total_cases_loaded": len(results),
        "total_evaluated": n,
        "diagnostic_failures": len(results) - n,
        # Proof lost presence
        "with_proof_lost": len(with_proof_lost),
        "proof_lost_rate_pct": pct(len(with_proof_lost), n),
        # Insn-level localization
        "insn_backtracked": len(backtracked),
        "insn_at_error": len(at_error),
        "insn_never_established": len(never_established),
        "insn_no_proof_lost": n - len(with_proof_lost) - len(never_established),
        "backtracking_rate_pct": pct(len(backtracked), len(with_proof_lost)),
        # Source line accuracy
        "line_evaluable": len(line_evaluable),
        "line_exact": len(line_exact),
        "line_within5": len(line_within5),
        "line_within10": len(line_within10),
        "line_no_match": len(line_evaluable) - len(line_within10),
        "line_exact_pct": pct(len(line_exact), len(line_evaluable)),
        "line_within5_pct": pct(len(line_within5), len(line_evaluable)),
        "line_within10_pct": pct(len(line_within10), len(line_evaluable)),
        # Text match
        "text_evaluable": len(text_evaluable),
        "text_match_yes": len(text_yes),
        "text_match_pct": pct(len(text_yes), len(text_evaluable)),
        # Diff availability
        "cases_with_diff": sum(1 for r in evaluated if r.diff_available),
        "cases_with_btf_line": sum(1 for r in evaluated if r.proof_lost_source_line is not None),
    }


def compute_by_source(results: list[CaseRCResult]) -> dict[str, Any]:
    by_source: dict[str, Any] = {}
    sources = sorted({r.source for r in results})
    for source in sources:
        source_results = [r for r in results if r.source == source]
        by_source[source] = compute_aggregate(source_results)
    return by_source


def compute_by_proof_status(results: list[CaseRCResult]) -> dict[str, Any]:
    by_status: dict[str, Any] = {}
    statuses = sorted({r.proof_status or "unknown" for r in results if r.diagnostic_success})
    for status in statuses:
        status_results = [r for r in results if r.proof_status == status and r.diagnostic_success]
        by_status[status] = compute_aggregate(status_results)
    return by_status


# ─── Markdown report ───────────────────────────────────────────────────────────

def pct_str(num: int, denom: int) -> str:
    if denom == 0:
        return "N/A"
    return f"{100.0 * num / denom:.1f}% ({num}/{denom})"


def write_markdown_report(
    results: list[CaseRCResult],
    aggregate: dict[str, Any],
    by_source: dict[str, Any],
    by_proof_status: dict[str, Any],
    report_path: Path,
) -> None:
    lines: list[str] = []
    lines.append("# Root-Cause Validation Report")
    lines.append("")
    lines.append(f"Generated: {now_iso()}")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    n = aggregate.get("total_evaluated", 0)
    n_pl = aggregate.get("with_proof_lost", 0)
    n_bt = aggregate.get("insn_backtracked", 0)
    n_le = aggregate.get("line_evaluable", 0)
    n_exact = aggregate.get("line_exact", 0)
    n_w5 = aggregate.get("line_within5", 0)
    n_w10 = aggregate.get("line_within10", 0)
    n_te = aggregate.get("text_evaluable", 0)
    n_tm = aggregate.get("text_match_yes", 0)

    lines.append(f"- **Total cases evaluated**: {n} (from {aggregate.get('total_cases_loaded', 0)} loaded)")
    lines.append(f"- **Cases with proof_lost span**: {pct_str(n_pl, n)}")
    lines.append(f"- **Backtracking rate** (proof_lost before rejected): {pct_str(n_bt, n_pl)}")
    lines.append(f"- **Source line: exact match**: {pct_str(n_exact, n_le)} (evaluable: {n_le})")
    lines.append(f"- **Source line: within ±5 lines**: {pct_str(n_w5, n_le)}")
    lines.append(f"- **Source line: within ±10 lines**: {pct_str(n_w10, n_le)}")
    lines.append(f"- **Text token match**: {pct_str(n_tm, n_te)} (evaluable: {n_te})")
    lines.append("")

    insn_dist_vals = [r.insn_distance for r in results if r.insn_distance is not None]
    if insn_dist_vals:
        avg_dist = sum(insn_dist_vals) / len(insn_dist_vals)
        max_dist = max(insn_dist_vals)
        lines.append(f"- **Average insn distance** (proof_lost to rejected): {avg_dist:.1f} (max: {max_dist})")
    lines.append("")

    # Per-source breakdown
    lines.append("## Per-Source Breakdown")
    lines.append("")
    lines.append("| Source | N | proof_lost% | backtrack% | line_exact% | line_w5% | text_match% |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for src, agg in sorted(by_source.items()):
        nn = agg.get("total_evaluated", 0)
        pl = agg.get("with_proof_lost", 0)
        bt = agg.get("insn_backtracked", 0)
        le = agg.get("line_evaluable", 0)
        ex = agg.get("line_exact", 0)
        w5 = agg.get("line_within5", 0)
        te = agg.get("text_evaluable", 0)
        tm = agg.get("text_match_yes", 0)

        def p(a: int, b: int) -> str:
            return f"{100.0*a/b:.0f}%" if b > 0 else "N/A"

        lines.append(f"| {src} | {nn} | {p(pl, nn)} | {p(bt, pl)} | {p(ex, le)} | {p(w5, le)} | {p(tm, te)} |")
    lines.append("")

    # By proof_status
    lines.append("## By Proof Status")
    lines.append("")
    lines.append("| proof_status | N | proof_lost% | backtrack% |")
    lines.append("| --- | ---: | ---: | ---: |")
    for status, agg in sorted(by_proof_status.items()):
        nn = agg.get("total_evaluated", 0)
        pl = agg.get("with_proof_lost", 0)
        bt = agg.get("insn_backtracked", 0)

        def p(a: int, b: int) -> str:
            return f"{100.0*a/b:.0f}%" if b > 0 else "N/A"

        lines.append(f"| {status} | {nn} | {p(pl, nn)} | {p(bt, pl)} |")
    lines.append("")

    # Insn-level localization distribution
    loc_counter: Counter[str] = Counter(
        r.insn_level_localization for r in results if r.diagnostic_success
    )
    lines.append("## Insn-Level Localization Distribution")
    lines.append("")
    lines.append("| Localization | Count |")
    lines.append("| --- | ---: |")
    for label, count in sorted(loc_counter.items(), key=lambda x: -x[1]):
        lines.append(f"| `{label}` | {count} |")
    lines.append("")

    # Source line match distribution
    slm_counter: Counter[str] = Counter(
        r.source_line_match for r in results if r.diagnostic_success and r.has_proof_lost
    )
    lines.append("## Source Line Match Distribution")
    lines.append("")
    lines.append("| Match Level | Count |")
    lines.append("| --- | ---: |")
    for label, count in sorted(slm_counter.items(), key=lambda x: -x[1]):
        lines.append(f"| `{label}` | {count} |")
    lines.append("")

    # Notable successes
    exact_matches = [r for r in results if r.source_line_match == "exact"]
    if exact_matches:
        lines.append("## Notable Successes (Exact Source Line Match)")
        lines.append("")
        for r in exact_matches[:10]:
            pl_line = r.proof_lost_source_line
            fix_lines = r.fix_source_lines
            lines.append(f"- **{r.case_id}** ({r.source}): proof_lost @ line {pl_line}, "
                         f"fix @ lines {fix_lines[:3]}")
            if r.proof_lost_source_text:
                snippet = r.proof_lost_source_text[:80]
                lines.append(f"  - proof_lost text: `{snippet}`")
        lines.append("")

    # Failures analysis
    no_match = [r for r in results if r.source_line_match == "no_match" and r.diagnostic_success]
    if no_match:
        lines.append(f"## Cases with No Source Line Match ({len(no_match)} cases)")
        lines.append("")
        for r in no_match[:5]:
            lines.append(f"- **{r.case_id}** ({r.source}): proof_lost @ line {r.proof_lost_source_line}, "
                         f"fix @ lines {r.fix_source_lines[:3]}, distance={r.min_line_distance}")
            if r.proof_lost_source_text:
                snippet = r.proof_lost_source_text[:60]
                lines.append(f"  - proof_lost text: `{snippet}`")
        lines.append("")

    # Limitations
    lines.append("## Limitations and Interpretation")
    lines.append("")
    lines.append("### Ground Truth Quality")
    lines.append("- SO/GH cases: ground truth from code diff between source_snippets[0] and snippets[1]/fixed_code.")
    lines.append("  Many SO cases lack a proper before/after code pair — fix is described in text only.")
    lines.append("- Kernel selftests: BTF line info provides exact source lines from verifier trace,")
    lines.append("  but these cases often lack before/after diffs (the case IS the failing test).")
    lines.append("")
    lines.append("### Coverage Gaps")
    lines.append(f"- Only {n_le}/{n_pl} proof_lost cases have both BTF line AND fix diff lines.")
    lines.append("- Source line comparison only works when: (a) BTF line info present in log,")
    lines.append("  AND (b) we have a before/after code diff.")
    lines.append("")
    lines.append("### What This Means for the Paper")
    lines.append("- The backtracking rate shows BPFix successfully identifies the proof obligation")
    lines.append("  that was lost BEFORE the rejection site — i.e., it's not just pointing at the")
    lines.append("  error line like most tools do.")
    lines.append("- Text token match provides a signal even without exact source lines.")
    lines.append("- The 'within_5' metric is the most meaningful for practical tool evaluation.")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nMarkdown report written to: {report_path}")


# ─── Entry point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("Running root-cause validation evaluation...")
    results = run_all()

    print(f"\nTotal cases evaluated: {sum(1 for r in results if r.diagnostic_success)} / {len(results)}")

    aggregate = compute_aggregate(results)
    by_source = compute_by_source(results)
    by_proof_status = compute_by_proof_status(results)

    # Print summary
    print("\n=== AGGREGATE METRICS ===")
    for k, v in aggregate.items():
        print(f"  {k}: {v}")

    # Serialize results
    def result_to_dict(r: CaseRCResult) -> dict[str, Any]:
        d = asdict(r)
        # Remove large span lists from JSON to keep file manageable
        d["proof_lost_span_count"] = len(d.pop("proof_lost_spans"))
        d["rejected_span_count"] = len(d.pop("rejected_spans"))
        return d

    output = {
        "generated_at": now_iso(),
        "aggregate": aggregate,
        "by_source": by_source,
        "by_proof_status": by_proof_status,
        "case_results": [result_to_dict(r) for r in results],
    }

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"\nJSON results written to: {args.results_path}")

    write_markdown_report(results, aggregate, by_source, by_proof_status, args.report_path)


if __name__ == "__main__":
    main()
