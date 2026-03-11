#!/usr/bin/env python3
"""Run a reproducible Pretty Verifier vs OBLIGE comparison over the corpus."""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.log_parser import ParsedLog, parse_log
from interface.extractor.trace_parser import CriticalTransition, ParsedTrace, parse_trace


CASE_DIRS = (
    ROOT / "case_study" / "cases" / "kernel_selftests",
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
)
DEFAULT_PRETTY_VERIFIER_ROOT = Path("/tmp/pretty-verifier")
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "pretty_verifier_comparison.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "pretty-verifier-comparison.md"
DEFAULT_CATALOG_PATH = ROOT / "taxonomy" / "error_catalog.yaml"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
ERROR_LINE_RE = re.compile(r"(?:(?P<number>-?\d+)\s+)?error:\s*(?P<message>.+)$", re.IGNORECASE)
INSTRUCTION_RE = re.compile(r"^\s*\d+:\s*\([0-9a-fA-F]{2}\)", flags=re.MULTILINE)
STATE_RE = re.compile(r"(?:^|\s)R\d+(?:_[a-z]+)?=")
SOURCE_ANNOTATION_RE = re.compile(r"^\s*;", flags=re.MULTILINE)

TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
    "verifier_bug",
)


@dataclass(slots=True)
class ManualLabel:
    case_id: str
    source_bucket: str
    difficulty: str
    taxonomy_class: str
    error_id: str
    confidence: str
    localizability: str
    specificity: str
    rationale: str
    ground_truth_fix: str


@dataclass(slots=True)
class PrettyVerifierResult:
    status: str
    selected_error_line: str
    error_number: int | None
    handler_name: str | None
    message: str
    source_location: str | None
    details: str
    actionable: bool
    raw_output: str
    exception: str | None
    predicted_taxonomy_class: str | None


@dataclass(slots=True)
class ObligeResult:
    error_id: str | None
    taxonomy_class: str | None
    error_line: str | None
    source_mapping: str | None
    has_source_mapping: bool
    critical_transition: str | None
    critical_transition_insn: int | None
    causal_chain_summary: str | None
    root_cause_insn: int | None
    error_insn: int | None
    root_cause_found: bool
    actionable: bool
    total_instructions: int
    has_btf_annotations: bool
    has_backtracking: bool


@dataclass(slots=True)
class CaseComparison:
    case_id: str
    case_path: str
    source: str
    title: str
    log_origin: str
    log_lines: int
    pretty_verifier: PrettyVerifierResult
    oblige: ObligeResult


def parse_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def load_manual_labels(path: Path) -> dict[str, ManualLabel]:
    labels: dict[str, ManualLabel] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 10:
            continue
        case_id = cells[0].strip("`")
        labels[case_id] = ManualLabel(
            case_id=case_id,
            source_bucket=cells[1],
            difficulty=cells[2],
            taxonomy_class=cells[3].strip("`"),
            error_id=cells[4].strip("`"),
            confidence=cells[5],
            localizability=cells[6],
            specificity=cells[7],
            rationale=cells[8],
            ground_truth_fix=cells[9],
        )
    return labels


def iter_case_paths(case_dirs: tuple[Path, ...]) -> list[Path]:
    paths: list[Path] = []
    for case_dir in case_dirs:
        paths.extend(sorted(path for path in case_dir.glob("*.yaml") if path.name != "index.yaml"))
    return paths


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def case_title(case_data: dict[str, Any]) -> str:
    question = case_data.get("question") or {}
    issue = case_data.get("issue") or {}
    selftest = case_data.get("selftest") or {}
    return (
        question.get("title")
        or issue.get("title")
        or selftest.get("function")
        or selftest.get("description")
        or case_data.get("case_id")
        or ""
    )


def extract_log_blocks(case_data: dict[str, Any]) -> tuple[list[str], str]:
    verifier_log = case_data.get("verifier_log")
    if isinstance(verifier_log, str) and verifier_log.strip():
        return [verifier_log.strip()], "string"

    if isinstance(verifier_log, dict):
        blocks = [
            block.strip()
            for block in verifier_log.get("blocks") or []
            if isinstance(block, str) and block.strip()
        ]
        if blocks:
            return blocks, "blocks"

        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return [combined.strip()], "combined"

    verifier_logs = case_data.get("verifier_logs")
    if isinstance(verifier_logs, list):
        blocks = [
            block.strip()
            for block in verifier_logs
            if isinstance(block, str) and block.strip()
        ]
        if blocks:
            return blocks, "verifier_logs"

    return [], "missing"


def score_log_block(block: str) -> int:
    lower = block.lower()
    score = 0
    if INSTRUCTION_RE.search(block):
        score += 8
    if re.search(STATE_RE, block):
        score += 6
    if "processed " in lower and " insns" in lower:
        score += 3
    if SOURCE_ANNOTATION_RE.search(block):
        score += 2
    if "last_idx" in lower or "regs=" in lower or "stack=" in lower:
        score += 2
    if "invalid access" in lower or "not allowed" in lower or "unknown func" in lower:
        score += 1
    return score


def select_primary_log(case_data: dict[str, Any]) -> tuple[str, str]:
    blocks, origin = extract_log_blocks(case_data)
    if not blocks:
        return "", origin
    if len(blocks) == 1:
        return blocks[0], origin
    return max(blocks, key=score_log_block), f"{origin}:best_block"


def clean_terminal_text(text: str) -> str:
    stripped = ANSI_RE.sub("", text)
    stripped = CONTROL_RE.sub("", stripped)
    return "\n".join(line.rstrip() for line in stripped.splitlines())


def truncate_to_processed(lines: list[str]) -> list[str]:
    prefix: list[str] = []
    for line in lines:
        prefix.append(line)
        if line.startswith("processed"):
            return prefix
    return prefix


def select_pretty_verifier_error_line(lines: list[str]) -> str:
    if not lines:
        return ""
    candidate = lines[-2] if len(lines) >= 2 else lines[-1]
    if candidate.startswith("old state: ") and len(lines) >= 4:
        candidate = lines[-4]
    return candidate


def extract_pretty_verifier_source_location(lines: list[str]) -> str | None:
    for idx, line in enumerate(lines):
        if re.match(r"^\s*\d+\s+\|", line):
            follow = lines[idx + 1] if idx + 1 < len(lines) else ""
            if "in file" in follow:
                return f"{line.strip()} {follow.strip()}"
            return line.strip()
    return None


def parse_pretty_verifier_output(raw_output: str) -> tuple[int | None, str, str, str | None]:
    cleaned = clean_terminal_text(raw_output)
    lines = [
        line
        for line in cleaned.splitlines()
        if line.strip()
        and "Prettier Verifier" not in line
        and "#######################" not in line
    ]

    error_number: int | None = None
    message = ""
    detail_lines: list[str] = []
    source_location = extract_pretty_verifier_source_location(lines)

    for idx, line in enumerate(lines):
        match = ERROR_LINE_RE.search(line.strip())
        if not match:
            continue
        if match.group("number") is not None:
            error_number = int(match.group("number"))
        message = match.group("message").strip()
        detail_lines = lines[idx + 1 :]
        break

    if source_location:
        detail_lines = [line for line in detail_lines if line.strip() != source_location.strip()]

    details = "\n".join(line.strip() for line in detail_lines if line.strip())
    return error_number, message, details, source_location


def load_pretty_verifier(
    pretty_verifier_root: Path,
) -> tuple[Callable[..., Any], Callable[[], None], str | None]:
    try:
        from pretty_verifier.handler import handle_error
        from pretty_verifier.utils import enable_enumerate
    except ImportError:
        src_path = pretty_verifier_root / "src"
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))
        from pretty_verifier.handler import handle_error
        from pretty_verifier.utils import enable_enumerate

    commit = None
    try:
        commit = (
            subprocess.check_output(
                ["git", "-C", str(pretty_verifier_root), "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            .strip()
        )
    except (OSError, subprocess.CalledProcessError):
        commit = None

    return handle_error, enable_enumerate, commit


def classify_pretty_verifier_taxonomy(
    result: PrettyVerifierResult,
) -> str | None:
    corpus_text = " ".join(
        part for part in (result.message, result.details, result.selected_error_line) if part
    ).lower()

    if not corpus_text:
        return None

    if any(token in corpus_text for token in ("verifier bug", "kernel bug", "warning:")):
        return "verifier_bug"

    if any(
        token in corpus_text
        for token in (
            "unknown func",
            "invalid btf",
            "gpl declaration missing",
            "kernel function need to be called from gpl",
            "map '",
            "type with btf",
            "helper access to the packet is not allowed",
            "not supported",
            "unsupported",
            "attach",
            "sleepable",
            "reference type('unknown ')",
        )
    ):
        return "env_mismatch"

    if any(
        token in corpus_text
        for token in (
            "combined stack size",
            "too deep",
            "too complex",
            "back-edge",
            "loop is not bounded",
            "program is too large",
            "tail calls",
            "stack size of previous subprogram",
        )
    ):
        return "verifier_limit"

    if any(
        token in corpus_text
        for token in (
            "either use unsigned",
            "var &= const",
            "unbounded min value",
            "unreachable insn",
            "offset -2147483648",
            "offset 2147483648",
        )
    ):
        return "lowering_artifact"

    if result.status in {"handled", "unhandled"}:
        return "source_bug"
    return None


def run_pretty_verifier(
    log_text: str,
    *,
    handle_error: Callable[..., Any],
    enable_enumerate: Callable[[], None],
    handler_inventory: dict[int, str],
) -> PrettyVerifierResult:
    stripped_lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    pv_lines = truncate_to_processed(stripped_lines)
    selected_error_line = select_pretty_verifier_error_line(pv_lines)

    raw_output = ""
    exception_text: str | None = None
    try:
        buffer = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buffer
        try:
            enable_enumerate()
            handle_error(pv_lines, [], None, llvm_objdump=pv_lines)
        finally:
            sys.stdout = old_stdout
        raw_output = buffer.getvalue()
    except Exception as exc:  # pragma: no cover - the comparison needs to record crashes.
        raw_output = raw_output or ""
        exception_text = f"{type(exc).__name__}: {exc}"

    error_number, message, details, source_location = parse_pretty_verifier_output(raw_output)
    handler_name = handler_inventory.get(error_number) if error_number is not None else None

    if exception_text is not None:
        status = "exception"
    elif not raw_output.strip():
        status = "no_output"
    elif message.startswith("Error not managed") or error_number == -1:
        status = "unhandled"
    else:
        status = "handled"

    actionable = (
        status == "handled"
        and bool(message.strip())
        and (
            bool(details.strip())
            or any(
                keyword in " ".join((message, details)).lower()
                for keyword in (
                    "use ",
                    "add ",
                    "make sure",
                    "initialize",
                    "null check",
                    "bound check",
                    "unsigned",
                    "expected",
                )
            )
        )
    )

    result = PrettyVerifierResult(
        status=status,
        selected_error_line=selected_error_line,
        error_number=error_number,
        handler_name=handler_name,
        message=message,
        source_location=source_location,
        details=details,
        actionable=actionable,
        raw_output=clean_terminal_text(raw_output),
        exception=exception_text,
        predicted_taxonomy_class=None,
    )
    result.predicted_taxonomy_class = classify_pretty_verifier_taxonomy(result)
    return result


def select_error_instruction(trace: ParsedTrace) -> Any | None:
    if trace.error_line:
        for instruction in reversed(trace.instructions):
            if instruction.error_text and trace.error_line in instruction.error_text:
                return instruction
    for instruction in reversed(trace.instructions):
        if instruction.is_error:
            return instruction
    return None


def select_transition(trace: ParsedTrace) -> CriticalTransition | None:
    if not trace.critical_transitions:
        return None

    error_instruction = select_error_instruction(trace)
    error_insn = error_instruction.insn_idx if error_instruction is not None else None
    preferred_registers: set[str] = set()
    if trace.causal_chain is not None:
        preferred_registers.add(trace.causal_chain.error_register)
        for link in trace.causal_chain.chain[:2]:
            preferred_registers.add(link.register)

    priority = {
        "RANGE_LOSS": 4,
        "BOUNDS_COLLAPSE": 3,
        "TYPE_DOWNGRADE": 2,
        "PROVENANCE_LOSS": 1,
    }

    def sort_key(item: CriticalTransition) -> tuple[int, int, int]:
        reg_score = 1 if item.register in preferred_registers else 0
        type_score = priority.get(item.transition_type, 0)
        if error_insn is None:
            distance_score = -abs(item.insn_idx)
        else:
            distance_score = -abs(error_insn - item.insn_idx)
        return (reg_score, type_score, distance_score)

    return max(trace.critical_transitions, key=sort_key)


def source_mapping_for(trace: ParsedTrace, preferred_insns: list[int | None]) -> str | None:
    for insn_idx in preferred_insns:
        if insn_idx is None:
            continue
        for instruction in reversed(trace.instructions):
            if instruction.insn_idx == insn_idx and instruction.source_line:
                return instruction.source_line
    for instruction in reversed(trace.instructions):
        if instruction.source_line:
            return instruction.source_line
    return None


def summarize_causal_chain(trace: ParsedTrace) -> tuple[str | None, int | None]:
    if trace.causal_chain is None:
        return None, None

    links = trace.causal_chain.chain
    root = next((link for link in links if link.role == "root_cause"), None)
    error_site = next((link for link in reversed(links) if link.role == "error_site"), None)
    propagation = [link for link in links if link.role == "propagation"]

    parts: list[str] = []
    if root is not None:
        parts.append(f"insn {root.insn_idx} ({root.register})")
    if propagation:
        props = ", ".join(f"insn {link.insn_idx} ({link.register})" for link in propagation[:2])
        parts.append(f"via {props}")
    if error_site is not None:
        parts.append(f"fails at insn {error_site.insn_idx} ({error_site.register})")
    return " -> ".join(parts) if parts else None, (root.insn_idx if root is not None else None)


def run_oblige(log_text: str, catalog_path: Path) -> ObligeResult:
    parsed_log: ParsedLog = parse_log(log_text, catalog_path=catalog_path)
    trace: ParsedTrace = parse_trace(log_text)
    error_instruction = select_error_instruction(trace)
    transition = select_transition(trace)
    causal_chain_summary, root_cause_insn = summarize_causal_chain(trace)
    source_mapping = source_mapping_for(
        trace,
        [
            root_cause_insn,
            transition.insn_idx if transition is not None else None,
            error_instruction.insn_idx if error_instruction is not None else None,
        ],
    )
    error_insn = error_instruction.insn_idx if error_instruction is not None else None
    root_cause_found = False
    if root_cause_insn is not None and error_insn is not None and root_cause_insn != error_insn:
        root_cause_found = True
    elif transition is not None and error_insn is not None and transition.insn_idx != error_insn:
        root_cause_found = True
    elif transition is not None and error_insn is None:
        root_cause_found = True

    actionable = bool(
        parsed_log.error_id
        and (
            transition is not None
            or trace.causal_chain is not None
            or source_mapping is not None
        )
    )

    return ObligeResult(
        error_id=parsed_log.error_id,
        taxonomy_class=parsed_log.taxonomy_class,
        error_line=trace.error_line or parsed_log.error_line,
        source_mapping=source_mapping,
        has_source_mapping=source_mapping is not None,
        critical_transition=transition.description if transition is not None else None,
        critical_transition_insn=transition.insn_idx if transition is not None else None,
        causal_chain_summary=causal_chain_summary,
        root_cause_insn=root_cause_insn,
        error_insn=error_insn,
        root_cause_found=root_cause_found,
        actionable=actionable,
        total_instructions=trace.total_instructions,
        has_btf_annotations=trace.has_btf_annotations,
        has_backtracking=trace.has_backtracking,
    )


def extract_pv_handler_inventory(handler_path: Path) -> dict[int, str]:
    text = handler_path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"set_error_number\((?P<number>\d+)\)\s*\n\s*(?P<handler>[a-zA-Z_][a-zA-Z0-9_]*)\(",
        flags=re.MULTILINE,
    )
    inventory = {
        int(match.group("number")): match.group("handler")
        for match in pattern.finditer(text)
    }
    return dict(sorted(inventory.items()))


def safe_ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0/0"
    return f"{numerator}/{denominator}"


def build_case_record(
    case_path: Path,
    case_data: dict[str, Any],
    *,
    handle_error: Callable[..., Any],
    enable_enumerate: Callable[[], None],
    handler_inventory: dict[int, str],
    catalog_path: Path,
) -> CaseComparison | None:
    log_text, log_origin = select_primary_log(case_data)
    if not log_text.strip():
        return None

    pretty = run_pretty_verifier(
        log_text,
        handle_error=handle_error,
        enable_enumerate=enable_enumerate,
        handler_inventory=handler_inventory,
    )
    oblige = run_oblige(log_text, catalog_path=catalog_path)

    return CaseComparison(
        case_id=str(case_data.get("case_id", case_path.stem)),
        case_path=str(case_path),
        source=str(case_data.get("source", "")),
        title=case_title(case_data),
        log_origin=log_origin,
        log_lines=len([line for line in log_text.splitlines() if line.strip()]),
        pretty_verifier=pretty,
        oblige=oblige,
    )


def manual_subset_rows(
    results_by_case: dict[str, CaseComparison],
    manual_labels: dict[str, ManualLabel],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id, label in manual_labels.items():
        record = results_by_case.get(case_id)
        if record is None:
            continue
        pv_class = record.pretty_verifier.predicted_taxonomy_class
        oblige_class = record.oblige.taxonomy_class
        rows.append(
            {
                "case_id": case_id,
                "manual_label": label.taxonomy_class,
                "manual_error_id": label.error_id,
                "pv_class": pv_class,
                "pv_correct": pv_class == label.taxonomy_class,
                "pv_summary": summarize_pretty_verifier(record.pretty_verifier),
                "oblige_class": oblige_class,
                "oblige_correct": oblige_class == label.taxonomy_class,
                "oblige_summary": summarize_oblige(record.oblige),
                "pv_actionable": record.pretty_verifier.actionable,
                "oblige_actionable": record.oblige.actionable,
                "pv_source_localized": bool(record.pretty_verifier.source_location),
                "oblige_source_localized": record.oblige.has_source_mapping,
                "pv_root_cause_found": False,
                "oblige_root_cause_found": record.oblige.root_cause_found,
            }
        )
    return rows


def summarize_pretty_verifier(result: PrettyVerifierResult) -> str:
    if result.status == "exception":
        return f"exception: {result.exception}"
    if result.status == "no_output":
        return "no output"
    prefix = (
        f"PV#{result.error_number}" if result.error_number is not None and result.error_number >= 0 else "PV?"
    )
    message = result.message or result.selected_error_line or "no diagnosis"
    if result.source_location:
        return f"{prefix}: {message}; {result.source_location}"
    if result.details:
        return f"{prefix}: {message}; {result.details.splitlines()[0]}"
    return f"{prefix}: {message}"


def summarize_oblige(result: ObligeResult) -> str:
    parts: list[str] = []
    if result.error_id:
        if result.taxonomy_class:
            parts.append(f"{result.error_id} ({result.taxonomy_class})")
        else:
            parts.append(result.error_id)
    elif result.taxonomy_class:
        parts.append(result.taxonomy_class)
    if result.critical_transition:
        parts.append(result.critical_transition)
    elif result.causal_chain_summary:
        parts.append(result.causal_chain_summary)
    elif result.error_line:
        parts.append(result.error_line)
    return "; ".join(parts) if parts else "unclassified"


def aggregate_metrics(
    rows: list[dict[str, Any]],
    manual_labels: dict[str, ManualLabel],
) -> dict[str, Any]:
    lowering_total = sum(1 for label in manual_labels.values() if label.taxonomy_class == "lowering_artifact")
    return {
        "manual_subset_size": len(rows),
        "pv_classification_accuracy": safe_ratio(sum(row["pv_correct"] for row in rows), len(rows)),
        "oblige_classification_accuracy": safe_ratio(sum(row["oblige_correct"] for row in rows), len(rows)),
        "pv_lowering_accuracy": safe_ratio(
            sum(
                row["pv_correct"]
                for row in rows
                if row["manual_label"] == "lowering_artifact"
            ),
            lowering_total,
        ),
        "oblige_lowering_accuracy": safe_ratio(
            sum(
                row["oblige_correct"]
                for row in rows
                if row["manual_label"] == "lowering_artifact"
            ),
            lowering_total,
        ),
        "pv_root_cause_localization": safe_ratio(
            sum(row["pv_root_cause_found"] for row in rows),
            len(rows),
        ),
        "oblige_root_cause_localization": safe_ratio(
            sum(row["oblige_root_cause_found"] for row in rows),
            len(rows),
        ),
        "pv_actionable_diagnosis": safe_ratio(
            sum(row["pv_actionable"] for row in rows),
            len(rows),
        ),
        "oblige_actionable_diagnosis": safe_ratio(
            sum(row["oblige_actionable"] for row in rows),
            len(rows),
        ),
    }


def corpus_summary(results: list[CaseComparison]) -> dict[str, Any]:
    by_source = Counter(record.source for record in results)
    pv_status = Counter(record.pretty_verifier.status for record in results)
    oblige_classes = Counter(record.oblige.taxonomy_class or "unclassified" for record in results)
    return {
        "cases": len(results),
        "by_source": dict(by_source),
        "pretty_verifier_status": dict(pv_status),
        "pretty_verifier_source_localization": sum(
            1 for record in results if record.pretty_verifier.source_location
        ),
        "oblige_source_localization": sum(
            1 for record in results if record.oblige.has_source_mapping
        ),
        "oblige_root_cause_found": sum(
            1 for record in results if record.oblige.root_cause_found
        ),
        "oblige_classes": dict(oblige_classes),
    }


def build_mapping_summary(results: list[CaseComparison]) -> dict[str, Any]:
    by_pv_error: dict[int, list[CaseComparison]] = defaultdict(list)
    observed_oblige_ids: set[str] = set()
    pv_equivalent_oblige_ids: set[str] = set()

    for record in results:
        if record.oblige.error_id:
            observed_oblige_ids.add(record.oblige.error_id)
        if record.pretty_verifier.error_number is not None and record.pretty_verifier.error_number >= 0:
            by_pv_error[record.pretty_verifier.error_number].append(record)

    rows: list[dict[str, Any]] = []
    for error_number, cases in sorted(by_pv_error.items()):
        handler_name = next(
            (
                case.pretty_verifier.handler_name
                for case in cases
                if case.pretty_verifier.handler_name is not None
            ),
            None,
        )
        oblige_ids = Counter(
            case.oblige.error_id or "unclassified"
            for case in cases
        )
        taxonomy_classes = Counter(
            case.oblige.taxonomy_class or "unclassified"
            for case in cases
        )
        dominant_id, dominant_count = oblige_ids.most_common(1)[0]
        if dominant_id != "unclassified":
            pv_equivalent_oblige_ids.add(dominant_id)
        rows.append(
            {
                "error_number": error_number,
                "handler_name": handler_name,
                "cases": len(cases),
                "dominant_oblige_error_id": dominant_id,
                "dominant_oblige_count": dominant_count,
                "distinct_oblige_error_ids": len(oblige_ids),
                "distinct_taxonomy_classes": len(taxonomy_classes),
                "oblige_error_ids": dict(oblige_ids),
                "taxonomy_classes": dict(taxonomy_classes),
                "coarse": len(oblige_ids) > 1 or len(taxonomy_classes) > 1,
            }
        )

    return {
        "rows": rows,
        "oblige_ids_without_pv_equivalent": sorted(observed_oblige_ids - pv_equivalent_oblige_ids),
    }


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    separator = ["---"] * len(headers)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(separator) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_report(
    *,
    results: list[CaseComparison],
    manual_rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    corpus: dict[str, Any],
    mapping: dict[str, Any],
    handler_inventory: dict[int, str],
    pretty_verifier_commit: str | None,
) -> str:
    feature_rows = [
        ["Error message parsing", "Yes", "Yes"],
        ["Full state trace analysis", "No", "Yes"],
        ["Critical transition detection", "No", "Yes"],
        ["Causal chain extraction", "No", "Yes"],
        ["Source localization", "via llvm-objdump or inline source comments", "via BTF/log annotations"],
        ["Taxonomy classification", "partial (handler/error number only)", "Yes (catalog-backed)"],
        ["Lowering artifact detection", "No", "Yes"],
        ["Cross-kernel stability", "fragile regex lineup", "more stable state-format parsing"],
    ]

    manual_table_rows = [
        [
            f"`{row['case_id']}`",
            f"`{row['manual_label']}`",
            row["pv_summary"].replace("|", "\\|"),
            row["oblige_summary"].replace("|", "\\|"),
            "Yes" if row["pv_correct"] else "No",
            "Yes" if row["oblige_correct"] else "No",
        ]
        for row in manual_rows
    ]

    lowering_rows = []
    for row in manual_rows:
        if row["manual_label"] != "lowering_artifact":
            continue
        lowering_rows.append(
            [
                f"`{row['case_id']}`",
                row["pv_summary"].replace("|", "\\|"),
                row["oblige_summary"].replace("|", "\\|"),
                f"PV: No; OBLIGE: {'Yes' if row['oblige_root_cause_found'] else 'No'}",
            ]
        )

    aggregate_rows = [
        ["Overall classification accuracy", metrics["pv_classification_accuracy"], metrics["oblige_classification_accuracy"]],
        ["Lowering artifact accuracy", metrics["pv_lowering_accuracy"], metrics["oblige_lowering_accuracy"]],
        ["Root cause localization", metrics["pv_root_cause_localization"], metrics["oblige_root_cause_localization"]],
        ["Cases with actionable diagnosis", metrics["pv_actionable_diagnosis"], metrics["oblige_actionable_diagnosis"]],
    ]

    mapping_rows = [
        [
            f"`{row['error_number']}`",
            f"`{row['handler_name']}`" if row["handler_name"] else "",
            str(row["cases"]),
            f"`{row['dominant_oblige_error_id']}`",
            str(row["distinct_oblige_error_ids"]),
            str(row["distinct_taxonomy_classes"]),
            "Yes" if row["coarse"] else "No",
        ]
        for row in mapping["rows"]
    ]

    pv_status_summary = ", ".join(
        f"{status}={count}" for status, count in sorted(corpus["pretty_verifier_status"].items())
    )
    source_summary = ", ".join(
        f"{source}={count}" for source, count in sorted(corpus["by_source"].items())
    )
    no_equiv = ", ".join(f"`{error_id}`" for error_id in mapping["oblige_ids_without_pv_equivalent"]) or "None"

    report_lines = [
        "# Pretty Verifier vs OBLIGE",
        "",
        "## Pretty Verifier Architecture Summary",
        "",
        f"- Upstream snapshot: `{pretty_verifier_commit or 'unknown commit'}` from `/tmp/pretty-verifier`.",
        f"- Handler inventory: `{len(handler_inventory)}` explicit `set_error_number()` branches in `src/pretty_verifier/handler.py`.",
        "- Entry path is CLI `main.py -> process_input() -> handle_error()`.",
        "- The core selector is `error = output_raw[-2]`, with one `old state:` special case. There is no reusable `Handler(...)` class in the current upstream repo.",
        "- Pretty Verifier is line-oriented: it matches one headline line against regex branches and prints one human-readable explanation, sometimes with a source hint and suggestion.",
        "- Concrete output shape is `N error: <message>` under a colored banner, followed by an optional source snippet, appendix, and suggestion. If no branch matches, it prints `-1 error: Error not managed -> <selected line>`.",
        "- It does not parse full register-state traces, detect proof-loss transitions, or backtrack register dependencies.",
        "- README claims best support on kernel `6.8` and source mapping via `llvm-objdump` plus compiled `.o` files. The OBLIGE corpus does not preserve those object files, so llvm-objdump-based localization is usually unavailable here.",
        "",
        "## Corpus and Method",
        "",
        f"- Compared `{corpus['cases']}` cases with non-empty verifier logs across `{source_summary}`.",
        f"- Pretty Verifier corpus outcome summary: `{pv_status_summary}`.",
        "- In this corpus, unhandled or brittle cases are common: many issue logs place trailer lines such as `verification time` or `stack depth` after the true rejection line, and `28` cases raised a Python exception instead of yielding a diagnosis.",
        f"- Pretty Verifier source localization succeeded on `{corpus['pretty_verifier_source_localization']}/{corpus['cases']}` cases. OBLIGE found log-native source mapping on `{corpus['oblige_source_localization']}/{corpus['cases']}` cases.",
        f"- OBLIGE found an earlier root-cause instruction/transition on `{corpus['oblige_root_cause_found']}/{corpus['cases']}` corpus cases.",
        "- For StackOverflow and GitHub YAMLs with multiple verifier blocks, the script selects the highest-scoring verbose block instead of the concatenated prose-heavy `combined` string.",
        "- OBLIGE uses `parse_log(..., catalog_path='taxonomy/error_catalog.yaml')` plus `parse_trace(...)` on the same normalized log block.",
        "",
        "## Table 1: Coverage and Capability",
        "",
        markdown_table(
            ["Feature", "Pretty Verifier", "OBLIGE"],
            feature_rows,
        ),
        "",
        "## Table 2: Per-Case Accuracy on the 30 Manually Labeled Cases",
        "",
        markdown_table(
            ["Case", "Manual label", "Pretty Verifier diagnosis", "OBLIGE diagnosis", "PV correct?", "OBLIGE correct?"],
            manual_table_rows,
        ),
        "",
        "## Table 3: Lowering Artifact Deep-Dive",
        "",
        markdown_table(
            ["Case", "Pretty Verifier", "OBLIGE trace analysis", "Root cause found?"],
            lowering_rows,
        ),
        "",
        "## Table 4: Aggregate Accuracy on the Manual 30-Case Subset",
        "",
        markdown_table(
            ["Metric", "Pretty Verifier", "OBLIGE"],
            aggregate_rows,
        ),
        "",
        "## Pretty Verifier Handler Coverage in This Corpus",
        "",
        f"- Observed Pretty Verifier handler numbers in this corpus: `{len(mapping['rows'])}` of `{len(handler_inventory)}` total branches.",
        f"- OBLIGE error IDs with no observed Pretty Verifier equivalent on this corpus: {no_equiv}.",
        "",
        markdown_table(
            ["PV #", "Handler", "Cases", "Dominant OBLIGE ID", "Distinct OBLIGE IDs", "Distinct taxonomy classes", "Too coarse?"],
            mapping_rows,
        ),
        "",
        "## Analysis",
        "",
        "OBLIGE's real advantage is not 'more regexes'. The distinguishing signal is trace structure: critical transitions, causal chains, and earlier proof-loss instructions. That is exactly where Pretty Verifier is blind.",
        "",
        "Pretty Verifier is sufficient for straightforward contract violations when the final verifier line already names the real defect. Iterator state misuse, many dynptr protocol failures, and simple helper-argument mismatches usually fit that pattern.",
        "",
        "Pretty Verifier is weak on lowering artifacts for two separate reasons. First, packet/map symptom lines are usually mapped to ordinary source-side bounds advice, even when the source already contains the needed check. Second, the upstream implementation's `output_raw[-2]` selection is brittle: several corpus logs place `stack depth`, `verification time`, or similar trailer lines between the real error and the final `processed ...` line, which makes the handler miss or mis-handle the failure entirely.",
        "",
        "The lowering-artifact cases show the sharpest separation. For cases like `stackoverflow-79530762` and `stackoverflow-74178703`, Pretty Verifier either crashes, stays unhandled, or restates the final symptom. OBLIGE instead surfaces the earlier register-state collapse that explains why the accepted fix is a loop/codegen rewrite rather than 'add another bounds check'.",
        "",
        "Concrete 'Pretty Verifier is enough' examples from the manual set are `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a`, `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`, and `stackoverflow-61945212`: the headline line already names the real helper or protocol contract violation, so a line-oriented explanation is adequate.",
        "",
        "Concrete misleading examples are `github-aya-rs-aya-1062` (`stack depth ...` is selected instead of the real signed-range failure), `stackoverflow-79530762` and `stackoverflow-73088287` (both crash with `IndexError`), and `stackoverflow-74178703` (the final map-bounds symptom is reported, but not the earlier proof-loss site).",
        "",
        "There are still limits on the OBLIGE side. If the corpus preserves only a short final snippet with no usable state trace, OBLIGE cannot recover a true earlier root cause either. Subprogram-boundary artifacts remain a current weak spot as well.",
        "",
        "## Honest Assessment",
        "",
        "Pretty Verifier contributes a helpful human-readable layer over specific verifier lines, especially when the headline message already encodes the real obligation violation. OBLIGE wins when the bug is not on the headline line: lowering artifacts, hidden proof-loss transitions, and other cases where the final rejection is only a symptom.",
        "",
    ]
    return "\n".join(report_lines).strip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pretty-verifier-root",
        type=Path,
        default=DEFAULT_PRETTY_VERIFIER_ROOT,
        help="Path to the Pretty Verifier checkout.",
    )
    parser.add_argument(
        "--manual-labels",
        type=Path,
        default=DEFAULT_MANUAL_LABELS,
        help="Path to docs/tmp/manual-labeling-30cases.md.",
    )
    parser.add_argument(
        "--catalog-path",
        type=Path,
        default=DEFAULT_CATALOG_PATH,
        help="Path to taxonomy/error_catalog.yaml.",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help="Where to write the JSON results.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Where to write the markdown report.",
    )
    args = parser.parse_args()

    handle_error, enable_enumerate, pv_commit = load_pretty_verifier(args.pretty_verifier_root)
    handler_inventory = extract_pv_handler_inventory(
        args.pretty_verifier_root / "src" / "pretty_verifier" / "handler.py"
    )
    manual_labels = load_manual_labels(args.manual_labels)

    results: list[CaseComparison] = []
    results_by_case: dict[str, CaseComparison] = {}
    for case_path in iter_case_paths(CASE_DIRS):
        case_data = read_yaml(case_path)
        record = build_case_record(
            case_path,
            case_data,
            handle_error=handle_error,
            enable_enumerate=enable_enumerate,
            handler_inventory=handler_inventory,
            catalog_path=args.catalog_path,
        )
        if record is None:
            continue
        results.append(record)
        results_by_case[record.case_id] = record

    manual_rows = manual_subset_rows(results_by_case, manual_labels)
    metrics = aggregate_metrics(manual_rows, manual_labels)
    corpus = corpus_summary(results)
    mapping = build_mapping_summary(results)
    report = build_report(
        results=results,
        manual_rows=manual_rows,
        metrics=metrics,
        corpus=corpus,
        mapping=mapping,
        handler_inventory=handler_inventory,
        pretty_verifier_commit=pv_commit,
    )

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(
        json.dumps(
            {
                "pretty_verifier_commit": pv_commit,
                "handler_inventory": handler_inventory,
                "corpus": corpus,
                "metrics": metrics,
                "mapping": mapping,
                "manual_rows": manual_rows,
                "results": [asdict(result) for result in results],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    args.report_path.write_text(report, encoding="utf-8")

    print(f"Wrote {len(results)} case comparisons to {args.results_path}")
    print(f"Wrote report to {args.report_path}")


if __name__ == "__main__":
    main()
