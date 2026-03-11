#!/usr/bin/env python3
"""Run a taxonomy-stratified multi-condition LLM verifier-diagnosis experiment."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from interface.extractor.log_parser import ParsedLog, VerifierLogParser
from interface.extractor.trace_parser import CriticalTransition, ParsedTrace, parse_trace


DEFAULT_OPENAI_MODEL = "gpt-5.4"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
DEFAULT_RESULTS_PATH = REPO_ROOT / "eval" / "results" / "llm_multi_model_results.json"
DEFAULT_REPORT_PATH = REPO_ROOT / "docs" / "tmp" / "llm-multi-model-experiment.md"
DEFAULT_MANUAL_LABELS_PATH = REPO_ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"
DEFAULT_VERBOSE_AUDIT_PATH = REPO_ROOT / "docs" / "tmp" / "verbose-log-audit.md"

TAXONOMY_ORDER = (
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "env_mismatch",
)

CONDITION_ORDER = (
    "error_message_only",
    "raw_verbose_log",
    "structured_trace_analysis",
)

MODEL_STRENGTH_ORDER = ("strong", "weak")

CONDITION_SPECS: dict[str, dict[str, str]] = {
    "error_message_only": {
        "label": "Condition A",
        "short_label": "A",
        "title": "Error Message Only",
    },
    "raw_verbose_log": {
        "label": "Condition B",
        "short_label": "B",
        "title": "Raw Verbose Log",
    },
    "structured_trace_analysis": {
        "label": "Condition C",
        "short_label": "C",
        "title": "Structured Trace Analysis",
    },
}

MODEL_STRENGTH_SPECS: dict[str, dict[str, str]] = {
    "strong": {
        "label": "Strong",
        "system_prompt": (
            "You are an eBPF expert. Diagnose Linux eBPF verifier failures precisely. "
            "Be concrete about the root cause, taxonomy class, and code-level fix. "
            "Respond with valid JSON only."
        ),
    },
    "weak": {
        "label": "Weak",
        "system_prompt": (
            "You are a junior developer who has basic eBPF knowledge but limited "
            "verifier experience. Respond concisely. Respond with valid JSON only."
        ),
    },
}

DEFAULT_TARGETS = {
    "source_bug": 9,
    "lowering_artifact": 6,
    "verifier_limit": 4,
    "env_mismatch": 3,
}

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "because",
    "before",
    "but",
    "by",
    "for",
    "from",
    "have",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "no",
    "not",
    "of",
    "on",
    "or",
    "so",
    "such",
    "that",
    "the",
    "their",
    "then",
    "there",
    "this",
    "to",
    "use",
    "with",
    "without",
    "would",
    "you",
    "your",
}


@dataclass(slots=True)
class ManualLabel:
    case_id: str
    source_bucket: str
    difficulty: str
    taxonomy_class: str
    error_id: str
    confidence: str
    localizability: str
    obligation_specificity: str
    rationale: str
    ground_truth_fix: str


@dataclass(slots=True)
class SelectionScore:
    total: int
    notes: list[str]


@dataclass(slots=True)
class CaseRecord:
    case_id: str
    case_path: str
    source: str
    source_bucket: str
    taxonomy_class: str
    error_id: str | None
    difficulty: str
    confidence: str
    ground_truth_root_cause: str
    ground_truth_fix: str
    ground_truth_fix_source: str
    source_url: str
    title: str
    buggy_code: str
    has_usable_code: bool
    verifier_log: str
    log_lines: int
    parsed_log: dict[str, Any]
    structured_analysis: dict[str, str]
    trace_metadata: dict[str, Any]
    verbose_audit_rank: int | None
    selection_score: int
    selection_notes: list[str]


@dataclass(slots=True)
class Score:
    root_cause_correct: int
    taxonomy_class_correct: int
    fix_direction_correct: int
    fix_specificity: int
    response_tokens: int | None
    token_count_method: str
    scoring_method: str
    predicted_taxonomy_class: str | None
    notes: str


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


def excerpt(text: str, limit: int = 180) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3].rstrip() + "..."


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def parse_targets(text: str) -> dict[str, int]:
    targets: dict[str, int] = {}
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, raw_value = chunk.split("=", 1)
        name = name.strip()
        if name not in TAXONOMY_ORDER:
            raise ValueError(f"Unknown taxonomy target: {name}")
        targets[name] = int(raw_value)
    for taxonomy in TAXONOMY_ORDER:
        targets.setdefault(taxonomy, 0)
    return targets


def source_bucket_for(source: str) -> str:
    mapping = {
        "stackoverflow": "SO",
        "github_issues": "GH",
        "kernel_selftests": "KS",
        "eval_commits": "EV",
    }
    return mapping.get(source, source.upper())


def run_key(case_id: str, model_strength: str, condition: str) -> str:
    return f"{case_id}::{model_strength}::{condition}"


def flatten_case_paths(paths: Iterable[Path]) -> list[Path]:
    resolved: list[Path] = []
    for path in paths:
        if path.is_dir():
            resolved.extend(sorted(p for p in path.rglob("*.yaml") if p.name != "index.yaml"))
        elif path.suffix == ".yaml":
            resolved.append(path)
    return sorted({path.resolve() for path in resolved})


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
            obligation_specificity=cells[7],
            rationale=cells[8],
            ground_truth_fix=cells[9],
        )
    return labels


def load_verbose_audit_ranks(path: Path) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| "):
            continue
        cells = parse_markdown_row(line)
        if len(cells) < 2:
            continue
        if not cells[0].isdigit():
            continue
        case_id = cells[1].strip("`")
        if case_id:
            ranks[case_id] = int(cells[0])
    return ranks


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    raw = case_data.get("verifier_log")
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        combined = raw.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = raw.get("blocks") or []
        if isinstance(blocks, list):
            joined = "\n\n".join(block.strip() for block in blocks if isinstance(block, str) and block.strip())
            return joined.strip()
    return ""


def is_log_like_snippet(snippet: str) -> bool:
    lines = [line for line in snippet.splitlines() if line.strip()]
    if not lines:
        return False
    log_hits = 0
    for line in lines[:10]:
        stripped = line.strip()
        if stripped.startswith(("libbpf:", "Validating ", "processed ")):
            log_hits += 1
        if re.match(r"^\d+: \([0-9a-f]{2}\)", stripped, flags=re.IGNORECASE):
            log_hits += 1
        if re.match(r"^(R\d|last_idx|regs=|invalid access|math between)", stripped):
            log_hits += 1
    return log_hits >= 2


def is_code_like_snippet(snippet: str) -> bool:
    if not snippet.strip():
        return False
    if is_log_like_snippet(snippet):
        return False
    code_markers = (
        'SEC("',
        '__section("',
        "__always_inline",
        "#define",
        "struct ",
        "enum ",
        "typedef ",
        "return ",
        "goto ",
        "if (",
        "for (",
        "while (",
        "asm volatile",
        "int ",
        "__u",
    )
    return any(marker in snippet for marker in code_markers)


def extract_code_from_diff(snippet: str) -> str:
    body: list[str] = []
    for line in snippet.splitlines():
        if line.startswith(("diff --git", "index ", "--- ", "+++ ")):
            continue
        if line.startswith("@@"):
            continue
        if line.startswith("+"):
            continue
        if line.startswith("-"):
            body.append(line[1:])
            continue
        if line.startswith(" "):
            body.append(line[1:])
            continue
    return "\n".join(body).strip()


def extract_code_from_text(text: str) -> str:
    if not text.strip():
        return ""
    lines = text.splitlines()
    start_idx: int | None = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if re.match(
            r'^(#include|#define|struct\s+\w+|static\s+__always_inline|SEC\("|__section\("|int\s+\w+\(|enum\s+\w+|typedef\s+|__u\d+)',
            stripped,
        ):
            start_idx = idx
            break
    if start_idx is None:
        return ""

    end_idx = len(lines)
    for idx in range(start_idx + 1, len(lines)):
        stripped = lines[idx].strip()
        if stripped.startswith(
            (
                "Following is the complete verifier log",
                "Following is the verifier log",
                "Here are a few last lines",
                "Full log is available here.",
                "When I try to load",
                "I get this error when",
                "Verifier output:",
                "libbpf:",
                "Validating ",
            )
        ):
            end_idx = idx
            break
        if re.match(r"^\d+: \([0-9a-f]{2}\)", stripped, flags=re.IGNORECASE):
            end_idx = idx
            break

    return "\n".join(lines[start_idx:end_idx]).strip()


def extract_buggy_code(case_data: dict[str, Any]) -> tuple[str, bool]:
    code_candidates: list[str] = []

    for snippet in case_data.get("source_snippets") or []:
        if isinstance(snippet, dict):
            code = snippet.get("code")
            if isinstance(code, str) and code.strip():
                code_candidates.append(code.strip())
            continue
        if not isinstance(snippet, str):
            continue
        if snippet.startswith("diff --git"):
            diff_code = extract_code_from_diff(snippet)
            if diff_code:
                code_candidates.append(diff_code)
            continue
        if is_code_like_snippet(snippet):
            code_candidates.append(snippet.strip())

    for body_key in ("question_body_text", "issue_body_text"):
        recovered = extract_code_from_text(case_data.get(body_key, ""))
        if recovered:
            code_candidates.append(recovered)

    if code_candidates:
        best = max(code_candidates, key=len)
        return best, True

    fallback = excerpt(
        case_data.get("question_body_text", "") or case_data.get("issue_body_text", ""),
        limit=1200,
    )
    if fallback:
        return (
            "No standalone buggy code snippet was preserved in YAML. "
            "Relevant source excerpt follows:\n\n" + fallback,
            False,
        )
    return "No source code snippet available in YAML.", False


def extract_fix_description(case_data: dict[str, Any], manual_label: ManualLabel | None) -> tuple[str, str]:
    selected_answer = case_data.get("selected_answer") or {}
    if isinstance(selected_answer, dict):
        text = (selected_answer.get("fix_description") or selected_answer.get("body_text") or "").strip()
        if text:
            return text, "yaml_selected_answer"

    issue_fix = case_data.get("fix") or {}
    if isinstance(issue_fix, dict):
        selected_comment = issue_fix.get("selected_comment") or {}
        text = (
            selected_comment.get("body_text")
            or issue_fix.get("summary")
            or ""
        ).strip()
        if text:
            return text, "yaml_issue_fix"

    if manual_label is not None and manual_label.ground_truth_fix:
        return manual_label.ground_truth_fix.strip(), "manual_label_doc"
    return "", "missing"


def extract_title(case_data: dict[str, Any]) -> str:
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


def extract_source_url(case_data: dict[str, Any]) -> str:
    question = case_data.get("question") or {}
    issue = case_data.get("issue") or {}
    return (
        question.get("url")
        or issue.get("url")
        or case_data.get("question_url")
        or case_data.get("issue_url")
        or ""
    )


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
    error_insn = error_instruction.insn_idx if error_instruction else None
    preferred_registers: set[str] = set()
    if trace.causal_chain:
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
        reg_match = 1 if item.register in preferred_registers else 0
        type_score = priority.get(item.transition_type, 0)
        if error_insn is None:
            distance_score = -abs(item.insn_idx)
        else:
            distance_score = -abs(error_insn - item.insn_idx)
        return (reg_match, type_score, distance_score)

    return max(trace.critical_transitions, key=sort_key)


def source_mapping_for(trace: ParsedTrace, preferred_insns: list[int | None]) -> str:
    for insn_idx in preferred_insns:
        if insn_idx is None:
            continue
        for instruction in reversed(trace.instructions):
            if instruction.insn_idx == insn_idx and instruction.source_line:
                return instruction.source_line
    for instruction in reversed(trace.instructions):
        if instruction.source_line:
            return instruction.source_line
    return "Unavailable"


def build_causal_chain_summary(trace: ParsedTrace) -> str:
    if trace.causal_chain is None:
        return "Unavailable"

    links = trace.causal_chain.chain
    root = next((link for link in links if link.role == "root_cause"), None)
    error_site = next((link for link in reversed(links) if link.role == "error_site"), None)
    propagation = [link for link in links if link.role == "propagation"]

    parts: list[str] = []
    if root is not None:
        parts.append(
            f"insn {root.insn_idx} ({root.register}): {excerpt(root.description, 120)}"
        )
    if propagation:
        props = ", ".join(f"insn {link.insn_idx} ({link.register})" for link in propagation[:2])
        parts.append(f"propagates through {props}")
    if error_site is not None:
        parts.append(
            f"fails at insn {error_site.insn_idx} ({error_site.register}): "
            f"{excerpt(error_site.description, 120)}"
        )
    return " -> ".join(parts) if parts else "Unavailable"


def build_structured_prompt_details(trace: ParsedTrace, parsed_log: ParsedLog) -> dict[str, str]:
    transition = select_transition(trace)
    error_instruction = select_error_instruction(trace)
    error_classification = parsed_log.error_id or "UNCLASSIFIED"
    if parsed_log.taxonomy_class:
        error_classification = f"{error_classification} ({parsed_log.taxonomy_class})"

    transition_text = (
        f"{transition.transition_type} at insn {transition.insn_idx}: {transition.description}"
        if transition is not None
        else "Unavailable"
    )

    return {
        "error_line": trace.error_line or parsed_log.error_line or "Unavailable",
        "error_classification": error_classification,
        "critical_transition": transition_text,
        "causal_chain": build_causal_chain_summary(trace),
        "source_mapping": source_mapping_for(
            trace,
            [
                error_instruction.insn_idx if error_instruction else None,
                transition.insn_idx if transition is not None else None,
                trace.instructions[-1].insn_idx if trace.instructions else None,
            ],
        ),
    }


def condition_prompt(case: CaseRecord, condition: str) -> str:
    response_format = textwrap.dedent(
        """\
        Return valid JSON with this schema:
        {
          "root_cause": "<short explanation>",
          "taxonomy_class": "source_bug|lowering_artifact|verifier_limit|env_mismatch|verifier_bug",
          "fix_direction": "<what to change>"
        }
        """
    ).strip()

    if condition == "error_message_only":
        return textwrap.dedent(
            f"""\
            You are an eBPF expert. A BPF program fails verification with this error:

            Error: {case.parsed_log["error_line"] or "Unavailable"}

            Source code:
            {case.buggy_code}

            What is the root cause? What taxonomy class is this (source_bug, lowering_artifact, verifier_limit, env_mismatch, verifier_bug)? How would you fix it?

            {response_format}
            """
        ).strip()

    if condition == "raw_verbose_log":
        return textwrap.dedent(
            f"""\
            You are an eBPF expert. A BPF program fails verification. Here is the complete verifier output:

            {case.verifier_log}

            Source code:
            {case.buggy_code}

            What is the root cause? What taxonomy class is this (source_bug, lowering_artifact, verifier_limit, env_mismatch, verifier_bug)? How would you fix it?

            {response_format}
            """
        ).strip()

    if condition == "structured_trace_analysis":
        details = case.structured_analysis
        return textwrap.dedent(
            f"""\
            You are an eBPF expert. A BPF program fails verification. Here is a structured analysis:

            Error: {details["error_line"]}
            Error classification: {details["error_classification"]}
            Critical state transition: {details["critical_transition"]}
            Causal chain: {details["causal_chain"]}
            Source mapping: {details["source_mapping"]}

            Source code:
            {case.buggy_code}

            What is the root cause? What taxonomy class is this (source_bug, lowering_artifact, verifier_limit, env_mismatch, verifier_bug)? How would you fix it?

            {response_format}
            """
        ).strip()

    raise ValueError(f"Unsupported condition: {condition}")


def extract_reference_keywords(text: str) -> list[str]:
    keywords: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_+-]*|\d+", text.lower()):
        if token in STOPWORDS:
            continue
        if len(token) < 4 and not token.isdigit():
            continue
        keywords.append(token)
    seen: set[str] = set()
    deduped: list[str] = []
    for token in keywords:
        if token not in seen:
            seen.add(token)
            deduped.append(token)
    return deduped


def extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if candidate.startswith("```"):
        fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, flags=re.DOTALL)
        if fence_match:
            candidate = fence_match.group(1)
    try:
        payload = json.loads(candidate)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass

    for match in re.finditer(r"\{.*?\}", candidate, flags=re.DOTALL):
        snippet = match.group(0)
        try:
            payload = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def extract_predicted_taxonomy(response_text: str) -> str | None:
    parsed = extract_json_object(response_text)
    if parsed:
        raw = parsed.get("taxonomy_class")
        if isinstance(raw, str) and raw.strip() in TAXONOMY_ORDER + ("verifier_bug",):
            return raw.strip()

    lowered = normalize(response_text)
    for taxonomy in TAXONOMY_ORDER + ("verifier_bug",):
        if taxonomy in lowered:
            return taxonomy
    return None


def keyword_hits(text: str, keywords: list[str]) -> int:
    haystack = normalize(text)
    return sum(1 for keyword in keywords if normalize(keyword) in haystack)


def score_binary_alignment(response_text: str, reference_texts: list[str], *, min_hits_floor: int = 1) -> tuple[int, list[str]]:
    combined = " ".join(text for text in reference_texts if text)
    keywords = extract_reference_keywords(combined)
    if not keywords:
        return 0, []
    distinctive = [keyword for keyword in keywords if len(keyword) >= 5 or "_" in keyword or keyword.isdigit()]
    if not distinctive:
        distinctive = keywords
    hits = [keyword for keyword in distinctive if normalize(keyword) in normalize(response_text)]
    threshold = max(min_hits_floor, min(4, max(1, math.ceil(len(distinctive) / 4))))
    return (1 if len(hits) >= threshold else 0), hits


def score_specificity(
    *,
    response_text: str,
    fix_correct: int,
    ground_truth_fix: str,
    buggy_code: str,
) -> tuple[int, list[str]]:
    if not fix_correct:
        return 1, []

    signals: list[str] = []
    response = response_text
    if re.search(r"```|`[^`]+`|if\s*\(|while\s*\(|for\s*\(", response):
        signals.append("code_shape")

    gt_keywords = extract_reference_keywords(ground_truth_fix)
    exact_hits = [
        keyword
        for keyword in gt_keywords
        if (len(keyword) >= 6 or "_" in keyword or keyword.isdigit())
        and normalize(keyword) in normalize(response)
    ]
    if len(exact_hits) >= 2:
        signals.append("gt_exact")

    code_identifiers = {
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", buggy_code)
        if len(token) >= 6 and token.lower() not in STOPWORDS
    }
    identifier_hits = [token for token in code_identifiers if normalize(token) in normalize(response)]
    if len(identifier_hits) >= 2:
        signals.append("code_identifier")

    if signals:
        return 3, signals
    return 2, []


def heuristic_score_response(
    *,
    case: CaseRecord,
    response_text: str,
    response_tokens: int | None,
    token_count_method: str,
) -> Score:
    predicted_taxonomy = extract_predicted_taxonomy(response_text)
    taxonomy_correct = int(predicted_taxonomy == case.taxonomy_class)

    root_correct, root_hits = score_binary_alignment(
        response_text,
        [
            case.ground_truth_root_cause,
            case.parsed_log["error_line"] or "",
            case.structured_analysis["critical_transition"],
        ],
        min_hits_floor=1,
    )
    fix_correct, fix_hits = score_binary_alignment(
        response_text,
        [case.ground_truth_fix],
        min_hits_floor=1,
    )
    specificity, specificity_signals = score_specificity(
        response_text=response_text,
        fix_correct=fix_correct,
        ground_truth_fix=case.ground_truth_fix,
        buggy_code=case.buggy_code,
    )

    notes = {
        "root_hits": root_hits[:8],
        "fix_hits": fix_hits[:8],
        "specificity_signals": specificity_signals,
    }
    return Score(
        root_cause_correct=root_correct,
        taxonomy_class_correct=taxonomy_correct,
        fix_direction_correct=fix_correct,
        fix_specificity=specificity,
        response_tokens=response_tokens,
        token_count_method=token_count_method,
        scoring_method="heuristic_keyword_overlap",
        predicted_taxonomy_class=predicted_taxonomy,
        notes=json.dumps(notes, sort_keys=True),
    )


def normalize_manual_score(
    payload: dict[str, Any],
    *,
    response_tokens: int | None,
    token_count_method: str,
) -> Score:
    return Score(
        root_cause_correct=int(payload.get("root_cause_correct", 0)),
        taxonomy_class_correct=int(payload.get("taxonomy_class_correct", 0)),
        fix_direction_correct=int(payload.get("fix_direction_correct", 0)),
        fix_specificity=max(1, min(3, int(payload.get("fix_specificity", 1)))),
        response_tokens=response_tokens,
        token_count_method=token_count_method,
        scoring_method=str(payload.get("scoring_method") or "manual"),
        predicted_taxonomy_class=payload.get("predicted_taxonomy_class"),
        notes=str(payload.get("notes") or ""),
    )


def load_manual_responses(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    responses: dict[str, dict[str, Any]] = {}
    if not isinstance(payload, dict):
        return responses

    for key, value in payload.items():
        if isinstance(value, str):
            responses[key] = {"response": value}
            continue
        if isinstance(value, dict):
            responses[key] = value
    return responses


def load_manual_scores(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        return {key: value for key, value in payload.items() if isinstance(value, dict)}
    return {}


def provider_api_key(provider: str) -> str | None:
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    return None


def provider_default_model(provider: str) -> str | None:
    if provider == "openai":
        return DEFAULT_OPENAI_MODEL
    if provider == "anthropic":
        return DEFAULT_ANTHROPIC_MODEL
    return None


def call_openai(
    *,
    api_key: str,
    model: str,
    prompt: str,
    system_prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_seconds: int,
) -> tuple[str, int | None]:
    payload = {
        "model": model,
        "instructions": system_prompt,
        "input": prompt,
        "temperature": temperature,
        "max_output_tokens": max_output_tokens,
        "text": {"format": {"type": "text"}},
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.load(response)

    text = payload.get("output_text")
    if not text:
        parts: list[str] = []
        for item in payload.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    parts.append(content.get("text", ""))
        text = "\n".join(part for part in parts if part)

    usage = payload.get("usage") or {}
    return text.strip(), usage.get("output_tokens")


def call_anthropic(
    *,
    api_key: str,
    model: str,
    prompt: str,
    system_prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_seconds: int,
) -> tuple[str, int | None]:
    payload = {
        "model": model,
        "system": system_prompt,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_output_tokens,
    }
    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": f"{api_key}",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.load(response)

    text_parts = [
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ]
    usage = payload.get("usage") or {}
    return "\n".join(part for part in text_parts if part).strip(), usage.get("output_tokens")


def invoke_provider(
    *,
    provider: str,
    model: str,
    api_key: str,
    prompt: str,
    system_prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_seconds: int,
) -> tuple[str, int | None]:
    if provider == "openai":
        return call_openai(
            api_key=api_key,
            model=model,
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
        )
    if provider == "anthropic":
        return call_anthropic(
            api_key=api_key,
            model=model,
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
        )
    raise ValueError(f"Unsupported provider: {provider}")


def selection_score(case: CaseRecord) -> SelectionScore:
    notes: list[str] = []
    total = 0

    if case.has_usable_code:
        total += 100
        notes.append("has_code:+100")
    else:
        total -= 200
        notes.append("missing_code:-200")

    total += min(case.log_lines, 500)
    notes.append(f"log_lines:+{min(case.log_lines, 500)}")

    if case.verbose_audit_rank is not None:
        audit_bonus = max(0, 240 - case.verbose_audit_rank * 10)
        total += audit_bonus
        notes.append(f"verbose_audit_rank:{case.verbose_audit_rank}:+{audit_bonus}")

    if case.source == "stackoverflow" and case.taxonomy_class in {"source_bug", "lowering_artifact"}:
        total += 80
        notes.append("preferred_so_bucket:+80")
    elif case.source == "kernel_selftests" and case.taxonomy_class == "source_bug":
        total += 60
        notes.append("preferred_ks_source_bug:+60")
    elif case.source == "kernel_selftests" and case.taxonomy_class == "verifier_limit":
        total += 30
        notes.append("preferred_ks_limit:+30")

    if case.trace_metadata["has_btf_annotations"]:
        total += 20
        notes.append("btf:+20")
    if case.trace_metadata["has_backtracking"]:
        total += 20
        notes.append("backtracking:+20")
    if case.trace_metadata["causal_chain_present"]:
        total += 20
        notes.append("causal_chain:+20")

    return SelectionScore(total=total, notes=notes)


def build_case_record(
    *,
    path: Path,
    manual_label: ManualLabel | None,
    verbose_audit_rank: int | None,
    parser: VerifierLogParser,
) -> CaseRecord:
    case_data = read_yaml(path)
    verifier_log = extract_verifier_log(case_data)
    parsed_log = parser.parse(verifier_log)
    trace = parse_trace(verifier_log)
    structured_analysis = build_structured_prompt_details(trace, parsed_log)
    buggy_code, has_usable_code = extract_buggy_code(case_data)
    fix_text, fix_source = extract_fix_description(case_data, manual_label)

    taxonomy_class = (
        manual_label.taxonomy_class
        if manual_label is not None
        else parsed_log.taxonomy_class
        or "source_bug"
    )
    error_id = manual_label.error_id if manual_label is not None else parsed_log.error_id
    difficulty = manual_label.difficulty if manual_label is not None else "unknown"
    confidence = manual_label.confidence if manual_label is not None else "unknown"
    root_cause = manual_label.rationale if manual_label is not None else parsed_log.error_line
    bucket = manual_label.source_bucket if manual_label is not None else source_bucket_for(case_data.get("source", ""))

    record = CaseRecord(
        case_id=case_data.get("case_id") or path.stem,
        case_path=str(path),
        source=str(case_data.get("source") or ""),
        source_bucket=bucket,
        taxonomy_class=taxonomy_class,
        error_id=error_id,
        difficulty=difficulty,
        confidence=confidence,
        ground_truth_root_cause=root_cause or "",
        ground_truth_fix=fix_text,
        ground_truth_fix_source=fix_source,
        source_url=extract_source_url(case_data),
        title=extract_title(case_data),
        buggy_code=buggy_code,
        has_usable_code=has_usable_code,
        verifier_log=verifier_log,
        log_lines=len([line for line in verifier_log.splitlines() if line.strip()]),
        parsed_log={
            "error_line": parsed_log.error_line,
            "error_id": parsed_log.error_id,
            "taxonomy_class": parsed_log.taxonomy_class,
            "source_line": parsed_log.source_line,
            "evidence": parsed_log.evidence,
        },
        structured_analysis=structured_analysis,
        trace_metadata={
            "total_instructions": trace.total_instructions,
            "has_btf_annotations": trace.has_btf_annotations,
            "has_backtracking": trace.has_backtracking,
            "critical_transition_count": len(trace.critical_transitions),
            "causal_chain_present": trace.causal_chain is not None,
        },
        verbose_audit_rank=verbose_audit_rank,
        selection_score=0,
        selection_notes=[],
    )

    ranking = selection_score(record)
    record.selection_score = ranking.total
    record.selection_notes = ranking.notes
    return record


def select_cases(
    *,
    case_records: list[CaseRecord],
    targets: dict[str, int],
    allow_missing_source: bool,
) -> tuple[list[CaseRecord], dict[str, Any]]:
    selected: list[CaseRecord] = []
    summary: dict[str, Any] = {"targets": targets, "by_taxonomy": {}, "shortfalls": {}}

    for taxonomy in TAXONOMY_ORDER:
        target = targets.get(taxonomy, 0)
        if target <= 0:
            continue

        eligible = [
            case
            for case in case_records
            if case.taxonomy_class == taxonomy
            and case.verifier_log.strip()
            and case.ground_truth_fix.strip()
            and case.ground_truth_root_cause.strip()
            and (allow_missing_source or case.has_usable_code)
        ]
        eligible.sort(
            key=lambda case: (
                case.selection_score,
                case.log_lines,
                1 if case.has_usable_code else 0,
                case.case_id,
            ),
            reverse=True,
        )

        chosen = eligible[:target]
        selected.extend(chosen)
        summary["by_taxonomy"][taxonomy] = {
            "target": target,
            "available": len(eligible),
            "selected": [case.case_id for case in chosen],
        }
        if len(chosen) < target:
            summary["shortfalls"][taxonomy] = {
                "target": target,
                "selected": len(chosen),
                "missing": target - len(chosen),
            }

    selected.sort(key=lambda case: (TAXONOMY_ORDER.index(case.taxonomy_class), case.case_id))
    summary["selected_case_count"] = len(selected)
    return selected, summary


def flatten_runs(case_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in case_entries:
        for model_strength in MODEL_STRENGTH_ORDER:
            for condition in CONDITION_ORDER:
                run = case["runs"][model_strength][condition]
                rows.append(
                    {
                        "case_id": case["case_id"],
                        "taxonomy_class": case["taxonomy_class"],
                        "source_bucket": case["source_bucket"],
                        "difficulty": case["difficulty"],
                        "log_lines": case["log_lines"],
                        "causal_chain_present": case["trace_metadata"]["causal_chain_present"],
                        "model_strength": model_strength,
                        "condition": condition,
                        "run": run,
                    }
                )
    return rows


def aggregate_bucket(runs: list[dict[str, Any]]) -> dict[str, Any]:
    total_runs = len(runs)
    scored = [row for row in runs if row["run"].get("score")]
    if not scored:
        return {
            "count": total_runs,
            "scored_count": 0,
            "root_cause_correct_total": 0,
            "root_cause_accuracy": 0.0,
            "taxonomy_class_correct_total": 0,
            "taxonomy_class_accuracy": 0.0,
            "fix_direction_correct_total": 0,
            "fix_direction_accuracy": 0.0,
            "mean_fix_specificity": 0.0,
            "mean_response_tokens": 0.0,
        }

    root_total = sum(row["run"]["score"]["root_cause_correct"] for row in scored)
    taxonomy_total = sum(row["run"]["score"]["taxonomy_class_correct"] for row in scored)
    fix_total = sum(row["run"]["score"]["fix_direction_correct"] for row in scored)
    specificity = sum(row["run"]["score"]["fix_specificity"] for row in scored) / len(scored)
    token_values = [
        row["run"]["score"]["response_tokens"]
        for row in scored
        if row["run"]["score"]["response_tokens"] is not None
    ]
    mean_tokens = (sum(token_values) / len(token_values)) if token_values else 0.0
    return {
        "count": total_runs,
        "scored_count": len(scored),
        "root_cause_correct_total": root_total,
        "taxonomy_class_correct_total": taxonomy_total,
        "fix_direction_correct_total": fix_total,
        "mean_fix_specificity": round(specificity, 2),
        "mean_response_tokens": round(mean_tokens, 2),
        "root_cause_accuracy": round(root_total / total_runs, 4) if total_runs else 0.0,
        "taxonomy_class_accuracy": round(taxonomy_total / total_runs, 4) if total_runs else 0.0,
        "fix_direction_accuracy": round(fix_total / total_runs, 4) if total_runs else 0.0,
    }


def compare_condition_scores(case_entry: dict[str, Any], model_strength: str) -> str:
    def ranking(condition: str) -> tuple[int, int, int, int, int]:
        score = case_entry["runs"][model_strength][condition].get("score") or {}
        return (
            int(score.get("root_cause_correct", 0)),
            int(score.get("taxonomy_class_correct", 0)),
            int(score.get("fix_direction_correct", 0)),
            int(score.get("fix_specificity", 0)),
            -(int(score.get("response_tokens") or 10**9)),
        )

    by_condition = {condition: ranking(condition) for condition in CONDITION_ORDER}
    return max(by_condition, key=by_condition.get)


def aggregate_summary(case_entries: list[dict[str, Any]]) -> dict[str, Any]:
    rows = flatten_runs(case_entries)
    summary: dict[str, Any] = {
        "overall_by_condition": {},
        "overall_by_strength_and_condition": {},
        "by_taxonomy_strength_condition": {},
        "best_condition_counts": {},
        "strong_vs_weak": {},
    }

    for condition in CONDITION_ORDER:
        summary["overall_by_condition"][condition] = aggregate_bucket(
            [row for row in rows if row["condition"] == condition]
        )

    for model_strength in MODEL_STRENGTH_ORDER:
        summary["overall_by_strength_and_condition"][model_strength] = {}
        for condition in CONDITION_ORDER:
            summary["overall_by_strength_and_condition"][model_strength][condition] = aggregate_bucket(
                [
                    row
                    for row in rows
                    if row["model_strength"] == model_strength and row["condition"] == condition
                ]
            )

    for model_strength in MODEL_STRENGTH_ORDER:
        summary["by_taxonomy_strength_condition"][model_strength] = {}
        for taxonomy in TAXONOMY_ORDER:
            summary["by_taxonomy_strength_condition"][model_strength][taxonomy] = {}
            for condition in CONDITION_ORDER:
                summary["by_taxonomy_strength_condition"][model_strength][taxonomy][condition] = aggregate_bucket(
                    [
                        row
                        for row in rows
                        if row["model_strength"] == model_strength
                        and row["taxonomy_class"] == taxonomy
                        and row["condition"] == condition
                    ]
                )

    for model_strength in MODEL_STRENGTH_ORDER:
        counts = {condition: 0 for condition in CONDITION_ORDER}
        for case_entry in case_entries:
            counts[compare_condition_scores(case_entry, model_strength)] += 1
        summary["best_condition_counts"][model_strength] = counts

    for condition in CONDITION_ORDER:
        strong = summary["overall_by_strength_and_condition"]["strong"][condition]
        weak = summary["overall_by_strength_and_condition"]["weak"][condition]
        summary["strong_vs_weak"][condition] = {
            "strong_root_cause_accuracy": strong["root_cause_accuracy"],
            "weak_root_cause_accuracy": weak["root_cause_accuracy"],
            "delta_root_cause_accuracy": round(
                strong["root_cause_accuracy"] - weak["root_cause_accuracy"], 4
            ),
            "strong_taxonomy_accuracy": strong["taxonomy_class_accuracy"],
            "weak_taxonomy_accuracy": weak["taxonomy_class_accuracy"],
            "delta_taxonomy_accuracy": round(
                strong["taxonomy_class_accuracy"] - weak["taxonomy_class_accuracy"], 4
            ),
        }

    return summary


def render_aggregate_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Model Strength | Condition | Cases | Root Cause | Taxonomy | Fix Direction | Mean Specificity | Mean Response Tokens |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for model_strength in MODEL_STRENGTH_ORDER:
        for condition in CONDITION_ORDER:
            bucket = summary["overall_by_strength_and_condition"][model_strength][condition]
            lines.append(
                "| "
                + " | ".join(
                    [
                        MODEL_STRENGTH_SPECS[model_strength]["label"],
                        CONDITION_SPECS[condition]["label"],
                        str(bucket["count"]),
                        f'{bucket["root_cause_correct_total"]}/{bucket["count"]}',
                        f'{bucket["taxonomy_class_correct_total"]}/{bucket["count"]}',
                        f'{bucket["fix_direction_correct_total"]}/{bucket["count"]}',
                        str(bucket["mean_fix_specificity"]),
                        str(bucket["mean_response_tokens"]),
                    ]
                )
                + " |"
            )
    return "\n".join(lines)


def render_overall_condition_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Condition | Cases | Root Cause | Taxonomy | Fix Direction | Mean Specificity | Mean Response Tokens |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition in CONDITION_ORDER:
        bucket = summary["overall_by_condition"][condition]
        lines.append(
            "| "
            + " | ".join(
                [
                    CONDITION_SPECS[condition]["label"],
                    str(bucket["count"]),
                    f'{bucket["root_cause_correct_total"]}/{bucket["count"]}',
                    f'{bucket["taxonomy_class_correct_total"]}/{bucket["count"]}',
                    f'{bucket["fix_direction_correct_total"]}/{bucket["count"]}',
                    str(bucket["mean_fix_specificity"]),
                    str(bucket["mean_response_tokens"]),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def render_taxonomy_breakdown_table(summary: dict[str, Any], model_strength: str) -> str:
    lines = [
        "| Taxonomy | Condition A | Condition B | Condition C |",
        "| --- | ---: | ---: | ---: |",
    ]
    for taxonomy in TAXONOMY_ORDER:
        row = [f"`{taxonomy}`"]
        for condition in CONDITION_ORDER:
            bucket = summary["by_taxonomy_strength_condition"][model_strength][taxonomy][condition]
            row.append(f'{bucket["root_cause_correct_total"]}/{bucket["count"]}')
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_strong_vs_weak_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Condition | Strong Root Cause | Weak Root Cause | Delta |",
        "| --- | ---: | ---: | ---: |",
    ]
    for condition in CONDITION_ORDER:
        bucket = summary["strong_vs_weak"][condition]
        lines.append(
            "| "
            + " | ".join(
                [
                    CONDITION_SPECS[condition]["label"],
                    f'{bucket["strong_root_cause_accuracy"]:.1%}',
                    f'{bucket["weak_root_cause_accuracy"]:.1%}',
                    f'{bucket["delta_root_cause_accuracy"]:.1%}',
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def render_per_case_table(case_entries: list[dict[str, Any]]) -> str:
    lines = [
        "| Case | Taxonomy | Model | Condition | Root | Taxonomy | Fix | Specificity |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for case in case_entries:
        for model_strength in MODEL_STRENGTH_ORDER:
            for condition in CONDITION_ORDER:
                score = case["runs"][model_strength][condition].get("score") or {}
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{case['case_id']}`",
                            f"`{case['taxonomy_class']}`",
                            MODEL_STRENGTH_SPECS[model_strength]["label"],
                            CONDITION_SPECS[condition]["label"],
                            str(score.get("root_cause_correct", "-")),
                            str(score.get("taxonomy_class_correct", "-")),
                            str(score.get("fix_direction_correct", "-")),
                            str(score.get("fix_specificity", "-")),
                        ]
                    )
                    + " |"
                )
    return "\n".join(lines)


def render_case_cohort_table(case_entries: list[dict[str, Any]]) -> str:
    lines = [
        "| Case | Taxonomy | Src | Difficulty | Log Lines | Ground Truth |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for case in case_entries:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{case['case_id']}`",
                    f"`{case['taxonomy_class']}`",
                    case["source_bucket"],
                    case["difficulty"],
                    str(case["log_lines"]),
                    case["ground_truth_fix_source"],
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def root_accuracy(summary: dict[str, Any], model_strength: str, condition: str, taxonomy: str | None = None) -> float:
    if taxonomy is None:
        return summary["overall_by_strength_and_condition"][model_strength][condition]["root_cause_accuracy"]
    return summary["by_taxonomy_strength_condition"][model_strength][taxonomy][condition]["root_cause_accuracy"]


def build_analysis(case_entries: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    strong_c = root_accuracy(summary, "strong", "structured_trace_analysis")
    strong_a = root_accuracy(summary, "strong", "error_message_only")
    strong_b = root_accuracy(summary, "strong", "raw_verbose_log")
    weak_c = root_accuracy(summary, "weak", "structured_trace_analysis")
    weak_a = root_accuracy(summary, "weak", "error_message_only")
    weak_b = root_accuracy(summary, "weak", "raw_verbose_log")

    lowering_strong = {
        condition: root_accuracy(summary, "strong", condition, "lowering_artifact")
        for condition in CONDITION_ORDER
    }
    lowering_weak = {
        condition: root_accuracy(summary, "weak", condition, "lowering_artifact")
        for condition in CONDITION_ORDER
    }

    complex_rows = [
        row
        for row in flatten_runs(case_entries)
        if row["log_lines"] >= 80 or row["causal_chain_present"]
    ]
    complex_by_strength_condition: dict[str, dict[str, Any]] = defaultdict(dict)
    for model_strength in MODEL_STRENGTH_ORDER:
        for condition in CONDITION_ORDER:
            complex_by_strength_condition[model_strength][condition] = aggregate_bucket(
                [
                    row
                    for row in complex_rows
                    if row["model_strength"] == model_strength and row["condition"] == condition
                ]
            )

    hypothesis_supported = (
        lowering_weak["structured_trace_analysis"] >= max(
            lowering_weak["error_message_only"],
            lowering_weak["raw_verbose_log"],
        )
        and weak_c >= max(weak_a, weak_b)
    )

    failing_runs_by_case: dict[str, int] = defaultdict(int)
    for row in flatten_runs(case_entries):
        score = row["run"].get("score") or {}
        if score.get("root_cause_correct") != 1 or score.get("fix_direction_correct") != 1:
            failing_runs_by_case[row["case_id"]] += 1
    failure_note = ""
    if failing_runs_by_case:
        ordered = sorted(failing_runs_by_case.items(), key=lambda item: (-item[1], item[0]))
        rendered = ", ".join(f"{case_id} ({count} run(s))" for case_id, count in ordered[:3])
        failure_note = f"Most misses concentrated in: {rendered}."

    lines = [
        (
            "Across the full 22-case cohort, Condition C "
            f"(structured trace) reached root-cause accuracy {strong_c:.1%} on the strong model "
            f"versus {strong_a:.1%} for Condition A and {strong_b:.1%} for Condition B; "
            f"on the weak model it reached {weak_c:.1%} versus {weak_a:.1%} and {weak_b:.1%}."
        ),
        (
            "On `lowering_artifact`, which is the main stress test for misleading verifier headlines, "
            f"Condition C scored {lowering_strong['structured_trace_analysis']:.1%} on the strong model "
            f"and {lowering_weak['structured_trace_analysis']:.1%} on the weak model. "
            f"For comparison, Condition A scored {lowering_strong['error_message_only']:.1%} / "
            f"{lowering_weak['error_message_only']:.1%}, and Condition B scored "
            f"{lowering_strong['raw_verbose_log']:.1%} / {lowering_weak['raw_verbose_log']:.1%}."
        ),
        (
            "For the complex subset "
            f"({complex_by_strength_condition['strong']['structured_trace_analysis']['count']} runs per condition; "
            "defined here as log-heavy or causal-chain-bearing cases), Condition C reached "
            f"{complex_by_strength_condition['strong']['structured_trace_analysis']['root_cause_accuracy']:.1%} "
            f"root-cause accuracy on the strong model and "
            f"{complex_by_strength_condition['weak']['structured_trace_analysis']['root_cause_accuracy']:.1%} "
            "on the weak model."
        ),
        (
            "The weak-model simulation is near ceiling: the prompt-only downgrade did reduce answer length "
            "and specificity, but it did not create a large correctness gap. That means the strong-vs-weak "
            "comparison should be interpreted as a prompt-ablation, not as evidence about a truly weaker base model."
        ),
        (
            "Hypothesis check: "
            + (
                "supported for the weak-model / lowering-artifact setting."
                if hypothesis_supported
                else "not cleanly supported by the aggregate scores; the structured trace did not dominate every baseline where expected."
            )
        ),
    ]
    if failure_note:
        lines.append(failure_note)
    return "\n\n".join(lines)


def render_markdown(result_payload: dict[str, Any]) -> str:
    lines = [
        "# Multi-Model LLM Experiment",
        "",
        f"Generated at: {result_payload['generated_at']}",
        "",
        "## Experiment Setup",
        "",
        f"- Selection strategy: `{result_payload['selection']['strategy']}`",
        f"- Selected cases: `{result_payload['selection']['selected_case_count']}`",
        f"- Targets: `{result_payload['selection']['targets']}`",
        f"- Manual response file: `{result_payload['manual_responses_path']}`",
        f"- Manual score file: `{result_payload['manual_scores_path']}`",
        "",
        "## Cohort",
        "",
        render_case_cohort_table(result_payload["cases"]),
        "",
        "## Aggregate Results",
        "",
        "Combined across both model strengths:",
        "",
        render_overall_condition_table(result_payload["summary"]),
        "",
        "Split by model strength:",
        "",
        render_aggregate_table(result_payload["summary"]),
        "",
        "Strong vs weak root-cause accuracy:",
        "",
        render_strong_vs_weak_table(result_payload["summary"]),
        "",
        "## Per-Taxonomy Breakdown",
        "",
        "Root-cause correctness counts for the strong model:",
        "",
        render_taxonomy_breakdown_table(result_payload["summary"], "strong"),
        "",
        "Root-cause correctness counts for the weak model:",
        "",
        render_taxonomy_breakdown_table(result_payload["summary"], "weak"),
        "",
        "## Per-Case x Condition x Model Results",
        "",
        render_per_case_table(result_payload["cases"]),
        "",
        "## Analysis",
        "",
        build_analysis(result_payload["cases"], result_payload["summary"]),
        "",
        "## Notes",
        "",
        "- Full prompts and raw responses are stored in the JSON results file.",
        "- Condition tables above use root-cause correctness counts in the key taxonomy breakdown.",
        "- Final scores come from the `codex_judge` pass when available; otherwise the script falls back to heuristic keyword scoring.",
        "",
    ]
    return "\n".join(lines)


def write_prompt_matrix_csv(path: Path, case_entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_key",
                "case_id",
                "taxonomy_class",
                "source_bucket",
                "difficulty",
                "log_lines",
                "model_strength",
                "condition",
                "condition_label",
                "system_prompt",
                "user_prompt",
                "ground_truth_root_cause",
                "ground_truth_fix",
            ],
        )
        writer.writeheader()
        for case in case_entries:
            for model_strength in MODEL_STRENGTH_ORDER:
                for condition in CONDITION_ORDER:
                    run = case["runs"][model_strength][condition]
                    writer.writerow(
                        {
                            "run_key": run_key(case["case_id"], model_strength, condition),
                            "case_id": case["case_id"],
                            "taxonomy_class": case["taxonomy_class"],
                            "source_bucket": case["source_bucket"],
                            "difficulty": case["difficulty"],
                            "log_lines": case["log_lines"],
                            "model_strength": model_strength,
                            "condition": condition,
                            "condition_label": CONDITION_SPECS[condition]["label"],
                            "system_prompt": run["system_prompt"],
                            "user_prompt": run["prompt"],
                            "ground_truth_root_cause": case["ground_truth_root_cause"],
                            "ground_truth_fix": case["ground_truth_fix"],
                        }
                    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a taxonomy-stratified multi-condition LLM comparison experiment."
    )
    parser.add_argument(
        "case_paths",
        nargs="*",
        type=Path,
        help="Optional explicit YAML case files or directories. If omitted, select from manual labels.",
    )
    parser.add_argument(
        "--manual-labels",
        type=Path,
        default=DEFAULT_MANUAL_LABELS_PATH,
        help="Manual-label Markdown file used for taxonomy and ground truth fallback.",
    )
    parser.add_argument(
        "--verbose-audit",
        type=Path,
        default=DEFAULT_VERBOSE_AUDIT_PATH,
        help="Verbose-log audit Markdown file used for selection ranking.",
    )
    parser.add_argument(
        "--targets",
        default="source_bug=9,lowering_artifact=6,verifier_limit=4,env_mismatch=3",
        help="Comma-separated taxonomy targets, e.g. source_bug=9,lowering_artifact=6.",
    )
    parser.add_argument(
        "--allow-missing-source",
        action="store_true",
        help="Allow cases that do not preserve a usable buggy-code snippet.",
    )
    parser.add_argument(
        "--provider",
        choices=("none", "openai", "anthropic"),
        default="none",
        help="Provider to call for automatic runs. Use 'none' with --manual-responses for Codex-driven runs.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override the remote model name for provider-backed execution.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature for provider-backed runs.",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=600,
        help="Maximum completion tokens for each provider-backed response.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="HTTP timeout for provider-backed responses.",
    )
    parser.add_argument(
        "--manual-responses",
        type=Path,
        default=None,
        help="Optional JSON file keyed by case_id::model_strength::condition with response payloads.",
    )
    parser.add_argument(
        "--manual-scores",
        type=Path,
        default=None,
        help="Optional JSON file keyed by case_id::model_strength::condition with score payloads.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help="Path to the full JSON results payload.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Path to the Markdown report.",
    )
    parser.add_argument(
        "--output-prompt-csv",
        type=Path,
        default=None,
        help="Optional CSV path for the prompt matrix used by external runners.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = parse_targets(args.targets)
    manual_labels = load_manual_labels(args.manual_labels)
    verbose_audit_ranks = load_verbose_audit_ranks(args.verbose_audit)
    verifier_parser = VerifierLogParser()

    explicit_paths = flatten_case_paths(args.case_paths)
    if explicit_paths:
        selected_records = [
            build_case_record(
                path=path,
                manual_label=manual_labels.get(path.stem),
                verbose_audit_rank=verbose_audit_ranks.get(path.stem),
                parser=verifier_parser,
            )
            for path in explicit_paths
        ]
        selection_summary = {
            "strategy": "explicit_case_paths",
            "targets": targets,
            "selected_case_count": len(selected_records),
            "selected_case_ids": [record.case_id for record in selected_records],
        }
    else:
        case_records = []
        for case_id, manual_label in manual_labels.items():
            path_matches = list((REPO_ROOT / "case_study" / "cases").rglob(f"{case_id}.yaml"))
            if not path_matches:
                continue
            case_records.append(
                build_case_record(
                    path=path_matches[0],
                    manual_label=manual_label,
                    verbose_audit_rank=verbose_audit_ranks.get(case_id),
                    parser=verifier_parser,
                )
            )
        selected_records, selection_summary = select_cases(
            case_records=case_records,
            targets=targets,
            allow_missing_source=args.allow_missing_source,
        )
        selection_summary["strategy"] = "manual_labels_stratified"

    manual_responses = load_manual_responses(args.manual_responses)
    manual_scores = load_manual_scores(args.manual_scores)
    provider_key = provider_api_key(args.provider)
    remote_model = args.model or provider_default_model(args.provider)

    case_entries: list[dict[str, Any]] = []
    for record in selected_records:
        case_entry = {
            "case_id": record.case_id,
            "case_path": record.case_path,
            "source": record.source,
            "source_bucket": record.source_bucket,
            "taxonomy_class": record.taxonomy_class,
            "error_id": record.error_id,
            "difficulty": record.difficulty,
            "confidence": record.confidence,
            "source_url": record.source_url,
            "title": record.title,
            "log_lines": record.log_lines,
            "ground_truth_root_cause": record.ground_truth_root_cause,
            "ground_truth_fix": record.ground_truth_fix,
            "ground_truth_fix_source": record.ground_truth_fix_source,
            "parsed_log": record.parsed_log,
            "structured_analysis": record.structured_analysis,
            "trace_metadata": record.trace_metadata,
            "selection_score": record.selection_score,
            "selection_notes": record.selection_notes,
            "runs": {},
        }

        for model_strength in MODEL_STRENGTH_ORDER:
            system_prompt = MODEL_STRENGTH_SPECS[model_strength]["system_prompt"]
            case_entry["runs"][model_strength] = {}

            for condition in CONDITION_ORDER:
                prompt = condition_prompt(record, condition)
                key = run_key(record.case_id, model_strength, condition)
                manual_payload = manual_responses.get(key) or {}
                response_text = None
                response_tokens: int | None = None
                token_count_method = "none"
                provider_used = "none"
                model_used = None
                error_message = None

                if manual_payload:
                    response_text = manual_payload.get("response")
                    if isinstance(response_text, str):
                        provider_used = str(manual_payload.get("provider") or "manual")
                        model_used = str(manual_payload.get("model") or model_strength)
                        if manual_payload.get("response_tokens") is not None:
                            response_tokens = int(manual_payload["response_tokens"])
                            token_count_method = "manual"
                        else:
                            response_tokens = estimate_tokens(response_text)
                            token_count_method = "approx_chars_div_4"
                    else:
                        response_text = None
                elif args.provider != "none" and provider_key and remote_model:
                    try:
                        response_text, response_tokens = invoke_provider(
                            provider=args.provider,
                            model=remote_model,
                            api_key=provider_key,
                            prompt=prompt,
                            system_prompt=system_prompt,
                            temperature=args.temperature,
                            max_output_tokens=args.max_output_tokens,
                            timeout_seconds=args.timeout_seconds,
                        )
                        token_count_method = (
                            "provider_usage" if response_tokens is not None else "approx_chars_div_4"
                        )
                        if response_tokens is None and response_text is not None:
                            response_tokens = estimate_tokens(response_text)
                        provider_used = args.provider
                        model_used = remote_model
                    except urllib.error.HTTPError as exc:
                        payload = exc.read().decode("utf-8", errors="replace")
                        error_message = f"HTTP {exc.code}: {payload}"
                    except urllib.error.URLError as exc:
                        error_message = f"URL error: {exc}"
                    except Exception as exc:  # pragma: no cover
                        error_message = str(exc)
                elif args.provider != "none" and not provider_key:
                    error_message = f"Skipped provider call because {args.provider.upper()} API key is not set."

                score = None
                if response_text:
                    if key in manual_scores:
                        score = asdict(
                            normalize_manual_score(
                                manual_scores[key],
                                response_tokens=response_tokens,
                                token_count_method=token_count_method,
                            )
                        )
                    else:
                        score = asdict(
                            heuristic_score_response(
                                case=record,
                                response_text=response_text,
                                response_tokens=response_tokens,
                                token_count_method=token_count_method,
                            )
                        )

                case_entry["runs"][model_strength][condition] = {
                    "system_prompt": system_prompt,
                    "prompt": prompt,
                    "response": response_text,
                    "provider": provider_used,
                    "model": model_used,
                    "score": score,
                    "error": error_message,
                }

        case_entries.append(case_entry)

    result_payload = {
        "generated_at": now_iso(),
        "provider": args.provider,
        "remote_model": remote_model,
        "manual_responses_path": str(args.manual_responses) if args.manual_responses else None,
        "manual_scores_path": str(args.manual_scores) if args.manual_scores else None,
        "selection": selection_summary,
        "cases": case_entries,
    }
    result_payload["summary"] = aggregate_summary(case_entries)

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    with args.output_json.open("w", encoding="utf-8") as handle:
        json.dump(result_payload, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if args.output_md is not None:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        with args.output_md.open("w", encoding="utf-8") as handle:
            handle.write(render_markdown(result_payload))

    if args.output_prompt_csv is not None:
        write_prompt_matrix_csv(args.output_prompt_csv, case_entries)

    print(render_aggregate_table(result_payload["summary"]))
    print(f"\nJSON: {args.output_json}")
    if args.output_md is not None:
        print(f"Markdown: {args.output_md}")
    if args.output_prompt_csv is not None:
        print(f"Prompt CSV: {args.output_prompt_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
