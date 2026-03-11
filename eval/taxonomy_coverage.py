#!/usr/bin/env python3
"""Analyze catalog coverage across collected verifier failure cases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.log_parser import ParsedLog, VerifierLogParser

CASE_DIRS = [
    ROOT / "benchmark" / "cases" / "kernel_selftests",
    ROOT / "benchmark" / "cases" / "stackoverflow",
    ROOT / "benchmark" / "cases" / "github_issues",
]
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "taxonomy-coverage-report.md"
DEFAULT_JSON_PATH = ROOT / "eval" / "results" / "taxonomy_coverage.json"
TAXONOMY_PATH = ROOT / "taxonomy" / "taxonomy.yaml"
CATALOG_PATH = ROOT / "taxonomy" / "error_catalog.yaml"

GENERIC_LINE_PATTERNS = [
    r"^\$ ",
    r"^libbpf: -- (begin|end) dump log --$",
    r"^libbpf:$",
    r"^verification time\b",
    r"^processed \d+ insns\b",
    r"^stack depth \d+\b",
    r"^max_states_per_insn\b",
    r"^peak_states\b",
    r"^mark_read\b",
    r"^prog section\b",
    r"^- type:",
    r"^- instructions:",
    r"^- license:",
    r"^verifier analysis:?$",
    r"^error: failed to load program$",
    r"^error: the bpf_prog_load syscall failed\.? verifier output:?$",
    r"^failed to run `",
    r"^=== run\b",
    r"^bpf_test\.go:\d+: verifier error: load program: invalid argument:?$",
    r"^\d+: \([0-9a-f]{2}\) ",
    r"^from \d+ to \d+: ",
    r"^r\d+=.*fp\d",
    r"^\[debug ",
    r'^"[^"]+": ',
    r"^[{}[\],]+$",
]

DIAGNOSTIC_LINE_PATTERNS = [
    (r"kernel bug at kernel/bpf/verifier\.c", 8),
    (r"warning:.*verifier", 8),
    (r"invalid state transition", 8),
    (r"unknown func", 7),
    (r"helper call is not allowed", 7),
    (r"program of this type cannot use helper", 7),
    (r"attach_btf_id is not a function", 7),
    (r"reference type\('unknown '\) size cannot be determined", 7),
    (r"invalid btf", 7),
    (r"not supported", 6),
    (r"unsupported", 6),
    (r"loop is not bounded", 7),
    (r"back-edge", 7),
    (r"too many states", 7),
    (r"too complex", 7),
    (r"program too large", 7),
    (r"unreachable insn", 6),
    (r"expected an initialized", 6),
    (r"possibly null", 6),
    (r"null pointer", 6),
    (r"unreleased reference", 6),
    (r"invalid access", 6),
    (r"invalid mem access", 6),
    (r"invalid read", 6),
    (r"invalid write", 6),
    (r"unbounded memory access", 6),
    (r"unbounded min value", 6),
    (r"min value is negative", 6),
    (r"math between .* pointer and register with unbounded", 6),
    (r"expected=.*", 5),
    (r"must be referenced or trusted", 5),
    (r"cannot overwrite referenced dynptr", 5),
    (r"value is outside of the allowed memory range", 5),
    (r"cannot restore irq state out of order", 5),
    (r"cannot be called from callback", 5),
    (r"holding a lock", 5),
    (r"rcu_read_lock", 5),
    (r"cannot be used inside .* region", 5),
    (r"arg#?\d+", 4),
    (r"type=.* expected=.*", 4),
    (r"size cannot be determined", 4),
]

CLASS_RULES: dict[str, list[tuple[str, int, str]]] = {
    "verifier_bug": [
        (r"kernel bug at kernel/bpf/verifier\.c", 8, "kernel BUG"),
        (r"warning:.*verifier", 8, "verifier warning"),
        (r"invalid state transition", 8, "invalid state transition"),
        (r"verifier regression", 7, "verifier regression"),
        (r"false positive", 6, "false positive"),
        (r"\bverifier bug\b", 6, "verifier bug"),
    ],
    "env_mismatch": [
        (r"unknown func", 8, "unknown helper or kfunc"),
        (r"helper call is not allowed", 8, "helper not allowed"),
        (r"program of this type cannot use helper", 8, "helper disallowed in program type"),
        (r"attach_btf_id is not a function", 8, "invalid attach BTF id"),
        (r"reference type\('unknown '\) size cannot be determined", 7, "unknown BTF reference size"),
        (r"invalid btf", 7, "invalid BTF"),
        (r"only read from bpf_array is supported", 7, "unsupported mutable global access"),
        (r"global functions that may sleep are not allowed in non-sleepable context", 7, "sleepable mismatch"),
        (r"cannot be called from callback(?: subprog)?", 6, "callback context restriction"),
        (r"not supported", 5, "unsupported feature"),
        (r"unsupported", 5, "unsupported feature"),
        (r"sleepable context", 5, "sleepable context"),
        (r"cannot call exception cb directly", 4, "callback attachment restriction"),
    ],
    "lowering_artifact": [
        (r"unreachable insn", 8, "unreachable instruction"),
        (r"pointer arithmetic on pkt_end", 7, "pkt_end arithmetic"),
        (r"expected pointer type, got scalar", 7, "pointer provenance lost"),
        (r"math between .* pointer and register with unbounded", 6, "pointer arithmetic with unbounded scalar"),
        (r"unbounded min value", 6, "unbounded minimum"),
        (r"min value is negative, either use unsigned or 'var &= const'", 6, "negative minimum after lowering"),
        (r"precision", 4, "precision loss"),
        (r"var_off", 3, "wide var_off range"),
    ],
    "verifier_limit": [
        (r"too many states", 8, "state explosion"),
        (r"the sequence of .* jumps is too complex", 8, "jump complexity"),
        (r"loop is not bounded", 8, "unbounded loop"),
        (r"back-edge", 8, "loop back-edge"),
        (r"program too large", 7, "program too large"),
        (r"combined stack size", 6, "combined stack size"),
        (r"stack depth .* exceeds", 6, "stack depth limit"),
        (r"complexity limit", 6, "complexity limit"),
    ],
    "source_bug": [
        (r"invalid access to packet", 8, "packet bounds violation"),
        (r"invalid access to map value", 8, "map value bounds violation"),
        (r"invalid mem access 'map_value_or_null'", 8, "nullable map value dereference"),
        (r"invalid mem access 'mem_or_null'", 8, "nullable memory dereference"),
        (r"invalid mem access 'scalar'", 7, "scalar dereference"),
        (r"invalid mem access 'inv'", 7, "invalid pointer dereference"),
        (r"invalid mem access", 7, "invalid memory access"),
        (r"invalid indirect read from stack", 8, "stack read before init"),
        (r"invalid read from stack", 8, "stack read before init"),
        (r"stack depth .* before init", 8, "stack read before init"),
        (r"unreleased reference", 8, "reference leak"),
        (r"reference type=ptr_ expected release", 8, "missing release"),
        (r"possibly null pointer", 7, "nullable pointer"),
        (r"null pointer passed", 7, "nullable pointer"),
        (r"expected an initialized dynptr", 7, "uninitialized dynptr"),
        (r"cannot overwrite referenced dynptr", 7, "dynptr reference overwrite"),
        (r"expected a dynptr of type", 7, "wrong dynptr type"),
        (r"value is outside of the allowed memory range", 7, "out of bounds access"),
        (r"misaligned stack access", 6, "misaligned stack access"),
        (r"arg \d+ is an unacquired reference", 6, "unacquired reference"),
        (r"must be referenced or trusted", 6, "missing trusted/reference proof"),
        (r"function calls are not allowed while holding a lock", 6, "lock discipline"),
        (r"bpf_exit instruction .* cannot be used inside .* region", 6, "lock or irq discipline"),
        (r"cannot restore irq state out of order", 6, "irq state discipline"),
        (r"arg#0 doesn't point to an irq flag on stack", 6, "invalid irq flag pointer"),
        (r"expected an initialized iter_num as arg #0", 6, "iterator initialization"),
        (r"arg#0 expected pointer to an iterator on stack", 6, "iterator pointer contract"),
        (r"type=.* expected=.*", 5, "type mismatch"),
        (r"at program exit the register r0 has unknown scalar value", 5, "unknown return value"),
        (r"unbounded memory access", 5, "unbounded memory access"),
    ],
}

RECOMMENDATION_RULES: list[tuple[str, str, str, str, list[str]]] = [
    (
        r"possibly null pointer passed to trusted arg|null pointer passed to trusted arg",
        "trusted_arg_nullability",
        "source_bug",
        "Trusted pointer argument may be NULL at call site",
        [
            r"Possibly NULL pointer passed to trusted arg\d+",
            r"NULL pointer passed to trusted arg\d+",
        ],
    ),
    (
        r"invalid mem access 'scalar'|invalid mem access 'inv'|type=scalar expected=ptr_|expected=ptr_, trusted_ptr_, rcu_ptr_",
        "scalar_pointer_dereference",
        "source_bug",
        "Scalar value dereferenced where a tracked pointer proof is required",
        [
            r"R\d+ invalid mem access '(?:scalar|inv)'",
            r"R\d+ type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_",
        ],
    ),
    (
        r"invalid access to map value",
        "map_value_bounds_violation",
        "source_bug",
        "Map value access exceeds the verifier-proven bounds of the target object",
        [r"invalid access to map value, value_size=\d+ off=-?\d+ size=\d+"],
    ),
    (
        r"only read from bpf_array is supported",
        "mutable_global_state_unsupported",
        "env_mismatch",
        "Mutable global or static data access unsupported in the active BPF environment",
        [r"only read from bpf_array is supported"],
    ),
    (
        r"reference type\('unknown '\) size cannot be determined|invalid btf",
        "btf_reference_metadata_missing",
        "env_mismatch",
        "BTF or reference type metadata is insufficient for verifier type validation",
        [
            r"arg#\d+ reference type\('UNKNOWN '\) size cannot be determined",
            r"invalid btf[_ ]id",
        ],
    ),
    (
        r"unreachable insn",
        "unreachable_instruction_lowering",
        "lowering_artifact",
        "Compiler lowering emitted unreachable instructions the verifier rejects",
        [r"unreachable insn \d+"],
    ),
    (
        r"expected an initialized dynptr|cannot overwrite referenced dynptr|dynptr",
        "dynptr_protocol_violation",
        "source_bug",
        "Dynptr initialization, lifetime, or access protocol violated",
        [
            r"Expected an initialized dynptr as arg #\d+",
            r"cannot overwrite referenced dynptr",
            r"Expected a dynptr of type .* as arg #\d+",
        ],
    ),
    (
        r"expected an initialized iter_num|iterator on stack|iter_",
        "iterator_state_protocol_violation",
        "source_bug",
        "Iterator state machine or stack-placement contract violated",
        [
            r"expected an initialized iter_num as arg #\d+",
            r"arg#\d+ expected pointer to an iterator on stack",
        ],
    ),
    (
        r"cannot restore irq state out of order|holding a lock|irq flag|rcu_read_lock|cannot be used inside .* region",
        "execution_context_discipline_violation",
        "source_bug",
        "Lock, IRQ, or RCU discipline violated on at least one control-flow path",
        [
            r"cannot restore irq state out of order",
            r"function calls are not allowed while holding a lock",
            r"BPF_EXIT instruction .* cannot be used inside .* region",
        ],
    ),
    (
        r"cannot be called from callback|program of this type cannot use helper|helper call is not allowed|unknown func|sleepable context",
        "helper_or_kfunc_context_restriction",
        "env_mismatch",
        "Helper or kfunc is unavailable in the current program type or execution context",
        [
            r"program of this type cannot use helper .*",
            r"helper call is not allowed",
            r"cannot be called from callback(?: subprog)?",
        ],
    ),
    (
        r"(?:min|max)? value is outside of the allowed memory range",
        "allowed_memory_range_violation",
        "source_bug",
        "Computed access range escapes the verifier-allowed memory window",
        [r"R\d+ (?:min|max) value is outside of the allowed memory range"],
    ),
    (
        r"combined stack size|stack depth .* exceeds|too many states|loop is not bounded|back-edge",
        "verifier_analysis_budget_limit",
        "verifier_limit",
        "Verifier rejects the proof shape due to bounded analysis or complexity limits",
        [
            r"combined stack size .*",
            r"too many states",
            r"loop is not bounded",
            r"back-edge",
        ],
    ),
]

EXPANSION_RULES: list[tuple[str, str, str, list[str]]] = [
    (
        r"unreleased reference",
        "OBLIGE-E004",
        "Expand E004 to match shorter `Unreleased reference` forms without an explicit `id=` suffix.",
        [r"Unreleased reference(?: id=\d+)?"],
    ),
    (
        r"invalid (?:indirect )?read from stack",
        "OBLIGE-E003",
        "Expand E003 to cover both `invalid indirect read from stack` and the shorter `invalid read from stack` wording.",
        [r"invalid (?:indirect )?read from stack"],
    ),
    (
        r"invalid mem access '(?:map_value_or_null|mem_or_null)'",
        "OBLIGE-E002",
        "Expand E002 to include nullable memory aliases beyond `map_value_or_null`.",
        [
            r"invalid mem access 'map_value_or_null'",
            r"invalid mem access 'mem_or_null'",
        ],
    ),
    (
        r"math between .* pointer and register with unbounded|(?:min|max)? value is outside of the allowed memory range",
        "OBLIGE-E005",
        "Broaden E005 to catch scalar-range failures currently phrased as allowed-memory-range violations.",
        [
            r"math between .* pointer and register with unbounded.*",
            r"(?:R\d+ )?(?:min|max)? value is outside of the allowed memory range",
        ],
    ),
    (
        r"program of this type cannot use helper|helper call is not allowed|unknown func",
        "OBLIGE-E009",
        "Expand E009 to cover helper restrictions phrased in program-type-specific wording.",
        [
            r"program of this type cannot use helper .*",
            r"helper call is not allowed",
            r"unknown func",
        ],
    ),
]

STOPWORDS = {
    "the",
    "and",
    "that",
    "this",
    "with",
    "from",
    "into",
    "while",
    "inside",
    "arg",
    "expected",
    "pointer",
    "type",
    "value",
    "register",
    "program",
    "cannot",
    "invalid",
    "access",
    "used",
    "passed",
    "allowed",
    "memory",
}


@dataclass(slots=True)
class CaseResult:
    case_id: str
    source: str
    path: str
    log_field: str
    parser_error_id: str | None
    parser_taxonomy_class: str | None
    parser_error_line: str
    heuristic_taxonomy_class: str
    heuristic_reasons: list[str]
    matched: bool
    message_candidates: list[str]


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def iter_case_paths() -> list[Path]:
    paths: list[Path] = []
    for root in CASE_DIRS:
        paths.extend(sorted(path for path in root.glob("*.yaml") if path.name != "index.yaml"))
    return paths


def normalize_case_log(case: dict[str, Any], source: str) -> tuple[str, str]:
    if source == "kernel_selftests":
        expected = case.get("expected_messages") or case.get("expected_verifier_messages") or {}
        if isinstance(expected, dict):
            combined = expected.get("combined") or []
        elif isinstance(expected, list):
            combined = expected
        elif isinstance(expected, str):
            combined = [expected]
        else:
            combined = []
        lines = [str(message).strip() for message in combined if str(message).strip()]
        return "\n".join(lines), "expected_verifier_messages.combined"

    verifier_log = case.get("verifier_log")
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip(), "verifier_log.combined"
        blocks = verifier_log.get("blocks") or []
        lines = [str(block).strip() for block in blocks if str(block).strip()]
        return "\n\n".join(lines), "verifier_log.blocks"
    if isinstance(verifier_log, str) and verifier_log.strip():
        return verifier_log.strip(), "verifier_log"

    verifier_logs = case.get("verifier_logs")
    if isinstance(verifier_logs, list):
        lines = [str(block).strip() for block in verifier_logs if str(block).strip()]
        return "\n\n".join(lines), "verifier_logs"
    if isinstance(verifier_logs, dict):
        combined = verifier_logs.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip(), "verifier_logs.combined"

    return "", "missing"


def clean_line(line: str) -> str:
    normalized = re.sub(r"\s+", " ", line.strip())
    return re.sub(r"^:\s*", "", normalized)


def is_generic_line(line: str) -> bool:
    if not line:
        return True
    lowered = line.strip().lower()
    return any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in GENERIC_LINE_PATTERNS)


def diagnostic_line_score(line: str) -> int:
    normalized = clean_line(line)
    if not normalized:
        return -100
    if is_generic_line(normalized):
        return -100

    score = 0
    lowered = normalized.lower()
    for pattern, weight in DIAGNOSTIC_LINE_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            score += weight

    if re.match(r"^r\d+=.*", lowered):
        score -= 4
    if re.match(r"^\d+:", lowered):
        score -= 4
    if "processed " in lowered and "insns" in lowered:
        score -= 10
    if normalized.endswith(":"):
        score -= 1
    if len(normalized) < 8:
        score -= 2
    return score


def normalize_message_key(message: str) -> str:
    normalized = clean_line(message).lower()
    replacements = [
        (r"0x[0-9a-f]+", "<hex>"),
        (r"\br\d+\b", "r#"),
        (r"\barg#?\d+\b", "arg#"),
        (r"\bfunc#\d+\b", "func#"),
        (r"\bid=\d+\b", "id=#"),
        (r"\boff(?:set)?=-?\d+\b", "off=#"),
        (r"\bsize=\d+\b", "size=#"),
        (r"\bline \d+\b", "line #"),
        (r"\b\d+\b", "#"),
        (r"\s+", " "),
    ]
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    return normalized.strip()


def extract_message_candidates(source: str, raw_log: str, parsed: ParsedLog) -> list[str]:
    lines = [clean_line(line) for line in raw_log.splitlines() if clean_line(line)]

    if source == "kernel_selftests":
        messages = []
        seen: set[str] = set()
        for line in lines:
            if is_generic_line(line):
                continue
            key = normalize_message_key(line)
            if key not in seen:
                seen.add(key)
                messages.append(line)
        return messages

    scored: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        score = diagnostic_line_score(line)
        if score > 0:
            scored.append((score, index, line))

    scored.sort(key=lambda item: (-item[0], item[1]))
    messages = []
    seen: set[str] = set()
    for _, _, line in scored:
        key = normalize_message_key(line)
        if key in seen:
            continue
        seen.add(key)
        messages.append(line)
        if len(messages) >= 2:
            break

    if messages:
        return messages

    fallback_candidates = [parsed.error_line] + lines[::-1]
    for line in fallback_candidates:
        normalized = clean_line(line)
        if normalized and not is_generic_line(normalized):
            return [normalized]
    return []


def classify_taxonomy(
    raw_log: str,
    parsed: ParsedLog,
    message_candidates: list[str],
    decision_order: list[str],
) -> tuple[str, list[str]]:
    scores = {class_id: 0 for class_id in CLASS_RULES}
    reasons: dict[str, list[str]] = defaultdict(list)

    if parsed.taxonomy_class:
        scores[parsed.taxonomy_class] += 6
        reasons[parsed.taxonomy_class].append(f"catalog match {parsed.error_id}")

    analysis_text = "\n".join(message_candidates) if message_candidates else raw_log
    lowered = analysis_text.lower()
    for class_id, rules in CLASS_RULES.items():
        for pattern, weight, label in rules:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                scores[class_id] += weight
                reasons[class_id].append(label)

    if not re.search(r"invalid|fail|error|warning|bug|unknown|not allowed|unsupported|unreachable", lowered):
        if "loaded (" in raw_log.lower() and "processed " in raw_log.lower():
            scores["env_mismatch"] += 4
            reasons["env_mismatch"].append("verification succeeded; issue likely outside verifier")

    max_score = max(scores.values(), default=0)
    if max_score <= 0:
        fallback = parsed.taxonomy_class or "source_bug"
        return fallback, reasons.get(fallback, [])

    tied = {class_id for class_id, score in scores.items() if score == max_score}
    chosen = next((class_id for class_id in decision_order if class_id in tied), "source_bug")
    return chosen, reasons.get(chosen, [])


def recommendation_key_from_message(message: str) -> tuple[str, str, str, str, list[str], bool]:
    lowered = message.lower()
    for pattern, short_name, taxonomy_class, title, patterns in RECOMMENDATION_RULES:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return short_name, taxonomy_class, title, short_name, patterns, True

    tokens = [
        token
        for token in re.findall(r"[a-z_]{4,}", lowered)
        if token not in STOPWORDS and not token.startswith("verifier")
    ]
    top_tokens = tokens[:3] or ["generic", "verifier", "gap"]
    short_name = "_".join(top_tokens)
    title = clean_line(message)
    return short_name, "source_bug", title, short_name, [re.escape(clean_line(message))], False


def expansion_target_from_message(message: str) -> tuple[str, str, list[str]] | None:
    lowered = message.lower()
    for pattern, error_id, note, patterns in EXPANSION_RULES:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return error_id, note, patterns
    return None


def load_taxonomy_config() -> tuple[list[str], list[str]]:
    payload = load_yaml(TAXONOMY_PATH)
    decision_order = payload.get("decision_order") or []
    class_ids = [entry["id"] for entry in payload.get("classes", [])]
    return decision_order, class_ids


def load_catalog_entries() -> list[dict[str, Any]]:
    payload = load_yaml(CATALOG_PATH)
    return payload.get("error_types", [])


def build_case_results(parser: VerifierLogParser, decision_order: list[str]) -> list[CaseResult]:
    results: list[CaseResult] = []
    for path in iter_case_paths():
        case = load_yaml(path)
        source = str(case.get("source") or path.parent.name)
        raw_log, log_field = normalize_case_log(case, source)
        parsed = parser.parse(raw_log)
        message_candidates = extract_message_candidates(source, raw_log, parsed)
        heuristic_class, heuristic_reasons = classify_taxonomy(
            raw_log,
            parsed,
            message_candidates,
            decision_order,
        )
        results.append(
            CaseResult(
                case_id=str(case.get("case_id") or path.stem),
                source=source,
                path=str(path.relative_to(ROOT)),
                log_field=log_field,
                parser_error_id=parsed.error_id,
                parser_taxonomy_class=parsed.taxonomy_class,
                parser_error_line=parsed.error_line,
                heuristic_taxonomy_class=heuristic_class,
                heuristic_reasons=heuristic_reasons,
                matched=parsed.error_id is not None,
                message_candidates=message_candidates,
            )
        )
    return results


def make_report(
    results: list[CaseResult],
    catalog_entries: list[dict[str, Any]],
    taxonomy_classes: list[str],
) -> tuple[str, dict[str, Any]]:
    total_cases = len(results)
    matched_cases = sum(1 for result in results if result.matched)
    coverage_rate = matched_cases / total_cases if total_cases else 0.0

    coverage_by_source: dict[str, dict[str, Any]] = {}
    source_buckets: dict[str, list[CaseResult]] = defaultdict(list)
    for result in results:
        source_buckets[result.source].append(result)
    for source, bucket in sorted(source_buckets.items()):
        source_matches = sum(1 for result in bucket if result.matched)
        coverage_by_source[source] = {
            "cases": len(bucket),
            "matched": source_matches,
            "coverage_rate": source_matches / len(bucket) if bucket else 0.0,
        }

    error_id_counts = {entry["error_id"]: 0 for entry in catalog_entries}
    parser_taxonomy_counts = {class_id: 0 for class_id in taxonomy_classes}
    heuristic_taxonomy_counts = {class_id: 0 for class_id in taxonomy_classes}
    unmatched_groups: dict[str, dict[str, Any]] = {}

    for result in results:
        if result.parser_error_id:
            error_id_counts[result.parser_error_id] = error_id_counts.get(result.parser_error_id, 0) + 1
        if result.parser_taxonomy_class:
            parser_taxonomy_counts[result.parser_taxonomy_class] = (
                parser_taxonomy_counts.get(result.parser_taxonomy_class, 0) + 1
            )
        heuristic_taxonomy_counts[result.heuristic_taxonomy_class] = (
            heuristic_taxonomy_counts.get(result.heuristic_taxonomy_class, 0) + 1
        )

        if result.matched:
            continue
        seen: set[str] = set()
        for message in result.message_candidates:
            key = normalize_message_key(message)
            if key in seen:
                continue
            seen.add(key)
            group = unmatched_groups.setdefault(
                key,
                {
                    "message": message,
                    "count": 0,
                    "case_ids": [],
                    "source_counts": Counter(),
                    "source_case_ids": defaultdict(set),
                    "examples": Counter(),
                },
            )
            group["count"] += 1
            group["case_ids"].append(result.case_id)
            group["source_counts"][result.source] += 1
            group["source_case_ids"][result.source].add(result.case_id)
            group["examples"][message] += 1

    top_unmatched = sorted(
        unmatched_groups.values(),
        key=lambda item: (-item["count"], item["message"].lower()),
    )[:20]
    top_unmatched_serialized = [
        {
            "message": group["examples"].most_common(1)[0][0],
            "count": group["count"],
            "sources": dict(sorted(group["source_counts"].items())),
            "sample_case_ids": group["case_ids"][:5],
        }
        for group in top_unmatched
    ]

    expansion_buckets: dict[str, dict[str, Any]] = {}
    recommendation_buckets: dict[str, dict[str, Any]] = {}
    for group in sorted(unmatched_groups.values(), key=lambda item: (-item["count"], item["message"].lower())):
        expansion_target = expansion_target_from_message(group["message"])
        if expansion_target is not None:
            error_id, note, patterns = expansion_target
            bucket = expansion_buckets.setdefault(
                error_id,
                {
                    "note": note,
                    "case_ids": set(),
                    "messages": [],
                    "patterns": patterns,
                    "source_case_ids": defaultdict(set),
                },
            )
            bucket["case_ids"].update(group["case_ids"])
            bucket["messages"].append(group["examples"].most_common(1)[0][0])
            for source, case_ids in group["source_case_ids"].items():
                bucket["source_case_ids"][source].update(case_ids)
            continue

        short_name, taxonomy_class, title, _, patterns, explicit = recommendation_key_from_message(
            group["message"]
        )
        bucket = recommendation_buckets.setdefault(
            short_name,
            {
                "taxonomy_class": taxonomy_class,
                "title": title,
                "case_ids": set(),
                "messages": [],
                "patterns": patterns,
                "source_case_ids": defaultdict(set),
                "explicit": explicit,
            },
        )
        bucket["case_ids"].update(group["case_ids"])
        bucket["messages"].append(group["examples"].most_common(1)[0][0])
        for source, case_ids in group["source_case_ids"].items():
            bucket["source_case_ids"][source].update(case_ids)

    expansion_recommendations = [
        {
            "existing_error_id": error_id,
            "supporting_case_count": len(payload["case_ids"]),
            "note": payload["note"],
            "candidate_patterns": payload["patterns"],
            "example_messages": payload["messages"][:3],
            "sources": {
                source: len(case_ids)
                for source, case_ids in sorted(payload["source_case_ids"].items())
            },
        }
        for error_id, payload in sorted(
            expansion_buckets.items(),
            key=lambda item: (-len(item[1]["case_ids"]), item[0]),
        )
    ]

    sorted_recommendations = sorted(
        (
            (short_name, payload)
            for short_name, payload in recommendation_buckets.items()
            if payload["explicit"]
        ),
        key=lambda item: (-len(item[1]["case_ids"]), item[0]),
    )[:8]

    recommendations = []
    next_id = len(catalog_entries) + 1
    for short_name, payload in sorted_recommendations:
        recommendations.append(
            {
                "proposed_error_id": f"OBLIGE-E{next_id:03d}",
                "short_name": short_name,
                "taxonomy_class": payload["taxonomy_class"],
                "title": payload["title"],
                "supporting_case_count": len(payload["case_ids"]),
                "candidate_patterns": payload["patterns"],
                "example_messages": payload["messages"][:3],
                "sources": {
                    source: len(case_ids)
                    for source, case_ids in sorted(payload["source_case_ids"].items())
                },
            }
        )
        next_id += 1

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    summary = {
        "generated_at": timestamp,
        "catalog_path": str(CATALOG_PATH.relative_to(ROOT)),
        "taxonomy_path": str(TAXONOMY_PATH.relative_to(ROOT)),
        "total_cases": total_cases,
        "matched_cases": matched_cases,
        "coverage_rate": coverage_rate,
        "coverage_by_source": coverage_by_source,
        "error_id_distribution": error_id_counts,
        "catalog_taxonomy_distribution": parser_taxonomy_counts,
        "heuristic_taxonomy_distribution": heuristic_taxonomy_counts,
        "top_unmatched_messages": top_unmatched_serialized,
        "existing_error_id_expansions": expansion_recommendations,
        "recommendations": recommendations,
        "cases": [
            {
                "case_id": result.case_id,
                "source": result.source,
                "path": result.path,
                "log_field": result.log_field,
                "matched": result.matched,
                "parser_error_id": result.parser_error_id,
                "parser_taxonomy_class": result.parser_taxonomy_class,
                "parser_error_line": result.parser_error_line,
                "heuristic_taxonomy_class": result.heuristic_taxonomy_class,
                "heuristic_reasons": result.heuristic_reasons,
                "message_candidates": result.message_candidates,
            }
            for result in results
        ],
    }

    lines = [
        "# Taxonomy Coverage Analysis",
        "",
        f"Generated at: `{timestamp}`",
        "",
        "## Coverage",
        "",
        f"- Total benchmark cases analyzed: **{total_cases}**",
        f"- Catalog-matched cases: **{matched_cases}**",
        f"- Coverage rate: **{coverage_rate:.1%}**",
        "",
        "### Coverage by Source",
        "",
        "| Source | Cases | Matched | Coverage |",
        "| --- | ---: | ---: | ---: |",
    ]
    for source, payload in sorted(coverage_by_source.items()):
        lines.append(
            f"| `{source}` | {payload['cases']} | {payload['matched']} | {payload['coverage_rate']:.1%} |"
        )

    lines.extend(
        [
            "",
            "## Distribution by Catalog Error ID",
            "",
            "| Error ID | Count |",
            "| --- | ---: |",
        ]
    )
    for error_id, count in sorted(error_id_counts.items()):
        lines.append(f"| `{error_id}` | {count} |")

    lines.extend(
        [
            "",
            "## Distribution by Taxonomy Class",
            "",
            "### Catalog-Matched Cases",
            "",
            "| Taxonomy Class | Count |",
            "| --- | ---: |",
        ]
    )
    for class_id in taxonomy_classes:
        lines.append(f"| `{class_id}` | {parser_taxonomy_counts.get(class_id, 0)} |")

    lines.extend(
        [
            "",
            "### Heuristic Classification Across All Cases",
            "",
            "| Taxonomy Class | Count |",
            "| --- | ---: |",
        ]
    )
    for class_id in taxonomy_classes:
        lines.append(f"| `{class_id}` | {heuristic_taxonomy_counts.get(class_id, 0)} |")

    lines.extend(
        [
            "",
            "## Top Unmatched Verifier Messages",
            "",
            "| Rank | Message | Count | Sources | Sample Cases |",
            "| ---: | --- | ---: | --- | --- |",
        ]
    )
    for rank, payload in enumerate(top_unmatched_serialized, start=1):
        sources = ", ".join(f"{source}:{count}" for source, count in payload["sources"].items())
        sample_cases = ", ".join(f"`{case_id}`" for case_id in payload["sample_case_ids"])
        lines.append(
            f"| {rank} | {payload['message']} | {payload['count']} | {sources or '-'} | {sample_cases or '-'} |"
        )

    lines.extend(
        [
            "",
            "## Recommended Pattern Expansions to Existing IDs",
            "",
            "These unmatched themes already look semantically close to existing catalog entries, so widening regex coverage is lower risk than introducing new IDs.",
            "",
        ]
    )
    for expansion in expansion_recommendations:
        patterns = ", ".join(f"`{pattern}`" for pattern in expansion["candidate_patterns"])
        examples = "; ".join(f"`{message}`" for message in expansion["example_messages"])
        sources = ", ".join(f"{source}:{count}" for source, count in expansion["sources"].items())
        lines.extend(
            [
                f"### {expansion['existing_error_id']}",
                "",
                f"- Supporting unmatched cases: {expansion['supporting_case_count']}",
                f"- Why expand it: {expansion['note']}",
                f"- Candidate regex patterns: {patterns}",
                f"- Example messages: {examples}",
                f"- Sources: {sources or '-'}",
                "",
            ]
        )

    lines.extend(
        [
            "",
            "## Recommendations for New Error IDs",
            "",
            "The current gap list mixes two kinds of misses: genuinely new semantic categories and messages that are likely pattern variants of existing catalog entries. The proposals below focus on the highest-frequency unmatched themes that recur across multiple cases.",
            "",
        ]
    )
    for recommendation in recommendations:
        patterns = ", ".join(f"`{pattern}`" for pattern in recommendation["candidate_patterns"])
        examples = "; ".join(f"`{message}`" for message in recommendation["example_messages"])
        sources = ", ".join(f"{source}:{count}" for source, count in recommendation["sources"].items())
        lines.extend(
            [
                f"### {recommendation['proposed_error_id']} `{recommendation['short_name']}`",
                "",
                f"- Taxonomy class: `{recommendation['taxonomy_class']}`",
                f"- Proposed title: {recommendation['title']}",
                f"- Supporting unmatched cases: {recommendation['supporting_case_count']}",
                f"- Candidate regex patterns: {patterns}",
                f"- Example messages: {examples}",
                f"- Sources: {sources or '-'}",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n", summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Markdown report output path.",
    )
    parser.add_argument(
        "--json-path",
        type=Path,
        default=DEFAULT_JSON_PATH,
        help="JSON summary output path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    decision_order, taxonomy_classes = load_taxonomy_config()
    catalog_entries = load_catalog_entries()
    parser = VerifierLogParser(catalog_path=CATALOG_PATH)
    results = build_case_results(parser, decision_order)
    report, summary = make_report(results, catalog_entries, taxonomy_classes)

    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")
    args.json_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {args.report_path.relative_to(ROOT)} and {args.json_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
