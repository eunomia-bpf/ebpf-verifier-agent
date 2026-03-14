#!/usr/bin/env python3
"""A/B v3 repair experiment — local 20B model, BTF-suppression, more lowering_artifact cases.

Improvements over v2:
  1. Uses local llama.cpp server with GPT-OSS 20B instead of OpenAI API.
  2. Detects BTF-misleading diagnostic text and suppresses it in Condition B.
  3. Targets ≥20 lowering_artifact cases (all available).
  4. Saves intermediate results every 5 cases to survive crashes.
  5. McNemar test on paired fix-type correctness.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests
import yaml
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.pipeline import diagnose
from interface.extractor.rust_diagnostic import generate_diagnostic

# ── optional oracle import ─────────────────────────────────────────────────────
try:
    from eval.verifier_oracle import OracleResult, verify_fix as oracle_verify_fix
    _ORACLE_AVAILABLE = True
except ImportError:
    _ORACLE_AVAILABLE = False

# ── llama-server constants ─────────────────────────────────────────────────────
LLAMA_SERVER_BINARY = (
    "/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server"
)
LLAMA_LIB_DIR = "/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin"
DEFAULT_MODEL = "~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf"
DEFAULT_PORT = 8080
DEFAULT_CTX_SIZE = 8192
SERVER_STARTUP_TIMEOUT = 180  # seconds — 20B model can take longer
HEALTH_CHECK_INTERVAL = 3
REQUEST_TIMEOUT = 180

# ── case selection ─────────────────────────────────────────────────────────────
CASE_DIRS = (
    ROOT / "case_study" / "cases" / "stackoverflow",
    ROOT / "case_study" / "cases" / "github_issues",
    ROOT / "case_study" / "cases" / "kernel_selftests",
)
# v3: maximise lowering_artifact; keep other buckets reasonable
TARGET_CASE_COUNTS = {
    "lowering_artifact": 20,
    "source_bug": 20,
    "verifier_limit": 8,
    "env_mismatch": 8,
}
TOTAL_CASES = sum(TARGET_CASE_COUNTS.values())
ALLOWED_TAXONOMIES = tuple(TARGET_CASE_COUNTS.keys())
TAXONOMY_ORDER = (
    "lowering_artifact",
    "source_bug",
    "verifier_limit",
    "env_mismatch",
)
SOURCE_PRIORITY = {
    "stackoverflow": 0,
    "github_issues": 1,
    "kernel_selftests": 2,
}
TRACE_RICH_LOG_LINES = 80
TRACE_RICH_STATE_LINES = 20

INTER_REQUEST_DELAY = 0.5  # seconds between LLM calls
SAVE_EVERY = 5              # save intermediate results after every N completed pairs

DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "repair_experiment_results_v3.json"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "repair-experiment-v3-results.md"
DEFAULT_MANUAL_LABELS = ROOT / "docs" / "tmp" / "manual-labeling-30cases.md"

# ── BTF-noise detection ────────────────────────────────────────────────────────
BTF_MISLEADING_PATTERNS = (
    re.compile(r"regenerate.*btf", re.IGNORECASE),
    re.compile(r"align.*func_info", re.IGNORECASE),
    re.compile(r"func_info metadata", re.IGNORECASE),
    re.compile(r"btf metadata.*mismatch", re.IGNORECASE),
    re.compile(r"toolchain.*kernel combination", re.IGNORECASE),
    re.compile(r"recompile.*btf", re.IGNORECASE),
)
BTF_PROOF_PATTERNS = (
    re.compile(r"proof.*lost", re.IGNORECASE),
    re.compile(r"mark_precise", re.IGNORECASE),
    re.compile(r"backtrack", re.IGNORECASE),
    re.compile(r"register.*bounds", re.IGNORECASE),
    re.compile(r"causal.*chain", re.IGNORECASE),
    re.compile(r"obligation", re.IGNORECASE),
)


def is_btf_misleading(diagnostic_text: str) -> bool:
    """Return True if the diagnostic is dominated by BTF metadata advice.

    Heuristic: contains ≥1 BTF-misleading phrase AND lacks proof-analysis content.
    """
    misleading_hits = sum(
        1 for pat in BTF_MISLEADING_PATTERNS if pat.search(diagnostic_text)
    )
    proof_hits = sum(
        1 for pat in BTF_PROOF_PATTERNS if pat.search(diagnostic_text)
    )
    return misleading_hits >= 1 and proof_hits == 0


# ── stop-words / tokenization ──────────────────────────────────────────────────
STOPWORDS = {
    "a", "about", "after", "all", "an", "and", "any", "are", "as", "at",
    "be", "before", "because", "but", "by", "can", "do", "does", "for",
    "from", "get", "has", "have", "here", "how", "if", "in", "into",
    "is", "it", "its", "just", "make", "my", "need", "not", "of", "on",
    "one", "only", "or", "out", "so", "that", "the", "their", "then",
    "there", "these", "this", "to", "up", "use", "using", "want", "was",
    "when", "with", "will", "work", "would", "you", "your",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percentage(n: int, d: int) -> float:
    return 0.0 if d == 0 else (n / d) * 100.0


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def significant_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", text.lower()):
        if token in STOPWORDS:
            continue
        if len(token) < 4 and not token.isdigit():
            continue
        tokens.append(token)
    deduped: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if token not in seen:
            seen.add(token)
            deduped.append(token)
    return deduped


def token_overlap(left: Iterable[str], right: Iterable[str]) -> list[str]:
    right_set = set(right)
    return [t for t in left if t in right_set]


# ── fix-tag specs (from repair_experiment.py) ─────────────────────────────────
@dataclass(slots=True)
class TagSpec:
    tag: str
    label: str
    taxonomy_hint: str | None
    location_kind: str
    patterns: tuple[re.Pattern[str], ...]


FIX_TAG_SPECS: tuple[TagSpec, ...] = (
    TagSpec("inline_hint", "add __always_inline", "lowering_artifact", "root_cause", (
        re.compile(r"__always_inline", re.IGNORECASE),
        re.compile(r"static inline", re.IGNORECASE),
        re.compile(r"\binline\b", re.IGNORECASE),
    )),
    TagSpec("no_panic_unwrap", "remove unwrap/panic", "lowering_artifact", "root_cause", (
        re.compile(r"\bpanic\b", re.IGNORECASE),
        re.compile(r"\bunwrap\b", re.IGNORECASE),
        re.compile(r"explicit error handling", re.IGNORECASE),
    )),
    TagSpec("checked_pointer_reuse", "reuse checked pointer", "lowering_artifact", "root_cause", (
        re.compile(r"same checked pointer", re.IGNORECASE),
        re.compile(r"recompute and access through the same", re.IGNORECASE),
        re.compile(r"re-?read packet pointers", re.IGNORECASE),
        re.compile(r"proof survives lowering", re.IGNORECASE),
        re.compile(r"keep the proof within one function", re.IGNORECASE),
        re.compile(r"verifier-friendly loop rewrite", re.IGNORECASE),
    )),
    TagSpec("unsigned_clamp", "add unsigned clamp", "lowering_artifact", "root_cause", (
        re.compile(r"\bunsigned\b", re.IGNORECASE),
        re.compile(r"non-negative", re.IGNORECASE),
        re.compile(r"\bclamp\b", re.IGNORECASE),
        re.compile(r"upper-bound clamp", re.IGNORECASE),
    )),
    TagSpec("spill_reload_avoid", "avoid spill/reload proof loss", "lowering_artifact", "root_cause", (
        re.compile(r"\bspill\b", re.IGNORECASE),
        re.compile(r"\breload\b", re.IGNORECASE),
        re.compile(r"separate registers", re.IGNORECASE),
    )),
    TagSpec("loop_unroll", "unroll or strengthen loop bound", "verifier_limit", "root_cause", (
        re.compile(r"\bunroll", re.IGNORECASE),
        re.compile(r"fully unroll", re.IGNORECASE),
        re.compile(r"bound/invariant explicit", re.IGNORECASE),
    )),
    TagSpec("reduce_branching", "reduce branching/state fan-out", "verifier_limit", "root_cause", (
        re.compile(r"reduce branching", re.IGNORECASE),
        re.compile(r"state fan-?out", re.IGNORECASE),
        re.compile(r"simpler stages", re.IGNORECASE),
        re.compile(r"too complex for the verifier", re.IGNORECASE),
        re.compile(r"hoist common checks", re.IGNORECASE),
    )),
    TagSpec("reduce_stack_depth", "reduce stack depth", "verifier_limit", "root_cause", (
        re.compile(r"stack depth", re.IGNORECASE),
        re.compile(r"stack use", re.IGNORECASE),
        re.compile(r"call tree", re.IGNORECASE),
    )),
    TagSpec("release_mode", "build in release mode", "env_mismatch", "root_cause", (
        re.compile(r"release mode", re.IGNORECASE),
        re.compile(r"build .*release", re.IGNORECASE),
    )),
    TagSpec("btf_regen", "regenerate or align BTF", "env_mismatch", "root_cause", (
        re.compile(r"\bbtf\b", re.IGNORECASE),
        re.compile(r"func_info", re.IGNORECASE),
        re.compile(r"regenerate", re.IGNORECASE),
    )),
    TagSpec("helper_switch", "switch helper or program type", "env_mismatch", "root_cause", (
        re.compile(r"helper allowed", re.IGNORECASE),
        re.compile(r"switch.*helper", re.IGNORECASE),
        re.compile(r"program type that permits", re.IGNORECASE),
        re.compile(r"unavailable helper", re.IGNORECASE),
    )),
    TagSpec("alignment_fix", "fix data alignment", "env_mismatch", "root_cause", (
        re.compile(r"\bpadding\b", re.IGNORECASE),
        re.compile(r"architecture", re.IGNORECASE),
    )),
    TagSpec("use_map_state", "move state into a BPF map", "env_mismatch", "root_cause", (
        re.compile(r"maintain state in a BPF map", re.IGNORECASE),
        re.compile(r"data must instead be written to maps", re.IGNORECASE),
    )),
    TagSpec("kernel_upgrade", "upgrade or backport kernel/toolchain", "env_mismatch", "root_cause", (
        re.compile(r"newer kernel", re.IGNORECASE),
        re.compile(r"\bbackport\b", re.IGNORECASE),
    )),
    TagSpec("queue_map_api", "use the queue-map helper API", "source_bug", "local", (
        re.compile(r"map_push_elem", re.IGNORECASE),
        re.compile(r"queue maps?", re.IGNORECASE),
    )),
    TagSpec("map_declaration", 'fix map declaration / SEC("maps")', "source_bug", "local", (
        re.compile(r'SEC\("maps"\)', re.IGNORECASE),
        re.compile(r"declare the map", re.IGNORECASE),
    )),
    TagSpec("init_stack", "initialize stack buffer", "source_bug", "local", (
        re.compile(r"initiali[sz]e .*buffer", re.IGNORECASE),
        re.compile(r"initiali[sz]e .*stack", re.IGNORECASE),
        re.compile(r"before the helper call", re.IGNORECASE),
    )),
    TagSpec("bounds_check", "add or tighten bounds check", "source_bug", "local", (
        re.compile(r"bounds check", re.IGNORECASE),
        re.compile(r"<=\s*data_end", re.IGNORECASE),
        re.compile(r"\bdata_end\b", re.IGNORECASE),
        re.compile(r"length explicitly bounded", re.IGNORECASE),
        re.compile(r"maximum amount of iterations", re.IGNORECASE),
    )),
    TagSpec("null_check", "add null check", "source_bug", "local", (
        re.compile(r"null check", re.IGNORECASE),
        re.compile(r"==\s*NULL", re.IGNORECASE),
        re.compile(r"!=\s*NULL", re.IGNORECASE),
    )),
    TagSpec("context_member_read", "read through a verifier-safe API", "source_bug", "local", (
        re.compile(r"use bpf_probe_read to read", re.IGNORECASE),
        re.compile(r"read any memeber in sk_buff", re.IGNORECASE),
    )),
    TagSpec("use_value_not_pointer", "pass the value, not a pointer", "source_bug", "local", (
        re.compile(r"pass event as the argument, not &event", re.IGNORECASE),
        re.compile(r"value type is not a pointer", re.IGNORECASE),
    )),
    TagSpec("pointer_type_fix", "use a valid pointer/object", "source_bug", "local", (
        re.compile(r"exact stack slot", re.IGNORECASE),
        re.compile(r"pointer type", re.IGNORECASE),
    )),
    TagSpec("release_balance", "balance acquire/release", "source_bug", "local", (
        re.compile(r"destroy .* every exit path", re.IGNORECASE),
        re.compile(r"balance acquire release", re.IGNORECASE),
    )),
    TagSpec("other_refactor", "refactor or rewrite", None, "root_cause", (
        re.compile(r"\brewrite\b", re.IGNORECASE),
        re.compile(r"\brestructure\b", re.IGNORECASE),
        re.compile(r"\brefactor\b", re.IGNORECASE),
    )),
)

FIX_TAG_LABELS = {spec.tag: spec.label for spec in FIX_TAG_SPECS}
FIX_TAG_TAXONOMY = {
    spec.tag: spec.taxonomy_hint
    for spec in FIX_TAG_SPECS
    if spec.taxonomy_hint is not None
}
ROOT_CAUSE_TAGS = {spec.tag for spec in FIX_TAG_SPECS if spec.location_kind == "root_cause"}
LOCAL_FIX_TAGS = {spec.tag for spec in FIX_TAG_SPECS if spec.location_kind == "local"}


def fix_type_label(tag: str) -> str:
    return FIX_TAG_LABELS.get(tag, tag.replace("_", " "))


def classify_fix_tags(texts: Iterable[str]) -> list[str]:
    combined = "\n".join(t for t in texts if t and t.strip())
    if not combined.strip():
        return []
    return [spec.tag for spec in FIX_TAG_SPECS
            if any(pat.search(combined) for pat in spec.patterns)]


# ── dataclasses ────────────────────────────────────────────────────────────────
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
class CaseCandidate:
    case_id: str
    case_path: str
    source: str
    title: str
    source_url: str
    taxonomy_class: str
    taxonomy_source: str
    error_id: str | None
    verifier_log: str
    log_lines: int
    trace_state_lines: int
    source_code: str
    code_source: str
    raw_fix_text: str
    raw_fix_source: str
    raw_fix_is_accepted: bool
    ground_truth_fix: str
    ground_truth_fix_source: str
    manual_label_present: bool
    manual_confidence: str | None
    expected_fix_tags: list[str]
    expected_fix_type: str
    expected_fix_type_source: str
    expected_location_kind: str
    root_span_text: str
    symptom_span_text: str
    root_tokens: list[str]
    symptom_tokens: list[str]
    diagnostic_text: str
    diagnostic_json: dict[str, Any]
    diagnostic_btf_misleading: bool
    recommended_fix: str | None
    selection_score: int
    selection_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ConditionResult:
    condition: str
    prompt: str
    model: str | None
    raw_response: str
    parsed_response: dict[str, Any] | None
    api_error: str | None
    usage_output_tokens: int | None
    latency_seconds: float | None
    predicted_fix_tags: list[str]
    predicted_fix_type: str
    predicted_location_kind: str | None
    fix_type_match: bool
    location_correct: bool | None
    semantic_similarity: bool | None
    semantic_overlap: list[str]
    btf_suppressed: bool
    # Oracle fields (None when --use-oracle is not set)
    oracle_compile_ok: bool | None = None
    oracle_verifier_pass: bool | None = None


@dataclass(slots=True)
class CaseExperimentResult:
    case_id: str
    case_path: str
    source: str
    taxonomy_class: str
    error_id: str | None
    title: str
    source_url: str
    expected_fix_type: str
    expected_fix_tags: list[str]
    ground_truth_fix: str
    ground_truth_fix_source: str
    root_span_text: str
    symptom_span_text: str
    diagnostic_btf_misleading: bool
    condition_a: ConditionResult
    condition_b: ConditionResult


# ── llama-server lifecycle ─────────────────────────────────────────────────────
def start_llama_server(
    model_path: str,
    port: int,
    ctx_size: int,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    expanded = os.path.expanduser(model_path)
    cmd = [
        LLAMA_SERVER_BINARY,
        "-m", expanded,
        "-c", str(ctx_size),
        "-ngl", "99",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    if LLAMA_LIB_DIR not in existing:
        env["LD_LIBRARY_PATH"] = f"{LLAMA_LIB_DIR}:{existing}" if existing else LLAMA_LIB_DIR
    if extra_env:
        env.update(extra_env)
    print(f"[server] Starting: {' '.join(cmd)}")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )


def wait_for_server(port: int, timeout: int) -> bool:
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "")
                if status == "ok":
                    print(f"  [health] Server ready after {attempt} checks.")
                    return True
                if status == "loading model":
                    print(f"  [health] Still loading model… (attempt {attempt})", flush=True)
        except requests.exceptions.ConnectionError:
            pass
        except Exception as exc:
            print(f"  [health] Warning: {exc}")
        time.sleep(HEALTH_CHECK_INTERVAL)
    return False


# ── case loading ───────────────────────────────────────────────────────────────
def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def parse_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def load_manual_labels(path: Path) -> dict[str, ManualLabel]:
    labels: dict[str, ManualLabel] = {}
    if not path.exists():
        return labels
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


def lookup_manual_label(case_id: str, labels: dict[str, ManualLabel]) -> ManualLabel | None:
    direct = labels.get(case_id)
    if direct is not None:
        return direct
    if not case_id.startswith("kernel-selftest-"):
        return None
    matches = [
        lbl for lid, lbl in labels.items()
        if lid.startswith(case_id + "-") or case_id.startswith(lid + "-")
    ]
    return matches[0] if len(matches) == 1 else None


def iter_case_paths(dirs: Iterable[Path]) -> list[Path]:
    resolved: set[Path] = set()
    for path in dirs:
        if path.is_dir():
            resolved.update(p.resolve() for p in path.glob("*.yaml") if p.name != "index.yaml")
        elif path.suffix == ".yaml" and path.name != "index.yaml":
            resolved.add(path.resolve())
    return sorted(resolved)


def extract_verifier_log(case_data: dict[str, Any]) -> str:
    vl = case_data.get("verifier_log")
    if isinstance(vl, dict):
        combined = vl.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = vl.get("blocks") or []
        joined = "\n\n".join(str(b).strip() for b in blocks if str(b).strip())
        return joined.strip()
    if isinstance(vl, str) and vl.strip():
        return vl.strip()
    vls = case_data.get("verifier_logs")
    if isinstance(vls, list):
        return "\n\n".join(str(b).strip() for b in vls if str(b).strip()).strip()
    if isinstance(vls, dict):
        combined = vls.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
    return ""


def is_log_like(snippet: str) -> bool:
    lines = [l for l in snippet.splitlines() if l.strip()]
    if not lines:
        return False
    hits = 0
    for line in lines[:10]:
        s = line.strip()
        if s.startswith(("libbpf:", "Validating ", "processed ")):
            hits += 1
        if re.match(r"^\d+: \([0-9a-f]{2}\)", s, re.IGNORECASE):
            hits += 1
        if re.match(r"^(R\d|last_idx|regs=|invalid access|math between)", s):
            hits += 1
    return hits >= 2


def is_code_like(snippet: str) -> bool:
    if not snippet.strip() or is_log_like(snippet):
        return False
    markers = (
        'SEC("', '__section("', "__always_inline", "#define", "struct ", "enum ",
        "typedef ", "fn ", "impl ", "match ", "unsafe ", "let ", "use ",
        "return ", "goto ", "if (", "for (", "while (", "asm volatile", "int ", "__u",
    )
    return any(m in snippet for m in markers)


def extract_code_from_diff(snippet: str) -> str:
    body: list[str] = []
    for line in snippet.splitlines():
        if line.startswith(("diff --git", "index ", "--- ", "+++ ", "@@")):
            continue
        if line.startswith("+"):
            continue
        if line.startswith("-"):
            body.append(line[1:])
        elif line.startswith(" "):
            body.append(line[1:])
    return "\n".join(body).strip()


def extract_code_from_text(text: str) -> str:
    if not text.strip():
        return ""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(
            r'^(#include|#define|struct\s+\w+|static\s+__always_inline|SEC\("|__section\("|'
            r'int\s+\w+\(|enum\s+\w+|typedef\s+|__u\d+|fn\s+\w+\(|use\s+\w+|unsafe\s+fn)',
            line.strip(),
        ):
            start = i
            break
    if start is None:
        return ""
    end = len(lines)
    for i in range(start + 1, len(lines)):
        s = lines[i].strip()
        if s.startswith(("libbpf:", "Validating ", "Traceback", "Error:")):
            end = i
            break
        if re.match(r"^\d+: \([0-9a-f]{2}\)", s, re.IGNORECASE):
            end = i
            break
    return "\n".join(lines[start:end]).strip()


def extract_source_code(case_data: dict[str, Any]) -> tuple[str, str]:
    candidates: list[tuple[str, str]] = []
    for snippet in case_data.get("source_snippets") or []:
        if isinstance(snippet, dict):
            code = snippet.get("code")
            if isinstance(code, str) and code.strip():
                candidates.append((code.strip(), "source_snippets.code"))
            continue
        if not isinstance(snippet, str) or not snippet.strip():
            continue
        if snippet.startswith("diff --git"):
            dc = extract_code_from_diff(snippet)
            if dc:
                candidates.append((dc, "source_snippets.diff"))
            continue
        if is_code_like(snippet):
            candidates.append((snippet.strip(), "source_snippets"))
    for bkey in ("question_body_text", "issue_body_text"):
        rec = extract_code_from_text(str(case_data.get(bkey, "")))
        if rec:
            candidates.append((rec, bkey))
    if not candidates:
        return "", "missing"
    return max(candidates, key=lambda x: len(x[0]))


def extract_title(case_data: dict[str, Any]) -> str:
    q = case_data.get("question") or {}
    iss = case_data.get("issue") or {}
    st = case_data.get("selftest") or {}
    return (
        str(q.get("title") or "")
        or str(iss.get("title") or "")
        or str(st.get("function") or "")
        or str(case_data.get("case_id") or "")
    )


def extract_source_url(case_data: dict[str, Any]) -> str:
    q = case_data.get("question") or {}
    iss = case_data.get("issue") or {}
    return (
        str(q.get("url") or "")
        or str(iss.get("url") or "")
        or str(case_data.get("question_url") or "")
        or str(case_data.get("issue_url") or "")
    )


def extract_raw_fix_text(case_data: dict[str, Any]) -> tuple[str, str, bool]:
    sa = case_data.get("selected_answer") or {}
    if isinstance(sa, dict):
        text = (sa.get("fix_description") or sa.get("body_text") or "").strip()
        if text:
            return text, "selected_answer", bool(sa.get("is_accepted"))
    fix = case_data.get("fix") or {}
    if isinstance(fix, dict):
        sc = fix.get("selected_comment") or {}
        text = (sc.get("body_text") or fix.get("summary") or "").strip()
        if text:
            return text, "issue_fix", True
    return "", "missing", False


def count_trace_state_lines(verifier_log: str) -> int:
    count = 0
    for line in verifier_log.splitlines():
        s = line.strip()
        if not s:
            continue
        if re.match(r"^\d+:\s+R\d+(?:_[A-Za-z]+)?=", s):
            count += 1
        elif re.match(r"^R\d+(?:_[A-Za-z]+)?=", s):
            count += 1
        elif re.match(r"^from \d+ to \d+:\s+R\d+(?:_[A-Za-z]+)?=", s):
            count += 1
        elif s.startswith(("last_idx", "regs=", "parent didn't have regs")):
            count += 1
    return count


def is_trace_rich(candidate: CaseCandidate) -> bool:
    return (
        candidate.log_lines >= TRACE_RICH_LOG_LINES
        or candidate.trace_state_lines >= TRACE_RICH_STATE_LINES
    )


def infer_taxonomy(
    *,
    manual_label: ManualLabel | None,
    expected_fix_tags: list[str],
    diagnosis_taxonomy: str | None,
) -> tuple[str, str]:
    if manual_label is not None and manual_label.taxonomy_class in ALLOWED_TAXONOMIES:
        return manual_label.taxonomy_class, "manual_label"
    scores: Counter[str] = Counter()
    for tag in expected_fix_tags:
        hint = FIX_TAG_TAXONOMY.get(tag)
        if hint in ALLOWED_TAXONOMIES:
            scores[hint] += 3
    if scores:
        taxonomy = max(
            ALLOWED_TAXONOMIES,
            key=lambda t: (scores.get(t, 0), -TAXONOMY_ORDER.index(t)),
        )
        if scores[taxonomy] > 0:
            return taxonomy, "fix_tag_heuristic"
    if diagnosis_taxonomy in ALLOWED_TAXONOMIES:
        return str(diagnosis_taxonomy), "oblige_diagnosis"
    return "source_bug", "default"


def generic_fix_type_for_taxonomy(taxonomy_class: str) -> str:
    return {
        "lowering_artifact": "other_refactor",
        "source_bug": "bounds_check",
        "verifier_limit": "reduce_branching",
        "env_mismatch": "helper_switch",
    }.get(taxonomy_class, "other_refactor")


def location_kind_for_expected(taxonomy_class: str, expected_fix_type: str) -> str:
    if taxonomy_class in {"lowering_artifact", "verifier_limit", "env_mismatch"}:
        return "root_cause"
    if expected_fix_type in ROOT_CAUSE_TAGS:
        return "root_cause"
    if expected_fix_type in LOCAL_FIX_TAGS:
        return "local"
    return "unknown"


def extract_root_and_symptom_spans(diagnostic_json: dict[str, Any]) -> tuple[str, str]:
    spans = diagnostic_json.get("spans") or []
    root_text = ""
    for role in ("proof_lost", "proof_established", "proof_propagated"):
        for span in spans:
            if span.get("role") == role and span.get("source_text"):
                root_text = str(span["source_text"])
                break
        if root_text:
            break
    symptom_text = ""
    for span in reversed(spans):
        if span.get("role") == "rejected" and span.get("source_text"):
            symptom_text = str(span["source_text"])
            break
    if not root_text and spans:
        root_text = str(spans[0].get("source_text") or "")
    if not symptom_text and spans:
        symptom_text = str(spans[-1].get("source_text") or "")
    return root_text, symptom_text


def selection_score(candidate: CaseCandidate) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []

    src_bonus = {"stackoverflow": 320, "github_issues": 220, "kernel_selftests": 40}.get(
        candidate.source, 0
    )
    score += src_bonus
    notes.append(f"source:+{src_bonus}")

    if candidate.manual_label_present:
        score += 120
        notes.append("manual_label:+120")

    if candidate.ground_truth_fix_source == "manual_label":
        score += 80
        notes.append("curated_fix:+80")
    elif candidate.ground_truth_fix_source != "missing":
        score += 50
        notes.append("raw_fix:+50")
    else:
        score -= 120
        notes.append("missing_fix:-120")

    if candidate.raw_fix_is_accepted:
        score += 25
        notes.append("accepted_fix:+25")

    if candidate.expected_fix_type_source == "ground_truth":
        score += 40
        notes.append("expected_from_gt:+40")
    elif candidate.expected_fix_type_source == "raw_fix":
        score += 25
        notes.append("expected_from_raw_fix:+25")
    elif candidate.expected_fix_type_source == "diagnosis_fallback":
        score -= 120
        notes.append("diagnosis_fallback:-120")

    if candidate.expected_fix_type != "other_refactor":
        score += 35
        notes.append("specific_fix:+35")

    if candidate.taxonomy_source == "manual_label":
        score += 50
        notes.append("manual_taxonomy:+50")
    elif candidate.taxonomy_source == "fix_tag_heuristic":
        score += 20
        notes.append("tag_taxonomy:+20")

    if candidate.source == "kernel_selftests" and not candidate.manual_label_present:
        score -= 120
        notes.append("selftest_without_manual_gt:-120")

    line_bonus = min(candidate.log_lines, 220) * 2
    score += line_bonus
    notes.append(f"log_lines:+{line_bonus}")

    trace_bonus = min(candidate.trace_state_lines, 80) * 4
    score += trace_bonus
    notes.append(f"trace_state_lines:+{trace_bonus}")

    if is_trace_rich(candidate):
        score += 60
        notes.append("trace_rich:+60")

    # v3: extra bonus for lowering_artifact (we want ≥20)
    if candidate.taxonomy_class == "lowering_artifact":
        score += 50
        notes.append("lowering_artifact_bonus:+50")

    return score, notes


def build_candidate(path: Path, manual_labels: dict[str, ManualLabel]) -> CaseCandidate | None:
    case_data = read_yaml(path)
    case_id = str(case_data.get("case_id") or path.stem)
    verifier_log = extract_verifier_log(case_data)
    if not verifier_log:
        return None

    source_code, code_source = extract_source_code(case_data)
    if not source_code:
        return None

    try:
        diag = diagnose(verifier_log)
    except Exception as exc:
        print(f"[warn] diagnose failed for {case_id}: {type(exc).__name__}: {exc}")
        return None

    try:
        diag_out = generate_diagnostic(verifier_log)
        diagnostic_text = diag_out.text
        diagnostic_json = diag_out.json_data
    except Exception as exc:
        diagnostic_text = f"OBLIGE diagnostic generation failed: {type(exc).__name__}: {exc}"
        diagnostic_json = {}

    btf_misleading = is_btf_misleading(diagnostic_text)

    manual_label = lookup_manual_label(case_id, manual_labels)
    raw_fix_text, raw_fix_source, raw_fix_is_accepted = extract_raw_fix_text(case_data)

    if manual_label is not None and manual_label.ground_truth_fix.strip():
        ground_truth_fix = manual_label.ground_truth_fix.strip()
        ground_truth_fix_source = "manual_label"
    elif raw_fix_text:
        ground_truth_fix = raw_fix_text
        ground_truth_fix_source = raw_fix_source
    else:
        ground_truth_fix = ""
        ground_truth_fix_source = "missing"
    if not ground_truth_fix.strip():
        return None

    expected_fix_tags = classify_fix_tags([ground_truth_fix])
    expected_fix_type_source = "ground_truth" if expected_fix_tags else "missing"
    if not expected_fix_tags and raw_fix_text:
        expected_fix_tags = classify_fix_tags([raw_fix_text])
        expected_fix_type_source = "raw_fix" if expected_fix_tags else "missing"
    if not expected_fix_tags and diag.recommended_fix:
        expected_fix_tags = classify_fix_tags([diag.recommended_fix])
        expected_fix_type_source = "diagnosis_fallback" if expected_fix_tags else "missing"

    taxonomy_class, taxonomy_source = infer_taxonomy(
        manual_label=manual_label,
        expected_fix_tags=expected_fix_tags,
        diagnosis_taxonomy=diag.taxonomy_class,
    )
    expected_fix_type = (
        expected_fix_tags[0] if expected_fix_tags else generic_fix_type_for_taxonomy(taxonomy_class)
    )
    expected_location_kind = location_kind_for_expected(taxonomy_class, expected_fix_type)
    root_span_text, symptom_span_text = extract_root_and_symptom_spans(diagnostic_json)

    candidate = CaseCandidate(
        case_id=case_id,
        case_path=str(path),
        source=str(case_data.get("source") or ""),
        title=extract_title(case_data),
        source_url=extract_source_url(case_data),
        taxonomy_class=taxonomy_class,
        taxonomy_source=taxonomy_source,
        error_id=diag.error_id,
        verifier_log=verifier_log,
        log_lines=len([l for l in verifier_log.splitlines() if l.strip()]),
        trace_state_lines=count_trace_state_lines(verifier_log),
        source_code=source_code,
        code_source=code_source,
        raw_fix_text=raw_fix_text,
        raw_fix_source=raw_fix_source,
        raw_fix_is_accepted=raw_fix_is_accepted,
        ground_truth_fix=ground_truth_fix,
        ground_truth_fix_source=ground_truth_fix_source,
        manual_label_present=manual_label is not None,
        manual_confidence=manual_label.confidence if manual_label is not None else None,
        expected_fix_tags=expected_fix_tags,
        expected_fix_type=expected_fix_type,
        expected_fix_type_source=expected_fix_type_source,
        expected_location_kind=expected_location_kind,
        root_span_text=root_span_text,
        symptom_span_text=symptom_span_text,
        root_tokens=significant_tokens(root_span_text),
        symptom_tokens=significant_tokens(symptom_span_text),
        diagnostic_text=diagnostic_text,
        diagnostic_json=diagnostic_json,
        diagnostic_btf_misleading=btf_misleading,
        recommended_fix=diag.recommended_fix,
        selection_score=0,
    )
    sc, notes = selection_score(candidate)
    candidate.selection_score = sc
    candidate.selection_notes = notes
    return candidate


def choose_next_candidate(
    candidates: list[CaseCandidate],
    seen_tags: set[str],
    seen_sources: set[str],
) -> CaseCandidate | None:
    if not candidates:
        return None

    def sort_key(c: CaseCandidate) -> tuple[int, int, str]:
        new_tag = int(c.expected_fix_type not in seen_tags and c.expected_fix_type != "other_refactor")
        new_src = int(c.source not in seen_sources)
        composite = (
            c.selection_score
            + new_tag * 30
            + new_src * 10
            + int(c.manual_label_present) * 10
        )
        return (composite, c.selection_score, c.case_id)

    return max(candidates, key=sort_key)


def select_cases(
    candidates: list[CaseCandidate],
    case_count: int,
) -> tuple[list[CaseCandidate], dict[str, Any]]:
    selected: list[CaseCandidate] = []
    selected_ids: set[str] = set()
    bucket_seen_tags: dict[str, set[str]] = {t: set() for t in ALLOWED_TAXONOMIES}
    bucket_seen_sources: dict[str, set[str]] = {t: set() for t in ALLOWED_TAXONOMIES}
    pool_counts = Counter(c.taxonomy_class for c in candidates)
    effective_targets = {
        taxonomy: min(TARGET_CASE_COUNTS[taxonomy], pool_counts.get(taxonomy, 0))
        for taxonomy in TAXONOMY_ORDER
    }
    minimum = sum(effective_targets.values())
    effective_count = max(case_count, minimum)
    effective_count = min(effective_count, len(candidates))

    summary: dict[str, Any] = {
        "requested_case_count": case_count,
        "effective_case_count": effective_count,
        "requested_targets": dict(TARGET_CASE_COUNTS),
        "effective_targets": effective_targets,
        "pool_counts": dict(pool_counts),
    }

    for taxonomy, target in effective_targets.items():
        done = 0
        while done < target:
            eligible = [c for c in candidates if c.case_id not in selected_ids and c.taxonomy_class == taxonomy]
            pick = choose_next_candidate(eligible, bucket_seen_tags[taxonomy], bucket_seen_sources[taxonomy])
            if pick is None:
                break
            selected.append(pick)
            selected_ids.add(pick.case_id)
            bucket_seen_tags[taxonomy].add(pick.expected_fix_type)
            bucket_seen_sources[taxonomy].add(pick.source)
            done += 1

    ov_tags: set[str] = {c.expected_fix_type for c in selected}
    ov_srcs: set[str] = {c.source for c in selected}
    while len(selected) < effective_count:
        eligible = [c for c in candidates if c.case_id not in selected_ids]
        pick = choose_next_candidate(eligible, ov_tags, ov_srcs)
        if pick is None:
            break
        selected.append(pick)
        selected_ids.add(pick.case_id)
        ov_tags.add(pick.expected_fix_type)
        ov_srcs.add(pick.source)

    selected.sort(
        key=lambda c: (
            TAXONOMY_ORDER.index(c.taxonomy_class),
            SOURCE_PRIORITY.get(c.source, 99),
            c.case_id,
        )
    )
    summary["selected_case_ids"] = [c.case_id for c in selected]
    summary["selected_taxonomy_counts"] = dict(Counter(c.taxonomy_class for c in selected))
    summary["selected_source_counts"] = dict(Counter(c.source for c in selected))
    summary["selected_trace_rich_count"] = sum(1 for c in selected if is_trace_rich(c))
    summary["selected_log_lines_total"] = sum(c.log_lines for c in selected)
    summary["selected_trace_state_lines"] = sum(c.trace_state_lines for c in selected)
    summary["selected_by_taxonomy"] = {
        t: [c.case_id for c in selected if c.taxonomy_class == t]
        for t in TAXONOMY_ORDER
    }
    summary["btf_misleading_count"] = sum(1 for c in selected if c.diagnostic_btf_misleading)
    return selected, summary


# ── LLM interaction ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You repair Linux eBPF programs that fail verification. "
    "Focus on the verifier's proof trace: where the proof was lost, what caused it, "
    "and the minimal source change that restores the proof. "
    "Choose the most likely single repair, not a list of unrelated ideas. "
    "Prefer concise, concrete fixes that address the root cause of proof failure. "
    "Do NOT follow advice about BTF metadata or func_info unless the error explicitly "
    "mentions a BTF mismatch. "
    "Provide: (1) a one-sentence explanation of the root cause, "
    "(2) the fix type as a short label (e.g. bounds_check, null_check, inline_rewrite), "
    "and (3) the fixed code in a ```c ... ``` fenced block."
)


def build_prompt(candidate: CaseCandidate, condition: str) -> str:
    """Build the LLM prompt for condition A or B.

    v3 improvement: for condition B, skip the OBLIGE diagnostic if it is
    BTF-misleading (detected by is_btf_misleading), so we don't push the LLM
    away from the correct source-bug repair.
    """
    lines = [
        "Fix this BPF program.",
        "Here is the verifier error log:",
        "```text",
        candidate.verifier_log,
        "```",
    ]
    if condition == "b":
        diagnostic_to_use = candidate.diagnostic_text
        if candidate.diagnostic_btf_misleading:
            # Suppress the misleading BTF diagnostic; add a note instead
            diagnostic_to_use = (
                "[OBLIGE: diagnostic suppressed — output contained BTF metadata advice "
                "not supported by this trace. Focus on the verifier log above.]"
            )
        lines.extend([
            "Here is OBLIGE's diagnostic analysis:",
            "```text",
            diagnostic_to_use,
            "```",
        ])
    lines.extend([
        "Here is the source code:",
        "```c",
        candidate.source_code,
        "```",
        "Reply with:",
        "1. One sentence: root cause of the verifier failure.",
        "2. Fix type label (e.g. bounds_check, null_check, inline_rewrite, unsigned_clamp, "
        "loop_unroll, reduce_stack_depth, btf_regen, init_stack, pointer_type_fix, "
        "release_balance, release_mode, spill_reload_avoid, reduce_branching).",
        "3. The fixed source code in a ```c ... ``` fenced block.",
    ])
    return "\n".join(lines)


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)

# Keywords → fix_type tags for free-text fallback classification.
# Ordered from most specific to least specific.
_FREETEXT_FIX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # More specific patterns first to avoid false positives.
    (re.compile(r"\bbounds?\s*check\b", re.IGNORECASE), "bounds_check"),
    (re.compile(r"\bdata_end\b", re.IGNORECASE), "bounds_check"),
    (re.compile(r"\blength\b.*\bbound", re.IGNORECASE), "bounds_check"),
    (re.compile(r"\bnull[\s_-]*check\b", re.IGNORECASE), "null_check"),
    (re.compile(r"check.*for\s+null\b", re.IGNORECASE), "null_check"),
    (re.compile(r"!=\s*NULL|==\s*NULL", re.IGNORECASE), "null_check"),
    (re.compile(r"map\s+lookup.*null|null.*map\s+lookup", re.IGNORECASE), "null_check"),
    (re.compile(r"\bunsigned\s*clamp\b|\bclamp\b.*\bunsigned\b", re.IGNORECASE), "unsigned_clamp"),
    (re.compile(r"\bunroll\b", re.IGNORECASE), "loop_unroll"),
    (re.compile(r"\bstack[\s_-]*depth\b", re.IGNORECASE), "reduce_stack_depth"),
    (re.compile(r"\bcall\s+tree\b|\bstack\s+use\b", re.IGNORECASE), "reduce_stack_depth"),
    (re.compile(r"\brelease\s*mode\b|\bbuild.*release\b", re.IGNORECASE), "release_mode"),
    (re.compile(r"\bbtf\b|\bfunc_info\b|\bregenerate\b", re.IGNORECASE), "btf_regen"),
    (re.compile(r"\binit(iali[sz]e)?\b.*\b(stack|buffer)\b", re.IGNORECASE), "init_stack"),
    (re.compile(r"\bspill\b|\breload\b", re.IGNORECASE), "spill_reload_avoid"),
    (re.compile(r"\binline\b.*\brewrite\b|\brewrite\b.*\binline\b", re.IGNORECASE), "inline_rewrite"),
    (re.compile(r"\breduce\s*branch", re.IGNORECASE), "reduce_branching"),
    (re.compile(r"\bstate\s*fan.?out\b", re.IGNORECASE), "reduce_branching"),
    (re.compile(r"\bpointer[\s_-]*type\b", re.IGNORECASE), "pointer_type_fix"),
    (re.compile(r"\bbalance\s*acquire.*release|destroy.*exit\s*path", re.IGNORECASE), "release_balance"),
]


def strip_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks produced by reasoning models (e.g. Qwen3.5)."""
    return _THINK_RE.sub("", text).strip()


def _try_json_parse(s: str) -> dict[str, Any] | None:
    """Attempt to parse *s* as JSON; return None on failure."""
    try:
        payload = json.loads(s)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        return None


def _extract_fenced_code(text: str) -> str | None:
    """Extract the first fenced code block content (```...```) from *text*."""
    match = re.search(r"```(?:\w+)?\s*\n?(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _infer_fix_type_from_text(text: str) -> str:
    """Guess a fix_type tag from free-form text using keyword heuristics."""
    for pat, tag in _FREETEXT_FIX_PATTERNS:
        if pat.search(text):
            return tag
    return "other_refactor"


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from *text*, handling:

    1. ``<think>…</think>`` blocks from reasoning models (Qwen3.5, DeepSeek-R1).
    2. JSON wrapped in a ```json … ``` fence.
    3. A bare JSON object anywhere in the text.
    4. Free-text / code-only responses: synthesise a minimal dict so the
       scorer can still classify the fix type via keyword matching.
    """
    # Step 1: strip reasoning blocks first.
    cleaned = strip_think_tags(text)

    # Step 2: if the cleaned text starts with a ``` fence, try to parse JSON inside it.
    if cleaned.startswith("```"):
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
        if fence_match:
            result = _try_json_parse(fence_match.group(1))
            if result is not None:
                return result

    # Step 3: try to parse the whole cleaned text as JSON.
    result = _try_json_parse(cleaned)
    if result is not None:
        return result

    # Step 4: scan for any {...} object embedded in the text (greedy-then-shrink).
    # Use the largest brace-delimited region first, then smaller ones.
    brace_matches = list(re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", cleaned, re.DOTALL))
    for match in reversed(brace_matches):  # try largest spans last → they were collected first
        result = _try_json_parse(match.group(0))
        if result is not None:
            return result

    # Step 5: free-text / code-block fallback — synthesise a dict so scoring still works.
    # Extract the code from a fenced block if present; use it as patched_code.
    fenced_code = _extract_fenced_code(cleaned)
    if fenced_code or cleaned:
        # Search the FULL cleaned text for keywords (both prose and code matter).
        inferred_fix = _infer_fix_type_from_text(cleaned)
        summary_text = cleaned[:500]
        return {
            "summary": summary_text,
            "fix_type": inferred_fix,
            "target_location": "",
            "patched_code": fenced_code or cleaned,
            "_parsed_from": "freetext_fallback",
        }

    return None


def call_local_llm(
    *,
    client: OpenAI,
    prompt: str,
    model_name: str = "local",
    temperature: float = 0.0,
    max_tokens: int = 1024,
    timeout: int = REQUEST_TIMEOUT,
    no_think: bool = False,
) -> tuple[str, dict[str, Any] | None, str | None, int | None]:
    """Call the local llama.cpp server and return (raw_text, parsed_dict, error, out_tokens).

    ``no_think=True`` adds ``enable_thinking=False`` to the request body (supported by
    llama.cpp ≥ b5157 for Qwen3 / DeepSeek-R1 models) to suppress the
    ``<think>...</think>`` reasoning preamble entirely.  Even without this flag the
    parser now strips any ``<think>`` blocks before attempting extraction.
    """
    # Build extra kwargs for the OpenAI client so we can pass non-standard fields.
    extra: dict[str, Any] = {}
    if no_think:
        # llama.cpp exposes this as a top-level body parameter.
        # The openai client passes unknown kwargs through to the request body.
        extra["extra_body"] = {"enable_thinking": False}

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            **extra,
        )
        raw_text = response.choices[0].message.content or ""
        # Always strip <think> blocks — harmless if not present.
        text = strip_think_tags(raw_text)
        out_tokens: int | None = None
        if response.usage:
            out_tokens = response.usage.completion_tokens
        parsed = extract_json_object(text)
        return text, parsed, None, out_tokens
    except Exception as exc:
        return "", None, f"{type(exc).__name__}: {exc}", None


# ── scoring ────────────────────────────────────────────────────────────────────
def response_text_for_scoring(raw: str, parsed: dict[str, Any] | None) -> str:
    parts = [raw]
    if parsed:
        for key in ("summary", "fix_type", "target_location", "patched_code"):
            v = parsed.get(key)
            if isinstance(v, str) and v.strip():
                parts.append(v.strip())
    return "\n".join(p for p in parts if p)


def infer_predicted_location_kind(
    *,
    candidate: CaseCandidate,
    response_text: str,
    predicted_fix_tags: list[str],
) -> str | None:
    if predicted_fix_tags:
        primary = predicted_fix_tags[0]
        if primary in ROOT_CAUSE_TAGS:
            return "root_cause"
        if primary in LOCAL_FIX_TAGS:
            return "local"
    resp_tokens = significant_tokens(response_text)
    root_hits = token_overlap(candidate.root_tokens, resp_tokens)
    sym_hits = token_overlap(candidate.symptom_tokens, resp_tokens)
    if root_hits and len(root_hits) > len(sym_hits):
        return "root_cause"
    if sym_hits and len(sym_hits) > len(root_hits):
        return "local"
    return None


def evaluate_response(
    *,
    candidate: CaseCandidate,
    condition: str,
    prompt: str,
    raw_response: str,
    parsed_response: dict[str, Any] | None,
    api_error: str | None,
    usage_output_tokens: int | None,
    latency_seconds: float | None,
    btf_suppressed: bool,
) -> ConditionResult:
    scoring_text = response_text_for_scoring(raw_response, parsed_response)
    predicted_fix_tags = classify_fix_tags([scoring_text])
    predicted_fix_type = predicted_fix_tags[0] if predicted_fix_tags else "other_refactor"
    fix_type_match = candidate.expected_fix_type in predicted_fix_tags

    predicted_location_kind = infer_predicted_location_kind(
        candidate=candidate,
        response_text=scoring_text,
        predicted_fix_tags=predicted_fix_tags,
    )
    if candidate.taxonomy_class in {"lowering_artifact", "verifier_limit", "env_mismatch"}:
        location_correct: bool | None = predicted_location_kind == "root_cause"
    elif candidate.expected_location_kind == "local":
        location_correct = fix_type_match or predicted_location_kind == "local"
    elif candidate.expected_location_kind == "root_cause":
        location_correct = predicted_location_kind == "root_cause"
    else:
        location_correct = None

    semantic_similarity: bool | None = None
    semantic_overlap: list[str] = []
    if candidate.ground_truth_fix.strip():
        gt_tokens = significant_tokens(candidate.ground_truth_fix)
        resp_tokens = significant_tokens(scoring_text)
        semantic_overlap = token_overlap(gt_tokens, resp_tokens)
        semantic_similarity = fix_type_match or len(semantic_overlap) >= 2

    return ConditionResult(
        condition=condition,
        prompt=prompt,
        model="local-20b",
        raw_response=raw_response,
        parsed_response=parsed_response,
        api_error=api_error,
        usage_output_tokens=usage_output_tokens,
        latency_seconds=latency_seconds,
        predicted_fix_tags=predicted_fix_tags,
        predicted_fix_type=predicted_fix_type,
        predicted_location_kind=predicted_location_kind,
        fix_type_match=fix_type_match,
        location_correct=location_correct,
        semantic_similarity=semantic_similarity,
        semantic_overlap=semantic_overlap[:12],
        btf_suppressed=btf_suppressed,
    )


# ── oracle integration ────────────────────────────────────────────────────────
def run_oracle_on_fix(
    parsed_response: dict[str, Any] | None,
    raw_response: str,
    verifier_log_hint: str,
    compile_only: bool,
) -> tuple[bool | None, bool | None]:
    """
    Extract the LLM-generated code from the parsed response and run the oracle on it.

    Returns (compile_ok, verifier_pass) where either may be None if the oracle
    could not be run (e.g., no code found or oracle unavailable).
    """
    if not _ORACLE_AVAILABLE:
        return None, None

    # Extract patched_code from the parsed response first, then fall back to raw text
    code: str = ""
    if parsed_response:
        code = str(parsed_response.get("patched_code") or "").strip()
    if not code:
        # Try to extract a code block from the raw response.
        # Handle common language tags LLMs use: c, C, cpp, bpf, ebpf, or none.
        fence_match = re.search(
            r"```(?:c|C|cpp|bpf|ebpf|eBPF)?\s*\n?(.*?)```",
            raw_response,
            re.DOTALL,
        )
        if fence_match:
            code = fence_match.group(1).strip()
    if not code:
        # No code found in the response
        return None, None

    try:
        result = oracle_verify_fix(
            source_code=code,
            verifier_log_hint=verifier_log_hint,
            compile_only=compile_only,
        )
        verifier_pass = result.verifier_pass if not compile_only else None
        return result.compiles, verifier_pass
    except Exception as exc:
        print(f"    [oracle] Warning: oracle raised {type(exc).__name__}: {exc}")
        return None, None


# ── aggregation ────────────────────────────────────────────────────────────────
def summarize_condition(results: list[ConditionResult]) -> dict[str, Any]:
    total = len(results)
    fix_correct = sum(1 for r in results if r.fix_type_match)
    loc_avail = sum(1 for r in results if r.location_correct is not None)
    loc_correct = sum(1 for r in results if r.location_correct)
    sem_avail = sum(1 for r in results if r.semantic_similarity is not None)
    sem_correct = sum(1 for r in results if r.semantic_similarity)
    # Oracle metrics (only non-None entries count toward the denominator)
    compile_avail = sum(1 for r in results if r.oracle_compile_ok is not None)
    compile_ok = sum(1 for r in results if r.oracle_compile_ok is True)
    vpass_avail = sum(1 for r in results if r.oracle_verifier_pass is not None)
    vpass_ok = sum(1 for r in results if r.oracle_verifier_pass is True)
    summary: dict[str, Any] = {
        "cases": total,
        "fix_type_correct": fix_correct,
        "fix_type_accuracy": percentage(fix_correct, total),
        "location_available": loc_avail,
        "location_correct": loc_correct,
        "location_accuracy": percentage(loc_correct, loc_avail),
        "semantic_available": sem_avail,
        "semantic_correct": sem_correct,
        "semantic_accuracy": percentage(sem_correct, sem_avail),
    }
    if compile_avail > 0:
        summary["oracle_compile_available"] = compile_avail
        summary["oracle_compile_ok"] = compile_ok
        summary["compile_rate"] = percentage(compile_ok, compile_avail)
    if vpass_avail > 0:
        summary["oracle_verifier_available"] = vpass_avail
        summary["oracle_verifier_pass"] = vpass_ok
        summary["verifier_pass_rate"] = percentage(vpass_ok, vpass_avail)
    return summary


def mcnemar_exact(results: list[CaseExperimentResult]) -> dict[str, Any]:
    a_only = sum(1 for r in results if r.condition_a.fix_type_match and not r.condition_b.fix_type_match)
    b_only = sum(1 for r in results if r.condition_b.fix_type_match and not r.condition_a.fix_type_match)
    total = a_only + b_only
    if total == 0:
        return {"a_only": a_only, "b_only": b_only, "p_value": 1.0}
    tail = sum(math.comb(total, k) for k in range(0, min(a_only, b_only) + 1)) / (2 ** total)
    return {"a_only": a_only, "b_only": b_only, "p_value": round(min(1.0, 2 * tail), 6)}


def aggregate_results(results: list[CaseExperimentResult]) -> dict[str, Any]:
    cond_a = summarize_condition([r.condition_a for r in results])
    cond_b = summarize_condition([r.condition_b for r in results])
    per_taxonomy: dict[str, Any] = {}
    for taxonomy in TAXONOMY_ORDER:
        bucket = [r for r in results if r.taxonomy_class == taxonomy]
        if not bucket:
            continue
        per_taxonomy[taxonomy] = {
            "cases": len(bucket),
            "condition_a": summarize_condition([r.condition_a for r in bucket]),
            "condition_b": summarize_condition([r.condition_b for r in bucket]),
            "btf_misleading_suppressed": sum(1 for r in bucket if r.diagnostic_btf_misleading),
        }
    btf_suppressed_results = [r for r in results if r.diagnostic_btf_misleading]
    btf_ok_results = [r for r in results if not r.diagnostic_btf_misleading]
    agg: dict[str, Any] = {
        "condition_a": cond_a,
        "condition_b": cond_b,
        "per_taxonomy": per_taxonomy,
        "mcnemar_fix_type": mcnemar_exact(results),
        "btf_suppressed_subset": {
            "n": len(btf_suppressed_results),
            "condition_a": summarize_condition([r.condition_a for r in btf_suppressed_results]) if btf_suppressed_results else {},
            "condition_b": summarize_condition([r.condition_b for r in btf_suppressed_results]) if btf_suppressed_results else {},
        },
        "btf_ok_subset": {
            "n": len(btf_ok_results),
            "condition_a": summarize_condition([r.condition_a for r in btf_ok_results]) if btf_ok_results else {},
            "condition_b": summarize_condition([r.condition_b for r in btf_ok_results]) if btf_ok_results else {},
        },
    }
    # Oracle aggregate metrics (only present when oracle was used)
    has_oracle_a = any(r.condition_a.oracle_compile_ok is not None for r in results)
    has_oracle_b = any(r.condition_b.oracle_compile_ok is not None for r in results)
    if has_oracle_a or has_oracle_b:
        oracle_agg: dict[str, Any] = {}
        for cond_key, cond_attr in (("condition_a", "condition_a"), ("condition_b", "condition_b")):
            conds = [getattr(r, cond_attr) for r in results]
            compile_avail = sum(1 for c in conds if c.oracle_compile_ok is not None)
            compile_ok = sum(1 for c in conds if c.oracle_compile_ok is True)
            vpass_avail = sum(1 for c in conds if c.oracle_verifier_pass is not None)
            vpass_ok = sum(1 for c in conds if c.oracle_verifier_pass is True)
            oracle_agg[cond_key] = {
                "compile_available": compile_avail,
                "compile_ok": compile_ok,
                "compile_rate": percentage(compile_ok, compile_avail),
                "verifier_available": vpass_avail,
                "verifier_pass": vpass_ok,
                "verifier_pass_rate": percentage(vpass_ok, vpass_avail),
            }
        agg["oracle"] = oracle_agg
    return agg


# ── output ─────────────────────────────────────────────────────────────────────
def save_results_bundle(
    path: Path,
    selection_summary: dict[str, Any],
    selected_cases: list[CaseCandidate],
    results: list[CaseExperimentResult],
    aggregates: dict[str, Any] | None,
    config: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now_iso(),
        "version": "v3",
        "config": config,
        "selection_summary": selection_summary,
        "selected_cases": [asdict(c) for c in selected_cases],
        "results": [asdict(r) for r in results],
        "aggregates": aggregates,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[output] Saved {len(results)} results → {path}")


def format_acc(n: int, d: int) -> str:
    return f"{n}/{d} ({percentage(n, d):.1f}%)"


def markdown_cell(text: str) -> str:
    return text.replace("`", "'").replace("\n", " ").strip()


def build_report(
    selected_cases: list[CaseCandidate],
    results: list[CaseExperimentResult],
    aggregates: dict[str, Any],
    config: dict[str, Any],
    selection_summary: dict[str, Any],
) -> str:
    a = aggregates["condition_a"]
    b = aggregates["condition_b"]
    mc = aggregates["mcnemar_fix_type"]
    btf_n = aggregates["btf_suppressed_subset"]["n"]
    btf_ok_n = aggregates["btf_ok_subset"]["n"]
    taxonomy_counts = Counter(c.taxonomy_class for c in selected_cases)

    lines = [
        "# Repair Experiment V3: Raw Verifier Log vs OBLIGE Diagnostic (Local 20B Model)",
        "",
        f"- Generated: `{now_iso()}`",
        f"- Model: local llama.cpp GPT-OSS 20B",
        f"- Selected cases: `{len(selected_cases)}`",
        f"- Desired taxonomy targets: `{dict(TARGET_CASE_COUNTS)}`",
        f"- Effective taxonomy targets: `{selection_summary['effective_targets']}`",
        f"- Selected taxonomy counts: `{selection_summary['selected_taxonomy_counts']}`",
        f"- BTF-misleading diagnostics suppressed in Condition B: `{btf_n}`",
        "",
        "Scoring rubric per condition: `location/fix_type/root_cause`, each binary in `{0,1}`.",
        "",
        "## Overall Summary",
        "",
        "| Condition | Location | Fix type | Root cause |",
        "| --- | ---: | ---: | ---: |",
        (
            f"| A (raw verifier log only) | "
            f"{format_acc(a['location_correct'], a['location_available'])} | "
            f"{format_acc(a['fix_type_correct'], a['cases'])} | "
            f"{format_acc(a['semantic_correct'], a['semantic_available'])} |"
        ),
        (
            f"| B (raw log + OBLIGE diagnostic) | "
            f"{format_acc(b['location_correct'], b['location_available'])} | "
            f"{format_acc(b['fix_type_correct'], b['cases'])} | "
            f"{format_acc(b['semantic_correct'], b['semantic_available'])} |"
        ),
        "",
        "## Summary By Taxonomy",
        "",
        "| Taxonomy | Cases | A location | B location | A fix type | B fix type | A root cause | B root cause |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for taxonomy in TAXONOMY_ORDER:
        bucket = aggregates["per_taxonomy"].get(taxonomy)
        if not bucket:
            continue
        ca = bucket["condition_a"]
        cb = bucket["condition_b"]
        lines.append(
            f"| `{taxonomy}` | {bucket['cases']} | "
            f"{format_acc(ca['location_correct'], ca['location_available'])} | "
            f"{format_acc(cb['location_correct'], cb['location_available'])} | "
            f"{format_acc(ca['fix_type_correct'], ca['cases'])} | "
            f"{format_acc(cb['fix_type_correct'], cb['cases'])} | "
            f"{format_acc(ca['semantic_correct'], ca['semantic_available'])} | "
            f"{format_acc(cb['semantic_correct'], cb['semantic_available'])} |"
        )

    lines.extend([
        "",
        "## BTF-Suppression Analysis",
        "",
        f"- Cases where OBLIGE diagnostic was BTF-misleading → suppressed: `{btf_n}`",
        f"- Cases with clean proof-analysis diagnostic: `{btf_ok_n}`",
    ])
    if btf_n > 0:
        bsa = aggregates["btf_suppressed_subset"]["condition_a"]
        bsb = aggregates["btf_suppressed_subset"]["condition_b"]
        lines.extend([
            "",
            "| Subset | Condition | Fix type | Location |",
            "| --- | --- | ---: | ---: |",
            f"| BTF-suppressed ({btf_n}) | A | {format_acc(bsa['fix_type_correct'], bsa['cases'])} | {format_acc(bsa['location_correct'], bsa['location_available'])} |",
            f"| BTF-suppressed ({btf_n}) | B | {format_acc(bsb['fix_type_correct'], bsb['cases'])} | {format_acc(bsb['location_correct'], bsb['location_available'])} |",
        ])
    if btf_ok_n > 0:
        boa = aggregates["btf_ok_subset"]["condition_a"]
        bob = aggregates["btf_ok_subset"]["condition_b"]
        lines.extend([
            f"| Clean diagnostic ({btf_ok_n}) | A | {format_acc(boa['fix_type_correct'], boa['cases'])} | {format_acc(boa['location_correct'], boa['location_available'])} |",
            f"| Clean diagnostic ({btf_ok_n}) | B | {format_acc(bob['fix_type_correct'], bob['cases'])} | {format_acc(bob['location_correct'], bob['location_available'])} |",
        ])

    lines.extend([
        "",
        "## Statistical Comparison",
        "",
        f"- Condition A fix-type accuracy: `{a['fix_type_correct']}/{a['cases']}` ({a['fix_type_accuracy']:.1f}%)",
        f"- Condition B fix-type accuracy: `{b['fix_type_correct']}/{b['cases']}` ({b['fix_type_accuracy']:.1f}%)",
        f"- McNemar exact test on paired fix-type: A-only={mc['a_only']}, B-only={mc['b_only']}, p={mc['p_value']:.4f}",
    ])

    # Oracle metrics section (only when oracle was used)
    oracle_agg = aggregates.get("oracle")
    if oracle_agg:
        oa = oracle_agg.get("condition_a", {})
        ob = oracle_agg.get("condition_b", {})
        lines.extend([
            "",
            "## Oracle Verification Metrics",
            "",
            "The verifier oracle compiled and/or loaded LLM-generated `patched_code` into the kernel.",
            "",
            "| Condition | Compile rate | Verifier pass rate |",
            "| --- | ---: | ---: |",
        ])
        def _oracle_rate(d: dict[str, Any], key: str, avail_key: str) -> str:
            avail = d.get(avail_key, 0)
            ok = d.get(key, 0)
            if avail == 0:
                return "n/a"
            return format_acc(ok, avail)

        lines.append(
            f"| A (raw verifier log only) | "
            f"{_oracle_rate(oa, 'compile_ok', 'compile_available')} | "
            f"{_oracle_rate(oa, 'verifier_pass', 'verifier_available')} |"
        )
        lines.append(
            f"| B (raw log + OBLIGE diagnostic) | "
            f"{_oracle_rate(ob, 'compile_ok', 'compile_available')} | "
            f"{_oracle_rate(ob, 'verifier_pass', 'verifier_available')} |"
        )
        lines.extend([
            "",
            f"- `verifier_pass_rate_A`: {oa.get('verifier_pass_rate', 0):.1f}%",
            f"- `verifier_pass_rate_B`: {ob.get('verifier_pass_rate', 0):.1f}%",
            f"- `compile_rate_A`: {oa.get('compile_rate', 0):.1f}%",
            f"- `compile_rate_B`: {ob.get('compile_rate', 0):.1f}%",
        ])

    show_oracle_cols = oracle_agg is not None
    per_case_header = "| Case | Taxonomy | A score | B score | A fix | B fix | Ground truth |"
    per_case_sep = "| --- | --- | ---: | ---: | --- | --- | --- |"
    if show_oracle_cols:
        per_case_header = "| Case | Taxonomy | A score | B score | A oracle | B oracle | A fix | B fix | Ground truth |"
        per_case_sep = "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |"
    lines.extend([
        "",
        "## Per-Case Results",
        "",
        per_case_header,
        per_case_sep,
    ])

    def _oracle_cell(compile_ok: bool | None, vpass: bool | None) -> str:
        c = "Y" if compile_ok is True else ("N" if compile_ok is False else "?")
        v = "Y" if vpass is True else ("N" if vpass is False else "-")
        return f"c={c}/v={v}"

    for result in results:
        a_score = (
            f"{int(result.condition_a.location_correct or 0)}/"
            f"{int(result.condition_a.fix_type_match)}/"
            f"{int(result.condition_a.semantic_similarity or 0)}"
        )
        b_score = (
            f"{int(result.condition_b.location_correct or 0)}/"
            f"{int(result.condition_b.fix_type_match)}/"
            f"{int(result.condition_b.semantic_similarity or 0)}"
        )
        a_fix = markdown_cell((result.condition_a.parsed_response or {}).get("summary", result.condition_a.predicted_fix_type))[:80]
        b_fix = markdown_cell((result.condition_b.parsed_response or {}).get("summary", result.condition_b.predicted_fix_type))[:80]
        gt = markdown_cell(result.ground_truth_fix)[:80]
        btf_flag = " [BTF-supp]" if result.diagnostic_btf_misleading else ""
        if show_oracle_cols:
            a_oracle = _oracle_cell(result.condition_a.oracle_compile_ok, result.condition_a.oracle_verifier_pass)
            b_oracle = _oracle_cell(result.condition_b.oracle_compile_ok, result.condition_b.oracle_verifier_pass)
            lines.append(
                f"| `{result.case_id}`{btf_flag} | `{result.taxonomy_class}` | "
                f"`{a_score}` | `{b_score}` | `{a_oracle}` | `{b_oracle}` | {a_fix} | {b_fix} | {gt} |"
            )
        else:
            lines.append(
                f"| `{result.case_id}`{btf_flag} | `{result.taxonomy_class}` | "
                f"`{a_score}` | `{b_score}` | {a_fix} | {b_fix} | {gt} |"
            )

    # Cases where B helped
    b_better = [r for r in results if r.condition_b.fix_type_match and not r.condition_a.fix_type_match]
    a_better = [r for r in results if r.condition_a.fix_type_match and not r.condition_b.fix_type_match]
    tied = [r for r in results if r.condition_a.fix_type_match == r.condition_b.fix_type_match]

    lines.extend(["", "## Cases Where Condition B Does Better", ""])
    if not b_better:
        lines.append("- None in this run.")
    else:
        for result in b_better:
            btf_note = " (BTF-suppression applied)" if result.diagnostic_btf_misleading else ""
            lines.extend([
                f"### `{result.case_id}`",
                "",
                f"- Taxonomy: `{result.taxonomy_class}`{btf_note}",
                f"- Condition A score: `{int(result.condition_a.location_correct or 0)}/{int(result.condition_a.fix_type_match)}/{int(result.condition_a.semantic_similarity or 0)}`",
                f"- Condition B score: `{int(result.condition_b.location_correct or 0)}/{int(result.condition_b.fix_type_match)}/{int(result.condition_b.semantic_similarity or 0)}`",
                f"- Ground truth: {markdown_cell(result.ground_truth_fix)[:200]}",
                f"- A fix: {markdown_cell((result.condition_a.parsed_response or {}).get('summary', result.condition_a.raw_response[:100]))}",
                f"- B fix: {markdown_cell((result.condition_b.parsed_response or {}).get('summary', result.condition_b.raw_response[:100]))}",
                "- Notes: Condition B helped.",
                "",
            ])

    lines.extend(["## Cases Where Condition B Does Worse", ""])
    if not a_better:
        lines.append("- None in this run.")
    else:
        for result in a_better:
            btf_note = " (BTF-suppression applied)" if result.diagnostic_btf_misleading else ""
            lines.extend([
                f"### `{result.case_id}`",
                "",
                f"- Taxonomy: `{result.taxonomy_class}`{btf_note}",
                f"- Condition A score: `{int(result.condition_a.location_correct or 0)}/{int(result.condition_a.fix_type_match)}/{int(result.condition_a.semantic_similarity or 0)}`",
                f"- Condition B score: `{int(result.condition_b.location_correct or 0)}/{int(result.condition_b.fix_type_match)}/{int(result.condition_b.semantic_similarity or 0)}`",
                f"- Ground truth: {markdown_cell(result.ground_truth_fix)[:200]}",
                f"- A fix: {markdown_cell((result.condition_a.parsed_response or {}).get('summary', result.condition_a.raw_response[:100]))}",
                f"- B fix: {markdown_cell((result.condition_b.parsed_response or {}).get('summary', result.condition_b.raw_response[:100]))}",
                f"- Notes: Condition B hurt{btf_note}.",
                "",
            ])

    lines.extend(["## Overall Conclusion", ""])
    delta_fix = b["fix_type_correct"] - a["fix_type_correct"]
    pct_delta = percentage(delta_fix, a["cases"])
    if delta_fix > 0:
        lines.append(f"Condition B (OBLIGE) improved fix-type accuracy by {pct_delta:+.1f}pp ({delta_fix:+d} cases).")
    elif delta_fix < 0:
        lines.append(f"Condition B (OBLIGE) regressed fix-type accuracy by {pct_delta:.1f}pp ({delta_fix:d} cases).")
    else:
        lines.append("Condition A and B achieved equal fix-type accuracy in this run.")

    la_bucket = aggregates["per_taxonomy"].get("lowering_artifact")
    if la_bucket:
        la_a = la_bucket["condition_a"]["fix_type_correct"]
        la_b = la_bucket["condition_b"]["fix_type_correct"]
        la_n = la_bucket["cases"]
        lines.append(
            f"For lowering_artifact ({la_n} cases): A={la_a}/{la_n}, B={la_b}/{la_n} "
            f"(delta {percentage(la_b - la_a, la_n):+.1f}pp)."
        )
    if btf_n > 0:
        bsb = aggregates["btf_suppressed_subset"]["condition_b"]
        bsa = aggregates["btf_suppressed_subset"]["condition_a"]
        lines.append(
            f"BTF-suppression affected {btf_n} cases: A={format_acc(bsa['fix_type_correct'], bsa['cases'])}, "
            f"B={format_acc(bsb['fix_type_correct'], bsb['cases'])}."
        )

    return "\n".join(lines) + "\n"


# ── main ───────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--ctx-size", type=int, default=DEFAULT_CTX_SIZE)
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--manual-labels-path", type=Path, default=DEFAULT_MANUAL_LABELS)
    parser.add_argument("--no-start-server", action="store_true")
    parser.add_argument("--startup-timeout", type=int, default=SERVER_STARTUP_TIMEOUT)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--use-oracle",
        action="store_true",
        default=False,
        help=(
            "After each LLM fix is generated, compile + verifier-load it via the "
            "verifier oracle. Adds oracle_compile_ok / oracle_verifier_pass to each "
            "result entry and verifier_pass_rate_A/B to the aggregates. "
            "Requires clang (always) and sudo bpftool (for full verifier check). "
            "Off by default so existing runs are unaffected."
        ),
    )
    parser.add_argument(
        "--compile-only-oracle",
        action="store_true",
        default=False,
        help=(
            "When --use-oracle is set, only compile the fix (skip bpftool loading). "
            "Faster but only reports compile_ok, not verifier_pass."
        ),
    )
    parser.add_argument(
        "--no-think",
        action="store_true",
        default=False,
        help=(
            "Pass enable_thinking=False in the request body to suppress <think> "
            "reasoning blocks from Qwen3 / DeepSeek-R1 models running under llama.cpp "
            "(requires llama.cpp ≥ b5157). Even without this flag, any <think> blocks "
            "are stripped from the response before parsing."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server_proc: subprocess.Popen[bytes] | None = None

    def cleanup(signum: int | None = None, frame: Any = None) -> None:
        if server_proc is not None and server_proc.poll() is None:
            print("\n[cleanup] Terminating llama-server…")
            server_proc.terminate()
            try:
                server_proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.communicate()
            print("[cleanup] Server stopped.")

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # ── Load cases ────────────────────────────────────────────────────────────
    print("[cases] Loading manual labels…")
    manual_labels = load_manual_labels(args.manual_labels_path)
    print(f"[cases] Loaded {len(manual_labels)} manual labels.")

    print("[cases] Scanning YAML case files…")
    all_paths = iter_case_paths(CASE_DIRS)
    print(f"[cases] Found {len(all_paths)} candidate YAML files.")

    candidates: list[CaseCandidate] = []
    for path in all_paths:
        cand = build_candidate(path, manual_labels)
        if cand is None:
            continue
        if cand.taxonomy_class not in ALLOWED_TAXONOMIES:
            continue
        candidates.append(cand)
    print(f"[cases] Eligible candidates: {len(candidates)}")

    if not candidates:
        print("[error] No eligible cases found.")
        return 1

    case_count = args.max_cases if args.max_cases is not None else TOTAL_CASES
    selected_cases, selection_summary = select_cases(candidates, case_count)
    print(f"[cases] Selected {len(selected_cases)} cases:")
    for tax in TAXONOMY_ORDER:
        n = selection_summary["selected_taxonomy_counts"].get(tax, 0)
        btf_n = sum(1 for c in selected_cases if c.taxonomy_class == tax and c.diagnostic_btf_misleading)
        print(f"  {tax}: {n} (BTF-misleading: {btf_n})")

    if args.dry_run:
        print("[dry-run] Done — no LLM calls.")
        return 0

    # ── Start server ──────────────────────────────────────────────────────────
    if not args.no_start_server:
        server_proc = start_llama_server(args.model, args.port, args.ctx_size)
        print(f"[server] Waiting up to {args.startup_timeout}s for server…")
        ready = wait_for_server(args.port, args.startup_timeout)
        if not ready:
            if server_proc is not None and server_proc.poll() is not None:
                stderr_out = b""
                if server_proc.stderr:
                    stderr_out = server_proc.stderr.read()
                print("[error] Server exited prematurely.")
                if stderr_out:
                    print("[server stderr]", stderr_out.decode("utf-8", errors="replace")[-2000:])
            else:
                print("[error] Server timeout.")
            cleanup()
            return 1
    else:
        print(f"[server] Skipping startup (--no-start-server), expecting port {args.port}.")
        try:
            resp = requests.get(f"http://127.0.0.1:{args.port}/health", timeout=5)
            print(f"[server] Health check: {resp.json()}")
        except Exception as exc:
            print(f"[error] Cannot reach server: {exc}")
            cleanup()
            return 1

    client = OpenAI(
        base_url=f"http://127.0.0.1:{args.port}/v1",
        api_key="not-needed",
    )

    # ── Run experiment ─────────────────────────────────────────────────────────
    results: list[CaseExperimentResult] = []
    use_oracle: bool = args.use_oracle
    compile_only_oracle: bool = args.compile_only_oracle
    if use_oracle and not _ORACLE_AVAILABLE:
        print("[warn] --use-oracle requested but eval.verifier_oracle could not be imported. Oracle disabled.")
        use_oracle = False
    no_think: bool = args.no_think
    config: dict[str, Any] = {
        "model": args.model,
        "port": args.port,
        "ctx_size": args.ctx_size,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "target_case_counts": dict(TARGET_CASE_COUNTS),
        "version": "v3",
        "use_oracle": use_oracle,
        "compile_only_oracle": compile_only_oracle,
        "no_think": no_think,
    }

    total = len(selected_cases)
    for idx, candidate in enumerate(selected_cases, start=1):
        print(
            f"  [{idx}/{total}] {candidate.case_id} [{candidate.taxonomy_class}]"
            f"{'  [BTF-supp]' if candidate.diagnostic_btf_misleading else ''}",
            flush=True,
        )

        # Condition A
        prompt_a = build_prompt(candidate, "a")
        t0 = time.monotonic()
        raw_a, parsed_a, err_a, tok_a = call_local_llm(
            client=client,
            prompt=prompt_a,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            no_think=no_think,
        )
        lat_a = round(time.monotonic() - t0, 3)
        cond_a = evaluate_response(
            candidate=candidate,
            condition="a",
            prompt=prompt_a,
            raw_response=raw_a,
            parsed_response=parsed_a,
            api_error=err_a,
            usage_output_tokens=tok_a,
            latency_seconds=lat_a,
            btf_suppressed=False,
        )
        if use_oracle:
            a_compile_ok, a_vpass = run_oracle_on_fix(
                parsed_a, raw_a, candidate.verifier_log, compile_only_oracle
            )
            cond_a.oracle_compile_ok = a_compile_ok
            cond_a.oracle_verifier_pass = a_vpass
            oracle_note_a = (
                f"  compile={'Y' if a_compile_ok else 'N' if a_compile_ok is False else '?'}"
                + (f" verifier={'Y' if a_vpass else 'N' if a_vpass is False else '?'}" if not compile_only_oracle else "")
            )
        else:
            oracle_note_a = ""

        time.sleep(INTER_REQUEST_DELAY)

        # Condition B
        prompt_b = build_prompt(candidate, "b")
        t0 = time.monotonic()
        raw_b, parsed_b, err_b, tok_b = call_local_llm(
            client=client,
            prompt=prompt_b,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            no_think=no_think,
        )
        lat_b = round(time.monotonic() - t0, 3)
        cond_b = evaluate_response(
            candidate=candidate,
            condition="b",
            prompt=prompt_b,
            raw_response=raw_b,
            parsed_response=parsed_b,
            api_error=err_b,
            usage_output_tokens=tok_b,
            latency_seconds=lat_b,
            btf_suppressed=candidate.diagnostic_btf_misleading,
        )
        if use_oracle:
            b_compile_ok, b_vpass = run_oracle_on_fix(
                parsed_b, raw_b, candidate.verifier_log, compile_only_oracle
            )
            cond_b.oracle_compile_ok = b_compile_ok
            cond_b.oracle_verifier_pass = b_vpass
            oracle_note_b = (
                f"  compile={'Y' if b_compile_ok else 'N' if b_compile_ok is False else '?'}"
                + (f" verifier={'Y' if b_vpass else 'N' if b_vpass is False else '?'}" if not compile_only_oracle else "")
            )
        else:
            oracle_note_b = ""

        result = CaseExperimentResult(
            case_id=candidate.case_id,
            case_path=candidate.case_path,
            source=candidate.source,
            taxonomy_class=candidate.taxonomy_class,
            error_id=candidate.error_id,
            title=candidate.title,
            source_url=candidate.source_url,
            expected_fix_type=candidate.expected_fix_type,
            expected_fix_tags=candidate.expected_fix_tags,
            ground_truth_fix=candidate.ground_truth_fix,
            ground_truth_fix_source=candidate.ground_truth_fix_source,
            root_span_text=candidate.root_span_text,
            symptom_span_text=candidate.symptom_span_text,
            diagnostic_btf_misleading=candidate.diagnostic_btf_misleading,
            condition_a=cond_a,
            condition_b=cond_b,
        )
        results.append(result)

        a_ok = "MATCH" if cond_a.fix_type_match else "miss"
        b_ok = "MATCH" if cond_b.fix_type_match else "miss"
        print(
            f"    A: {a_ok} ({lat_a:.1f}s){oracle_note_a}  "
            f"B: {b_ok} ({lat_b:.1f}s){oracle_note_b}",
            flush=True,
        )

        # Intermediate save
        if idx % SAVE_EVERY == 0 or idx == total:
            agg = aggregate_results(results)
            save_results_bundle(
                path=args.results_path,
                selection_summary=selection_summary,
                selected_cases=selected_cases,
                results=results,
                aggregates=agg,
                config=config,
            )

        if idx < total:
            time.sleep(INTER_REQUEST_DELAY)

    # ── Final aggregation + report ─────────────────────────────────────────────
    aggregates = aggregate_results(results)
    save_results_bundle(
        path=args.results_path,
        selection_summary=selection_summary,
        selected_cases=selected_cases,
        results=results,
        aggregates=aggregates,
        config=config,
    )

    report = build_report(
        selected_cases=selected_cases,
        results=results,
        aggregates=aggregates,
        config=config,
        selection_summary=selection_summary,
    )
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")
    print(f"[report] Written → {args.report_path}")

    # Print summary
    a_sum = aggregates["condition_a"]
    b_sum = aggregates["condition_b"]
    mc = aggregates["mcnemar_fix_type"]
    print("\n[summary]")
    print(f"  Cases:        {a_sum['cases']}")
    print(f"  A fix-type:   {a_sum['fix_type_correct']}/{a_sum['cases']} ({a_sum['fix_type_accuracy']:.1f}%)")
    print(f"  B fix-type:   {b_sum['fix_type_correct']}/{b_sum['cases']} ({b_sum['fix_type_accuracy']:.1f}%)")
    print(f"  McNemar:      A-only={mc['a_only']}, B-only={mc['b_only']}, p={mc['p_value']:.4f}")
    for taxonomy in TAXONOMY_ORDER:
        bucket = aggregates["per_taxonomy"].get(taxonomy)
        if not bucket:
            continue
        ca = bucket["condition_a"]
        cb = bucket["condition_b"]
        print(f"  {taxonomy}: A={ca['fix_type_correct']}/{bucket['cases']}, B={cb['fix_type_correct']}/{bucket['cases']}")
    oracle_agg = aggregates.get("oracle")
    if oracle_agg:
        oa = oracle_agg.get("condition_a", {})
        ob = oracle_agg.get("condition_b", {})
        print(f"  compile_rate_A:       {oa.get('compile_rate', 0):.1f}% ({oa.get('compile_ok', 0)}/{oa.get('compile_available', 0)})")
        print(f"  compile_rate_B:       {ob.get('compile_rate', 0):.1f}% ({ob.get('compile_ok', 0)}/{ob.get('compile_available', 0)})")
        if oa.get("verifier_available", 0) > 0:
            print(f"  verifier_pass_rate_A: {oa.get('verifier_pass_rate', 0):.1f}% ({oa.get('verifier_pass', 0)}/{oa.get('verifier_available', 0)})")
            print(f"  verifier_pass_rate_B: {ob.get('verifier_pass_rate', 0):.1f}% ({ob.get('verifier_pass', 0)}/{ob.get('verifier_available', 0)})")

    cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
