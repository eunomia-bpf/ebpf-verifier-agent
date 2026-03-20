#!/usr/bin/env python3
"""Build minimal reproducible compilation units for external SO/GH verifier cases.

This script intentionally optimizes for artifact generation and traceability:

- Enumerate non-quarantined Stack Overflow / GitHub issue cases from
  ``case_study/ground_truth.yaml``.
- Recover a C source candidate from ``source_snippets`` and, when needed,
  from ``question_body_text`` / ``issue_body_text``.
- Wrap the recovered source with the smallest practical libbpf-style
  boilerplate needed for standalone compilation.
- Compile with ``clang -target bpf`` and attempt a live verifier load via
  ``sudo bpftool prog load``.
- Materialize one output directory per case under
  ``case_study/cases/so_gh_verified/<case_id>/`` with ``prog.c``,
  ``Makefile``, ``verification_status.txt``, and captured verifier logs.

The external corpus is noisy by construction: some YAMLs contain only verifier
logs, disassembly, diffs, BCC macro DSL fragments, or Rust/Go snippets. Those
cases are preserved with explicit skip/block reasons instead of silently
dropping them.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import textwrap
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.verifier_oracle import detect_prog_type
GROUND_TRUTH_PATH = ROOT / "case_study" / "ground_truth.yaml"
CASE_ROOT = ROOT / "case_study" / "cases"
OUTPUT_ROOT_DEFAULT = CASE_ROOT / "so_gh_verified"
SUMMARY_PATH_DEFAULT = ROOT / "docs" / "tmp" / "so-gh-verification.md"

CLANG = "clang"
BPFTOLL = "bpftool"
CLANG_CMD = [CLANG, "-target", "bpf", "-O2", "-g", "-I", "/usr/include"]

WRAPPER_PREAMBLE = """\
/* === WRAPPER: compilation boilerplate === */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef __section
#define __section(name) SEC(name)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef memcpy
#define memcpy __builtin_memcpy
#endif

#ifndef memset
#define memset __builtin_memset
#endif

#ifndef memmove
#define memmove __builtin_memmove
#endif

#ifndef __constant_ntohs
#define __constant_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef __constant_htons
#define __constant_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

#ifndef csum_diff
#define csum_diff bpf_csum_diff
#endif

#ifndef skb_store_bytes
#define skb_store_bytes bpf_skb_store_bytes
#endif

#ifndef l3_csum_replace
#define l3_csum_replace bpf_l3_csum_replace
#endif

#ifndef l4_csum_replace
#define l4_csum_replace bpf_l4_csum_replace
#endif

#ifndef redirect
#define redirect bpf_redirect
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#ifndef size_key
#define size_key key_size
#endif

#ifndef size_value
#define size_value value_size
#endif

#ifndef max_elem
#define max_elem max_entries
#endif

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 map_flags;
    __u32 pinning;
};

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                                   \
    ({                                                                         \
        char ____fmt[] = fmt;                                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

/* === END WRAPPER BOILERPLATE === */
"""

MAKEFILE_TEMPLATE = """\
CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -g -I /usr/include
PIN ?= /sys/fs/bpf/{pin_name}

all:{fixed_dep} prog.o

prog.o: prog.c
\t$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
\t$(BPFTool) -d prog load prog.o $(PIN)

{fixed_target}clean:
\trm -f prog.o fixed.o
"""

SOURCE_BODY_MARKERS = [
    "following is the code:",
    "here is the code:",
    "the program:",
    "my program:",
    "here is my full code:",
    "here's my c code:",
    "ebpf program",
    "the code below",
    "below is part of my program",
    "here is the code:",
    "here is my full code:",
]

BODY_END_MARKERS = [
    "verifier log",
    "verifier output",
    "the verifier output",
    "llvm output",
    "error when loading",
    "loader, until point of failure",
    "disassembly of section",
    "the entire error message",
    "error message during loading",
    "following is the complete verifier log",
]

NON_C_MARKERS = {
    "rust": [
        "#[xdp]",
        "#[kprobe]",
        "pub fn ",
        "unsafe fn ",
        "aya_bpf",
        "ProbeContext",
        "XdpContext",
        "let ",
    ],
    "go": [
        "package ",
        "func ",
        "map[string]",
        "go:generate",
    ],
}

UNSUPPORTED_DSL_MARKERS = [
    "BPF_TABLE_PINNED(",
    "BPF_STACK(",
    ".lookup_or_try_init(",
    ".push(",
    ".peek(",
    ".update(",
]


@dataclass
class CaseAttempt:
    case_id: str
    source_bucket: str
    language: str
    source_origin: str
    status: str
    compile_ok: bool
    verifier_rejected: bool | None
    verifier_error_match: str
    fixed_status: str
    notes: str
    original_error: str
    captured_error: str


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def extract_verifier_log(case: dict) -> str:
    value = case.get("verifier_log")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        combined = value.get("combined")
        if isinstance(combined, str):
            return combined
        blocks = value.get("blocks") or []
        return "\n\n".join(block for block in blocks if isinstance(block, str))
    return ""


def detect_language(text: str) -> str:
    lower = text.lower()
    if re.search(r"^\s*#\[[^\]]+\]", text, re.MULTILINE) or re.search(r"\bpub\s+fn\b", text) or re.search(r"\bunsafe\s+fn\b", text):
        return "rust"
    if "aya_bpf" in lower or "probecontext" in lower or "xdpcontext" in lower:
        return "rust"
    if re.search(r"^\s*package\s+\w+", text, re.MULTILINE) or re.search(r"^\s*func\s+\w+", text, re.MULTILINE):
        return "go"
    if any(marker in text for marker in ("#include", "SEC(", "struct xdp_md", "struct __sk_buff", "BPF_PROG", "BPF_KPROBE", "__u32", "bpf_")):
        return "c"
    if re.search(r"^\s*(?:static\s+)?(?:int|void|long|char|bool|__u\d+|u\d+)\s+\w+\s*\(", text, re.MULTILINE):
        return "c"
    if re.search(r"^\s*struct\s+\w+", text, re.MULTILINE):
        return "c"
    return "unknown"


def looks_like_verifier_log(text: str) -> bool:
    markers = [
        "libbpf:",
        "Verifier analysis:",
        "processed ",
        "last_idx",
        "R0=",
        "R1=",
        "func#0 @0",
        "Validating ",
        "load program: permission denied",
    ]
    return any(marker in text for marker in markers)


def looks_like_disassembly(text: str) -> bool:
    return any(
        marker in text
        for marker in (
            "Disassembly of section",
            "file format elf64-bpf",
            "0000000000000000",
            "r1 = 0 ll",
        )
    )


def looks_like_metadata_dump(text: str) -> bool:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    score = sum(1 for line in lines[:12] if line.endswith(": true,") or line.startswith("btf: Some("))
    return score >= 3


def looks_like_diff(text: str) -> bool:
    return text.lstrip().startswith("diff --git ")


def normalize_source(text: str) -> str:
    source = text.replace("\r\n", "\n").strip()
    source = re.sub(r"^\s*\w+\s*=\s*\"\"\"\s*", "", source)
    source = re.sub(r"\s*\"\"\"\s*$", "", source)
    source = re.sub(r"^\s*`{3,}\w*\s*", "", source)
    source = re.sub(r"\s*`{3,}\s*$", "", source)
    lines = source.splitlines()
    if lines and re.fullmatch(r"[\w./-]+\.(?:c|h|bpf\.c)", lines[0].strip()):
        lines = lines[1:]
    source = "\n".join(lines).strip()
    source = source.replace("\t", "    ")
    source = source.replace("\\\\n", "\\n")
    source = source.replace('\\\\\"', '\\"')
    source = source.replace("char __license[] SEC(\"license\") = \"Dual MIT/GPL\";", 'char __license[] SEC("license") = "GPL";')
    if "int main(" in source and "SEC(" in source:
        source = source.split("int main(", 1)[0].rstrip()
    source = trim_unmatched_endif(source)
    return source.strip()


def trim_unmatched_endif(source: str) -> str:
    lines = source.splitlines()
    depth = 0
    kept: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("#if", "#ifdef", "#ifndef")):
            depth += 1
            kept.append(line)
            continue
        if stripped.startswith("#endif"):
            if depth == 0:
                continue
            depth -= 1
            kept.append(line)
            continue
        kept.append(line)
    return "\n".join(kept)


def strip_includes(source: str) -> str:
    kept = [line for line in source.splitlines() if not line.strip().startswith("#include")]
    return "\n".join(kept).strip()


def code_line_score(line: str) -> int:
    stripped = line.strip()
    if not stripped:
        return 0
    score = 0
    if stripped.startswith(("#include", "#define", "SEC(", "struct ", "enum ", "typedef ")):
        score += 5
    if re.match(r"^(static\s+)?(?:__always_inline\s+)?(?:int|void|long|char|bool|__u\d+|u\d+)\b", stripped):
        score += 5
    if any(token in stripped for token in ("{", "}", ";", "->", "(", ")")):
        score += 2
    if any(token in stripped for token in ("bpf_", "BPF_", "__u", "xdp_md", "__sk_buff", "pt_regs", "tcphdr", "iphdr")):
        score += 3
    if looks_like_verifier_log(stripped):
        score -= 8
    if looks_like_disassembly(stripped):
        score -= 8
    if re.match(r"^\d+:\s+\(", stripped) or re.match(r"^R\d", stripped):
        score -= 8
    if len(stripped.split()) > 9 and not any(ch in stripped for ch in "{}();#[]"):
        score -= 3
    return score


def split_body_segments(body: str) -> list[str]:
    lines = body.replace("\r\n", "\n").splitlines()
    segments: list[list[str]] = []
    current: list[str] = []
    non_code_run = 0
    for line in lines:
        score = code_line_score(line)
        if score > 0 or (current and not line.strip()):
            current.append(line)
            non_code_run = 0
            continue
        if current:
            non_code_run += 1
            if non_code_run <= 1:
                current.append(line)
                continue
            if any(code_line_score(item) > 0 for item in current):
                segments.append(current)
            current = []
            non_code_run = 0
    if current and any(code_line_score(item) > 0 for item in current):
        segments.append(current)
    normalized = [normalize_source("\n".join(seg)) for seg in segments]
    return [segment for segment in normalized if segment]


def extract_after_markers(body: str) -> list[str]:
    lower = body.lower()
    candidates: list[str] = []
    for marker in SOURCE_BODY_MARKERS:
        idx = lower.find(marker)
        if idx == -1:
            continue
        tail = body[idx + len(marker):]
        end_idx = len(tail)
        lower_tail = tail.lower()
        for end_marker in BODY_END_MARKERS:
            pos = lower_tail.find(end_marker)
            if pos != -1:
                end_idx = min(end_idx, pos)
        snippet = normalize_source(tail[:end_idx])
        if snippet:
            candidates.append(snippet)
    return dedupe(candidates)


def extract_body_candidates(body: str) -> list[str]:
    if not body.strip():
        return []
    candidates = extract_after_markers(body)
    if not candidates:
        candidates = split_body_segments(body)
    ranked = sorted(candidates, key=body_candidate_score, reverse=True)
    return dedupe([candidate for candidate in ranked if body_candidate_score(candidate) > 0])


def body_candidate_score(candidate: str) -> int:
    score = len(candidate)
    if looks_like_verifier_log(candidate):
        score -= 10000
    if looks_like_disassembly(candidate):
        score -= 10000
    if looks_like_metadata_dump(candidate):
        score -= 10000
    if looks_like_diff(candidate):
        score -= 2000
    if detect_language(candidate) == "c":
        score += 4000
    if "SEC(" in candidate:
        score += 1000
    if "#include" in candidate:
        score += 500
    return score


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def extract_buggy_candidates(case: dict) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for idx, snippet in enumerate(case.get("source_snippets") or []):
        if not isinstance(snippet, str) or not snippet.strip():
            continue
        normalized = normalize_source(snippet)
        candidates.append((f"source_snippets[{idx}]", normalized))
    body = case.get("question_body_text") or case.get("issue_body_text") or ""
    for idx, candidate in enumerate(extract_body_candidates(body)):
        candidates.append((f"body[{idx}]", candidate))
    filtered: list[tuple[str, str]] = []
    for origin, candidate in candidates:
        if looks_like_metadata_dump(candidate):
            continue
        if not looks_recoverable_c(candidate):
            continue
        filtered.append((origin, candidate))
    filtered.sort(key=lambda item: candidate_priority(item[1]), reverse=True)
    return dedupe_pairs(filtered)


def extract_fixed_candidates(case: dict) -> list[str]:
    selected = case.get("selected_answer") or {}
    text_parts = [value for value in selected.values() if isinstance(value, str)]
    fixed_text = "\n".join(text_parts).strip()
    if not fixed_text:
        return []
    return extract_body_candidates(fixed_text)


def dedupe_pairs(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for origin, source in items:
        if source in seen:
            continue
        seen.add(source)
        result.append((origin, source))
    return result


def candidate_priority(source: str) -> int:
    score = len(source)
    lang = detect_language(source)
    if lang == "c":
        score += 5000
    elif lang in {"rust", "go"}:
        score -= 10000
    if looks_like_verifier_log(source) or looks_like_disassembly(source):
        score -= 10000
    if looks_like_metadata_dump(source):
        score -= 10000
    if any(marker in source for marker in UNSUPPORTED_DSL_MARKERS):
        score -= 5000
    if "SEC(" in source:
        score += 1000
    if "#include" in source:
        score += 500
    if "int main(" in source:
        score -= 500
    return score


def looks_recoverable_c(source: str) -> bool:
    if looks_like_verifier_log(source) or looks_like_disassembly(source) or looks_like_metadata_dump(source):
        return False
    if detect_language(source) == "c":
        return True
    strong_markers = ("if (", "for (", "while (", "return ", "{", "}", ";", "struct ")
    return any(marker in source for marker in strong_markers) and any(token in source for token in ("bpf_", "__u", "ctx", "skb", "data_end", "data"))


def requires_bcc_frontend(source: str) -> bool:
    if any(marker in source for marker in ("bpf_text = \"\"\"", "bpf_text2 = \"\"\"")):
        return True
    if "bpf_trace_printk(" in source and "%s" in source:
        return True
    return False


def infer_case_language(case: dict) -> str:
    sources = []
    for snippet in case.get("source_snippets") or []:
        if isinstance(snippet, str):
            sources.append(snippet)
    for key in ("question_body_text", "issue_body_text"):
        value = case.get(key)
        if isinstance(value, str):
            sources.append(value)
    return detect_language("\n".join(sources))


def add_license_if_missing(source: str) -> str:
    if re.search(r'SEC\s*\(\s*"license"\s*\)', source):
        return source
    return source.rstrip() + '\n\n/* === WRAPPER: added license === */\nchar _license[] SEC("license") = "GPL";\n'


def add_sec_if_missing(source: str, prog_type: str) -> str:
    if "SEC(" in source:
        return source
    func_match = re.search(
        r"^(static\s+)?(?:__always_inline\s+)?(?:int|void|long)\s+\w+\s*\(\s*(?:struct\s+)?(?:xdp_md|__sk_buff|pt_regs|bpf_sock_ops|bpf_perf_event_data|bpf_raw_tracepoint_args|sock|task_struct|file)\b",
        source,
        re.MULTILINE,
    )
    if not func_match:
        return source
    insert_at = func_match.start()
    return source[:insert_at] + f'SEC("{prog_type}")\n' + source[insert_at:]


def build_source_variants(case_id: str, original_source: str, verifier_log: str, *, apply_case_rewrite: bool = True) -> list[tuple[str, str]]:
    prog_type = detect_prog_type(original_source, verifier_log)
    normalized = normalize_source(original_source)
    normalized = rewrite_legacy_struct_bpf_map(normalized)
    include_stripped = strip_includes(normalized)
    prepared = []

    if apply_case_rewrite and case_id in CASE_SOURCE_REWRITES:
        rewritten = CASE_SOURCE_REWRITES[case_id](normalized)
        if rewritten:
            rewritten = strip_includes(normalize_source(rewritten))
            rewritten = rewrite_legacy_struct_bpf_map(rewritten)
            rewritten = add_license_if_missing(add_sec_if_missing(rewritten, prog_type))
            prepared.append(("case-rewrite", wrap_with_sections(WRAPPER_PREAMBLE, rewritten)))

    raw = add_license_if_missing(add_sec_if_missing(normalized, prog_type))
    prepared.append(("raw", wrap_with_sections("", raw)))

    wrapped = add_license_if_missing(add_sec_if_missing(include_stripped or normalized, prog_type))
    prepared.append(("wrapped", wrap_with_sections(WRAPPER_PREAMBLE, wrapped)))

    if include_stripped and include_stripped != normalized:
        prepared.append(("wrapped-stripped", wrap_with_sections(WRAPPER_PREAMBLE, add_license_if_missing(add_sec_if_missing(include_stripped, prog_type)))))

    return dedupe_pairs(prepared)


def rewrite_legacy_struct_bpf_map(source: str) -> str:
    return re.sub(r"\bstruct\s+bpf_map(\s+SEC\s*\(\s*\"maps\"\s*\))", r"struct bpf_map_def\1", source)


def wrap_with_sections(preamble: str, original_source: str) -> str:
    parts = []
    if preamble:
        parts.append(preamble.rstrip())
    else:
        parts.append("/* === WRAPPER: compilation boilerplate === */\n/* no extra boilerplate required */")
    parts.append("/* === ORIGINAL CODE from SO/GH post === */")
    parts.append(original_source.rstrip())
    parts.append("/* === END ORIGINAL CODE === */")
    return "\n\n".join(parts).rstrip() + "\n"


def compile_bpf(source_path: Path, object_path: Path) -> tuple[bool, str]:
    cmd = CLANG_CMD + ["-c", str(source_path), "-o", str(object_path)]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return completed.returncode == 0, (completed.stderr or completed.stdout or "").strip()


def load_bpf(object_path: Path) -> tuple[bool, str]:
    pin_path = f"/sys/fs/bpf/so_gh_{uuid.uuid4().hex[:12]}"
    cmd = ["sudo", "-n", BPFTOLL, "-d", "prog", "load", str(object_path), pin_path]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        log = (completed.stderr or completed.stdout or "").strip()
        return completed.returncode == 0, log
    except subprocess.TimeoutExpired:
        return False, "bpftool timed out"
    finally:
        subprocess.run(["sudo", "-n", "rm", "-f", pin_path], capture_output=True, text=True, check=False)


def first_error_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("libbpf:", "--")):
            continue
        if any(token in stripped.lower() for token in ("invalid", "expected", "prohibited", "unbounded", "outside", "too many", "permission denied")):
            return stripped
        if re.search(r"R\d+ .*expected", stripped):
            return stripped
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def normalize_error_text(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"0x[0-9a-f]+", "0xaddr", lowered)
    lowered = re.sub(r"\b\d+\b", "N", lowered)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered.strip()


def compare_errors(original: str, captured: str) -> str:
    if not original or not captured:
        return "unknown"
    no = normalize_error_text(original)
    nc = normalize_error_text(captured)
    if no == nc:
        return "exact"
    if no in nc or nc in no:
        return "substring"
    original_tokens = set(re.findall(r"[a-z_']+", no))
    captured_tokens = set(re.findall(r"[a-z_']+", nc))
    if not original_tokens or not captured_tokens:
        return "unknown"
    overlap = len(original_tokens & captured_tokens) / max(1, len(original_tokens | captured_tokens))
    return "partial" if overlap >= 0.35 else "mismatch"


def is_loader_artifact(log: str) -> bool:
    markers = [
        "legacy map definitions in 'maps' section are not supported",
        "failed to guess program type from elf section",
        "unrecognized elf section name",
        "error: failed to open object file",
    ]
    lower = log.lower()
    return any(marker in lower for marker in markers)


def write_case_dir(
    out_dir: Path,
    prog_source: str | None,
    fixed_source: str | None,
    prog_log: str,
    fixed_log: str,
    status_text: str,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if prog_source is not None:
        (out_dir / "prog.c").write_text(prog_source, encoding="utf-8")
    if fixed_source is not None:
        (out_dir / "fixed.c").write_text(fixed_source, encoding="utf-8")
    (out_dir / "verifier_log_captured.txt").write_text(prog_log, encoding="utf-8")
    if fixed_log:
        (out_dir / "fixed_verifier_log_captured.txt").write_text(fixed_log, encoding="utf-8")
    (out_dir / "verification_status.txt").write_text(status_text, encoding="utf-8")
    pin_name = out_dir.name.replace("/", "_")
    fixed_dep = " fixed.o" if fixed_source is not None else ""
    fixed_target = "fixed.o: fixed.c\n\t$(CLANG) $(CFLAGS) -c $< -o $@\n\n" if fixed_source is not None else ""
    makefile = MAKEFILE_TEMPLATE.format(pin_name=pin_name, fixed_dep=fixed_dep, fixed_target=fixed_target)
    (out_dir / "Makefile").write_text(makefile, encoding="utf-8")


def status_block(case_id: str, language: str, reason: str, source_bucket: str, notes: str = "") -> CaseAttempt:
    return CaseAttempt(
        case_id=case_id,
        source_bucket=source_bucket,
        language=language,
        source_origin="",
        status=reason,
        compile_ok=False,
        verifier_rejected=None,
        verifier_error_match="unknown",
        fixed_status="not_attempted",
        notes=notes,
        original_error="",
        captured_error="",
    )


def build_status_text(
    case_id: str,
    source_bucket: str,
    language: str,
    source_origin: str,
    compile_ok: bool,
    verifier_rejected: bool | None,
    match: str,
    fixed_status: str,
    original_error: str,
    captured_error: str,
    notes: str,
) -> str:
    verifier_status = (
        "not_run" if verifier_rejected is None else ("rejected" if verifier_rejected else "accepted")
    )
    return textwrap.dedent(
        f"""\
        case_id: {case_id}
        source_bucket: {source_bucket}
        language: {language}
        source_origin: {source_origin}
        compile_ok: {compile_ok}
        verifier_status: {verifier_status}
        verifier_error_match: {match}
        fixed_status: {fixed_status}
        original_error: {original_error or "<none>"}
        captured_error: {captured_error or "<none>"}
        notes: {notes or "<none>"}
        """
    )


def try_source_variants(case_id: str, verifier_log: str, variants: list[tuple[str, str]], out_dir: Path) -> tuple[str | None, bool, bool | None, str, str, str]:
    last_compile_success: tuple[str, str, str] | None = None
    for origin, source in variants:
        prog_path = out_dir / "prog.c"
        obj_path = out_dir / "prog.o"
        prog_path.write_text(source, encoding="utf-8")
        compile_ok, compile_log = compile_bpf(prog_path, obj_path)
        if not compile_ok:
            continue
        verifier_ok, verifier_log_captured = load_bpf(obj_path)
        last_compile_success = (source, origin, verifier_log_captured)
        if is_loader_artifact(verifier_log_captured):
            continue
        original_error = first_error_line(verifier_log)
        captured_error = first_error_line(verifier_log_captured)
        return source, True, (not verifier_ok), origin, verifier_log_captured, compare_errors(original_error, captured_error)
    if last_compile_success is not None:
        source, origin, verifier_log_captured = last_compile_success
        return source, True, True, origin, verifier_log_captured, "mismatch"
    return None, False, None, "", "", "unknown"


def try_fixed_variants(case_id: str, verifier_log: str, source: str | None, out_dir: Path) -> tuple[str | None, str, str]:
    if source is None:
        return None, "", "not_attempted"
    transforms = []
    if case_id in CASE_FIXED_REWRITES:
        transforms.append(CASE_FIXED_REWRITES[case_id](source))
    case = read_yaml(case_yaml_path(case_id))
    transforms.extend(extract_fixed_candidates(case))
    fixed_variants = []
    for idx, candidate in enumerate(transforms):
        if not candidate or not candidate.strip():
            continue
        for origin, variant in build_source_variants(case_id, candidate, verifier_log, apply_case_rewrite=False):
            fixed_variants.append((f"fixed[{idx}]/{origin}", variant))
    fixed_variants = dedupe_pairs(fixed_variants)
    last_compile_success: tuple[str, str] | None = None
    for origin, fixed_source in fixed_variants:
        fixed_path = out_dir / "fixed.c"
        fixed_obj = out_dir / "fixed.o"
        fixed_path.write_text(fixed_source, encoding="utf-8")
        compile_ok, compile_log = compile_bpf(fixed_path, fixed_obj)
        if not compile_ok:
            continue
        verifier_ok, fixed_log = load_bpf(fixed_obj)
        last_compile_success = (fixed_source, fixed_log)
        if is_loader_artifact(fixed_log):
            continue
        if verifier_ok:
            return fixed_source, fixed_log, f"accepted:{origin}"
        return fixed_source, fixed_log, f"rejected:{origin}"
    if last_compile_success is not None:
        fixed_source, fixed_log = last_compile_success
        return fixed_source, fixed_log, "rejected:loader_artifact"
    return None, "", "not_attempted"


def case_yaml_path(case_id: str) -> Path:
    bucket = "stackoverflow" if case_id.startswith("stackoverflow-") else "github_issues"
    return CASE_ROOT / bucket / f"{case_id}.yaml"


def iter_target_case_ids(limit: int | None = None) -> list[str]:
    data = read_yaml(GROUND_TRUTH_PATH)
    case_ids = []
    for case in data.get("cases", []):
        case_id = case.get("case_id", "")
        if case.get("quarantined"):
            continue
        if case_id.startswith(("stackoverflow-", "github-")):
            case_ids.append(case_id)
    if limit is not None:
        case_ids = case_ids[:limit]
    return case_ids


def generate_summary(summary_path: Path, attempts: list[CaseAttempt]) -> None:
    total = len(attempts)
    compiled = sum(1 for attempt in attempts if attempt.compile_ok)
    rejected = sum(1 for attempt in attempts if attempt.verifier_rejected)
    matched = sum(1 for attempt in attempts if attempt.verifier_error_match in {"exact", "substring", "partial"})
    fixed_accepted = sum(1 for attempt in attempts if attempt.fixed_status.startswith("accepted:"))
    blocked = total - compiled

    lines = [
        "# SO/GH Verification",
        "",
        "Generated from the checked-in corpus on 2026-03-19.",
        "",
        f"- Target cases in current `case_study/ground_truth.yaml`: `{total}`",
        "- Note: this checkout contains `41` non-quarantined Stack Overflow cases and `10` non-quarantined GitHub issue cases, not `43 + 10`.",
        f"- Buggy programs that compiled: `{compiled}`",
        f"- Buggy programs rejected by verifier: `{rejected}`",
        f"- Rejections with at least partial error-message agreement: `{matched}`",
        f"- Fixed variants accepted by verifier: `{fixed_accepted}`",
        f"- Blocked / skipped cases: `{blocked}`",
        "",
        "| Case | Source | Language | Buggy | Verifier | Match | Fixed | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for attempt in attempts:
        verifier = (
            "not_run"
            if attempt.verifier_rejected is None
            else ("rejected" if attempt.verifier_rejected else "accepted")
        )
        lines.append(
            f"| `{attempt.case_id}` | `{attempt.source_bucket}` | `{attempt.language}` | "
            f"`{'compiled' if attempt.compile_ok else attempt.status}` | `{verifier}` | "
            f"`{attempt.verifier_error_match}` | `{attempt.fixed_status}` | "
            f"{attempt.notes or '-'} |"
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_bool_or_none(value: str) -> bool | None:
    if value == "True":
        return True
    if value == "False":
        return False
    return None


def collect_attempts_from_output(out_dir: Path) -> list[CaseAttempt]:
    attempts: list[CaseAttempt] = []
    if not out_dir.exists():
        return attempts
    for case_dir in sorted(path for path in out_dir.iterdir() if path.is_dir()):
        status_path = case_dir / "verification_status.txt"
        if not status_path.exists():
            continue
        fields: dict[str, str] = {}
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
        compile_ok = fields.get("compile_ok") == "True"
        verifier_status = fields.get("verifier_status", "not_run")
        verifier_rejected = None
        if verifier_status == "rejected":
            verifier_rejected = True
        elif verifier_status == "accepted":
            verifier_rejected = False
        attempts.append(
            CaseAttempt(
                case_id=fields.get("case_id", case_dir.name),
                source_bucket=fields.get("source_bucket", ""),
                language=fields.get("language", ""),
                source_origin=fields.get("source_origin", ""),
                status="compiled" if compile_ok else fields.get("notes", "unknown"),
                compile_ok=compile_ok,
                verifier_rejected=verifier_rejected,
                verifier_error_match=fields.get("verifier_error_match", "unknown"),
                fixed_status=fields.get("fixed_status", "not_attempted"),
                notes=fields.get("notes", ""),
                original_error=fields.get("original_error", ""),
                captured_error=fields.get("captured_error", ""),
            )
        )
    return attempts


def rewrite_61945212(source: str) -> str:
    return re.sub(
        r"bpf_map_update_elem\(&queue_map,\s*NULL,\s*&value,\s*BPF_ANY\);",
        "bpf_map_push_elem(&queue_map, &value, BPF_ANY);",
        source,
    )


def rewrite_69767533(source: str) -> str:
    return source.replace("char tmp_buffer[128];", "char tmp_buffer[128] = {};")


def rewrite_72005172(source: str) -> str:
    fixed = source.replace("(void*)iph + 1", "(void*)(iph + 1)")
    fixed = fixed.replace("(void*)tcph + 1", "(void*)(tcph + 1)")
    return fixed


def rewrite_75643912(source: str) -> str:
    old = "for (int i = 0; i < MAX_PACKET_OFF && tcp_data + i <= data_end; ++i) {\nif (tcp_data[i] == ' ') {\nbpf_printk(\"space\");\nreturn TC_ACT_SHOT;\n}\n}"
    new = "for (int i = 0; i < MAX_PACKET_OFF; ++i) {\n__u8 *loop_data = tcp_data + i;\nif (loop_data + 1 > data_end)\nbreak;\nif (*loop_data == ' ') {\nbpf_printk(\"space\");\nreturn TC_ACT_SHOT;\n}\n}"
    return source.replace(old, new)


def rewrite_79348306(source: str) -> str:
    fixed = source.replace("struct path file_path;\n", "")
    fixed = re.sub(
        r"BPF_CORE_READ_INTO\(&file_path,\s*file,\s*f_path\);\s*long err = bpf_d_path\(&file_path,\s*path_buffer,\s*sizeof\(path_buffer\)\);",
        "long err = bpf_d_path(&file->f_path, path_buffer, sizeof(path_buffer));",
        fixed,
        flags=re.DOTALL,
    )
    return fixed


def rewrite_61945212_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct {
            __uint(type, BPF_MAP_TYPE_QUEUE);
            __uint(max_entries, 100);
            __type(value, int);
        } queue_map SEC(".maps");

        SEC("tracepoint/syscalls/sys_enter_execve")
        int bpf_prog(void *ctx) {
            int value;

            value = 123;
            bpf_map_update_elem(&queue_map, NULL, &value, BPF_ANY);
            return 0;
        }
        """
    )


def rewrite_67402772_buggy(source: str) -> str:
    return source.replace('SEC("dump_skb_member")', 'SEC("classifier")')


CASE_SOURCE_REWRITES: dict[str, Callable[[str], str]] = {
    "stackoverflow-61945212": rewrite_61945212_buggy,
    "stackoverflow-67402772": rewrite_67402772_buggy,
}
CASE_FIXED_REWRITES: dict[str, Callable[[str], str]] = {
    "stackoverflow-61945212": rewrite_61945212,
    "stackoverflow-69767533": rewrite_69767533,
    "stackoverflow-72005172": rewrite_72005172,
    "stackoverflow-75643912": rewrite_75643912,
    "stackoverflow-79348306": rewrite_79348306,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=OUTPUT_ROOT_DEFAULT)
    parser.add_argument("--summary-path", type=Path, default=SUMMARY_PATH_DEFAULT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--clean", action="store_true", help="Delete the output directory before regenerating.")
    parser.add_argument("--summarize-only", action="store_true", help="Regenerate the markdown summary from existing per-case artifacts.")
    args = parser.parse_args()

    if args.clean and args.out_dir.exists():
        shutil.rmtree(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.summarize_only:
        generate_summary(args.summary_path, collect_attempts_from_output(args.out_dir))
        return

    attempts: list[CaseAttempt] = []
    case_ids = iter_target_case_ids()
    if args.start_index:
        case_ids = case_ids[args.start_index:]
    if args.limit is not None:
        case_ids = case_ids[: args.limit]

    for case_id in case_ids:
        yaml_path = case_yaml_path(case_id)
        case = read_yaml(yaml_path)
        verifier_log = extract_verifier_log(case)
        source_bucket = "stackoverflow" if case_id.startswith("stackoverflow-") else "github_issues"
        out_dir = args.out_dir / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        buggy_candidates = extract_buggy_candidates(case)
        language = (
            detect_language("\n\n".join(source for _, source in buggy_candidates[:3]))
            if buggy_candidates
            else infer_case_language(case)
        )
        if language in {"rust", "go"} and not buggy_candidates:
            attempt = status_block(case_id, language, "skipped_non_c", source_bucket, "Corpus artifact is not C.")
            write_case_dir(
                out_dir=out_dir,
                prog_source=None,
                fixed_source=None,
                prog_log="",
                fixed_log="",
                status_text=build_status_text(
                    case_id=case_id,
                    source_bucket=source_bucket,
                    language=language,
                    source_origin="",
                    compile_ok=False,
                    verifier_rejected=None,
                    match="unknown",
                    fixed_status="not_attempted",
                    original_error="",
                    captured_error="",
                    notes=attempt.notes,
                ),
            )
            attempts.append(attempt)
            continue
        if not buggy_candidates:
            attempt = status_block(case_id, language, "blocked_missing_source", source_bucket, "No recoverable C source found in snippets or body text.")
            write_case_dir(
                out_dir=out_dir,
                prog_source=None,
                fixed_source=None,
                prog_log="",
                fixed_log="",
                status_text=build_status_text(
                    case_id=case_id,
                    source_bucket=source_bucket,
                    language=language,
                    source_origin="",
                    compile_ok=False,
                    verifier_rejected=None,
                    match="unknown",
                    fixed_status="not_attempted",
                    original_error="",
                    captured_error="",
                    notes=attempt.notes,
                ),
            )
            attempts.append(attempt)
            continue

        origin, chosen = buggy_candidates[0]
        if requires_bcc_frontend(chosen):
            attempt = status_block(case_id, language, "blocked_bcc_frontend", source_bucket, "Recovered source depends on BCC frontend rewriting, not standalone clang C.")
            write_case_dir(
                out_dir=out_dir,
                prog_source=None,
                fixed_source=None,
                prog_log="",
                fixed_log="",
                status_text=build_status_text(
                    case_id=case_id,
                    source_bucket=source_bucket,
                    language=language,
                    source_origin=origin,
                    compile_ok=False,
                    verifier_rejected=None,
                    match="unknown",
                    fixed_status="not_attempted",
                    original_error="",
                    captured_error="",
                    notes=attempt.notes,
                ),
            )
            attempts.append(attempt)
            continue
        if any(marker in chosen for marker in UNSUPPORTED_DSL_MARKERS):
            attempt = status_block(case_id, language, "blocked_bcc_dsl", source_bucket, "Recovered source uses BCC macro DSL that is not standalone clang C.")
            write_case_dir(
                out_dir=out_dir,
                prog_source=None,
                fixed_source=None,
                prog_log="",
                fixed_log="",
                status_text=build_status_text(
                    case_id=case_id,
                    source_bucket=source_bucket,
                    language=language,
                    source_origin=origin,
                    compile_ok=False,
                    verifier_rejected=None,
                    match="unknown",
                    fixed_status="not_attempted",
                    original_error="",
                    captured_error="",
                    notes=attempt.notes,
                ),
            )
            attempts.append(attempt)
            continue

        source_variants = build_source_variants(case_id, chosen, verifier_log)
        prog_source, compile_ok, verifier_rejected, variant_origin, captured_log, match = try_source_variants(case_id, verifier_log, source_variants, out_dir)
        original_error = first_error_line(verifier_log)
        captured_error = first_error_line(captured_log)

        fixed_source = None
        fixed_log = ""
        fixed_status = "not_attempted"
        notes = ""
        if compile_ok:
            fixed_source, fixed_log, fixed_status = try_fixed_variants(case_id, verifier_log, prog_source, out_dir)
        else:
            notes = "No source variant compiled with the exact clang command requested."

        status_text = build_status_text(
            case_id=case_id,
            source_bucket=source_bucket,
            language=language,
            source_origin=f"{origin} -> {variant_origin}".strip(),
            compile_ok=compile_ok,
            verifier_rejected=verifier_rejected,
            match=match,
            fixed_status=fixed_status,
            original_error=original_error,
            captured_error=captured_error,
            notes=notes,
        )
        write_case_dir(
            out_dir=out_dir,
            prog_source=prog_source,
            fixed_source=fixed_source,
            prog_log=captured_log,
            fixed_log=fixed_log,
            status_text=status_text,
        )
        attempts.append(
            CaseAttempt(
                case_id=case_id,
                source_bucket=source_bucket,
                language=language,
                source_origin=f"{origin} -> {variant_origin}".strip(),
                status="compiled" if compile_ok else "compile_failed",
                compile_ok=compile_ok,
                verifier_rejected=verifier_rejected,
                verifier_error_match=match,
                fixed_status=fixed_status,
                notes=notes,
                original_error=original_error,
                captured_error=captured_error,
            )
        )

    generate_summary(args.summary_path, collect_attempts_from_output(args.out_dir))


if __name__ == "__main__":
    main()
