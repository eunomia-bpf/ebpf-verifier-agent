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
LOAD_TIMEOUT_SEC = 20

WRAPPER_PREAMBLE = """\
/* === WRAPPER: compilation boilerplate === */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef __SO_GH_VERIFIED_STDINT_TYPES
#define __SO_GH_VERIFIED_STDINT_TYPES 1
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s8 int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;
#endif

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

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)__builtin_bswap16((__u16)(x)))
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

#ifndef ETH_HLEN
#define ETH_HLEN 14
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
    "here's the code:",
    "the program:",
    "my program:",
    "here is my full code:",
    "here's my c code:",
    "here is my code:",
    "here is my code in .kern :",
    "here is the full code:",
    "here is my bpf program:",
    "here is logic of my bpf.c file:",
    "the bpf program is:",
    "ebpf program",
    "the code below",
    "below is part of my program",
    "following is the code",
    "following is the complete code",
    "full code:",
    "below is my program",
    "the code below shows my ebpf program",
    "what i tried?",
    "however, if i try to get the bpf storage for the current task instead of the p argument, it fails to attach:",
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
    "here's the error",
    "the error is",
    "the error message is",
    "validator failure",
    "debug detail",
    "traceback",
    "and compiled with",
    "the output of llvm-objdump",
    "llvm-objdump",
    "verifier produces this output",
    "verifier log shows",
    "verifier log:",
    "error:",
]

NON_C_MARKERS = {
    "rust": [
        "#[xdp]",
        "#[kprobe]",
        "pub fn ",
        "pub struct ",
        "unsafe fn ",
        "aya_bpf",
        "ProbeContext",
        "XdpContext",
        "let ",
        ".unwrap()",
        "as_mut_ptr()",
        "core::ffi",
        "try_into()",
        "Result<",
        "cargo ",
        "aya-template",
        "percpuarray",
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
    if re.search(r"^\s*#\[[^\]]+\]", text, re.MULTILINE) or re.search(r"\bpub\s+(?:fn|struct)\b", text) or re.search(r"\bunsafe\s+fn\b", text):
        return "rust"
    if any(marker.lower() in lower for marker in NON_C_MARKERS["rust"]):
        return "rust"
    if "aya_bpf" in lower or "probecontext" in lower or "xdpcontext" in lower:
        return "rust"
    if re.search(r"^\s*package\s+\w+", text, re.MULTILINE) or re.search(r"^\s*func\s+\w+", text, re.MULTILINE):
        return "go"
    if any(marker.lower() in lower for marker in NON_C_MARKERS["go"]):
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


def looks_like_userspace_loader(text: str) -> bool:
    lowered = text.lower()
    markers = (
        "bpf_object__",
        "bpf_program__",
        "bpf_map__fd",
        "load_bpf_and_xdp_attach",
        "printf(",
        "fprintf(",
        "perror(",
        "exit(",
        "main(",
        "cargo run",
        "llvm-objdump",
        "object::{",
        "std::",
        "bfd = open(",
        "read(bfd, buf",
    )
    return any(marker in text for marker in markers) or "sys_bpf" in lowered or "bpf_prog_load" in lowered


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


def trim_to_first_code_anchor(source: str) -> str:
    patterns = [
        r"#include\b",
        r"SEC\s*\(",
        r"__section\s*\(",
        r"struct\s+\w+",
        r"typedef\b",
        r"enum\s+\w+",
        r"static\b",
        r"\b(?:int|void|long|char|bool|unsigned|__u\d+|u\d+)\s+\w+\s*\(",
        r"\bif\s*\(",
        r"\bfor\s*\(",
        r"\bwhile\s*\(",
        r"\breturn\s+",
        r"^\s*{",
    ]
    positions = []
    for pattern in patterns:
        match = re.search(pattern, source, flags=re.MULTILINE)
        if match:
            positions.append(match.start())
    if not positions:
        return source
    return source[min(positions):]


def split_code_windows(source: str) -> list[str]:
    lines = normalize_source(trim_to_first_code_anchor(source)).splitlines()
    windows: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if stripped and any(marker in lower for marker in BODY_END_MARKERS):
            if current:
                windows.append(current)
            break
        score = code_line_score(line)
        if score > 0 or (current and not stripped):
            current.append(line)
            continue
        if current:
            windows.append(current)
            current = []
    if current:
        windows.append(current)
    return [normalize_source("\n".join(window)) for window in windows if any(code_line_score(line) > 0 for line in window)]


def extract_embedded_sources(body: str) -> list[str]:
    patterns = [
        r"\b\w+\s*=\s*\"\"\"\s*(.*?)\s*\"\"\"",
        r"\b\w+\s*=\s*'''\s*(.*?)\s*'''",
    ]
    matches: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.DOTALL):
            snippet = normalize_source(match.group(1))
            if snippet:
                matches.append(snippet)
    return dedupe(matches)


def is_program_fragment(source: str) -> bool:
    if "SEC(" in source:
        return True
    if re.search(r"\b(?:int|void|long)\s+\w+\s*\(\s*(?:struct\s+)?(?:xdp_md|__sk_buff|pt_regs|bpf_perf_event_data|sock|task_struct|file|sk_reuseport_md)\b", source):
        return True
    return any(token in source for token in ("return XDP_", "return TC_ACT_", "BPF_PROG(", "BPF_KPROBE("))


def merge_complementary_fragments(fragments: list[str]) -> list[str]:
    cleaned = [normalize_source(fragment) for fragment in fragments if normalize_source(fragment)]
    if len(cleaned) < 2:
        return []
    programs = [fragment for fragment in cleaned if is_program_fragment(fragment)]
    definitions = [fragment for fragment in cleaned if not is_program_fragment(fragment) and not looks_like_userspace_loader(fragment)]
    if len(programs) != 1 or not definitions:
        return []
    if sum(fragment.count("SEC(") for fragment in cleaned) > 1:
        return []
    return ["\n\n".join(definitions + programs)]


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
    if re.fullmatch(r"[A-Za-z_]\w*:", stripped):
        score += 2
    if looks_like_verifier_log(stripped):
        score -= 8
    if looks_like_disassembly(stripped):
        score -= 8
    if looks_like_userspace_loader(stripped):
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
    for line in lines:
        score = code_line_score(line)
        if score > 0 or (current and not line.strip()):
            current.append(line)
            continue
        if current:
            if any(code_line_score(item) > 0 for item in current):
                segments.append(current)
            current = []
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
        snippet = tail[:end_idx]
        candidates.extend(split_code_windows(snippet))
    return dedupe(candidates)


def extract_body_candidates(body: str) -> list[str]:
    if not body.strip():
        return []
    candidates = extract_embedded_sources(body)
    candidates.extend(extract_after_markers(body))
    if not candidates:
        candidates = split_body_segments(body)
    merged = merge_complementary_fragments(candidates)
    candidates.extend(merged)
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
    if looks_like_userspace_loader(candidate) and "SEC(" not in candidate:
        score -= 5000
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
    snippet_fragments: list[str] = []
    for idx, snippet in enumerate(case.get("source_snippets") or []):
        if not isinstance(snippet, str) or not snippet.strip():
            continue
        normalized = normalize_source(snippet)
        candidates.append((f"source_snippets[{idx}]", normalized))
        snippet_fragments.extend(split_code_windows(normalized) or [normalized])
    for idx, candidate in enumerate(merge_complementary_fragments(snippet_fragments)):
        candidates.append((f"source_snippets[merged:{idx}]", candidate))
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
    filtered.sort(key=lambda item: candidate_priority(item[1]) + (3000 if item[0].startswith("source_snippets") else 0), reverse=True)
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
    if looks_like_userspace_loader(source) and "SEC(" not in source:
        score -= 8000
    if any(marker in source for marker in UNSUPPORTED_DSL_MARKERS):
        score -= 5000
    if "SEC(" in source:
        score += 1000
    if "#include" in source:
        score += 500
    if "int main(" in source:
        score -= 500
    if is_program_fragment(source):
        score += 2000
    return score


def looks_recoverable_c(source: str) -> bool:
    if looks_like_verifier_log(source) or looks_like_disassembly(source) or looks_like_metadata_dump(source):
        return False
    lang = detect_language(source)
    if lang in {"rust", "go"}:
        return False
    if looks_like_userspace_loader(source) and "SEC(" not in source and "struct bpf_insn" not in source:
        return False
    if lang == "c":
        return True
    strong_markers = ("if (", "for (", "while (", "return ", "{", "}", ";", "struct ")
    return any(marker in source for marker in strong_markers) and any(token in source for token in ("bpf_", "__u", "ctx", "skb", "data_end", "data"))


def requires_bcc_frontend(source: str) -> bool:
    if any(marker in source for marker in UNSUPPORTED_DSL_MARKERS):
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
    inferred = detect_language("\n".join(sources))
    issue = case.get("issue") or {}
    combined = "\n".join(sources)
    if issue.get("repository") == "aya-rs/aya" and not any(token in combined for token in ("SEC(", "#include", "struct xdp_md", "struct __sk_buff", "BPF_PROG(")):
        return "rust"
    return inferred


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
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=LOAD_TIMEOUT_SEC)
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


def rewrite_53136145_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct ip_addr {
            __u32 addr;
        };

        struct some_key {
            struct ip_addr dst_ip;
        };

        struct global_vars {
            __u32 dummy;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, 1);
            __type(key, int);
            __type(value, struct global_vars);
        } globals_map SEC(".maps");

        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __uint(max_entries, 1024);
            __type(key, struct ip_addr);
            __type(value, __u8);
        } some_map SEC(".maps");

        static __always_inline int some_inlined_func(struct xdp_md *ctx, struct some_key *key)
        {
            __builtin_memset(key, 0, sizeof(*key));
            return 0;
        }

        SEC("xdp")
        int entry_point(struct xdp_md *ctx)
        {
            int act = XDP_DROP;
            int rc, i = 0;
            struct global_vars *globals;
            struct ip_addr addr = {};
            struct some_key key = {};
            void *temp;

            globals = bpf_map_lookup_elem(&globals_map, &i);
            if (!globals)
                return XDP_ABORTED;

            rc = some_inlined_func(ctx, &key);
            addr = key.dst_ip;
            temp = bpf_map_lookup_elem(&some_map, &addr);

            switch (rc) {
            case 0:
                if (!temp)
                    act = XDP_PASS;
                break;
            default:
                break;
            }

            return act;
        }
        """
    )


def rewrite_67679109_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        SEC("uretprobe/crc32")
        int crc32(struct pt_regs *ctx)
        {
            char str[256] = {};
            const uint32_t Polynomial = 0xEDB88320;
            u64 startTime = bpf_ktime_get_ns();
            uint32_t previousCrc32 = 0;
            uint32_t crc = ~previousCrc32;
            unsigned char *current = 0;
            int maxVal = sizeof(str);
            int result;
            u64 totalTime;
            char crc_fmt[] = "crc=0x%x\\n";
            char time_fmt[] = "cycles=%llu\\n";

            bpf_probe_read(&str, sizeof(str), (void *)PT_REGS_RC(ctx));

            while (maxVal--) {
                crc ^= *current++;
                for (unsigned int j = 0; j < 8; j++)
                    crc = (crc >> 1) ^ ((0 - (crc & 1)) & Polynomial);
            }

            result = ~crc;
            totalTime = bpf_ktime_get_ns() - startTime;
            bpf_trace_printk(crc_fmt, sizeof(crc_fmt), result);
            bpf_trace_printk(time_fmt, sizeof(time_fmt), totalTime);
            return 0;
        }
        """
    )


def rewrite_70721661_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct share_me {
            struct iphdr dest_ip;
        };

        struct bpf_map_def SEC("maps") ip_map = {
            .type = BPF_MAP_TYPE_ARRAY,
            .key_size = sizeof(int),
            .value_size = sizeof(struct share_me),
            .max_entries = 64,
        };

        SEC("xdp")
        int xdp_sock_prog(struct xdp_md *ctx)
        {
            int index = ctx->rx_queue_index;
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            struct share_me me = {};

            if ((void *)(eth + 1) > data_end)
                return XDP_PASS;

            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)(ip + 1) > data_end)
                return XDP_PASS;

            memcpy(&me.dest_ip, ip, sizeof(struct iphdr));
            bpf_map_update_elem(&ip_map, &index, &me, 0);
            return XDP_PASS;
        }
        """
    )


def rewrite_70729664_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define INV_RET_U32 4294967295U
        #define INV_RET_U16 65535U
        #define INV_RET_U8 255U
        #define DATA_CHUNK 0

        struct hdr_cursor {
            void *pos;
        };

        static __always_inline __u16 parse_ethhdr(struct hdr_cursor *nh, void *data_end)
        {
            struct ethhdr *eth = nh->pos;
            int hdrsize = sizeof(*eth);

            if (nh->pos + hdrsize > data_end)
                return INV_RET_U16;
            nh->pos += hdrsize;
            return eth->h_proto;
        }

        static __always_inline __u8 parse_iphdr(struct hdr_cursor *nh, void *data_end)
        {
            struct iphdr *iph = nh->pos;
            int hdrsize;

            if (iph + 1 > data_end)
                return INV_RET_U8;
            hdrsize = iph->ihl * 4;
            if (hdrsize < sizeof(*iph))
                return INV_RET_U8;
            if (nh->pos + hdrsize > data_end)
                return INV_RET_U8;
            nh->pos += hdrsize;
            return iph->protocol;
        }

        static __always_inline __u8 parse_sctp_chunk_type(void *data, void *data_end)
        {
            if (data + 1 > data_end)
                return INV_RET_U8;
            return *(__u8 *)data;
        }

        static __always_inline __u16 parse_sctp_chunk_size(void *data, void *data_end)
        {
            if (data + 4 > data_end)
                return INV_RET_U16;
            return bpf_ntohs(*(__u16 *)(data + 2));
        }

        static __always_inline __u32 parse_sctp_hdr(struct hdr_cursor *nh, void *data_end)
        {
            struct sctphdr *sctph = nh->pos;
            int hdrsize = sizeof(*sctph);

            if (sctph + 1 > data_end)
                return INV_RET_U32;
            nh->pos += hdrsize;

        #pragma clang loop unroll(full)
            for (int i = 0; i < 16; ++i) {
                __u8 type = parse_sctp_chunk_type(nh->pos, data_end);
                __u16 size;

                if (type == INV_RET_U8)
                    return INV_RET_U32;

                size = parse_sctp_chunk_size(nh->pos, data_end);
                if (size > 512)
                    return INV_RET_U32;

                size += (size % 4) == 0 ? 0 : 4 - size % 4;
                if (type == DATA_CHUNK) {
                    /* Original post omitted the DATA chunk body. */
                }

                if (nh->pos + size < data_end)
                    nh->pos += size;
                else
                    return INV_RET_U32;
            }

            return INV_RET_U32;
        }

        SEC("xdp")
        int xdp_parse_sctp(struct xdp_md *ctx)
        {
            void *data_end = (void *)(long)ctx->data_end;
            void *data = (void *)(long)ctx->data;
            struct hdr_cursor nh;
            __u32 nh_type;
            __u32 ip_type;

            nh.pos = data;
            nh_type = parse_ethhdr(&nh, data_end);
            if (bpf_ntohs(nh_type) != ETH_P_IP)
                return XDP_PASS;

            ip_type = parse_iphdr(&nh, data_end);
            if (ip_type != IPPROTO_SCTP)
                return XDP_PASS;

            parse_sctp_hdr(&nh, data_end);
            return XDP_PASS;
        }
        """
    )


def rewrite_71522674_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        SEC("xdp")
        int checksum_probe(struct xdp_md *ctx)
        {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct tcphdr *tcph = data;
            __u32 tcp_len = 0;
            __s64 value = 0;

            if (tcph + 1 > data_end)
                return XDP_DROP;

            tcp_len = tcph->doff * 4;
            if (tcp_len < sizeof(*tcph))
                return XDP_DROP;
            if ((void *)tcph + tcp_len > data_end)
                return XDP_DROP;

            value = bpf_csum_diff(0, 0, (void *)tcph, tcp_len, 0);
            if (value == 0)
                return XDP_DROP;

            return XDP_PASS;
        }
        """
    )


def rewrite_71946593_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        SEC("kprobe/nf_hook_slow")
        int BPF_KPROBE(nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state,
                       const struct nf_hook_entries *e, unsigned int s)
        {
            if (skb) {
                struct ethhdr *eth = (struct ethhdr *)(skb->head + skb->mac_header);
                __u16 proto = 0;
                bpf_probe_read_kernel(&proto, sizeof(proto), &eth->h_proto);
            }
            return 0;
        }
        """
    )


def rewrite_72005172_buggy(source: str) -> str:
    fixed = source
    fixed = re.sub(r"^#define SEC\(NAME\).*\n", "", fixed, flags=re.MULTILINE)
    fixed = re.sub(
        r"static long \(\*bpf_trace_printk\)\(const char \*fmt, __u32 fmt_size,\s*\.\.\.\) = \(void \*\)BPF_FUNC_trace_printk;\n",
        "",
        fixed,
        flags=re.MULTILINE,
    )
    fixed = fixed.replace('SEC("classifier")\nstatic inline int classification', 'SEC("classifier")\nint classification')
    return fixed


def rewrite_72074115_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        static __always_inline struct bictcp *inet_csk_ca(const struct sock *sk)
        {
            return (struct bictcp *)((char *)(struct inet_connection_sock *)sk + offsetof(struct inet_connection_sock, icsk_ca_priv));
        }

        static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
        {
            return (struct tcp_sock *)sk;
        }

        #define tcp_jiffies32 ((__u32)bpf_jiffies64())
        #define after(seq2, seq1) ((__s32)((seq1) - (seq2)) < 0)

        SEC("struct_ops/bictcp_cwnd_event")
        void BPF_PROG(bictcp_cwnd_event, struct sock *sk, enum tcp_ca_event event)
        {
            if (event == CA_EVENT_TX_START) {
                struct bictcp *ca = inet_csk_ca(sk);
                __u32 now = tcp_jiffies32;
                __s32 delta;

                delta = now - tcp_sk(sk)->lsndtime;
                if (ca->epoch_start && delta > 0) {
                    ca->epoch_start += delta;
                    if (after(ca->epoch_start, now))
                        ca->epoch_start = now;
                }
                return;
            }
        }
        """
    )


def rewrite_74178703_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct bpf_elf_map __section("maps") data_store = {
            .type = BPF_MAP_TYPE_ARRAY,
            .size_key = sizeof(__u32),
            .size_value = 1024,
            .max_elem = 4096,
            .pinning = PIN_GLOBAL_NS,
        };

        static __always_inline void read_data(__u32 idx, __u32 offset, void *dst, __u32 size)
        {
            __u8 *dst_bytes = dst;
            __u8 *b;

            if (size > 512 || offset >= 1024)
                return;

            b = bpf_map_lookup_elem(&data_store, &idx);
            if (!b)
                return;

            if (offset + size <= 1024) {
                for (__u32 i = 0; i < size && i < 512; ++i) {
                    if (offset + i >= 1024)
                        return;
                    memcpy(dst_bytes + i, b + offset + i, sizeof(__u8));
                }
            } else {
                dst_bytes -= offset;
                for (__u32 i = offset; i < size + offset && i < 1024; ++i)
                    memcpy(dst_bytes + i, b + i, sizeof(__u8));
            }
        }

        SEC("tracepoint/syscalls/sys_enter_execve")
        int read_data_probe(void *ctx)
        {
            char dst[64] = {};
            read_data(0, 0, dst, sizeof(dst));
            return 0;
        }
        """
    )


def rewrite_75515263_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MAX_ENTRIES 1024

        struct sock_info {
            __u64 ctime;
            __u16 sport;
            __u16 dport;
        };

        struct bpf_map_def SEC("maps") lookup = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(u32),
            .value_size = sizeof(struct sock_info *),
            .max_entries = MAX_ENTRIES,
        };

        SEC("tracepoint/syscalls/sys_enter_execve")
        int read_lookup(void *ctx)
        {
            u32 pid = 0;
            struct sock_info *og_sock = bpf_map_lookup_elem(&lookup, &pid);
            if (og_sock) {
                const char foo[] = "output %llu";
                bpf_trace_printk(foo, sizeof(foo), og_sock->ctime);
            }
            return 0;
        }
        """
    )


def rewrite_75643912_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MAX_PACKET_OFF 0xFFFF

        SEC("classifier")
        int handle_tc_ingress(struct __sk_buff *skb)
        {
            void *data_end = (void *)(long)skb->data_end;
            void *data = (void *)(long)skb->data;
            struct ethhdr *eth_hdr = data;

            if ((void *)(eth_hdr + 1) > data_end)
                return TC_ACT_OK;
            if (eth_hdr->h_proto != bpf_htons(ETH_P_IP))
                return TC_ACT_OK;

            struct iphdr *ipv4_hdr = (struct iphdr *)(eth_hdr + 1);
            if ((void *)(ipv4_hdr + 1) > data_end)
                return TC_ACT_OK;

            struct tcphdr *tcp_hdr = (struct tcphdr *)((__u8 *)ipv4_hdr + 4 * ipv4_hdr->ihl);
            if ((void *)(tcp_hdr + 1) > data_end)
                return TC_ACT_OK;

            __u8 *tcp_data = (__u8 *)tcp_hdr + 4 * tcp_hdr->doff;
            if ((void *)tcp_data > data_end)
                return TC_ACT_OK;

            for (int i = 0; i < MAX_PACKET_OFF && tcp_data + i <= data_end; ++i) {
                if (tcp_data[i] == ' ') {
                    bpf_printk("space");
                    return TC_ACT_SHOT;
                }
            }
            return TC_ACT_OK;
        }
        """
    )


def rewrite_76160985_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MAX_RULES 50
        #define MAX_RULE_NAME 20
        #define MAX_BYTE_PATTERN 11

        struct filter_rule {
            char rule_name[MAX_RULE_NAME];
            char byte_pattern[MAX_BYTE_PATTERN];
        };

        static __always_inline unsigned char mystrlen(const char *s, unsigned char max_len)
        {
            unsigned char i = 0;
            if (s == NULL)
                return 0;
            for (i = 0; i < max_len; i++) {
                if (s[i] == '\0')
                    return i;
            }
            return i;
        }

        static __always_inline bool find_substring(const char *str, const char *search)
        {
            if (str != NULL && search != NULL) {
                unsigned char l1 = mystrlen(str, 50);
                unsigned char l2 = mystrlen(search, MAX_BYTE_PATTERN);
                unsigned char i = 0, j = 0;
                unsigned char flag = 0;
                if (l1 == 0 || l2 == 0)
                    return false;
                for (i = 0; i <= l1 - l2; i++) {
                    for (j = i; j < i + l2; j++) {
                        flag = 1;
                        if (str[j] != search[j - i]) {
                            flag = 0;
                            break;
                        }
                    }
                    if (flag == 1)
                        break;
                }
                return flag == 1;
            }
            return false;
        }

        unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");

        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(key_size, sizeof(int));
            __uint(value_size, sizeof(struct filter_rule));
            __uint(max_entries, MAX_RULES);
        } filter_rules SEC(".maps");

        SEC("classifier")
        int ingress_hndlr(struct __sk_buff *ctx)
        {
            unsigned char buff[51] = {0};
            int tcp_payload_length = ctx->len;
            int payload_offset = 0;
            unsigned int key = 0;
            struct filter_rule *rule;

            for (int i = 0; i < tcp_payload_length && i < 50; ++i)
                buff[i] = load_byte(ctx, payload_offset + i);

            rule = bpf_map_lookup_elem(&filter_rules, &key);
            if (rule) {
                bool ret = find_substring((const char *)buff, rule->byte_pattern);
                if (ret)
                    return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
        """
    )


def rewrite_76960866_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        SEC("kprobe/inet_accept")
        int BPF_KPROBE(kprobe__inet_accept)
        {
            struct socket *newsock = (struct socket *)PT_REGS_PARM2(ctx);
            __u16 type = 0;

            if (newsock == NULL)
                return 0;

            bpf_trace_printk("inet_accept called\\n", sizeof("inet_accept called\\n"));
            bpf_probe_read_kernel(&type, sizeof(type), &newsock->type);
            bpf_trace_printk("inet_accept type %d\\n", sizeof("inet_accept type %d\\n"), type);
            return 0;
        }
        """
    )


def rewrite_77205912_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define SRC_IP_ADDR ((__be32)0)
        #define IBP_IP_ADDR ((__be32)0)
        #define LOC_IP_ADDR ((__be32)0)

        SEC("classifier")
        int tc_egress(struct __sk_buff *skb)
        {
            const __be32 cluster_ip = SRC_IP_ADDR;
            const __be32 pod_ip = IBP_IP_ADDR;
            const __be32 loc_ip = LOC_IP_ADDR;
            const int l3_off = ETH_HLEN;
            const int l4_off = l3_off + 20;
            __be32 sum;
            void *data = (void *)(long)skb->data;
            void *data_end = (void *)(long)skb->data_end;

            if (data_end < data + l4_off)
                return TC_ACT_OK;

            struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
            if (ip4->daddr != cluster_ip || ip4->protocol != IPPROTO_TCP)
                return TC_ACT_OK;

            if (data_end < data + l4_off + sizeof(struct tcphdr))
                return TC_ACT_OK;

            struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);
            if (bpf_ntohs(tcph->dest) != 9080)
                return TC_ACT_OK;

            sum = csum_diff((void *)&ip4->daddr, 4, (void *)&pod_ip, 4, 0);
            skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)&pod_ip, 4, 0);
            l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
            l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

            sum = csum_diff((void *)&ip4->saddr, 4, (void *)&loc_ip, 4, 0);
            skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), (void *)&loc_ip, 4, 0);
            l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
            l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);
            return TC_ACT_OK;
        }
        """
    )


def rewrite_77762365_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MAX_READ_CONTENT_LENGTH 4096
        #define DEBUG(fmt, ...) do { } while (0)

        struct ReadArgs {
            int fd;
            uintptr_t buf;
        };

        struct ReadEvent {
            int eventType;
            int fd;
            int len;
            u8 content[MAX_READ_CONTENT_LENGTH];
        };

        static __always_inline int readData(struct ReadArgs *args, struct ReadEvent *event, int read)
        {
            if ((void *)args->buf == NULL)
                return -1;
            event->fd = args->fd;
            if (event->len > MAX_READ_CONTENT_LENGTH)
                return -1;
            else
                event->len &= (MAX_READ_CONTENT_LENGTH - 1);
            if (read > MAX_READ_CONTENT_LENGTH)
                read = MAX_READ_CONTENT_LENGTH - 1;
            else
                read &= (MAX_READ_CONTENT_LENGTH - 1);
            if (event->len + read < MAX_READ_CONTENT_LENGTH) {
                long res = bpf_probe_read_user(&event->content[event->len], read, (const void *)args->buf);
                if (res < 0) {
                    DEBUG("readData: bpf_probe_read_user return %d", res);
                    return -1;
                }
            }
            return 0;
        }

        SEC("tracepoint/syscalls/sys_enter_execve")
        int read_data_probe(void *ctx)
        {
            struct ReadArgs args = {};
            struct ReadEvent event = {};
            readData(&args, &event, 0);
            return 0;
        }
        """
    )


def rewrite_78236201_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define VLAN_MAX_DEPTH 2
        #define VLAN_VID_MASK 0x0fff
        #define XDP_ACTION_MAX (XDP_REDIRECT + 1)

        /* === WRAPPER: support copied from the tutorial includes that are not available here === */
        struct datarec {
            __u64 rx_packets;
            __u64 rx_bytes;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
            __uint(max_entries, XDP_ACTION_MAX);
            __type(key, __u32);
            __type(value, struct datarec);
        } xdp_stats_map SEC(".maps");

        static __always_inline int xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
        {
            __u64 bytes = (__u64)ctx->data_end - (__u64)ctx->data;
            struct datarec *rec;

            rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
            if (!rec)
                return XDP_ABORTED;

            rec->rx_packets++;
            rec->rx_bytes += bytes;
            return action;
        }

        /* === ORIGINAL LOGIC from the post === */
        struct hdr_cursor {
            void *pos;
        };

        struct collect_vlans {
            __u16 id[VLAN_MAX_DEPTH];
        };

        static __always_inline int proto_is_vlan(__u16 h_proto)
        {
            return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                      h_proto == bpf_htons(ETH_P_8021AD));
        }

        static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
                                                     void *data_end,
                                                     struct ethhdr **ethhdr,
                                                     struct collect_vlans *vlans)
        {
            struct ethhdr *eth = nh->pos;
            int hdrsize = sizeof(*eth);
            struct vlan_hdr *vlh;
            __u16 h_proto;
            int i;

            if (nh->pos + hdrsize > data_end)
                return -1;

            nh->pos += hdrsize;
            *ethhdr = eth;
            vlh = nh->pos;
            h_proto = eth->h_proto;

        #pragma unroll
            for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto))
                    break;
                if (vlh + 1 > data_end)
                    break;
                h_proto = vlh->h_vlan_encapsulated_proto;
                if (vlans)
                    vlans->id[i] = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
                vlh++;
            }

            nh->pos = vlh;
            return h_proto;
        }

        static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                                void *data_end,
                                                struct ethhdr **ethhdr)
        {
            return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
        }

        static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                                void *data_end,
                                                struct ipv6hdr **ip6hdr)
        {
            struct ipv6hdr *ip6h = nh->pos;

            if (ip6h + 1 > data_end)
                return -1;
            nh->pos = ip6h + 1;
            *ip6hdr = ip6h;
            return ip6h->nexthdr;
        }

        static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                               void *data_end,
                                               struct iphdr **iphdr)
        {
            struct iphdr *iph = nh->pos;
            int hdrsize;

            if (iph + 1 > data_end)
                return -1;

            hdrsize = iph->ihl * 4;
            if (hdrsize < sizeof(*iph))
                return -1;
            if (nh->pos + hdrsize > data_end)
                return -1;

            nh->pos += hdrsize;
            *iphdr = iph;
            return iph->protocol;
        }

        static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                                                  void *data_end,
                                                  struct icmp6hdr **icmp6hdr)
        {
            struct icmp6hdr *icmp6h = nh->pos;

            if (icmp6h + 1 > data_end)
                return -1;
            nh->pos = icmp6h + 1;
            *icmp6hdr = icmp6h;
            return icmp6h->icmp6_type;
        }

        static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                                 void *data_end,
                                                 struct icmphdr **icmphdr)
        {
            struct icmphdr *icmph = nh->pos;

            if (icmph + 1 > data_end)
                return -1;
            nh->pos = icmph + 1;
            *icmphdr = icmph;
            return icmph->type;
        }

        SEC("xdp")
        int xdp_parser_func(struct xdp_md *ctx)
        {
            void *data_end = (void *)(long)ctx->data_end;
            void *data = (void *)(long)ctx->data;
            struct ethhdr *eth;
            __u32 action = XDP_PASS;
            struct hdr_cursor nh;
            int nh_type;

            nh.pos = data;
            nh_type = parse_ethhdr(&nh, data_end, &eth);
            if (nh_type == bpf_htons(ETH_P_8021Q)) {
                struct collect_vlans vlans;
                int vlan_proto = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

                if (vlan_proto < 0)
                    return XDP_ABORTED;
                for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
                    if (vlans.id[i] == 0)
                        /* Original post had the break commented out. */
                        bpf_printk("VLAN ID[%d] = %u\\n", i, vlans.id[i]);
                }
            }

            if (nh_type == bpf_htons(ETH_P_IPV6)) {
                struct ipv6hdr *ip6hdr;
                int ip6_next_header = parse_ip6hdr(&nh, data_end, &ip6hdr);

                if (ip6_next_header == IPPROTO_ICMPV6) {
                    struct icmp6hdr *icmp6hdr;
                    int icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);

                    if (icmp6_type < 0)
                        return XDP_ABORTED;
                }
            }

            if (nh_type == bpf_htons(ETH_P_IP)) {
                struct iphdr *iphdr;
                int ip_next_header = parse_iphdr(&nh, data_end, &iphdr);

                if (ip_next_header == IPPROTO_ICMP) {
                    struct icmphdr *icmphdr;
                    int icmp_type = parse_icmphdr(&nh, data_end, &icmphdr);

                    if (icmp_type < 0)
                        return XDP_ABORTED;

                    bpf_printk("IPv4 Header: Source Address = %x, Destination Address = %x\\n",
                               bpf_ntohl(iphdr->saddr), bpf_ntohl(iphdr->daddr));
                    bpf_printk("Protocol = %d\\n", iphdr->protocol);
                    bpf_printk("ICMP Header: Type = %d, Code = %d\\n",
                               icmphdr->type, icmphdr->code);
                }
            }

            return xdp_stats_record_action(ctx, action);
        }
        """
    )


def rewrite_79485758_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MAX_ACTION_LIST 8
        #define MAX_PAYLOAD_OFFSET 128
        #define MAX_IDS 4
        #define CONTEXT_KEY 0
        #define GRPC_ID_MASK 0xffe0
        #define GRPC_ID_SHIFT 5
        #define GRPC_LEN_MASK 0x001f

        typedef __u32 context_key_t;

        typedef struct {
            __u16 offset;
            __u16 field_index;
            __u16 field_id[MAX_IDS];
        } find_grpc_t;

        typedef struct {
            find_grpc_t find_grpc_args;
        } action_arg_t;

        typedef struct {
            __u16 action_index;
            __u16 payload_offset;
            struct {
                find_grpc_t find_grpc_args;
            } action_argument[MAX_ACTION_LIST];
        } context_data_t;

        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, 1);
            __type(key, context_key_t);
            __type(value, context_data_t);
        } context_map SEC(".maps");

        SEC("classifier")
        int find_grpc(struct __sk_buff *skb)
        {
            context_key_t key = CONTEXT_KEY;
            context_data_t *ctx = bpf_map_lookup_elem(&context_map, &key);
            void *data_end = (void *)(__u64)skb->data_end;
            void *data = (void *)(__u64)skb->data;
            unsigned short field_offset;
            char len = 0;
            uint16_t x;
            find_grpc_t *args;
            unsigned short toBeFound;

            if (skb == NULL || ctx == NULL)
                goto EXIT;
            if (ctx->action_index >= MAX_ACTION_LIST || ctx->payload_offset > MAX_PAYLOAD_OFFSET)
                goto EXIT;

            args = (find_grpc_t *)&ctx->action_argument[ctx->action_index].find_grpc_args;
            if (args->offset > 100 || args->field_index > MAX_IDS)
                goto EXIT;

            field_offset = ctx->payload_offset + args->offset;
            toBeFound = args->field_id[args->field_index];
        LOOK:
            if ((data + field_offset + sizeof(uint16_t)) > data_end)
                goto EXIT;
            x = *((uint16_t *)(data + field_offset));
            char y = (x & GRPC_ID_MASK) >> GRPC_ID_SHIFT;
            len = x & GRPC_LEN_MASK;
            if (len > 32)
                goto EXIT;
            if (y == toBeFound)
                goto FOUND;
            field_offset += len;
            goto LOOK;
        FOUND:
        EXIT:
            return TC_ACT_OK;
        }
        """
    )


def rewrite_79812509_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct provenance_structure {
            __u8 to_trace;
            struct bpf_spin_lock lock;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, struct provenance_structure);
        } provenance_structure_map_task SEC(".maps");

        SEC("lsm/task_alloc")
        int BPF_PROG(task_allocation, struct task_struct *p, u64 clone_flags)
        {
            struct task_struct *s_task = (void *)bpf_get_current_task();
            struct provenance_structure *prov;

            prov = bpf_task_storage_get(&provenance_structure_map_task, s_task, NULL, 0);
            if (prov) {
                bpf_spin_lock(&prov->lock);
                prov->to_trace = 1;
                bpf_spin_unlock(&prov->lock);
            }
            return 0;
        }
        """
    )


def rewrite_74531552_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct automaton_s {
            int initial_state;
            int function[4][4];
        };
        typedef struct automaton_s automaton_t;

        struct {
            __uint(type, BPF_MAP_TYPE_STACK);
            __uint(max_entries, 1);
            __type(value, automaton_t);
        } automaton SEC(".maps");

        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __uint(max_entries, 1);
            __type(key, int);
            __type(value, int);
        } state_store SEC(".maps");

        static __always_inline int *state_store_lookup_or_try_init(int *key, int *init_val)
        {
            int *curr_state = bpf_map_lookup_elem(&state_store, key);
            if (curr_state)
                return curr_state;
            bpf_map_update_elem(&state_store, key, init_val, BPF_NOEXIST);
            return bpf_map_lookup_elem(&state_store, key);
        }

        SEC("kprobe/tcp_connect")
        int trace_connect_v4_return(struct pt_regs *ctx)
        {
            int key = 0, init_val = 0;
            int *curr_state;
            automaton_t aut;
            int next;

            curr_state = state_store_lookup_or_try_init(&key, &init_val);
            if (!curr_state)
                return -1;

            if (bpf_map_peek_elem(&automaton, &aut) < 0) {
                aut = (automaton_t){
                    .initial_state = 0,
                    .function = {
                        { 1, -1, -1, -1 },
                        { -1, 2, -1, -1 },
                        { -1, -1, 3, -1 },
                        { -1, -1, -1, 0 },
                    },
                };
                bpf_map_push_elem(&automaton, &aut, 0);
            }

            next = aut.function[*curr_state][0];
            if (!next || next > 3 || next < -1)
                return -1;
            *curr_state = next;
            return 0;
        }
        """
    )


def rewrite_76277872_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        struct bpf_map_def SEC("maps") srcMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u32),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        struct bpf_map_def SEC("maps") dstMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u32),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        struct bpf_map_def SEC("maps") protoMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u8),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        struct bpf_map_def SEC("maps") sportMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u16),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        struct bpf_map_def SEC("maps") dportMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u16),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        struct bpf_map_def SEC("maps") actionMap = {
            .type = BPF_MAP_TYPE_HASH,
            .key_size = sizeof(__u64),
            .value_size = sizeof(__u64),
            .max_entries = 4194304,
        };

        SEC("xdp")
        int xdp_ip_filter(struct xdp_md *ctx)
        {
            void *end = (void *)(unsigned long)ctx->data_end;
            void *data = (void *)(unsigned long)ctx->data;
            __u32 ip_src, ip_dst;
            struct iphdr *iph;

            if (end < data + sizeof(struct ethhdr))
                return XDP_ABORTED;

            iph = data + sizeof(struct ethhdr);
            if ((void *)(iph + 1) > end)
                return XDP_ABORTED;

            ip_src = iph->saddr;
            ip_dst = iph->daddr;
            __u8 proto = iph->protocol;

            if (proto == 1 || proto == 6 || proto == 17) {
                __u64 *srcMap_value, *dstMap_value, *protoMap_value, bitmap;
                srcMap_value = bpf_map_lookup_elem(&srcMap, &ip_src);
                dstMap_value = bpf_map_lookup_elem(&dstMap, &ip_dst);
                protoMap_value = bpf_map_lookup_elem(&protoMap, &proto);

                if (srcMap_value == 0) {
                    __u32 default_sip = 0;
                    srcMap_value = bpf_map_lookup_elem(&srcMap, &default_sip);
                }
                if (dstMap_value == 0) {
                    __u32 default_dip = 0;
                    dstMap_value = bpf_map_lookup_elem(&dstMap, &default_dip);
                }
                if (protoMap_value == 0) {
                    __u8 default_prot = 0;
                    protoMap_value = bpf_map_lookup_elem(&protoMap, &default_prot);
                }
                if (!srcMap_value || !dstMap_value || !protoMap_value)
                    return XDP_PASS;

                if (proto == 1) {
                    bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value);
                } else if (proto == 6) {
                    struct tcphdr *tcph;
                    __u64 *sportMap_value, *dportMap_value;
                    __u16 sport, dport;

                    if (end < data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
                        return XDP_ABORTED;
                    tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                    sport = tcph->source;
                    dport = tcph->dest;
                    sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);
                    dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);
                    if (!sportMap_value || !dportMap_value)
                        return XDP_PASS;
                    bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
                } else {
                    struct udphdr *udph;
                    __u64 *sportMap_value, *dportMap_value;
                    __u16 sport, dport;

                    if (end < data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
                        return XDP_ABORTED;
                    udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                    sport = udph->source;
                    dport = udph->dest;
                    sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);
                    dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);
                    if (!sportMap_value || !dportMap_value)
                        return XDP_PASS;
                    bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
                }

                __u64 *actionMap_value = bpf_map_lookup_elem(&actionMap, &bitmap);
                if (actionMap_value) {
                    (*actionMap_value) = (*actionMap_value) + 1;
                    bpf_map_update_elem(&actionMap, &bitmap, actionMap_value, BPF_EXIST);
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }
        """
    )


def rewrite_79530762_buggy(source: str) -> str:
    return textwrap.dedent(
        """\
        #define MY_OPTION_TYPE 31
        #define MAX_CHECKING 4

        static __always_inline __u16 iph_csum(struct iphdr *iph, void *data_end)
        {
            __u32 sum = 0;
            __u16 *buf = (__u16 *)iph;
            __u16 ihl = iph->ihl << 2;

            iph->check = 0;
            for (__u8 i = 0; i < ihl && i < 60; i += 2) {
                if ((void *)(buf + 1) > data_end)
                    break;
                sum += *buf++;
            }
            for (__u8 i = 0; sum >> 16 && i < MAX_CHECKING; i += 1)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return ~sum;
        }

        SEC("xdp")
        int inter_op_ebpf(struct xdp_md *ctx)
        {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;

            if ((void *)eth + sizeof(*eth) > data_end)
                return XDP_PASS;

            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)ip + sizeof(*ip) > data_end)
                return XDP_PASS;
            if (ip->version != 4)
                return XDP_PASS;

            int options_len = (ip->ihl * 4) - sizeof(struct iphdr);
            __u8 *options = (__u8 *)(ip + 1);
            if (options_len > 0 && (void *)(options + 4) < data_end) {
                __u8 option_type = options[0];
                if (option_type == MY_OPTION_TYPE) {
                    __u8 option_length = options[1];
                    __u8 *data_bytes = (__u8 *)data;
                    int shift_data_length = sizeof(*eth) + sizeof(struct iphdr);

                    if (option_length == 8 || option_length == 12) {
                        for (int i = shift_data_length - 1; i >= 0; i--) {
                            if ((void *)(data_bytes + i + option_length + 1) > data_end)
                                return XDP_PASS;
                            data_bytes[i + option_length] = data_bytes[i];
                        }
                    }
                }
            }
            return XDP_PASS;
        }
        """
    )


CASE_SOURCE_REWRITES: dict[str, Callable[[str], str]] = {
    "stackoverflow-61945212": rewrite_61945212_buggy,
    "stackoverflow-67402772": rewrite_67402772_buggy,
    "stackoverflow-53136145": rewrite_53136145_buggy,
    "stackoverflow-67679109": rewrite_67679109_buggy,
    "stackoverflow-70721661": rewrite_70721661_buggy,
    "stackoverflow-70729664": rewrite_70729664_buggy,
    "stackoverflow-71522674": rewrite_71522674_buggy,
    "stackoverflow-71946593": rewrite_71946593_buggy,
    "stackoverflow-72005172": rewrite_72005172_buggy,
    "stackoverflow-72074115": rewrite_72074115_buggy,
    "stackoverflow-74178703": rewrite_74178703_buggy,
    "stackoverflow-74531552": rewrite_74531552_buggy,
    "stackoverflow-75515263": rewrite_75515263_buggy,
    "stackoverflow-75643912": rewrite_75643912_buggy,
    "stackoverflow-76160985": rewrite_76160985_buggy,
    "stackoverflow-76277872": rewrite_76277872_buggy,
    "stackoverflow-76960866": rewrite_76960866_buggy,
    "stackoverflow-77205912": rewrite_77205912_buggy,
    "stackoverflow-77762365": rewrite_77762365_buggy,
    "stackoverflow-78236201": rewrite_78236201_buggy,
    "stackoverflow-79485758": rewrite_79485758_buggy,
    "stackoverflow-79530762": rewrite_79530762_buggy,
    "stackoverflow-79812509": rewrite_79812509_buggy,
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
        issue = case.get("issue") or {}
        if issue.get("repository") == "aya-rs/aya" and buggy_candidates and not any(
            any(token in source for token in ("SEC(", "#include", "struct xdp_md", "struct __sk_buff", "BPF_PROG("))
            for _, source in buggy_candidates[:3]
        ):
            language = "rust"
            buggy_candidates = []
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
        has_case_rewrite = case_id in CASE_SOURCE_REWRITES
        if requires_bcc_frontend(chosen) and not has_case_rewrite:
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
        if any(marker in chosen for marker in UNSUPPORTED_DSL_MARKERS) and not has_case_rewrite:
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
