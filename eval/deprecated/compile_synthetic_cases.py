#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_KERNEL_ROOT = Path("/tmp/ebpf-eval-repos/linux")
DEFAULT_CASES_ROOT = ROOT_DIR / "case_study" / "cases" / "eval_commits_synthetic"
DEFAULT_WORK_DIR = Path("/tmp/oblige-synthetic-compilation")
DEFAULT_REPORT_PATH = ROOT_DIR / "docs" / "tmp" / "synthetic-compilation-report.md"
DEFAULT_RESULTS_PATH = ROOT_DIR / "eval" / "results" / "synthetic_compilation_results.json"
VMLINUX_BTF = Path("/sys/kernel/btf/vmlinux")
HELPER_SOURCE = ROOT_DIR / "case_study" / "selftest_prog_loader.c"
HELPER_BINARY_NAME = "selftest_prog_loader"
VERIFIER_LOG_STYLE_KEY = "verifier_log"
PILOT_FIX_TYPES = ("inline_hint", "bounds_check", "null_check", "loop_rewrite")
COMPILE_TIMEOUT_SECONDS = 30
LOAD_TIMEOUT_SECONDS = 10

FILE_MARKER_RE = re.compile(r"^\s*// FILE:\s*(?P<label>.+?)\s*$")
CONTEXT_MARKER_RE = re.compile(r"^\s*// CONTEXT:\s*")
SECTION_LINE_RE = re.compile(r"\bSEC\s*\(|\b__section(?:_tail)?\s*\(")
BPF_PROG_RE = re.compile(r"\bBPF_PROG\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
FUNC_DEF_RE = re.compile(
    r"(?ms)^(?P<prefix>(?:static|inline|__always_inline|__maybe_unused|__noinline|__weak|"
    r"__hidden|extern|const|\s)+)?"
    r"(?P<ret>[A-Za-z_][A-Za-z0-9_\s\*\t]*?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<params>[^;{}]*)\)\s*\{"
)
PROG_NAME_RE = re.compile(
    r"(?ms)^(?:\s*SEC\s*\([^)]*\)\s*)+"
    r"(?:static\s+)?(?:__always_inline\s+|__maybe_unused\s+|__noinline\s+|__weak\s+|"
    r"inline\s+|__hidden\s+)*"
    r"[A-Za-z_][A-Za-z0-9_\s\*\t]*?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
ANNOTATED_BPF_PROG_RE = re.compile(r"(?ms)^(?:\s*SEC\s*\([^)]*\)\s*)+.*?\bBPF_PROG\(")
SECTION_MACRO_RE = re.compile(r"(?m)^(?P<indent>\s*)__section\(\s*\"(?P<section>[^\"]+)\"\s*\)")
SECTION_TAIL_MACRO_RE = re.compile(
    r"(?m)^(?P<indent>\s*)__section_tail\(\s*[^,]+,\s*[^)]+\)"
)
BPF_LICENSE_RE = re.compile(r"\bBPF_LICENSE\(\s*\"(?P<license>[^\"]+)\"\s*\)\s*;?")
INCLUDE_RE = re.compile(r'^\s*#include\s*[<"](?P<path>[^">]+)[">]\s*$')


class LiteralString(str):
    pass


class LiteralDumper(yaml.SafeDumper):
    pass


def literal_string_representer(dumper: yaml.SafeDumper, value: LiteralString) -> yaml.nodes.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(value), style="|")


LiteralDumper.add_representer(LiteralString, literal_string_representer)


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    path: Path
    fix_type: str
    source_snippet: str


@dataclass(frozen=True)
class ToolVersions:
    kernel_release: str
    clang: str
    bpftool: str


@dataclass(frozen=True)
class CompileUnit:
    source_text: str
    program_name: str
    selected_file: str
    selected_fragment_index: int
    selection_score: int
    used_wrapper: bool
    used_compat_prelude: bool
    effective_section: str | None


@dataclass
class CompileResult:
    ok: bool
    object_path: Path | None
    stdout: str
    stderr: str
    returncode: int
    source_path: Path


@dataclass
class LoadResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    parsed: dict[str, Any] | None

    @property
    def load_ok(self) -> bool:
        return bool(self.parsed and self.parsed.get("load_ok"))

    @property
    def verifier_log(self) -> str:
        if not self.parsed:
            return ""
        value = self.parsed.get("verifier_log")
        return value if isinstance(value, str) else ""

    @property
    def error_message(self) -> str:
        if self.parsed and isinstance(self.parsed.get("error_message"), str):
            return self.parsed["error_message"]
        return self.stderr.strip() or self.stdout.strip() or f"loader exited with {self.returncode}"


@dataclass
class CaseRunResult:
    case_id: str
    case_path: str
    fix_type: str
    batch: str
    compile_ok: bool
    load_ok: bool | None
    verifier_log_length: int
    error_message: str
    program_name: str
    selected_file: str
    selected_fragment_index: int
    selection_score: int
    used_wrapper: bool
    used_compat_prelude: bool
    effective_section: str | None
    yaml_updated: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile and load synthetic eBPF case fragments to capture real verifier logs."
    )
    parser.add_argument("--kernel-root", type=Path, default=DEFAULT_KERNEL_ROOT)
    parser.add_argument("--cases-root", type=Path, default=DEFAULT_CASES_ROOT)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--results-json", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--pilot-per-fix-type", type=int, default=5)
    parser.add_argument("--pilot-threshold", type=float, default=0.30)
    parser.add_argument("--pilot-only", action="store_true")
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def emit(message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    stdout_handle: Any | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            cwd=cwd,
            text=True,
            stdout=stdout_handle if stdout_handle is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_text = "" if exc.stdout is None else str(exc.stdout)
        stderr_text = "" if exc.stderr is None else str(exc.stderr)
        if stderr_text:
            stderr_text = f"{stderr_text.rstrip()}\ncommand timed out after {timeout}s"
        else:
            stderr_text = f"command timed out after {timeout}s"
        return subprocess.CompletedProcess(args=args, returncode=124, stdout=stdout_text, stderr=stderr_text)


def host_arch_macro() -> tuple[str, str]:
    machine = run_command(["uname", "-m"]).stdout.strip()
    mapping = {
        "x86_64": ("x86", "bpfel"),
        "aarch64": ("arm64", "bpfel"),
        "arm64": ("arm64", "bpfel"),
        "riscv64": ("riscv", "bpfel"),
        "s390x": ("s390", "bpfeb"),
        "ppc64le": ("powerpc", "bpfel"),
        "ppc64": ("powerpc", "bpfeb"),
    }
    if machine not in mapping:
        raise SystemExit(f"Unsupported host architecture for this script: {machine}")
    return mapping[machine]


def collect_clang_sys_includes(clang: str) -> list[str]:
    completed = run_command([clang, "-v", "-E", "-"])
    lines = completed.stderr.splitlines()
    includes: list[str] = []
    collecting = False
    for line in lines:
        stripped = line.strip()
        if "#include <...> search starts here:" in stripped:
            collecting = True
            continue
        if stripped == "End of search list.":
            break
        if collecting and stripped.startswith("/"):
            includes.extend(["-idirafter", stripped])
    return includes


def ensure_kernel_paths(kernel_root: Path, arch_macro: str) -> None:
    required = [
        kernel_root / "tools" / "lib" / "bpf",
        kernel_root / "tools" / "include",
        kernel_root / "tools" / "build",
        kernel_root / "tools" / "scripts",
        kernel_root / "tools" / "arch" / arch_macro / "include",
        kernel_root / "scripts" / "bpf_doc.py",
    ]
    missing = [path for path in required if not path.exists()]
    if not missing:
        return
    if not (kernel_root / ".git").exists():
        raise SystemExit(
            "Kernel checkout is missing required paths: "
            + ", ".join(str(path) for path in missing)
        )

    sparse_paths = [
        "tools/lib/bpf",
        "tools/include",
        "tools/build",
        "tools/scripts",
        f"tools/arch/{arch_macro}/include",
        "scripts",
    ]
    emit("Expanding sparse checkout with the libbpf build prerequisites")
    completed = run_command(["git", "-C", str(kernel_root), "sparse-checkout", "add", *sparse_paths])
    if completed.returncode != 0:
        raise SystemExit(f"Failed to expand sparse checkout:\n{completed.stdout}{completed.stderr}")
    missing = [path for path in required if not path.exists()]
    if missing:
        raise SystemExit(
            "Kernel checkout is still missing required paths: "
            + ", ".join(str(path) for path in missing)
        )


def ensure_helper_binary(work_dir: Path) -> Path:
    helper_bin = work_dir / "bin" / HELPER_BINARY_NAME
    helper_bin.parent.mkdir(parents=True, exist_ok=True)
    if helper_bin.exists() and helper_bin.stat().st_mtime >= HELPER_SOURCE.stat().st_mtime:
        return helper_bin
    emit(f"Compiling helper loader {HELPER_SOURCE} -> {helper_bin}")
    completed = run_command(
        [
            shutil.which("cc") or "cc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(HELPER_SOURCE),
            "-lbpf",
            "-lelf",
            "-lz",
            "-o",
            str(helper_bin),
        ]
    )
    if completed.returncode != 0:
        raise SystemExit(f"Failed to compile helper loader:\n{completed.stdout}{completed.stderr}")
    return helper_bin


def ensure_vmlinux_header(work_dir: Path) -> Path:
    if not VMLINUX_BTF.exists():
        raise SystemExit(f"Missing kernel BTF at {VMLINUX_BTF}")
    include_dir = work_dir / "include"
    include_dir.mkdir(parents=True, exist_ok=True)
    vmlinux_header = include_dir / "vmlinux.h"
    if vmlinux_header.exists():
        return vmlinux_header
    emit(f"Generating {vmlinux_header} from {VMLINUX_BTF}")
    with vmlinux_header.open("w", encoding="utf-8") as handle:
        completed = run_command(
            ["bpftool", "btf", "dump", "file", str(VMLINUX_BTF), "format", "c"],
            stdout_handle=handle,
        )
    if completed.returncode != 0:
        raise SystemExit(f"Failed to generate vmlinux.h:\n{completed.stderr}")
    return vmlinux_header


def ensure_libbpf_headers(kernel_root: Path, work_dir: Path) -> Path:
    include_root = work_dir / "libbpf-root"
    header_dir = include_root / "include"
    expected_header = header_dir / "bpf" / "bpf_helper_defs.h"
    if expected_header.exists():
        return header_dir

    build_dir = work_dir / "libbpf-build"
    include_root.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)
    emit(f"Generating libbpf headers into {header_dir}")
    completed = run_command(
        [
            "make",
            "-C",
            str(kernel_root / "tools" / "lib" / "bpf"),
            f"OUTPUT={build_dir}/",
            f"DESTDIR={include_root}",
            "prefix=",
            "install_headers",
        ]
    )
    if completed.returncode != 0:
        raise SystemExit(f"Failed to generate libbpf headers:\n{completed.stdout}{completed.stderr}")
    if not expected_header.exists():
        raise SystemExit(f"libbpf header generation did not create {expected_header}")
    return header_dir


def ensure_sudo_available() -> None:
    completed = run_command(["sudo", "-n", "true"], timeout=5)
    if completed.returncode != 0:
        raise SystemExit("`sudo -n` is required for the loader step but is not available without a password.")


def detect_versions(clang: str) -> ToolVersions:
    kernel_release = run_command(["uname", "-r"]).stdout.strip() or "<unknown>"
    clang_version = (run_command([clang, "--version"]).stdout.splitlines() or ["<unknown>"])[0].strip()
    bpftool_line = (run_command(["bpftool", "version"]).stdout.splitlines() or ["<unknown>"])[0].strip()
    return ToolVersions(kernel_release=kernel_release, clang=clang_version, bpftool=bpftool_line)


def load_cases(cases_root: Path) -> list[CaseRecord]:
    case_paths = sorted(cases_root.glob("*.yaml"))
    if not case_paths:
        raise SystemExit(f"No YAML cases found under {cases_root}")
    cases: list[CaseRecord] = []
    for path in case_paths:
        payload = yaml.safe_load(path.read_text())
        if not isinstance(payload, dict):
            continue
        snippets = payload.get("source_snippets") or []
        if not snippets:
            continue
        first = snippets[0]
        if not isinstance(first, str):
            continue
        cases.append(
            CaseRecord(
                case_id=str(payload.get("case_id", path.stem)),
                path=path,
                fix_type=str(payload.get("fix_type", "unknown")),
                source_snippet=first,
            )
        )
    if not cases:
        raise SystemExit("No usable synthetic cases were found.")
    return cases


def split_file_segments(snippet: str) -> list[tuple[str, str]]:
    segments: list[tuple[str, list[str]]] = []
    current_label = "snippet"
    current_lines: list[str] = []
    saw_marker = False
    for line in snippet.splitlines():
        match = FILE_MARKER_RE.match(line)
        if match:
            saw_marker = True
            if current_lines:
                segments.append((current_label, current_lines))
            current_label = match.group("label").strip()
            current_lines = []
            continue
        current_lines.append(line)
    if current_lines or not saw_marker:
        segments.append((current_label, current_lines))
    return [(label, "\n".join(lines).rstrip()) for label, lines in segments if "\n".join(lines).strip()]


def strip_marker_lines(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines():
        if FILE_MARKER_RE.match(line):
            continue
        context_match = CONTEXT_MARKER_RE.match(line)
        if context_match:
            payload = line[context_match.end() :]
            if payload.strip():
                kept.append(payload)
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def sanitize_includes(text: str) -> str:
    allowed = {
        "vmlinux.h",
        "stdbool.h",
        "stddef.h",
        "stdint.h",
        "linux/bpf.h",
        "bpf/bpf.h",
        "bpf/bpf_helpers.h",
        "bpf/bpf_tracing.h",
        "bpf/bpf_core_read.h",
        "bpf/bpf_endian.h",
        "bpf/bpf_helper_defs.h",
    }
    kept: list[str] = []
    for line in text.splitlines():
        match = INCLUDE_RE.match(line)
        if not match:
            kept.append(line)
            continue
        path = match.group("path")
        if path in allowed or path.startswith(("linux/", "asm/")):
            kept.append(line)
    return "\n".join(kept)


def count_file_markers(text: str) -> int:
    return sum(1 for line in text.splitlines() if FILE_MARKER_RE.match(line))


def segment_score(text: str) -> int:
    score = 0
    lower = text.lower()
    if SECTION_LINE_RE.search(text):
        score += 8
    if "BPF_PROG(" in text:
        score += 6
    if "BPF_MAP_TYPE" in text or 'SEC(".maps")' in text:
        score += 4
    if "struct __sk_buff" in text or "__ctx_buff" in text:
        score += 4
    if "struct xdp_md" in text:
        score += 4
    if "struct bpf_sock_addr" in text or "struct bpf_sock" in text:
        score += 4
    if "#include <vmlinux.h>" in text or '#include "vmlinux.h"' in text:
        score += 3
    if "#include <bpf/" in text:
        score += 3
    if re.search(r"\bbpf_[A-Za-z0-9_]+\(", text):
        score += 2
    if re.search(r"\b(?:tracepoint|kprobe|fentry|xdp|classifier|cgroup/)", lower):
        score += 2
    if "#include" not in text:
        score += 2
    if re.search(r"#include\s+[<\"][^>\"]*(?:stdio|stdlib|unistd|libelf|gelf|sys/|fcntl|errno)", lower):
        score -= 6
    if re.search(r"\b(?:fopen|malloc|free|ioctl|elf_|gelf_|uname|close)\s*\(", text):
        score -= 4
    if count_file_markers(text) > 1:
        score -= 10
    line_count = len([line for line in text.splitlines() if line.strip()])
    score -= min(line_count // 80, 5)
    return score


def choose_compile_fragment(case: CaseRecord) -> tuple[str, str, int, int]:
    segments = split_file_segments(case.source_snippet)
    scored = [
        (segment_score(raw_text), index, label, raw_text)
        for index, (label, raw_text) in enumerate(segments)
    ]
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    best_score, best_index, best_label, best_text = scored[0]
    return best_label, best_text, best_index, best_score


def first_significant_line_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if line.strip():
            return index
    return None


def first_anchor_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if SECTION_LINE_RE.search(line):
            return index
        if not line.startswith((" ", "\t")) and FUNC_DEF_RE.match("\n".join(lines[index : index + 6])):
            return index
    return None


def trim_leading_fragment(text: str) -> str:
    lines = text.splitlines()
    first_index = first_significant_line_index(lines)
    if first_index is None:
        return text.strip()
    first_line = lines[first_index]
    anchor_index = first_anchor_index(lines)
    if first_line.startswith((" ", "\t")) and anchor_index is not None and anchor_index > first_index:
        lines = lines[anchor_index:]
    return "\n".join(lines).strip()


def infer_section(section_hint: str, text: str) -> str:
    hint = section_hint.lower()
    if hint.startswith(("tracepoint/", "kprobe/", "uprobe/", "uretprobe/", "fentry/", "fexit/", "lsm/")):
        return section_hint
    if hint in {"xdp", "xdp.frags"}:
        return section_hint
    if "sock4" in hint:
        return "cgroup/sendmsg4" if "snd" in hint or "send" in hint else "cgroup/connect4"
    if "sock6" in hint:
        return "cgroup/sendmsg6" if "snd" in hint or "send" in hint else "cgroup/connect6"
    if "sockops" in hint:
        return "sockops"
    if any(token in hint for token in ("netdev", "network", "container", "policy", "tail", "host")):
        return "classifier"
    if "struct __sk_buff" in text or "__ctx_buff" in text:
        return "classifier"
    if "struct xdp_md" in text:
        return "xdp"
    if "struct bpf_sock_addr" in text:
        return "cgroup/connect6" if "6" in hint else "cgroup/connect4"
    if "struct bpf_sock" in text:
        return "sockops"
    return "xdp"


def rewrite_custom_sections(text: str) -> tuple[str, str | None]:
    effective_section: str | None = None

    def replace_section(match: re.Match[str]) -> str:
        nonlocal effective_section
        section_name = infer_section(match.group("section"), text)
        if effective_section is None:
            effective_section = section_name
        return f'{match.group("indent")}SEC("{section_name}")'

    def replace_tail(match: re.Match[str]) -> str:
        nonlocal effective_section
        section_name = infer_section("tail", text)
        if effective_section is None:
            effective_section = section_name
        return f'{match.group("indent")}SEC("{section_name}")'

    rewritten = SECTION_MACRO_RE.sub(replace_section, text)
    rewritten = SECTION_TAIL_MACRO_RE.sub(replace_tail, rewritten)
    return rewritten, effective_section


def rewrite_bpf_license(text: str) -> tuple[str, bool]:
    match = BPF_LICENSE_RE.search(text)
    if not match:
        return text, False
    license_value = match.group("license")
    replacement = f'char __license[] SEC("license") = "{license_value}";'
    return BPF_LICENSE_RE.sub(replacement, text, count=1), True


def has_annotated_program(text: str) -> bool:
    return bool(PROG_NAME_RE.search(text) or ANNOTATED_BPF_PROG_RE.search(text))


def has_include_statements(text: str) -> bool:
    return "#include" in text


def has_license_section(text: str) -> bool:
    return bool(
        re.search(r'SEC\s*\(\s*"(?:license|/license)"\s*\)', text)
        or "__license[]" in text
        or "__license []" in text
    )


def needs_compat_prelude(text: str) -> bool:
    indicators = [
        "__ctx_buff",
        "__section(",
        "__section_tail(",
        "BPF_PROG_ARRAY(",
        "__BPF_MAP(",
        "tail_call(",
        "ep_tail_call(",
        "map_lookup_elem(",
        "map_update_elem(",
        "send_drop_notify(",
        "send_drop_notify_error(",
        "send_trace_notify(",
        "cilium_trace(",
        "cilium_dbg_capture(",
        "cilium_trace_capture(",
        "bpf_clear_meta(",
        "bpf_clear_cb(",
        "policy_mark_skip(",
        "policy_clear_mark(",
        "barrier_data(",
        "load_byte(",
        "LIBBPF_PIN_BY_NAME",
        "PIN_GLOBAL_NS",
        "PIN_OBJECT_NS",
        "CONNECT_PROCEED",
        "SENDMSG_PROCEED",
        "SYS_PROCEED",
    ]
    return any(indicator in text for indicator in indicators)


def standard_header_block() -> str:
    return "\n".join(
        [
            '#include "vmlinux.h"',
            "#include <stdbool.h>",
            "#include <bpf/bpf_helpers.h>",
            "#include <bpf/bpf_tracing.h>",
            "#include <bpf/bpf_core_read.h>",
            "#include <bpf/bpf_endian.h>",
            "",
        ]
    )


def compat_prelude_block() -> str:
    return "\n".join(
        [
            "typedef __u8 u8;",
            "typedef __u16 u16;",
            "typedef __u32 u32;",
            "typedef __u64 u64;",
            "typedef __s8 s8;",
            "typedef __s16 s16;",
            "typedef __s32 s32;",
            "typedef __s64 s64;",
            "",
            "#ifndef __ctx_buff",
            "#define __ctx_buff __sk_buff",
            "#endif",
            "#ifndef __inline__",
            "#define __inline__ __always_inline",
            "#endif",
            "#ifndef __maybe_unused",
            "#define __maybe_unused __attribute__((unused))",
            "#endif",
            "#ifndef likely",
            "#define likely(x) (!!(x))",
            "#endif",
            "#ifndef unlikely",
            "#define unlikely(x) (!!(x))",
            "#endif",
            "#ifndef LIBBPF_PIN_BY_NAME",
            "#define LIBBPF_PIN_BY_NAME 1",
            "#endif",
            "#ifndef PIN_GLOBAL_NS",
            "#define PIN_GLOBAL_NS LIBBPF_PIN_BY_NAME",
            "#endif",
            "#ifndef PIN_OBJECT_NS",
            "#define PIN_OBJECT_NS LIBBPF_PIN_BY_NAME",
            "#endif",
            "#ifndef CONNECT_PROCEED",
            "#define CONNECT_PROCEED 1",
            "#endif",
            "#ifndef SENDMSG_PROCEED",
            "#define SENDMSG_PROCEED 1",
            "#endif",
            "#ifndef SYS_PROCEED",
            "#define SYS_PROCEED 1",
            "#endif",
            "#ifndef barrier_data",
            '#define barrier_data(ptr) asm volatile("" : : "r"(ptr) : "memory")',
            "#endif",
            "#ifndef BPF_PROG_ARRAY",
            "#define BPF_PROG_ARRAY(name, idx, pin, max_entries) \\",
            "struct { \\",
            "\t__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \\",
            "\t__uint(max_entries, max_entries); \\",
            "\t__type(key, __u32); \\",
            "\t__type(value, __u32); \\",
            "} name SEC(\".maps\")",
            "#endif",
            "#ifndef __BPF_MAP",
            "#define __BPF_MAP(name, map_type, index, key_size, value_size, pinning, max_entries) \\",
            "struct { \\",
            "\t__uint(type, map_type); \\",
            "\t__uint(max_entries, max_entries); \\",
            "\t__type(key, __u32); \\",
            "\t__type(value, __u64); \\",
            "\t__uint(pinning, LIBBPF_PIN_BY_NAME); \\",
            "} name SEC(\".maps\")",
            "#endif",
            "#ifndef map_lookup_elem",
            "#define map_lookup_elem bpf_map_lookup_elem",
            "#endif",
            "#ifndef map_update_elem",
            "#define map_update_elem bpf_map_update_elem",
            "#endif",
            "#ifndef tail_call",
            "#define tail_call(ctx, map, slot) bpf_tail_call(ctx, map, slot)",
            "#endif",
            "#ifndef redirect",
            "#define redirect(ifindex, flags) bpf_redirect(ifindex, flags)",
            "#endif",
            "#ifndef datapath_redirect",
            "#define datapath_redirect(ifindex, flags) bpf_redirect(ifindex, flags)",
            "#endif",
            "#ifndef load_byte",
            "#define load_byte(ctx, off) 0",
            "#endif",
            "#define send_drop_notify(...) TC_ACT_SHOT",
            "#define send_drop_notify_error(...) TC_ACT_SHOT",
            "#define send_trace_notify(...) 0",
            "#define cilium_trace(...) 0",
            "#define cilium_dbg_capture(...) do { } while (0)",
            "#define cilium_trace_capture(...) do { } while (0)",
            "#define policy_mark_skip(...) do { } while (0)",
            "#define policy_clear_mark(...) do { } while (0)",
            "#define bpf_clear_meta(...) do { } while (0)",
            "#define bpf_clear_cb(...) do { } while (0)",
            "#define ep_tail_call(...) do { } while (0)",
            "#define invoke_tailcall_if(...) do { } while (0)",
            "#define relax_verifier() do { } while (0)",
            "",
        ]
    )


def extract_program_name(text: str) -> str:
    bpf_prog_match = BPF_PROG_RE.search(text)
    if bpf_prog_match:
        return bpf_prog_match.group("name")
    prog_match = PROG_NAME_RE.search(text)
    if prog_match:
        return prog_match.group("name")
    func_match = FUNC_DEF_RE.search(text)
    if func_match:
        return func_match.group("name")
    return "prog"


def find_first_callable(text: str) -> tuple[str, str, str] | None:
    for match in FUNC_DEF_RE.finditer(text):
        name = match.group("name")
        if name in {"if", "for", "while", "switch"}:
            continue
        return (match.group("ret").strip(), name, match.group("params").strip())
    return None


def normalize_param_type(param: str) -> str:
    text = " ".join(param.strip().split())
    if text in {"", "void"}:
        return ""
    text = re.sub(r"\[[^\]]*\]$", "", text)
    text = re.sub(r"\s+[A-Za-z_][A-Za-z0-9_]*$", "", text)
    return text.strip()


def default_argument_for_param(param: str) -> str:
    clean = " ".join(param.strip().split())
    if not clean or clean == "void":
        return ""
    param_type = normalize_param_type(clean)
    if "*" in clean or clean.endswith("]"):
        return "NULL"
    if re.search(r"\bbool\b", clean):
        return "false"
    if param_type.startswith(("struct ", "union ")):
        return f"({param_type}){{0}}"
    if re.search(r"\b(?:enum|int|short|long|char|size_t|ssize_t|pid_t|u8|u16|u32|u64|s8|s16|s32|s64|__u8|__u16|__u32|__u64|__s8|__s16|__s32|__s64|bool)\b", clean):
        return "0"
    if param_type:
        return f"({param_type})0"
    return "0"


def build_wrapper(text: str) -> str:
    callable_info = find_first_callable(text)
    if callable_info:
        ret_type, func_name, params = callable_info
        args = [default_argument_for_param(part) for part in params.split(",") if default_argument_for_param(part)]
        call_expr = f"{func_name}({', '.join(args)})"
        body_lines = ["\t(void)ctx;"]
        if "void" in ret_type.split():
            body_lines.append(f"\t{call_expr};")
            body_lines.append("\treturn XDP_PASS;")
        else:
            body_lines.append(f"\treturn (int){call_expr};")
        body = "\n".join(body_lines)
    else:
        indented = "\n".join(f"\t{line}" if line else "" for line in text.splitlines())
        body = "\n".join(["\t(void)ctx;", indented, "\treturn XDP_PASS;"]).rstrip()
    return "\n".join(
        [
            'SEC("xdp")',
            "int prog(struct xdp_md *ctx)",
            "{",
            body,
            "}",
        ]
    )


def build_compile_unit(case: CaseRecord) -> CompileUnit:
    selected_file, fragment_text, fragment_index, selection_score = choose_compile_fragment(case)
    normalized = strip_marker_lines(fragment_text)
    normalized = sanitize_includes(normalized)
    normalized = trim_leading_fragment(normalized)
    normalized, effective_section = rewrite_custom_sections(normalized)
    normalized, had_bpf_license_macro = rewrite_bpf_license(normalized)

    use_wrapper = not has_annotated_program(normalized)
    use_compat = needs_compat_prelude(normalized)
    include_headers = (not has_include_statements(normalized)) or use_compat or use_wrapper

    pieces: list[str] = []
    if include_headers:
        pieces.append(standard_header_block().rstrip())
    if use_compat:
        pieces.append(compat_prelude_block().rstrip())

    if use_wrapper:
        if find_first_callable(normalized):
            pieces.append(normalized.rstrip())
            pieces.append(build_wrapper(normalized))
        else:
            pieces.append(build_wrapper(normalized))
        program_name = "prog"
        effective_section = effective_section or "xdp"
    else:
        pieces.append(normalized.rstrip())
        program_name = extract_program_name(normalized)

    if not has_license_section("\n\n".join(pieces)) and not had_bpf_license_macro:
        pieces.append('char __license[] SEC("license") = "GPL";')

    source_text = "\n\n".join(piece for piece in pieces if piece).rstrip() + "\n"
    return CompileUnit(
        source_text=source_text,
        program_name=program_name,
        selected_file=selected_file,
        selected_fragment_index=fragment_index,
        selection_score=selection_score,
        used_wrapper=use_wrapper,
        used_compat_prelude=use_compat,
        effective_section=effective_section,
    )


def compile_source(
    source_path: Path,
    object_path: Path,
    *,
    work_dir: Path,
    kernel_root: Path,
    libbpf_include_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    arch_macro: str,
    bpf_target: str,
) -> CompileResult:
    args = [
        clang,
        "-O2",
        "-g",
        "-std=gnu11",
        f"--target={bpf_target}",
        f"-D__TARGET_ARCH_{arch_macro}",
        f"-I{source_path.parent}",
        f"-I{work_dir / 'include'}",
        f"-I{libbpf_include_dir}",
        f"-I{kernel_root / 'tools' / 'include' / 'uapi'}",
        f"-I{kernel_root / 'tools' / 'include'}",
        f"-I{kernel_root / 'include' / 'uapi'}",
        f"-I{kernel_root / 'include'}",
        f"-I{kernel_root / 'arch' / arch_macro / 'include'}",
        *clang_sys_includes,
        "-c",
        str(source_path),
        "-o",
        str(object_path),
    ]
    completed = run_command(args, timeout=COMPILE_TIMEOUT_SECONDS)
    return CompileResult(
        ok=completed.returncode == 0,
        object_path=object_path if completed.returncode == 0 else None,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        source_path=source_path,
    )


def run_loader(helper_bin: Path, object_path: Path, program_name: str) -> LoadResult:
    completed = run_command(
        ["sudo", "-n", str(helper_bin), str(object_path), program_name],
        timeout=LOAD_TIMEOUT_SECONDS,
    )
    parsed: dict[str, Any] | None = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return LoadResult(
        ok=completed.returncode == 0,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        parsed=parsed,
    )


def normalized_compile_failure(stderr: str) -> str:
    for line in stderr.splitlines():
        stripped = line.strip()
        if "timed out after" in stripped:
            return stripped
        if "fatal error:" in stripped:
            return stripped.split("fatal error:", 1)[1].strip()
    for line in stderr.splitlines():
        stripped = line.strip()
        if ": error:" in stripped:
            return stripped.split(": error:", 1)[1].strip()
    return next((line.strip() for line in stderr.splitlines() if line.strip()), "unknown compile error")


def normalize_verifier_log_text(verifier_log: str) -> str:
    lines = [line.rstrip() for line in verifier_log.splitlines()]
    return "\n".join(lines).rstrip()


def replace_verifier_log(payload: dict[str, Any], verifier_log: str) -> dict[str, Any]:
    new_payload: dict[str, Any] = {}
    inserted = False
    for key, value in payload.items():
        if key == VERIFIER_LOG_STYLE_KEY:
            continue
        new_payload[key] = value
        if key == "fix_description":
            new_payload[VERIFIER_LOG_STYLE_KEY] = LiteralString(verifier_log)
            inserted = True
    if not inserted:
        new_payload[VERIFIER_LOG_STYLE_KEY] = LiteralString(verifier_log)
    return new_payload


def update_case_yaml(case_path: Path, verifier_log: str) -> bool:
    raw_text = case_path.read_text()
    payload = yaml.safe_load(raw_text)
    if not isinstance(payload, dict):
        return False
    normalized_log = normalize_verifier_log_text(verifier_log)
    current_log = payload.get(VERIFIER_LOG_STYLE_KEY)
    if isinstance(current_log, str) and normalize_verifier_log_text(current_log) == normalized_log:
        return False
    updated = replace_verifier_log(payload, normalized_log)
    with case_path.open("w", encoding="utf-8") as handle:
        yaml.dump(updated, handle, Dumper=LiteralDumper, sort_keys=False, allow_unicode=False, width=1000)
    return True


def case_score_for_pilot(case: CaseRecord) -> tuple[int, int, str]:
    _label, text, fragment_index, segment_score_value = choose_compile_fragment(case)
    normalized = strip_marker_lines(text)
    normalized = trim_leading_fragment(normalized)
    score = segment_score_value
    if count_file_markers(case.source_snippet) == 1:
        score += 4
    if has_annotated_program(normalized):
        score += 5
    if "BPF_PROG(" in normalized:
        score += 3
    if "struct __sk_buff" in normalized or "struct xdp_md" in normalized or "struct bpf_sock_addr" in normalized:
        score += 2
    line_count = max(len(normalized.splitlines()), 1)
    score -= min(line_count // 40, 6)
    return score, fragment_index, case.case_id


def select_pilot_cases(cases: list[CaseRecord], pilot_per_fix_type: int) -> list[CaseRecord]:
    selected: list[CaseRecord] = []
    by_fix_type: dict[str, list[CaseRecord]] = {fix_type: [] for fix_type in PILOT_FIX_TYPES}
    for case in cases:
        if case.fix_type in by_fix_type:
            by_fix_type[case.fix_type].append(case)

    for fix_type in PILOT_FIX_TYPES:
        candidates = by_fix_type.get(fix_type, [])
        if len(candidates) < pilot_per_fix_type:
            raise SystemExit(
                f"Fix type {fix_type!r} has only {len(candidates)} cases; need {pilot_per_fix_type} for the pilot."
            )
        scored = [(case_score_for_pilot(case), case) for case in candidates]
        scored.sort(key=lambda item: (-item[0][0], item[0][1], item[0][2]))
        chosen = [case for _, case in scored[:pilot_per_fix_type]]
        selected.extend(chosen)
    return sorted(selected, key=lambda case: (PILOT_FIX_TYPES.index(case.fix_type), case.case_id))


def summarize_results(results: list[CaseRunResult]) -> dict[str, Any]:
    total = len(results)
    compile_ok = sum(1 for item in results if item.compile_ok)
    load_attempted = compile_ok
    load_ok = sum(1 for item in results if item.load_ok is True)
    load_failed = sum(1 for item in results if item.load_ok is False)
    logs_captured = sum(1 for item in results if item.verifier_log_length > 0)
    rejected_logs_captured = sum(1 for item in results if item.load_ok is False and item.verifier_log_length > 0)
    yaml_updates = sum(1 for item in results if item.yaml_updated)

    by_fix_type: dict[str, dict[str, Any]] = {}
    for fix_type in sorted({item.fix_type for item in results}):
        subset = [item for item in results if item.fix_type == fix_type]
        subset_compile_ok = sum(1 for item in subset if item.compile_ok)
        subset_load_attempted = subset_compile_ok
        subset_load_ok = sum(1 for item in subset if item.load_ok is True)
        subset_load_failed = sum(1 for item in subset if item.load_ok is False)
        subset_logs = sum(1 for item in subset if item.verifier_log_length > 0)
        by_fix_type[fix_type] = {
            "cases": len(subset),
            "compile_ok": subset_compile_ok,
            "compile_rate": round(subset_compile_ok / len(subset), 4) if subset else 0.0,
            "load_attempted": subset_load_attempted,
            "load_ok": subset_load_ok,
            "load_failed": subset_load_failed,
            "load_failure_rate": round(subset_load_failed / subset_load_attempted, 4)
            if subset_load_attempted
            else 0.0,
            "verifier_logs": subset_logs,
            "verifier_log_capture_rate": round(subset_logs / subset_load_attempted, 4)
            if subset_load_attempted
            else 0.0,
        }

    load_error_distribution = Counter(
        item.error_message for item in results if item.compile_ok and item.load_ok is not None
    )
    compile_failure_distribution = Counter(
        item.error_message for item in results if not item.compile_ok
    )
    false_negatives = [asdict(item) for item in results if item.compile_ok and item.load_ok is True]

    return {
        "cases": total,
        "compile_ok": compile_ok,
        "compile_rate": round(compile_ok / total, 4) if total else 0.0,
        "load_attempted": load_attempted,
        "load_ok": load_ok,
        "load_failed": load_failed,
        "load_failure_rate": round(load_failed / load_attempted, 4) if load_attempted else 0.0,
        "verifier_logs": logs_captured,
        "rejected_verifier_logs": rejected_logs_captured,
        "verifier_log_capture_rate": round(rejected_logs_captured / load_attempted, 4) if load_attempted else 0.0,
        "yaml_updates": yaml_updates,
        "by_fix_type": by_fix_type,
        "load_error_distribution": load_error_distribution.most_common(),
        "compile_failure_distribution": compile_failure_distribution.most_common(),
        "false_negatives": false_negatives,
    }


def markdown_percentage(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.0%"
    return f"{(100.0 * numerator / denominator):.1f}%"


def render_fix_type_table(summary: dict[str, Any]) -> str:
    lines = [
        "| fix_type | cases | compile_ok | compile_rate | load_failed | load_failure_rate | verifier_logs | log_capture_rate |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    by_fix_type = summary["by_fix_type"]
    for fix_type in sorted(by_fix_type):
        row = by_fix_type[fix_type]
        lines.append(
            "| {fix_type} | {cases} | {compile_ok} | {compile_rate} | {load_failed} | {load_failure_rate} | {verifier_logs} | {log_capture_rate} |".format(
                fix_type=fix_type,
                cases=row["cases"],
                compile_ok=row["compile_ok"],
                compile_rate=markdown_percentage(row["compile_ok"], row["cases"]),
                load_failed=row["load_failed"],
                load_failure_rate=markdown_percentage(row["load_failed"], row["load_attempted"]),
                verifier_logs=row["verifier_logs"],
                log_capture_rate=markdown_percentage(row["verifier_logs"], row["load_attempted"]),
            )
        )
    return "\n".join(lines)


def render_distribution_table(title: str, rows: list[tuple[str, int]], limit: int = 15) -> str:
    lines = [f"### {title}", "", "| message | count |", "| --- | ---: |"]
    if not rows:
        lines.append("| none | 0 |")
        return "\n".join(lines)
    for message, count in rows[:limit]:
        safe = message.replace("\n", " ").strip()
        lines.append(f"| `{safe}` | {count} |")
    return "\n".join(lines)


def render_false_negative_list(results: list[dict[str, Any]]) -> str:
    if not results:
        return "- None."
    lines = []
    for result in results:
        lines.append(
            f"- `{result['case_id']}` (`{result['fix_type']}`) loaded successfully via `{result['program_name']}` "
            f"from `{result['selected_file']}`."
        )
    return "\n".join(lines)


def build_report(
    *,
    versions: ToolVersions,
    cases_root: Path,
    pilot_cases: list[CaseRecord],
    pilot_summary: dict[str, Any],
    pilot_results: list[CaseRunResult],
    full_summary: dict[str, Any] | None,
    full_results: list[CaseRunResult] | None,
    full_skipped_reason: str | None,
    started_at: datetime,
    finished_at: datetime,
) -> str:
    lines: list[str] = []
    lines.append("# Synthetic Compilation Report")
    lines.append("")
    lines.append(f"Run date: {finished_at.astimezone(UTC).date().isoformat()}")
    lines.append("")
    lines.append("## Environment")
    lines.append("")
    lines.append(f"- Cases root: `{cases_root}`")
    lines.append(f"- Host kernel: `{versions.kernel_release}`")
    lines.append(f"- Clang: `{versions.clang}`")
    lines.append(f"- bpftool: `{versions.bpftool}`")
    lines.append(f"- Loader: `{HELPER_SOURCE}`")
    lines.append(f"- Pilot shape: 5 each of `{', '.join(PILOT_FIX_TYPES)}` ({len(pilot_cases)} total)")
    lines.append("- Multi-file snippets were reduced to the highest-scoring BPF-like `// FILE:` fragment before compilation.")
    lines.append("- Custom Cilium-style section macros were rewritten to loadable libbpf sections when possible.")
    lines.append("")
    lines.append("## Pilot Results")
    lines.append("")
    lines.append(f"- Cases attempted: {pilot_summary['cases']}")
    lines.append(
        f"- Compile success: {pilot_summary['compile_ok']}/{pilot_summary['cases']} "
        f"({markdown_percentage(pilot_summary['compile_ok'], pilot_summary['cases'])})"
    )
    lines.append(
        f"- Load failure: {pilot_summary['load_failed']}/{pilot_summary['load_attempted']} "
        f"({markdown_percentage(pilot_summary['load_failed'], pilot_summary['load_attempted'])})"
    )
    lines.append(
        f"- Verifier logs captured on rejected loads: {pilot_summary['rejected_verifier_logs']}/{pilot_summary['load_attempted']} "
        f"({markdown_percentage(pilot_summary['rejected_verifier_logs'], pilot_summary['load_attempted'])})"
    )
    lines.append(f"- YAML files updated with verifier logs: {pilot_summary['yaml_updates']}")
    lines.append("")
    lines.append(render_fix_type_table(pilot_summary))
    lines.append("")
    pilot_case_ids = ", ".join(f"`{case.case_id}`" for case in pilot_cases)
    lines.append("### Pilot Cases")
    lines.append("")
    lines.append(pilot_case_ids)
    lines.append("")
    lines.append(render_distribution_table("Pilot Compile Failures", pilot_summary["compile_failure_distribution"]))
    lines.append("")
    lines.append(render_distribution_table("Pilot Loader Error Messages", pilot_summary["load_error_distribution"]))
    lines.append("")
    lines.append("### Pilot False Negatives")
    lines.append("")
    lines.append(render_false_negative_list(pilot_summary["false_negatives"]))
    lines.append("")
    if full_summary is None:
        lines.append("## Full Run")
        lines.append("")
        lines.append(f"- Skipped. {full_skipped_reason}")
        lines.append("")
    else:
        lines.append("## Full Run")
        lines.append("")
        lines.append(f"- Cases attempted: {full_summary['cases']}")
        lines.append(
            f"- Compile success: {full_summary['compile_ok']}/{full_summary['cases']} "
            f"({markdown_percentage(full_summary['compile_ok'], full_summary['cases'])})"
        )
        lines.append(
            f"- Load failure: {full_summary['load_failed']}/{full_summary['load_attempted']} "
            f"({markdown_percentage(full_summary['load_failed'], full_summary['load_attempted'])})"
        )
        lines.append(
            f"- Verifier logs captured on rejected loads: {full_summary['rejected_verifier_logs']}/{full_summary['load_attempted']} "
            f"({markdown_percentage(full_summary['rejected_verifier_logs'], full_summary['load_attempted'])})"
        )
        lines.append(f"- YAML files updated with verifier logs: {full_summary['yaml_updates']}")
        lines.append("")
        lines.append(render_fix_type_table(full_summary))
        lines.append("")
        lines.append(render_distribution_table("Full Compile Failures", full_summary["compile_failure_distribution"]))
        lines.append("")
        lines.append(render_distribution_table("Full Loader Error Messages", full_summary["load_error_distribution"]))
        lines.append("")
        lines.append("### Full False Negatives")
        lines.append("")
        lines.append(render_false_negative_list(full_summary["false_negatives"]))
        lines.append("")
    lines.append("## Timing")
    lines.append("")
    lines.append(f"- Started: {started_at.astimezone(UTC).isoformat()}")
    lines.append(f"- Finished: {finished_at.astimezone(UTC).isoformat()}")
    lines.append(f"- Duration seconds: {(finished_at - started_at).total_seconds():.1f}")
    lines.append("")
    return "\n".join(lines)


def compile_and_load_case(
    case: CaseRecord,
    *,
    batch: str,
    work_dir: Path,
    kernel_root: Path,
    libbpf_include_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    arch_macro: str,
    bpf_target: str,
    helper_bin: Path,
    keep_workdir: bool,
) -> CaseRunResult:
    compile_unit = build_compile_unit(case)

    if keep_workdir:
        case_dir = work_dir / "artifacts" / batch / case.case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        cleanup_context = None
    else:
        cleanup_context = tempfile.TemporaryDirectory(prefix=f"{case.case_id}-", dir=work_dir / "tmp")
        case_dir = Path(cleanup_context.__enter__())

    try:
        source_path = case_dir / f"{case.case_id}.bpf.c"
        object_path = case_dir / f"{case.case_id}.bpf.o"
        source_path.write_text(compile_unit.source_text, encoding="utf-8")

        compile_result = compile_source(
            source_path,
            object_path,
            work_dir=work_dir,
            kernel_root=kernel_root,
            libbpf_include_dir=libbpf_include_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
        )
        if not compile_result.ok or not compile_result.object_path:
            return CaseRunResult(
                case_id=case.case_id,
                case_path=str(case.path),
                fix_type=case.fix_type,
                batch=batch,
                compile_ok=False,
                load_ok=None,
                verifier_log_length=0,
                error_message=normalized_compile_failure(compile_result.stderr),
                program_name=compile_unit.program_name,
                selected_file=compile_unit.selected_file,
                selected_fragment_index=compile_unit.selected_fragment_index,
                selection_score=compile_unit.selection_score,
                used_wrapper=compile_unit.used_wrapper,
                used_compat_prelude=compile_unit.used_compat_prelude,
                effective_section=compile_unit.effective_section,
                yaml_updated=False,
            )

        load_result = run_loader(helper_bin, compile_result.object_path, compile_unit.program_name)
        verifier_log = load_result.verifier_log
        yaml_updated = False
        if verifier_log and not load_result.load_ok:
            yaml_updated = update_case_yaml(case.path, verifier_log)

        return CaseRunResult(
            case_id=case.case_id,
            case_path=str(case.path),
            fix_type=case.fix_type,
            batch=batch,
            compile_ok=True,
            load_ok=load_result.load_ok,
            verifier_log_length=len(verifier_log),
            error_message=load_result.error_message,
            program_name=compile_unit.program_name,
            selected_file=compile_unit.selected_file,
            selected_fragment_index=compile_unit.selected_fragment_index,
            selection_score=compile_unit.selection_score,
            used_wrapper=compile_unit.used_wrapper,
            used_compat_prelude=compile_unit.used_compat_prelude,
            effective_section=compile_unit.effective_section,
            yaml_updated=yaml_updated,
        )
    finally:
        if cleanup_context is not None:
            cleanup_context.__exit__(None, None, None)


def process_cases(
    cases: list[CaseRecord],
    *,
    batch: str,
    existing_results: dict[str, CaseRunResult] | None,
    work_dir: Path,
    kernel_root: Path,
    libbpf_include_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    arch_macro: str,
    bpf_target: str,
    helper_bin: Path,
    keep_workdir: bool,
) -> list[CaseRunResult]:
    result_map = dict(existing_results or {})
    pending_cases = [case for case in cases if case.case_id not in result_map]
    total = len(cases)
    for index, case in enumerate(cases, start=1):
        if case.case_id in result_map:
            continue
        if index % 20 == 0 or index == 1 or index == total:
            emit(f"[{batch}] progress {index}/{total}: processing {case.case_id}")
        result_map[case.case_id] = compile_and_load_case(
            case,
            batch=batch,
            work_dir=work_dir,
            kernel_root=kernel_root,
            libbpf_include_dir=libbpf_include_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
            helper_bin=helper_bin,
            keep_workdir=keep_workdir,
        )
    ordered = [result_map[case.case_id] for case in cases]
    if pending_cases:
        emit(f"[{batch}] completed {len(pending_cases)} new case(s)")
    return ordered


def main() -> int:
    args = parse_args()
    started_at = datetime.now(UTC)
    if not args.cases_root.exists():
        raise SystemExit(f"Cases root not found: {args.cases_root}")
    if not args.kernel_root.exists():
        raise SystemExit(f"Kernel root not found: {args.kernel_root}")

    args.work_dir.mkdir(parents=True, exist_ok=True)
    (args.work_dir / "tmp").mkdir(parents=True, exist_ok=True)

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found in PATH")
    arch_macro, bpf_target = host_arch_macro()
    ensure_kernel_paths(args.kernel_root, arch_macro)
    ensure_sudo_available()
    helper_bin = ensure_helper_binary(args.work_dir)
    ensure_vmlinux_header(args.work_dir)
    libbpf_include_dir = ensure_libbpf_headers(args.kernel_root, args.work_dir)
    clang_sys_includes = collect_clang_sys_includes(clang)
    versions = detect_versions(clang)

    all_cases = load_cases(args.cases_root)
    pilot_cases = select_pilot_cases(all_cases, args.pilot_per_fix_type)
    emit(f"Loaded {len(all_cases)} synthetic cases; pilot will process {len(pilot_cases)} cases")

    pilot_results = process_cases(
        pilot_cases,
        batch="pilot",
        existing_results=None,
        work_dir=args.work_dir,
        kernel_root=args.kernel_root,
        libbpf_include_dir=libbpf_include_dir,
        clang=clang,
        clang_sys_includes=clang_sys_includes,
        arch_macro=arch_macro,
        bpf_target=bpf_target,
        helper_bin=helper_bin,
        keep_workdir=args.keep_workdir,
    )
    pilot_summary = summarize_results(pilot_results)

    full_results: list[CaseRunResult] | None = None
    full_summary: dict[str, Any] | None = None
    full_skipped_reason: str | None = None

    if args.pilot_only:
        full_skipped_reason = "Pilot-only mode was requested."
    elif pilot_summary["compile_rate"] <= args.pilot_threshold:
        full_skipped_reason = (
            f"Pilot compile success was {markdown_percentage(pilot_summary['compile_ok'], pilot_summary['cases'])}, "
            f"which did not exceed the required {100.0 * args.pilot_threshold:.1f}% threshold."
        )
        emit(full_skipped_reason)
    else:
        emit(
            f"Pilot compile success reached {markdown_percentage(pilot_summary['compile_ok'], pilot_summary['cases'])}; "
            f"scaling to all {len(all_cases)} cases"
        )
        cached = {result.case_id: result for result in pilot_results}
        full_results = process_cases(
            all_cases,
            batch="full",
            existing_results=cached,
            work_dir=args.work_dir,
            kernel_root=args.kernel_root,
            libbpf_include_dir=libbpf_include_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
            helper_bin=helper_bin,
            keep_workdir=args.keep_workdir,
        )
        full_summary = summarize_results(full_results)

    finished_at = datetime.now(UTC)

    report_text = build_report(
        versions=versions,
        cases_root=args.cases_root,
        pilot_cases=pilot_cases,
        pilot_summary=pilot_summary,
        pilot_results=pilot_results,
        full_summary=full_summary,
        full_results=full_results,
        full_skipped_reason=full_skipped_reason,
        started_at=started_at,
        finished_at=finished_at,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report_text, encoding="utf-8")

    results_payload = {
        "generated_at": finished_at.isoformat(),
        "environment": asdict(versions),
        "paths": {
            "cases_root": str(args.cases_root),
            "kernel_root": str(args.kernel_root),
            "report": str(args.report),
            "work_dir": str(args.work_dir),
        },
        "pilot": {
            "selected_case_ids": [case.case_id for case in pilot_cases],
            "summary": pilot_summary,
            "results": [asdict(result) for result in pilot_results],
        },
        "full_run": {
            "performed": full_results is not None,
            "skipped_reason": full_skipped_reason,
            "summary": full_summary,
            "results": [asdict(result) for result in full_results] if full_results is not None else None,
        },
    }
    args.results_json.parent.mkdir(parents=True, exist_ok=True)
    args.results_json.write_text(json.dumps(results_payload, indent=2, sort_keys=False), encoding="utf-8")

    emit(f"Wrote report to {args.report}")
    emit(f"Wrote results to {args.results_json}")

    if not args.keep_workdir:
        shutil.rmtree(args.work_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
