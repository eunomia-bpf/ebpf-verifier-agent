#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from capture_kernel_selftests_verifier_logs import (
    collect_clang_sys_includes,
    ensure_helper_binary,
    ensure_kernel_paths,
    ensure_libbpf_headers,
    host_arch_macro,
    ProgramKey,
    run_loader,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
GROUND_TRUTH_PATH = ROOT_DIR / "case_study" / "ground_truth.yaml"
CASE_YAML_ROOT = ROOT_DIR / "case_study" / "cases" / "kernel_selftests"
DEFAULT_KERNEL_ROOT = Path("/tmp/linux-selftests")
DEFAULT_OUTPUT_ROOT = ROOT_DIR / "case_study" / "cases" / "kernel_selftests_verified"
DEFAULT_REPORT_PATH = ROOT_DIR / "docs" / "tmp" / "selftest-verification.md"
HELPER_SOURCE = ROOT_DIR / "case_study" / "selftest_prog_loader.c"
VMLINUX_BTF = Path("/sys/kernel/btf/vmlinux")
SYSTEM_VMLINUX = Path("/usr/include/vmlinux.h")
VMLINUX_SANITIZED_NAME = "vmlinux.h"
VMLINUX_KSYM_RE = re.compile(r"^\s*extern\b.*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*__ksym\s*;\s*$")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
TRACE_PREFIX_RE = re.compile(r"^\s*(func#|Live regs before insn:|mark_precise:|;|\d+:)")
PROCESSED_RE = re.compile(r"^processed\s+\d+\s+insns")
ANNOTATION_LINE_RE = re.compile(
    r"^\s*__(failure(?:_unpriv)?|success(?:_unpriv)?|msg(?:_unpriv)?|description|retval|flag|log_level|exception_cb)\b"
)


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    case_yaml: Path
    selftest_file: str
    function: str
    section: str
    expected_messages: tuple[str, ...]
    yaml_verifier_log: str


@dataclass(frozen=True)
class Chunk:
    text: str
    kind: str
    function_name: str | None = None
    is_sec_program: bool = False


@dataclass
class CaseResult:
    case: CaseRecord
    source_found: bool
    reduced_programs_retained: int
    compile_ok: bool
    load_attempted: bool
    rejected: bool
    verifier_log_captured: bool
    expected_message_match: bool
    diagnostic_tail_match: bool
    exact_log_match: bool
    compile_error: str = ""
    load_error: str = ""
    notes: list[str] | None = None

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build self-contained per-case kernel selftest artifacts for the 85 intentional "
            "negative benchmark cases and verify them locally."
        )
    )
    parser.add_argument(
        "--kernel-root",
        type=Path,
        default=DEFAULT_KERNEL_ROOT,
        help="Sparse Linux checkout root. Default: /tmp/linux-selftests",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Output directory for per-case artifacts.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Markdown summary report path.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("/tmp/kernel-selftests-verified-work"),
        help="Scratch directory for generated headers, depfiles, and temporary objects.",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Limit the run to specific case IDs. May be repeated.",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep the temporary work directory after the run.",
    )
    return parser.parse_args()


def emit(message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def prepare_kernel_checkout(kernel_root: Path, arch_macro: str) -> Path:
    sparse_paths = [
        "tools/testing/selftests/bpf",
        "tools/lib/bpf",
        "tools/include",
        "tools/build",
        "tools/scripts",
        "scripts",
        f"tools/arch/{arch_macro}/include",
    ]
    if kernel_root.exists():
        if not (kernel_root / ".git").exists():
            raise SystemExit(f"{kernel_root} exists but is not a git checkout")
        emit(f"Using existing kernel sparse checkout at {kernel_root}")
        ensure_kernel_paths(kernel_root, arch_macro)
        return kernel_root

    emit(f"Cloning Linux selftests into {kernel_root}")
    kernel_root.parent.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--no-checkout",
            "https://github.com/torvalds/linux.git",
            str(kernel_root),
        ],
        check=True,
    )
    run_command(["git", "-C", str(kernel_root), "sparse-checkout", "init", "--cone"], check=True)
    run_command(
        ["git", "-C", str(kernel_root), "sparse-checkout", "set", *sparse_paths],
        check=True,
    )
    run_command(["git", "-C", str(kernel_root), "checkout"], check=True)
    ensure_kernel_paths(kernel_root, arch_macro)
    return kernel_root


def load_case_records(selected_case_ids: set[str] | None) -> list[CaseRecord]:
    payload = yaml.safe_load(GROUND_TRUTH_PATH.read_text())
    raw_cases = payload.get("cases") or []
    case_ids: list[str] = []
    for entry in raw_cases:
        case_id = str(entry.get("case_id", ""))
        if not case_id.startswith("kernel-selftest-"):
            continue
        if not entry.get("is_intentional_negative_test"):
            continue
        if selected_case_ids and case_id not in selected_case_ids:
            continue
        case_ids.append(case_id)

    records: list[CaseRecord] = []
    for case_id in sorted(case_ids):
        case_yaml = CASE_YAML_ROOT / f"{case_id}.yaml"
        if not case_yaml.exists():
            raise SystemExit(f"Missing case YAML for {case_id}: {case_yaml}")
        case_payload = yaml.safe_load(case_yaml.read_text())
        selftest = case_payload.get("selftest") or {}
        expected = case_payload.get("expected_verifier_messages") or {}
        records.append(
            CaseRecord(
                case_id=case_id,
                case_yaml=case_yaml,
                selftest_file=str(selftest.get("file", "")),
                function=str(selftest.get("function", "")),
                section=str(selftest.get("section", "")),
                expected_messages=tuple(str(msg) for msg in (expected.get("combined") or [])),
                yaml_verifier_log=str(case_payload.get("verifier_log", "") or ""),
            )
        )

    if not records:
        raise SystemExit("No intentional negative kernel selftest cases selected.")
    return records


def collect_selftest_declared_ksyms(kernel_root: Path) -> set[str]:
    declared: set[str] = set()
    header_roots = [
        kernel_root / "tools" / "testing" / "selftests" / "bpf",
        kernel_root / "tools" / "testing" / "selftests" / "bpf" / "progs",
    ]
    decl_re = re.compile(
        r"\bextern\b[\s\S]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*?__ksym\b",
        re.MULTILINE,
    )
    for header_root in header_roots:
        if not header_root.exists():
            continue
        for header_path in header_root.rglob("*.h"):
            if not header_path.exists():
                continue
            text = header_path.read_text(encoding="utf-8", errors="replace")
            for match in decl_re.finditer(text):
                declared.add(match.group(1))
    return declared


def ensure_sanitized_vmlinux_header(work_dir: Path, kernel_root: Path) -> Path:
    include_dir = work_dir / "include"
    include_dir.mkdir(parents=True, exist_ok=True)
    output_path = include_dir / VMLINUX_SANITIZED_NAME
    if output_path.exists():
        return output_path

    if not VMLINUX_BTF.exists():
        if not SYSTEM_VMLINUX.exists():
            raise SystemExit(f"Missing both {SYSTEM_VMLINUX} and {VMLINUX_BTF}")
        emit(f"Falling back to system vmlinux.h from {SYSTEM_VMLINUX}")
        source_text = SYSTEM_VMLINUX.read_text(encoding="utf-8", errors="replace")
    else:
        emit(f"Generating vmlinux.h from {VMLINUX_BTF}")
        completed = run_command(
            ["bpftool", "btf", "dump", "file", str(VMLINUX_BTF), "format", "c"],
            check=True,
        )
        source_text = completed.stdout

    duplicate_ksyms = collect_selftest_declared_ksyms(kernel_root)
    sanitized_lines: list[str] = []
    for line in source_text.splitlines():
        match = VMLINUX_KSYM_RE.match(line)
        if match and match.group(1) in duplicate_ksyms:
            continue
        sanitized_lines.append(line)
    output_path.write_text("\n".join(sanitized_lines) + "\n", encoding="utf-8")
    return output_path


def split_top_level_chunks(text: str) -> list[Chunk]:
    chunks: list[Chunk] = []
    length = len(text)
    index = 0

    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        start = index

        if text[index] == "#":
            end = index
            while end < length:
                newline = text.find("\n", end)
                if newline == -1:
                    end = length
                    break
                if newline > start and text[newline - 1] == "\\":
                    end = newline + 1
                    continue
                end = newline + 1
                break
            chunks.append(Chunk(text=text[start:end], kind="preprocessor"))
            index = end
            continue

        brace_depth = 0
        paren_depth = 0
        bracket_depth = 0
        in_string = False
        in_char = False
        line_comment = False
        block_comment = False
        cursor = index

        while cursor < length:
            char = text[cursor]
            next_char = text[cursor + 1] if cursor + 1 < length else ""

            if line_comment:
                if char == "\n":
                    line_comment = False
                cursor += 1
                continue
            if block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    cursor += 2
                    continue
                cursor += 1
                continue
            if in_string:
                if char == "\\":
                    cursor += 2
                    continue
                if char == '"':
                    in_string = False
                cursor += 1
                continue
            if in_char:
                if char == "\\":
                    cursor += 2
                    continue
                if char == "'":
                    in_char = False
                cursor += 1
                continue

            if char == "/" and next_char == "/":
                line_comment = True
                cursor += 2
                continue
            if char == "/" and next_char == "*":
                block_comment = True
                cursor += 2
                continue
            if char == '"':
                in_string = True
                cursor += 1
                continue
            if char == "'":
                in_char = True
                cursor += 1
                continue

            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(paren_depth - 1, 0)
            elif char == "[":
                bracket_depth += 1
            elif char == "]":
                bracket_depth = max(bracket_depth - 1, 0)
            elif char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth = max(brace_depth - 1, 0)
                if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                    lookahead = cursor + 1
                    while lookahead < length and text[lookahead].isspace():
                        lookahead += 1
                    if lookahead < length and text[lookahead] == ";":
                        end = lookahead + 1
                        chunk_text = text[start:end]
                        chunks.append(classify_chunk(chunk_text))
                        index = end
                        break
                    end = cursor + 1
                    chunk_text = text[start:end]
                    chunks.append(classify_chunk(chunk_text))
                    index = end
                    break
            elif char == ";" and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                end = cursor + 1
                chunk_text = text[start:end]
                chunks.append(classify_chunk(chunk_text))
                index = end
                break

            cursor += 1
        else:
            chunk_text = text[start:length]
            chunks.append(classify_chunk(chunk_text))
            index = length

    return chunks


def classify_chunk(chunk_text: str) -> Chunk:
    stripped = chunk_text.strip()
    if stripped.endswith("}"):
        function_name = extract_chunk_function_name(chunk_text)
        if function_name:
            return Chunk(
                text=chunk_text,
                kind="function",
                function_name=function_name,
                is_sec_program=bool(re.search(r"(?m)^\s*SEC\(", chunk_text)),
            )
    return Chunk(text=chunk_text, kind="declaration")


def extract_chunk_signature(chunk_text: str) -> str:
    signature_lines: list[str] = []
    for line in chunk_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "/*", "*", "//", "SEC(")):
            continue
        if ANNOTATION_LINE_RE.match(stripped):
            continue
        if stripped == "{":
            break
        if "{" in stripped:
            signature_lines.append(stripped.split("{", 1)[0].strip())
            break
        signature_lines.append(stripped)
    return " ".join(line for line in signature_lines if line)


def extract_chunk_function_name(chunk_text: str) -> str:
    signature = extract_chunk_signature(chunk_text)
    if not signature:
        return ""
    bpf_prog_match = re.search(r"\bBPF_PROG\(\s*([A-Za-z_][A-Za-z0-9_]*)\b", signature)
    if bpf_prog_match:
        return bpf_prog_match.group(1)
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", signature)
    if match and match.group(1) not in {"if", "for", "while", "switch"}:
        return match.group(1)
    return ""


def build_reduced_source(source_text: str, target_function: str) -> tuple[str, int]:
    chunks = split_top_level_chunks(source_text)
    function_chunks = [chunk for chunk in chunks if chunk.kind == "function" and chunk.function_name]
    name_to_chunk = {chunk.function_name: chunk for chunk in function_chunks if chunk.function_name}

    kept_functions: set[str] = {target_function}
    changed = True
    while changed:
        changed = False
        for function_name in list(kept_functions):
            chunk = name_to_chunk.get(function_name)
            if not chunk:
                continue
            content = chunk.text
            content = re.sub(rf"\b{re.escape(function_name)}\b", "", content, count=1)
            for candidate_name in name_to_chunk:
                if candidate_name in kept_functions:
                    continue
                if re.search(rf"\b{re.escape(candidate_name)}\b", content):
                    kept_functions.add(candidate_name)
                    changed = True

    emitted_chunks: list[str] = []
    retained_programs = 0
    for chunk in chunks:
        if chunk.kind != "function":
            emitted_chunks.append(chunk.text.strip("\n"))
            continue
        if chunk.function_name == target_function:
            emitted_chunks.append(chunk.text.strip("\n"))
            if chunk.is_sec_program:
                retained_programs += 1
            continue
        if chunk.function_name in kept_functions and not chunk.is_sec_program:
            emitted_chunks.append(chunk.text.strip("\n"))
            continue

    reduced_source = "\n\n".join(part for part in emitted_chunks if part.strip()) + "\n"
    return reduced_source, retained_programs


def parse_depfile(depfile_path: Path) -> list[Path]:
    raw = depfile_path.read_text(encoding="utf-8", errors="replace")
    flattened = raw.replace("\\\n", " ")
    _, _, dep_text = flattened.partition(":")
    paths: list[Path] = []
    for token in shlex.split(dep_text, posix=True):
        if token:
            paths.append(Path(token))
    return paths


def try_hardlink_or_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        return
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def map_dependency_path(
    dep_path: Path,
    *,
    sanitized_vmlinux_path: Path,
    kernel_root: Path,
    libbpf_include_dir: Path,
    arch_macro: str,
) -> Path | None:
    roots: list[tuple[Path, Path]] = [
        (sanitized_vmlinux_path.parent, Path("headers")),
        (kernel_root / "tools" / "testing" / "selftests" / "bpf" / "progs", Path("headers/progs")),
        (kernel_root / "tools" / "testing" / "selftests" / "bpf", Path("headers")),
        (libbpf_include_dir, Path("headers")),
        (kernel_root / "tools" / "include" / "uapi", Path("headers")),
        (kernel_root / "tools" / "include", Path("headers")),
        (kernel_root / "tools" / "arch" / arch_macro / "include", Path("headers")),
    ]

    for source_root, output_root in roots:
        try:
            relative = dep_path.relative_to(source_root)
        except ValueError:
            continue
        return output_root / relative
    return None


def compile_with_full_roots(
    *,
    source_path: Path,
    object_path: Path,
    depfile_path: Path,
    clang: str,
    clang_sys_includes: list[str],
    sanitized_vmlinux_dir: Path,
    kernel_root: Path,
    libbpf_include_dir: Path,
    arch_macro: str,
    bpf_target: str,
) -> subprocess.CompletedProcess[str]:
    args = [
        clang,
        "-g",
        "-Wall",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unused-variable",
        f"-D__TARGET_ARCH_{arch_macro}",
        "-mlittle-endian" if bpf_target == "bpfel" else "-mbig-endian",
        f"-I{sanitized_vmlinux_dir}",
        f"-I{kernel_root / 'tools' / 'testing' / 'selftests' / 'bpf'}",
        f"-I{kernel_root / 'tools' / 'testing' / 'selftests' / 'bpf' / 'progs'}",
        f"-I{libbpf_include_dir}",
        f"-I{kernel_root / 'tools' / 'include' / 'uapi'}",
        f"-I{kernel_root / 'tools' / 'include'}",
        f"-I{kernel_root / 'tools' / 'arch' / arch_macro / 'include'}",
        "-std=gnu11",
        "-fno-strict-aliasing",
        "-Wno-microsoft-anon-tag",
        "-fms-extensions",
        "-Wno-compare-distinct-pointer-types",
        "-Wno-initializer-overrides",
        *clang_sys_includes,
        "-O2",
        f"--target={bpf_target}",
        "-mcpu=v3",
        "-MD",
        "-MF",
        str(depfile_path),
        "-c",
        str(source_path),
        "-o",
        str(object_path),
    ]
    return run_command(args)


def compile_with_local_headers(
    *,
    case_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    arch_macro: str,
    bpf_target: str,
) -> subprocess.CompletedProcess[str]:
    args = [
        clang,
        "-g",
        "-Wall",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unused-variable",
        f"-D__TARGET_ARCH_{arch_macro}",
        "-mlittle-endian" if bpf_target == "bpfel" else "-mbig-endian",
        f"-I{case_dir / 'headers'}",
        f"-I{case_dir / 'headers' / 'progs'}",
        "-std=gnu11",
        "-fno-strict-aliasing",
        "-Wno-microsoft-anon-tag",
        "-fms-extensions",
        "-Wno-compare-distinct-pointer-types",
        "-Wno-initializer-overrides",
        *clang_sys_includes,
        "-O2",
        f"--target={bpf_target}",
        "-mcpu=v3",
        "-c",
        str(case_dir / "prog.c"),
        "-o",
        str(case_dir / "prog.o"),
    ]
    return run_command(args)


def sanitize_case_pin(case_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", case_id)
    return f"/sys/fs/bpf/{cleaned}"


def extract_bpftool_verifier_log(output_text: str) -> str:
    begin = "-- BEGIN PROG LOAD LOG --"
    end = "-- END PROG LOAD LOG --"
    start = output_text.find(begin)
    if start == -1:
        return output_text.strip()
    finish = output_text.find(end, start)
    if finish == -1:
        return output_text[start:].strip()
    return output_text[start : finish + len(end)].strip()


def strip_bpftool_log_markers(log_text: str) -> str:
    lines = [
        line
        for line in log_text.splitlines()
        if line.strip() not in {"-- BEGIN PROG LOAD LOG --", "-- END PROG LOAD LOG --"}
    ]
    return "\n".join(lines).strip()


def normalize_log(text: str) -> str:
    if not text:
        return ""
    normalized = HEX_RE.sub("0xADDR", text)
    normalized_lines = [line.rstrip() for line in normalized.splitlines()]
    return "\n".join(normalized_lines).strip()


def diagnostic_tail(log_text: str) -> list[str]:
    useful: list[str] = []
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if TRACE_PREFIX_RE.match(line):
            continue
        useful.append(line)
    return useful[-3:]


def write_makefile(
    case_dir: Path,
    *,
    arch_macro: str,
    bpf_target: str,
    case_id: str,
    target_function: str,
) -> None:
    endian_flag = "-mlittle-endian" if bpf_target == "bpfel" else "-mbig-endian"
    pin_path = sanitize_case_pin(case_id)
    makefile_text = f"""CLANG ?= clang
CC ?= cc
PIN ?= {pin_path}
TARGET_FUNCTION ?= {target_function}

CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | awk '/#include <...> search starts here:/{{flag=1; next}} /End of search list./{{flag=0}} flag && $$1 ~ /^\\// {{printf "-idirafter %s ", $$1}}')
CFLAGS := -g -Wall -Werror -Wno-unused-function -Wno-unused-variable -D__TARGET_ARCH_{arch_macro} {endian_flag} -Iheaders -Iheaders/progs -std=gnu11 -fno-strict-aliasing -Wno-microsoft-anon-tag -fms-extensions -Wno-compare-distinct-pointer-types -Wno-initializer-overrides $(CLANG_SYS_INCLUDES) -O2 --target={bpf_target} -mcpu=v3

.PHONY: all verify clean

all: prog.o selftest_prog_loader

prog.o: prog.c
\t$(CLANG) $(CFLAGS) -c $< -o $@

selftest_prog_loader: selftest_prog_loader.c
\t$(CC) -O2 -Wall -Wextra -Werror $< -lbpf -lelf -lz -o $@

verify: prog.o selftest_prog_loader
\t@sudo ./selftest_prog_loader prog.o $(TARGET_FUNCTION) > verifier_load_result.json
\t@python3 - <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path("verifier_load_result.json").read_text())
verifier_log = data.get("verifier_log") or ""
pathlib.Path("verifier_log_captured.txt").write_text(verifier_log + ("\\n" if verifier_log else ""), encoding="utf-8")
sys.exit(0 if data.get("load_ok") else 1)
PY

clean:
\trm -f prog.o selftest_prog_loader verifier_log_captured.txt verifier_load_result.json
"""
    (case_dir / "Makefile").write_text(makefile_text, encoding="utf-8")


def build_case_artifact(
    case: CaseRecord,
    *,
    kernel_root: Path,
    output_root: Path,
    work_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    sanitized_vmlinux_path: Path,
    libbpf_include_dir: Path,
    helper_bin: Path,
    arch_macro: str,
    bpf_target: str,
) -> CaseResult:
    case_dir = output_root / case.case_id
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "headers").mkdir(parents=True, exist_ok=True)

    source_path = kernel_root / case.selftest_file
    if not source_path.exists():
        try_hardlink_or_copy(HELPER_SOURCE, case_dir / "selftest_prog_loader.c")
        write_makefile(
            case_dir,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
            case_id=case.case_id,
            target_function=case.function,
        )
        status_lines = [
            f"case_id: {case.case_id}",
            f"status: source_not_found",
            f"source_file: {case.selftest_file}",
            f"checked_at_utc: {datetime.now(UTC).isoformat()}",
        ]
        (case_dir / "verification_status.txt").write_text("\n".join(status_lines) + "\n", encoding="utf-8")
        return CaseResult(
            case=case,
            source_found=False,
            reduced_programs_retained=0,
            compile_ok=False,
            load_attempted=False,
            rejected=False,
            verifier_log_captured=False,
            expected_message_match=False,
            diagnostic_tail_match=False,
            exact_log_match=False,
            compile_error=f"missing source file: {source_path}",
        )

    original_source = source_path.read_text(encoding="utf-8", errors="replace")
    reduced_source, retained_programs = build_reduced_source(original_source, case.function)
    temp_dir = work_dir / case.case_id
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_source = temp_dir / "prog.c"
    temp_object = temp_dir / "prog.o"
    depfile = temp_dir / "prog.d"
    temp_source.write_text(reduced_source, encoding="utf-8")

    compile_probe = compile_with_full_roots(
        source_path=temp_source,
        object_path=temp_object,
        depfile_path=depfile,
        clang=clang,
        clang_sys_includes=clang_sys_includes,
        sanitized_vmlinux_dir=sanitized_vmlinux_path.parent,
        kernel_root=kernel_root,
        libbpf_include_dir=libbpf_include_dir,
        arch_macro=arch_macro,
        bpf_target=bpf_target,
    )

    compile_ok = compile_probe.returncode == 0
    compile_error = compile_probe.stderr.strip()
    header_deps: list[Path] = []
    if compile_ok:
        header_deps = parse_depfile(depfile)
        for dep in header_deps:
            mapped = map_dependency_path(
                dep,
                sanitized_vmlinux_path=sanitized_vmlinux_path,
                kernel_root=kernel_root,
                libbpf_include_dir=libbpf_include_dir,
                arch_macro=arch_macro,
            )
            if mapped is None:
                continue
            try_hardlink_or_copy(dep, case_dir / mapped)

    (case_dir / "prog.c").write_text(reduced_source, encoding="utf-8")
    try_hardlink_or_copy(HELPER_SOURCE, case_dir / "selftest_prog_loader.c")
    write_makefile(
        case_dir,
        arch_macro=arch_macro,
        bpf_target=bpf_target,
        case_id=case.case_id,
        target_function=case.function,
    )

    local_compile = None
    if compile_ok:
        local_compile = compile_with_local_headers(
            case_dir=case_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
        )
        compile_ok = local_compile.returncode == 0
        if not compile_ok:
            compile_error = local_compile.stderr.strip()

    load_attempted = False
    rejected = False
    verifier_log_captured = False
    expected_message_match = False
    diagnostic_tail_match = False
    exact_log_match = False
    load_error = ""
    captured_log_text = ""

    if compile_ok:
        load_attempted = True
        load_result = run_loader(
            helper_bin,
            case_dir / "prog.o",
            ProgramKey(
                selftest_file=case.selftest_file,
                function=case.function,
                section=case.section,
            ),
        )
        raw_output = (load_result.stdout or "") + (load_result.stderr or "")
        captured_log_text = strip_bpftool_log_markers(load_result.verifier_log)
        verifier_log_captured = bool(captured_log_text.strip())
        rejected = not load_result.load_ok
        load_error = load_result.error_message if hasattr(load_result, "error_message") else raw_output.strip()
        if verifier_log_captured:
            (case_dir / "verifier_log_captured.txt").write_text(captured_log_text + "\n", encoding="utf-8")
            normalized_captured = normalize_log(captured_log_text)
            normalized_yaml = normalize_log(case.yaml_verifier_log)
            exact_log_match = bool(normalized_yaml) and normalized_captured == normalized_yaml
            expected_message_match = all(msg in captured_log_text for msg in case.expected_messages)
            yaml_tail = diagnostic_tail(case.yaml_verifier_log)
            captured_tail_blob = "\n".join(diagnostic_tail(captured_log_text))
            diagnostic_tail_match = bool(yaml_tail) and all(line in captured_tail_blob or line in captured_log_text for line in yaml_tail)

    status_lines = [
        f"case_id: {case.case_id}",
        f"checked_at_utc: {datetime.now(UTC).isoformat()}",
        f"source_file: {case.selftest_file}",
        f"target_function: {case.function}",
        f"section: {case.section}",
        f"source_found: {'yes' if source_path.exists() else 'no'}",
        f"retained_sec_program_count: {retained_programs}",
        f"header_files_copied: {sum(1 for path in (case_dir / 'headers').rglob('*') if path.is_file())}",
        f"compile_ok: {'yes' if compile_ok else 'no'}",
        f"load_attempted: {'yes' if load_attempted else 'no'}",
        f"verifier_rejected: {'yes' if rejected else 'no'}",
        f"verifier_log_captured: {'yes' if verifier_log_captured else 'no'}",
        f"expected_message_match: {'yes' if expected_message_match else 'no'}",
        f"diagnostic_tail_match: {'yes' if diagnostic_tail_match else 'no'}",
        f"exact_log_match: {'yes' if exact_log_match else 'no'}",
    ]
    if compile_error:
        status_lines.append("compile_error: |")
        status_lines.extend(f"  {line}" for line in compile_error.splitlines())
    if load_error and load_attempted:
        status_lines.append("load_output_excerpt: |")
        excerpt_lines = (raw_output if load_attempted else load_error).splitlines()[:30]
        status_lines.extend(f"  {line}" for line in excerpt_lines)
    (case_dir / "verification_status.txt").write_text("\n".join(status_lines) + "\n", encoding="utf-8")

    return CaseResult(
        case=case,
        source_found=True,
        reduced_programs_retained=retained_programs,
        compile_ok=compile_ok,
        load_attempted=load_attempted,
        rejected=rejected,
        verifier_log_captured=verifier_log_captured,
        expected_message_match=expected_message_match,
        diagnostic_tail_match=diagnostic_tail_match,
        exact_log_match=exact_log_match,
        compile_error=compile_error,
        load_error=load_error,
        notes=[],
    )


def common_compile_issues(results: Iterable[CaseResult]) -> list[str]:
    counts: dict[str, int] = {}
    for result in results:
        if not result.compile_error:
            continue
        first_line = result.compile_error.splitlines()[0].strip()
        counts[first_line] = counts.get(first_line, 0) + 1
    return [f"{count} case(s): `{reason}`" for reason, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def build_report(
    *,
    results: list[CaseResult],
    output_root: Path,
    kernel_root: Path,
    started_at: datetime,
    finished_at: datetime,
) -> str:
    source_found = sum(1 for result in results if result.source_found)
    compiled = sum(1 for result in results if result.compile_ok)
    rejected = sum(1 for result in results if result.rejected)
    expected_match = sum(1 for result in results if result.expected_message_match)
    diagnostic_match = sum(1 for result in results if result.diagnostic_tail_match)
    exact_match = sum(1 for result in results if result.exact_log_match)
    retained_single_program = sum(1 for result in results if result.reduced_programs_retained == 1)

    lines: list[str] = []
    lines.append("# Kernel Selftest Verification")
    lines.append("")
    lines.append(f"Run date: {finished_at.astimezone(UTC).date().isoformat()}")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- Intentional negative benchmark cases processed: {len(results)}")
    lines.append(f"- Kernel source root: `{kernel_root}`")
    lines.append(f"- Output root: `{output_root}`")
    lines.append("- Each case directory contains a reduced single-case `prog.c`, copied local headers, a `Makefile`, and per-case verification status.")
    lines.append("- `vmlinux.h` was sanitized to drop `__ksym` declarations that conflict with selftest helper headers on this host kernel.")
    lines.append("- Verifier checks were executed with a small libbpf loader that selects the target program by function name; this avoids `bpftool prog load` ambiguity for multi-function selftest objects.")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(f"- Source files found: {source_found} / {len(results)}")
    lines.append(f"- Reduced sources with exactly one retained SEC program: {retained_single_program} / {len(results)}")
    lines.append(f"- Compiled successfully: {compiled} / {len(results)}")
    lines.append(f"- Rejected by verifier as expected: {rejected} / {len(results)}")
    lines.append(f"- Captured logs matching all expected message strings: {expected_match} / {len(results)}")
    lines.append(f"- Captured logs matching the YAML diagnostic tail: {diagnostic_match} / {len(results)}")
    lines.append(f"- Exact normalized full-log matches: {exact_match} / {len(results)}")
    lines.append("")
    lines.append("## Matching Rule")
    lines.append("")
    lines.append("- Primary `matching verifier logs` count above uses the YAML diagnostic tail: the last 1-3 non-trace diagnostic lines from the benchmark YAML must appear in the captured verifier log.")
    lines.append("- Exact full-log match is reported separately because verifier traces contain unstable addresses and kernel-version-specific detail.")
    lines.append("")
    lines.append("## Common Compilation Issues")
    lines.append("")
    issues = common_compile_issues(results)
    if issues:
        lines.extend(f"- {issue}" for issue in issues)
    else:
        lines.append("- None in this run.")
    lines.append("")
    lines.append("## Cases With Problems")
    lines.append("")
    problematic = [result for result in results if not (result.compile_ok and result.rejected)]
    if problematic:
        for result in problematic:
            lines.append(f"- `{result.case.case_id}`: compile_ok={result.compile_ok}, rejected={result.rejected}")
    else:
        lines.append("- None.")
    lines.append("")
    lines.append("## Timing")
    lines.append("")
    lines.append(f"- Started: {started_at.astimezone(UTC).isoformat()}")
    lines.append(f"- Finished: {finished_at.astimezone(UTC).isoformat()}")
    lines.append(f"- Duration seconds: {(finished_at - started_at).total_seconds():.1f}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    started_at = datetime.now(UTC)

    selected_case_ids = set(args.case_id) if args.case_id else None
    records = load_case_records(selected_case_ids)

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found in PATH")
    clang_sys_includes = collect_clang_sys_includes(clang)
    arch_macro, bpf_target = host_arch_macro()

    kernel_root = prepare_kernel_checkout(args.kernel_root, arch_macro)
    work_dir = args.work_dir
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    sanitized_vmlinux_path = ensure_sanitized_vmlinux_header(work_dir, kernel_root)
    libbpf_include_dir = ensure_libbpf_headers(kernel_root, work_dir)
    helper_bin = ensure_helper_binary(work_dir)

    if args.output_root.exists():
        shutil.rmtree(args.output_root)
    args.output_root.mkdir(parents=True, exist_ok=True)

    emit(f"Building per-case artifacts for {len(records)} kernel selftest benchmark cases")
    results: list[CaseResult] = []
    for index, record in enumerate(records, start=1):
        emit(f"[{index}/{len(records)}] {record.case_id}")
        result = build_case_artifact(
            record,
            kernel_root=kernel_root,
            output_root=args.output_root,
            work_dir=work_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            sanitized_vmlinux_path=sanitized_vmlinux_path,
            libbpf_include_dir=libbpf_include_dir,
            helper_bin=helper_bin,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
        )
        results.append(result)

    finished_at = datetime.now(UTC)
    report_text = build_report(
        results=results,
        output_root=args.output_root,
        kernel_root=kernel_root,
        started_at=started_at,
        finished_at=finished_at,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report_text + "\n", encoding="utf-8")
    emit(f"Wrote report to {args.report}")

    if not args.keep_workdir:
        shutil.rmtree(work_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
