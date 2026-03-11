#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_KERNEL_ROOT = Path("/tmp/ebpf-eval-repos/linux")
DEFAULT_CASE_DIR_GLOB = "kernel_selftests*"
DEFAULT_WORK_DIR = Path("/tmp/kernel-selftests-verbose-capture")
DEFAULT_REPORT_PATH = ROOT_DIR / "docs" / "tmp" / "selftests-verbose-log-capture-report.md"
VMLINUX_BTF = Path("/sys/kernel/btf/vmlinux")
HELPER_SOURCE = ROOT_DIR / "case_study" / "selftest_prog_loader.c"
HELPER_BINARY_NAME = "selftest_prog_loader"
VERIFIER_LOG_STYLE_KEY = "verifier_log"
BPF_PROG_RE = re.compile(r"\bBPF_PROG\(\s*([A-Za-z_][A-Za-z0-9_]*)\b")


class LiteralString(str):
    pass


class LiteralDumper(yaml.SafeDumper):
    pass


def literal_string_representer(dumper: yaml.SafeDumper, value: LiteralString) -> yaml.nodes.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(value), style="|")


LiteralDumper.add_representer(LiteralString, literal_string_representer)


@dataclass(frozen=True, order=True)
class ProgramKey:
    selftest_file: str
    function: str
    section: str


@dataclass
class CaseRecord:
    case_id: str
    path: Path
    selftest_file: str
    function: str
    section: str
    expected_messages: list[str]

    @property
    def key(self) -> ProgramKey:
        return ProgramKey(self.selftest_file, self.function, self.section)


@dataclass
class CompileResult:
    source_path: Path
    object_path: Path | None
    ok: bool
    stdout: str
    stderr: str


@dataclass
class LoadResult:
    key: ProgramKey
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile kernel selftest negative programs, capture verbose verifier logs, and update YAML cases."
    )
    parser.add_argument(
        "--kernel-root",
        type=Path,
        default=DEFAULT_KERNEL_ROOT,
        help="Linux kernel checkout root with tools/testing/selftests/bpf/ available.",
    )
    parser.add_argument(
        "--cases-root",
        type=Path,
        default=ROOT_DIR / "case_study" / "cases",
        help="Root directory containing kernel_selftests* case directories.",
    )
    parser.add_argument(
        "--case-dir-glob",
        default=DEFAULT_CASE_DIR_GLOB,
        help="Glob under --cases-root used to find selftest case directories.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="Scratch directory for helper binaries, generated headers, and compiled objects.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Markdown report output path.",
    )
    parser.add_argument(
        "--max-programs",
        type=int,
        default=None,
        help="Limit the number of unique selftest programs processed. Useful for the initial small-batch debug pass.",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep compiled objects and helper artifacts in the work directory after completion.",
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
    stdout_handle: Any | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        text=True,
        stdout=stdout_handle if stdout_handle is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def host_arch_macro() -> tuple[str, str]:
    machine = run_command(["uname", "-m"], check=True).stdout.strip()
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
    completed = run_command([clang, "-v", "-E", "-"], check=True)
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


def find_case_directories(cases_root: Path, case_dir_glob: str) -> list[Path]:
    directories = [path for path in sorted(cases_root.glob(case_dir_glob)) if path.is_dir()]
    if not directories:
        raise SystemExit(f"No case directories matched {case_dir_glob!r} under {cases_root}")
    return directories


def extract_function_name(source_snippet: str) -> str:
    if not source_snippet:
        return ""
    head = source_snippet.split("{", 1)[0]
    bpf_prog_match = BPF_PROG_RE.search(head)
    if bpf_prog_match:
        return bpf_prog_match.group(1)

    candidate_lines: list[str] = []
    for line in head.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("SEC(", "__", "/*", "*", "//")):
            continue
        candidate_lines.append(stripped)
    signature = " ".join(candidate_lines[-2:]) if candidate_lines else ""
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", signature)
    if match and match.group(1) not in {"if", "for", "while", "switch"}:
        return match.group(1)
    return ""


def load_cases(case_dirs: list[Path]) -> tuple[int, list[CaseRecord], dict[ProgramKey, list[CaseRecord]]]:
    total_yaml_files = 0
    records: list[CaseRecord] = []
    grouped: dict[ProgramKey, list[CaseRecord]] = defaultdict(list)
    for case_dir in case_dirs:
        for case_path in sorted(case_dir.glob("*.yaml")):
            if case_path.name == "index.yaml":
                continue
            total_yaml_files += 1
            payload = yaml.safe_load(case_path.read_text())
            if not isinstance(payload, dict):
                continue
            selftest = payload.get("selftest") or {}
            messages = payload.get("expected_verifier_messages") or {}
            source_snippets = payload.get("source_snippets") or []
            first_snippet = source_snippets[0] if source_snippets and isinstance(source_snippets[0], dict) else {}
            recovered_function = extract_function_name(str(first_snippet.get("code", "")))
            function_name = str(selftest.get("function", "")).strip()
            if not function_name or function_name == "BPF_PROG":
                function_name = recovered_function

            record = CaseRecord(
                case_id=str(payload.get("case_id", case_path.stem)),
                path=case_path,
                selftest_file=str(selftest.get("file", "")),
                function=function_name,
                section=str(selftest.get("section", "")),
                expected_messages=[str(msg) for msg in (messages.get("combined") or [])],
            )
            if not record.selftest_file or not record.function or not record.section:
                continue
            records.append(record)
            grouped[record.key].append(record)
    return total_yaml_files, records, grouped


def ensure_kernel_paths(kernel_root: Path, arch_macro: str) -> None:
    required = [
        kernel_root / "tools" / "testing" / "selftests" / "bpf",
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
        missing_text = ", ".join(str(path) for path in missing)
        raise SystemExit(f"Kernel checkout is missing required paths and is not a git checkout: {missing_text}")

    sparse_paths = [
        "tools/testing/selftests/bpf",
        "tools/lib/bpf",
        "tools/include",
        "tools/build",
        "tools/scripts",
        f"tools/arch/{arch_macro}/include",
        "scripts",
    ]
    emit("Expanding sparse checkout with additional libbpf/selftests build paths")
    completed = run_command(["git", "-C", str(kernel_root), "sparse-checkout", "add", *sparse_paths])
    if completed.returncode != 0:
        raise SystemExit(f"Failed to expand sparse checkout:\n{completed.stdout}{completed.stderr}")
    missing = [path for path in required if not path.exists()]
    if missing:
        missing_text = ", ".join(str(path) for path in missing)
        raise SystemExit(f"Kernel checkout is still missing required paths after sparse update: {missing_text}")


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
        raise SystemExit(
            "Failed to compile selftest_prog_loader.c:\n"
            f"{completed.stdout}{completed.stderr}"
        )
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
    build_dir.mkdir(parents=True, exist_ok=True)
    include_root.mkdir(parents=True, exist_ok=True)
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


def compile_source(
    source_path: Path,
    *,
    work_dir: Path,
    libbpf_include_dir: Path,
    clang: str,
    clang_sys_includes: list[str],
    arch_macro: str,
    bpf_target: str,
) -> CompileResult:
    if not source_path.exists():
        return CompileResult(
            source_path=source_path,
            object_path=None,
            ok=False,
            stdout="",
            stderr=f"missing source file: {source_path}",
        )
    obj_dir = work_dir / "objects"
    obj_dir.mkdir(parents=True, exist_ok=True)
    object_path = obj_dir / f"{source_path.stem}.bpf.o"
    selftests_root = source_path.parents[1]
    kernel_tools_root = source_path.parents[4]
    args = [
        clang,
        "-g",
        "-Wall",
        "-Werror",
        f"-D__TARGET_ARCH_{arch_macro}",
        "-mlittle-endian" if bpf_target == "bpfel" else "-mbig-endian",
        f"-I{work_dir / 'include'}",
        f"-I{selftests_root}",
        f"-I{selftests_root / 'progs'}",
        f"-I{libbpf_include_dir}",
        f"-I{kernel_tools_root / 'include' / 'uapi'}",
        f"-I{kernel_tools_root / 'include'}",
        f"-I{kernel_tools_root / 'arch' / arch_macro / 'include'}",
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
        str(source_path),
        "-o",
        str(object_path),
    ]
    completed = run_command(args)
    return CompileResult(
        source_path=source_path,
        object_path=object_path if completed.returncode == 0 else None,
        ok=completed.returncode == 0,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_loader(helper_bin: Path, object_path: Path, key: ProgramKey) -> LoadResult:
    completed = run_command(
        ["sudo", "-n", str(helper_bin), str(object_path), key.function],
    )
    parsed: dict[str, Any] | None = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return LoadResult(
        key=key,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        parsed=parsed,
    )


def normalized_compile_failure(stderr: str) -> str:
    for line in stderr.splitlines():
        stripped = line.strip()
        if "fatal error:" in stripped:
            return stripped.split("fatal error:", 1)[1].strip()
    for line in stderr.splitlines():
        stripped = line.strip()
        if ": error:" in stripped:
            return stripped.split(": error:", 1)[1].strip()
    return next((line.strip() for line in stderr.splitlines() if line.strip()), "unknown compile error")


def replace_verifier_log(payload: dict[str, Any], verifier_log: str) -> dict[str, Any]:
    new_payload: dict[str, Any] = {}
    inserted = False
    for key, value in payload.items():
        if key == VERIFIER_LOG_STYLE_KEY:
            continue
        new_payload[key] = value
        if key == "expected_verifier_messages":
            new_payload[VERIFIER_LOG_STYLE_KEY] = LiteralString(verifier_log)
            inserted = True
    if not inserted:
        new_payload[VERIFIER_LOG_STYLE_KEY] = LiteralString(verifier_log)
    return new_payload


def normalize_verifier_log_text(verifier_log: str) -> str:
    lines = [line.rstrip() for line in verifier_log.splitlines()]
    return "\n".join(lines).rstrip()


def update_case_yaml(case_path: Path, verifier_log: str) -> bool:
    raw_text = case_path.read_text()
    payload = yaml.safe_load(raw_text)
    if not isinstance(payload, dict):
        return False
    normalized_log = normalize_verifier_log_text(verifier_log)
    current_log = payload.get(VERIFIER_LOG_STYLE_KEY)
    if (
        isinstance(current_log, str)
        and normalize_verifier_log_text(current_log) == normalized_log
        and f"{VERIFIER_LOG_STYLE_KEY}: |" in raw_text
    ):
        return False
    updated = replace_verifier_log(payload, normalized_log)
    with case_path.open("w", encoding="utf-8") as handle:
        yaml.dump(updated, handle, Dumper=LiteralDumper, sort_keys=False, allow_unicode=False, width=1000)
    return True


def short_log_excerpt(log_text: str, max_lines: int = 60, max_chars: int = 4000) -> str:
    lines = log_text.strip().splitlines()
    excerpt = "\n".join(lines[:max_lines])
    if len(excerpt) > max_chars:
        excerpt = excerpt[: max_chars - 1].rstrip() + "\n..."
    return excerpt


def count_yaml_logs_on_disk(case_dirs: list[Path]) -> int:
    total = 0
    for case_dir in case_dirs:
        for case_path in sorted(case_dir.glob("*.yaml")):
            if case_path.name == "index.yaml":
                continue
            payload = yaml.safe_load(case_path.read_text())
            if not isinstance(payload, dict):
                continue
            verifier_log = payload.get(VERIFIER_LOG_STYLE_KEY)
            if isinstance(verifier_log, str) and verifier_log.strip():
                total += 1
    return total


def build_report(
    *,
    case_dirs: list[Path],
    total_yaml_files: int,
    all_cases: list[CaseRecord],
    selected_keys: list[ProgramKey],
    compile_results: dict[str, CompileResult],
    load_results: dict[ProgramKey, LoadResult],
    yaml_with_logs_after_run: int,
    yaml_updates: int,
    started_at: datetime,
    finished_at: datetime,
) -> str:
    compile_attempted = len(compile_results)
    compile_succeeded = sum(1 for result in compile_results.values() if result.ok)
    compile_failed = compile_attempted - compile_succeeded
    load_attempted = len(load_results)
    load_succeeded = sum(1 for result in load_results.values() if result.load_ok)
    load_failed = load_attempted - load_succeeded
    logs_captured = sum(1 for result in load_results.values() if result.verifier_log)
    rejected_logs_captured = sum(1 for result in load_results.values() if (not result.load_ok) and result.verifier_log)
    compile_failures = Counter(
        normalized_compile_failure(result.stderr) for result in compile_results.values() if not result.ok
    )
    sample_failures = [result for result in load_results.values() if (not result.load_ok) and result.verifier_log][:3]

    lines: list[str] = []
    lines.append("# Kernel Selftests Verbose Log Capture Report")
    lines.append("")
    lines.append(f"Run date: {finished_at.astimezone(UTC).date().isoformat()}")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- Case directories scanned: {', '.join(str(path) for path in case_dirs)}")
    lines.append(f"- YAML case files present on disk: {total_yaml_files}")
    lines.append(f"- YAML case files with usable selftest metadata: {len(all_cases)}")
    lines.append(f"- Unique selftest program targets: {len({case.key for case in all_cases})}")
    if len(selected_keys) != len({case.key for case in all_cases}):
        lines.append(f"- This run processed a limited subset: {len(selected_keys)} targets")
    lines.append(f"- Unique selftest source files referenced by processed targets: {len(compile_results)}")
    lines.append("- Programs were loaded one at a time with a custom libbpf helper using per-program verifier log level 2.")
    lines.append("- No bpffs pins were created during load attempts; helper processes exited after each load.")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(f"- Compile files attempted: {compile_attempted}")
    lines.append(f"- Compile files succeeded: {compile_succeeded}")
    lines.append(f"- Compile files failed: {compile_failed}")
    lines.append(f"- Program loads attempted: {load_attempted}")
    lines.append(f"- Program loads succeeded: {load_succeeded}")
    lines.append(f"- Program loads rejected or failed: {load_failed}")
    lines.append(f"- Programs with non-empty verifier logs captured: {logs_captured}")
    lines.append(f"- Rejected programs with verifier logs captured: {rejected_logs_captured}")
    lines.append(f"- YAML case files with `verifier_log` after this run: {yaml_with_logs_after_run}")
    lines.append(f"- YAML case files updated with `verifier_log` in this run: {yaml_updates}")
    lines.append("")
    lines.append("## Compilation Failures")
    lines.append("")
    if compile_failures:
        for reason, count in compile_failures.most_common():
            lines.append(f"- {count} file(s): `{reason}`")
    else:
        lines.append("- None in this run.")
    lines.append("")
    lines.append("## Sample Verifier Logs")
    lines.append("")
    if sample_failures:
        for result in sample_failures:
            parsed = result.parsed or {}
            lines.append(f"### `{result.key.function}` from `{result.key.selftest_file}`")
            lines.append("")
            lines.append(f"- Section: `{result.key.section}`")
            lines.append(f"- Error: `{parsed.get('error_message', result.error_message)}`")
            lines.append("")
            lines.append("```text")
            lines.append(short_log_excerpt(result.verifier_log))
            lines.append("```")
            lines.append("")
    else:
        lines.append("- No rejected programs produced verifier logs in this run.")
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
    if not args.kernel_root.exists():
        raise SystemExit(f"Kernel root not found: {args.kernel_root}")

    case_dirs = find_case_directories(args.cases_root, args.case_dir_glob)
    total_yaml_files, all_cases, grouped_cases = load_cases(case_dirs)
    if not grouped_cases:
        raise SystemExit("No kernel selftest cases were found to process.")

    selected_keys = sorted(grouped_cases)
    if args.max_programs is not None:
        selected_keys = selected_keys[: args.max_programs]

    selected_files = sorted({key.selftest_file for key in selected_keys})
    work_dir = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)
    helper_bin = ensure_helper_binary(work_dir)
    ensure_vmlinux_header(work_dir)

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found in PATH")
    clang_sys_includes = collect_clang_sys_includes(clang)
    arch_macro, bpf_target = host_arch_macro()
    ensure_kernel_paths(args.kernel_root, arch_macro)
    libbpf_include_dir = ensure_libbpf_headers(args.kernel_root, work_dir)

    emit(
        f"Processing {len(selected_keys)} unique programs across {len(selected_files)} source files from "
        f"{len(case_dirs)} case directories"
    )

    compile_results: dict[str, CompileResult] = {}
    load_results: dict[ProgramKey, LoadResult] = {}

    for relative_source in selected_files:
        source_path = args.kernel_root / relative_source
        emit(f"Compiling {relative_source}")
        compile_results[relative_source] = compile_source(
            source_path,
            work_dir=work_dir,
            libbpf_include_dir=libbpf_include_dir,
            clang=clang,
            clang_sys_includes=clang_sys_includes,
            arch_macro=arch_macro,
            bpf_target=bpf_target,
        )

    yaml_updates = 0
    for index, key in enumerate(selected_keys, start=1):
        compile_result = compile_results[key.selftest_file]
        if not compile_result.ok or not compile_result.object_path:
            continue
        emit(f"[{index}/{len(selected_keys)}] Loading {key.function} from {key.selftest_file}")
        load_result = run_loader(helper_bin, compile_result.object_path, key)
        load_results[key] = load_result
        verifier_log = load_result.verifier_log
        if load_result.load_ok or not verifier_log:
            continue
        for case in grouped_cases[key]:
            if update_case_yaml(case.path, verifier_log):
                yaml_updates += 1

    finished_at = datetime.now(UTC)
    yaml_with_logs_after_run = count_yaml_logs_on_disk(case_dirs)
    report_text = build_report(
        case_dirs=case_dirs,
        total_yaml_files=total_yaml_files,
        all_cases=all_cases,
        selected_keys=selected_keys,
        compile_results=compile_results,
        load_results=load_results,
        yaml_with_logs_after_run=yaml_with_logs_after_run,
        yaml_updates=yaml_updates,
        started_at=started_at,
        finished_at=finished_at,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report_text, encoding="utf-8")
    emit(f"Wrote report to {args.report}")

    if not args.keep_workdir:
        shutil.rmtree(work_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
