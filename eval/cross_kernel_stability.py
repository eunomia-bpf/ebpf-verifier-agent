#!/usr/bin/env python3
"""Prototype cross-kernel stability runner for OBLIGE."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from case_study.capture_kernel_selftests_verifier_logs import (
    collect_clang_sys_includes,
    compile_source,
    ensure_helper_binary,
    ensure_kernel_paths,
    ensure_libbpf_headers,
    host_arch_macro,
)
from eval.pretty_verifier_comparison import ObligeResult, run_oblige
from interface.extractor.log_parser import parse_log


DEFAULT_KERNEL_ROOT = Path("/tmp/ebpf-eval-repos/linux")
DEFAULT_RUNTIME_DIR = ROOT / ".kernels"
DEFAULT_WORK_DIR = Path("/tmp/oblige-cross-kernel")
DEFAULT_CATALOG_PATH = ROOT / "taxonomy" / "error_catalog.yaml"
HOST_VMLINUX_BTF = Path("/sys/kernel/btf/vmlinux")
TOKEN_RE = re.compile(r"[a-zA-Z_]+")
VERSION_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?")
INSTRUCTION_LINE_RE = re.compile(r"^\d+:\s*\([0-9a-f]{2}\)", re.IGNORECASE)


@dataclass(slots=True)
class CaseSpec:
    case_id: str
    case_path: Path
    source_bucket: str
    source_relpath: Path
    program_name: str
    section: str
    description: str


@dataclass(slots=True)
class KernelRuntime:
    requested_version: str
    kernel_root: Path | None
    vmlinux_btf: Path | None
    load_command: list[str] | None
    reason_unavailable: str | None = None

    @property
    def available(self) -> bool:
        return (
            self.reason_unavailable is None
            and self.kernel_root is not None
            and self.vmlinux_btf is not None
            and self.load_command is not None
        )


@dataclass(slots=True)
class KernelRunResult:
    kernel: str
    available: bool
    compile_ok: bool = False
    load_ok: bool | None = None
    reason: str | None = None
    object_path: str | None = None
    error_message: str | None = None
    verifier_log: str | None = None
    raw_error_line: str | None = None
    raw_error_tokens: list[str] | None = None
    error_id: str | None = None
    taxonomy_class: str | None = None
    root_cause: str | None = None
    source_mapping: str | None = None


@dataclass(slots=True)
class PairwiseComparison:
    left_kernel: str
    right_kernel: str
    raw_token_jaccard: float
    error_id_exact_match: bool
    taxonomy_exact_match: bool
    root_cause_exact_match: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a kernel selftest case against one or more kernel runtimes, "
            "capture verifier logs, run OBLIGE diagnosis, and compare stability."
        )
    )
    parser.add_argument("case_yaml", type=Path, help="Path to a case YAML.")
    parser.add_argument(
        "--kernels",
        nargs="+",
        required=True,
        help="Kernel versions or labels to compare, for example: 6.15 6.6 6.1.",
    )
    parser.add_argument(
        "--kernel-root",
        type=Path,
        default=DEFAULT_KERNEL_ROOT,
        help="Kernel source tree to use for the current host runtime.",
    )
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=DEFAULT_RUNTIME_DIR,
        help=(
            "Directory containing optional .kernels/<version>/runtime.json descriptors "
            "for non-host runtimes."
        ),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="Scratch directory for helper binaries, generated headers, and objects.",
    )
    parser.add_argument(
        "--catalog-path",
        type=Path,
        default=DEFAULT_CATALOG_PATH,
        help="Path to taxonomy/error_catalog.yaml.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional path for structured JSON output.",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=None,
        help="Optional path for a Markdown comparison table.",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep generated artifacts instead of overwriting them on the next run.",
    )
    return parser.parse_args()


def run_command(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def current_kernel_release() -> str:
    completed = run_command(["uname", "-r"])
    release = completed.stdout.strip()
    if not release:
        raise SystemExit("Failed to determine current kernel release via uname -r")
    return release


def kernel_aliases(release: str) -> set[str]:
    aliases = {release}
    aliases.add(release.split("-", 1)[0])
    match = VERSION_RE.search(release)
    if match:
        aliases.add(f"{match.group('major')}.{match.group('minor')}")
        if match.group("patch") is not None:
            aliases.add(
                f"{match.group('major')}.{match.group('minor')}.{match.group('patch')}"
            )
    return aliases


def load_case_spec(case_path: Path) -> CaseSpec:
    payload = yaml.safe_load(case_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"Case file is not a YAML mapping: {case_path}")

    selftest = payload.get("selftest")
    if not isinstance(selftest, dict):
        raise SystemExit(
            "Prototype currently supports only `kernel_selftests` cases with a `selftest` block."
        )

    source_relpath = selftest.get("file")
    program_name = selftest.get("function")
    if not isinstance(source_relpath, str) or not source_relpath.strip():
        raise SystemExit(f"Case is missing selftest.file: {case_path}")
    if not isinstance(program_name, str) or not program_name.strip():
        raise SystemExit(f"Case is missing selftest.function: {case_path}")

    return CaseSpec(
        case_id=str(payload.get("case_id", case_path.stem)),
        case_path=case_path,
        source_bucket=str(payload.get("source", "kernel_selftests")),
        source_relpath=Path(source_relpath),
        program_name=program_name.strip(),
        section=str(selftest.get("section", "")),
        description=str(selftest.get("description", program_name)),
    )


def load_runtime_descriptor(path: Path, requested_version: str) -> KernelRuntime:
    payload = json.loads(path.read_text(encoding="utf-8"))
    kernel_root = payload.get("kernel_root")
    vmlinux_btf = payload.get("vmlinux_btf")
    load_command = payload.get("load_command")
    if not isinstance(kernel_root, str) or not kernel_root:
        return KernelRuntime(
            requested_version=requested_version,
            kernel_root=None,
            vmlinux_btf=None,
            load_command=None,
            reason_unavailable=f"{path} is missing string field `kernel_root`",
        )
    if not isinstance(vmlinux_btf, str) or not vmlinux_btf:
        return KernelRuntime(
            requested_version=requested_version,
            kernel_root=None,
            vmlinux_btf=None,
            load_command=None,
            reason_unavailable=f"{path} is missing string field `vmlinux_btf`",
        )
    if not isinstance(load_command, list) or not all(isinstance(item, str) for item in load_command):
        return KernelRuntime(
            requested_version=requested_version,
            kernel_root=None,
            vmlinux_btf=None,
            load_command=None,
            reason_unavailable=f"{path} is missing string-list field `load_command`",
        )
    return KernelRuntime(
        requested_version=requested_version,
        kernel_root=Path(kernel_root),
        vmlinux_btf=Path(vmlinux_btf),
        load_command=list(load_command),
    )


def resolve_runtime(version: str, args: argparse.Namespace, host_release: str) -> KernelRuntime:
    if version in kernel_aliases(host_release) or version == "host":
        return KernelRuntime(
            requested_version=version,
            kernel_root=args.kernel_root,
            vmlinux_btf=HOST_VMLINUX_BTF,
            load_command=["sudo", "-n", "{helper}", "{object}", "{program}"],
        )

    runtime_json = args.runtime_dir / version / "runtime.json"
    if runtime_json.exists():
        return load_runtime_descriptor(runtime_json, version)

    runtime_dir = args.runtime_dir / version
    if runtime_dir.exists():
        return KernelRuntime(
            requested_version=version,
            kernel_root=None,
            vmlinux_btf=None,
            load_command=None,
            reason_unavailable=(
                f"{runtime_dir} exists but runtime.json is missing; "
                "setup_kernels.sh scaffolding alone is not enough to execute loads"
            ),
        )

    return KernelRuntime(
        requested_version=version,
        kernel_root=None,
        vmlinux_btf=None,
        load_command=None,
        reason_unavailable=(
            f"No runtime descriptor for kernel {version}. "
            f"Expected {runtime_json} or the current host kernel."
        ),
    )


def ensure_vmlinux_header_from_btf(btf_path: Path, work_dir: Path) -> Path:
    if not btf_path.exists():
        raise SystemExit(f"Missing BTF file: {btf_path}")
    include_dir = work_dir / "include"
    include_dir.mkdir(parents=True, exist_ok=True)
    header_path = include_dir / "vmlinux.h"
    if header_path.exists() and header_path.stat().st_mtime >= btf_path.stat().st_mtime:
        return header_path

    with header_path.open("w", encoding="utf-8") as handle:
        completed = subprocess.run(
            ["bpftool", "btf", "dump", "file", str(btf_path), "format", "c"],
            text=True,
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        raise SystemExit(f"Failed to generate {header_path} from {btf_path}:\n{completed.stderr}")
    return header_path


def format_load_command(template: list[str], *, helper: Path, object_path: Path, program: str, kernel: str) -> list[str]:
    return [
        part.format(
            helper=str(helper),
            object=str(object_path),
            program=program,
            kernel=kernel,
        )
        for part in template
    ]


def tokenize_error_line(message: str | None) -> list[str]:
    if not message:
        return []
    tokens = []
    for token in TOKEN_RE.findall(message.lower()):
        if len(token) <= 2:
            continue
        if token in {"arg", "off", "size", "insn", "idx", "left", "right", "from", "into"}:
            continue
        tokens.append(token)
    return sorted(set(tokens))


def is_low_signal_line(line: str) -> bool:
    lowered = line.lower().strip()
    if not lowered:
        return True
    if lowered.startswith(
        (
            "processed ",
            "max_states",
            "peak_states",
            "mark_read",
            "verification time",
            "last_idx ",
            "regs=",
            "func#",
            "live regs before insn",
            "from ",
        )
    ):
        return True
    if line.startswith(";"):
        return True
    if INSTRUCTION_LINE_RE.match(line):
        return True
    if re.match(r"^[Rr]\d+=", line):
        return True
    return False


def select_human_error_line(log_text: str, *candidates: str | None) -> str | None:
    keywords = (
        "invalid",
        "expected",
        "cannot",
        "unreleased",
        "unsupported",
        "unbounded",
        "warning",
        "pointer",
        "reference",
        "must",
        "null",
        "access",
        "type=",
        "type ",
        "out of order",
    )

    for candidate in candidates:
        if candidate and not is_low_signal_line(candidate):
            return candidate.strip()

    best_line = None
    best_score = -1
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if is_low_signal_line(line):
            continue
        score = sum(keyword in line.lower() for keyword in keywords)
        if "error" in line.lower():
            score += 1
        if score > best_score:
            best_score = score
            best_line = line
    return best_line


def stable_root_cause(result: ObligeResult) -> str | None:
    for candidate in (result.causal_chain_summary, result.critical_transition, result.error_line):
        if candidate:
            return candidate
    return None


def execute_case_for_kernel(
    case: CaseSpec,
    runtime: KernelRuntime,
    helper_bin: Path,
    catalog_path: Path,
    base_work_dir: Path,
) -> KernelRunResult:
    if not runtime.available:
        return KernelRunResult(
            kernel=runtime.requested_version,
            available=False,
            reason=runtime.reason_unavailable,
        )

    assert runtime.kernel_root is not None
    assert runtime.vmlinux_btf is not None
    assert runtime.load_command is not None

    source_path = runtime.kernel_root / case.source_relpath
    if not source_path.exists():
        return KernelRunResult(
            kernel=runtime.requested_version,
            available=True,
            reason=f"Missing source file under kernel_root: {source_path}",
        )

    clang = shutil.which("clang")
    if clang is None:
        raise SystemExit("clang is not available in PATH")

    arch_macro, bpf_target = host_arch_macro()
    ensure_kernel_paths(runtime.kernel_root, arch_macro)

    kernel_work_dir = base_work_dir / runtime.requested_version.replace("/", "_")
    kernel_work_dir.mkdir(parents=True, exist_ok=True)
    ensure_vmlinux_header_from_btf(runtime.vmlinux_btf, kernel_work_dir)
    libbpf_include_dir = ensure_libbpf_headers(runtime.kernel_root, kernel_work_dir)
    clang_sys_includes = collect_clang_sys_includes(clang)
    compile_result = compile_source(
        source_path,
        work_dir=kernel_work_dir,
        libbpf_include_dir=libbpf_include_dir,
        clang=clang,
        clang_sys_includes=clang_sys_includes,
        arch_macro=arch_macro,
        bpf_target=bpf_target,
    )
    if not compile_result.ok or compile_result.object_path is None:
        stderr = compile_result.stderr.strip() or compile_result.stdout.strip() or "compile failed"
        return KernelRunResult(
            kernel=runtime.requested_version,
            available=True,
            compile_ok=False,
            reason=stderr,
        )

    command = format_load_command(
        runtime.load_command,
        helper=helper_bin,
        object_path=compile_result.object_path,
        program=case.program_name,
        kernel=runtime.requested_version,
    )
    completed = run_command(command)
    try:
        payload = json.loads(completed.stdout) if completed.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return KernelRunResult(
            kernel=runtime.requested_version,
            available=True,
            compile_ok=True,
            reason=f"Load command did not return JSON: {exc}",
            object_path=str(compile_result.object_path),
            error_message=completed.stderr.strip() or completed.stdout.strip(),
        )

    verifier_log = payload.get("verifier_log")
    error_message = payload.get("error_message")
    load_ok = payload.get("load_ok")
    if not isinstance(verifier_log, str):
        verifier_log = ""
    if not isinstance(error_message, str):
        error_message = completed.stderr.strip() or completed.stdout.strip() or None

    parsed = parse_log(verifier_log) if verifier_log else None
    oblige_result = run_oblige(verifier_log, catalog_path=catalog_path) if verifier_log else None
    error_line = None
    raw_tokens: list[str] = []
    error_id = None
    taxonomy_class = None
    root_cause = None
    source_mapping = None
    if oblige_result is not None:
        error_line = select_human_error_line(
            verifier_log,
            oblige_result.error_line,
            parsed.error_line if parsed is not None else None,
        )
        raw_tokens = tokenize_error_line(error_line)
        error_id = oblige_result.error_id
        taxonomy_class = oblige_result.taxonomy_class
        root_cause = stable_root_cause(oblige_result) or error_line
        if root_cause is not None and is_low_signal_line(root_cause) and error_line is not None:
            root_cause = error_line
        source_mapping = oblige_result.source_mapping

    return KernelRunResult(
        kernel=runtime.requested_version,
        available=True,
        compile_ok=True,
        load_ok=bool(load_ok) if isinstance(load_ok, bool) else None,
        reason=None,
        object_path=str(compile_result.object_path),
        error_message=error_message,
        verifier_log=verifier_log or None,
        raw_error_line=error_line,
        raw_error_tokens=raw_tokens,
        error_id=error_id,
        taxonomy_class=taxonomy_class,
        root_cause=root_cause,
        source_mapping=source_mapping,
    )


def jaccard_similarity(left: list[str] | None, right: list[str] | None) -> float:
    left_set = set(left or [])
    right_set = set(right or [])
    if not left_set and not right_set:
        return 1.0
    return len(left_set & right_set) / len(left_set | right_set)


def pairwise_comparisons(results: list[KernelRunResult]) -> list[PairwiseComparison]:
    comparable = [result for result in results if result.verifier_log]
    rows: list[PairwiseComparison] = []
    for left, right in combinations(comparable, 2):
        rows.append(
            PairwiseComparison(
                left_kernel=left.kernel,
                right_kernel=right.kernel,
                raw_token_jaccard=jaccard_similarity(left.raw_error_tokens, right.raw_error_tokens),
                error_id_exact_match=bool(left.error_id and right.error_id and left.error_id == right.error_id),
                taxonomy_exact_match=bool(
                    left.taxonomy_class
                    and right.taxonomy_class
                    and left.taxonomy_class == right.taxonomy_class
                ),
                root_cause_exact_match=bool(
                    left.root_cause and right.root_cause and left.root_cause == right.root_cause
                ),
            )
        )
    return rows


def summarize(results: list[KernelRunResult], pairs: list[PairwiseComparison]) -> dict[str, Any]:
    comparable = [result for result in results if result.verifier_log]
    distinct_error_ids = sorted({result.error_id for result in comparable if result.error_id})
    distinct_taxonomy = sorted({result.taxonomy_class for result in comparable if result.taxonomy_class})
    distinct_root_causes = sorted({result.root_cause for result in comparable if result.root_cause})
    return {
        "kernels_requested": len(results),
        "kernels_available": sum(result.available for result in results),
        "kernels_with_logs": len(comparable),
        "avg_pairwise_raw_token_jaccard": (
            round(sum(pair.raw_token_jaccard for pair in pairs) / len(pairs), 3) if pairs else None
        ),
        "error_id_exact_match_all": len(distinct_error_ids) <= 1 if comparable else None,
        "taxonomy_exact_match_all": len(distinct_taxonomy) <= 1 if comparable else None,
        "root_cause_exact_match_all": len(distinct_root_causes) <= 1 if comparable else None,
        "distinct_error_ids": distinct_error_ids,
        "distinct_taxonomy_classes": distinct_taxonomy,
        "distinct_root_causes": distinct_root_causes,
    }


def maybe_shorten(value: str | None, limit: int = 72) -> str:
    if not value:
        return ""
    text = value.replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def markdown_table(case: CaseSpec, results: list[KernelRunResult], pairs: list[PairwiseComparison], summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Cross-Kernel Stability: `{case.case_id}`")
    lines.append("")
    lines.append(f"- Case file: `{case.case_path}`")
    lines.append(f"- Program: `{case.program_name}` in `{case.source_relpath}`")
    lines.append(f"- Section: `{case.section}`")
    lines.append("")
    lines.append("## Per-kernel results")
    lines.append("")
    lines.append("| Kernel | Available | Compile | Load | Raw error line | OBLIGE error_id | Taxonomy | Root-cause proxy |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for result in results:
        lines.append(
            "| "
            + " | ".join(
                [
                    result.kernel,
                    "yes" if result.available else "no",
                    "yes" if result.compile_ok else "no",
                    (
                        "yes"
                        if result.load_ok is True
                        else "no"
                        if result.load_ok is False
                        else ""
                    ),
                    maybe_shorten(result.raw_error_line).replace("|", "\\|"),
                    result.error_id or "",
                    result.taxonomy_class or "",
                    maybe_shorten(result.root_cause).replace("|", "\\|"),
                ]
            )
            + " |"
        )
    lines.append("")
    lines.append("## Pairwise comparison")
    lines.append("")
    lines.append("| Kernels | Raw-token Jaccard | error_id exact-match | taxonomy exact-match | root-cause exact-match |")
    lines.append("| --- | --- | --- | --- | --- |")
    for pair in pairs:
        lines.append(
            f"| `{pair.left_kernel}` vs `{pair.right_kernel}` | "
            f"{pair.raw_token_jaccard:.3f} | "
            f"{'yes' if pair.error_id_exact_match else 'no'} | "
            f"{'yes' if pair.taxonomy_exact_match else 'no'} | "
            f"{'yes' if pair.root_cause_exact_match else 'no'} |"
        )
    if not pairs:
        lines.append("| n/a | n/a | n/a | n/a | n/a |")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for key, value in summary.items():
        lines.append(f"- {key}: `{value}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    host_release = current_kernel_release()
    case = load_case_spec(args.case_yaml.resolve())
    helper_bin = ensure_helper_binary(args.work_dir / "shared")
    results: list[KernelRunResult] = []
    for kernel in args.kernels:
        runtime = resolve_runtime(kernel, args, host_release)
        result = execute_case_for_kernel(
            case=case,
            runtime=runtime,
            helper_bin=helper_bin,
            catalog_path=args.catalog_path,
            base_work_dir=args.work_dir,
        )
        results.append(result)

    pairs = pairwise_comparisons(results)
    summary = summarize(results, pairs)
    payload = {
        "case_id": case.case_id,
        "case_path": str(case.case_path),
        "host_kernel_release": host_release,
        "results": [asdict(result) for result in results],
        "pairwise": [asdict(pair) for pair in pairs],
        "summary": summary,
    }

    markdown = markdown_table(case, results, pairs, summary)
    print(markdown)

    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_markdown is not None:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
