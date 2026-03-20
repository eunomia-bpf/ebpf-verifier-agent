#!/usr/bin/env python3
"""Materialize and verify lowering-artifact case directories."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CASE_ROOT = ROOT / "case_study" / "cases"
EVAL_CASES_DIR = CASE_ROOT / "eval_commits"
OUTPUT_ROOT = CASE_ROOT / "eval_commits_verified"
REPORT_PATH = ROOT / "docs" / "tmp" / "lowering-artifact-verification.md"
GROUND_TRUTH_PATH = ROOT / "case_study" / "ground_truth.yaml"
REPO_CACHE = ROOT / "case_study" / ".cache" / "lowering-artifact-repos"

REPO_PRIORITY = {"katran": 0, "bcc": 1, "cilium": 2}
REPO_SEARCH_PATHS = {
    "katran": ("katran/lib/bpf", "katran/decap/bpf"),
    "bcc": ("libbpf-tools", "examples", "tools"),
    "cilium": ("bpf",),
}
CODE_SUFFIXES = {".c", ".cc", ".cpp"}
HEADER_SUFFIXES = {".h", ".hpp"}
STRONG_FIX_TYPES = {"inline_hint", "volatile_hack", "attribute_annotation"}
SECONDARY_FIX_TYPES = {"alignment", "type_cast", "bounds_check"}
COMMIT_KEYWORD_PATTERNS: dict[str, re.Pattern[str]] = {
    "bounds": re.compile(r"\bbounds?\b", re.IGNORECASE),
    "range": re.compile(r"\brange\b", re.IGNORECASE),
    "clamp": re.compile(r"\bclamp(?:ing|ed)?\b", re.IGNORECASE),
    "mask": re.compile(r"\bmask(?:ing|ed)?\b", re.IGNORECASE),
    "volatile": re.compile(r"\bvolatile\b", re.IGNORECASE),
    "__always_inline": re.compile(r"__always_inline|always_inline", re.IGNORECASE),
    "lowering": re.compile(r"\blowering\b", re.IGNORECASE),
    "compiler": re.compile(r"\bcompiler\b", re.IGNORECASE),
    "llvm": re.compile(r"\bllvm\b", re.IGNORECASE),
    "spill": re.compile(r"\bspill(?:ed|ing)?\b", re.IGNORECASE),
    "reload": re.compile(r"\breload(?:ed|ing)?\b", re.IGNORECASE),
}
DIFF_SIGNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "clamp_or_mask": re.compile(r"\bclamp\b|\bmask\b", re.IGNORECASE),
    "verifier_visible_bound": re.compile(
        r"verifier-visible|bounded value|restoring a verifier-visible bound|keep precise track",
        re.IGNORECASE,
    ),
    "codegen_workaround": re.compile(
        r"older kernels accept|verifier-friendly code generation|inlining annotations|__always_inline|always_inline",
        re.IGNORECASE,
    ),
    "proof_reshaping": re.compile(
        r"\bproof\b|bounds check|explicit .*bound|unsigned range|signed range",
        re.IGNORECASE,
    ),
}
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
CODE_FENCE_RE = re.compile(r"```(?:c|cc|cpp|rust)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
FUNC_RE = re.compile(
    r"^\s*(?:static\s+)?(?:__always_inline\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_\s\*]+\([^;{}]*\)\s*\{",
    re.MULTILINE,
)
INSTRUCTION_LINE_RE = re.compile(r"^\d+: \(")
STATE_LINE_RE = re.compile(r"\bR\d[\w]*=")

GENERIC_TEMPLATE = textwrap.dedent(
    """\
    #include <vmlinux.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>
    #include <bpf/bpf_tracing.h>
    #include <bpf/bpf_core_read.h>
    """
)


@dataclass(slots=True)
class EvalCandidate:
    case_id: str
    path: Path
    payload: dict[str, Any]
    repo_name: str
    score: int


@dataclass(slots=True)
class CompileLoadResult:
    compiles: bool
    compile_rc: int | None
    compile_log: str
    verifier_pass: bool | None
    load_rc: int | None
    verifier_log: str
    reason: str
    command: list[str] = field(default_factory=list)
    load_command: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CaseResult:
    case_id: str
    source_kind: str
    repo_name: str
    case_dir: Path
    metadata: dict[str, Any]
    buggy: CompileLoadResult
    fixed: CompileLoadResult | None
    status: str
    reason: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument("--report-path", type=Path, default=REPORT_PATH)
    parser.add_argument("--top-eval", type=int, default=30)
    parser.add_argument("--skip-pytest", action="store_true")
    return parser.parse_args()


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    check: bool = False,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=check, capture_output=True, text=text)


def repo_name_from_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1].removesuffix(".git")


def load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_yaml(path: Path, payload: dict[str, Any]) -> None:
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=False, width=1000)
    write_text(path, text)


def complete_program_shape(source: str) -> bool:
    return "#include" in source and "SEC(" in source


def matched_patterns(text: str, patterns: dict[str, re.Pattern[str]]) -> list[str]:
    return [label for label, pattern in patterns.items() if pattern.search(text or "")]


def score_eval_case(case_path: Path, payload: dict[str, Any]) -> int:
    fix_type = str(payload.get("fix_type") or "").strip() or None
    taxonomy_class = str(payload.get("taxonomy_class") or "").strip() or None
    commit_message = str(payload.get("commit_message") or "")
    diff_summary = str(payload.get("diff_summary") or "")
    buggy_code = str(payload.get("buggy_code") or "")

    score = 0
    if taxonomy_class == "lowering_artifact":
        score += 6
    if fix_type in STRONG_FIX_TYPES:
        score += 4
    elif fix_type in SECONDARY_FIX_TYPES:
        score += 2
    score += min(3, len(matched_patterns(commit_message, COMMIT_KEYWORD_PATTERNS)))
    if matched_patterns(diff_summary, DIFF_SIGNAL_PATTERNS):
        score += 2
    if complete_program_shape(buggy_code):
        score += 1
    return score


def select_top_eval_cases(limit: int) -> list[EvalCandidate]:
    candidates: list[EvalCandidate] = []
    for case_path in sorted(EVAL_CASES_DIR.glob("eval-*.yaml")):
        payload = load_yaml(case_path)
        repo_name = repo_name_from_url(str(payload.get("repository") or ""))
        if repo_name not in REPO_PRIORITY:
            continue
        candidates.append(
            EvalCandidate(
                case_id=str(payload.get("case_id") or case_path.stem),
                path=case_path,
                payload=payload,
                repo_name=repo_name,
                score=score_eval_case(case_path, payload),
            )
        )
    candidates.sort(key=lambda item: (REPO_PRIORITY[item.repo_name], -item.score, item.case_id))
    return candidates[:limit]


def ground_truth_case_ids() -> list[str]:
    payload = yaml.safe_load(GROUND_TRUTH_PATH.read_text(encoding="utf-8")) or []
    if isinstance(payload, dict):
        payload = payload.get("cases") or []
    if not isinstance(payload, list):
        return []
    case_ids: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("taxonomy_class") != "lowering_artifact":
            continue
        if item.get("quarantined"):
            continue
        case_id = item.get("case_id")
        if isinstance(case_id, str):
            case_ids.append(case_id)
    return case_ids


def existing_lowering_case_paths() -> list[Path]:
    wanted = set(ground_truth_case_ids())
    paths: list[Path] = []
    for case_path in sorted((CASE_ROOT / "stackoverflow").glob("*.yaml")):
        if case_path.stem in wanted:
            paths.append(case_path)
    for case_path in sorted((CASE_ROOT / "github_issues").glob("*.yaml")):
        if case_path.stem in wanted:
            paths.append(case_path)
    return paths


def ensure_repo(repo_name: str, repo_url: str) -> Path:
    target = REPO_CACHE / repo_name
    if target.exists():
        probe = run(["git", "rev-parse", "HEAD"], cwd=target)
        if probe.returncode == 0:
            return target
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    run(
        ["git", "-c", "http.version=HTTP/1.1", "clone", "--filter=blob:none", repo_url, str(target)],
        check=True,
    )
    return target


def ensure_commit(repo_path: Path, commit_hash: str) -> None:
    probe = run(["git", "cat-file", "-e", f"{commit_hash}^{{commit}}"], cwd=repo_path)
    if probe.returncode == 0:
        return
    run(["git", "fetch", "--depth", "2", "origin", commit_hash], cwd=repo_path, check=True)


def git_stdout(repo_path: Path, *args: str) -> str:
    return run(["git", *args], cwd=repo_path, check=True).stdout


def git_cat_file_exists(repo_path: Path, rev: str, relpath: str) -> bool:
    return run(["git", "cat-file", "-e", f"{rev}:{relpath}"], cwd=repo_path).returncode == 0


def git_show_text(repo_path: Path, rev: str, relpath: str) -> str:
    return git_stdout(repo_path, "show", f"{rev}:{relpath}")


def git_show_resolved_text(repo_path: Path, rev: str, relpath: str) -> str:
    text = git_show_text(repo_path, rev, relpath)
    stripped = text.strip()
    if "\n" not in stripped and stripped.endswith(".h"):
        candidate = str(Path(relpath).parent / stripped).replace("\\", "/")
        if git_cat_file_exists(repo_path, rev, candidate):
            return git_show_text(repo_path, rev, candidate)
    return text


def changed_code_files(repo_path: Path, parent: str, commit_hash: str, repo_name: str) -> list[str]:
    search_paths = REPO_SEARCH_PATHS.get(repo_name, ("",))
    output = git_stdout(
        repo_path,
        "diff",
        "--name-status",
        "--diff-filter=M",
        parent,
        commit_hash,
        "--",
        *search_paths,
    )
    results: list[str] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        path = parts[-1]
        suffix = Path(path).suffix.lower()
        if suffix in CODE_SUFFIXES | HEADER_SUFFIXES:
            results.append(path)
    return results


def score_source_path(path: str, text: str) -> int:
    score = 0
    lower = path.lower()
    if ".bpf.c" in lower:
        score += 8
    if lower.endswith("_kern.c"):
        score += 6
    if "bpf" in lower:
        score += 4
    if 'SEC("' in text:
        score += 10
    if 'SEC("' in text and "license" in text.lower():
        score += 2
    quoted_includes = len(re.findall(r'^\s*#\s*include\s*"', text, re.MULTILINE))
    score -= quoted_includes
    if "xdp" in text.lower():
        score += 1
    if "BPF_PROG(" in text:
        score += 2
    score -= max(0, len(text.splitlines()) // 300)
    return score


def find_header_consumers(
    repo_path: Path,
    rev: str,
    header_path: str,
    repo_name: str,
) -> list[str]:
    basename = Path(header_path).name
    candidates: set[str] = set()
    for pattern in (basename, header_path):
        proc = run(
            ["git", "grep", "-l", pattern, rev, "--", *REPO_SEARCH_PATHS.get(repo_name, ("",))],
            cwd=repo_path,
        )
        if proc.returncode not in {0, 1}:
            continue
        for line in proc.stdout.splitlines():
            normalized = line
            prefix = f"{rev}:"
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
            if Path(normalized).suffix.lower() in CODE_SUFFIXES:
                candidates.add(normalized)
    return sorted(candidates)


def choose_target_file(repo_path: Path, commit_hash: str, parent: str, repo_name: str) -> tuple[str | None, list[str]]:
    changed_files = changed_code_files(repo_path, parent, commit_hash, repo_name)
    source_candidates: list[tuple[int, str]] = []
    for relpath in changed_files:
        if Path(relpath).suffix.lower() not in CODE_SUFFIXES:
            continue
        text = git_show_text(repo_path, commit_hash, relpath)
        source_candidates.append((score_source_path(relpath, text), relpath))
    if source_candidates:
        source_candidates.sort(key=lambda item: (-item[0], item[1]))
        return source_candidates[0][1], changed_files

    header_candidates: list[tuple[int, str]] = []
    seen: set[str] = set()
    for relpath in changed_files:
        if Path(relpath).suffix.lower() not in HEADER_SUFFIXES:
            continue
        for consumer in find_header_consumers(repo_path, commit_hash, relpath, repo_name):
            if consumer in seen:
                continue
            seen.add(consumer)
            text = git_show_text(repo_path, commit_hash, consumer)
            header_candidates.append((score_source_path(consumer, text), consumer))
    if header_candidates:
        header_candidates.sort(key=lambda item: (-item[0], item[1]))
        return header_candidates[0][1], changed_files
    return None, changed_files


def resolve_include(
    repo_path: Path,
    rev: str,
    current_path: str,
    include_name: str,
    extra_roots: list[str],
) -> str | None:
    current_dir = Path(current_path).parent
    candidate_paths = [current_dir / include_name]
    for root in extra_roots:
        candidate_paths.append(Path(root) / include_name)
    for candidate in candidate_paths:
        relpath = str(candidate).replace("\\", "/")
        if git_cat_file_exists(repo_path, rev, relpath):
            return relpath
    return None


def copy_include_closure(
    repo_path: Path,
    rev: str,
    target_file: str,
    case_dir: Path,
    repo_name: str,
    variant: str,
) -> tuple[list[str], list[str]]:
    headers_dir = case_dir / "headers" / variant
    copied: set[str] = set()
    unresolved: list[str] = []
    queue = [target_file]

    extra_roots = [str(Path(target_file).parent)]
    if repo_name == "katran":
        extra_roots.extend(["katran/lib/bpf", "katran/lib/linux_includes"])
    elif repo_name == "bcc":
        extra_roots.extend(["libbpf-tools", "libbpf-tools/x86"])
    elif repo_name == "cilium":
        extra_roots.extend(["bpf", "bpf/lib", str(Path(target_file).parent)])

    while queue:
        relpath = queue.pop()
        if relpath in copied:
            continue
        copied.add(relpath)
        if not git_cat_file_exists(repo_path, rev, relpath):
            unresolved.append(relpath)
            continue
        text = git_show_resolved_text(repo_path, rev, relpath)
        write_text(headers_dir / relpath, text)
        for include_name in INCLUDE_RE.findall(text):
            resolved = resolve_include(repo_path, rev, relpath, include_name, extra_roots)
            if resolved is None:
                unresolved.append(f"{relpath}: {include_name}")
                continue
            if resolved not in copied:
                queue.append(resolved)

    if repo_name == "bcc":
        vmlinux_rel = "libbpf-tools/x86/vmlinux.h"
        if git_cat_file_exists(repo_path, rev, vmlinux_rel):
            write_text(headers_dir / vmlinux_rel, git_show_resolved_text(repo_path, rev, vmlinux_rel))
    return sorted(copied), sorted(set(unresolved))


def repo_compile_flags(case_dir: Path, repo_name: str, variant: str) -> list[str]:
    headers = case_dir / "headers" / variant
    flags = ["clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86"]
    if repo_name == "katran":
        kver = run(["uname", "-r"], check=True).stdout.strip()
        flags.extend(
            [
                "-D__no_sanitize_or_inline=",
                "-include",
                "stddef.h",
                "-include",
                "stdbool.h",
                "-include",
                "stdint.h",
                "-include",
                "linux/types.h",
                "-I/usr/include",
                f"-I/usr/src/linux-headers-{kver}/include/uapi",
                f"-I/usr/src/linux-headers-{kver}/arch/x86/include/generated/uapi",
                f"-I/usr/src/linux-headers-{kver}/arch/x86/include/generated",
                f"-I/usr/src/linux-headers-{kver}/arch/x86/include/uapi",
                f"-I/usr/src/linux-headers-{kver}/arch/x86/include",
                f"-I/usr/src/linux-headers-{kver}/include",
                f"-I{headers / 'katran/lib/bpf'}",
                f"-I{headers / 'katran/lib/linux_includes'}",
            ]
        )
        return flags
    if repo_name == "bcc":
        flags.extend(
            [
                "-I/usr/include",
                f"-I{headers / 'libbpf-tools/x86'}",
                f"-I{headers / 'libbpf-tools'}",
            ]
        )
        return flags
    flags.extend(["-I/usr/include", f"-I{headers}"])
    return flags


def generic_compile_flags(case_dir: Path) -> list[str]:
    return [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-D__TARGET_ARCH_x86",
        "-I/usr/include",
    ]


def program_type_hint(source_text: str, repo_name: str) -> str | None:
    combined = source_text.lower()
    if 'sec("xdp' in combined or repo_name == "katran":
        return "xdp"
    if 'sec("tracepoint/' in combined:
        return "tracepoint"
    if 'sec("classifier' in combined or 'sec("tc' in combined:
        return "classifier"
    if 'sec("socket' in combined:
        return "socket"
    return None


def classify_load_outcome(log: str) -> bool | None:
    if not log.strip():
        return None
    verifier_markers = (
        "processed ",
        "invalid access",
        "R0 ",
        "R1 ",
        "max_states_per_insn",
        "stack depth",
        "min value is",
        "unbounded",
        "misaligned",
    )
    lower = log.lower()
    if any(marker.lower() in lower for marker in verifier_markers):
        return False
    return None


def load_object(
    obj_path: Path,
    *,
    repo_name: str,
    source_text: str,
    pin_name: str,
) -> tuple[bool | None, int | None, str, list[str]]:
    pin_path = f"/sys/fs/bpf/{pin_name}"
    run(["sudo", "rm", "-rf", pin_path])
    cmd = ["sudo", "bpftool", "-d"]
    if repo_name == "katran":
        cmd.extend(["-m", "-L"])
    cmd.extend(["prog", "loadall", str(obj_path), pin_path])
    prog_type = program_type_hint(source_text, repo_name)
    if prog_type is not None:
        cmd.extend(["type", prog_type])
    completed = run(cmd)
    run(["sudo", "rm", "-rf", pin_path])
    log = (completed.stdout + completed.stderr).strip()
    if completed.returncode == 0:
        verifier_pass: bool | None = True
    else:
        verifier_pass = classify_load_outcome(log)
    return verifier_pass, completed.returncode, log, cmd


def compile_and_load(
    case_dir: Path,
    *,
    repo_name: str,
    source_path: Path,
    obj_name: str,
    flags: list[str],
    pin_name: str,
) -> CompileLoadResult:
    obj_path = case_dir / obj_name
    cmd = [*flags, "-c", str(source_path), "-o", str(obj_path)]
    compile_proc = run(cmd)
    compile_log = (compile_proc.stdout + compile_proc.stderr).strip()
    if compile_proc.returncode != 0:
        return CompileLoadResult(
            compiles=False,
            compile_rc=compile_proc.returncode,
            compile_log=compile_log,
            verifier_pass=None,
            load_rc=None,
            verifier_log="",
            reason="compile_error",
            command=cmd,
            load_command=[],
        )
    source_text = source_path.read_text(encoding="utf-8")
    verifier_pass, load_rc, verifier_log, load_cmd = load_object(
        obj_path,
        repo_name=repo_name,
        source_text=source_text,
        pin_name=pin_name,
    )
    if verifier_pass is True:
        reason = "pass"
    elif verifier_pass is False:
        reason = "fail"
    else:
        reason = "load_error"
    return CompileLoadResult(
        compiles=True,
        compile_rc=compile_proc.returncode,
        compile_log=compile_log,
        verifier_pass=verifier_pass,
        load_rc=load_rc,
        verifier_log=verifier_log,
        reason=reason,
        command=cmd,
        load_command=load_cmd,
    )


def looks_like_code(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    markers = ["#include", "SEC(", "struct ", "if (", "return ", ";", "{", "}"]
    return sum(marker in stripped for marker in markers) >= 2


def extract_code_candidates(value: Any) -> list[str]:
    candidates: list[str] = []
    if isinstance(value, str):
        for block in CODE_FENCE_RE.findall(value):
            if looks_like_code(block):
                candidates.append(block.strip())
        if looks_like_code(value):
            candidates.append(value.strip())
    elif isinstance(value, list):
        for item in value:
            candidates.extend(extract_code_candidates(item))
    elif isinstance(value, dict):
        for nested in value.values():
            candidates.extend(extract_code_candidates(nested))
    return candidates


def wrap_snippet(snippet: str) -> str:
    code = snippet.strip()
    if not code:
        return ""
    if "#include" in code or "SEC(" in code:
        if 'SEC("license")' in code or "SEC(\"license\")" in code:
            return code.rstrip() + "\n"
        return code.rstrip() + '\nchar _license[] SEC("license") = "GPL";\n'
    if FUNC_RE.search(code):
        return GENERIC_TEMPLATE + "\n" + code.rstrip() + '\nchar _license[] SEC("license") = "GPL";\n'
    body = textwrap.indent(code, "    ")
    return (
        GENERIC_TEMPLATE
        + "\n"
        + 'SEC("xdp")\n'
        + "int repro(struct xdp_md *ctx)\n{\n"
        + "    void *data = (void *)(long)ctx->data;\n"
        + "    void *data_end = (void *)(long)ctx->data_end;\n"
        + "    (void)data;\n"
        + "    (void)data_end;\n"
        + body
        + "\n    return XDP_PASS;\n}\n"
        + 'char _license[] SEC("license") = "GPL";\n'
    )


def select_buggy_fixed_from_case(payload: dict[str, Any]) -> tuple[str, str | None, str, str | None]:
    source_snippets = payload.get("source_snippets") or []
    buggy_candidates = extract_code_candidates(source_snippets)
    buggy_code = max(buggy_candidates, key=len) if buggy_candidates else ""
    buggy_origin = "source_snippets"

    fixed_candidates: list[str] = []
    fixed_origin: str | None = None
    for key in ("fixed_code", "selected_answer", "fix", "source_snippets"):
        candidates = extract_code_candidates(payload.get(key))
        if candidates:
            fixed_candidates = candidates
            fixed_origin = key
            break
    fixed_code = max(fixed_candidates, key=len) if fixed_candidates else None
    return buggy_code, fixed_code, buggy_origin, fixed_origin


def classify_log_quality(verifier_log: str) -> str:
    instruction_lines = sum(
        1 for line in verifier_log.splitlines() if INSTRUCTION_LINE_RE.match(line.strip())
    )
    state_lines = sum(1 for line in verifier_log.splitlines() if STATE_LINE_RE.search(line))
    if instruction_lines >= 3 and state_lines >= 1:
        return "trace_rich"
    if instruction_lines >= 1 or state_lines >= 1:
        return "partial"
    return "message_only" if verifier_log.strip() else "none"


def status_from_results(buggy: CompileLoadResult, fixed: CompileLoadResult | None) -> tuple[str, str]:
    if fixed and buggy.compiles and buggy.verifier_pass is False and fixed.compiles and fixed.verifier_pass:
        return "confirmed", "buggy rejected by verifier and fixed loaded successfully"
    if buggy.compiles and fixed and fixed.compiles:
        return "partial", f"buggy={buggy.reason}, fixed={fixed.reason}"
    if buggy.compiles:
        return "partial", f"buggy={buggy.reason}"
    return "failed", buggy.reason


def makefile_text(case_id: str, repo_name: str, fixed_available: bool) -> str:
    if repo_name == "katran":
        cflags = textwrap.dedent(
            """\
            COMMON_CFLAGS := -target bpf -O2 -g -D__TARGET_ARCH_x86 -D__no_sanitize_or_inline= \
            	-include stddef.h -include stdbool.h -include stdint.h -include linux/types.h \
            	-I/usr/include \
            	-I/usr/src/linux-headers-$(shell uname -r)/include/uapi \
            	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated/uapi \
            	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated \
            	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include/uapi \
            	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include \
            	-I/usr/src/linux-headers-$(shell uname -r)/include
            BUGGY_INCLUDE_FLAGS := -I$(CURDIR)/headers/buggy/katran/lib/bpf -I$(CURDIR)/headers/buggy/katran/lib/linux_includes
            FIXED_INCLUDE_FLAGS := -I$(CURDIR)/headers/fixed/katran/lib/bpf -I$(CURDIR)/headers/fixed/katran/lib/linux_includes
            LOAD_PREFIX := sudo bpftool -m -L -d prog loadall
            LOAD_SUFFIX := type xdp
            """
        )
    elif repo_name == "bcc":
        cflags = textwrap.dedent(
            """\
            COMMON_CFLAGS := -target bpf -O2 -g -D__TARGET_ARCH_x86 -I/usr/include
            BUGGY_INCLUDE_FLAGS := -I$(CURDIR)/headers/buggy/libbpf-tools/x86 -I$(CURDIR)/headers/buggy/libbpf-tools
            FIXED_INCLUDE_FLAGS := -I$(CURDIR)/headers/fixed/libbpf-tools/x86 -I$(CURDIR)/headers/fixed/libbpf-tools
            LOAD_PREFIX := sudo bpftool -d prog loadall
            LOAD_SUFFIX :=
            """
        )
    else:
        cflags = textwrap.dedent(
            """\
            COMMON_CFLAGS := -target bpf -O2 -g -D__TARGET_ARCH_x86 -I/usr/include
            BUGGY_INCLUDE_FLAGS :=
            FIXED_INCLUDE_FLAGS :=
            LOAD_PREFIX := sudo bpftool -d prog loadall
            LOAD_SUFFIX := type xdp
            """
        )
    fixed_targets = textwrap.dedent(
        f"""\
        fixed.o: fixed.c
        \tclang $(COMMON_CFLAGS) $(FIXED_INCLUDE_FLAGS) -c $< -o $@

        verify-fixed: fixed.o
        \tsudo rm -rf /sys/fs/bpf/{case_id}_fixed
        \t$(LOAD_PREFIX) $< /sys/fs/bpf/{case_id}_fixed $(LOAD_SUFFIX)
        \tsudo rm -rf /sys/fs/bpf/{case_id}_fixed
        """
    ) if fixed_available else ""
    return (
        cflags
        + "\n"
        + textwrap.dedent(
            f"""\
            .PHONY: all clean verify-buggy verify-fixed

            all: buggy.o{" fixed.o" if fixed_available else ""}

            buggy.o: buggy.c
            \tclang $(COMMON_CFLAGS) $(BUGGY_INCLUDE_FLAGS) -c $< -o $@

            verify-buggy: buggy.o
            \tsudo rm -rf /sys/fs/bpf/{case_id}_buggy
            \t$(LOAD_PREFIX) $< /sys/fs/bpf/{case_id}_buggy $(LOAD_SUFFIX)
            \tsudo rm -rf /sys/fs/bpf/{case_id}_buggy

            {fixed_targets}clean:
            \trm -f buggy.o fixed.o
            """
        )
    )


def write_attempt_artifacts(
    case_dir: Path,
    *,
    metadata: dict[str, Any],
    buggy: CompileLoadResult,
    fixed: CompileLoadResult | None,
    status: str,
    reason: str,
) -> None:
    write_yaml(case_dir / "metadata.yaml", metadata)
    write_text(case_dir / "compile_log_buggy.txt", buggy.compile_log + ("\n" if buggy.compile_log else ""))
    if buggy.verifier_log:
        write_text(case_dir / "verifier_log_buggy.txt", buggy.verifier_log + "\n")
    if fixed is not None:
        write_text(case_dir / "compile_log_fixed.txt", fixed.compile_log + ("\n" if fixed.compile_log else ""))
        if fixed.verifier_log:
            write_text(case_dir / "verifier_log_fixed.txt", fixed.verifier_log + "\n")
    write_text(
        case_dir / "verification_status.txt",
        f"status: {status}\nreason: {reason}\n"
        f"buggy_compile: {buggy.compiles}\n"
        f"buggy_verifier_pass: {buggy.verifier_pass}\n"
        f"fixed_compile: {fixed.compiles if fixed else 'n/a'}\n"
        f"fixed_verifier_pass: {fixed.verifier_pass if fixed else 'n/a'}\n",
    )


def process_eval_case(candidate: EvalCandidate, output_root: Path) -> CaseResult:
    payload = candidate.payload
    case_dir = output_root / candidate.case_id
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    repo_path = ensure_repo(candidate.repo_name, str(payload.get("repository") or ""))
    commit_hash = str(payload.get("commit_hash"))
    ensure_commit(repo_path, commit_hash)
    parent = git_stdout(repo_path, "rev-parse", f"{commit_hash}^").strip()
    target_file, changed_files = choose_target_file(repo_path, commit_hash, parent, candidate.repo_name)
    if target_file is None:
        buggy = CompileLoadResult(False, None, "", None, None, "", "no_target_file")
        fixed = CompileLoadResult(False, None, "", None, None, "", "no_target_file")
        metadata = {
            "case_id": candidate.case_id,
            "source": "eval_commits",
            "repository": payload.get("repository"),
            "repo_name": candidate.repo_name,
            "commit_hash": commit_hash,
            "parent_commit": parent,
            "case_yaml": str(candidate.path),
            "score": candidate.score,
            "changed_files": changed_files,
            "selected_source_file": None,
        }
        write_text(case_dir / "buggy.c", "/* unable to identify a full compilation unit */\n")
        write_text(case_dir / "fixed.c", "/* unable to identify a full compilation unit */\n")
        write_text(case_dir / "Makefile", makefile_text(candidate.case_id, candidate.repo_name, True))
        status, reason = "failed", "no_target_file"
        write_attempt_artifacts(case_dir, metadata=metadata, buggy=buggy, fixed=fixed, status=status, reason=reason)
        return CaseResult(candidate.case_id, "eval_commits", candidate.repo_name, case_dir, metadata, buggy, fixed, status, reason)

    buggy_source = git_show_text(repo_path, parent, target_file)
    fixed_source = git_show_text(repo_path, commit_hash, target_file)
    write_text(case_dir / "buggy.c", buggy_source)
    write_text(case_dir / "fixed.c", fixed_source)
    copied_buggy, unresolved_buggy = copy_include_closure(
        repo_path, parent, target_file, case_dir, candidate.repo_name, "buggy"
    )
    copied_fixed, unresolved_fixed = copy_include_closure(
        repo_path, commit_hash, target_file, case_dir, candidate.repo_name, "fixed"
    )
    write_text(case_dir / "Makefile", makefile_text(candidate.case_id, candidate.repo_name, True))

    buggy = compile_and_load(
        case_dir,
        repo_name=candidate.repo_name,
        source_path=case_dir / "buggy.c",
        obj_name="buggy.o",
        flags=repo_compile_flags(case_dir, candidate.repo_name, "buggy"),
        pin_name=f"{candidate.case_id}_buggy",
    )
    fixed = compile_and_load(
        case_dir,
        repo_name=candidate.repo_name,
        source_path=case_dir / "fixed.c",
        obj_name="fixed.o",
        flags=repo_compile_flags(case_dir, candidate.repo_name, "fixed"),
        pin_name=f"{candidate.case_id}_fixed",
    )
    status, reason = status_from_results(buggy, fixed)
    metadata = {
        "case_id": candidate.case_id,
        "source": "eval_commits",
        "repository": payload.get("repository"),
        "repo_name": candidate.repo_name,
        "commit_hash": commit_hash,
        "parent_commit": parent,
        "case_yaml": str(candidate.path),
        "score": candidate.score,
        "changed_files": changed_files,
        "selected_source_file": target_file,
        "buggy_include_closure": copied_buggy,
        "fixed_include_closure": copied_fixed,
        "unresolved_buggy_includes": unresolved_buggy,
        "unresolved_fixed_includes": unresolved_fixed,
        "compile_command_buggy": buggy.command,
        "compile_command_fixed": fixed.command,
        "load_command_buggy": buggy.load_command,
        "load_command_fixed": fixed.load_command,
    }
    write_attempt_artifacts(case_dir, metadata=metadata, buggy=buggy, fixed=fixed, status=status, reason=reason)
    return CaseResult(candidate.case_id, "eval_commits", candidate.repo_name, case_dir, metadata, buggy, fixed, status, reason)


def process_existing_case(case_path: Path, output_root: Path) -> CaseResult:
    payload = load_yaml(case_path)
    case_id = str(payload.get("case_id") or case_path.stem)
    repo_name = repo_name_from_url(str(payload.get("repository") or payload.get("issue", {}).get("repository") or ""))
    if not repo_name:
        repo_name = str(payload.get("source") or case_path.parent.name)
    case_dir = output_root / case_id
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    buggy_snippet, fixed_snippet, buggy_origin, fixed_origin = select_buggy_fixed_from_case(payload)
    wrapped_buggy = wrap_snippet(buggy_snippet)
    wrapped_fixed = wrap_snippet(fixed_snippet) if fixed_snippet else None
    write_text(case_dir / "buggy.c", wrapped_buggy or "/* no code-like buggy source found */\n")
    if wrapped_fixed:
        write_text(case_dir / "fixed.c", wrapped_fixed)
    write_text(case_dir / "Makefile", makefile_text(case_id, "generic", wrapped_fixed is not None))

    buggy = compile_and_load(
        case_dir,
        repo_name="generic",
        source_path=case_dir / "buggy.c",
        obj_name="buggy.o",
        flags=generic_compile_flags(case_dir),
        pin_name=f"{case_id}_buggy",
    ) if wrapped_buggy else CompileLoadResult(False, None, "", None, None, "", "no_buggy_source")

    fixed = None
    if wrapped_fixed:
        fixed = compile_and_load(
            case_dir,
            repo_name="generic",
            source_path=case_dir / "fixed.c",
            obj_name="fixed.o",
            flags=generic_compile_flags(case_dir),
            pin_name=f"{case_id}_fixed",
        )
    status, reason = status_from_results(buggy, fixed)
    metadata = {
        "case_id": case_id,
        "source": case_path.parent.name,
        "case_yaml": str(case_path),
        "buggy_origin": buggy_origin,
        "fixed_origin": fixed_origin,
        "repository_hint": payload.get("repository") or payload.get("issue", {}).get("repository"),
        "compile_command_buggy": buggy.command,
        "compile_command_fixed": fixed.command if fixed else None,
        "load_command_buggy": buggy.load_command,
        "load_command_fixed": fixed.load_command if fixed else None,
    }
    write_attempt_artifacts(case_dir, metadata=metadata, buggy=buggy, fixed=fixed, status=status, reason=reason)
    return CaseResult(case_id, case_path.parent.name, repo_name, case_dir, metadata, buggy, fixed, status, reason)


def render_report(
    results: list[CaseResult],
    selected_eval: list[EvalCandidate],
    existing_paths: list[Path],
) -> str:
    eval_results = [result for result in results if result.source_kind == "eval_commits"]
    existing_results = [result for result in results if result.source_kind != "eval_commits"]

    def count_compiled(items: list[CaseResult], which: str) -> int:
        return sum(1 for item in items if getattr(item, which).compiles)

    def count_verifier_pass(items: list[CaseResult], which: str) -> int:
        return sum(1 for item in items if getattr(item, which).verifier_pass is True)

    def count_verifier_fail(items: list[CaseResult], which: str) -> int:
        return sum(1 for item in items if getattr(item, which).verifier_pass is False)

    fully_confirmed = [item for item in results if item.status == "confirmed"]

    per_repo: dict[str, Counter[str]] = defaultdict(Counter)
    for item in results:
        bucket = per_repo[item.repo_name or item.source_kind]
        bucket["attempted"] += 1
        bucket["buggy_compiled"] += int(item.buggy.compiles)
        bucket["buggy_reject"] += int(item.buggy.verifier_pass is False)
        if item.fixed is not None:
            bucket["fixed_compiled"] += int(item.fixed.compiles)
            bucket["fixed_pass"] += int(item.fixed.verifier_pass is True)
        bucket["confirmed"] += int(item.status == "confirmed")

    failure_reasons: Counter[str] = Counter()
    header_helped = 0
    for item in eval_results:
        if item.buggy.compiles or (item.fixed and item.fixed.compiles):
            if item.metadata.get("buggy_include_closure") or item.metadata.get("fixed_include_closure"):
                header_helped += 1
        failure_reasons[item.reason] += 1
        failure_reasons[item.buggy.reason] += 1
        if item.fixed is not None:
            failure_reasons[item.fixed.reason] += 1
    for item in existing_results:
        failure_reasons[item.reason] += 1
        failure_reasons[item.buggy.reason] += 1
        if item.fixed is not None:
            failure_reasons[item.fixed.reason] += 1

    lines: list[str] = [
        "# Lowering Artifact Verification",
        "",
        "## Scope",
        "",
        f"- `eval_commits` candidates attempted: `{len(selected_eval)}`",
        "  Selection policy: repo priority `katran -> bcc -> cilium`, then heuristic lowering-artifact score.",
        f"- Existing non-quarantined SO/GH lowering_artifact cases attempted: `{len(existing_paths)}`",
        f"- Total attempted: `{len(results)}`",
        f"- Buggy compiled: `{count_compiled(results, 'buggy')}`",
        f"- Buggy verifier reject: `{count_verifier_fail(results, 'buggy')}`",
        f"- Fixed compiled: `{sum(1 for item in results if item.fixed and item.fixed.compiles)}`",
        f"- Fixed verifier pass: `{sum(1 for item in results if item.fixed and item.fixed.verifier_pass is True)}`",
        f"- Fully confirmed: `{len(fully_confirmed)}`",
        "",
        "## Dataset Split",
        "",
        f"- `eval_commits`: `{len(eval_results)}` attempted, `{count_compiled(eval_results, 'buggy')}` buggy compiled, `{count_verifier_fail(eval_results, 'buggy')}` buggy reject.",
        f"- Existing SO/GH: `{len(existing_results)}` attempted, `{count_compiled(existing_results, 'buggy')}` buggy compiled, `{count_verifier_fail(existing_results, 'buggy')}` buggy reject.",
        "",
        "## Per-Repo Breakdown",
        "",
        "| Bucket | Attempted | Buggy Compiled | Buggy Reject | Fixed Compiled | Fixed Pass | Confirmed |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for bucket_name in sorted(per_repo):
        bucket = per_repo[bucket_name]
        lines.append(
            "| "
            + " | ".join(
                [
                    bucket_name,
                    str(bucket["attempted"]),
                    str(bucket["buggy_compiled"]),
                    str(bucket["buggy_reject"]),
                    str(bucket["fixed_compiled"]),
                    str(bucket["fixed_pass"]),
                    str(bucket["confirmed"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Failure Reasons",
            "",
            f"- Cases where header extraction still led to at least one successful compile: `{header_helped}`",
            "",
            "| Reason | Count |",
            "| --- | ---: |",
        ]
    )
    for reason, count in failure_reasons.most_common():
        lines.append(f"| `{reason}` | {count} |")

    lines.extend(["", "## Confirmed Cases", ""])
    if fully_confirmed:
        for item in fully_confirmed:
            log_quality = classify_log_quality((item.buggy.verifier_log or "") + "\n" + (item.fixed.verifier_log or ""))
            lines.append(
                f"- `{item.case_id}` ({item.repo_name}): log quality `{log_quality}`; dir `{item.case_dir.relative_to(ROOT)}`."
            )
    else:
        lines.append("- No case reached `buggy reject + fixed pass` on this host/kernel with the generated standalone units.")

    lines.extend(
        [
            "",
            "## Attempted Cases",
            "",
            "| Case ID | Source | Repo | Buggy Compile | Buggy Result | Fixed Compile | Fixed Result | Status | Selected File / Origin | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in sorted(results, key=lambda result: (result.source_kind, result.case_id)):
        selected = item.metadata.get("selected_source_file") or item.metadata.get("buggy_origin") or "n/a"
        fixed_compile = "yes" if item.fixed and item.fixed.compiles else "no"
        fixed_result = (
            "pass"
            if item.fixed and item.fixed.verifier_pass is True
            else "fail"
            if item.fixed and item.fixed.verifier_pass is False
            else item.fixed.reason if item.fixed else "n/a"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{item.case_id}`",
                    item.source_kind,
                    item.repo_name,
                    "yes" if item.buggy.compiles else "no",
                    "pass"
                    if item.buggy.verifier_pass is True
                    else "fail"
                    if item.buggy.verifier_pass is False
                    else item.buggy.reason,
                    fixed_compile,
                    fixed_result,
                    item.status,
                    f"`{selected}`",
                    item.reason.replace("|", "/"),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def run_pytest() -> subprocess.CompletedProcess[str]:
    return run(["pytest"], cwd=ROOT)


def main() -> int:
    args = parse_args()
    output_root: Path = args.output_root
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    selected_eval = select_top_eval_cases(args.top_eval)
    existing_paths = existing_lowering_case_paths()
    results: list[CaseResult] = []

    for candidate in selected_eval:
        results.append(process_eval_case(candidate, output_root))
    for case_path in existing_paths:
        results.append(process_existing_case(case_path, output_root))

    report = render_report(results, selected_eval, existing_paths)
    write_text(args.report_path, report)

    if not args.skip_pytest:
        pytest_proc = run_pytest()
        write_text(
            output_root / "pytest.txt",
            (pytest_proc.stdout + pytest_proc.stderr).strip() + "\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
