#!/usr/bin/env python3
"""Compile top-scored Cilium eval_commits cases with actual Cilium headers."""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from case_study.verify_lowering_artifact_cases import (  # noqa: E402
    choose_target_file,
    ensure_commit,
    git_stdout,
)
from scripts.find_lowering_artifact_commits import score_case  # noqa: E402


DEFAULT_CASES_DIR = ROOT / "case_study" / "cases" / "eval_commits"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "cilium-compilation-results.md"
DEFAULT_REPO_PATH = Path("/tmp/cilium-repo")
INCLUDE_DIRS = ("bpf", "bpf/lib", "bpf/include")
DECLARED_FILE_RE = re.compile(r"^\s*//\s*FILE:\s*(\S+)\s*$", re.MULTILINE)
VERIFIER_REJECT_MARKERS = (
    "invalid access",
    "math between",
    "pointer arithmetic",
    "unbounded",
    "out of bounds",
    "misaligned",
    "stack depth",
    "back-edge",
    "sequence of",
    "processed ",
    "min value is",
    "max value is",
    "r0 ",
    "r1 ",
    "r2 ",
    "r3 ",
    "type=scalar expected=",
)
LOADER_FAILURE_MARKERS = (
    "error loading btf",
    "failed to open object",
    "failed to load object",
    "failed to guess program type",
    "load bpf program failed",
    "libbpf: ",
    "object file doesn't contain any bpf program",
    "operation not permitted",
    "permission denied",
    "unsupported relo",
)


@dataclass(slots=True)
class Candidate:
    case_id: str
    path: Path
    score: int
    commit_hash: str
    buggy_code: str
    declared_file: str | None


@dataclass(slots=True)
class CompileLoadResult:
    attempted: bool = False
    compiled: bool = False
    source_path: str | None = None
    compile_command: list[str] = field(default_factory=list)
    compile_returncode: int | None = None
    compile_log: str = ""
    extra_flags: list[str] = field(default_factory=list)
    load_attempted: bool = False
    load_returncode: int | None = None
    load_log: str = ""
    load_status: str | None = None
    note: str = ""


@dataclass(slots=True)
class CaseResult:
    candidate: Candidate
    parent_commit: str | None
    target_file: str | None
    target_reason: str | None
    snippet: CompileLoadResult
    actual: CompileLoadResult

    @property
    def final_method(self) -> str:
        if self.snippet.compiled:
            return "snippet"
        if self.actual.compiled:
            return "actual_file"
        return "none"

    @property
    def final_result(self) -> CompileLoadResult | None:
        if self.snippet.compiled:
            return self.snippet
        if self.actual.compiled:
            return self.actual
        return None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR)
    parser.add_argument("--repo-path", type=Path, default=DEFAULT_REPO_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--limit", type=int, default=50)
    return parser.parse_args()


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=text,
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def extract_declared_file(snippet: str) -> str | None:
    match = DECLARED_FILE_RE.search(snippet or "")
    return match.group(1) if match else None


def first_meaningful_line(text: str) -> str:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("make: Entering directory") and not line.startswith("make: Leaving directory"):
            return line
    return ""


def best_log_line(text: str) -> str:
    preferred_markers = (
        " error:",
        "fatal error:",
        "libbpf:",
        "invalid access",
        "processed ",
        "stack depth",
        "too many arguments",
        "stack arguments are not supported",
        "failed to ",
        "permission denied",
        "operation not permitted",
    )
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if any(marker in line.lower() for marker in preferred_markers):
            return re.sub(r"/tmp/[^ :]+/", "", line)
    return re.sub(r"/tmp/[^ :]+/", "", first_meaningful_line(text))


def truncate(text: str, limit: int = 120) -> str:
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def ensure_cilium_repo(repo_path: Path) -> None:
    if (repo_path / ".git").is_dir():
        return
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    completed = run(
        ["git", "clone", "--depth", "1", "https://github.com/cilium/cilium.git", str(repo_path)],
        cwd=ROOT,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"failed to clone Cilium repo: {(completed.stdout + completed.stderr).strip()}")


def select_top_cilium_candidates(cases_dir: Path, limit: int) -> list[Candidate]:
    rows: list[Candidate] = []
    for case_path in sorted(cases_dir.glob("eval-cilium-*.yaml")):
        payload = load_yaml(case_path)
        record = score_case(case_path, payload, min_score=0)
        rows.append(
            Candidate(
                case_id=record.case_id,
                path=case_path,
                score=record.score,
                commit_hash=str(payload.get("commit_hash") or ""),
                buggy_code=str(payload.get("buggy_code") or ""),
                declared_file=extract_declared_file(str(payload.get("buggy_code") or "")),
            )
        )
    rows.sort(key=lambda item: (-item.score, item.case_id))
    return rows[:limit]


def pin_path(case_id: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{case_id}:{suffix}".encode("utf-8")).hexdigest()[:12]
    return f"/sys/fs/bpf/cilium_eval_{digest}"


def cleanup_pin(path: str) -> None:
    run(["sudo", "rm", "-rf", path])


def classify_load_status(returncode: int, log: str) -> str:
    if returncode == 0:
        return "loaded"
    lower = log.lower()
    if any(marker in lower for marker in VERIFIER_REJECT_MARKERS):
        return "verifier_reject"
    if any(marker in lower for marker in LOADER_FAILURE_MARKERS):
        return "loader_error"
    return "load_error"


def load_object(obj_path: Path, case_id: str, suffix: str) -> tuple[int, str, str]:
    target = pin_path(case_id, suffix)
    cleanup_pin(target)
    completed = run(
        ["sudo", "bpftool", "prog", "load", str(obj_path), target],
        cwd=ROOT,
    )
    cleanup_pin(target)
    log = (completed.stdout + completed.stderr).strip()
    return completed.returncode, log, classify_load_status(completed.returncode, log)


def compile_source(
    source_path: Path,
    obj_path: Path,
    include_roots: list[Path],
    *,
    extra_flags: list[str] | None = None,
    force_c: bool = False,
) -> tuple[list[str], subprocess.CompletedProcess[str]]:
    cmd = ["clang", "-target", "bpf", "-O2", "-g"]
    if extra_flags:
        cmd.extend(extra_flags)
    for include_root in include_roots:
        cmd.extend(["-I", str(include_root)])
    cmd.extend(["-I", "/usr/include"])
    if force_c:
        cmd.extend(["-x", "c"])
    cmd.extend(["-c", str(source_path), "-o", str(obj_path)])
    return cmd, run(cmd, cwd=ROOT)


def extract_make_compile_flags(make_output: str, compile_dir: Path) -> list[str]:
    clang_lines: list[str] = []
    for raw_line in make_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("clang ") or re.match(r"^/[^ ]*clang(\s|$)", line):
            clang_lines.append(line)
    if not clang_lines:
        return []
    tokens = shlex.split(clang_lines[-1])
    results: list[str] = []
    idx = 1
    while idx < len(tokens):
        token = tokens[idx]
        if token in {"-c", "-o"}:
            break
        if token.startswith("-D"):
            results.append(token)
        elif token == "-D" and idx + 1 < len(tokens):
            results.extend([token, tokens[idx + 1]])
            idx += 1
        elif token.startswith("-I"):
            if token == "-I" and idx + 1 < len(tokens):
                include_path = tokens[idx + 1]
                resolved = str((compile_dir / include_path).resolve()) if not Path(include_path).is_absolute() else include_path
                results.extend(["-I", resolved])
                idx += 1
            else:
                include_path = token[2:]
                if include_path:
                    resolved = str((compile_dir / include_path).resolve()) if not Path(include_path).is_absolute() else include_path
                    results.append(f"-I{resolved}")
        elif token == "-include" and idx + 1 < len(tokens):
            include_file = tokens[idx + 1]
            resolved = str((compile_dir / include_file).resolve()) if not Path(include_file).is_absolute() else include_file
            results.extend(["-include", resolved])
            idx += 1
        idx += 1
    return results


def make_flag_hints(worktree_dir: Path, target_file: str) -> list[str]:
    source_path = worktree_dir / target_file
    if source_path.suffix.lower() != ".c":
        return []
    compile_dir = source_path.parent
    completed = run(["make", "-n", "-C", str(compile_dir), source_path.with_suffix(".o").name], cwd=ROOT)
    if completed.returncode != 0:
        return []
    return extract_make_compile_flags(completed.stdout, compile_dir)


def resolve_target_file(repo_path: Path, candidate: Candidate) -> tuple[str | None, str | None, str | None]:
    ensure_commit(repo_path, candidate.commit_hash)
    parent = git_stdout(repo_path, "rev-parse", f"{candidate.commit_hash}^").strip()
    target_file, _changed = choose_target_file(repo_path, candidate.commit_hash, parent, "cilium")
    if target_file is not None:
        return parent, target_file, "commit_diff"
    if candidate.declared_file:
        probe = run(["git", "cat-file", "-e", f"{parent}:{candidate.declared_file}"], cwd=repo_path)
        if probe.returncode == 0:
            return parent, candidate.declared_file, "snippet_declared_file"
    return parent, None, None


def attempt_snippet(candidate: Candidate, include_roots: list[Path]) -> CompileLoadResult:
    result = CompileLoadResult(attempted=True, source_path="snippet:buggy_code")
    with tempfile.TemporaryDirectory(prefix=f"{candidate.case_id}-snippet-") as tmpdir_name:
        tmpdir = Path(tmpdir_name)
        source_path = tmpdir / "prog.c"
        obj_path = tmpdir / "prog.o"
        source_path.write_text(candidate.buggy_code, encoding="utf-8")
        cmd, completed = compile_source(source_path, obj_path, include_roots)
        result.compile_command = cmd
        result.compile_returncode = completed.returncode
        result.compile_log = (completed.stdout + completed.stderr).strip()
        result.compiled = completed.returncode == 0
        if not result.compiled:
            result.note = truncate(best_log_line(result.compile_log) or "snippet compilation failed")
            return result
        result.load_attempted = True
        load_rc, load_log, load_status = load_object(obj_path, candidate.case_id, "snippet")
        result.load_returncode = load_rc
        result.load_log = load_log
        result.load_status = load_status
        result.note = truncate(best_log_line(load_log) or load_status or "loaded")
        return result


def attempt_actual_file(repo_path: Path, candidate: Candidate) -> tuple[str | None, str | None, CompileLoadResult]:
    parent_commit, target_file, target_reason = resolve_target_file(repo_path, candidate)
    result = CompileLoadResult(attempted=target_file is not None, source_path=target_file)
    if target_file is None:
        result.note = "no target file"
        return parent_commit, target_file, result

    with tempfile.TemporaryDirectory(prefix=f"{candidate.case_id}-worktree-") as worktree_name:
        worktree_dir = Path(worktree_name)
        worktree_added = run(["git", "-C", str(repo_path), "worktree", "add", "--detach", str(worktree_dir), parent_commit], cwd=ROOT)
        if worktree_added.returncode != 0:
            result.note = truncate(first_meaningful_line(worktree_added.stderr) or "worktree creation failed")
            result.compile_log = (worktree_added.stdout + worktree_added.stderr).strip()
            return parent_commit, target_file, result
        try:
            source_path = worktree_dir / target_file
            if not source_path.exists():
                result.note = "target file missing in worktree"
                return parent_commit, target_file, result

            with tempfile.TemporaryDirectory(prefix=f"{candidate.case_id}-actual-") as build_dir_name:
                build_dir = Path(build_dir_name)
                obj_path = build_dir / "prog.o"
                include_roots = [worktree_dir / path for path in INCLUDE_DIRS]
                extra_flags = make_flag_hints(worktree_dir, target_file)
                if not extra_flags:
                    extra_flags = [f"-D__NR_CPUS__={subprocess.check_output(['nproc'], text=True).strip()}"]
                result.extra_flags = extra_flags
                cmd, completed = compile_source(
                    source_path,
                    obj_path,
                    include_roots,
                    extra_flags=extra_flags,
                    force_c=source_path.suffix.lower() == ".h",
                )
                result.compile_command = cmd
                result.compile_returncode = completed.returncode
                result.compile_log = (completed.stdout + completed.stderr).strip()
                result.compiled = completed.returncode == 0
                if not result.compiled:
                    result.note = truncate(best_log_line(result.compile_log) or "actual file compilation failed")
                    return parent_commit, target_file, result
                result.load_attempted = True
                load_rc, load_log, load_status = load_object(obj_path, candidate.case_id, "actual")
                result.load_returncode = load_rc
                result.load_log = load_log
                result.load_status = load_status
                result.note = truncate(best_log_line(load_log) or load_status or "loaded")
                return parent_commit, target_file, result
        finally:
            run(["git", "-C", str(repo_path), "worktree", "remove", "--force", str(worktree_dir)], cwd=ROOT)


def run_case(repo_path: Path, candidate: Candidate) -> CaseResult:
    include_roots = [repo_path / path for path in INCLUDE_DIRS]
    snippet = attempt_snippet(candidate, include_roots)
    actual_parent, target_file, target_reason = (None, None, None)
    actual = CompileLoadResult()
    if not snippet.compiled:
        actual_parent, target_file, actual = attempt_actual_file(repo_path, candidate)
        target_reason = "commit_diff" if target_file and target_file != candidate.declared_file else None
        if actual.attempted and target_file == candidate.declared_file:
            target_reason = "snippet_declared_file"
    return CaseResult(
        candidate=candidate,
        parent_commit=actual_parent,
        target_file=target_file,
        target_reason=target_reason,
        snippet=snippet,
        actual=actual,
    )


def counter_table(counter: Counter[str], limit: int = 5) -> list[str]:
    rows: list[str] = []
    for item, count in counter.most_common(limit):
        rows.append(f"- `{count}` x {item}")
    return rows


def render_report(results: list[CaseResult], repo_path: Path, limit: int) -> str:
    include_roots = [repo_path / path for path in INCLUDE_DIRS]
    repo_head = git_stdout(repo_path, "rev-parse", "HEAD").strip()

    snippet_ok = sum(1 for row in results if row.snippet.compiled)
    actual_attempted = sum(1 for row in results if row.actual.attempted)
    actual_ok = sum(1 for row in results if row.actual.compiled)
    final_ok = sum(1 for row in results if row.final_result is not None)
    load_ok = sum(1 for row in results if row.final_result and row.final_result.load_status == "loaded")
    verifier_rejects = sum(1 for row in results if row.final_result and row.final_result.load_status == "verifier_reject")

    snippet_errors = Counter(
        truncate(best_log_line(row.snippet.compile_log) or row.snippet.note, 140)
        for row in results
        if row.snippet.attempted and not row.snippet.compiled
    )
    actual_errors = Counter(
        truncate(best_log_line(row.actual.compile_log) or row.actual.note, 140)
        for row in results
        if row.actual.attempted and not row.actual.compiled
    )
    load_errors = Counter(
        truncate(best_log_line(row.final_result.load_log) or row.final_result.note, 140)
        for row in results
        if row.final_result and row.final_result.load_attempted and row.final_result.load_status != "loaded"
    )

    lines = [
        "# Cilium Eval Commits Compilation Results",
        "",
        f"- Generated at: `{now_iso()}`",
        f"- Cilium repo: `{repo_path}` @ `{repo_head}`",
        f"- Include roots: {', '.join(f'`{path}`' for path in include_roots)}",
        f"- Selection: top `{limit}` `eval-cilium-*` cases sorted by heuristic score descending, then `case_id` ascending",
        "",
        "## Summary",
        "",
        f"- Snippet compile successes: `{snippet_ok}` / `{len(results)}`",
        f"- Actual-file fallback attempted: `{actual_attempted}` / `{len(results)}`",
        f"- Actual-file compile successes: `{actual_ok}` / `{actual_attempted}`" if actual_attempted else "- Actual-file compile successes: `0 / 0`",
        f"- Final compile successes: `{final_ok}` / `{len(results)}`",
        f"- Final load successes: `{load_ok}` / `{final_ok}`" if final_ok else "- Final load successes: `0 / 0`",
        f"- Final verifier rejects with captured load log: `{verifier_rejects}`",
        "",
        "## Common Failures",
        "",
        "### Snippet Compile",
        "",
    ]
    lines.extend(counter_table(snippet_errors) or ["- none"])
    lines.extend(["", "### Actual File Compile", ""])
    lines.extend(counter_table(actual_errors) or ["- none"])
    lines.extend(["", "### Load", ""])
    lines.extend(counter_table(load_errors) or ["- none"])
    lines.extend(["", "## Results", ""])
    lines.extend(
        [
            "| Case | Score | Commit | Declared File | Actual File | Snippet | Actual | Final | Load | Note |",
            "| --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in results:
        final = row.final_result
        load_status = final.load_status if final and final.load_attempted else "n/a"
        note_source = (
            final.note
            if final is not None
            else row.actual.note or row.snippet.note or "compile failed"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{row.candidate.case_id}`",
                    str(row.candidate.score),
                    f"`{row.candidate.commit_hash[:12]}`",
                    f"`{row.candidate.declared_file or 'None'}`",
                    f"`{row.target_file or 'None'}`",
                    "yes" if row.snippet.compiled else "no",
                    "yes" if row.actual.compiled else ("n/a" if not row.actual.attempted else "no"),
                    f"`{row.final_method}`",
                    f"`{load_status}`",
                    truncate(note_source.replace("|", "/"), 140),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    ensure_cilium_repo(args.repo_path)

    include_paths = [args.repo_path / path for path in INCLUDE_DIRS]
    missing = [path for path in include_paths if not path.is_dir()]
    if missing:
        missing_text = ", ".join(str(path) for path in missing)
        raise SystemExit(f"missing expected Cilium include directories: {missing_text}")

    candidates = select_top_cilium_candidates(args.cases_dir, args.limit)
    results = [run_case(args.repo_path, candidate) for candidate in candidates]
    report = render_report(results, args.repo_path, args.limit)
    write_text(args.report_path, report)
    print(f"Wrote {args.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
