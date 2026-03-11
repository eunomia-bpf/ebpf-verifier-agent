#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from collector_utils import (
    HttpClient,
    ProgressLogger,
    c_string_unescape,
    compact_case_index,
    ensure_directory,
    repo_relative,
    slugify,
    utc_now,
    write_yaml,
)


SELFTESTS_SUBDIR = Path("tools/testing/selftests/bpf/progs")
SEC_RE = re.compile(r'(?m)^SEC\("(?P<section>[^"]+)"\)\s*$')
DESCRIPTION_RE = re.compile(r'__description\("((?:[^"\\]|\\.)*)"\)')
MSG_RE = re.compile(r'__msg\("((?:[^"\\]|\\.)*)"\)')
MSG_UNPRIV_RE = re.compile(r'__msg_unpriv\("((?:[^"\\]|\\.)*)"\)')
LOG_LEVEL_RE = re.compile(r"__log_level\((\d+)\)")
BPF_PROG_RE = re.compile(r"\bBPF_PROG\(\s*([A-Za-z_][A-Za-z0-9_]*)\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect negative eBPF verifier selftests from the Linux kernel tree.")
    parser.set_defaults(quiet=False)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("case_study/cases/kernel_selftests"),
        help="Directory where YAML case files and index.yaml are written.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("case_study/.cache/linux-selftests"),
        help="Cache directory for the sparse kernel checkout or extracted tarball.",
    )
    parser.add_argument(
        "--repo-url",
        default="https://github.com/torvalds/linux.git",
        help="Kernel git repository URL.",
    )
    parser.add_argument(
        "--tarball-url",
        default="https://github.com/torvalds/linux/archive/refs/heads/master.tar.gz",
        help="Tarball URL used when download mode is selected.",
    )
    parser.add_argument(
        "--ref",
        default="master",
        help="Git ref to clone when using git mode.",
    )
    parser.add_argument(
        "--fetch-method",
        choices=("auto", "git", "tarball"),
        default="auto",
        help="How to fetch kernel selftests.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Refresh an existing cached checkout before scanning.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=250,
        help="Maximum number of cases to write.",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--quiet",
        dest="quiet",
        action="store_true",
        help="Reduce progress output.",
    )
    verbosity.add_argument(
        "--verbose",
        dest="quiet",
        action="store_false",
        help="Enable progress output.",
    )
    return parser.parse_args()


class KernelSelftestsCollector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = ProgressLogger(quiet=args.quiet)
        self.client = HttpClient(
            min_interval_seconds=1.0,
            logger=self.logger,
            user_agent="OBLIGE kernel selftests collector/0.1",
        )

    def run(self) -> int:
        ensure_directory(self.args.output_dir)
        kernel_root, fetch_metadata = self._prepare_source_tree()
        progs_dir = kernel_root / SELFTESTS_SUBDIR
        if not progs_dir.exists():
            raise RuntimeError(f"Expected selftests directory {progs_dir} does not exist")

        file_paths = sorted(path for path in progs_dir.rglob("*") if path.is_file() and path.suffix in {".c", ".h"})
        self.logger.info(f"Scanning {len(file_paths)} source files under {progs_dir}")

        case_summaries: list[dict[str, Any]] = []
        seen_case_paths: set[Path] = set()
        written = 0
        for file_path in file_paths:
            if written >= self.args.max_cases:
                break
            try:
                cases = self._extract_cases_from_file(kernel_root, file_path)
            except Exception as exc:  # pragma: no cover - source variability
                self.logger.warn(f"Failed to parse {file_path}: {exc}")
                continue
            for case in cases:
                if written >= self.args.max_cases:
                    break
                case_path = self.args.output_dir / f"{case['case_id']}.yaml"
                if case_path in seen_case_paths:
                    self.logger.warn(f"Skipping duplicate case path {case_path}")
                    continue
                write_yaml(case_path, case)
                seen_case_paths.add(case_path)
                case_summaries.append(
                    {
                        "case_id": case["case_id"],
                        "path": repo_relative(case_path),
                        "file": case["selftest"]["file"],
                        "function": case["selftest"]["function"],
                        "description": case["selftest"]["description"],
                        "failure_mode": case["selftest"]["failure_mode"],
                        "expected_messages": case["expected_verifier_messages"]["privileged"],
                        "expected_messages_unprivileged": case["expected_verifier_messages"]["unprivileged"],
                    }
                )
                written += 1
                self.logger.info(f"Saved selftest case {written}/{self.args.max_cases}: {case['case_id']}")

        index_payload = compact_case_index(
            source_name="kernel_selftests",
            script_name="case_study/collect_kernel_selftests.py",
            output_dir=self.args.output_dir,
            cases=case_summaries,
            source_details=fetch_metadata,
        )
        write_yaml(self.args.output_dir / "index.yaml", index_payload)
        self.logger.info(f"Wrote {written} kernel selftest case files to {self.args.output_dir}")
        return 0

    def _prepare_source_tree(self) -> tuple[Path, dict[str, Any]]:
        method = self.args.fetch_method
        if method == "auto":
            method = "git" if shutil.which("git") else "tarball"
        if method == "git":
            return self._prepare_git_checkout()
        return self._prepare_tarball_checkout()

    def _prepare_git_checkout(self) -> tuple[Path, dict[str, Any]]:
        cache_dir = self.args.cache_dir
        if cache_dir.exists() and not (cache_dir / ".git").exists():
            raise RuntimeError(f"{cache_dir} exists but is not a git checkout")

        if not cache_dir.exists():
            ensure_directory(cache_dir.parent)
            self.logger.info(f"Cloning sparse kernel checkout into {cache_dir}")
            self._run_git(
                [
                    "clone",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--sparse",
                    "--branch",
                    self.args.ref,
                    self.args.repo_url,
                    str(cache_dir),
                ]
            )
            self._run_git(["-C", str(cache_dir), "sparse-checkout", "set", str(SELFTESTS_SUBDIR)])
        elif self.args.refresh:
            self.logger.info(f"Refreshing cached kernel checkout in {cache_dir}")
            self._run_git(["-C", str(cache_dir), "fetch", "--depth", "1", "origin", self.args.ref])
            self._run_git(["-C", str(cache_dir), "checkout", "FETCH_HEAD"])
            self._run_git(["-C", str(cache_dir), "sparse-checkout", "set", str(SELFTESTS_SUBDIR)])
        else:
            self.logger.info(f"Using cached kernel checkout at {cache_dir}")

        commit = self._run_git(["-C", str(cache_dir), "rev-parse", "HEAD"], capture_output=True).strip()
        return cache_dir, {
            "fetch_method": "git",
            "repo_url": self.args.repo_url,
            "ref": self.args.ref,
            "commit": commit,
            "selftests_subdir": str(SELFTESTS_SUBDIR),
        }

    def _prepare_tarball_checkout(self) -> tuple[Path, dict[str, Any]]:
        cache_dir = self.args.cache_dir
        extract_root = cache_dir / "extracted"
        progs_dir = extract_root / SELFTESTS_SUBDIR
        if progs_dir.exists() and not self.args.refresh:
            self.logger.info(f"Using cached extracted tarball at {extract_root}")
            return extract_root, {
                "fetch_method": "tarball",
                "tarball_url": self.args.tarball_url,
                "ref": self.args.ref,
                "selftests_subdir": str(SELFTESTS_SUBDIR),
            }

        ensure_directory(cache_dir)
        archive_path = cache_dir / "linux-selftests.tar.gz"
        self.logger.info(f"Downloading kernel tarball from {self.args.tarball_url}")
        self.client.download_file(self.args.tarball_url, archive_path)

        if extract_root.exists():
            shutil.rmtree(extract_root)
        ensure_directory(extract_root)
        self.logger.info(f"Extracting {SELFTESTS_SUBDIR} from tarball")
        with tempfile.TemporaryDirectory(prefix="oblige-linux-tarball-") as temp_dir:
            temp_extract = Path(temp_dir)
            with tarfile.open(archive_path, "r:gz") as archive:
                archive.extractall(temp_extract, filter="data")
            extracted_roots = [path for path in temp_extract.iterdir() if path.is_dir()]
            if not extracted_roots:
                raise RuntimeError("Kernel tarball extraction produced no root directory")
            extracted_root = extracted_roots[0]
            extracted_progs = extracted_root / SELFTESTS_SUBDIR
            if not extracted_progs.exists():
                raise RuntimeError(f"Tarball did not contain {SELFTESTS_SUBDIR}")
            shutil.copytree(extracted_root / "tools", extract_root / "tools", dirs_exist_ok=True)

        return extract_root, {
            "fetch_method": "tarball",
            "tarball_url": self.args.tarball_url,
            "ref": self.args.ref,
            "selftests_subdir": str(SELFTESTS_SUBDIR),
        }

    def _run_git(self, args: list[str], capture_output: bool = False) -> str:
        completed = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=capture_output,
            text=True,
        )
        return completed.stdout if capture_output else ""

    def _extract_cases_from_file(self, kernel_root: Path, file_path: Path) -> list[dict[str, Any]]:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        matches = list(SEC_RE.finditer(text))
        if not matches:
            return []

        cases: list[dict[str, Any]] = []
        for index, match in enumerate(matches):
            start = match.start()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            chunk = text[start:end].strip()
            if "__failure" not in chunk and "__failure_unpriv" not in chunk:
                continue

            section = match.group("section")
            descriptions = [c_string_unescape(value) for value in DESCRIPTION_RE.findall(chunk)]
            privileged_messages = [c_string_unescape(value) for value in MSG_RE.findall(chunk)]
            unprivileged_messages = [c_string_unescape(value) for value in MSG_UNPRIV_RE.findall(chunk)]
            log_level_match = LOG_LEVEL_RE.search(chunk)
            function_name = self._extract_function_name(chunk)
            failure_mode = self._failure_mode(chunk)

            if not privileged_messages and not unprivileged_messages and "fail" not in file_path.name:
                continue

            description = descriptions[0] if descriptions else function_name or file_path.stem
            relative_file = file_path.relative_to(kernel_root)
            chunk_hash = hashlib.sha1(chunk.encode("utf-8")).hexdigest()[:8]
            file_slug = slugify(relative_file.stem, fallback="selftest", max_length=24)
            function_slug = slugify(function_name or description, fallback="prog", max_length=44)
            section_slug = slugify(section, fallback="section", max_length=24)
            case_id = f"kernel-selftest-{file_slug}-{function_slug}-{section_slug}-{chunk_hash}"
            cases.append(
                {
                    "case_id": case_id,
                    "source": "kernel_selftests",
                    "collected_at": utc_now(),
                    "selftest": {
                        "file": str(relative_file),
                        "section": section,
                        "function": function_name,
                        "description": description,
                        "failure_mode": failure_mode,
                        "log_level": int(log_level_match.group(1)) if log_level_match else None,
                    },
                    "expected_verifier_messages": {
                        "privileged": privileged_messages,
                        "unprivileged": unprivileged_messages,
                        "combined": privileged_messages + unprivileged_messages,
                    },
                    "source_snippets": [
                        {
                            "file": str(relative_file),
                            "code": chunk,
                        }
                    ],
                }
            )
        return cases

    def _extract_function_name(self, chunk: str) -> str:
        head = chunk.split("{", 1)[0]
        bpf_prog_match = BPF_PROG_RE.search(head)
        if bpf_prog_match:
            return bpf_prog_match.group(1)

        candidate_lines = []
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

    def _failure_mode(self, chunk: str) -> str:
        fails_privileged = bool(re.search(r"__failure\b", chunk))
        fails_unprivileged = bool(re.search(r"__failure_unpriv\b", chunk))
        if fails_privileged and fails_unprivileged:
            return "privileged_and_unprivileged"
        if fails_privileged:
            return "privileged_only"
        if fails_unprivileged:
            return "unprivileged_only"
        return "unknown"


def main() -> int:
    args = parse_args()
    collector = KernelSelftestsCollector(args)
    try:
        return collector.run()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    finally:
        collector.client.close()


if __name__ == "__main__":
    raise SystemExit(main())
