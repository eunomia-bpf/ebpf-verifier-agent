#!/usr/bin/env python3
"""Batch compile and cross-kernel verify promising eval_commits candidates."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import textwrap
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from case_study.verify_lowering_artifact_cases import (  # noqa: E402
    EvalCandidate,
    process_eval_case,
)
from scripts.find_lowering_artifact_commits import score_case  # noqa: E402


DEFAULT_CASES_DIR = ROOT / "case_study" / "cases" / "eval_commits"
DEFAULT_STAGE_ROOT = ROOT / ".cache" / "eval-commits-batch-verification"
DEFAULT_CONFIRMED_ROOT = ROOT / "case_study" / "cases" / "eval_commits_verified"
DEFAULT_REPORT_PATH = ROOT / "docs" / "tmp" / "eval-commits-batch-verification.md"
SUPPORTED_REPOS = ("bcc", "katran", "cilium")
QEMU_STATE_DIR = ROOT / ".cache" / "qemu" / "debian-11-5.10"
QEMU_SSH_PORT = 2222
QEMU_SSH_USER = "root"
QEMU_SSH_KEY = QEMU_STATE_DIR / "id_ed25519"
QEMU_KNOWN_HOSTS = QEMU_STATE_DIR / "known_hosts"

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
    "R0 ",
    "R1 ",
    "R2 ",
    "R3 ",
    "min value is",
    "max value is",
    "type=scalar expected=",
)
STRONG_LOADER_FAILURE_MARKERS = (
    "error loading btf",
    "no matching targets found",
    "substituting insn",
    "object file doesn't contain any bpf program",
    "failed to guess program type",
    "invalid insn",
    "unsupported relo",
    "failed to open object",
)
WEAK_LOADER_FAILURE_MARKERS = (
    "load bpf program failed",
    "libbpf: failed to load object",
    "failed to load object file",
)


@dataclass(slots=True)
class GuestResult:
    attempted: bool
    load_ok: bool | None
    returncode: int | None
    log: str
    category: str
    headline: str


@dataclass(slots=True)
class BatchCaseResult:
    candidate: EvalCandidate
    host_result: Any
    guest_buggy: GuestResult | None
    guest_fixed: GuestResult | None
    confirmed: bool
    confirmation_reason: str


@dataclass(slots=True)
class SelectionStats:
    promising_total: int
    supported_total: int
    unsupported_total: int


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR)
    parser.add_argument("--stage-root", type=Path, default=DEFAULT_STAGE_ROOT)
    parser.add_argument("--confirmed-root", type=Path, default=DEFAULT_CONFIRMED_ROOT)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--min-score",
        type=int,
        default=4,
        help="Minimum promising-score threshold from scripts/find_lowering_artifact_commits.py.",
    )
    parser.add_argument(
        "--supported-repos",
        nargs="+",
        default=list(SUPPORTED_REPOS),
        help="Subset of repos to materialize and compile.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional cap after sorting supported promising cases by score descending.",
    )
    parser.add_argument(
        "--skip-qemu",
        action="store_true",
        help="Run only the host 6.15 compile/load stage.",
    )
    parser.add_argument(
        "--keep-stage",
        action="store_true",
        help="Reuse the stage root if it already exists.",
    )
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


def write_yaml(path: Path, payload: dict[str, Any]) -> None:
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=False, width=1000)
    write_text(path, text)


def parse_boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes"}:
        return True
    if text in {"false", "no"}:
        return False
    return None


def repo_name_from_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1].removesuffix(".git")


def load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def select_candidates(
    cases_dir: Path,
    *,
    min_score: int,
    supported_repos: set[str],
    limit: int | None,
) -> tuple[list[EvalCandidate], list[tuple[str, str, int]], SelectionStats]:
    selected: list[EvalCandidate] = []
    skipped: list[tuple[str, str, int]] = []
    promising_total = 0
    for case_path in sorted(cases_dir.glob("eval-*.yaml")):
        payload = load_yaml(case_path)
        record = score_case(case_path, payload, min_score)
        if not record.promising:
            continue
        promising_total += 1
        repo_name = repo_name_from_url(str(payload.get("repository") or ""))
        if repo_name not in supported_repos:
            skipped.append((record.case_id, repo_name, record.score))
            continue
        selected.append(
            EvalCandidate(
                case_id=record.case_id,
                path=case_path,
                payload=payload,
                repo_name=repo_name,
                score=record.score,
            )
        )
    supported_total = len(selected)
    selected.sort(key=lambda item: (-item.score, item.case_id))
    if limit is not None:
        selected = selected[:limit]
    skipped.sort(key=lambda item: (-item[2], item[0]))
    return selected, skipped, SelectionStats(
        promising_total=promising_total,
        supported_total=supported_total,
        unsupported_total=len(skipped),
    )


def ssh_ready() -> bool:
    if not QEMU_SSH_KEY.is_file():
        return False
    cmd = [
        "ssh",
        "-i",
        str(QEMU_SSH_KEY),
        "-p",
        str(QEMU_SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={QEMU_KNOWN_HOSTS}",
        f"{QEMU_SSH_USER}@127.0.0.1",
        "true",
    ]
    completed = run(cmd, cwd=ROOT)
    return completed.returncode == 0


def ensure_qemu_ready() -> str:
    if ssh_ready():
        return query_qemu_kernel()
    launch = run(
        [str(ROOT / "scripts" / "qemu-launch-5.10.sh"), "--daemonize"],
        cwd=ROOT,
    )
    if launch.returncode != 0:
        raise RuntimeError(
            "Failed to start QEMU:\n"
            + (launch.stdout or "")
            + (launch.stderr or "")
        )
    for _ in range(90):
        if ssh_ready():
            return query_qemu_kernel()
        time.sleep(2)
    raise RuntimeError(
        "Timed out waiting for SSH on the 5.10 QEMU guest.\n"
        f"See {QEMU_STATE_DIR / 'serial.log'} for the serial console log."
    )


def query_qemu_kernel() -> str:
    cmd = [
        "ssh",
        "-i",
        str(QEMU_SSH_KEY),
        "-p",
        str(QEMU_SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={QEMU_KNOWN_HOSTS}",
        f"{QEMU_SSH_USER}@127.0.0.1",
        "uname -r",
    ]
    completed = run(cmd, cwd=ROOT)
    if completed.returncode != 0:
        raise RuntimeError((completed.stdout + completed.stderr).strip() or "uname -r failed in QEMU")
    return completed.stdout.strip()


def first_meaningful_line(log: str) -> str:
    for raw in log.splitlines():
        line = raw.strip()
        if not line or line.startswith("libbpf:") or line.startswith("kernel="):
            continue
        return line
    return ""


def classify_guest_result(returncode: int, log: str) -> tuple[str, str]:
    headline = first_meaningful_line(log)
    lower = log.lower()
    if returncode == 0:
        return "pass", headline or "accepted"
    if any(marker in lower for marker in STRONG_LOADER_FAILURE_MARKERS):
        return "loader_incompat", headline or "loader failure"
    if any(marker.lower() in lower for marker in VERIFIER_REJECT_MARKERS):
        return "verifier_reject", headline or "verifier reject"
    if any(marker in lower for marker in WEAK_LOADER_FAILURE_MARKERS):
        return "loader_incompat", headline or "loader failure"
    return "reject_unknown", headline or "rejected"


def verify_on_qemu(obj_path: Path) -> GuestResult:
    cmd = [str(ROOT / "scripts" / "qemu-verify-bpf.sh"), "--scp-always", "--loadall", str(obj_path)]
    completed = run(cmd, cwd=ROOT)
    log = (completed.stdout or "") + (completed.stderr or "")
    category, headline = classify_guest_result(completed.returncode, log)
    return GuestResult(
        attempted=True,
        load_ok=(completed.returncode == 0),
        returncode=completed.returncode,
        log=log.strip(),
        category=category,
        headline=headline,
    )


def skipped_guest_result(reason: str) -> GuestResult:
    return GuestResult(
        attempted=False,
        load_ok=None,
        returncode=None,
        log="",
        category=reason,
        headline=reason,
    )


def namespace_load_result(*, compiles: bool, verifier_pass: bool | None, reason: str) -> SimpleNamespace:
    return SimpleNamespace(compiles=compiles, verifier_pass=verifier_pass, reason=reason)


def parse_key_value_text(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def build_failed_host_result(candidate: EvalCandidate, materialized_root: Path, error: str) -> SimpleNamespace:
    case_dir = materialized_root / candidate.case_id
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "case_id": candidate.case_id,
        "source": "eval_commits",
        "repository": candidate.payload.get("repository"),
        "repo_name": candidate.repo_name,
        "case_yaml": str(candidate.path),
        "score": candidate.score,
        "error": error,
    }
    write_yaml(case_dir / "metadata.yaml", metadata)
    write_text(
        case_dir / "verification_status.txt",
        "status: failed\n"
        f"reason: {error}\n"
        "buggy_compile: False\n"
        "buggy_verifier_pass: n/a\n"
        "fixed_compile: False\n"
        "fixed_verifier_pass: n/a\n",
    )
    return SimpleNamespace(
        case_dir=case_dir,
        metadata=metadata,
        buggy=namespace_load_result(compiles=False, verifier_pass=None, reason=error),
        fixed=namespace_load_result(compiles=False, verifier_pass=None, reason=error),
        status="failed",
        reason=error,
    )


def load_saved_batch_result(candidate: EvalCandidate, case_dir: Path) -> BatchCaseResult:
    metadata = load_yaml(case_dir / "metadata.yaml") if (case_dir / "metadata.yaml").exists() else {}
    verification = parse_key_value_text(case_dir / "verification_status.txt")
    cross = load_yaml(case_dir / "cross_kernel_status.yaml")

    buggy_6_15 = cross.get("buggy_6_15") or {}
    fixed_6_15 = cross.get("fixed_6_15") or {}
    buggy = namespace_load_result(
        compiles=parse_boolish(buggy_6_15.get("compiles")) or parse_boolish(verification.get("buggy_compile")) or False,
        verifier_pass=parse_boolish(buggy_6_15.get("verifier_pass")),
        reason=str(buggy_6_15.get("reason") or verification.get("reason") or "unknown"),
    )

    fixed_compile_value = parse_boolish(fixed_6_15.get("compiles"))
    if fixed_compile_value is None and verification.get("fixed_compile", "").lower() == "n/a":
        fixed = None
    else:
        fixed = namespace_load_result(
            compiles=fixed_compile_value if fixed_compile_value is not None else (parse_boolish(verification.get("fixed_compile")) or False),
            verifier_pass=parse_boolish(fixed_6_15.get("verifier_pass")),
            reason=str(fixed_6_15.get("reason") or "unknown"),
        )

    guest_buggy_log = (case_dir / "verifier_log_buggy_5_10.txt").read_text(encoding="utf-8").strip() if (case_dir / "verifier_log_buggy_5_10.txt").exists() else ""
    guest_fixed_log = (case_dir / "verifier_log_fixed_5_10.txt").read_text(encoding="utf-8").strip() if (case_dir / "verifier_log_fixed_5_10.txt").exists() else ""
    buggy_5_10 = cross.get("buggy_5_10") or {}
    fixed_5_10 = cross.get("fixed_5_10") or {}

    buggy_returncode = buggy_5_10.get("returncode")
    buggy_attempted = bool(buggy_5_10.get("attempted"))
    if guest_buggy_log and buggy_returncode is not None:
        buggy_category, buggy_headline = classify_guest_result(int(buggy_returncode), guest_buggy_log)
    else:
        buggy_category = str(buggy_5_10.get("category") or "unknown")
        buggy_headline = str(buggy_5_10.get("headline") or "")
    guest_buggy = GuestResult(
        attempted=buggy_attempted,
        load_ok=(buggy_category == "pass") if buggy_attempted else None,
        returncode=buggy_returncode,
        log=guest_buggy_log,
        category=buggy_category,
        headline=buggy_headline,
    )

    fixed_returncode = fixed_5_10.get("returncode")
    fixed_attempted = bool(fixed_5_10.get("attempted"))
    if guest_fixed_log and fixed_returncode is not None:
        fixed_category, fixed_headline = classify_guest_result(int(fixed_returncode), guest_fixed_log)
    else:
        fixed_category = str(fixed_5_10.get("category") or "unknown")
        fixed_headline = str(fixed_5_10.get("headline") or "")
    guest_fixed = GuestResult(
        attempted=fixed_attempted,
        load_ok=(fixed_category == "pass") if fixed_attempted else None,
        returncode=fixed_returncode,
        log=guest_fixed_log,
        category=fixed_category,
        headline=fixed_headline,
    )

    host_result = SimpleNamespace(
        case_dir=case_dir,
        metadata=metadata,
        buggy=buggy,
        fixed=fixed,
        status=verification.get("status", "unknown"),
        reason=verification.get("reason", "unknown"),
    )
    confirmed, confirmation_reason = confirm_case(host_result, guest_buggy, guest_fixed)
    return BatchCaseResult(
        candidate=candidate,
        host_result=host_result,
        guest_buggy=guest_buggy,
        guest_fixed=guest_fixed,
        confirmed=confirmed,
        confirmation_reason=confirmation_reason,
    )


def combine_logs(case_dir: Path, guest_buggy: GuestResult | None, guest_fixed: GuestResult | None) -> tuple[str, str]:
    host_buggy = (case_dir / "verifier_log_buggy.txt").read_text(encoding="utf-8") if (case_dir / "verifier_log_buggy.txt").exists() else ""
    host_fixed = (case_dir / "verifier_log_fixed.txt").read_text(encoding="utf-8") if (case_dir / "verifier_log_fixed.txt").exists() else ""
    host_text = textwrap.dedent(
        f"""\
        === buggy ===
        {host_buggy.rstrip()}

        === fixed ===
        {host_fixed.rstrip()}
        """
    ).strip() + "\n"
    guest_text = textwrap.dedent(
        f"""\
        === buggy ===
        {(guest_buggy.log if guest_buggy else '').rstrip()}

        === fixed ===
        {(guest_fixed.log if guest_fixed else '').rstrip()}
        """
    ).strip() + "\n"
    return host_text, guest_text


def sync_confirmed_case(batch_result: BatchCaseResult, *, host_kernel: str, guest_kernel: str, confirmed_root: Path) -> None:
    case_dir = batch_result.host_result.case_dir
    dest_dir = confirmed_root / batch_result.candidate.case_id
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    for name in ("buggy.c", "fixed.c", "buggy.o", "fixed.o", "metadata.yaml"):
        src = case_dir / name
        if src.exists():
            shutil.copy2(src, dest_dir / name)

    host_log, guest_log = combine_logs(case_dir, batch_result.guest_buggy, batch_result.guest_fixed)
    write_text(dest_dir / "verifier_log_6.15.txt", host_log)
    write_text(dest_dir / "verifier_log_5.10.txt", guest_log)
    write_text(
        dest_dir / "verification_status.txt",
        textwrap.dedent(
            f"""\
            status: confirmed
            reason: {batch_result.confirmation_reason}
            host_kernel: {host_kernel}
            guest_kernel: {guest_kernel}
            repo: {batch_result.candidate.repo_name}
            score: {batch_result.candidate.score}
            source_case_yaml: {batch_result.candidate.path.relative_to(ROOT)}
            selected_source_file: {batch_result.host_result.metadata.get('selected_source_file')}
            host_buggy_pass_6_15: {batch_result.host_result.buggy.verifier_pass}
            host_fixed_pass_6_15: {batch_result.host_result.fixed.verifier_pass if batch_result.host_result.fixed else None}
            guest_buggy_category_5_10: {batch_result.guest_buggy.category if batch_result.guest_buggy else None}
            guest_buggy_headline_5_10: {batch_result.guest_buggy.headline if batch_result.guest_buggy else None}
            guest_fixed_category_5_10: {batch_result.guest_fixed.category if batch_result.guest_fixed else None}
            guest_fixed_headline_5_10: {batch_result.guest_fixed.headline if batch_result.guest_fixed else None}
            """
        ),
    )


def confirm_case(host_result: Any, guest_buggy: GuestResult | None, guest_fixed: GuestResult | None) -> tuple[bool, str]:
    if host_result.buggy.verifier_pass is not True:
        return False, "buggy did not pass on 6.15"
    if host_result.fixed is None or host_result.fixed.verifier_pass is not True:
        return False, "fixed did not pass on 6.15"
    if guest_buggy is None or guest_buggy.category != "verifier_reject":
        return False, "buggy did not hit a clean verifier rejection on 5.10"
    if guest_fixed is None or guest_fixed.category != "pass":
        return False, "fixed did not pass on 5.10"
    return True, "buggy passes on 6.15, cleanly rejects on 5.10, fixed passes on both"


def render_report(
    *,
    generated_at: str,
    host_kernel: str,
    guest_kernel: str | None,
    selection_stats: SelectionStats,
    candidates: list[EvalCandidate],
    skipped: list[tuple[str, str, int]],
    results: list[BatchCaseResult],
) -> str:
    per_repo: dict[str, Counter[str]] = defaultdict(Counter)
    for item in results:
        bucket = per_repo[item.candidate.repo_name]
        bucket["attempted"] += 1
        bucket["buggy_compiled"] += int(item.host_result.buggy.compiles)
        bucket["buggy_pass_6_15"] += int(item.host_result.buggy.verifier_pass is True)
        bucket["fixed_compiled"] += int(item.host_result.fixed is not None and item.host_result.fixed.compiles)
        bucket["fixed_pass_6_15"] += int(item.host_result.fixed is not None and item.host_result.fixed.verifier_pass is True)
        bucket["buggy_pass_5_10"] += int(item.guest_buggy is not None and item.guest_buggy.category == "pass")
        bucket["buggy_verifier_reject_5_10"] += int(item.guest_buggy is not None and item.guest_buggy.category == "verifier_reject")
        bucket["buggy_loader_incompat_5_10"] += int(item.guest_buggy is not None and item.guest_buggy.category == "loader_incompat")
        bucket["fixed_pass_5_10"] += int(item.guest_fixed is not None and item.guest_fixed.category == "pass")
        bucket["confirmed"] += int(item.confirmed)

    skipped_counts = Counter(repo for _, repo, _ in skipped)
    confirmed = [item for item in results if item.confirmed]
    interesting_unconfirmed = [
        item for item in results
        if not item.confirmed
        and item.host_result.buggy.verifier_pass is True
        and item.guest_buggy is not None
        and item.guest_buggy.category in {"verifier_reject", "loader_incompat", "reject_unknown"}
    ]

    host_buggy_pass = sum(1 for item in results if item.host_result.buggy.verifier_pass is True)
    host_fixed_pass = sum(1 for item in results if item.host_result.fixed and item.host_result.fixed.verifier_pass is True)
    guest_buggy_verifier_reject = sum(1 for item in results if item.guest_buggy and item.guest_buggy.category == "verifier_reject")
    guest_buggy_loader_incompat = sum(1 for item in results if item.guest_buggy and item.guest_buggy.category == "loader_incompat")

    lines: list[str] = [
        "# Eval Commits Batch Verification",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Host kernel: `{host_kernel}`",
        f"- Guest kernel: `{guest_kernel or 'not tested'}`",
        "",
        "## Scope",
        "",
        "- Candidate source: `case_study/cases/eval_commits/*.yaml`",
        "- Selection policy: `promising == true` from `scripts/find_lowering_artifact_commits.py` scoring, then score-descending order.",
        f"- Promising candidates in full pool: `{selection_stats.promising_total}`",
        f"- Supported C-repo candidates before any limit: `{selection_stats.supported_total}`",
        f"- Supported C-repo candidates attempted here: `{len(candidates)}`",
        f"- Skipped unsupported repos: `{selection_stats.unsupported_total}`",
        "",
        "## Unsupported Repos",
        "",
    ]
    if skipped_counts:
        for repo, count in sorted(skipped_counts.items()):
            lines.append(f"- `{repo}`: `{count}` skipped")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Host buggy compile successes: `{sum(1 for item in results if item.host_result.buggy.compiles)}`",
            f"- Host buggy verifier passes on 6.15: `{host_buggy_pass}`",
            f"- Host fixed verifier passes on 6.15: `{host_fixed_pass}`",
            f"- 5.10 buggy clean verifier rejects: `{guest_buggy_verifier_reject}`",
            f"- 5.10 buggy loader/BTF incompatibilities: `{guest_buggy_loader_incompat}`",
            f"- Confirmed lowering artifacts: `{len(confirmed)}`",
            "",
            "## Per-Repo Breakdown",
            "",
            "| Repo | Attempted | Buggy Compiled | Buggy 6.15 Pass | Fixed Compiled | Fixed 6.15 Pass | Buggy 5.10 Pass | Buggy 5.10 Verifier Reject | Buggy 5.10 Loader Incompat | Fixed 5.10 Pass | Confirmed |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for repo in sorted(per_repo):
        bucket = per_repo[repo]
        lines.append(
            "| "
            + " | ".join(
                [
                    repo,
                    str(bucket["attempted"]),
                    str(bucket["buggy_compiled"]),
                    str(bucket["buggy_pass_6_15"]),
                    str(bucket["fixed_compiled"]),
                    str(bucket["fixed_pass_6_15"]),
                    str(bucket["buggy_pass_5_10"]),
                    str(bucket["buggy_verifier_reject_5_10"]),
                    str(bucket["buggy_loader_incompat_5_10"]),
                    str(bucket["fixed_pass_5_10"]),
                    str(bucket["confirmed"]),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Confirmed Cases", ""])
    if confirmed:
        lines.extend(
            [
                "| Case | Repo | Score | Selected File | 5.10 Buggy Headline | 5.10 Fixed Headline |",
                "| --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for item in confirmed:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{item.candidate.case_id}`",
                        item.candidate.repo_name,
                        str(item.candidate.score),
                        f"`{item.host_result.metadata.get('selected_source_file')}`",
                        item.guest_buggy.headline if item.guest_buggy else "",
                        item.guest_fixed.headline if item.guest_fixed else "",
                    ]
                )
                + " |"
            )
    else:
        lines.append("- No case met the full confirmation rule in this run.")

    lines.extend(["", "## Interesting But Unconfirmed", ""])
    if interesting_unconfirmed:
        lines.extend(
            [
                "| Case | Repo | Host Buggy | Host Fixed | Guest Buggy | Guest Fixed | Reason |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in interesting_unconfirmed:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{item.candidate.case_id}`",
                        item.candidate.repo_name,
                        "pass" if item.host_result.buggy.verifier_pass is True else item.host_result.buggy.reason,
                        "pass" if item.host_result.fixed and item.host_result.fixed.verifier_pass is True else (item.host_result.fixed.reason if item.host_result.fixed else "n/a"),
                        item.guest_buggy.category if item.guest_buggy else "n/a",
                        item.guest_fixed.category if item.guest_fixed else "n/a",
                        item.confirmation_reason.replace("|", "/"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Full Results",
            "",
            "| Case | Repo | Score | Buggy Compile | Buggy 6.15 | Fixed Compile | Fixed 6.15 | Buggy 5.10 | Fixed 5.10 | Selected File | Note |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in results:
        fixed = item.host_result.fixed
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{item.candidate.case_id}`",
                    item.candidate.repo_name,
                    str(item.candidate.score),
                    "yes" if item.host_result.buggy.compiles else "no",
                    "pass" if item.host_result.buggy.verifier_pass is True else "fail" if item.host_result.buggy.verifier_pass is False else item.host_result.buggy.reason,
                    "yes" if fixed and fixed.compiles else "no",
                    "pass" if fixed and fixed.verifier_pass is True else "fail" if fixed and fixed.verifier_pass is False else (fixed.reason if fixed else "n/a"),
                    item.guest_buggy.category if item.guest_buggy else "not-run",
                    item.guest_fixed.category if item.guest_fixed else "not-run",
                    f"`{item.host_result.metadata.get('selected_source_file')}`",
                    item.confirmation_reason.replace("|", "/"),
                ]
            )
            + " |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    supported_repos = set(args.supported_repos)

    candidates, skipped, selection_stats = select_candidates(
        args.cases_dir,
        min_score=args.min_score,
        supported_repos=supported_repos,
        limit=args.limit,
    )
    if not candidates:
        raise SystemExit("No supported promising candidates were selected.")

    stage_root: Path = args.stage_root
    if stage_root.exists() and not args.keep_stage:
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, exist_ok=True)
    materialized_root = stage_root / "materialized"
    if materialized_root.exists() and not args.keep_stage:
        shutil.rmtree(materialized_root)
    materialized_root.mkdir(parents=True, exist_ok=True)

    host_kernel = run(["uname", "-r"]).stdout.strip() or "unknown"
    guest_kernel: str | None = None
    if not args.skip_qemu:
        guest_kernel = ensure_qemu_ready()

    results: list[BatchCaseResult] = []
    confirmed_root: Path = args.confirmed_root
    confirmed_root.mkdir(parents=True, exist_ok=True)

    for idx, candidate in enumerate(candidates, start=1):
        case_dir = materialized_root / candidate.case_id
        if args.keep_stage and (case_dir / "cross_kernel_status.yaml").exists():
            batch_result = load_saved_batch_result(candidate, case_dir)
            results.append(batch_result)
            if batch_result.confirmed and guest_kernel is not None:
                sync_confirmed_case(batch_result, host_kernel=host_kernel, guest_kernel=guest_kernel, confirmed_root=confirmed_root)
            print(f"[resume] {idx}/{len(candidates)} {candidate.case_id}", flush=True)
            continue

        print(f"[host] {idx}/{len(candidates)} {candidate.case_id} ({candidate.repo_name}, score={candidate.score})", flush=True)
        try:
            host_result = process_eval_case(candidate, materialized_root)
        except Exception as exc:
            error = f"materialization_error: {type(exc).__name__}: {exc}"
            host_result = build_failed_host_result(candidate, materialized_root, error)
            guest_buggy = skipped_guest_result("host_materialization_error")
            guest_fixed = skipped_guest_result("host_materialization_error")
            confirmed, reason = False, error
            batch_result = BatchCaseResult(
                candidate=candidate,
                host_result=host_result,
                guest_buggy=guest_buggy,
                guest_fixed=guest_fixed,
                confirmed=confirmed,
                confirmation_reason=reason,
            )
            results.append(batch_result)
            write_yaml(
                host_result.case_dir / "cross_kernel_status.yaml",
                {
                    "case_id": candidate.case_id,
                    "host_kernel": host_kernel,
                    "guest_kernel": guest_kernel,
                    "buggy_6_15": {
                        "compiles": False,
                        "verifier_pass": None,
                        "reason": error,
                    },
                    "fixed_6_15": {
                        "compiles": False,
                        "verifier_pass": None,
                        "reason": error,
                    },
                    "buggy_5_10": {
                        "attempted": False,
                        "category": guest_buggy.category,
                        "headline": guest_buggy.headline,
                        "returncode": None,
                    },
                    "fixed_5_10": {
                        "attempted": False,
                        "category": guest_fixed.category,
                        "headline": guest_fixed.headline,
                        "returncode": None,
                    },
                    "confirmed": False,
                    "confirmation_reason": reason,
                },
            )
            continue
        guest_buggy: GuestResult | None = None
        guest_fixed: GuestResult | None = None

        if not args.skip_qemu and host_result.buggy.verifier_pass is True:
            buggy_obj = host_result.case_dir / "buggy.o"
            if buggy_obj.exists():
                guest_buggy = verify_on_qemu(buggy_obj)
                write_text(host_result.case_dir / "verifier_log_buggy_5_10.txt", guest_buggy.log + ("\n" if guest_buggy.log else ""))
            else:
                guest_buggy = skipped_guest_result("buggy_object_missing")
        elif not args.skip_qemu:
            guest_buggy = skipped_guest_result("buggy_not_pass_on_6_15")

        if not args.skip_qemu and host_result.fixed and host_result.fixed.verifier_pass is True:
            fixed_obj = host_result.case_dir / "fixed.o"
            if fixed_obj.exists():
                guest_fixed = verify_on_qemu(fixed_obj)
                write_text(host_result.case_dir / "verifier_log_fixed_5_10.txt", guest_fixed.log + ("\n" if guest_fixed.log else ""))
            else:
                guest_fixed = skipped_guest_result("fixed_object_missing")
        elif not args.skip_qemu:
            guest_fixed = skipped_guest_result("fixed_not_pass_on_6_15")

        confirmed, reason = confirm_case(host_result, guest_buggy, guest_fixed)
        batch_result = BatchCaseResult(
            candidate=candidate,
            host_result=host_result,
            guest_buggy=guest_buggy,
            guest_fixed=guest_fixed,
            confirmed=confirmed,
            confirmation_reason=reason,
        )
        results.append(batch_result)

        write_yaml(
            host_result.case_dir / "cross_kernel_status.yaml",
            {
                "case_id": candidate.case_id,
                "host_kernel": host_kernel,
                "guest_kernel": guest_kernel,
                "buggy_6_15": {
                    "compiles": host_result.buggy.compiles,
                    "verifier_pass": host_result.buggy.verifier_pass,
                    "reason": host_result.buggy.reason,
                },
                "fixed_6_15": {
                    "compiles": host_result.fixed.compiles if host_result.fixed else None,
                    "verifier_pass": host_result.fixed.verifier_pass if host_result.fixed else None,
                    "reason": host_result.fixed.reason if host_result.fixed else None,
                },
                "buggy_5_10": {
                    "attempted": guest_buggy.attempted if guest_buggy else False,
                    "category": guest_buggy.category if guest_buggy else None,
                    "headline": guest_buggy.headline if guest_buggy else None,
                    "returncode": guest_buggy.returncode if guest_buggy else None,
                },
                "fixed_5_10": {
                    "attempted": guest_fixed.attempted if guest_fixed else False,
                    "category": guest_fixed.category if guest_fixed else None,
                    "headline": guest_fixed.headline if guest_fixed else None,
                    "returncode": guest_fixed.returncode if guest_fixed else None,
                },
                "confirmed": confirmed,
                "confirmation_reason": reason,
            },
        )

        if confirmed and guest_kernel is not None:
            sync_confirmed_case(batch_result, host_kernel=host_kernel, guest_kernel=guest_kernel, confirmed_root=confirmed_root)

    report = render_report(
        generated_at=now_iso(),
        host_kernel=host_kernel,
        guest_kernel=guest_kernel,
        selection_stats=selection_stats,
        candidates=candidates,
        skipped=skipped,
        results=results,
    )
    write_text(args.report_path, report)
    print(f"[done] report written to {args.report_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
