#!/usr/bin/env python3
"""Import replay-valid commit-derived verifier failures into bpfix-bench."""

from __future__ import annotations

import argparse
import shlex
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.replay_case import parse_verifier_log, replay_case

DEFAULT_BENCH_ROOT = ROOT / "bpfix-bench"
ENVIRONMENT_ID_FALLBACK = "kernel-6.15.11-clang-18-log2"
VARIANTS = ("buggy", "fixed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--bench-root", type=Path, default=DEFAULT_BENCH_ROOT)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--variant", choices=VARIANTS, action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--reviewed",
        action="store_true",
        help="Allow importing manually audited commit-derived cases into the single benchmark case set.",
    )
    parser.add_argument("--timeout-sec", type=int, default=45)
    args = parser.parse_args(argv)

    candidates = discover(args.source_root.resolve(), set(args.variant or VARIANTS))
    selected = select(candidates, set(args.case_id))
    print_summary(candidates, selected)

    if not args.apply:
        print("dry_run: true")
        return 0
    if not args.all and not args.case_id:
        raise SystemExit("--apply requires --case-id or --all")
    if not args.reviewed:
        raise SystemExit("--apply requires --reviewed for commit-derived cases")

    manifest = load_manifest(args.bench_root.resolve())
    imported: list[str] = []
    failed: list[str] = []
    for candidate in selected:
        try:
            import_case(
                candidate,
                args.bench_root.resolve(),
                manifest,
                force=args.force,
                timeout_sec=args.timeout_sec,
            )
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{candidate['case_id']}: {exc}")
            continue
        imported.append(candidate["case_id"])

    write_manifest(args.bench_root.resolve(), manifest)
    print("imported:")
    for case_id in imported:
        print(f"  - {case_id}")
    if failed:
        print("failed:")
        for item in failed:
            print(f"  - {item}")
    return 1 if failed else 0


def discover(source_root: Path, variants: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for source_dir in sorted(path for path in source_root.iterdir() if path.is_dir()):
        metadata_path = source_dir / "metadata.yaml"
        status_path = source_dir / "verification_status.txt"
        if not metadata_path.exists() or not status_path.exists():
            continue
        metadata = load_yaml(metadata_path)
        status = parse_status(status_path)
        source_case_id = str(metadata.get("case_id") or source_dir.name)
        for variant in VARIANTS:
            if variant not in variants:
                continue
            case_id = f"{source_case_id}-{variant}"
            reason = eligibility_reason(source_dir, metadata, status, variant)
            candidates.append(
                {
                    "case_id": case_id,
                    "source_case_id": source_case_id,
                    "variant": variant,
                    "source_dir": source_dir,
                    "metadata": metadata,
                    "status": status,
                    "reason": reason,
                }
            )
    return candidates


def eligibility_reason(source_dir: Path, metadata: dict[str, Any], status: dict[str, str], variant: str) -> str | None:
    source = source_dir / f"{variant}.c"
    headers = source_dir / "headers" / variant
    log_path = source_dir / f"verifier_log_{variant}.txt"
    if not source.exists():
        return f"missing {variant}.c"
    if not headers.exists():
        return f"missing headers/{variant}"
    if not log_path.exists():
        return f"missing verifier_log_{variant}.txt"
    if status.get(f"{variant}_compile") != "True":
        return f"{variant}_compile is not True"
    if metadata.get(f"compile_command_{variant}") is None:
        return f"missing compile_command_{variant}"
    if metadata.get(f"load_command_{variant}") is None:
        return f"missing load_command_{variant}"
    parsed = parse_verifier_log(log_path.read_text(encoding="utf-8", errors="replace"), source=log_path.name)
    if parsed.log_quality != "trace_rich":
        return f"stored verifier_log_{variant}.txt is not trace-rich"
    return None


def select(candidates: list[dict[str, Any]], case_ids: set[str]) -> list[dict[str, Any]]:
    selected = [candidate for candidate in candidates if candidate["reason"] is None]
    if case_ids:
        selected = [candidate for candidate in selected if candidate["case_id"] in case_ids]
        missing = sorted(case_ids - {candidate["case_id"] for candidate in selected})
        if missing:
            raise SystemExit(f"requested case ids are not eligible: {', '.join(missing)}")
    return selected


def print_summary(candidates: list[dict[str, Any]], selected: list[dict[str, Any]]) -> None:
    selected_ids = {candidate["case_id"] for candidate in selected}
    eligible = [candidate for candidate in candidates if candidate["reason"] is None]
    print(f"eligible: {len(eligible)}")
    for candidate in eligible:
        marker = "*" if candidate["case_id"] in selected_ids else " "
        print(f"{marker} {candidate['case_id']} source={candidate['source_case_id']} variant={candidate['variant']}")
    skipped: dict[str, int] = {}
    for candidate in candidates:
        if candidate["reason"]:
            skipped[candidate["reason"]] = skipped.get(candidate["reason"], 0) + 1
    if skipped:
        print("skipped:")
        for reason, count in sorted(skipped.items()):
            print(f"  {count:3d} {reason}")


def import_case(
    candidate: dict[str, Any],
    bench_root: Path,
    manifest: dict[str, Any],
    *,
    force: bool,
    timeout_sec: int,
) -> None:
    case_id = candidate["case_id"]
    variant = candidate["variant"]
    source_dir: Path = candidate["source_dir"]
    case_dir = bench_root / "cases" / case_id
    if case_dir.exists():
        if not force:
            return
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)

    shutil.copy2(source_dir / f"{variant}.c", case_dir / "prog.c")
    shutil.copytree(source_dir / "headers" / variant, case_dir / "headers")
    write_makefile(case_dir / "Makefile", candidate)

    skeleton = {
        "reproducer": {"build_command": "make", "load_command": "make replay-verify", "object_path": "prog.o"},
        "capture": {"verifier_log": "verifier.log"},
    }
    replay = replay_case(case_dir, skeleton, timeout_sec=timeout_sec)
    fresh = replay.parsed_log
    if replay.build.returncode != 0:
        raise RuntimeError(f"build failed: {replay.build.returncode}")
    if replay.load.returncode == 0:
        raise RuntimeError("fresh replay load succeeded; expected verifier reject")
    if not replay.verifier_log_captured or not fresh.terminal_error or fresh.rejected_insn_idx is None:
        raise RuntimeError("fresh replay did not produce a trace-rich verifier log")

    stored = parse_verifier_log((source_dir / f"verifier_log_{variant}.txt").read_text(encoding="utf-8", errors="replace"))
    if stored.terminal_error and stored.terminal_error != fresh.terminal_error:
        raise RuntimeError(f"terminal error drifted: expected {stored.terminal_error!r}, got {fresh.terminal_error!r}")

    (case_dir / "verifier.log").write_text(replay.verifier_log_captured, encoding="utf-8")
    environment_id = str(manifest.get("environment_id") or ENVIRONMENT_ID_FALLBACK)
    capture_id = f"{case_id}__{environment_id}"
    imported_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    (case_dir / "case.yaml").write_text(
        dump_yaml(build_case_yaml(candidate, capture_id, environment_id, fresh)),
        encoding="utf-8",
    )
    (case_dir / "capture.yaml").write_text(
        dump_yaml(build_capture_yaml(candidate, capture_id, environment_id, imported_at)),
        encoding="utf-8",
    )

    upsert_manifest(
        manifest,
        {
            "case_id": case_id,
            "path": f"cases/{case_id}",
            "source_kind": "commit_derived",
            "family_id": family_id(str(fresh.terminal_error)),
            "representative": True,
            "capture_id": capture_id,
        },
    )


def write_makefile(path: Path, candidate: dict[str, Any]) -> None:
    source_dir: Path = candidate["source_dir"]
    metadata: dict[str, Any] = candidate["metadata"]
    variant = candidate["variant"]
    case_id = candidate["case_id"]
    compile_command = localize_command(metadata[f"compile_command_{variant}"], source_dir, variant, case_id, "compile")
    load_command = localize_command(metadata[f"load_command_{variant}"], source_dir, variant, case_id, "load")
    path.write_text(
        f"""\
.PHONY: all replay-verify verify clean

all: prog.o

prog.o: prog.c
\t{compile_command}

verify: replay-verify

replay-verify: prog.o
\trm -f replay-verifier.log
\tsudo rm -rf /sys/fs/bpf/{case_id}
\t{load_command} > replay-verifier.log 2>&1

clean:
\trm -f prog.o replay-verifier.log
\tsudo rm -rf /sys/fs/bpf/{case_id}
""",
        encoding="utf-8",
    )


def localize_command(command: list[Any], source_dir: Path, variant: str, case_id: str, kind: str) -> str:
    localized: list[str] = []
    source_dir_s = str(source_dir)
    header_prefix = str(source_dir / "headers" / variant)
    for raw in command:
        arg = str(raw)
        if arg == str(source_dir / f"{variant}.c"):
            localized.append("prog.c")
        elif arg == str(source_dir / f"{variant}.o"):
            localized.append("prog.o")
        elif arg.startswith(header_prefix):
            suffix = Path(arg).relative_to(header_prefix)
            localized.append(str(Path("headers") / suffix) if str(suffix) != "." else "headers")
        elif arg.startswith("-I" + header_prefix):
            suffix = Path(arg[2:]).relative_to(header_prefix)
            include_path = str(Path("headers") / suffix) if str(suffix) != "." else "headers"
            localized.append("-I" + include_path)
        elif arg.startswith("/sys/fs/bpf/"):
            localized.append(f"/sys/fs/bpf/{case_id}")
        elif source_dir_s in arg:
            localized.append(arg.replace(source_dir_s, "."))
        else:
            localized.append(arg)
    if kind == "load" and f"/sys/fs/bpf/{case_id}" not in localized:
        localized.append(f"/sys/fs/bpf/{case_id}")
    return " ".join(shlex.quote(arg) for arg in localized)


def build_case_yaml(
    candidate: dict[str, Any],
    capture_id: str,
    environment_id: str,
    fresh: Any,
) -> dict[str, Any]:
    metadata: dict[str, Any] = candidate["metadata"]
    variant = candidate["variant"]
    return {
        "schema_version": "bpfix.case/v1",
        "case_id": candidate["case_id"],
        "source": {
            "kind": "commit_derived",
            "url": commit_url(metadata),
            "repository": metadata.get("repository"),
            "commit": metadata.get("commit_hash"),
            "parent_commit": metadata.get("parent_commit"),
            "upstream_file": metadata.get("selected_source_file"),
            "upstream_section": None,
            "collected_at": None,
            "raw_excerpt_files": [],
            "variant": variant,
        },
        "reproducer": {
            "status": "ready",
            "reconstruction": "original",
            "language": "C",
            "source_file": "prog.c",
            "build_command": "make",
            "object_path": "prog.o",
            "load_command": "make replay-verify",
            "notes": "Imported from an explicit commit-derived artifact; replay log is generated as replay-verifier.log.",
        },
        "capture": {
            "capture_id": capture_id,
            "environment_id": environment_id,
            "build_status": "success",
            "load_status": "verifier_reject",
            "verifier_pass": False,
            "exit_code": 1,
            "verifier_log": "replay-verifier.log",
            "capture_metadata": "capture.yaml",
            "log_quality": fresh.log_quality,
            "terminal_error": fresh.terminal_error,
            "rejected_insn_idx": fresh.rejected_insn_idx,
        },
        "external_match": {
            "status": "not_applicable",
            "policy": "commit_derived_replay",
            "matched_messages": [fresh.terminal_error],
            "notes": "Commit-derived case admitted only after manual audit and local replay.",
        },
        "label": {
            "capture_id": capture_id,
            "taxonomy_class": "verifier_reject",
            "error_id": "commit_derived_verifier_failure",
            "confidence": "low",
            "label_source": "fresh verifier terminal error; root-cause label requires manual audit",
            "root_cause_description": fresh.terminal_error,
            "rejected_insn_idx": fresh.rejected_insn_idx,
            "root_cause_insn_idx": None,
            "rejected_line": None,
            "root_cause_line": None,
            "localization_confidence": "low",
            "fix_type": None,
            "fix_direction": None,
        },
        "repair": {"eligible": False},
        "reporting": {
            "family_id": family_id(str(fresh.terminal_error)),
            "representative": True,
            "intentional_negative_test": False,
            "notes": "Replay-valid manually audited commit-derived verifier failure.",
        },
    }


def build_capture_yaml(
    candidate: dict[str, Any],
    capture_id: str,
    environment_id: str,
    imported_at: str,
) -> dict[str, Any]:
    metadata: dict[str, Any] = candidate["metadata"]
    status: dict[str, str] = candidate["status"]
    variant = candidate["variant"]
    return {
        "schema_version": "bpfix.capture/v1",
        "capture_id": capture_id,
        "case_id": candidate["case_id"],
        "environment_id": environment_id,
        "imported_at": imported_at,
        "source_artifact": {
            "path": relpath(candidate["source_dir"]),
            "status_file": "verification_status.txt",
            "metadata_file": "metadata.yaml",
            "repository": metadata.get("repository"),
            "commit": metadata.get("commit_hash"),
            "parent_commit": metadata.get("parent_commit"),
            "variant": variant,
            "variant_compile": status.get(f"{variant}_compile"),
            "variant_verifier_pass": status.get(f"{variant}_verifier_pass"),
        },
        "replay": {
            "build_command": "make",
            "load_command": "make replay-verify",
            "verifier_log": "replay-verifier.log",
            "expected_load_status": "verifier_reject",
        },
    }


def parse_status(path: Path) -> dict[str, str]:
    status: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        status[key.strip()] = value.strip()
    return status


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise TypeError(f"{path} must contain a mapping")
    return data


def load_manifest(bench_root: Path) -> dict[str, Any]:
    path = bench_root / "manifest.yaml"
    if not path.exists():
        return {
            "schema_version": "bpfix.benchmark/v1",
            "benchmark_id": "bpfix-bench-seed-v1",
            "frozen_at": date.today().isoformat(),
            "environment_id": ENVIRONMENT_ID_FALLBACK,
            "description": "Benchmark with locally reproducible verifier-log cases.",
            "cases": [],
        }
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("cases", [])
    return data


def write_manifest(bench_root: Path, manifest: dict[str, Any]) -> None:
    manifest["cases"] = sorted(manifest.get("cases") or [], key=lambda item: item.get("case_id", ""))
    (bench_root / "manifest.yaml").write_text(dump_yaml(manifest), encoding="utf-8")


def upsert_manifest(manifest: dict[str, Any], entry: dict[str, Any]) -> None:
    cases = manifest.setdefault("cases", [])
    cases[:] = [case for case in cases if case.get("case_id") != entry["case_id"]]
    cases.append(entry)


def family_id(terminal_error: str) -> str:
    return terminal_error.split(";", 1)[0].strip()[:120]


def commit_url(metadata: dict[str, Any]) -> str | None:
    repository = metadata.get("repository")
    commit = metadata.get("commit_hash")
    if isinstance(repository, str) and isinstance(commit, str) and repository.startswith("https://github.com/"):
        return f"{repository}/commit/{commit}"
    return repository if isinstance(repository, str) else None


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
