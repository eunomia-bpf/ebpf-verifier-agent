#!/usr/bin/env python3
"""Import locally verified kernel selftest cases into bpfix-bench."""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.replay_case import replay_case

DEFAULT_SOURCE_ROOT = ROOT / "case_study" / "cases" / "kernel_selftests_verified"
DEFAULT_BENCH_ROOT = ROOT / "bpfix-bench"
DEFAULT_GROUND_TRUTH = ROOT / "case_study" / "ground_truth.yaml"
ENVIRONMENT_ID_FALLBACK = "kernel-6.15.11-clang-18-log2"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--bench-root", type=Path, default=DEFAULT_BENCH_ROOT)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--allow-rebuild-no-log",
        action="store_true",
        help="Allow old verified artifacts without captured logs; fresh replay must still produce a trace-rich verifier reject.",
    )
    parser.add_argument("--timeout-sec", type=int, default=30)
    args = parser.parse_args(argv)

    labels = load_labels(args.ground_truth.resolve())
    candidates = discover(args.source_root.resolve(), labels, allow_rebuild_no_log=args.allow_rebuild_no_log)
    selected = select(candidates, set(args.case_id), args.limit)
    print_summary(candidates, selected)

    if not args.apply:
        print("dry_run: true")
        return 0
    if not args.all and not args.case_id:
        raise SystemExit("--apply requires --case-id or --all")

    manifest = load_manifest(args.bench_root.resolve())
    imported: list[str] = []
    failed: list[str] = []
    for candidate in selected:
        try:
            import_case(candidate, args.bench_root.resolve(), manifest, force=args.force, timeout_sec=args.timeout_sec)
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


def load_labels(path: Path) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        case["case_id"]: case
        for case in data.get("cases") or []
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    }


def discover(source_root: Path, labels: dict[str, dict[str, Any]], *, allow_rebuild_no_log: bool) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for source_dir in sorted(path for path in source_root.iterdir() if path.is_dir()):
        status = parse_status(source_dir / "verification_status.txt")
        case_id = status.get("case_id") or source_dir.name
        reason = eligibility_reason(source_dir, status, labels.get(case_id), allow_rebuild_no_log=allow_rebuild_no_log)
        candidates.append({"case_id": case_id, "source_dir": source_dir, "status": status, "label": labels.get(case_id), "reason": reason})
    return candidates


def parse_status(path: Path) -> dict[str, str]:
    status: dict[str, str] = {}
    if not path.exists():
        return status
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        status[key.strip()] = value.strip()
    return status


def eligibility_reason(
    source_dir: Path,
    status: dict[str, str],
    label: dict[str, Any] | None,
    *,
    allow_rebuild_no_log: bool,
) -> str | None:
    for name in ("prog.c", "Makefile", "selftest_prog_loader.c", "headers"):
        if not (source_dir / name).exists():
            return f"missing {name}"
    if status.get("compile_ok") != "yes":
        return "compile_ok is not yes"
    if status.get("load_attempted") != "yes":
        return "load_attempted is not yes"
    if status.get("verifier_rejected") != "yes":
        return "verifier_rejected is not yes"
    if status.get("verifier_log_captured") != "yes" and not allow_rebuild_no_log:
        return "verifier_log_captured is not yes"
    if not status.get("target_function"):
        return "missing target_function"
    if label is None:
        return "missing ground-truth label"
    return None


def select(candidates: list[dict[str, Any]], case_ids: set[str], limit: int | None) -> list[dict[str, Any]]:
    selected = [candidate for candidate in candidates if candidate["reason"] is None]
    if case_ids:
        selected = [candidate for candidate in selected if candidate["case_id"] in case_ids]
        missing = sorted(case_ids - {candidate["case_id"] for candidate in selected})
        if missing:
            raise SystemExit(f"requested case ids are not eligible: {', '.join(missing)}")
    if limit is not None:
        selected = selected[:limit]
    return selected


def print_summary(candidates: list[dict[str, Any]], selected: list[dict[str, Any]]) -> None:
    eligible = [candidate for candidate in candidates if candidate["reason"] is None]
    print(f"eligible: {len(eligible)}")
    selected_ids = {candidate["case_id"] for candidate in selected}
    for candidate in eligible:
        marker = "*" if candidate["case_id"] in selected_ids else " "
        status = candidate["status"]
        print(f"{marker} {candidate['case_id']} target={status.get('target_function')}")
    skipped: dict[str, int] = {}
    for candidate in candidates:
        if candidate["reason"]:
            skipped[candidate["reason"]] = skipped.get(candidate["reason"], 0) + 1
    if skipped:
        print("skipped:")
        for reason, count in sorted(skipped.items()):
            print(f"  {count:3d} {reason}")


def load_manifest(bench_root: Path) -> dict[str, Any]:
    path = bench_root / "manifest.yaml"
    if not path.exists():
        return {
            "schema_version": "bpfix.benchmark/v1",
            "benchmark_id": "bpfix-bench-seed-v1",
            "frozen_at": date.today().isoformat(),
            "environment_id": ENVIRONMENT_ID_FALLBACK,
            "description": "Minimal seed benchmark with locally reproducible verifier-log cases.",
            "cases": [],
        }
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("cases", [])
    return data


def write_manifest(bench_root: Path, manifest: dict[str, Any]) -> None:
    manifest["cases"] = sorted(manifest.get("cases") or [], key=lambda item: item.get("case_id", ""))
    (bench_root / "manifest.yaml").write_text(dump_yaml(manifest), encoding="utf-8")


def import_case(candidate: dict[str, Any], bench_root: Path, manifest: dict[str, Any], *, force: bool, timeout_sec: int) -> None:
    case_id = candidate["case_id"]
    source_dir: Path = candidate["source_dir"]
    status: dict[str, str] = candidate["status"]
    label: dict[str, Any] = candidate["label"]
    case_dir = bench_root / "cases" / case_id
    if case_dir.exists():
        if not force:
            return
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)

    shutil.copy2(source_dir / "prog.c", case_dir / "prog.c")
    shutil.copy2(source_dir / "selftest_prog_loader.c", case_dir / "selftest_prog_loader.c")
    shutil.copytree(source_dir / "headers", case_dir / "headers")
    patch_iterator_asm_ksym_btf(case_dir / "prog.c")
    write_makefile(case_dir / "Makefile", status["target_function"])

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

    (case_dir / "verifier.log").write_text(replay.verifier_log_captured, encoding="utf-8")
    environment_id = str(manifest.get("environment_id") or ENVIRONMENT_ID_FALLBACK)
    capture_id = f"{case_id}__{environment_id}"
    imported_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    case_yaml = build_case_yaml(candidate, capture_id, environment_id, fresh.terminal_error, fresh.rejected_insn_idx, fresh.log_quality)
    (case_dir / "case.yaml").write_text(dump_yaml(case_yaml), encoding="utf-8")
    capture_yaml = build_capture_yaml(candidate, capture_id, environment_id, imported_at)
    (case_dir / "capture.yaml").write_text(dump_yaml(capture_yaml), encoding="utf-8")

    upsert_manifest(manifest, {
        "case_id": case_id,
        "path": f"cases/{case_id}",
        "source_kind": "kernel_selftest",
        "family_id": family_id(fresh.terminal_error),
        "representative": True,
        "capture_id": capture_id,
    })


def write_makefile(path: Path, target_function: str) -> None:
    path.write_text(f"""\
CLANG ?= clang
CC ?= cc
TARGET_FUNCTION ?= {target_function}

CLANG_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | awk '/#include <...> search starts here:/{{flag=1; next}} /End of search list./{{flag=0}} flag && $$1 ~ /^\\// {{printf \"-idirafter %s \", $$1}}')
CFLAGS := -g -Wall -Werror -Wno-unused-function -Wno-unused-variable -D__TARGET_ARCH_x86 -mlittle-endian -Iheaders -Iheaders/progs -std=gnu11 -fno-strict-aliasing -Wno-microsoft-anon-tag -fms-extensions -Wno-compare-distinct-pointer-types -Wno-initializer-overrides $(CLANG_SYS_INCLUDES) -O2 --target=bpfel -mcpu=v3

.PHONY: all verify replay-verify clean

all: prog.o selftest_prog_loader

prog.o: prog.c
\t$(CLANG) $(CFLAGS) -c $< -o $@

selftest_prog_loader: selftest_prog_loader.c
\t$(CC) -O2 -Wall -Wextra -Werror $< -lbpf -lelf -lz -o $@

verify: prog.o selftest_prog_loader
\t@sudo ./selftest_prog_loader prog.o $(TARGET_FUNCTION) > verifier_load_result.json || true
\t@python3 -c "import json, pathlib, sys; data = json.loads(pathlib.Path('verifier_load_result.json').read_text()); verifier_log = data.get('verifier_log') or ''; pathlib.Path('verifier.log').write_text(verifier_log + ('\\n' if verifier_log else ''), encoding='utf-8'); sys.exit(0 if data.get('load_ok') else 1)"

replay-verify: prog.o selftest_prog_loader
\t@sudo ./selftest_prog_loader prog.o $(TARGET_FUNCTION) > replay_load_result.json || true
\t@python3 -c "import json, pathlib, sys; data = json.loads(pathlib.Path('replay_load_result.json').read_text()); verifier_log = data.get('verifier_log') or ''; pathlib.Path('replay-verifier.log').write_text(verifier_log + ('\\n' if verifier_log else ''), encoding='utf-8'); sys.exit(0 if data.get('load_ok') else 1)"

clean:
\trm -f prog.o selftest_prog_loader verifier_load_result.json replay_load_result.json replay-verifier.log
""", encoding="utf-8")


def patch_iterator_asm_ksym_btf(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if "__imm(bpf_iter_num_new)" not in source or "force_iter_ksym_btf" in source:
        return

    marker = 'char _license[] SEC("license") = "GPL";'
    helper = """

static __attribute__((used)) void force_iter_ksym_btf(struct bpf_iter_num *it)
{
\tbpf_iter_num_new(it, 0, 0);
\tbpf_iter_num_next(it);
\tbpf_iter_num_destroy(it);
}
"""
    if marker not in source:
        return
    path.write_text(source.replace(marker, marker + helper, 1), encoding="utf-8")


def build_case_yaml(
    candidate: dict[str, Any],
    capture_id: str,
    environment_id: str,
    terminal_error: str,
    rejected_insn_idx: int,
    log_quality: str,
) -> dict[str, Any]:
    case_id = candidate["case_id"]
    status: dict[str, str] = candidate["status"]
    label: dict[str, Any] = candidate["label"]
    return {
        "schema_version": "bpfix.case/v1",
        "case_id": case_id,
        "source": {
            "kind": "kernel_selftest",
            "url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/" + str(status.get("source_file") or ""),
            "repository": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            "commit": None,
            "upstream_file": status.get("source_file"),
            "upstream_section": status.get("target_function"),
            "collected_at": status.get("checked_at_utc"),
            "raw_excerpt_files": [],
        },
        "reproducer": {
            "status": "ready",
            "reconstruction": "original",
            "language": "C",
            "program_type": status.get("section"),
            "source_file": "prog.c",
            "build_command": "make",
            "object_path": "prog.o",
            "load_command": "make replay-verify",
            "notes": "Imported from locally verified kernel selftest artifact; replay log is written to replay-verifier.log.",
        },
        "capture": {
            "capture_id": capture_id,
            "environment_id": environment_id,
            "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "build_status": "success",
            "load_status": "verifier_reject",
            "verifier_pass": False,
            "exit_code": 1,
            "verifier_log": "replay-verifier.log",
            "capture_metadata": "capture.yaml",
            "log_quality": log_quality,
            "terminal_error": terminal_error,
            "rejected_insn_idx": rejected_insn_idx,
        },
        "external_match": {
            "status": "not_applicable",
            "policy": "kernel_selftest_expected_message",
            "matched_messages": [terminal_error],
            "notes": "Kernel selftest case; no external report matching is required.",
        },
        "label": {
            "capture_id": capture_id,
            "taxonomy_class": label.get("taxonomy_class"),
            "error_id": label.get("error_id"),
            "confidence": label.get("confidence"),
            "label_source": label.get("label_source"),
            "root_cause_description": label.get("root_cause_description"),
            "rejected_insn_idx": rejected_insn_idx,
            "legacy_rejected_insn_idx": label.get("rejected_insn_idx"),
            "root_cause_insn_idx": label.get("root_cause_insn_idx"),
            "rejected_line": label.get("rejected_line"),
            "root_cause_line": label.get("root_cause_line"),
            "localization_confidence": label.get("localization_confidence"),
            "fix_type": label.get("fix_type"),
            "fix_direction": label.get("fix_direction"),
        },
        "repair": {"eligible": False},
        "reporting": {
            "family_id": family_id(terminal_error),
            "representative": True,
            "intentional_negative_test": bool(label.get("is_intentional_negative_test", True)),
            "notes": "Kernel selftest replay-valid case.",
        },
    }


def build_capture_yaml(candidate: dict[str, Any], capture_id: str, environment_id: str, imported_at: str) -> dict[str, Any]:
    status: dict[str, str] = candidate["status"]
    return {
        "schema_version": "bpfix.capture/v1",
        "capture_id": capture_id,
        "case_id": candidate["case_id"],
        "environment_id": environment_id,
        "imported_at": imported_at,
        "source_artifact": {
            "path": relpath(candidate["source_dir"]),
            "status_file": "verification_status.txt",
            "source_file": status.get("source_file"),
            "target_function": status.get("target_function"),
            "section": status.get("section"),
            "compile_ok": status.get("compile_ok") == "yes",
            "load_attempted": status.get("load_attempted") == "yes",
            "verifier_rejected": status.get("verifier_rejected") == "yes",
            "verifier_log_captured": status.get("verifier_log_captured") == "yes",
        },
        "replay": {
            "build_command": "make",
            "load_command": "make replay-verify",
            "verifier_log": "replay-verifier.log",
            "expected_load_status": "verifier_reject",
        },
    }


def family_id(terminal_error: str) -> str:
    return terminal_error.split(";", 1)[0].strip()[:120]


def upsert_manifest(manifest: dict[str, Any], entry: dict[str, Any]) -> None:
    cases = manifest.setdefault("cases", [])
    cases[:] = [case for case in cases if case.get("case_id") != entry["case_id"]]
    cases.append(entry)


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
