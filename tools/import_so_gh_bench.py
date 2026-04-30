#!/usr/bin/env python3
"""Import verified Stack Overflow / GitHub cases into bpfix-bench.

The importer is intentionally conservative:

* Only verifier_status=rejected is eligible.
* exact/partial matches are imported by default; mismatch cases require
  --match mismatch plus --verify-replay and are marked as semantic matches.
* A ground-truth label is required before a case can enter bpfix-bench.
* Writes require --apply and either explicit --case-id values or --all.
* Existing benchmark cases are not overwritten unless --force is supplied.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
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
DEFAULT_MATCHES = {"exact", "partial", "substring"}
SUPPORTED_MATCHES = {"exact", "partial", "substring", "mismatch"}


@dataclass(frozen=True)
class Candidate:
    case_id: str
    source_dir: Path
    status: dict[str, str]
    label: dict[str, Any] | None
    reason: str | None

    @property
    def eligible(self) -> bool:
        return self.reason is None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--bench-root", type=Path, default=DEFAULT_BENCH_ROOT)
    parser.add_argument("--ground-truth", type=Path)
    parser.add_argument("--case-id", action="append", default=[], help="Import only this case id; repeatable")
    parser.add_argument("--match", choices=sorted(SUPPORTED_MATCHES), action="append", help="Restrict match quality")
    parser.add_argument("--limit", type=int, help="Limit selected eligible cases")
    parser.add_argument("--all", action="store_true", help="Allow applying all selected eligible cases")
    parser.add_argument("--apply", action="store_true", help="Write bpfix-bench cases and manifest entries")
    parser.add_argument("--force", action="store_true", help="Replace an existing imported case directory")
    parser.add_argument(
        "--verify-replay",
        action="store_true",
        help="Replay each imported case before adding it to manifest; remove it if fresh verifier output differs",
    )
    parser.add_argument("--timeout-sec", type=int, default=30, help="Per-command replay timeout for --verify-replay")
    args = parser.parse_args(argv)

    source_root = args.source_root.resolve()
    bench_root = args.bench_root.resolve()
    labels = load_labels(args.ground_truth.resolve()) if args.ground_truth else {}
    matches = set(args.match or DEFAULT_MATCHES)
    candidates = discover_candidates(source_root, labels, matches)
    selected = select_candidates(candidates, set(args.case_id), args.limit)

    print_summary(candidates, selected)

    if not args.apply:
        print("dry_run: true")
        return 0
    if not selected:
        print("nothing selected")
        return 0
    if not args.all and not args.case_id:
        raise SystemExit("--apply requires --case-id or --all")

    manifest = load_manifest(bench_root)
    imported: list[str] = []
    failed: list[str] = []
    for candidate in selected:
        try:
            import_case(
                candidate,
                bench_root,
                manifest,
                force=args.force,
                verify_replay=args.verify_replay,
                timeout_sec=args.timeout_sec,
            )
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{candidate.case_id}: {exc}")
            continue
        imported.append(candidate.case_id)
    write_manifest(bench_root, manifest)
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
    cases = data.get("cases") or []
    labels: dict[str, dict[str, Any]] = {}
    for case in cases:
        if isinstance(case, dict) and isinstance(case.get("case_id"), str):
            labels[case["case_id"]] = case
    return labels


def discover_candidates(source_root: Path, labels: dict[str, dict[str, Any]], matches: set[str]) -> list[Candidate]:
    candidates: list[Candidate] = []
    for status_path in sorted(source_root.glob("*/verification_status.txt")):
        status = parse_status_file(status_path)
        case_id = status.get("case_id") or status_path.parent.name
        reason = eligibility_reason(status_path.parent, status, labels.get(case_id), matches)
        candidates.append(Candidate(case_id, status_path.parent, status, labels.get(case_id), reason))
    return candidates


def parse_status_file(path: Path) -> dict[str, str]:
    status: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        status[key.strip()] = value.strip()
    return status


def eligibility_reason(
    source_dir: Path,
    status: dict[str, str],
    label: dict[str, Any] | None,
    matches: set[str],
) -> str | None:
    if status.get("verifier_status") != "rejected":
        return "verifier_status is not rejected"
    if status.get("verifier_error_match") not in matches:
        return "verifier_error_match is not selected"
    for name in ("prog.c", "Makefile", "verifier_log_captured.txt"):
        if not (source_dir / name).exists():
            return f"missing {name}"
    if label is None:
        return "missing ground-truth label"
    return None


def select_candidates(candidates: list[Candidate], case_ids: set[str], limit: int | None) -> list[Candidate]:
    selected = [candidate for candidate in candidates if candidate.eligible]
    if case_ids:
        selected = [candidate for candidate in selected if candidate.case_id in case_ids]
        missing = sorted(case_ids - {candidate.case_id for candidate in selected})
        if missing:
            raise SystemExit(f"requested case ids are not eligible or do not exist: {', '.join(missing)}")
    if limit is not None:
        selected = selected[:limit]
    return selected


def print_summary(candidates: list[Candidate], selected: list[Candidate]) -> None:
    eligible = [candidate for candidate in candidates if candidate.eligible]
    print(f"eligible: {len(eligible)}")
    for candidate in eligible:
        match = candidate.status.get("verifier_error_match")
        fixed = "yes" if (candidate.source_dir / "fixed.c").exists() else "no"
        marker = "*" if candidate in selected else " "
        print(f"{marker} {candidate.case_id} match={match} fixed={fixed}")
    skipped: dict[str, int] = {}
    for candidate in candidates:
        if candidate.reason:
            skipped[candidate.reason] = skipped.get(candidate.reason, 0) + 1
    if skipped:
        print("skipped:")
        for reason, count in sorted(skipped.items()):
            print(f"  {count:3d} {reason}")


def load_manifest(bench_root: Path) -> dict[str, Any]:
    manifest_path = bench_root / "manifest.yaml"
    if not manifest_path.exists():
        return {
            "schema_version": "bpfix.benchmark/v1",
            "benchmark_id": "bpfix-bench-seed-v1",
            "frozen_at": date.today().isoformat(),
            "environment_id": ENVIRONMENT_ID_FALLBACK,
            "description": "Minimal seed benchmark with locally reproducible verifier-log cases.",
            "cases": [],
        }
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data.get("cases"), list):
        data["cases"] = []
    return data


def write_manifest(bench_root: Path, manifest: dict[str, Any]) -> None:
    bench_root.mkdir(parents=True, exist_ok=True)
    manifest["cases"] = sorted(manifest.get("cases") or [], key=lambda entry: entry.get("case_id", ""))
    (bench_root / "manifest.yaml").write_text(dump_yaml(manifest), encoding="utf-8")


def import_case(
    candidate: Candidate,
    bench_root: Path,
    manifest: dict[str, Any],
    force: bool,
    verify_replay: bool,
    timeout_sec: int,
) -> None:
    assert candidate.label is not None
    case_id = candidate.case_id
    raw_match = candidate.status.get("verifier_error_match")
    if raw_match == "mismatch" and not verify_replay:
        raise SystemExit(f"mismatch import requires --verify-replay: {case_id}")
    case_dir = bench_root / "cases" / case_id
    if case_dir.exists():
        if not force:
            raise SystemExit(f"case already exists, use --force to replace: {case_id}")
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)

    copy_artifacts(candidate.source_dir, case_dir)
    compatibility_notes = apply_compatibility_rewrites(candidate, case_dir / "prog.c")
    rewrite_makefile(case_dir / "Makefile")
    apply_makefile_compatibility(candidate, case_dir / "Makefile")

    environment_id = str(manifest.get("environment_id") or ENVIRONMENT_ID_FALLBACK)
    capture_id = f"{case_id}__{environment_id}"
    imported_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    parsed = parse_verifier_log(
        (candidate.source_dir / "verifier_log_captured.txt").read_text(encoding="utf-8", errors="replace"),
        source="verifier_log_captured.txt",
    )

    if verify_replay:
        skeleton = {
            "reproducer": {
                "build_command": "make",
                "load_command": "make replay-verify",
                "object_path": "prog.o",
            },
            "capture": {"verifier_log": "verifier.log"},
        }
        replay = replay_case(case_dir, skeleton, timeout_sec=timeout_sec)
        fresh = replay.parsed_log
        if replay.load.returncode == 0:
            shutil.rmtree(case_dir)
            raise RuntimeError(f"fresh replay load succeeded; expected verifier reject for {case_id}")
        fresh_log_text = replay.verifier_log_captured or replay.load.combined_output
        if not fresh_log_text or not fresh.terminal_error or fresh.rejected_insn_idx is None:
            shutil.rmtree(case_dir)
            raise RuntimeError(f"fresh replay did not produce a trace-rich verifier log for {case_id}")
        captured_error = candidate.status.get("captured_error")
        if raw_match != "mismatch" and captured_error and fresh.terminal_error != captured_error:
            shutil.rmtree(case_dir)
            raise RuntimeError(
                "fresh replay terminal error does not match verified captured_error for "
                f"{case_id}: expected {captured_error!r}, got {fresh.terminal_error!r}"
            )
        (case_dir / "verifier.log").write_text(fresh_log_text, encoding="utf-8")
        parsed = fresh
    else:
        if not parsed.terminal_error or parsed.rejected_insn_idx is None:
            shutil.rmtree(case_dir)
            raise SystemExit(f"stored verifier log is not trace-rich enough for import: {case_id}")
        shutil.copy2(candidate.source_dir / "verifier_log_captured.txt", case_dir / "verifier.log")

    case_yaml = build_case_yaml(
        candidate,
        capture_id,
        environment_id,
        parsed.terminal_error,
        parsed.rejected_insn_idx,
        parsed.log_quality,
        compatibility_notes,
    )
    (case_dir / "case.yaml").write_text(dump_yaml(case_yaml), encoding="utf-8")
    capture_yaml = build_capture_yaml(candidate, capture_id, environment_id, imported_at)
    if compatibility_notes:
        capture_yaml["source_artifact"]["compatibility_rewrites"] = compatibility_notes
    (case_dir / "capture.yaml").write_text(dump_yaml(capture_yaml), encoding="utf-8")

    upsert_manifest_entry(
        manifest,
        {
            "case_id": case_id,
            "path": f"cases/{case_id}",
            "source_kind": source_kind(case_id),
            "family_id": case_id,
            "representative": True,
            "capture_id": capture_id,
        },
    )


def copy_artifacts(source_dir: Path, case_dir: Path) -> None:
    for name in ("prog.c", "Makefile"):
        shutil.copy2(source_dir / name, case_dir / name)
    if (source_dir / "prog.o").exists():
        shutil.copy2(source_dir / "prog.o", case_dir / "prog.o")
    fixed_source = source_dir / "fixed.c"
    if fixed_source.exists():
        fixed_dir = case_dir / "fixed"
        fixed_dir.mkdir()
        shutil.copy2(fixed_source, fixed_dir / "prog.c")


def apply_compatibility_rewrites(candidate: Candidate, source_path: Path) -> list[str]:
    notes: list[str] = []
    if candidate.case_id == "stackoverflow-70721661":
        source = source_path.read_text(encoding="utf-8")
        old = """struct bpf_map_def SEC("maps") ip_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct share_me),
    .max_entries = 64,
};"""
        new = """struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, struct share_me);
} ip_map SEC(".maps");"""
        source = replace_required(source, old, new, candidate.case_id)
        source = replace_required(
            source,
            """    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

""",
            "",
            candidate.case_id,
        )
        source_path.write_text(source, encoding="utf-8")
        return [
            "converted legacy array map to BTF SEC(\".maps\") definition",
            "removed reconstructed IP-header bounds check so the replay reaches the reported packet-access rejection",
        ]
    if candidate.case_id == "stackoverflow-74178703":
        source = source_path.read_text(encoding="utf-8")
        old = """struct bpf_elf_map __section("maps") data_store = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = 1024,
    .max_elem = 4096,
    .pinning = PIN_GLOBAL_NS,
};"""
        new = """struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8[1024]);
} data_store SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[512]);
} dst_store SEC(".maps");"""
        source = replace_required(source, old, new, candidate.case_id)
        source = replace_required(
            source,
            """    char dst[64] = {};
    read_data(0, 0, dst, sizeof(dst));
    return 0;""",
            """    __u32 zero = 0;
    __u8 *dst = bpf_map_lookup_elem(&dst_store, &zero);
    if (!dst)
        return 0;

    __u32 off = bpf_get_prandom_u32() & 1023;
    __u32 sz = (bpf_get_prandom_u32() & 511) + 1;
    read_data(0, off, dst, sz);
    return dst[0];""",
            candidate.case_id,
        )
        source_path.write_text(source, encoding="utf-8")
        return [
            "converted legacy bpf_elf_map to BTF SEC(\".maps\") definitions",
            "made offset/size verifier-visible scalars and preserved the copied byte so clang cannot optimize away the map-value read",
        ]
    if candidate.case_id == "stackoverflow-75294010":
        source = source_path.read_text(encoding="utf-8")
        source = replace_original_code(
            source,
            """#define MAX_MSG_SIZE 1024

struct syscall_write_event_t {
    struct attr_t {
        int event_type;
        int fd;
        int bytes;
        int msg_size;
    } attr;
    char msg[MAX_MSG_SIZE];
};

struct sys_enter_read_write_ctx {
    __u64 __unused_syscall_header;
    __u32 __unused_syscall_nr;
    __u64 fd;
    const char *buf;
    size_t count;
};

enum {
    kEventTypeSyscallWriteEvent = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syscall_write_event_t);
} write_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} syscall_write_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__probe_write(struct sys_enter_read_write_ctx *ctx)
{
    int zero = 0;
    struct syscall_write_event_t *event = bpf_map_lookup_elem(&write_buffer_heap, &zero);
    if (!event)
        return 0;

    __builtin_memset(&event, 0, sizeof(event));
    event->attr.fd = ctx->fd;
    event->attr.bytes = ctx->count;
    size_t buf_size = ctx->count & 0x3ff;
    bpf_probe_read(&event->msg, buf_size, ctx->buf);
    event->attr.msg_size = buf_size;
    event->attr.event_type = kEventTypeSyscallWriteEvent;
    bpf_perf_event_output(ctx, &syscall_write_events, BPF_F_CURRENT_CPU, &event, sizeof(event->attr) + buf_size);
    return 0;
}

char _license[] SEC("license") = "GPL";""",
            candidate.case_id,
        )
        source_path.write_text(source, encoding="utf-8")
        return [
            "reconstructed the full tracepoint program body because the verified artifact only captured map declarations",
            "kept the original pointer-clearing memset pattern that triggers the reported invalid memory access",
        ]
    if candidate.case_id == "stackoverflow-75515263":
        source = source_path.read_text(encoding="utf-8")
        old = """struct bpf_map_def SEC("maps") lookup = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct sock_info *),
    .max_entries = MAX_ENTRIES,
};"""
        new = """struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct sock_info *);
} lookup SEC(".maps");"""
        source = replace_required(source, old, new, candidate.case_id)
        source = replace_required(source, "og_sock->ctime", "og_sock->sport", candidate.case_id)
        source_path.write_text(source, encoding="utf-8")
        return [
            "converted legacy hash map to BTF SEC(\".maps\") definition while preserving pointer-sized map values",
            "read the first field past the pointer-sized map value to reproduce the reported off=8 map-value rejection",
        ]
    if candidate.case_id == "stackoverflow-76277872":
        source = source_path.read_text(encoding="utf-8")
        replacements = {
            "srcMap": ("__u32", "__u64"),
            "dstMap": ("__u32", "__u64"),
            "protoMap": ("__u8", "__u64"),
            "sportMap": ("__u16", "__u64"),
            "dportMap": ("__u16", "__u64"),
            "actionMap": ("__u64", "__u64"),
        }
        for name, (key_type, value_type) in replacements.items():
            old = f"""struct bpf_map_def SEC("maps") {name} = {{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof({key_type}),
    .value_size = sizeof({value_type}),
    .max_entries = 4194304,
}};"""
            new = f"""struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4194304);
    __type(key, {key_type});
    __type(value, {value_type});
}} {name} SEC(".maps");"""
            source = replace_required(source, old, new, candidate.case_id)
        source = replace_required(
            source,
            """    if ((void *)(iph + 1) > end)
        return XDP_ABORTED;

""",
            "",
            candidate.case_id,
        )
        source_path.write_text(source, encoding="utf-8")
        return [
            "converted legacy hash maps to BTF SEC(\".maps\") definitions",
            "removed reconstructed IP-header bounds check so the replay reaches the reported packet-access rejection",
        ]
    if candidate.case_id != "stackoverflow-69413427":
        return notes
    source = source_path.read_text(encoding="utf-8")
    old = """    struct bpf_map_def info SEC("maps") ={
        .type = BPF_MAP_TYPE_HASH,
        .max_entries =  100,
        .key_size = sizeof(struct inode *),
        .value_size = sizeof(struct value),
        .map_flags = BPF_F_NO_PREALLOC,
    };"""
    new = """    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100);
        __type(key, struct inode *);
        __type(value, struct value);
        __uint(map_flags, BPF_F_NO_PREALLOC);
    } info SEC(".maps");"""
    if old not in source:
        raise RuntimeError("compatibility rewrite pattern not found for stackoverflow-69413427")
    source_path.write_text(source.replace(old, new), encoding="utf-8")
    return ["converted legacy SEC(\"maps\") bpf_map_def to BTF SEC(\".maps\") definition for libbpf v1 replay"]


def replace_required(source: str, old: str, new: str, case_id: str) -> str:
    if old not in source:
        raise RuntimeError(f"compatibility rewrite pattern not found for {case_id}")
    return source.replace(old, new)


def replace_original_code(source: str, new_body: str, case_id: str) -> str:
    start_marker = "/* === ORIGINAL CODE from SO/GH post === */"
    end_marker = "/* === END ORIGINAL CODE === */"
    start = source.find(start_marker)
    end = source.find(end_marker)
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError(f"original-code markers not found for {case_id}")
    prefix = source[: start + len(start_marker)].rstrip()
    suffix = source[end:].lstrip()
    return f"{prefix}\n\n{new_body.rstrip()}\n\n{suffix}"


def rewrite_makefile(makefile_path: Path) -> None:
    makefile_path.write_text(
        """\
SHELL := /bin/bash
CLANG ?= clang
BPFTool ?= sudo bpftool
CFLAGS ?= -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86
PIN ?= /sys/fs/bpf/$(notdir $(CURDIR))
LOG_LIMIT ?= 8000000

.PHONY: all verify replay-verify clean

all: prog.o

prog.o: prog.c
\t$(CLANG) $(CFLAGS) -c $< -o $@

verify: prog.o
\t$(BPFTool) -d prog load prog.o $(PIN)

replay-verify: prog.o
\trm -f replay-verifier.log
\tset -o pipefail; $(BPFTool) -d prog load prog.o $(PIN) 2>&1 | tail -c $(LOG_LIMIT) > replay-verifier.log

clean:
\trm -f prog.o replay-verifier.log
""",
        encoding="utf-8",
    )


def apply_makefile_compatibility(candidate: Candidate, makefile_path: Path) -> None:
    if candidate.case_id != "github-aya-rs-aya-521":
        return
    source = makefile_path.read_text(encoding="utf-8")
    source = source.replace(
        "CFLAGS ?= -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86",
        "CFLAGS ?= -target bpf -O2 -I /usr/include -D__TARGET_ARCH_x86",
    )
    makefile_path.write_text(source, encoding="utf-8")


def build_capture_yaml(
    candidate: Candidate,
    capture_id: str,
    environment_id: str,
    imported_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": "bpfix.capture/v1",
        "capture_id": capture_id,
        "case_id": candidate.case_id,
        "environment_id": environment_id,
        "imported_at": imported_at,
        "source_artifact": {
            "path": relpath(candidate.source_dir),
            "status_file": "verification_status.txt",
            "captured_log_file": "verifier_log_captured.txt",
            "source_origin": candidate.status.get("source_origin"),
            "source_bucket": candidate.status.get("source_bucket"),
            "language": candidate.status.get("language"),
            "compile_ok": parse_bool(candidate.status.get("compile_ok")),
            "verifier_status": candidate.status.get("verifier_status"),
            "verifier_error_match": candidate.status.get("verifier_error_match"),
            "fixed_status": candidate.status.get("fixed_status"),
        },
        "replay": {
            "build_command": "make",
            "load_command": "make replay-verify",
            "verifier_log": "replay-verifier.log",
            "expected_load_status": "verifier_reject",
        },
    }


def build_case_yaml(
    candidate: Candidate,
    capture_id: str,
    environment_id: str,
    terminal_error: str,
    rejected_insn_idx: int,
    log_quality: str,
    compatibility_notes: list[str],
) -> dict[str, Any]:
    label = candidate.label or {}
    raw_match = candidate.status["verifier_error_match"]
    match = "semantic" if raw_match == "mismatch" else ("partial" if raw_match == "substring" else raw_match)
    original_error = candidate.status.get("original_error")
    captured_error = candidate.status.get("captured_error")
    reproducer_notes = "Imported from an explicit reconstructed SO/GH artifact; replay logs are generated as replay-verifier.log."
    if compatibility_notes:
        reproducer_notes += " Compatibility rewrite: " + "; ".join(compatibility_notes) + "."
    return {
        "schema_version": "bpfix.case/v1",
        "case_id": candidate.case_id,
        "source": build_source(candidate),
        "reproducer": {
            "status": "ready",
            "reconstruction": "reconstructed",
            "language": "C",
            "source_file": "prog.c",
            "build_command": "make",
            "object_path": "prog.o",
            "load_command": "make replay-verify",
            "notes": reproducer_notes,
        },
        "capture": {
            "capture_id": capture_id,
            "environment_id": environment_id,
            "build_status": "success",
            "load_status": "verifier_reject",
            "verifier_pass": False,
            "verifier_log": "replay-verifier.log",
            "capture_metadata": "capture.yaml",
            "log_quality": log_quality,
            "terminal_error": terminal_error,
            "rejected_insn_idx": rejected_insn_idx,
        },
        "external_match": {
            "status": match,
            "policy": "terminal_error",
            "matched_messages": [value for value in (original_error, captured_error) if value],
            "notes": external_match_notes(raw_match),
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
        "repair": {"eligible": (candidate.source_dir / "fixed.c").exists()},
        "reporting": {
            "family_id": candidate.case_id,
            "representative": True,
            "intentional_negative_test": bool(label.get("is_intentional_negative_test", False)),
            "notes": reporting_notes(raw_match),
        },
    }


def external_match_notes(raw_match: str) -> str:
    if raw_match == "mismatch":
        return (
            "Original external report text did not exactly match this kernel's terminal verifier error; "
            "the case is included because the local replay produces a trace-rich verifier rejection."
        )
    return "Imported only because verifier_error_match was exact/partial in the verified SO/GH artifact."


def reporting_notes(raw_match: str) -> str:
    if raw_match == "mismatch":
        return "External SO/GH case imported as a replay-valid semantic match."
    return "External SO/GH case imported from verified exact/partial artifact."


def build_source(candidate: Candidate) -> dict[str, Any]:
    case_id = candidate.case_id
    if case_id.startswith("stackoverflow-"):
        question_id = case_id.rsplit("-", 1)[-1]
        raw = load_raw_external_case(case_id)
        question = raw.get("question") if isinstance(raw.get("question"), dict) else {}
        url = question.get("url") if isinstance(question.get("url"), str) else None
        return {
            "kind": "stackoverflow",
            "url": url or f"https://stackoverflow.com/questions/{question_id}",
            "repository": None,
            "commit": None,
            "upstream_file": None,
            "collected_at": raw.get("collected_at") if isinstance(raw.get("collected_at"), str) else None,
            "raw_excerpt_files": [relpath(raw_external_path(case_id))] if raw_external_path(case_id).exists() else [],
        }
    if case_id.startswith("github-"):
        raw = load_raw_external_case(case_id)
        issue_data = raw.get("issue") if isinstance(raw.get("issue"), dict) else {}
        repository = issue_data.get("repository") if isinstance(issue_data.get("repository"), str) else None
        raw_url = issue_data.get("url") if isinstance(issue_data.get("url"), str) else None
        owner, repo = (repository.split("/", 1) if repository and "/" in repository else (None, None))
        issue = str(issue_data.get("number")) if issue_data.get("number") is not None else case_id.rsplit("-", 1)[-1]
        url = raw_url or (f"https://github.com/{owner}/{repo}/issues/{issue}" if owner and repo else None)
        return {
            "kind": "github_issue",
            "url": url,
            "repository": f"https://github.com/{owner}/{repo}" if owner and repo else None,
            "commit": None,
            "upstream_file": None,
            "collected_at": raw.get("collected_at") if isinstance(raw.get("collected_at"), str) else None,
            "raw_excerpt_files": [relpath(raw_external_path(case_id))] if raw_external_path(case_id).exists() else [],
        }
    return {"kind": "external", "url": None, "raw_excerpt_files": []}


def raw_external_path(case_id: str) -> Path:
    bucket = "so" if case_id.startswith("stackoverflow-") else "gh"
    new_path = ROOT / "bpfix-bench" / "raw" / bucket / f"{case_id}.yaml"
    if new_path.exists():
        return new_path
    return new_path


def load_raw_external_case(case_id: str) -> dict[str, Any]:
    path = raw_external_path(case_id)
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    if isinstance(data, dict) and data.get("schema_version") == "bpfix.raw_external/v1":
        raw = data.get("raw")
        return raw if isinstance(raw, dict) else {}
    return data if isinstance(data, dict) else {}


def source_kind(case_id: str) -> str:
    if case_id.startswith("stackoverflow-"):
        return "stackoverflow"
    if case_id.startswith("github-"):
        return "github_issue"
    return "external"


def upsert_manifest_entry(manifest: dict[str, Any], entry: dict[str, Any]) -> None:
    cases = manifest.setdefault("cases", [])
    cases[:] = [existing for existing in cases if existing.get("case_id") != entry["case_id"]]
    cases.append(entry)


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
