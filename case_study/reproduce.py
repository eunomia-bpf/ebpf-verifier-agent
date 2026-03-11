#!/usr/bin/env python3
"""Skeleton reproduction harness for verifier failures."""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


LOG = logging.getLogger("benchmark.reproduce")


@dataclass(slots=True)
class ReproductionTarget:
    source_code: Path
    compile_args: str
    target_kernel: str
    output_dir: Path
    execute: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reproduce a verifier failure from source, compile flags, and target-kernel metadata."
        )
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    single_parser = subparsers.add_parser(
        "single",
        help="Plan or run reproduction for a single benchmark case.",
    )
    single_parser.add_argument("--source-code", type=Path, required=True, help="Path to the failing .bpf.c file.")
    single_parser.add_argument("--compile-args", required=True, help="Exact clang flags used for reproduction.")
    single_parser.add_argument("--target-kernel", required=True, help="Kernel version or label.")
    single_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out") / "reproduce",
        help="Directory to place generated artifacts.",
    )
    single_parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually invoke clang. Without this flag the script only prints a plan.",
    )
    single_parser.set_defaults(handler=handle_single)

    batch_parser = subparsers.add_parser(
        "batch",
        help="Read a benchmark manifest and print the cases that would be reproduced.",
    )
    batch_parser.add_argument("manifest", type=Path, help="Manifest file produced by case_study/collect.py.")
    batch_parser.set_defaults(handler=handle_batch)

    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def handle_single(args: argparse.Namespace) -> int:
    target = ReproductionTarget(
        source_code=args.source_code,
        compile_args=args.compile_args,
        target_kernel=args.target_kernel,
        output_dir=args.output_dir,
        execute=args.execute,
    )

    plan = build_reproduction_plan(target)
    print(json.dumps(plan, indent=2))

    if not target.execute:
        LOG.info("Dry run only. Re-run with --execute to invoke clang.")
        return 0

    return run_single(target, plan)


def build_reproduction_plan(target: ReproductionTarget) -> dict[str, object]:
    output_obj = target.output_dir / f"{target.source_code.stem}.o"
    compile_command = build_clang_command(target.source_code, output_obj, target.compile_args)
    return {
        "status": "planned",
        "target_kernel": target.target_kernel,
        "source_code": str(target.source_code),
        "output_object": str(output_obj),
        "compile_command": compile_command,
        "next_steps": [
            "Compile the source to BPF bytecode.",
            "Load the program with a verifier-log-capable loader.",
            "Capture the raw verifier log and store it alongside the case.",
        ],
    }


def build_clang_command(source_code: Path, output_object: Path, compile_args: str) -> list[str]:
    return ["clang", *shlex.split(compile_args), "-c", str(source_code), "-o", str(output_object)]


def run_single(target: ReproductionTarget, plan: dict[str, object]) -> int:
    clang = shutil.which("clang")
    if clang is None:
        LOG.error("clang is not available in PATH; cannot execute reproduction.")
        return 2

    target.output_dir.mkdir(parents=True, exist_ok=True)
    command = plan["compile_command"]
    LOG.info("Running compile command: %s", " ".join(command))
    completed = subprocess.run(command, check=False, text=True, capture_output=True)

    if completed.stdout:
        LOG.info("clang stdout:\n%s", completed.stdout.strip())
    if completed.stderr:
        LOG.info("clang stderr:\n%s", completed.stderr.strip())

    if completed.returncode != 0:
        LOG.error("Compilation failed with exit code %d", completed.returncode)
        return completed.returncode

    LOG.info(
        "Compilation succeeded. Loader integration is still TODO, so verifier reproduction stops here."
    )
    return 0


def handle_batch(args: argparse.Namespace) -> int:
    manifest_path = args.manifest
    if not manifest_path.exists():
        LOG.error("Manifest file does not exist: %s", manifest_path)
        return 2

    with manifest_path.open("r", encoding="utf-8") as handle:
        if manifest_path.suffix == ".json":
            payload = json.load(handle)
        else:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - exercised only when YAML input is used
                raise RuntimeError("PyYAML is required to read YAML manifests.") from exc
            payload = yaml.safe_load(handle) or {}

    cases = payload.get("cases", [])
    print(f"manifest={manifest_path}")
    print(f"cases={len(cases)}")
    for case in cases:
        print(f"- {case.get('case_id', '<unknown>')}: {case.get('title', '<untitled>')}")

    LOG.info("Batch reproduction is currently a planning-only path.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
