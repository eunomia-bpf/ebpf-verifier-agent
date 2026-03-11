#!/usr/bin/env python3
"""Skeleton collector for assembling the OBLIGE benchmark corpus."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - covered indirectly by CLI smoke tests
    yaml = None


LOG = logging.getLogger("benchmark.collect")
SUPPORTED_SOURCES = (
    "stackoverflow",
    "selftest",
    "cilium",
    "aya",
    "katran",
    "synthetic",
)


@dataclass(slots=True)
class CollectionRequest:
    source: str
    limit: int
    output: Path
    force: bool = False
    emit_stub: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect, normalize, and validate verifier failure cases for the "
            "OBLIGE benchmark corpus."
        )
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser(
        "list-sources",
        help="List supported collection sources.",
    )
    list_parser.set_defaults(handler=handle_list_sources)

    collect_parser = subparsers.add_parser(
        "collect",
        help="Create a normalized collection manifest for a source.",
    )
    collect_parser.add_argument(
        "--source",
        choices=SUPPORTED_SOURCES,
        required=True,
        help="Source family to collect from.",
    )
    collect_parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of cases to collect in this run.",
    )
    collect_parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark") / "cases" / "manifest.yaml",
        help="Destination manifest path.",
    )
    collect_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing manifest if it already exists.",
    )
    collect_parser.add_argument(
        "--emit-stub",
        action="store_true",
        help="Emit one placeholder case to make downstream tooling easier to test.",
    )
    collect_parser.add_argument(
        "--format",
        choices=("yaml", "json"),
        default="yaml",
        help="Manifest serialization format.",
    )
    collect_parser.set_defaults(handler=handle_collect)

    validate_parser = subparsers.add_parser(
        "validate-manifest",
        help="Run a light schema sanity check on an existing manifest.",
    )
    validate_parser.add_argument(
        "manifest",
        type=Path,
        help="Path to a YAML or JSON manifest file.",
    )
    validate_parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).with_name("schema.yaml"),
        help="Schema document to use for required-field checks.",
    )
    validate_parser.set_defaults(handler=handle_validate_manifest)

    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required for YAML input/output support.")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def dump_yaml(path: Path, payload: dict[str, Any]) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required for YAML output support.")
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)


def handle_list_sources(_args: argparse.Namespace) -> int:
    for source in SUPPORTED_SOURCES:
        print(source)
    return 0


def handle_collect(args: argparse.Namespace) -> int:
    request = CollectionRequest(
        source=args.source,
        limit=args.limit,
        output=args.output,
        force=args.force,
        emit_stub=args.emit_stub,
    )

    if request.output.exists() and not request.force:
        LOG.error("Refusing to overwrite existing manifest: %s", request.output)
        return 2

    request.output.parent.mkdir(parents=True, exist_ok=True)
    payload = build_manifest(request)

    if args.format == "yaml":
        dump_yaml(request.output, payload)
    else:
        with request.output.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")

    LOG.info("Wrote collection manifest to %s", request.output)
    return 0


def build_manifest(request: CollectionRequest) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "collector_version": "0.1.0",
        "source": request.source,
        "limit": request.limit,
        "schema": "benchmark/schema.yaml",
        "status": "skeleton",
        "notes": [
            "Collector integrations are not implemented yet.",
            "This manifest is intended to unblock downstream development.",
        ],
        "cases": [],
    }
    if request.emit_stub:
        manifest["cases"].append(
            {
                "case_id": f"{request.source}-stub-001",
                "source": request.source,
                "title": "Placeholder verifier failure case",
                "failure_class": "source_bug",
                "source_code": "benchmark/cases/stub/prog.bpf.c",
                "compile_args": "-O2 -g -target bpf",
                "target_kernel": "6.8.0",
                "verifier_log": "benchmark/cases/stub/verifier.log",
                "root_cause": "Placeholder case emitted by collector skeleton.",
                "fix_patch": "benchmark/cases/stub/fix.patch",
                "semantic_test": "benchmark/cases/stub/test.sh",
                "tags": ["stub"],
                "difficulty": "easy",
            }
        )
    return manifest


def handle_validate_manifest(args: argparse.Namespace) -> int:
    schema = load_yaml(args.schema)
    manifest_path = args.manifest
    if not manifest_path.exists():
        LOG.error("Manifest file does not exist: %s", manifest_path)
        return 2

    if manifest_path.suffix in {".yaml", ".yml"}:
        manifest = load_yaml(manifest_path)
    else:
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)

    required_fields = set(schema.get("required", []))
    cases = manifest.get("cases", [])
    missing_by_case: dict[str, list[str]] = {}

    for case in cases:
        case_id = case.get("case_id", "<missing-case-id>")
        missing = sorted(field for field in required_fields if field not in case)
        if missing:
            missing_by_case[case_id] = missing

    if missing_by_case:
        for case_id, missing in missing_by_case.items():
            LOG.error("Case %s is missing required fields: %s", case_id, ", ".join(missing))
        return 1

    LOG.info("Validated %d cases against required field list.", len(cases))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
