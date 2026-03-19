"""Command-line entry point for generating BPFix diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from interface.extractor.rust_diagnostic import generate_diagnostic


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bpfix",
        description="Generate BPFix diagnostics from a verifier log or case manifest.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to a raw verifier log or YAML case manifest. Use '-' or omit to read stdin.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "both"),
        default="text",
        help="Output format to print.",
    )
    parser.add_argument(
        "--catalog",
        help="Optional path to an alternate taxonomy/error catalog.",
    )
    parser.add_argument(
        "--bpftool-xlated",
        metavar="PATH",
        help="Optional bpftool `prog dump xlated linum` output to improve source correlation.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation level when printing JSON output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="bpfix 0.1.0",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw_log, metadata = _load_input(args.input)
    bpftool_xlated = (
        Path(args.bpftool_xlated).read_text(encoding="utf-8")
        if args.bpftool_xlated
        else None
    )
    output = generate_diagnostic(
        raw_log,
        catalog_path=args.catalog,
        bpftool_xlated=bpftool_xlated,
    )
    json_data = dict(output.json_data)

    case_id = metadata.get("case_id")
    if isinstance(case_id, str) and case_id:
        json_data["case_id"] = case_id

    kernel_release = metadata.get("kernel_release") or metadata.get("target_kernel")
    if isinstance(kernel_release, str) and kernel_release:
        json_data["kernel_release"] = kernel_release

    if args.format in {"text", "both"}:
        print(output.text)
    if args.format in {"json", "both"}:
        if args.format == "both":
            print()
        print(json.dumps(json_data, indent=args.indent, sort_keys=True))

    return 0


def _load_input(raw_input: str) -> tuple[str, dict[str, Any]]:
    if raw_input == "-":
        return sys.stdin.read(), {}

    path = Path(raw_input)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return text, {}

    payload = yaml.safe_load(text)
    if not isinstance(payload, dict) or "verifier_log" not in payload:
        return text, {}

    return _extract_verifier_log(payload), payload


def _extract_verifier_log(payload: dict[str, Any]) -> str:
    verifier_log = payload["verifier_log"]
    if isinstance(verifier_log, str):
        return verifier_log
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str):
            return combined
        blocks = verifier_log.get("blocks")
        if isinstance(blocks, list):
            return "\n\n".join(block for block in blocks if isinstance(block, str))
    raise ValueError("YAML input does not contain a usable `verifier_log` value")
