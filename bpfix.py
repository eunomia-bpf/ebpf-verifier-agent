"""User-facing BPFix module and CLI shim."""

from __future__ import annotations

from oblige import (
    DiagnosticOutput,
    SCHEMA_PATH,
    build_diagnostic,
    generate_diagnostic,
    load_schema,
)
from oblige.cli import main


__all__ = [
    "DiagnosticOutput",
    "SCHEMA_PATH",
    "build_diagnostic",
    "generate_diagnostic",
    "load_schema",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
