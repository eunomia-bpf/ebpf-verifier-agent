"""User-facing API for BPFix."""

from __future__ import annotations

from interface.api import SCHEMA_PATH, build_diagnostic, load_schema
from interface.extractor.rust_diagnostic import DiagnosticOutput, generate_diagnostic


__all__ = [
    "DiagnosticOutput",
    "SCHEMA_PATH",
    "build_diagnostic",
    "generate_diagnostic",
    "load_schema",
]
