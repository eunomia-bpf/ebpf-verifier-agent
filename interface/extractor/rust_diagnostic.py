"""Compatibility surface for Rust-style verifier diagnostics."""

from __future__ import annotations

from .renderer import DiagnosticOutput
from .pipeline import generate_diagnostic


__all__ = ["DiagnosticOutput", "generate_diagnostic"]
