"""Span-normalization helpers for Rust diagnostics."""

from __future__ import annotations

from ._impl import _normalize_spans

__all__ = ["_normalize_spans"]
