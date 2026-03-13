"""Backward slicing helpers for the proof engine."""

from __future__ import annotations

from .obligation_inference import backward_obligation_slice, backward_slice

__all__ = [
    "backward_obligation_slice",
    "backward_slice",
]
