"""Backward-slicing helpers for proof obligations."""

from __future__ import annotations

from ._impl import SliceEdge, backward_obligation_slice, backward_slice

__all__ = ["SliceEdge", "backward_obligation_slice", "backward_slice"]
