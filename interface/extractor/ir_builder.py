"""IR construction helpers for the proof engine."""

from __future__ import annotations

from .obligation_inference import InstructionNode, TraceIR, ValueVersion, build_trace_ir

__all__ = [
    "InstructionNode",
    "TraceIR",
    "ValueVersion",
    "build_trace_ir",
]
