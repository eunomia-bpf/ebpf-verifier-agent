"""Compatibility surface for the split trace parser."""

from __future__ import annotations

from .trace_parser_parts._impl import _is_pointer_type
from .trace_parser_parts import (
    BacktrackChain,
    BacktrackInfo,
    BacktrackLine,
    BacktrackLink,
    CausalChain,
    ChainLink,
    CriticalTransition,
    ErrorLine,
    InstructionLine,
    OtherLine,
    ParsedTrace,
    RegisterState,
    RegisterStateLine,
    SourceAnnotation,
    TraceLine,
    TracedInstruction,
    extract_backtrack_chains,
    parse_line,
    parse_trace,
    parse_verifier_trace,
)

__all__ = [
    "BacktrackChain",
    "BacktrackInfo",
    "BacktrackLine",
    "BacktrackLink",
    "CausalChain",
    "ChainLink",
    "CriticalTransition",
    "ErrorLine",
    "InstructionLine",
    "OtherLine",
    "ParsedTrace",
    "RegisterState",
    "RegisterStateLine",
    "SourceAnnotation",
    "TraceLine",
    "TracedInstruction",
    "_is_pointer_type",
    "extract_backtrack_chains",
    "parse_line",
    "parse_trace",
    "parse_verifier_trace",
]
