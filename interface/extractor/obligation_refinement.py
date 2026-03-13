"""Obligation refinement helpers for Rust diagnostics."""

from __future__ import annotations

from typing import Any

from .rust_diagnostic_parts._impl import (
    _engine_obligation_to_proof_obligation,
    _infer_obligation,
    _infer_obligation_from_engine_result,
    _infer_with_proof_analysis_result,
    _obligation_type,
    _refine_obligation_with_specific_reject,
)


def engine_obligation_to_proof_obligation(result: Any) -> Any:
    return _engine_obligation_to_proof_obligation(result)


def infer_catalog_obligation(parsed_log: Any, diagnosis: Any) -> Any:
    return _infer_obligation(parsed_log, diagnosis)


def infer_obligation_from_engine_result(
    parsed_log: Any,
    parsed_trace: Any,
    diagnosis: Any,
) -> Any:
    return _infer_obligation_from_engine_result(parsed_log, parsed_trace, diagnosis)


def infer_with_proof_analysis_result(
    parsed_log: Any,
    parsed_trace: Any,
    diagnosis: Any,
    *,
    find_instruction: Any | None = None,
    register_from_error: Any | None = None,
) -> Any:
    del find_instruction, register_from_error
    return _infer_with_proof_analysis_result(parsed_log, parsed_trace, diagnosis)


def obligation_type(obligation: Any) -> str:
    return _obligation_type(obligation)


def refine_obligation_with_specific_reject(obligation: Any, specific_reject: Any) -> Any:
    return _refine_obligation_with_specific_reject(obligation, specific_reject)

__all__ = [
    "engine_obligation_to_proof_obligation",
    "infer_catalog_obligation",
    "infer_obligation_from_engine_result",
    "infer_with_proof_analysis_result",
    "obligation_type",
    "refine_obligation_with_specific_reject",
]
