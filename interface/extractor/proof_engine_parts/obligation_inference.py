"""Obligation inference entry points for the proof engine."""

from __future__ import annotations

from ._impl import CompositeObligation, OBLIGATION_FAMILIES, Obligation, ObligationSpec, PredicateAtom, infer_formal_obligation, infer_obligation, track_composite

__all__ = [
    "CompositeObligation",
    "OBLIGATION_FAMILIES",
    "Obligation",
    "ObligationSpec",
    "PredicateAtom",
    "infer_formal_obligation",
    "infer_obligation",
    "track_composite",
]
