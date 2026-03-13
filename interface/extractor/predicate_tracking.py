"""Predicate evaluation helpers for the proof engine."""

from __future__ import annotations

from .obligation_inference import (
    OBLIGATION_FAMILIES,
    CompositeObligation,
    Obligation,
    ObligationSpec,
    PredicateAtom,
    PredicateEval,
    ProofAnalysisResult,
    SliceEdge,
    TransitionWitness,
    evaluate_obligation,
    find_loss_transition,
    track_composite,
)

__all__ = [
    "OBLIGATION_FAMILIES",
    "CompositeObligation",
    "Obligation",
    "ObligationSpec",
    "PredicateAtom",
    "PredicateEval",
    "ProofAnalysisResult",
    "SliceEdge",
    "TransitionWitness",
    "evaluate_obligation",
    "find_loss_transition",
    "track_composite",
]
