"""Compatibility surface for the proof engine implementation."""

from __future__ import annotations

from .backward_slicing import backward_obligation_slice, backward_slice
from .ir_builder import InstructionNode, TraceIR, ValueVersion, build_trace_ir
from .obligation_inference import analyze_proof, infer_formal_obligation, infer_obligation
from .predicate_tracking import (
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
    "CompositeObligation",
    "InstructionNode",
    "OBLIGATION_FAMILIES",
    "Obligation",
    "ObligationSpec",
    "PredicateAtom",
    "PredicateEval",
    "ProofAnalysisResult",
    "SliceEdge",
    "TraceIR",
    "TransitionWitness",
    "ValueVersion",
    "analyze_proof",
    "backward_obligation_slice",
    "backward_slice",
    "build_trace_ir",
    "evaluate_obligation",
    "find_loss_transition",
    "infer_formal_obligation",
    "infer_obligation",
    "track_composite",
]
