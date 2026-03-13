"""Internal proof-engine submodules."""

from __future__ import annotations

from .backward_slicing import SliceEdge, backward_obligation_slice, backward_slice
from .ir_builder import InstructionNode, TraceIR, ValueVersion, build_trace_ir
from .obligation_inference import CompositeObligation, OBLIGATION_FAMILIES, Obligation, ObligationSpec, PredicateAtom, infer_formal_obligation, infer_obligation, track_composite
from .predicate_tracking import PredicateEval, ProofAnalysisResult, TransitionWitness, analyze_proof, evaluate_obligation, find_loss_transition

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
