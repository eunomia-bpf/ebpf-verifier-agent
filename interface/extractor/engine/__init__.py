"""Proof engine for eBPF verifier trace analysis.

Public API:
- TraceMonitor: evaluates predicates over instruction traces
- MonitorResult: result of trace monitoring
- Predicate (and subclasses): declarative safety properties
- RepairSynthesizer: template-based repair synthesis
- RepairSuggestion: a concrete repair suggestion
- infer_predicate: map error messages to predicates
- infer_predicate_from_trace: higher-level inference
"""

from __future__ import annotations

from .ebpf_predicates import infer_predicate, infer_predicate_from_trace
from .monitor import MonitorResult, TraceMonitor
from .predicate import (
    CompositeAllPredicate,
    IntervalContainment,
    NullCheckPredicate,
    PacketAccessPredicate,
    Predicate,
    ScalarBound,
    TypeMembership,
)
from .synthesizer import RepairSuggestion, RepairSynthesizer
from .transition_analyzer import (
    TransitionAnalyzer,
    TransitionChain,
    TransitionDetail,
    TransitionEffect,
    analyze_transitions,
)

__all__ = [
    # Monitor
    "TraceMonitor",
    "MonitorResult",
    # Predicates
    "Predicate",
    "IntervalContainment",
    "TypeMembership",
    "ScalarBound",
    "NullCheckPredicate",
    "PacketAccessPredicate",
    "CompositeAllPredicate",
    # Predicate inference
    "infer_predicate",
    "infer_predicate_from_trace",
    # Synthesis
    "RepairSynthesizer",
    "RepairSuggestion",
    # Transition analysis
    "TransitionAnalyzer",
    "TransitionChain",
    "TransitionDetail",
    "TransitionEffect",
    "analyze_transitions",
]
