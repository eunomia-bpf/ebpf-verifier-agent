"""Proof engine for eBPF verifier trace analysis.

Public API:
- TraceMonitor: evaluates predicates over instruction traces
- MonitorResult: result of trace monitoring
- Predicate (and subclasses): declarative safety properties
- RepairSynthesizer: template-based repair synthesis
- RepairSuggestion: a concrete repair suggestion
- OpcodeConditionPredicate: opcode-driven safety condition predicate
- SafetyCondition / SafetyDomain: ISA-derived safety condition structures
- infer_conditions_from_error_insn: opcode-driven condition inference
- find_violated_condition: identify violated condition at error instruction
"""

from __future__ import annotations

from .monitor import MonitorResult, TraceMonitor
from .opcode_safety import (
    OpcodeClass,
    OpcodeConditionPredicate,
    OpcodeInfo,
    SafetyCondition,
    SafetyDomain,
    decode_opcode,
    derive_safety_conditions,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
)
from .predicate import (
    ClassificationOnlyPredicate,
    CompositeAllPredicate,
    IntervalContainment,
    NullCheckPredicate,
    PacketAccessPredicate,
    Predicate,
    ScalarBound,
    TypeMembership,
)
from .synthesizer import RepairSuggestion, RepairSynthesizer
from .control_dep import (
    ControlDep,
    compute_control_dependence,
    compute_control_dependence_from_trace,
    controlling_branches,
    control_dependent_instructions,
)
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
    # Opcode-driven safety analysis (primary path)
    "OpcodeClass",
    "OpcodeConditionPredicate",
    "OpcodeInfo",
    "SafetyCondition",
    "SafetyDomain",
    "decode_opcode",
    "derive_safety_conditions",
    "evaluate_condition",
    "find_violated_condition",
    "infer_conditions_from_error_insn",
    # Predicates (kept for backward compatibility and structural errors)
    "Predicate",
    "IntervalContainment",
    "TypeMembership",
    "ScalarBound",
    "NullCheckPredicate",
    "PacketAccessPredicate",
    "CompositeAllPredicate",
    "ClassificationOnlyPredicate",
    # Synthesis
    "RepairSynthesizer",
    "RepairSuggestion",
    # Control dependence
    "ControlDep",
    "compute_control_dependence",
    "compute_control_dependence_from_trace",
    "controlling_branches",
    "control_dependent_instructions",
    # Transition analysis
    "TransitionAnalyzer",
    "TransitionChain",
    "TransitionDetail",
    "TransitionEffect",
    "analyze_transitions",
]
