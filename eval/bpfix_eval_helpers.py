"""Reusable BPFix-side helpers shared by evaluation scripts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interface.extractor.log_parser import ParsedLog, parse_log
from interface.extractor.trace_parser import CriticalTransition, ParsedTrace, parse_trace


@dataclass(slots=True)
class BPFixResult:
    error_id: str | None
    taxonomy_class: str | None
    error_line: str | None
    source_mapping: str | None
    has_source_mapping: bool
    critical_transition: str | None
    critical_transition_insn: int | None
    causal_chain_summary: str | None
    root_cause_insn: int | None
    error_insn: int | None
    root_cause_found: bool
    actionable: bool
    total_instructions: int
    has_btf_annotations: bool
    has_backtracking: bool


def select_error_instruction(trace: ParsedTrace) -> Any | None:
    if trace.error_line:
        for instruction in reversed(trace.instructions):
            if instruction.error_text and trace.error_line in instruction.error_text:
                return instruction
    for instruction in reversed(trace.instructions):
        if instruction.is_error:
            return instruction
    return None


def select_transition(trace: ParsedTrace) -> CriticalTransition | None:
    if not trace.critical_transitions:
        return None

    error_instruction = select_error_instruction(trace)
    error_insn = error_instruction.insn_idx if error_instruction is not None else None
    preferred_registers: set[str] = set()
    if trace.causal_chain is not None:
        preferred_registers.add(trace.causal_chain.error_register)
        for link in trace.causal_chain.chain[:2]:
            preferred_registers.add(link.register)

    priority = {
        "RANGE_LOSS": 4,
        "BOUNDS_COLLAPSE": 3,
        "TYPE_DOWNGRADE": 2,
        "PROVENANCE_LOSS": 1,
    }

    def sort_key(item: CriticalTransition) -> tuple[int, int, int]:
        reg_score = 1 if item.register in preferred_registers else 0
        type_score = priority.get(item.transition_type, 0)
        if error_insn is None:
            distance_score = -abs(item.insn_idx)
        else:
            distance_score = -abs(error_insn - item.insn_idx)
        return (reg_score, type_score, distance_score)

    return max(trace.critical_transitions, key=sort_key)


def source_mapping_for(trace: ParsedTrace, preferred_insns: list[int | None]) -> str | None:
    for insn_idx in preferred_insns:
        if insn_idx is None:
            continue
        for instruction in reversed(trace.instructions):
            if instruction.insn_idx == insn_idx and instruction.source_line:
                return instruction.source_line
    for instruction in reversed(trace.instructions):
        if instruction.source_line:
            return instruction.source_line
    return None


def summarize_causal_chain(trace: ParsedTrace) -> tuple[str | None, int | None]:
    if trace.causal_chain is None:
        return None, None

    links = trace.causal_chain.chain
    root = next((link for link in links if link.role == "root_cause"), None)
    error_site = next((link for link in reversed(links) if link.role == "error_site"), None)
    propagation = [link for link in links if link.role == "propagation"]

    parts: list[str] = []
    if root is not None:
        parts.append(f"insn {root.insn_idx} ({root.register})")
    if propagation:
        props = ", ".join(f"insn {link.insn_idx} ({link.register})" for link in propagation[:2])
        parts.append(f"via {props}")
    if error_site is not None:
        parts.append(f"fails at insn {error_site.insn_idx} ({error_site.register})")
    return " -> ".join(parts) if parts else None, (root.insn_idx if root is not None else None)


def run_bpfix(log_text: str, catalog_path: Path) -> BPFixResult:
    parsed_log: ParsedLog = parse_log(log_text, catalog_path=catalog_path)
    trace: ParsedTrace = parse_trace(log_text)
    error_instruction = select_error_instruction(trace)
    transition = select_transition(trace)
    causal_chain_summary, root_cause_insn = summarize_causal_chain(trace)
    source_mapping = source_mapping_for(
        trace,
        [
            root_cause_insn,
            transition.insn_idx if transition is not None else None,
            error_instruction.insn_idx if error_instruction is not None else None,
        ],
    )
    error_insn = error_instruction.insn_idx if error_instruction is not None else None
    root_cause_found = False
    if root_cause_insn is not None and error_insn is not None and root_cause_insn != error_insn:
        root_cause_found = True
    elif transition is not None and error_insn is not None and transition.insn_idx != error_insn:
        root_cause_found = True
    elif transition is not None and error_insn is None:
        root_cause_found = True

    actionable = bool(
        parsed_log.error_id
        and (
            transition is not None
            or trace.causal_chain is not None
            or source_mapping is not None
        )
    )

    return BPFixResult(
        error_id=parsed_log.error_id,
        taxonomy_class=parsed_log.taxonomy_class,
        error_line=trace.error_line or parsed_log.error_line,
        source_mapping=source_mapping,
        has_source_mapping=source_mapping is not None,
        critical_transition=transition.description if transition is not None else None,
        critical_transition_insn=transition.insn_idx if transition is not None else None,
        causal_chain_summary=causal_chain_summary,
        root_cause_insn=root_cause_insn,
        error_insn=error_insn,
        root_cause_found=root_cause_found,
        actionable=actionable,
        total_instructions=trace.total_instructions,
        has_btf_annotations=trace.has_btf_annotations,
        has_backtracking=trace.has_backtracking,
    )
