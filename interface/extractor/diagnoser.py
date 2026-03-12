"""Proof-aware differential diagnosis built on top of the existing parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .log_parser import ParsedLog, parse_log
from .trace_parser import (
    CriticalTransition,
    ParsedTrace,
    RegisterState,
    TracedInstruction,
    parse_trace,
)

INSTRUCTION_RE = re.compile(r"^\s*(?P<idx>\d+):\s*\([0-9a-fA-F]{2}\)")
REGISTER_RE = re.compile(r"\b([RrWw]\d+)\b")
PROCESSED_INSNS_RE = re.compile(r"processed\s+(?P<count>\d+)\s+insns?", re.IGNORECASE)
DIRECT_ERROR_MARKERS = (
    "invalid access",
    "invalid mem access",
    "invalid bpf_context access",
    "pointer comparison prohibited",
    "failed to find kernel btf type id",
    "number of funcs in func_info doesn't match",
    "invalid name",
    "not allowed",
    "prohibited",
    "must point",
)
GENERIC_ERROR_PREFIXES = (
    "permission denied",
    "prog section ",
    "processed ",
    "libbpf: load bpf program failed",
)

LOOP_LIMIT_MARKERS = ("back-edge", "loop is not bounded")
STATE_EXPLOSION_MARKERS = ("too many states", "too complex", "complexity limit")
ANALYSIS_LIMIT_MARKERS = (
    "stack depth",
    "combined stack size",
    "bpf program is too large",
)
ENV_HELPER_MARKERS = (
    "unknown func",
    "helper call is not allowed",
    "program of this type cannot use helper",
    "attach_btf_id is not a function",
)
ENV_CONTEXT_MARKERS = (
    "attach type",
    "attach to unsupported member",
    "cannot be called from callback",
    "calling kernel function",
    "sleepable",
)
ENV_BTF_MARKERS = (
    "invalid btf",
    "missing btf func_info",
    "unknown type",
    "reference type('unknown ')",
)

TRANSITION_PRIORITY = {
    "RANGE_LOSS": 0,
    "BOUNDS_COLLAPSE": 1,
    "PROVENANCE_LOSS": 2,
    "TYPE_DOWNGRADE": 3,
}
ARITHMETIC_TOKEN_RE = re.compile(r"(\+=|-=|<<=|>>=|&=|\|=|\^=|\*=|/=|\bbe16\b|\bbe32\b)")
STACK_ACCESS_RE = re.compile(r"\(r10\s*[-+]")
BACKWARD_JUMP_RE = re.compile(r"\bgoto pc-\d+\b", re.IGNORECASE)


@dataclass(slots=True)
class Diagnosis:
    error_id: str | None
    taxonomy_class: str | None
    symptom_insn: int | None
    root_cause_insn: int | None
    proof_status: str | None
    loss_context: str | None
    recommended_fix: str | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    critical_transitions: list[CriticalTransition] = field(default_factory=list)
    causal_chain: Any | None = None


@dataclass(slots=True)
class _ProofAssessment:
    status: str | None
    evidence: list[str]


def diagnose(verifier_log: str, catalog_path: str | None = None) -> Diagnosis:
    """Return a single proof-aware diagnosis for a raw verifier log."""

    parsed_log = parse_log(
        verifier_log,
        catalog_path=Path(catalog_path) if catalog_path is not None else None,
    )
    parsed_trace = parse_trace(verifier_log)
    error_line = _preferred_error_line(parsed_log, parsed_trace)

    initial_symptom_insn = _select_symptom_insn(
        verifier_log=verifier_log,
        parsed_trace=parsed_trace,
        error_line=error_line,
    )
    symptom_instruction = _find_instruction(parsed_trace.instructions, initial_symptom_insn)
    registers_of_interest = _collect_registers_of_interest(
        error_line=error_line,
        symptom_instruction=symptom_instruction,
        parsed_trace=parsed_trace,
    )
    relevant_transitions = _select_relevant_transitions(
        parsed_trace=parsed_trace,
        symptom_insn=initial_symptom_insn,
        registers_of_interest=registers_of_interest,
    )
    proof = _assess_proof(
        parsed_trace=parsed_trace,
        symptom_insn=initial_symptom_insn,
        registers_of_interest=registers_of_interest,
        relevant_transitions=relevant_transitions,
    )
    root_transition = _select_root_transition(relevant_transitions)
    loss_context = _infer_loss_context(
        verifier_log=verifier_log,
        parsed_trace=parsed_trace,
        symptom_insn=initial_symptom_insn,
        root_transition=root_transition,
        proof_status=proof.status,
    )
    error_id, taxonomy_class = _classify(
        verifier_log=verifier_log,
        parsed_log=parsed_log,
        error_line=error_line,
        proof_status=proof.status,
        relevant_transitions=relevant_transitions,
        loss_context=loss_context,
    )

    symptom_insn = _refine_symptom_insn(
        verifier_log=verifier_log,
        parsed_trace=parsed_trace,
        current_symptom_insn=initial_symptom_insn,
        taxonomy_class=taxonomy_class,
        loss_context=loss_context,
    )
    root_cause_insn = _select_root_cause_insn(
        parsed_trace=parsed_trace,
        symptom_insn=symptom_insn,
        root_transition=root_transition,
        proof_status=proof.status,
        loss_context=loss_context,
    )
    recommended_fix = _recommend_fix(
        error_id=error_id,
        taxonomy_class=taxonomy_class,
        loss_context=loss_context,
        relevant_transitions=relevant_transitions,
    )
    evidence = _build_evidence(
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        error_line=error_line,
        symptom_insn=symptom_insn,
        root_cause_insn=root_cause_insn,
        proof=proof,
        taxonomy_class=taxonomy_class,
        error_id=error_id,
        loss_context=loss_context,
        relevant_transitions=relevant_transitions,
    )
    confidence = _estimate_confidence(
        error_id=error_id,
        taxonomy_class=taxonomy_class,
        symptom_insn=symptom_insn,
        root_cause_insn=root_cause_insn,
        proof_status=proof.status,
        relevant_transitions=relevant_transitions,
        parsed_log=parsed_log,
    )

    return Diagnosis(
        error_id=error_id,
        taxonomy_class=taxonomy_class,
        symptom_insn=symptom_insn,
        root_cause_insn=root_cause_insn,
        proof_status=proof.status,
        loss_context=loss_context,
        recommended_fix=recommended_fix,
        confidence=confidence,
        evidence=evidence,
        critical_transitions=parsed_trace.critical_transitions,
        causal_chain=parsed_trace.causal_chain,
    )


def _preferred_error_line(parsed_log: ParsedLog, parsed_trace: ParsedTrace) -> str:
    if parsed_trace.error_line and parsed_log.error_line:
        if _error_line_specificity(parsed_log.error_line) >= _error_line_specificity(
            parsed_trace.error_line
        ):
            return parsed_log.error_line
        return parsed_trace.error_line
    if parsed_trace.error_line:
        return parsed_trace.error_line
    return parsed_log.error_line


def _select_symptom_insn(
    verifier_log: str,
    parsed_trace: ParsedTrace,
    error_line: str | None,
) -> int | None:
    if parsed_trace.causal_chain is not None:
        return parsed_trace.causal_chain.error_insn

    raw_lines = [line.rstrip() for line in verifier_log.splitlines()]
    error_index = _find_error_line_index(raw_lines, error_line)
    if error_index is not None:
        for idx in range(error_index - 1, -1, -1):
            match = INSTRUCTION_RE.match(raw_lines[idx].strip())
            if match:
                return int(match.group("idx"))

    if parsed_trace.instructions:
        return parsed_trace.instructions[-1].insn_idx
    return None


def _find_error_line_index(lines: Sequence[str], error_line: str | None) -> int | None:
    if error_line:
        needle = error_line.strip()
        for idx, line in enumerate(lines):
            if line.strip() == needle:
                return idx
        for idx, line in enumerate(lines):
            if needle and needle in line:
                return idx

    for idx, line in enumerate(lines):
        lowered = line.lower()
        if any(
            token in lowered
            for token in (
                "invalid access",
                "outside of the packet",
                "not allowed",
                "too many",
                "too complex",
                "back-edge",
                "loop is not bounded",
                "bpf program is too large",
            )
        ):
            return idx
    return None


def _find_instruction(
    instructions: Sequence[TracedInstruction],
    insn_idx: int | None,
) -> TracedInstruction | None:
    if insn_idx is None:
        return None
    for instruction in instructions:
        if instruction.insn_idx == insn_idx:
            return instruction
    return None


def _collect_registers_of_interest(
    error_line: str | None,
    symptom_instruction: TracedInstruction | None,
    parsed_trace: ParsedTrace,
) -> list[str]:
    registers: list[str] = []

    if parsed_trace.causal_chain is not None:
        registers.append(parsed_trace.causal_chain.error_register)
        registers.extend(link.register for link in parsed_trace.causal_chain.chain)

    if error_line:
        registers.extend(_extract_registers(error_line))

    if symptom_instruction is not None:
        registers.extend(_extract_registers(symptom_instruction.bytecode))
        if symptom_instruction.source_line:
            registers.extend(_extract_registers(symptom_instruction.source_line))

    deduped: list[str] = []
    for register in registers:
        normalized = _normalize_register(register)
        if normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _extract_registers(text: str) -> list[str]:
    return [_normalize_register(match.group(1)) for match in REGISTER_RE.finditer(text)]


def _normalize_register(register: str) -> str:
    lowered = register.lower()
    if lowered.startswith(("r", "w")):
        return f"R{lowered[1:]}"
    return register


def _select_relevant_transitions(
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    registers_of_interest: Sequence[str],
) -> list[CriticalTransition]:
    candidates = [
        transition
        for transition in parsed_trace.critical_transitions
        if symptom_insn is None or transition.insn_idx <= symptom_insn
    ]
    if not candidates:
        return []

    if registers_of_interest:
        register_matches = [
            transition
            for transition in candidates
            if transition.register in registers_of_interest
        ]
        if register_matches:
            candidates = register_matches

    if symptom_insn is not None:
        nearby = [
            transition
            for transition in candidates
            if symptom_insn - 24 <= transition.insn_idx <= symptom_insn
        ]
        if nearby:
            candidates = nearby

    deduped: list[CriticalTransition] = []
    seen: set[tuple[str, int, str]] = set()
    for transition in sorted(candidates, key=lambda item: (item.insn_idx, item.transition_type)):
        key = (transition.transition_type, transition.insn_idx, transition.register)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(transition)
    return deduped


def _assess_proof(
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    registers_of_interest: Sequence[str],
    relevant_transitions: Sequence[CriticalTransition],
) -> _ProofAssessment:
    if relevant_transitions:
        transition = relevant_transitions[0]
        return _ProofAssessment(
            status="established_then_lost",
            evidence=[
                (
                    "Proof existed earlier and was lost at "
                    f"insn {transition.insn_idx} ({transition.transition_type})."
                )
            ],
        )

    proof_signals = _collect_proof_signals(
        parsed_trace=parsed_trace,
        symptom_insn=symptom_insn,
        registers_of_interest=registers_of_interest,
    )
    if proof_signals:
        return _ProofAssessment(
            status="established_but_insufficient",
            evidence=proof_signals[:2],
        )

    if parsed_trace.instructions:
        return _ProofAssessment(
            status="never_established",
            evidence=["No earlier dominating proof-establishing branch or narrowing was found."],
        )
    return _ProofAssessment(status=None, evidence=[])


def _collect_proof_signals(
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    registers_of_interest: Sequence[str],
) -> list[str]:
    signals: list[str] = []
    for instruction in parsed_trace.instructions:
        if symptom_insn is not None and instruction.insn_idx >= symptom_insn:
            continue
        signal = _instruction_proof_signal(instruction, registers_of_interest)
        if signal and signal not in signals:
            signals.append(signal)
    return signals


def _instruction_proof_signal(
    instruction: TracedInstruction,
    registers_of_interest: Sequence[str],
) -> str | None:
    registers = list(registers_of_interest) or _extract_registers(instruction.bytecode)
    range_narrowed = False
    for register in registers:
        before = instruction.pre_state.get(register)
        after = instruction.post_state.get(register)
        if before is None or after is None:
            continue
        if _state_narrowed(before, after):
            range_narrowed = True
            break

    source_hint = (
        instruction.source_line.lower()
        if instruction.source_line is not None
        else ""
    )
    branch_hint = instruction.bytecode.startswith("if ")
    comparison_hint = any(token in source_hint for token in ("data_end", "null", "<", ">", "==", "!="))

    if branch_hint and (comparison_hint or range_narrowed):
        return f"Branch at insn {instruction.insn_idx} appears to establish a proof: {instruction.bytecode}"
    if range_narrowed:
        return f"Register state narrowed at insn {instruction.insn_idx}: {instruction.bytecode}"
    return None


def _state_narrowed(before: RegisterState, after: RegisterState) -> bool:
    if after.range is not None and (before.range or 0) < after.range:
        return True
    if before.umax is not None and after.umax is not None and after.umax < before.umax:
        return True
    if before.umin is not None and after.umin is not None and after.umin > before.umin:
        return True
    return False


def _select_root_transition(
    relevant_transitions: Sequence[CriticalTransition],
) -> CriticalTransition | None:
    if not relevant_transitions:
        return None
    return sorted(
        relevant_transitions,
        key=lambda item: (TRANSITION_PRIORITY.get(item.transition_type, 99), item.insn_idx),
    )[0]


def _infer_loss_context(
    verifier_log: str,
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    root_transition: CriticalTransition | None,
    proof_status: str | None,
) -> str | None:
    lowered = verifier_log.lower()
    processed = _processed_insn_count(verifier_log)
    if proof_status != "established_then_lost" and (
        any(marker in lowered for marker in LOOP_LIMIT_MARKERS)
        or (
            processed is not None
            and processed > 100000
            and (
                _anchor_has_backward_jump(parsed_trace, symptom_insn, root_transition)
                or _has_backward_jump(parsed_trace)
            )
        )
    ):
        return "loop"

    anchor_insn = root_transition.insn_idx if root_transition is not None else symptom_insn
    window = _instruction_window(parsed_trace.instructions, anchor_insn)
    window_text = " ".join(
        text
        for instruction in window
        for text in (instruction.bytecode, instruction.source_line or "")
    )
    if proof_status == "established_then_lost" and "call " in window_text:
        return "function_boundary"
    if proof_status == "established_then_lost" and STACK_ACCESS_RE.search(window_text):
        return "register_spill"
    if proof_status in {"established_then_lost", "established_but_insufficient"} and ARITHMETIC_TOKEN_RE.search(window_text):
        return "arithmetic"
    if proof_status in {"established_but_insufficient", "established_then_lost"} and any(
        instruction.bytecode.startswith("if ") for instruction in window
    ):
        return "branch"
    return None


def _instruction_window(
    instructions: Sequence[TracedInstruction],
    anchor_insn: int | None,
) -> list[TracedInstruction]:
    if anchor_insn is None:
        return []

    by_index = {instruction.insn_idx: instruction for instruction in instructions}
    window: list[TracedInstruction] = []
    for insn_idx in (anchor_insn - 1, anchor_insn, anchor_insn + 1):
        instruction = by_index.get(insn_idx)
        if instruction is not None:
            window.append(instruction)
    return window


def _anchor_has_backward_jump(
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    root_transition: CriticalTransition | None,
) -> bool:
    anchor_insn = root_transition.insn_idx if root_transition is not None else symptom_insn
    return any(
        BACKWARD_JUMP_RE.search(instruction.bytecode)
        for instruction in _instruction_window(parsed_trace.instructions, anchor_insn)
    )


def _has_backward_jump(parsed_trace: ParsedTrace) -> bool:
    return any(
        BACKWARD_JUMP_RE.search(instruction.bytecode)
        for instruction in parsed_trace.instructions
    )


def _classify(
    verifier_log: str,
    parsed_log: ParsedLog,
    error_line: str,
    proof_status: str | None,
    relevant_transitions: Sequence[CriticalTransition],
    loss_context: str | None,
) -> tuple[str | None, str | None]:
    lowered = verifier_log.lower()
    error_lowered = error_line.lower() if error_line else ""
    parsed_error_lowered = parsed_log.error_line.lower() if parsed_log.error_line else ""
    error_candidates = [text for text in (error_lowered, parsed_error_lowered) if text]

    # --- Priority 1: catalog-based classification (most precise) ---
    # The catalog has per-error-pattern matching that is more specific than
    # broad keyword scans.  Trust it when available.
    if parsed_log.error_id and parsed_log.taxonomy_class:
        # The catalog already classified this case.  Only override it below
        # if trace analysis shows strong proof-loss evidence.
        catalog_id = parsed_log.error_id
        catalog_class = parsed_log.taxonomy_class

        # Override: proof was established then lost → lowering artifact,
        # regardless of what the catalog said (catalog only sees the error
        # line, not the proof lifecycle).
        if proof_status == "established_then_lost" and catalog_class == "source_bug":
            transition_types = {t.transition_type for t in relevant_transitions}
            if (
                {"PROVENANCE_LOSS", "TYPE_DOWNGRADE"} & transition_types
                and loss_context in {"function_boundary", "register_spill"}
            ):
                return "OBLIGE-E006", "lowering_artifact"
            return "OBLIGE-E005", "lowering_artifact"

        return catalog_id, catalog_class

    # --- Priority 2: verifier_limit (unambiguous structural signals) ---
    processed = _processed_insn_count(verifier_log)
    if any(marker in lowered for marker in LOOP_LIMIT_MARKERS):
        return "OBLIGE-E008", "verifier_limit"
    if any(marker in lowered for marker in STATE_EXPLOSION_MARKERS):
        return "OBLIGE-E007", "verifier_limit"
    if any(marker in lowered for marker in ANALYSIS_LIMIT_MARKERS) or (
        processed is not None and processed > 100000
    ):
        return "OBLIGE-E018", "verifier_limit"

    # --- Priority 3: env_mismatch (check ERROR LINE, not full log) ---
    # Only match env markers against the error line to avoid false positives
    # from BTF-like text appearing in register-state dumps of source_bug cases.
    if any(marker in error_lowered for marker in ENV_HELPER_MARKERS):
        return "OBLIGE-E009", "env_mismatch"
    if any(marker in error_lowered for marker in ENV_CONTEXT_MARKERS):
        return "OBLIGE-E016", "env_mismatch"
    if any(marker in error_lowered for marker in ENV_BTF_MARKERS):
        return "OBLIGE-E021", "env_mismatch"
    if "only read from bpf_array is supported" in error_lowered:
        return "OBLIGE-E022", "env_mismatch"
    if any("failed to find kernel btf type id" in text for text in error_candidates):
        return "OBLIGE-E021", "env_mismatch"
    if any("invalid bpf_context access" in text for text in error_candidates):
        return "OBLIGE-E023", "source_bug"
    if any("pointer comparison prohibited" in text for text in error_candidates):
        return "OBLIGE-E023", "source_bug"

    # --- Priority 4: proof-loss → lowering artifact ---
    if proof_status == "established_then_lost":
        transition_types = {t.transition_type for t in relevant_transitions}
        if (
            {"PROVENANCE_LOSS", "TYPE_DOWNGRADE"} & transition_types
            and loss_context in {"function_boundary", "register_spill"}
        ):
            return "OBLIGE-E006", "lowering_artifact"
        if "expected pointer type, got scalar" in lowered:
            return "OBLIGE-E006", "lowering_artifact"
        return "OBLIGE-E005", "lowering_artifact"

    # --- Priority 5: fallback from error line ---
    if "invalid access to packet" in error_lowered:
        return "OBLIGE-E001", "source_bug"
    return None, None


def _processed_insn_count(verifier_log: str) -> int | None:
    matches = PROCESSED_INSNS_RE.findall(verifier_log)
    if not matches:
        return None
    return max(int(match) for match in matches)


def _refine_symptom_insn(
    verifier_log: str,
    parsed_trace: ParsedTrace,
    current_symptom_insn: int | None,
    taxonomy_class: str | None,
    loss_context: str | None,
) -> int | None:
    if taxonomy_class != "verifier_limit" or loss_context != "loop":
        return current_symptom_insn

    for instruction in parsed_trace.instructions:
        if BACKWARD_JUMP_RE.search(instruction.bytecode):
            return instruction.insn_idx
    return current_symptom_insn


def _select_root_cause_insn(
    parsed_trace: ParsedTrace,
    symptom_insn: int | None,
    root_transition: CriticalTransition | None,
    proof_status: str | None,
    loss_context: str | None,
) -> int | None:
    if root_transition is not None:
        return root_transition.insn_idx

    if proof_status == "established_but_insufficient" and parsed_trace.causal_chain is not None:
        for link in parsed_trace.causal_chain.chain:
            if link.role != "error_site":
                return link.insn_idx

    if loss_context == "loop":
        for instruction in parsed_trace.instructions:
            if BACKWARD_JUMP_RE.search(instruction.bytecode):
                return instruction.insn_idx

    return symptom_insn


def _recommend_fix(
    error_id: str | None,
    taxonomy_class: str | None,
    loss_context: str | None,
    relevant_transitions: Sequence[CriticalTransition],
) -> str | None:
    if taxonomy_class == "source_bug" and error_id == "OBLIGE-E001":
        return "Add bounds check: if (data + offset + size <= data_end)"

    if taxonomy_class == "lowering_artifact":
        transition_types = {transition.transition_type for transition in relevant_transitions}
        if "PROVENANCE_LOSS" in transition_types and loss_context == "function_boundary":
            return "Add __always_inline to the helper function"
        if loss_context == "register_spill":
            return "Keep pointer and offset in separate registers and avoid spill/reload across stack slots"
        if loss_context == "arithmetic" or "BOUNDS_COLLAPSE" in transition_types:
            return "Add an explicit unsigned clamp and keep the offset calculation in a separate verified register"
        return "Restructure lowering so the verifier can preserve the earlier proof across the transformed code"

    if taxonomy_class == "verifier_limit":
        if error_id == "OBLIGE-E008":
            return "Strengthen the loop bound or fully unroll the loop"
        return "Split the program with tail calls or reduce branching and loop work"

    if taxonomy_class == "env_mismatch":
        if error_id == "OBLIGE-E021":
            return "Regenerate BTF artifacts and ensure they match the running kernel"
        return "Check that the target kernel and program type support the helper, kfunc, or attach type"

    if taxonomy_class == "verifier_bug":
        return "Minimize the reproducer and bisect the verifier behavior across kernel versions"

    return None


def _build_evidence(
    parsed_log: ParsedLog,
    parsed_trace: ParsedTrace,
    error_line: str,
    symptom_insn: int | None,
    root_cause_insn: int | None,
    proof: _ProofAssessment,
    taxonomy_class: str | None,
    error_id: str | None,
    loss_context: str | None,
    relevant_transitions: Sequence[CriticalTransition],
) -> list[str]:
    evidence: list[str] = []

    if error_line:
        evidence.append(f"Verifier symptom: {error_line}")

    if parsed_log.error_id:
        evidence.append(
            f"Catalog seed: {parsed_log.error_id} ({parsed_log.taxonomy_class or 'unknown'})"
        )

    symptom_instruction = _find_instruction(parsed_trace.instructions, symptom_insn)
    if symptom_instruction is not None:
        evidence.append(
            f"Symptom insn {symptom_instruction.insn_idx}: {symptom_instruction.bytecode}"
        )

    if proof.evidence:
        evidence.extend(proof.evidence[:2])

    if root_cause_insn is not None and root_cause_insn != symptom_insn:
        evidence.append(f"Root cause localized to insn {root_cause_insn}, earlier than the reject site.")

    for transition in relevant_transitions[:2]:
        evidence.append(transition.description)

    if loss_context:
        evidence.append(f"Loss context inferred as {loss_context}.")

    if taxonomy_class and error_id and (
        taxonomy_class != parsed_log.taxonomy_class or error_id != parsed_log.error_id
    ):
        evidence.append(f"Final diagnosis overrides the catalog seed to {error_id} ({taxonomy_class}).")

    for line in parsed_log.evidence[:2]:
        if line not in evidence:
            evidence.append(line)

    deduped: list[str] = []
    for line in evidence:
        if line not in deduped:
            deduped.append(line)
    return deduped[:8]


def _estimate_confidence(
    error_id: str | None,
    taxonomy_class: str | None,
    symptom_insn: int | None,
    root_cause_insn: int | None,
    proof_status: str | None,
    relevant_transitions: Sequence[CriticalTransition],
    parsed_log: ParsedLog,
) -> float:
    score = 0.35
    if error_id is not None:
        score += 0.18
    if taxonomy_class is not None:
        score += 0.1
    if symptom_insn is not None:
        score += 0.08
    if root_cause_insn is not None:
        score += 0.05
    if parsed_log.error_line:
        score += 0.05
    if proof_status is not None:
        score += 0.08
    if relevant_transitions:
        score += 0.14
    if proof_status == "established_then_lost":
        score += 0.07
    if taxonomy_class in {"verifier_limit", "env_mismatch"}:
        score += 0.07
    return min(round(score, 2), 0.98)


def _error_line_specificity(line: str | None) -> int:
    if not line:
        return -10

    lowered = line.lower()
    score = 0
    if any(marker in lowered for marker in DIRECT_ERROR_MARKERS):
        score += 6
    if any(token in lowered for token in ("off=", "size=", "arg#", "r0", "r1", "r2", "r3")):
        score += 1
    if lowered.startswith(GENERIC_ERROR_PREFIXES):
        score -= 5
    return score
