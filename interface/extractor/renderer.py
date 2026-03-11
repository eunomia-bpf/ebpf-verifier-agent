"""Render correlated proof spans as Rust-style text and structured JSON."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .source_correlator import ProofObligation, SourceSpan


@dataclass(slots=True)
class DiagnosticOutput:
    text: str
    json_data: dict[str, Any]


def render_diagnostic(
    error_id: str,
    taxonomy_class: str,
    proof_status: str,
    spans: list[SourceSpan],
    obligation: ProofObligation | None,
    note: str | None,
    help_text: str | None,
) -> DiagnosticOutput:
    """Render a proof-aware diagnostic in text and JSON forms."""

    ordered_spans = sorted(spans, key=lambda span: (span.insn_range[0], span.insn_range[1]))
    headline = _headline_summary(taxonomy_class, proof_status, obligation)
    text_lines = [f"error[{error_id}]: {taxonomy_class} — {headline}"]

    if ordered_spans:
        header = _header_label(ordered_spans)
        width = max(len(str(_display_line(span))) for span in ordered_spans)
        text_lines.extend(
            [
                f"  ┌─ {header}",
                "  │",
            ]
        )
        for span in ordered_spans:
            line_label = str(_display_line(span)).rjust(width)
            text_lines.append(f"{line_label} │     {span.source_text}")
            text_lines.append(
                f"{' ' * width} │     {_underline(span.source_text)} {_role_label(span)}"
            )
            if span.state_change:
                text_lines.append(
                    f"{' ' * width} │     {_display_state_change(span.state_change)}"
                )
            text_lines.append(f"{' ' * width} │")
    else:
        text_lines.append("  = note: no source-correlated spans available")

    if note:
        text_lines.append(f"  = note: {note}")
    if help_text:
        text_lines.append(f"  = help: {help_text}")

    json_data: dict[str, Any] = {
        "error_id": error_id,
        "taxonomy_class": taxonomy_class,
        "proof_status": proof_status,
        "spans": [
            {
                "role": span.role,
                "source": {"file": span.file, "line": span.line},
                "insn_idx": span.insn_range[0],
                "source_text": span.source_text,
                "state_change": _display_state_change(span.state_change)
                if span.state_change
                else None,
                "reason": span.reason,
            }
            for span in ordered_spans
        ],
        "obligation": (
            {
                "type": _obligation_type(obligation),
                "required": _obligation_required(obligation),
            }
            if obligation is not None
            else None
        ),
        "note": note,
        "help": help_text,
    }

    return DiagnosticOutput(text="\n".join(text_lines), json_data=json_data)


def _headline_summary(
    taxonomy_class: str,
    proof_status: str,
    obligation: ProofObligation | None,
) -> str:
    if taxonomy_class == "lowering_artifact" and proof_status == "established_then_lost":
        if obligation and _obligation_type(obligation) == "packet_access":
            return "packet access with lost proof"
        return "proof established, then lost before rejection"
    if taxonomy_class == "source_bug" and proof_status == "never_established":
        if obligation and _obligation_type(obligation) == "non_null_dereference":
            return "nullable pointer dereferenced without refinement"
        return "required proof never established"
    if proof_status == "established_but_insufficient":
        return "proof exists but is insufficient at the reject site"
    if proof_status == "unknown":
        return "verifier rejection"
    return proof_status.replace("_", " ")


def _header_label(spans: list[SourceSpan]) -> str:
    file_names = [span.file for span in spans if span.file]
    if file_names:
        return file_names[0]
    if any(_looks_like_source(span.source_text) for span in spans):
        return "<source>"
    return "<bytecode>"


def _looks_like_source(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("r") and " " in stripped and "+=" in stripped:
        return False
    return any(token in stripped for token in (";", "{", "}", "->", "__", "if (", "for("))


def _display_line(span: SourceSpan) -> int:
    if span.line is not None:
        return span.line
    return span.insn_range[0]


def _underline(source_text: str) -> str:
    visible = source_text.lstrip()
    return "─" * max(6, min(len(visible), 36))


def _role_label(span: SourceSpan) -> str:
    labels = {
        "proof_established": "proof established",
        "proof_propagated": "proof propagated",
        "proof_lost": "proof lost",
        "rejected": "rejected",
    }
    label = labels.get(span.role, span.role.replace("_", " "))
    if span.role == "proof_lost" and span.reason:
        return f"{label}: {span.reason}"
    return label


def _display_state_change(state_change: str) -> str:
    return state_change.replace(" -> ", " → ")


def _obligation_type(obligation: ProofObligation) -> str:
    return getattr(obligation, "type", None) or getattr(obligation, "obligation_type", "unknown")


def _obligation_required(obligation: ProofObligation) -> str:
    return getattr(obligation, "required", None) or getattr(
        obligation,
        "required_condition",
        "",
    )
