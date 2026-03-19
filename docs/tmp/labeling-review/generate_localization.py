#!/usr/bin/env python3
from __future__ import annotations

import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.pipeline import generate_diagnostic
from interface.extractor.trace_parser import ParsedTrace, TracedInstruction, parse_trace


DATE = "2026-03-19"
CASE_LIST_PATH = ROOT / "docs/tmp/labeling_case_ids.txt"
GROUND_TRUTH_PATH = ROOT / "docs/tmp/labeling-review/ground_truth_v3.yaml"
OUTPUT_YAML_PATH = ROOT / "docs/tmp/labeling-review/localization_annotations.yaml"
OUTPUT_MD_PATH = ROOT / "docs/tmp/labeling-review/localization_summary.md"
CASE_DIRS = (
    ROOT / "case_study/cases/kernel_selftests",
    ROOT / "case_study/cases/stackoverflow",
    ROOT / "case_study/cases/github_issues",
)

INSTRUCTION_RE = re.compile(r"^\s*\d+:\s*\([0-9a-fA-F]{2}\)")
STATE_RE = re.compile(r"\b(?:[Rr]\d+|fp-?\d+)=")
SOURCE_ANNOTATION_RE = re.compile(r"^\s*;")
SOURCE_LOC_RE = re.compile(r"\s*@\s*(?P<file>[^:@]+):(?P<line>\d+)\s*$")


@dataclass(frozen=True)
class CaseOverride:
    root_cause_insn_idx: int | None = None
    rejected_insn_idx: int | None = None
    confidence: str = "medium"
    note: str = ""


LA_OVERRIDES: dict[str, CaseOverride] = {
    "stackoverflow-53136145": CaseOverride(
        root_cause_insn_idx=105,
        confidence="low",
        note=(
            "The merged UDP pointer is checked through a derived alias (`r4`) but the "
            "dereference still uses the original merged pointer (`r0`), so verifier "
            "provenance is lost before the final load."
        ),
    ),
    "stackoverflow-60506220": CaseOverride(
        root_cause_insn_idx=4,
        confidence="medium",
        note=(
            "The 32-bit lowering reconstructs a packet-end-related scalar with `r2 |= r1`; "
            "that same instruction is where the verifier rejects the verifier-hostile form."
        ),
    ),
    "stackoverflow-70729664": CaseOverride(
        root_cause_insn_idx=2940,
        confidence="high",
        note=(
            "Packet-range/provenance collapses at the loop-side packet check before the "
            "later byte load at insn 2948."
        ),
    ),
    "stackoverflow-70750259": CaseOverride(
        root_cause_insn_idx=20,
        confidence="high",
        note=(
            "The TLS extension length loses its clean unsigned interpretation while being "
            "assembled from bytes, before the later packet-pointer addition."
        ),
    ),
    "stackoverflow-70760516": CaseOverride(
        root_cause_insn_idx=31,
        confidence="medium",
        note=(
            "The running extension cursor loses packet-range precision at the loop latch; "
            "its instruction number is later because it is the back-edge for the next iteration."
        ),
    ),
    "stackoverflow-70873332": CaseOverride(
        root_cause_insn_idx=11,
        confidence="medium",
        note=(
            "The map-loaded packet offset is folded into the packet base at insn 11, and the "
            "verifier no longer carries the earlier bound to the later byte read."
        ),
    ),
    "stackoverflow-71522674": CaseOverride(
        root_cause_insn_idx=47,
        confidence="low",
        note=(
            "The log only exposes the final `bpf_csum_diff()` rejection; the ground-truth "
            "label indicates a variable-length proof that was not preserved to the helper pair."
        ),
    ),
    "stackoverflow-72074115": CaseOverride(
        root_cause_insn_idx=234,
        confidence="medium",
        note=(
            "The table base/index are recombined one instruction before the failing read, "
            "which is where the verifier-visible index proof is lost."
        ),
    ),
    "stackoverflow-72560675": CaseOverride(
        root_cause_insn_idx=24,
        confidence="medium",
        note=(
            "The older verifier only retains the copy-size clamp when it is restated "
            "explicitly; the helper call fails later after that bound is effectively lost."
        ),
    ),
    "stackoverflow-72575736": CaseOverride(
        root_cause_insn_idx=28,
        confidence="high",
        note=(
            "Older-kernel scalar tracking loses the packet-range proof at the range/latch "
            "check before the later byte load."
        ),
    ),
    "stackoverflow-73088287": CaseOverride(
        root_cause_insn_idx=69,
        confidence="low",
        note=(
            "A masked payload offset is added into a different register than the final "
            "packet load uses; only a short log snippet is available."
        ),
    ),
    "stackoverflow-74178703": CaseOverride(
        root_cause_insn_idx=204,
        confidence="high",
        note=(
            "The map-value offset proof collapses on the loop guard/latch before the failing "
            "`memcpy` byte load; the causal site has a higher numeric insn due to loop structure."
        ),
    ),
    "stackoverflow-76160985": CaseOverride(
        root_cause_insn_idx=189,
        confidence="medium",
        note=(
            "This is a cross-function proof-loss case: the callee `find_substring` begins "
            "without the caller's fixed-size buffer fact, so the function entry is the best "
            "visible root in the log."
        ),
    ),
    "stackoverflow-76637174": CaseOverride(
        root_cause_insn_idx=39,
        confidence="high",
        note=(
            "The scan cursor is recomputed with a variable TCP-header step, and packet-range "
            "precision drops there before the later payload byte test."
        ),
    ),
    "stackoverflow-77762365": CaseOverride(
        root_cause_insn_idx=127,
        confidence="medium",
        note=(
            "The combined `event->len + read` bound is formed here and is not preserved "
            "through to the later user-read helper call."
        ),
    ),
    "stackoverflow-79485758": CaseOverride(
        root_cause_insn_idx=44,
        confidence="medium",
        note=(
            "The checked packet cursor is rebuilt with `field_offset` at insn 44, which is "
            "where the verifier stops retaining the earlier range proof."
        ),
    ),
    "stackoverflow-79530762": CaseOverride(
        root_cause_insn_idx=22,
        confidence="high",
        note=(
            "The checked and dereferenced packet-register paths diverge at the option-type "
            "branch before the later packet store."
        ),
    ),
    "github-aya-rs-aya-1056": CaseOverride(
        root_cause_insn_idx=37,
        confidence="medium",
        note=(
            "The debug/logging path first computes a frame-pointer distance from an "
            "unbounded scalar at insn 37; the final subtraction at insn 48 is only the symptom."
        ),
    ),
    "github-aya-rs-aya-1062": CaseOverride(
        root_cause_insn_idx=8,
        confidence="high",
        note=(
            "The sign-extension step on the `ctx.ret().unwrap()`-derived length destroys the "
            "non-negative bound before `bpf_probe_read_user()`."
        ),
    ),
    "github-cilium-cilium-41522": CaseOverride(
        root_cause_insn_idx=927,
        confidence="medium",
        note=(
            "The builtins-expanded packet walk first loses packet range/provenance well before "
            "the final packet read at insn 945."
        ),
    ),
}

SOURCE_OVERRIDES: dict[str, CaseOverride] = {
    "kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0": CaseOverride(
        root_cause_insn_idx=5,
        confidence="high",
        note=(
            "The leaked reference originates at the earlier `bpf_kptr_xchg(..., NULL)` call; "
            "the verifier only reports it when the main program exits."
        ),
    ),
    "kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98": CaseOverride(
        root_cause_insn_idx=67,
        confidence="high",
        note=(
            "The original crypto context returned by `bpf_crypto_ctx_create()` is never released; "
            "the later acquire/release only balances a secondary reference."
        ),
    ),
}


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dump_yaml(path: Path, data: Any) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )


def read_case_ids() -> list[str]:
    return [
        line.strip()
        for line in CASE_LIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_case_paths() -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for case_dir in CASE_DIRS:
        for path in case_dir.glob("*.yaml"):
            if path.name == "index.yaml":
                continue
            paths[path.stem] = path
    return paths


def extract_log_blocks(case_data: dict[str, Any]) -> list[str]:
    verifier_log = case_data.get("verifier_log")

    if isinstance(verifier_log, str) and verifier_log.strip():
        return [verifier_log.strip()]

    if isinstance(verifier_log, dict):
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            block_candidates = [
                block.strip()
                for block in blocks
                if isinstance(block, str) and block.strip()
            ]
            if block_candidates:
                return block_candidates

        for key in ("generated", "combined"):
            value = verifier_log.get(key)
            if isinstance(value, str) and value.strip():
                return [value.strip()]

    return []


def score_log_block(block: str) -> int:
    lower = block.lower()
    score = 0
    if INSTRUCTION_RE.search(block):
        score += 8
    if STATE_RE.search(block):
        score += 6
    if "processed " in lower and " insns" in lower:
        score += 3
    if SOURCE_ANNOTATION_RE.search(block):
        score += 2
    if "last_idx" in lower or "regs=" in lower or "stack=" in lower:
        score += 2
    if "invalid access" in lower or "not allowed" in lower or "unknown func" in lower:
        score += 1
    return score


def instruction_count(block: str) -> int:
    return sum(1 for line in block.splitlines() if INSTRUCTION_RE.match(line))


def select_primary_log(case_data: dict[str, Any]) -> tuple[str, str]:
    blocks = extract_log_blocks(case_data)
    if not blocks:
        return "", "missing"
    if len(blocks) == 1:
        return blocks[0], "single"
    best = max(
        blocks,
        key=lambda block: (
            score_log_block(block) + instruction_count(block),
            score_log_block(block),
            instruction_count(block),
            len(block),
        ),
    )
    return best, "best_block"


def span_start(span: dict[str, Any]) -> int | None:
    insn_range = span.get("insn_range")
    if isinstance(insn_range, list) and insn_range and isinstance(insn_range[0], int):
        return insn_range[0]
    return None


def normalize_source_text(source_line: str | None) -> str | None:
    if not source_line:
        return None
    text = source_line.strip()
    if not text:
        return None
    match = SOURCE_LOC_RE.search(text)
    if match:
        text = text[: match.start()].rstrip()
    text = text.strip()
    return text or None


def select_rejected_instruction(trace: ParsedTrace) -> TracedInstruction | None:
    explicit = [insn for insn in trace.instructions if insn.is_error]
    if explicit:
        return explicit[-1]
    if trace.instructions:
        return trace.instructions[-1]
    return None


def select_instruction_for_idx(
    trace: ParsedTrace,
    insn_idx: int | None,
    *,
    prefer_error: bool = False,
) -> TracedInstruction | None:
    if insn_idx is None:
        return None
    matches = [insn for insn in trace.instructions if insn.insn_idx == insn_idx]
    if not matches:
        return None
    if prefer_error:
        error_matches = [insn for insn in matches if insn.is_error]
        if error_matches:
            return error_matches[-1]
    with_source = [insn for insn in matches if normalize_source_text(insn.source_line)]
    if with_source:
        return with_source[-1]
    return matches[-1]


def diagnostic_proof_spans(log_text: str) -> list[dict[str, Any]]:
    try:
        output = generate_diagnostic(log_text)
    except Exception:
        return []
    metadata = output.json_data.get("metadata") or {}
    raw = metadata.get("proof_spans")
    if isinstance(raw, list):
        return [span for span in raw if isinstance(span, dict)]
    return []


def select_lowering_root(
    case_id: str,
    trace: ParsedTrace,
    reject_idx: int | None,
    proof_spans: list[dict[str, Any]],
) -> tuple[int | None, str, str]:
    override = LA_OVERRIDES.get(case_id)
    if override is not None:
        return override.root_cause_insn_idx, override.confidence, override.note

    proof_lost = [
        span
        for span in proof_spans
        if span.get("role") == "proof_lost" and span_start(span) != reject_idx
    ]
    if proof_lost:
        idx = span_start(proof_lost[-1])
        return (
            idx,
            "high" if idx is not None else "medium",
            "The diagnostic trace exposes an earlier proof-loss span before the rejected instruction.",
        )

    transitions = [t for t in trace.critical_transitions if t.insn_idx != reject_idx]
    if transitions:
        before = [t for t in transitions if reject_idx is not None and t.insn_idx < reject_idx]
        if before:
            chosen = min(before, key=lambda t: (reject_idx - t.insn_idx, t.insn_idx))
        elif reject_idx is not None:
            chosen = min(transitions, key=lambda t: (abs(t.insn_idx - reject_idx), t.insn_idx))
        else:
            chosen = transitions[-1]
        note = (
            f"The earliest clear proof-loss signal in this log is the {chosen.transition_type.lower()} "
            f"transition at insn {chosen.insn_idx}."
        )
        return chosen.insn_idx, "medium", note

    chain = trace.causal_chain
    if chain is not None and chain.chain:
        root = chain.chain[0]
        if root.insn_idx != reject_idx:
            return (
                root.insn_idx,
                "medium",
                "The backward register chain points to an earlier instruction than the final symptom site.",
            )

    return (
        reject_idx,
        "low",
        "The label indicates verifier-visible proof loss, but this log does not expose a cleaner earlier transition than the reject site.",
    )


def select_source_root(
    case_id: str,
    taxonomy_class: str,
    error_id: str,
    reject_idx: int | None,
) -> tuple[int | None, str, str]:
    override = SOURCE_OVERRIDES.get(case_id)
    if override is not None:
        return override.root_cause_insn_idx, override.confidence, override.note

    if error_id == "BPFIX-E004":
        return (
            reject_idx,
            "medium",
            "The rejection is tied to reference-lifetime handling; no earlier acquire site was unambiguously exposed in this log.",
        )

    if taxonomy_class == "env_mismatch":
        return (
            reject_idx,
            "high",
            "The unsupported helper/kfunc/context use is rejected at the call site itself.",
        )

    if taxonomy_class == "verifier_limit":
        return (
            reject_idx,
            "medium",
            "The log reports a verifier budget/complexity limit at the last visible traced instruction rather than at an earlier semantic bug site.",
        )

    if error_id in {"BPFIX-E013", "BPFIX-E014"}:
        return (
            reject_idx,
            "high",
            "The rejected instruction is itself inside a disallowed verifier state/discipline.",
        )

    return (
        reject_idx,
        "high",
        "The rejected instruction is also the concrete unsafe access or call for this source-level bug.",
    )


def format_note(note: str) -> str:
    return " ".join(part for part in note.split())


def build_case_annotation(
    case_id: str,
    case_path: Path,
    ground_truth: dict[str, Any],
) -> dict[str, Any]:
    case_data = load_yaml(case_path)
    log_text, _ = select_primary_log(case_data)
    trace = parse_trace(log_text) if log_text else ParsedTrace(
        instructions=[],
        critical_transitions=[],
        causal_chain=None,
        backtrack_chains=[],
        error_line=None,
        total_instructions=0,
        has_btf_annotations=False,
        has_backtracking=False,
    )

    reject_override = LA_OVERRIDES.get(case_id) or SOURCE_OVERRIDES.get(case_id)
    rejected_instruction = select_rejected_instruction(trace)
    rejected_idx = reject_override.rejected_insn_idx if reject_override and reject_override.rejected_insn_idx is not None else (
        rejected_instruction.insn_idx if rejected_instruction is not None else None
    )
    rejected_instruction = (
        select_instruction_for_idx(trace, rejected_idx, prefer_error=True)
        if rejected_idx is not None
        else rejected_instruction
    )
    rejected_line = normalize_source_text(
        rejected_instruction.source_line if rejected_instruction is not None else None
    )

    taxonomy_class = ground_truth["taxonomy_class"]
    error_id = ground_truth["error_id"]
    proof_spans = diagnostic_proof_spans(log_text) if taxonomy_class == "lowering_artifact" else []

    if taxonomy_class == "lowering_artifact":
        root_idx, confidence, note = select_lowering_root(
            case_id,
            trace,
            rejected_idx,
            proof_spans,
        )
    else:
        root_idx, confidence, note = select_source_root(
            case_id,
            taxonomy_class,
            error_id,
            rejected_idx,
        )

    root_instruction = select_instruction_for_idx(trace, root_idx)
    root_line = normalize_source_text(root_instruction.source_line if root_instruction else None)

    distance = 0
    if rejected_idx is not None and root_idx is not None:
        distance = abs(rejected_idx - root_idx)

    return {
        "case_id": case_id,
        "rejected_insn_idx": rejected_idx,
        "rejected_line": rejected_line,
        "root_cause_insn_idx": root_idx,
        "root_cause_line": root_line,
        "has_btf_annotations": bool(trace.has_btf_annotations),
        "total_traced_insns": int(trace.total_instructions),
        "distance_insns": distance,
        "localization_confidence": confidence,
        "localization_note": format_note(note),
    }


def bucket_distance(distance: int) -> str:
    if distance == 0:
        return "0"
    if distance == 1:
        return "1"
    if 2 <= distance <= 5:
        return "2-5"
    if 6 <= distance <= 20:
        return "6-20"
    return ">20"


def build_summary(cases: list[dict[str, Any]]) -> str:
    total = len(cases)
    btf_count = sum(1 for case in cases if case["has_btf_annotations"])
    different = [
        case
        for case in cases
        if case["root_cause_insn_idx"] is not None
        and case["rejected_insn_idx"] is not None
        and case["root_cause_insn_idx"] != case["rejected_insn_idx"]
    ]
    earlier = [
        case
        for case in different
        if case["root_cause_insn_idx"] < case["rejected_insn_idx"]
    ]
    later = [
        case
        for case in different
        if case["root_cause_insn_idx"] > case["rejected_insn_idx"]
    ]

    distances = [case["distance_insns"] for case in cases]
    buckets: dict[str, int] = {}
    for key in ("0", "1", "2-5", "6-20", ">20"):
        buckets[key] = sum(1 for distance in distances if bucket_distance(distance) == key)

    interesting_ids = {
        "stackoverflow-53136145",
        "stackoverflow-70729664",
        "stackoverflow-70760516",
        "stackoverflow-76160985",
        "kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98",
        "github-cilium-cilium-41412",
    }
    examples = [case for case in cases if case["case_id"] in interesting_ids]
    examples.sort(key=lambda case: case["case_id"])

    lines: list[str] = []
    lines.append("# Localization Summary")
    lines.append("")
    lines.append(f"- Cases analyzed: `{total}`")
    lines.append(
        f"- Cases with BTF annotations: `{btf_count}/{total}` ({btf_count / total * 100:.1f}%)"
    )
    lines.append(
        f"- Cases with `root_cause_insn_idx != rejected_insn_idx`: "
        f"`{len(different)}/{total}` ({len(different) / total * 100:.1f}%)"
    )
    lines.append(
        f"- Cases with strictly earlier root-cause instruction index: "
        f"`{len(earlier)}/{total}` ({len(earlier) / total * 100:.1f}%)"
    )
    if later:
        lines.append(
            f"- Cases whose causal root has a higher numeric insn index due to loop/back-edge structure: "
            f"`{len(later)}`"
        )
    lines.append("")
    lines.append("## Distance Distribution")
    lines.append("")
    lines.append("| `distance_insns` bucket | Count |")
    lines.append("| --- | ---: |")
    for key in ("0", "1", "2-5", "6-20", ">20"):
        lines.append(f"| `{key}` | `{buckets[key]}` |")
    lines.append("")
    lines.append("## Interesting Patterns")
    lines.append("")
    lines.append(
        "- **Pointer-merge / checked-vs-dereferenced split**: `stackoverflow-53136145` and "
        "`stackoverflow-79530762` both reject at the final dereference, but the earlier root is "
        "where the verifier-visible pointer path diverges from the checked one."
    )
    lines.append(
        "- **Loop-latch / cursor-evolution losses**: `stackoverflow-70760516`, "
        "`stackoverflow-74178703`, and `stackoverflow-76637174` lose the proof on loop cursor "
        "or latch instructions rather than at the final memory access."
    )
    lines.append(
        "- **Cross-function proof loss**: `stackoverflow-76160985` localizes to the callee entry, "
        "because the caller's fixed-size buffer proof is not visible inside the separately "
        "verified subprogram."
    )
    lines.append(
        "- **Reference-lifetime bugs**: `kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98` "
        "and `kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0` "
        "reject at `exit`, but the root cause is the earlier acquire/ref-return site."
    )
    lines.append(
        "- **Verifier-limit cases**: `github-cilium-cilium-41412` and the async stack-depth cases "
        "do not expose an earlier semantic bug in the trace; the last visible instruction is only "
        "the point where the verifier gives up."
    )
    lines.append("")
    lines.append("## Example Cases")
    lines.append("")
    lines.append("| Case | Rejected | Root Cause | Distance | Note |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for case in examples:
        lines.append(
            f"| `{case['case_id']}` | `{case['rejected_insn_idx']}` | "
            f"`{case['root_cause_insn_idx']}` | `{case['distance_insns']}` | "
            f"{case['localization_note']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    case_ids = read_case_ids()
    case_paths = load_case_paths()
    ground_truth = load_yaml(GROUND_TRUTH_PATH)
    gt_by_id = {case["case_id"]: case for case in ground_truth["cases"]}

    annotations: list[dict[str, Any]] = []
    for case_id in case_ids:
        case_path = case_paths.get(case_id)
        gt = gt_by_id.get(case_id)
        if case_path is None:
            raise FileNotFoundError(f"Missing case file for {case_id}")
        if gt is None:
            raise KeyError(f"Missing ground-truth label for {case_id}")
        annotations.append(build_case_annotation(case_id, case_path, gt))

    btf_count = sum(1 for case in annotations if case["has_btf_annotations"])
    earlier_count = sum(
        1
        for case in annotations
        if case["root_cause_insn_idx"] is not None
        and case["rejected_insn_idx"] is not None
        and case["root_cause_insn_idx"] < case["rejected_insn_idx"]
    )
    median_distance = (
        int(statistics.median_low([case["distance_insns"] for case in annotations]))
        if annotations
        else 0
    )

    payload = {
        "metadata": {
            "date": DATE,
            "total_cases": len(annotations),
            "cases_with_btf": btf_count,
            "cases_with_root_cause_before_reject": earlier_count,
            "median_distance": median_distance,
        },
        "cases": annotations,
    }
    dump_yaml(OUTPUT_YAML_PATH, payload)
    OUTPUT_MD_PATH.write_text(build_summary(annotations), encoding="utf-8")


if __name__ == "__main__":
    main()
