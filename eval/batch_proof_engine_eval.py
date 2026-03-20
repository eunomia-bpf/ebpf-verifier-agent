#!/usr/bin/env python3
"""Batch-evaluate the proof engine across all case-study logs with useful verifier text."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.batch_diagnostic_eval import MIN_LOG_CHARS, extract_verifier_log, iter_case_files, read_yaml
from interface.extractor.pipeline import diagnose, try_proof_engine
from interface.extractor.log_parser import parse_log
from interface.extractor.trace_parser import parse_trace


DEFAULT_RESULTS_PATH = ROOT / "eval" / "results" / "batch_proof_engine_round3.json"


@dataclass(slots=True)
class CaseEval:
    case_id: str
    case_path: str
    source: str
    source_dir: str
    verifier_log_chars: int
    proof_success: bool
    proof_exception: str | None
    obligation_kind: str | None
    proof_status: str | None
    status_reason: str | None
    reject_site: int | None
    diagnoser_success: bool
    diagnoser_exception: str | None
    diagnoser_proof_status: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_RESULTS_PATH,
        help=f"Where to write the JSON results (default: {DEFAULT_RESULTS_PATH})",
    )
    parser.add_argument(
        "--min-log-chars",
        type=int,
        default=MIN_LOG_CHARS,
        help=f"Minimum verifier log length to include (default: {MIN_LOG_CHARS})",
    )
    return parser.parse_args()


def _select_error_insn(parsed_trace: Any) -> int | None:
    error_insns = [instruction.insn_idx for instruction in parsed_trace.instructions if instruction.is_error]
    if error_insns:
        return error_insns[-1]
    if parsed_trace.instructions:
        return parsed_trace.instructions[-1].insn_idx
    return None


def evaluate_case(
    source: str,
    source_dir: str,
    path: Path,
    min_log_chars: int,
) -> CaseEval | None:
    case_data = read_yaml(path)
    verifier_log = extract_verifier_log(case_data)
    if len(verifier_log) < min_log_chars:
        return None

    case_id = str(case_data.get("case_id") or path.stem)
    parsed_trace = parse_trace(verifier_log)
    parsed_log = parse_log(verifier_log)
    error_insn = _select_error_insn(parsed_trace)

    proof_success = False
    proof_exception = None
    obligation_kind = None
    proof_status = None
    status_reason = None
    reject_site = error_insn
    _cached_diagnosis = None

    diagnoser_success = False
    diagnoser_exception = None
    diagnoser_proof_status = None
    try:
        _cached_diagnosis = diagnose(verifier_log)
        diagnoser_success = True
        diagnoser_proof_status = _cached_diagnosis.proof_status
    except Exception as exc:  # pragma: no cover - batch runner should not abort on one case.
        diagnoser_exception = f"{type(exc).__name__}: {exc}"

    try:
        if _cached_diagnosis is None:
            _cached_diagnosis = diagnose(verifier_log)
        proof_result = try_proof_engine(parsed_log, parsed_trace, _cached_diagnosis)
        proof_success = True
        if proof_result is not None:
            obligation_kind = (
                getattr(proof_result.obligation, "obligation_type", None)
                if proof_result.obligation is not None
                else None
            )
            proof_status = proof_result.proof_status
            status_reason = proof_result.fallback_reasons[0] if proof_result.fallback_reasons else None
    except Exception as exc:  # pragma: no cover - batch runner should not abort on one case.
        proof_exception = f"{type(exc).__name__}: {exc}"

    return CaseEval(
        case_id=case_id,
        case_path=str(path),
        source=source,
        source_dir=source_dir,
        verifier_log_chars=len(verifier_log),
        proof_success=proof_success,
        proof_exception=proof_exception,
        obligation_kind=obligation_kind,
        proof_status=proof_status,
        status_reason=status_reason,
        reject_site=reject_site,
        diagnoser_success=diagnoser_success,
        diagnoser_exception=diagnoser_exception,
        diagnoser_proof_status=diagnoser_proof_status,
    )


def build_summary(results: list[CaseEval]) -> dict[str, Any]:
    proof_successes = [result for result in results if result.proof_success]
    proof_errors = [result for result in results if not result.proof_success]
    diagnoser_errors = [result for result in results if not result.diagnoser_success]
    obligation_count = sum(result.obligation_kind is not None for result in proof_successes)
    proof_status_counts = Counter((result.proof_status or "unknown") for result in proof_successes)
    diagnoser_status_counts = Counter(
        (result.diagnoser_proof_status or "unknown")
        for result in results
        if result.diagnoser_success
    )

    comparable = [
        result
        for result in results
        if result.proof_success and result.diagnoser_success
    ]
    matches = [
        result
        for result in comparable
        if (result.proof_status or "unknown") == (result.diagnoser_proof_status or "unknown")
    ]
    mismatches = [result for result in comparable if result not in matches]
    comparison_matrix = Counter(
        ((result.proof_status or "unknown"), (result.diagnoser_proof_status or "unknown"))
        for result in comparable
    )

    return {
        "cases": len(results),
        "proof_successes": len(proof_successes),
        "proof_errors": len(proof_errors),
        "diagnoser_errors": len(diagnoser_errors),
        "obligation_non_null": obligation_count,
        "proof_status_counts": dict(sorted(proof_status_counts.items())),
        "diagnoser_status_counts": dict(sorted(diagnoser_status_counts.items())),
        "proof_vs_diagnoser_matches": len(matches),
        "proof_vs_diagnoser_mismatches": len(mismatches),
        "proof_vs_diagnoser_matrix": [
            {
                "proof_status": proof_status,
                "diagnoser_proof_status": diagnoser_proof_status,
                "count": count,
            }
            for (proof_status, diagnoser_proof_status), count in sorted(comparison_matrix.items())
        ],
        "mismatch_examples": [
            {
                "case_id": result.case_id,
                "proof_status": result.proof_status or "unknown",
                "diagnoser_proof_status": result.diagnoser_proof_status or "unknown",
                "obligation_kind": result.obligation_kind,
                "reject_site": result.reject_site,
                "status_reason": result.status_reason,
            }
            for result in mismatches[:25]
        ],
        "proof_error_examples": [
            {
                "case_id": result.case_id,
                "exception": result.proof_exception,
            }
            for result in proof_errors[:10]
        ],
    }


def main() -> None:
    args = parse_args()
    case_files = iter_case_files()
    results: list[CaseEval] = []

    for index, (source, source_dir, path) in enumerate(case_files, start=1):
        evaluated = evaluate_case(source, source_dir, path, args.min_log_chars)
        if evaluated is None:
            continue
        results.append(evaluated)
        if index % 50 == 0:
            print(
                f"[batch_proof_engine_eval] scanned {index}/{len(case_files)} files; kept {len(results)}",
                flush=True,
            )

    summary = build_summary(results)
    payload = {
        "summary": summary,
        "cases": [asdict(result) for result in results],
    }

    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print(f"[batch_proof_engine_eval] evaluated {summary['cases']} cases", flush=True)
    print(
        f"[batch_proof_engine_eval] obligation != None: {summary['obligation_non_null']}",
        flush=True,
    )
    print(
        f"[batch_proof_engine_eval] proof_status counts: {summary['proof_status_counts']}",
        flush=True,
    )
    print(
        f"[batch_proof_engine_eval] proof errors: {summary['proof_errors']}",
        flush=True,
    )
    print(
        "[batch_proof_engine_eval] proof vs diagnoser: "
        f"{summary['proof_vs_diagnoser_matches']} matches / "
        f"{summary['proof_vs_diagnoser_mismatches']} mismatches",
        flush=True,
    )
    print(f"[batch_proof_engine_eval] wrote results to {args.results_path}", flush=True)


if __name__ == "__main__":
    main()
