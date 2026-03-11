"""Evaluation entrypoint for running the repair loop over the benchmark corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from agent.repair_loop import RepairAttempt, RepairSession
from eval.metrics import CaseMetric, summarize_results


def load_cases(cases_dir: Path) -> list[dict[str, Any]]:
    """Load benchmark manifests from a directory tree."""

    manifests = sorted(cases_dir.rglob("*.yaml"))
    cases: list[dict[str, Any]] = []
    for manifest_path in manifests:
        with manifest_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
        if payload:
            cases.append(payload)
    return cases


def session_to_metric(session: RepairSession) -> CaseMetric:
    """Convert an agent repair session into the shared metrics representation."""

    final_attempt: RepairAttempt | None = session.attempts[-1] if session.attempts else None
    patch_correct = bool(final_attempt and final_attempt.verifier_passed)
    return CaseMetric(
        case_id=session.case_id,
        success=session.succeeded,
        iterations=len(session.attempts),
        elapsed_seconds=session.elapsed_seconds,
        patch_correct=patch_correct,
        kernels_validated=1,
        kernels_passed=1 if session.succeeded else 0,
    )


def build_parser() -> argparse.ArgumentParser:
    """Create a light-weight CLI for aggregating precomputed case sessions."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sessions",
        type=Path,
        help="Optional JSON file containing serialized repair sessions to aggregate.",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=Path("case_study/cases"),
        help="Benchmark case directory used for counting or future execution.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Aggregate a set of repair sessions or report current benchmark size."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.sessions and args.sessions.exists():
        payload = json.loads(args.sessions.read_text(encoding="utf-8"))
        metrics = [CaseMetric(**entry) for entry in payload]
        print(json.dumps(summarize_results(metrics), indent=2))
        return 0

    cases = load_cases(args.cases_dir)
    print(json.dumps({"cases_discovered": len(cases)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
