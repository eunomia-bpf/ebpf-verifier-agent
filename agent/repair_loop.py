#!/usr/bin/env python3
"""Skeleton driver for an agent-facing repair loop."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


LOG = logging.getLogger("agent.repair_loop")


@dataclass(slots=True)
class RepairAction:
    action: str
    rationale: str
    patch_hint: str | None = None


@dataclass(slots=True)
class RepairIteration:
    iteration: int
    action_plan: list[RepairAction] = field(default_factory=list)
    patch_path: str | None = None
    verifier_pass: bool = False
    semantic_pass: bool = False
    notes: str = ""


@dataclass(slots=True)
class RepairLoopConfig:
    diagnostic: Path
    case_dir: Path
    output: Path
    max_iterations: int = 3
    dry_run: bool = True


class RepairLoop:
    def __init__(self, config: RepairLoopConfig) -> None:
        self.config = config

    def load_diagnostic(self) -> dict[str, Any]:
        with self.config.diagnostic.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def choose_actions(self, diagnostic: dict[str, Any]) -> list[RepairAction]:
        failure_class = diagnostic.get("failure_class", "source_bug")
        obligation = diagnostic.get("missing_obligation", "").lower()

        if failure_class == "env_mismatch":
            return [
                RepairAction(
                    action="GATE_BY_KERNEL_CAPABILITY",
                    rationale="The diagnostic points to environment capability drift.",
                    patch_hint="Add a capability check or alternate helper path.",
                )
            ]
        if "null" in obligation:
            return [
                RepairAction(
                    action="ADD_NULL_CHECK",
                    rationale="The missing obligation refers to pointer non-nullness.",
                    patch_hint="Guard the nullable value before dereference or helper use.",
                )
            ]
        if "bound" in obligation or "range" in obligation:
            return [
                RepairAction(
                    action="ADD_BOUNDS_GUARD",
                    rationale="The missing obligation refers to bounds or scalar range proof.",
                    patch_hint="Add a dominating bounds check and keep the guarded path simple.",
                )
            ]
        if failure_class == "lowering_artifact":
            return [
                RepairAction(
                    action="SIMPLIFY_CFG",
                    rationale="The diagnostic suggests the source proof was lost during lowering.",
                    patch_hint="Rewrite the logic into shorter basic blocks with fewer joins.",
                )
            ]
        if failure_class == "verifier_bug":
            return [
                RepairAction(
                    action="INVESTIGATE_VERIFIER_BUG",
                    rationale="This looks like a kernel-side defect rather than a source bug.",
                    patch_hint="Minimize the case and identify the kernel range impacted.",
                )
            ]
        return [
            RepairAction(
                action="UNKNOWN",
                rationale="No specialized heuristic matched the diagnostic yet.",
                patch_hint="Inspect source span, verifier log, and abstract state manually.",
            )
        ]

    def run(self) -> dict[str, Any]:
        diagnostic = self.load_diagnostic()
        iterations: list[RepairIteration] = []

        for index in range(1, self.config.max_iterations + 1):
            actions = self.choose_actions(diagnostic)
            iteration = RepairIteration(
                iteration=index,
                action_plan=actions,
                notes=(
                    "Dry-run skeleton. No patch synthesis or verifier execution is performed."
                    if self.config.dry_run
                    else "Execution mode reserved for future integration."
                ),
            )
            iterations.append(iteration)
            if self.config.dry_run:
                break

        return {
            "status": "dry-run" if self.config.dry_run else "planned",
            "case_dir": str(self.config.case_dir),
            "diagnostic": diagnostic,
            "iterations": [
                {
                    **asdict(item),
                    "action_plan": [asdict(action) for action in item.action_plan],
                }
                for item in iterations
            ],
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a minimal repair loop over structured verifier diagnostics."
    )
    parser.add_argument("diagnostic", type=Path, help="Path to a structured diagnostic JSON file.")
    parser.add_argument(
        "--case-dir",
        type=Path,
        default=Path("."),
        help="Case working directory containing source, logs, and patches.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "repair-plan.json",
        help="Destination path for the repair-loop report.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of loop iterations to plan.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Reserved flag for future execution mode. Current implementation remains planning-only.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    config = RepairLoopConfig(
        diagnostic=args.diagnostic,
        case_dir=args.case_dir,
        output=args.output,
        max_iterations=args.max_iterations,
        dry_run=not args.execute,
    )
    report = RepairLoop(config).run()
    config.output.parent.mkdir(parents=True, exist_ok=True)
    with config.output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    LOG.info("Wrote repair-loop report to %s", config.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
