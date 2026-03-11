"""Semantic correctness oracle for repaired eBPF programs."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(slots=True)
class OracleResult:
    """Outcome of task-level correctness checks after a verifier pass."""

    passed: bool
    build_returncode: int | None = None
    run_returncode: int | None = None
    executed_commands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class SemanticOracle:
    """Execute build and runtime commands stored in a benchmark case manifest."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def evaluate(self, case: Mapping[str, Any], execute: bool = False) -> OracleResult:
        """Plan or execute the semantic test encoded in the benchmark case."""

        semantic_test = dict(case.get("semantic_test", {}))
        build_command = semantic_test.get("build", "")
        run_command = semantic_test.get("run", "")
        expected_exit_code = int(semantic_test.get("expected_exit_code", 0))

        result = OracleResult(
            passed=not execute,
            executed_commands=[cmd for cmd in (build_command, run_command) if cmd],
        )

        if not execute:
            result.notes.append("Dry run only; set execute=True to run semantic commands.")
            return result

        if build_command:
            build = subprocess.run(
                shlex.split(build_command),
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            result.build_returncode = build.returncode
            if build.returncode != 0:
                result.passed = False
                result.notes.append("Build step failed.")
                return result

        if run_command:
            run = subprocess.run(
                shlex.split(run_command),
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            result.run_returncode = run.returncode
            result.passed = run.returncode == expected_exit_code
            if not result.passed:
                result.notes.append(
                    f"Run step returned {run.returncode}; expected {expected_exit_code}."
                )
        else:
            result.notes.append("No runtime oracle command configured.")

        return result

