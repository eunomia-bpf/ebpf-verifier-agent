"""Cross-kernel stability utilities for comparing diagnostics and repair outcomes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class KernelOutcome:
    """Per-kernel result for a single benchmark case."""

    kernel_release: str
    verifier_passed: bool
    oracle_passed: bool
    error_id: str | None = None


class CrossKernelEvaluator:
    """Aggregate per-kernel outcomes into stability summaries."""

    def summarize_case(self, case_id: str, outcomes: Iterable[KernelOutcome]) -> dict[str, Any]:
        rows = list(outcomes)
        accepted = sum(outcome.verifier_passed for outcome in rows)
        oracle_ok = sum(outcome.oracle_passed for outcome in rows)
        error_ids = sorted({outcome.error_id for outcome in rows if outcome.error_id})
        return {
            "case_id": case_id,
            "kernels_tested": len(rows),
            "verifier_acceptance_rate": accepted / len(rows) if rows else 0.0,
            "oracle_success_rate": oracle_ok / len(rows) if rows else 0.0,
            "error_ids": error_ids,
        }

    def load_json(self, path: Path) -> dict[str, Any]:
        """Load a previously saved cross-kernel result bundle."""

        return json.loads(path.read_text(encoding="utf-8"))

