#!/usr/bin/env python3
"""Helpers for loading the canonical ground-truth labels."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GROUND_TRUTH_PATH = ROOT / "case_study" / "ground_truth.yaml"


@dataclass(slots=True)
class GroundTruthLabel:
    case_id: str
    taxonomy_class: str
    error_id: str | None
    confidence: str | None
    root_cause_description: str
    fix_type: str | None
    fix_direction: str
    quarantined: bool
    quarantine_reason: str | None
    rejected_insn_idx: int | None
    root_cause_insn_idx: int | None
    rejected_line: str | None
    root_cause_line: str | None
    distance_insns: int | None
    has_btf_annotations: bool | None
    localization_confidence: str | None


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def load_ground_truth_payload(path: Path = DEFAULT_GROUND_TRUTH_PATH) -> dict[str, Any]:
    return _read_yaml(path)


def _coerce_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _coerce_bool(value: Any) -> bool:
    return bool(value) if isinstance(value, bool) else False


def load_ground_truth_labels(
    path: Path = DEFAULT_GROUND_TRUTH_PATH,
    *,
    include_quarantined: bool = False,
) -> dict[str, GroundTruthLabel]:
    payload = load_ground_truth_payload(path)
    raw_cases = payload.get("cases") or []
    if not isinstance(raw_cases, list):
        raise ValueError(f"{path} did not contain a top-level 'cases' list")

    labels: dict[str, GroundTruthLabel] = {}
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            continue
        case_id = raw_case.get("case_id")
        taxonomy_class = raw_case.get("taxonomy_class")
        if not isinstance(case_id, str) or not isinstance(taxonomy_class, str):
            continue
        quarantined = _coerce_bool(raw_case.get("quarantined"))
        if quarantined and not include_quarantined:
            continue
        labels[case_id] = GroundTruthLabel(
            case_id=case_id,
            taxonomy_class=taxonomy_class,
            error_id=str(raw_case["error_id"]) if raw_case.get("error_id") is not None else None,
            confidence=str(raw_case["confidence"]) if raw_case.get("confidence") is not None else None,
            root_cause_description=str(raw_case.get("root_cause_description") or ""),
            fix_type=str(raw_case["fix_type"]) if raw_case.get("fix_type") is not None else None,
            fix_direction=str(raw_case.get("fix_direction") or ""),
            quarantined=quarantined,
            quarantine_reason=(
                str(raw_case["quarantine_reason"])
                if raw_case.get("quarantine_reason") is not None
                else None
            ),
            rejected_insn_idx=_coerce_int(raw_case.get("rejected_insn_idx")),
            root_cause_insn_idx=_coerce_int(raw_case.get("root_cause_insn_idx")),
            rejected_line=str(raw_case["rejected_line"]) if raw_case.get("rejected_line") is not None else None,
            root_cause_line=(
                str(raw_case["root_cause_line"])
                if raw_case.get("root_cause_line") is not None
                else None
            ),
            distance_insns=_coerce_int(raw_case.get("distance_insns")),
            has_btf_annotations=(
                raw_case["has_btf_annotations"]
                if isinstance(raw_case.get("has_btf_annotations"), bool)
                else None
            ),
            localization_confidence=(
                str(raw_case["localization_confidence"])
                if raw_case.get("localization_confidence") is not None
                else None
            ),
        )
    return labels
