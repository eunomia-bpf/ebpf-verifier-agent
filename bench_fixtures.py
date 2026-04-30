"""Shared test helpers for the canonical bpfix-bench layout."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent


def resolve_case_path(path_or_id: str | Path) -> Path:
    raw = Path(path_or_id)
    text = str(path_or_id)
    if raw.is_absolute():
        return raw

    if text.startswith("stackoverflow-"):
        return ROOT / "bpfix-bench" / "raw" / "so" / f"{text}.yaml"
    if text.startswith("github-") or text.startswith("eval-"):
        return ROOT / "bpfix-bench" / "raw" / "gh" / f"{text}.yaml"
    if text.startswith("kernel-selftest-"):
        return ROOT / "bpfix-bench" / "raw" / "kernel_selftests" / f"{text}.yaml"

    return ROOT / raw


def load_case(path_or_id: str | Path) -> dict[str, Any]:
    path = resolve_case_path(path_or_id)
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def raw_payload(case_data: dict[str, Any]) -> dict[str, Any]:
    if case_data.get("schema_version") == "bpfix.raw_external/v1":
        raw = case_data.get("raw")
        return raw if isinstance(raw, dict) else {}
    return case_data


def verifier_log_from_case(case_data: dict[str, Any], *, block_index: int | None = None) -> str:
    payload = raw_payload(case_data)
    verifier_log = payload.get("original_verifier_log", payload.get("verifier_log"))
    if isinstance(verifier_log, str):
        if block_index not in (None, 0):
            raise IndexError(block_index)
        return verifier_log
    if not isinstance(verifier_log, dict):
        return ""
    if block_index is not None:
        blocks = verifier_log.get("blocks") or []
        return blocks[block_index]
    combined = verifier_log.get("combined")
    if isinstance(combined, str) and combined.strip():
        return combined
    blocks = verifier_log.get("blocks") or []
    return "\n\n".join(block for block in blocks if isinstance(block, str))


def load_verifier_log(path_or_id: str | Path) -> str:
    return verifier_log_from_case(load_case(path_or_id))


def load_verifier_block(path_or_id: str | Path, index: int) -> str:
    return verifier_log_from_case(load_case(path_or_id), block_index=index)
