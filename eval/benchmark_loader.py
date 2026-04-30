#!/usr/bin/env python3
"""Load the canonical bpfix-bench layout for eval scripts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_benchmark_rows(benchmark: str | Path, root: Path = ROOT) -> list[dict[str, Any]]:
    """Load benchmark rows from ``<benchmark>/manifest.yaml`` and case YAML files."""

    benchmark_dir = _resolve_path(Path(benchmark), root)
    manifest_path = benchmark_dir / "manifest.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"benchmark manifest not found: {manifest_path}")

    manifest = _read_yaml(manifest_path)
    benchmark_id = _string_or_default(
        _first_present(manifest, ("benchmark_id", "id", "name")),
        benchmark_dir.name,
    )

    rows: list[dict[str, Any]] = []
    for entry in _case_entries(manifest, benchmark_dir):
        case_yaml_path = _case_yaml_path(benchmark_dir, entry)
        case_data = _read_yaml(case_yaml_path)
        case_dir = case_yaml_path.parent
        case_id = _string_or_default(
            _first_present(case_data, ("case_id", "id"))
            or _first_present(entry, ("case_id", "id")),
            case_dir.name,
        )

        verifier_log_path = _verifier_log_path(case_dir, case_data)
        verifier_log = _read_verifier_log(case_data, verifier_log_path)
        rows.append(
            {
                "benchmark_id": benchmark_id,
                "case_id": case_id,
                "case_path": str(case_yaml_path),
                "verifier_log_path": str(verifier_log_path) if verifier_log_path else None,
                "verifier_log": verifier_log,
                "capture_id": _as_optional_string(
                    _first_present(case_data, ("capture_id",))
                    or _find_nested(case_data, (("capture", "capture_id"), ("capture", "id")))
                    or _first_present(entry, ("capture_id",))
                ),
                "source_kind": _as_optional_string(
                    _first_present(entry, ("source_kind", "source"))
                    or _first_present(case_data, ("source_kind",))
                    or _find_nested(case_data, (("source", "kind"),))
                    or _first_present(entry, ("source_kind", "source"))
                ),
                "family_id": _as_optional_string(
                    _first_present(entry, ("family_id", "family"))
                    or _first_present(case_data, ("family_id",))
                    or _find_nested(case_data, (("reporting", "family_id"), ("family", "id")))
                    or _first_present(entry, ("family_id", "family"))
                ),
                "representative": bool(
                    _first_present(entry, ("representative", "core_representative"))
                    or _first_present(case_data, ("representative", "core_representative"))
                    or _find_nested(case_data, (("reporting", "representative"),))
                    or _first_present(entry, ("representative", "core_representative"))
                    or False
                ),
                "label": _first_present(case_data, ("label", "failure_class", "taxonomy_class"))
                or _find_nested(
                    case_data,
                    (("labels", "taxonomy"), ("labels", "failure_class"), ("ground_truth", "label")),
                ),
            }
        )

    return rows


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"expected mapping YAML in {path}")
    return payload


def _resolve_path(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else root / path


def _case_entries(manifest: dict[str, Any], benchmark_dir: Path) -> list[dict[str, Any]]:
    entries = manifest.get("cases")
    if entries is None:
        return [
            {"path": path.relative_to(benchmark_dir)}
            for path in sorted((benchmark_dir / "cases").glob("*/case.yaml"))
        ]
    if not isinstance(entries, list):
        raise ValueError("manifest field 'cases' must be a list")

    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, str):
            normalized.append({"case_id": entry})
        elif isinstance(entry, dict):
            normalized.append(entry)
        else:
            raise ValueError(f"unsupported manifest case entry: {entry!r}")
    return normalized


def _case_yaml_path(benchmark_dir: Path, entry: dict[str, Any]) -> Path:
    raw_path = _first_present(entry, ("path", "case_path", "case_yaml"))
    if raw_path is None:
        case_id = _first_present(entry, ("case_id", "id"))
        if not case_id:
            raise ValueError(f"manifest case entry missing case_id/path: {entry!r}")
        return benchmark_dir / "cases" / str(case_id) / "case.yaml"

    path = Path(str(raw_path))
    full_path = path if path.is_absolute() else benchmark_dir / path
    if full_path.is_dir():
        return full_path / "case.yaml"
    return full_path


def _verifier_log_path(case_dir: Path, case_data: dict[str, Any]) -> Path | None:
    raw_path = (
        _first_present(case_data, ("verifier_log_path", "log_path"))
        or _find_nested(
            case_data,
            (("artifacts", "verifier_log"), ("capture", "verifier_log"), ("capture", "verifier_log_path"), ("capture", "log_path")),
        )
    )
    if raw_path is None:
        for default_name in ("replay-verifier.log", "verifier.log"):
            default_path = case_dir / default_name
            if default_path.exists():
                return default_path
        return None

    path = Path(str(raw_path))
    return path if path.is_absolute() else case_dir / path


def _read_verifier_log(case_data: dict[str, Any], verifier_log_path: Path | None) -> str:
    if verifier_log_path and verifier_log_path.exists():
        return verifier_log_path.read_text(encoding="utf-8")

    inline_log = case_data.get("verifier_log", "")
    if isinstance(inline_log, str) and inline_log:
        return inline_log
    if isinstance(inline_log, dict):
        combined = inline_log.get("combined", "")
        if isinstance(combined, str) and combined:
            return combined
        blocks = inline_log.get("blocks", [])
        if isinstance(blocks, list):
            return "\n".join(block for block in blocks if isinstance(block, str))

    if verifier_log_path:
        raise FileNotFoundError(f"verifier log not found: {verifier_log_path}")
    raise ValueError("case has no verifier_log_path, verifier.log, or inline verifier_log")


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _find_nested(mapping: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any:
    for path in paths:
        current: Any = mapping
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if current is not None:
            return current
    return None


def _as_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_or_default(value: Any, default: str) -> str:
    if value is None:
        return default
    return str(value)
