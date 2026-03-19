#!/usr/bin/env python3
"""Helpers for splitting evaluation cases by source stratum."""

from __future__ import annotations

SOURCE_ORDER = ("kernel_selftests", "stackoverflow", "github_issues")
SOURCE_LABELS = {
    "kernel_selftests": "kernel_selftests",
    "stackoverflow": "stackoverflow",
    "github_issues": "github_issues",
}
STRATUM_ORDER = ("selftest_cases", "real_world_cases", "all_cases")
STRATUM_LABELS = {
    "selftest_cases": "Selftest Cases",
    "real_world_cases": "Real-World Cases",
    "all_cases": "All Cases",
}


def case_source(case_id: str) -> str | None:
    if case_id.startswith("kernel-selftest"):
        return "kernel_selftests"
    if case_id.startswith("stackoverflow"):
        return "stackoverflow"
    if case_id.startswith("github"):
        return "github_issues"
    return None


def source_case_ids(case_ids: list[str], source: str) -> list[str]:
    return [case_id for case_id in case_ids if case_source(case_id) == source]


def selftest_case_ids(case_ids: list[str]) -> list[str]:
    return source_case_ids(case_ids, "kernel_selftests")


def real_world_case_ids(case_ids: list[str]) -> list[str]:
    return [
        case_id
        for case_id in case_ids
        if case_source(case_id) in {"stackoverflow", "github_issues"}
    ]


def stratum_case_ids(case_ids: list[str], stratum: str) -> list[str]:
    if stratum == "selftest_cases":
        return selftest_case_ids(case_ids)
    if stratum == "real_world_cases":
        return real_world_case_ids(case_ids)
    if stratum == "all_cases":
        return list(case_ids)
    raise KeyError(f"Unknown source stratum: {stratum}")
