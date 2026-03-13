from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_expected_files_exist() -> None:
    expected = [
        ROOT / "pyproject.toml",
        ROOT / "case_study" / "schema.yaml",
        ROOT / "taxonomy" / "taxonomy.yaml",
        ROOT / "interface" / "schema" / "diagnostic.json",
        ROOT / "case_study" / "collect.py",
        ROOT / "case_study" / "reproduce.py",
        ROOT / "agent" / "repair_loop.py",
        ROOT / "eval" / "metrics.py",
        ROOT / "README.md",
        ROOT / "requirements.txt",
        ROOT / ".gitignore",
    ]
    missing = [path for path in expected if not path.exists()]
    assert not missing, f"missing expected files: {missing}"


def test_benchmark_schema_has_expected_fields() -> None:
    payload = yaml.safe_load((ROOT / "case_study" / "schema.yaml").read_text(encoding="utf-8"))
    expected_fields = {
        "case_id",
        "source",
        "title",
        "url",
        "failure_class",
        "source_code",
        "compile_args",
        "target_kernel",
        "verifier_log",
        "root_cause",
        "fix_patch",
        "semantic_test",
        "tags",
        "difficulty",
    }
    assert expected_fields.issubset(payload["fields"].keys())
    assert set(payload["required"]) == expected_fields - {"url"}


def test_taxonomy_defines_all_five_classes() -> None:
    payload = yaml.safe_load((ROOT / "taxonomy" / "taxonomy.yaml").read_text(encoding="utf-8"))
    classes = payload["classes"]
    assert len(classes) == 5
    assert {entry["id"] for entry in classes} == {
        "source_bug",
        "lowering_artifact",
        "verifier_limit",
        "env_mismatch",
        "verifier_bug",
    }


def test_diagnostic_schema_accepts_minimal_example() -> None:
    schema = json.loads((ROOT / "interface" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    example = {
        "diagnostic_version": "0.1.0",
        "error_id": "packet.bounds.missing_guard",
        "failure_class": "source_bug",
        "message": "packet access requires a dominating bounds check",
        "source_span": {
            "path": "case_study/cases/so-12345/prog.bpf.c",
            "line_start": 12,
            "line_end": 14
        },
        "missing_obligation": "prove packet cursor stays within data_end before load"
    }
    Draft202012Validator(schema).validate(example)


def test_cli_help_commands_work() -> None:
    scripts = [
        ROOT / "case_study" / "collect.py",
        ROOT / "case_study" / "reproduce.py",
        ROOT / "agent" / "repair_loop.py",
        ROOT / "eval" / "metrics.py",
    ]
    for script in scripts:
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "usage" in result.stdout.lower()

    oblige_result = subprocess.run(
        [sys.executable, "-m", "oblige", "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert oblige_result.returncode == 0, oblige_result.stderr
    assert "usage" in oblige_result.stdout.lower()
