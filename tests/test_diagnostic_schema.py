from __future__ import annotations

import json
from pathlib import Path
import sys

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from interface.extractor.rust_diagnostic import generate_diagnostic


def _load_verifier_log(relative_path: str) -> str:
    payload = yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))
    verifier_log = payload["verifier_log"]
    if isinstance(verifier_log, str):
        return verifier_log
    combined = verifier_log.get("combined")
    if isinstance(combined, str):
        return combined
    blocks = verifier_log.get("blocks") or []
    return "\n\n".join(block for block in blocks if isinstance(block, str))


def test_generate_diagnostic_json_matches_declared_schema() -> None:
    schema = json.loads((ROOT / "interface" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    output = generate_diagnostic(
        _load_verifier_log("case_study/cases/stackoverflow/stackoverflow-70750259.yaml")
    )

    Draft202012Validator(schema).validate(output.json_data)
