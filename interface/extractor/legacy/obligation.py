"""Infer missing proof obligations from parsed verifier logs and the obligation catalog."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from interface.extractor.log_parser import ParsedLog


@dataclass(slots=True)
class ObligationInference:
    """Catalog-backed missing obligation selected for a verifier failure."""

    obligation_id: str
    title: str
    repair_hints: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "title": self.title,
            "repair_hints": self.repair_hints,
        }


class ObligationExtractor:
    """Match parsed verifier failures to reusable proof-obligation templates."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        self.catalog_path = catalog_path or (
            Path(__file__).resolve().parents[3] / "taxonomy" / "obligation_catalog.yaml"
        )
        self._templates = self._load_templates()

    def _load_templates(self) -> list[dict[str, Any]]:
        with self.catalog_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        return payload.get("templates", [])

    def extract(self, parsed_log: ParsedLog) -> ObligationInference:
        """Pick the best obligation template using error IDs first, then cue matching."""

        for template in self._templates:
            if parsed_log.error_id and parsed_log.error_id in template.get("related_error_ids", []):
                return self._build_inference(template)

        lowered = parsed_log.raw_log.lower()
        for template in self._templates:
            if any(cue.lower() in lowered for cue in template.get("verifier_cues", [])):
                return self._build_inference(template)

        fallback = {
            "obligation_id": "OBLIGE-O000",
            "title": "Unknown obligation; manual triage required",
            "repair_hints": [
                "Capture a minimal reproducer and label the case.",
                "Extend the obligation catalog with a stable template before automation.",
            ],
        }
        return self._build_inference(fallback)

    def _build_inference(self, template: dict[str, Any]) -> ObligationInference:
        return ObligationInference(
            obligation_id=template["obligation_id"],
            title=template["title"],
            repair_hints=list(template.get("repair_hints", [])),
        )
