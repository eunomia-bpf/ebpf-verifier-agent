"""Helpers for mapping verifier diagnostics back to source locations using BTF or debug metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover - optional dependency during early bootstrapping
    ELFFile = None


@dataclass(slots=True)
class SourceSpan:
    """Resolved source span for a verifier diagnostic."""

    path: str
    line: int
    column: int = 1
    end_line: int | None = None
    end_column: int | None = None
    function: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "function": self.function,
        }


class BTFMapper:
    """Maintain a minimal source-line index and inspect ELF metadata when available."""

    def __init__(self, line_index: dict[int, SourceSpan] | None = None) -> None:
        self.line_index = line_index or {}

    @classmethod
    def from_manifest(cls, manifest_path: Path) -> "BTFMapper":
        """Load a lightweight line map from JSON for early experiments."""

        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        line_index = {
            int(entry["line"]): SourceSpan(
                path=entry["path"],
                line=int(entry["line"]),
                column=int(entry.get("column", 1)),
                end_line=entry.get("end_line"),
                end_column=entry.get("end_column"),
                function=entry.get("function"),
            )
            for entry in payload.get("lines", [])
        }
        return cls(line_index=line_index)

    @classmethod
    def inspect_elf(cls, elf_path: Path) -> dict[str, Any]:
        """Return a small metadata summary to help decide how to extract source mappings."""

        if ELFFile is None:
            raise RuntimeError("pyelftools is required to inspect ELF/BTF metadata")

        with elf_path.open("rb") as handle:
            elf = ELFFile(handle)
            return {
                "sections": [section.name for section in elf.iter_sections()],
                "has_btf": elf.get_section_by_name(".BTF") is not None,
                "has_btf_ext": elf.get_section_by_name(".BTF.ext") is not None,
            }

    def lookup(self, verifier_line: int | None, source_path: str | None = None) -> SourceSpan:
        """Resolve a source span using a precomputed line index or a conservative fallback."""

        if verifier_line is not None and verifier_line in self.line_index:
            return self.line_index[verifier_line]
        return SourceSpan(path=source_path or "<unknown>", line=verifier_line or 1, column=1)
