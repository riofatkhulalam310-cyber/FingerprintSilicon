from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    title: str
    detail: str
    confidence: str = "rendah"
    category: str = "umum"


@dataclass
class AnalysisResult:
    path: Path
    file_name: str
    size_bytes: int
    sha256: str
    mime_guess: str
    summary: str
    confidence: str
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    raw_signals: dict[str, Any] = field(default_factory=dict)
    c2pa: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": {
                "path": str(self.path),
                "name": self.file_name,
                "size_bytes": self.size_bytes,
                "sha256": self.sha256,
                "mime_guess": self.mime_guess,
            },
            "summary": self.summary,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "findings": [finding.__dict__ for finding in self.findings],
            "limitations": self.limitations,
            "raw_signals": self.raw_signals,
            "c2pa": self.c2pa,
        }
