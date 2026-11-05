"""Shared Finding type used by every detector and by the report.

A Finding is a single, evidence-backed observation. It carries an ATT&CK
technique, a severity, a human summary, and - crucially for a court-ready
report - an ``evidence`` list of (artifact_file, row, note) citations so a
reviewer can walk from the claim straight to the source row.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Evidence:
    source: str          # artifact file name
    row: int             # 1-based row / record number
    note: str = ""
    host: str = ""

    def cite(self) -> str:
        loc = f"{self.source}:{self.row}" if self.row else self.source
        if self.host:
            loc = f"{self.host}/{loc}"
        return loc if not self.note else f"{loc} ({self.note})"


@dataclass
class Finding:
    detector: str
    tactic: str          # ATT&CK tactic name
    technique: str       # ATT&CK technique id, e.g. T1558.003
    technique_name: str
    severity: str        # critical|high|medium|low|info
    host: str
    title: str
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    key: str = ""        # stable identity for ground-truth scoring / dedupe
    confidence: Optional[str] = None  # high|moderate|low (execution model etc.)

    def add(self, source: str, row: int, note: str = "", host: str = "") -> "Finding":
        self.evidence.append(Evidence(source=source, row=row, note=note,
                                      host=host or self.host))
        return self

    @property
    def sev_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "tactic": self.tactic,
            "technique": self.technique,
            "technique_name": self.technique_name,
            "severity": self.severity,
            "host": self.host,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "key": self.key,
            "evidence": [e.cite() for e in self.evidence],
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic order: severity desc, then host, technique, title."""
    return sorted(findings, key=lambda f: (-f.sev_rank, f.host, f.technique, f.title))
