"""Evidence integrity: manifest, chain-of-custody, and tamper verification.

A court-defensible triage must be able to show that the artifacts analysed are
the artifacts collected. This module builds a manifest (SHA-256 of every file,
size, collector, collection time) plus a chain-of-custody log, writes it as
JSON, and later verifies a case directory against a manifest - detecting added,
removed or modified files down to a single changed byte.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .model import sha256_file

MANIFEST_NAME = "MANIFEST.json"


@dataclass
class FileRecord:
    path: str          # path relative to the case root, forward-slashed
    sha256: str
    size: int
    host: str


@dataclass
class CustodyEntry:
    time: str
    actor: str
    action: str
    detail: str = ""


@dataclass
class Manifest:
    case: str
    collector: str
    collected_utc: str
    files: list[FileRecord] = field(default_factory=list)
    custody: list[CustodyEntry] = field(default_factory=list)

    def to_json(self) -> str:
        d = {
            "case": self.case,
            "collector": self.collector,
            "collected_utc": self.collected_utc,
            "files": [asdict(f) for f in self.files],
            "custody": [asdict(c) for c in self.custody],
        }
        return json.dumps(d, indent=2, sort_keys=False)

    @classmethod
    def from_json(cls, text: str) -> "Manifest":
        d = json.loads(text)
        return cls(
            case=d["case"], collector=d["collector"], collected_utc=d["collected_utc"],
            files=[FileRecord(**f) for f in d["files"]],
            custody=[CustodyEntry(**c) for c in d.get("custody", [])],
        )

    @property
    def by_path(self) -> dict[str, FileRecord]:
        return {f.path: f for f in self.files}


def _iter_artifact_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.name == MANIFEST_NAME:
            continue
        yield p


def build_manifest(case_dir: str | Path, *, case: str = "Northwind Logistics triage",
                   collector: str = "KAPE 1.3 (synthetic)",
                   collected_utc: Optional[str] = None,
                   now: Optional[datetime] = None) -> Manifest:
    """Compute a manifest over every artifact file under ``case_dir``.

    ``collected_utc``/``now`` are injectable so the manifest is reproducible in
    tests (no implicit wall-clock).
    """
    root = Path(case_dir)
    if not root.exists():
        raise FileNotFoundError(str(root))
    stamp = collected_utc or (now or datetime(2026, 10, 19, 15, 0, tzinfo=timezone.utc)) \
        .astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records: list[FileRecord] = []
    for p in _iter_artifact_files(root):
        rel = p.relative_to(root).as_posix()
        host = rel.split("/", 1)[0] if "/" in rel else "-"
        records.append(FileRecord(path=rel, sha256=sha256_file(str(p)),
                                  size=p.stat().st_size, host=host))
    custody = [
        CustodyEntry(time=stamp, actor=collector, action="acquired",
                     detail=f"{len(records)} files hashed SHA-256 at collection"),
        CustodyEntry(time=stamp, actor="J. Scirica (Tier 2)", action="received",
                     detail="transferred to analysis workstation, hashes re-verified"),
    ]
    return Manifest(case=case, collector=collector, collected_utc=stamp,
                    files=records, custody=custody)


def write_manifest(case_dir: str | Path, out_path: Optional[str | Path] = None,
                   **kwargs) -> Path:
    manifest = build_manifest(case_dir, **kwargs)
    out = Path(out_path) if out_path else Path(case_dir) / MANIFEST_NAME
    out.write_text(manifest.to_json() + "\n", encoding="utf-8")
    return out


@dataclass
class VerifyResult:
    ok: bool
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.ok:
            return "integrity OK: every file matches the manifest"
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.missing:
            parts.append(f"{len(self.missing)} missing")
        if self.added:
            parts.append(f"{len(self.added)} added (not in manifest)")
        return "integrity FAILED: " + ", ".join(parts)


def verify(case_dir: str | Path, manifest: Manifest | str | Path) -> VerifyResult:
    """Verify a case directory against a manifest; detect any tampering."""
    root = Path(case_dir)
    if isinstance(manifest, (str, Path)):
        manifest = Manifest.from_json(Path(manifest).read_text(encoding="utf-8"))
    expected = manifest.by_path
    seen: set[str] = set()
    modified, missing, added = [], [], []
    for p in _iter_artifact_files(root):
        rel = p.relative_to(root).as_posix()
        seen.add(rel)
        rec = expected.get(rel)
        if rec is None:
            added.append(rel)
            continue
        if sha256_file(str(p)) != rec.sha256 or p.stat().st_size != rec.size:
            modified.append(rel)
    for rel in expected:
        if rel not in seen:
            missing.append(rel)
    ok = not (modified or missing or added)
    return VerifyResult(ok=ok, modified=sorted(modified), missing=sorted(missing),
                        added=sorted(added))
