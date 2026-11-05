"""Parse AppCompatCacheParser (Shimcache) CSV into ExecArtifact records.

Shimcache (AppCompatCache) records a path and the file's $StandardInfo last
modified time when the shim engine sees the file. CRITICAL forensic nuance: on
Windows 8.1 / 10 / 11 the 'Executed' flag is NOT populated, so Shimcache
presence alone does NOT prove execution - it only proves the file existed and
was enumerated. ``proves_execution`` is therefore False, and the confidence
model gives shimcache-only the lowest weight. See docs/execution-evidence.md.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..model import ExecArtifact, image_name, parse_time


def parse(path: Path, host: str) -> list[ExecArtifact]:
    out: list[ExecArtifact] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=1):
            p = (row.get("Path") or "").strip()
            lmt = parse_time(row.get("LastModifiedTimeUTC"))
            executed = (row.get("Executed") or "").strip()
            # On Win10+, Executed is 'NA'/'' -> we never treat it as proof.
            proves = executed.lower() in ("yes", "true")
            out.append(ExecArtifact(
                host=host, target=image_name(p), path=p, kind="shimcache",
                first_seen=lmt, last_seen=lmt, proves_execution=proves,
                source=path.name, row=i, executed_flag=executed))
    return out
