"""Parse AmcacheParser CSV (associated file entries) into ExecArtifact records.

Amcache records a file's presence and metadata (SHA1, size, publisher) when it
is referenced by the system. It is strong evidence that a binary *was present*
and usually that it executed, but with caveats (an entry can be created by
program-compatibility scanning, not only execution), so ``proves_execution`` is
left False and the confidence model treats it as presence+.
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
            full = (row.get("FullPath") or "").strip()
            name = (row.get("Name") or image_name(full)).strip()
            seen = parse_time(row.get("FileKeyLastWriteTimestamp"))
            out.append(ExecArtifact(
                host=host, target=image_name(name), path=full, kind="amcache",
                first_seen=seen, last_seen=seen, sha1=(row.get("SHA1") or "").strip().lower(),
                proves_execution=False, source=path.name, row=i,
                publisher=(row.get("Publisher") or "").strip()))
    return out
