"""Parse an MFTECmd $MFT CSV subset into dict rows for timestomp detection.

The columns of interest are the $StandardInformation (0x10) and $FileName
(0x30) created timestamps. A file whose $SI created time is meaningfully
earlier than its $FN created time is a classic timestomping signal: the
attacker backdated the easily-writable $SI times, but the $FN times (updated by
the kernel on rename/move) still show the true creation.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..model import parse_time


def parse(path: Path, host: str) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=1):
            rows.append({
                "host": host,
                "entry": row.get("EntryNumber", ""),
                "filename": (row.get("FileName") or "").strip(),
                "parent": (row.get("ParentPath") or "").strip(),
                "extension": (row.get("Extension") or "").strip(),
                "size": row.get("FileSize", ""),
                "si_created": parse_time(row.get("Created0x10")),
                "fn_created": parse_time(row.get("Created0x30")),
                "si_modified": parse_time(row.get("LastModified0x10")),
                "source": str(path.name),
                "row": i,
            })
    return rows
