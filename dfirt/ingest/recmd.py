"""Parse RECmd Run/RunOnce-key CSV into registry Events.

RECmd (Eric Zimmerman) exports registry values with a key path, value name,
value data and the hive the value came from. We emit one ``registry`` Event per
row with ``action='run_key'`` so the persistence detector can reason over them.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..model import Event, parse_time


def parse(path: Path, host: str) -> list[Event]:
    out: list[Event] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=1):
            key = (row.get("KeyPath") or "").strip()
            t = parse_time(row.get("LastWriteTimestamp"))
            is_run = "currentversion\\run" in key.lower()
            out.append(Event(t, host, "registry",
                             "run_key" if is_run else "registry_value", {
                                 "key_path": key,
                                 "value_name": (row.get("ValueName") or "").strip(),
                                 "value_data": (row.get("ValueData") or "").strip(),
                                 "hive": (row.get("HivePath") or "").strip(),
                                 "comment": (row.get("Comment") or "").strip()},
                             source=str(path.name), row=i))
    return out
