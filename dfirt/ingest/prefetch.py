"""Parse PECmd prefetch CSV into ExecArtifact records.

Prefetch is the strongest single evidence-of-execution artifact on a
workstation: a ``.pf`` file is written only because the program *ran*. PECmd
reports the run count and, on Windows 8+, the last eight run times
(``LastRun`` + ``PreviousRun0..6``). ``proves_execution`` is True.

The executable's full path is recovered from ``FilesLoaded`` (the entry whose
file name equals ``ExecutableName``), with the ``\\VOLUME{guid}`` prefix mapped
to ``C:``. That lets a query by full path tell the System32 ``svchost.exe``
apart from a masquerading one.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from ..model import ExecArtifact, image_name, parse_time

_VOLUME = re.compile(r"^\\VOLUME\{[^}]*\}", re.I)


def volume_to_drive(path: str) -> str:
    return _VOLUME.sub("C:", path.strip())


def exe_full_path(row: dict) -> str:
    exe = (row.get("ExecutableName") or "").strip().lower()
    for item in (row.get("FilesLoaded") or "").split(","):
        item = item.strip()
        if item and item.rsplit("\\", 1)[-1].lower() == exe:
            return volume_to_drive(item)
    d = (row.get("Directories") or "").split(",")[0].strip()
    return volume_to_drive(f"{d}\\{row.get('ExecutableName', '')}") if d else exe


def parse(path: Path, host: str) -> list[ExecArtifact]:
    out: list[ExecArtifact] = []
    with path.open(encoding="utf-8", newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=1):
            runs = [parse_time(row.get("LastRun"))]
            runs += [parse_time(row.get(f"PreviousRun{n}")) for n in range(7)]
            runs = [t for t in runs if t]               # newest first, at most 8
            try:
                count = int(row.get("RunCount") or 0)
            except ValueError:
                count = 0
            exe_path = exe_full_path(row)
            out.append(ExecArtifact(
                host=host, target=image_name(exe_path), path=exe_path, kind="prefetch",
                first_seen=min(runs) if runs else None, last_seen=runs[0] if runs else None,
                run_count=count, run_times=runs, proves_execution=True,
                source=path.name, row=i))
    return out
