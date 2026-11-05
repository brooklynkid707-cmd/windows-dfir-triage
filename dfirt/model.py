"""Common normalized event model and shared helpers.

Every ingest adapter maps a vendor/tool-specific record into one of the small
dataclasses here so that detectors never have to know which CSV column a given
field came from. The model is intentionally forensic-flavoured: a process has a
``process_guid`` (Sysmon's stable identity), execution artifacts carry the
distinction between *presence* and *proof of execution*, and every record keeps
a ``source`` (artifact file) and ``row`` (1-based line) so a finding can cite
exactly where the evidence lives.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #
def parse_time(value: str | datetime | None) -> Optional[datetime]:
    """Parse the timestamp formats that Zimmerman tools and Sysmon emit.

    Returns a timezone-aware UTC datetime, or None when the value is empty.
    Naive timestamps are assumed to already be UTC (the collection convention
    documented in docs/triage-workflow.md).
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    # EvtxECmd / PECmd often use "yyyy-MM-dd HH:mm:ss.ffffff"
    s = s.replace(" ", "T", 1) if re.match(r"\d{4}-\d{2}-\d{2} \d", s) else s
    for fmt in (
        None,  # fromisoformat
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"unrecognized timestamp: {value!r}")


def iso(dt: Optional[datetime]) -> str:
    """Render a datetime back to a stable ISO-8601 UTC string."""
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --------------------------------------------------------------------------- #
# paths / masquerading helpers
# --------------------------------------------------------------------------- #
# Images that Windows ships and expects to live under System32 / SysWOW64.
SYSTEM_BINARIES = {
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "taskhostw.exe",
}

SYSTEM_DIRS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
)

def norm_path(path: str | None) -> str:
    """Lower-case a Windows path for comparison; keep separators as backslash."""
    if not path:
        return ""
    return path.strip().strip('"').replace("/", "\\").lower()


def image_name(path: str | None) -> str:
    """Return the bare executable name from a full image path."""
    p = norm_path(path)
    return p.rsplit("\\", 1)[-1] if p else ""


def in_system_dir(path: str | None) -> bool:
    p = norm_path(path)
    return any(p.startswith(d) for d in SYSTEM_DIRS)


def is_masquerade(path: str | None) -> bool:
    """A protected system binary name running from a non-system directory."""
    name = image_name(path)
    if name not in SYSTEM_BINARIES:
        return False
    return not in_system_dir(path)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def defang_ip(ip: str) -> str:
    """Render an IPv4 address safe to paste into a report/ticket."""
    return ip.replace(".", "[.]")


# --------------------------------------------------------------------------- #
# normalized records
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    """A generic, source-tagged event on the super-timeline.

    ``kind`` is a coarse category ("process", "security", "sysmon", "defender",
    "powershell", "terminalservices", "registry", "filecreate", ...). ``data``
    holds the normalized fields a detector cares about. ``source``/``row`` cite
    the artifact file and 1-based row the event came from.
    """

    time: Optional[datetime]
    host: str
    kind: str
    action: str
    data: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    row: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    @property
    def eid(self) -> Optional[int]:
        v = self.data.get("event_id")
        return int(v) if v not in (None, "") else None


@dataclass
class Process:
    """A Sysmon EventID 1 process-create, keyed by ProcessGuid."""

    time: Optional[datetime]
    host: str
    guid: str
    pid: Optional[int]
    image: str
    command_line: str
    user: str
    parent_guid: str
    parent_pid: Optional[int]
    parent_image: str
    parent_command_line: str
    sha256: str = ""
    source: str = ""
    row: int = 0

    @property
    def name(self) -> str:
        return image_name(self.image)

    @property
    def parent_name(self) -> str:
        return image_name(self.parent_image)


@dataclass
class ExecArtifact:
    """An 'evidence of execution' observation from one artifact source.

    ``kind`` is one of prefetch / amcache / shimcache / sysmon1 / evt4688.
    ``proves_execution`` captures the forensic nuance documented in
    docs/execution-evidence.md (shimcache does NOT prove execution on Win10+).
    """

    host: str
    target: str  # normalized image name, e.g. "svchost.exe"
    path: str
    kind: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    run_count: Optional[int] = None
    run_times: list = field(default_factory=list)
    sha1: str = ""
    proves_execution: bool = False
    source: str = ""
    row: int = 0
    publisher: str = ""        # Amcache only
    executed_flag: str = ""    # Shimcache only: 'NA' on Win8.1+, Yes/No on Win7
