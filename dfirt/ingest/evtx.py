"""Parse EvtxECmd CSV output (any channel) into normalized Events.

EvtxECmd (Eric Zimmerman) flattens an .evtx into one CSV row per record with a
``MapDescription`` and ``PayloadDataN`` columns. The ``Channel`` tells us the
coarse event family; we keep the raw payload fields in ``data`` and lift the
fields detectors need (event_id, user, remote host, logon type, SPN, ...).
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from ..model import Event, parse_time

_LOGON_TYPE = re.compile(r"LogonType\s*(\d+)", re.I)
_ENC_TYPE = re.compile(r"0x[0-9a-fA-F]{2}")


def _kind_for(channel: str) -> str:
    c = channel.lower()
    if "security" in c:
        return "security"
    if "powershell" in c:
        return "powershell"
    if "terminalservices" in c:
        return "terminalservices"
    if "defender" in c:
        return "defender"
    if "system" in c:
        return "system"
    return "evtx"


def parse(path: Path, host: str) -> list[Event]:
    events: list[Event] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=1):
            channel = row.get("Channel", "")
            kind = _kind_for(channel)
            eid = int(row.get("EventId") or 0)
            t = parse_time(row.get("TimeCreated"))
            computer = row.get("Computer", host) or host
            pds = [row.get(f"PayloadData{n}", "") for n in range(1, 7)]
            data = {
                "event_id": eid,
                "description": row.get("MapDescription", ""),
                "user": row.get("UserName", ""),
                "remote_host": row.get("RemoteHost", ""),
                "provider": row.get("Provider", ""),
                "channel": channel,
                "level": row.get("Level", ""),
                "payload": row.get("Payload", ""),
                "pd": pds,
            }
            blob = " ".join(pds) + " " + row.get("Payload", "")
            m = _LOGON_TYPE.search(blob)
            if m:
                data["logon_type"] = int(m.group(1))
            # Kerberos 4769: SPN is PayloadData1, encryption type is a 0x.. token
            if eid == 4769:
                data["service_name"] = pds[0]
                data["account"] = pds[1]
                enc = _ENC_TYPE.search(" ".join(pds[2:4]))
                data["ticket_encryption"] = enc.group(0).lower() if enc else ""
            if eid in (4624, 4634, 4648):
                data["account"] = pds[1] if len(pds) > 1 else row.get("UserName", "")
            if eid in (7045, 4697):
                data["service_name"] = pds[0]
                data["service_image"] = pds[1]
                data["service_info"] = " ".join(pds[2:])
            if eid == 4698:
                data["task_name"] = pds[0]
                data["task_action"] = pds[1]
            action = {
                4624: "logon", 4634: "logoff", 4648: "explicit_logon",
                4672: "special_privileges", 4688: "process_create",
                4697: "service_install", 7045: "service_install",
                4698: "task_create", 4769: "kerberos_tgs",
                1102: "log_cleared", 104: "log_cleared",
                5001: "defender_rtp_disabled", 5007: "defender_config_change",
                4104: "scriptblock",
            }.get(eid, f"event_{eid}")
            events.append(Event(t, computer, kind, action, data, source=str(path.name), row=i))
    return events
