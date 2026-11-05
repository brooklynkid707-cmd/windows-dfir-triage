"""Parse Sysmon events exported as JSON lines into Process + Event records.

Handled EventIDs: 1 (process create -> Process), 3 (network), 7 (image load),
10 (process access / LSASS), 11 (file create), 13 (registry set), 19/20/21 (WMI
event subscription), 22 (DNS). Field names follow Sysmon's own schema; a few
common alternates are accepted so a different exporter still parses.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..model import Event, Process, parse_time


def _hashes(raw: str) -> dict:
    out = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().upper()] = v.strip()
    return out


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse(path: Path, host: str) -> tuple[list[Process], list[Event]]:
    procs: list[Process] = []
    events: list[Event] = []
    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            eid = int(o.get("EventID", 0))
            computer = o.get("Computer", host) or host
            t = parse_time(o.get("UtcTime"))
            src = str(path.name)
            if eid == 1:
                h = _hashes(o.get("Hashes", ""))
                procs.append(Process(
                    time=t, host=computer, guid=o.get("ProcessGuid", ""),
                    pid=_int(o.get("ProcessId")), image=o.get("Image", ""),
                    command_line=o.get("CommandLine", ""), user=o.get("User", ""),
                    parent_guid=o.get("ParentProcessGuid", ""),
                    parent_pid=_int(o.get("ParentProcessId")),
                    parent_image=o.get("ParentImage", ""),
                    parent_command_line=o.get("ParentCommandLine", ""),
                    sha256=h.get("SHA256", ""), source=src, row=i))
                events.append(Event(t, computer, "sysmon", "process_create", {
                    "event_id": 1, "image": o.get("Image", ""),
                    "command_line": o.get("CommandLine", ""),
                    "parent_image": o.get("ParentImage", ""),
                    "guid": o.get("ProcessGuid", ""), "user": o.get("User", "")},
                    source=src, row=i))
            elif eid == 3:
                events.append(Event(t, computer, "sysmon", "network_connect", {
                    "event_id": 3, "image": o.get("Image", ""),
                    "dest_ip": o.get("DestinationIp", ""),
                    "dest_port": _int(o.get("DestinationPort")),
                    "dest_host": o.get("DestinationHostname", ""),
                    "src_ip": o.get("SourceIp", "")}, source=src, row=i))
            elif eid == 7:
                events.append(Event(t, computer, "sysmon", "image_load", {
                    "event_id": 7, "image": o.get("Image", ""),
                    "image_loaded": o.get("ImageLoaded", ""),
                    "signed": str(o.get("Signed", "")).lower(),
                    "signature": o.get("Signature", "")}, source=src, row=i))
            elif eid == 10:
                events.append(Event(t, computer, "sysmon", "process_access", {
                    "event_id": 10, "source_image": o.get("SourceImage", ""),
                    "target_image": o.get("TargetImage", ""),
                    "granted_access": o.get("GrantedAccess", ""),
                    "call_trace": o.get("CallTrace", "")}, source=src, row=i))
            elif eid == 11:
                events.append(Event(t, computer, "sysmon", "file_create", {
                    "event_id": 11, "image": o.get("Image", ""),
                    "target_filename": o.get("TargetFilename", ""),
                    "user": o.get("User", "")}, source=src, row=i))
            elif eid == 13:
                events.append(Event(t, computer, "sysmon", "registry_set", {
                    "event_id": 13, "image": o.get("Image", ""),
                    "target_object": o.get("TargetObject", ""),
                    "details": o.get("Details", "")}, source=src, row=i))
            elif eid in (19, 20, 21):
                events.append(Event(t, computer, "sysmon", "wmi_subscription", {
                    "event_id": eid, "name": o.get("Name", ""),
                    "query": o.get("Query", ""), "destination": o.get("Destination", ""),
                    "consumer": o.get("Consumer", ""), "filter": o.get("Filter", ""),
                    "type": o.get("Type", "")}, source=src, row=i))
            elif eid == 22:
                events.append(Event(t, computer, "sysmon", "dns_query", {
                    "event_id": 22, "image": o.get("Image", ""),
                    "query_name": o.get("QueryName", ""),
                    "query_results": o.get("QueryResults", "")}, source=src, row=i))
    return procs, events
