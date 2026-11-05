"""Super-timeline across all hosts (CSV + Markdown) with a key-events view.

Every normalized Event, Process, scheduled task and MFT record is flattened to
a timeline row (time, host, source artifact, kind, actor, detail) and sorted.
``key_events`` keeps exactly the rows that a triage finding cites as evidence,
so the key view and the report always tell the same story, and benign noise
(SCCM, AES tickets, the allowlisted admin RDP) never appears in it.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .model import iso, image_name


@dataclass
class TLRow:
    time: Optional[datetime]
    host: str
    source: str
    kind: str
    actor: str
    detail: str
    row: int = 0

    def as_dict(self) -> dict:
        return {"time": iso(self.time), "host": self.host, "source": self.source,
                "row": self.row, "kind": self.kind, "actor": self.actor, "detail": self.detail}


def _min_dt():
    return datetime.min.replace(tzinfo=timezone.utc)


def build(case) -> list[TLRow]:
    rows: list[TLRow] = []
    for p in case.processes:
        rows.append(TLRow(p.time, p.host, p.source, "process_create",
                          p.user or "-",
                          f"{p.parent_name} -> {p.name} :: {p.command_line[:80]}", p.row))
    for e in case.events:
        actor = e.get("user") or e.get("account") or e.get("image") or "-"
        if e.kind == "sysmon" and e.action == "process_create":
            continue  # already emitted via processes
        detail = _event_detail(e)
        rows.append(TLRow(e.time, e.host, e.source,
                          f"{e.kind}:{e.action}", image_name(actor) if "\\" in str(actor) else actor,
                          detail, e.row))
    for t in case.tasks:
        rows.append(TLRow(t.get("registration_date"), t["host"], f"tasks/{t['source']}",
                          "scheduled_task", t.get("user_id", "-"),
                          f"{t['name']} -> {t['command']}", 0))
    for m in case.mft_rows:
        path = f"{m['parent']}\\{m['filename']}"
        # $FN created is kernel-maintained: it is the timeline position of record.
        when = m.get("fn_created") or m.get("si_created")
        stomp = (m.get("si_created") and m.get("fn_created")
                 and m["si_created"] < m["fn_created"])
        detail = f"$FN created {path}"
        if stomp:
            detail += f" ($SI claims {iso(m['si_created'])}: timestomped)"
        rows.append(TLRow(when, m["host"], m["source"], "mft:file_created", "-", detail, m["row"]))
    rows.sort(key=lambda r: (r.time or _min_dt(), r.host, r.source, r.row))
    return rows


def _event_detail(e) -> str:
    a = e.action
    if a == "network_connect":
        return f"-> {e.get('dest_ip','')}:{e.get('dest_port','')} {e.get('dest_host','')}".strip()
    if a == "dns_query":
        return f"DNS {e.get('query_name','')} -> {e.get('query_results','')}"
    if a == "file_create":
        return f"wrote {e.get('target_filename','')}"
    if a == "registry_set":
        return f"{e.get('target_object','')} = {e.get('details','')}"
    if a == "process_access":
        return f"{image_name(e.get('source_image',''))} -> lsass.exe {e.get('granted_access','')}"
    if a == "kerberos_tgs":
        return f"TGS {e.get('service_name','')} etype={e.get('ticket_encryption','')}"
    if a == "logon":
        return f"LogonType {e.get('logon_type','')} from {e.get('remote_host','')}"
    if a == "service_install":
        return f"service {e.get('service_name','')} ({e.get('service_image','')})"
    if a == "wmi_subscription":
        if e.eid == 19:
            return f"WMI filter {e.get('name', '')}: {e.get('query', '')}"
        if e.eid == 20:
            return f"WMI consumer {e.get('name', '')} ({e.get('type', '')}) -> {e.get('destination', '')}"
        return f"WMI binding {e.get('filter', '')} -> {e.get('consumer', '')}"
    if a in ("run_key", "registry_value"):
        return f"{e.get('key_path', '')}\\{e.get('value_name', '')} = {e.get('value_data', '')}"
    if a == "task_create":
        return f"4698 task {e.get('task_name', '')} -> {e.get('task_action', '')}"
    if a == "explicit_logon":
        pd = e.get("pd") or ["", "", ""]
        return f"4648 explicit creds as {pd[1]} to {pd[2]}"
    if a == "scriptblock":
        return f"ScriptBlock: {e.get('payload','')[:80]}"
    if a in ("log_cleared", "defender_rtp_disabled", "defender_config_change"):
        return e.get("payload", "") or e.get("description", "")
    return e.get("description", "") or e.get("payload", "")[:80]


def key_events(rows: list[TLRow], findings=None, case=None) -> list[TLRow]:
    """Rows that carry the narrative.

    With ``findings``: exactly the rows some finding cites as evidence (so the
    key view and the report can never disagree). Without: fall back to a
    conservative filter on attack-relevant event kinds.
    """
    if findings is None and case is not None:
        from . import triage
        findings = triage.run(case).findings
    if findings is not None:
        cited = {(e.host or f.host, e.source, e.row) for f in findings for e in f.evidence}
        return [r for r in rows if (r.host, r.source, r.row) in cited]
    keep = {"sysmon:process_access", "sysmon:wmi_subscription", "security:log_cleared",
            "defender:defender_rtp_disabled", "system:service_install"}
    return [r for r in rows if r.kind in keep]


def to_csv(rows: list[TLRow]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["time", "host", "source", "row", "kind", "actor", "detail"])
    for r in rows:
        w.writerow([iso(r.time), r.host, r.source, r.row, r.kind, r.actor, r.detail])
    return buf.getvalue()


def to_markdown(rows: list[TLRow], title: str = "Timeline") -> str:
    lines = [f"# {title}", "", f"{len(rows)} events, all times UTC. Synthetic case data.", "",
             "| Time (UTC) | Host | Source:row | Kind | Actor | Detail |",
             "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        detail = r.detail.replace("|", "\\|")[:100]
        loc = f"{r.source}:{r.row}" if r.row else r.source
        lines.append(f"| {iso(r.time)} | {r.host} | {loc} | {r.kind} | "
                     f"{r.actor} | {detail} |")
    return "\n".join(lines) + "\n"
