"""Lateral-movement analysis and host-to-host movement graph.

Correlates, per destination host:

  * LogonType 10 (RemoteInteractive) + TerminalServices 1149  -> RDP edge
  * LogonType 3 (network) followed within 10 min by a service install
    (7045 / 4697) that is not an allowlisted signed vendor service -> PsExec-style edge
  * 4672 special privileges at the same logon -> severity raised (admin session)
  * 4648 explicit-credential logons to a *remote* target -> pass-the-credentials hint

Sanctioned admin RDP (exact account + jump-host IP + target + business hours,
per config/allowlist.yml) is kept as an "allowlisted" edge for the report but
never becomes a finding. The graph is emitted as Mermaid.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from . import allowlist
from .findings import Finding
from .model import Event

HOST_BY_IP = {
    "10.20.5.17": "WS-ACCT-07",
    "10.20.1.10": "FS-01",
    "10.20.1.5": "DC-01",
    "10.20.0.50": "JUMP-01",
}
SERVICE_AFTER_LOGON = timedelta(minutes=10)
CORRELATE = timedelta(minutes=2)


@dataclass(frozen=True)
class MovementEdge:
    src: str
    dst: str
    method: str          # service | rdp
    account: str
    technique: str
    allowlisted: str = ""   # ticket id when sanctioned

    def label(self) -> str:
        tag = f", {self.allowlisted}" if self.allowlisted else ""
        return f"{self.method} as {self.account}{tag}"


def _acct(name: str) -> str:
    return name.split("\\")[-1].split("@")[0].lower() if name else ""


def _near(events: list[Event], action: str, t, acct: str, window=CORRELATE):
    for e in events:
        if e.action == action and e.time and t and abs(e.time - t) <= window \
                and _acct(e.get("user", "") or e.get("account", "")) == acct:
            return e
    return None


def analyze(events: list[Event], allow: dict | None = None
            ) -> tuple[list[MovementEdge], list[Finding]]:
    allow = allow if allow is not None else allowlist.load()
    edges: set[MovementEdge] = set()
    findings: list[Finding] = []

    by_host: dict[str, list[Event]] = {}
    for e in events:
        by_host.setdefault(e.host, []).append(e)

    for host in sorted(by_host):
        evs = by_host[host]
        logons = [e for e in evs if e.action == "logon"]

        # --- RDP (Type 10) ---------------------------------------------------
        for e in (x for x in logons if x.get("logon_type") == 10):
            src_ip = e.get("remote_host", "")
            acct = _acct(e.get("user", "") or e.get("account", ""))
            src = HOST_BY_IP.get(src_ip, src_ip or "unknown")
            ticket = allowlist.rdp_allowed(acct, src_ip, host,
                                           e.time.hour if e.time else None, allow)
            if ticket:
                edges.add(MovementEdge(src, host, "rdp", acct, "T1021.001", ticket))
                continue
            edges.add(MovementEdge(src, host, "rdp", acct, "T1021.001"))
            priv = _near(evs, "special_privileges", e.time, acct)
            f = Finding(
                detector="lateral", tactic="Lateral Movement", technique="T1021.001",
                technique_name="Remote Services: Remote Desktop Protocol",
                severity="critical" if priv else "high", host=host,
                title=f"RDP logon to {host} from {src} as {acct}",
                description=("LogonType 10 (RemoteInteractive) from a source/account/time "
                             "that does not match the RDP allowlist"
                             + ("; 4672 shows an administrative session." if priv else ".")),
                key=f"lateral:rdp:{src}->{host}:{acct}")
            f.add(e.source, e.row, f"4624 LogonType 10 from {src_ip}")
            ts_evt = next((x for x in evs if x.kind == "terminalservices" and x.eid == 1149
                           and x.get("remote_host") == src_ip and x.time and e.time
                           and abs(x.time - e.time) <= CORRELATE), None)
            if ts_evt:
                f.add(ts_evt.source, ts_evt.row, "1149 RDP authentication succeeded")
            if priv:
                f.add(priv.source, priv.row, "4672 special privileges")
            findings.append(f)

        # --- service install after network logon (PsExec-style) ---------------
        for si in (x for x in evs if x.action == "service_install"):
            name = si.get("service_name", "")
            info = f"{si.get('service_info', '')} {si.get('payload', '')}"
            if allowlist.service_allowed(name, si.get("service_image", ""), info, allow):
                continue
            partner = next((nl for nl in logons if nl.get("logon_type") == 3 and nl.time
                            and si.time and timedelta(0) <= si.time - nl.time <= SERVICE_AFTER_LOGON),
                           None)
            if partner is None:
                continue
            src_ip = partner.get("remote_host", "")
            acct = _acct(partner.get("user", "") or partner.get("account", ""))
            src = HOST_BY_IP.get(src_ip, src_ip or "unknown")
            edges.add(MovementEdge(src, host, "service", acct, "T1021.002"))
            key = f"lateral:service:{src}->{host}"
            existing = next((f for f in findings if f.key == key), None)
            if existing:
                existing.add(si.source, si.row, f"EventID {si.eid} service {name}")
                continue
            f = Finding(
                detector="lateral", tactic="Lateral Movement", technique="T1021.002",
                technique_name="Remote Services: SMB/Windows Admin Shares",
                severity="high", host=host,
                title=f"PsExec-style service '{name}' on {host} after network logon from {src}",
                description=("A non-allowlisted service was installed within minutes of a "
                             "Type 3 logon from the same source - remote service execution."),
                key=key)
            f.add(partner.source, partner.row, f"4624 LogonType 3 from {src_ip} as {acct}")
            priv = _near(evs, "special_privileges", partner.time, acct)
            if priv:
                f.add(priv.source, priv.row, "4672 special privileges")
            f.add(si.source, si.row, f"EventID {si.eid} service {name}")
            findings.append(f)

        # --- 4648 explicit credentials to a remote host -----------------------
        for e in (x for x in evs if x.action == "explicit_logon"):
            target = (e.get("pd") or ["", "", ""])[2].lower()
            if target in ("localhost", "127.0.0.1", host.lower(), ""):
                continue  # local re-auth (e.g. SCCM client) is not movement
            acct = _acct(e.get("user", ""))
            f = Finding(
                detector="lateral", tactic="Lateral Movement", technique="T1550",
                technique_name="Use Alternate Authentication Material",
                severity="medium", host=host,
                title=f"Explicit credentials used by {acct} toward {target}",
                description="4648 explicit-credential logon to a remote target.",
                key=f"lateral:4648:{host}:{acct}:{target}")
            f.add(e.source, e.row, f"target={target}")
            findings.append(f)

    return sorted(edges, key=lambda e: (e.src, e.dst, e.method, e.account)), findings


def attack_edges(edges: list[MovementEdge]) -> list[MovementEdge]:
    return [e for e in edges if not e.allowlisted]


def movement_mermaid(edges: list[MovementEdge]) -> str:
    """Render the movement graph as Mermaid; allowlisted edges are dotted."""
    lines = ["flowchart LR"]
    nodes = sorted({e.src for e in edges} | {e.dst for e in edges})
    for n in nodes:
        lines.append(f'    {n.replace("-", "_")}["{n}"]')
    for e in edges:
        s, d = e.src.replace("-", "_"), e.dst.replace("-", "_")
        arrow = "-.->" if e.allowlisted else "==>"
        lines.append(f'    {s} {arrow}|"{e.label()}"| {d}')
    return "\n".join(lines)
