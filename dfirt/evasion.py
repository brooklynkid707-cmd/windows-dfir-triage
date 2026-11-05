"""Defense-evasion detection: log clearing, Defender tampering, timestomping,
masquerading.

  * Log cleared        - Security 1102 / System 104                 T1070.001
  * Defender disabled  - Defender 5001 (RTP off) / 5007 config      T1562.001
  * Timestomping       - $SI created meaningfully earlier than $FN  T1070.006
  * Masquerading       - protected system-binary name in wrong path T1036.005
"""
from __future__ import annotations

from datetime import timedelta

from .findings import Finding
from .model import Event, is_masquerade

# A tolerance so sub-second ordering noise does not create false timestomps.
TIMESTOMP_MIN_DELTA = timedelta(days=1)


def detect_log_clearing(events: list[Event], host: str) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        if e.host != host or e.action != "log_cleared":
            continue
        f = Finding(
            detector="evasion", tactic="Defense Evasion", technique="T1070.001",
            technique_name="Indicator Removal: Clear Windows Event Logs",
            severity="high", host=host,
            title=f"Event log cleared on {host} (EventID {e.eid})",
            description=f"{e.get('description','The audit log was cleared')}.",
            key=f"evasion:log_clear:{host}:{e.eid}")
        f.add(e.source, e.row, e.get("payload", ""))
        out.append(f)
    return out


def detect_defender_tamper(events: list[Event], host: str) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        if e.host != host:
            continue
        if e.action == "defender_rtp_disabled":
            f = Finding(
                detector="evasion", tactic="Defense Evasion", technique="T1562.001",
                technique_name="Impair Defenses: Disable or Modify Tools",
                severity="high", host=host,
                title=f"Microsoft Defender real-time protection disabled on {host}",
                description="Defender EventID 5001 - real-time protection turned off.",
                key=f"evasion:defender:{host}")
            f.add(e.source, e.row, e.get("payload", ""))
            out.append(f)
    return out


def detect_timestomping(mft_rows: list[dict], host: str) -> list[Finding]:
    out: list[Finding] = []
    for r in mft_rows:
        if r["host"] != host:
            continue
        si, fn = r.get("si_created"), r.get("fn_created")
        if not si or not fn:
            continue
        # Classic timestomp: $SI created is older than $FN created by a wide margin.
        if fn - si >= TIMESTOMP_MIN_DELTA:
            path = f"{r['parent']}\\{r['filename']}"
            f = Finding(
                detector="evasion", tactic="Defense Evasion", technique="T1070.006",
                technique_name="Indicator Removal: Timestomp",
                severity="high", host=host,
                title=f"Timestomping on {r['filename']} ($SI older than $FN)",
                description=(f"$SI created {si.isoformat()} is earlier than $FN created "
                             f"{fn.isoformat()}; the easily-writable $SI times were "
                             "backdated while $FN retains the true creation time."),
                key=f"evasion:timestomp:{host}:{path.lower()}")
            f.add(r["source"], r["row"], f"$SI={si.isoformat()} $FN={fn.isoformat()}")
            out.append(f)
    return out


def detect_masquerading(processes: list, host: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for p in processes:
        if p.host != host:
            continue
        if is_masquerade(p.image) and p.image.lower() not in seen:
            seen.add(p.image.lower())
            f = Finding(
                detector="evasion", tactic="Defense Evasion", technique="T1036.005",
                technique_name="Masquerading: Match Legitimate Name or Location",
                severity="high", host=host,
                title=f"Masquerading binary {p.name} at {p.image}",
                description=(f"{p.name} is a protected Windows binary name but is running "
                             "from a user-writable directory."),
                key=f"evasion:masquerade:{host}:{p.image.lower()}")
            f.add(p.source, p.row, f"image={p.image}")
            out.append(f)
    return out


def detect(events: list[Event], mft_rows: list[dict], processes: list,
           host: str) -> list[Finding]:
    out: list[Finding] = []
    out.extend(detect_log_clearing(events, host))
    out.extend(detect_defender_tamper(events, host))
    out.extend(detect_timestomping(mft_rows, host))
    out.extend(detect_masquerading(processes, host))
    return out
