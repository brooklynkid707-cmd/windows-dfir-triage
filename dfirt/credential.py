"""Credential-access detection: Kerberoasting and suspicious LSASS access.

Kerberoasting (T1558.003): a single account requesting Kerberos service tickets
(4769) for many distinct SPNs in a short window, with RC4 encryption (0x17)
which is downgraded and crackable offline. Benign AES (0x12/0x11) tickets and
low-volume requests do not fire.

LSASS access (T1003.001): Sysmon EventID 10 handles to lsass.exe from a process
that is not a known system component, especially with GrantedAccess masks that
include read/VM access (0x1010, 0x1410, 0x1438, 0x143a ...).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .findings import Finding
from .model import Event, image_name, in_system_dir

RC4_ETYPES = {"0x17", "0x18"}          # RC4-HMAC (downgrade)
KERBEROAST_MIN_SPNS = 3                 # distinct SPNs by one account
KERBEROAST_WINDOW = timedelta(minutes=10)

# GrantedAccess masks commonly seen in LSASS credential theft.
SUSPICIOUS_LSASS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff"}
SYSTEM_LSASS_READERS = {"wininit.exe", "services.exe", "csrss.exe", "lsass.exe",
                        "msmpeng.exe", "wmiprvse.exe"}


def detect_kerberoasting(events: list[Event], host: str) -> list[Finding]:
    tgs = [e for e in events if e.host == host and e.action == "kerberos_tgs"]
    by_account: dict[str, list[Event]] = defaultdict(list)
    for e in tgs:
        acct = (e.get("account", "") or "").split("@")[0].lower()
        by_account[acct].append(e)

    out: list[Finding] = []
    for acct, evs in by_account.items():
        rc4 = [e for e in evs if (e.get("ticket_encryption", "") or "").lower() in RC4_ETYPES
               and not (e.get("service_name", "") or "").endswith("$")   # machine accounts
               and (e.get("service_name", "") or "").lower() != "krbtgt"]
        spns = {e.get("service_name", "") for e in rc4 if e.get("service_name")}
        if len(spns) < KERBEROAST_MIN_SPNS:
            continue
        times = sorted(e.time for e in rc4 if e.time)
        if times and (times[-1] - times[0]) > KERBEROAST_WINDOW:
            # too spread out to be a scripted roast
            continue
        f = Finding(
            detector="credential", tactic="Credential Access", technique="T1558.003",
            technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
            severity="critical", host=host,
            title=f"Kerberoasting: {acct} requested RC4 tickets for {len(spns)} service accounts",
            description=(f"{', '.join(sorted(spns))} requested with RC4 (0x17) by one account "
                         f"within {int((times[-1] - times[0]).total_seconds()) if len(times) > 1 else 0}s; "
                         "RC4 service tickets can be cracked offline to recover the service "
                         "account passwords."),
            key=f"credential:kerberoast:{host}:{acct}")
        for e in sorted(rc4, key=lambda x: x.row):
            f.add(e.source, e.row, f"service={e.get('service_name','')} etype=0x17")
        out.append(f)
    return out


def detect_lsass_access(events: list[Event], host: str) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        if e.host != host or e.action != "process_access":
            continue
        if "lsass.exe" not in (e.get("target_image", "") or "").lower():
            continue
        simg = e.get("source_image", "")
        sname = image_name(simg)
        mask = (e.get("granted_access", "") or "").lower()
        if in_system_dir(simg) and sname in SYSTEM_LSASS_READERS:
            continue
        suspicious_mask = mask in SUSPICIOUS_LSASS_MASKS or mask.startswith("0x14") or mask.startswith("0x1f")
        f = Finding(
            detector="credential", tactic="Credential Access", technique="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            severity="critical", host=host,
            title=f"LSASS memory accessed by {sname or simg}",
            description=(f"GrantedAccess {mask} to lsass.exe from a non-system process."
                         + ("" if suspicious_mask else " (mask reviewed)")),
            key=f"credential:lsass:{host}:{simg.lower()}")
        f.add(e.source, e.row, f"GrantedAccess={mask} CallTrace={e.get('call_trace','')[:40]}")
        out.append(f)
    return out


def detect(events: list[Event], host: str) -> list[Finding]:
    out: list[Finding] = []
    out.extend(detect_kerberoasting(events, host))
    out.extend(detect_lsass_access(events, host))
    return out
