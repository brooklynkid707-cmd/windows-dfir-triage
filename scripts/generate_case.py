#!/usr/bin/env python3
"""Deterministic generator for the synthetic Northwind Logistics case.

Writes KAPE / Eric Zimmerman tool-style exports plus Sysmon JSONL under
``case/<host>/``. Running it twice produces byte-identical output (no clock,
no randomness beyond a fixed seed), which a test asserts.

Artifact formats produced (column names mirror the real tools as closely as
practical; see docs/artifact-cheatsheet.md for the mapping and caveats):
  * EvtxECmd  -> *_EvtxECmd.csv   (Security / System / PowerShell / TerminalServices / Defender)
  * Sysmon    -> sysmon.jsonl     (EventID 1,3,7,10,11,13,19,20,21,22)
  * PECmd     -> prefetch_PECmd.csv
  * Amcache   -> amcache_AmcacheParserAssociated.csv
  * Shimcache -> appcompatcache_AppCompatCacheParser.csv
  * RECmd     -> runkeys_RECmd.csv
  * Tasks     -> tasks/*.xml
  * MFTECmd   -> mft_MFTECmd.csv

Nothing in this file is executable attacker code. Command-line strings are
evidence only; all IPs are RFC 5737 / RFC 1918.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import _spine as S  # noqa: E402

CASE = ROOT / "case"          # rebound by main(--out)
GROUND_TRUTH = ROOT / "tests" / "ground_truth.json"
D = S.DATE  # "2026-10-19"


def ts(hms: str, frac: str = "0000") -> str:
    """Build an EvtxECmd-style timestamp 'yyyy-MM-dd HH:mm:ss.ffffff'."""
    return f"{D} {hms}.{frac}00"


def utc(hms: str, frac: str = "000") -> str:
    """Build a Sysmon UtcTime 'yyyy-MM-dd HH:mm:ss.fff'."""
    return f"{D} {hms}.{frac}"


# --------------------------------------------------------------------------- #
# generic CSV writer (deterministic, LF line endings)
# --------------------------------------------------------------------------- #
def write_csv(path: Path, header: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_evtx(path: Path, rows: list[dict]) -> None:
    """EvtxECmd output is in record order, which tracks time: sort + renumber."""
    rows = sorted(rows, key=lambda r: r["TimeCreated"])
    for i, r in enumerate(rows, start=1):
        r["RecordNumber"] = 1000 + i
    write_csv(path, EVTX_HEADER, rows)


def write_jsonl(path: Path, objs: list[dict]) -> None:
    objs = sorted(objs, key=lambda o: o["UtcTime"])   # stable: ties keep order
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for o in objs:
            fh.write(json.dumps(o, separators=(",", ":"), sort_keys=True) + "\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------- #
# EvtxECmd rows
# --------------------------------------------------------------------------- #
EVTX_HEADER = [
    "RecordNumber", "TimeCreated", "EventId", "Level", "Provider", "Channel",
    "Computer", "UserName", "MapDescription", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "ExecutableInfo", "Payload",
]


def evtx_row(n, time, eid, channel, computer, desc, provider="",
             level="Information", user="-", remote="", pd=None, payload=""):
    pd = pd or []
    pd = (pd + [""] * 6)[:6]
    return {
        "RecordNumber": n, "TimeCreated": time, "EventId": eid, "Level": level,
        "Provider": provider, "Channel": channel, "Computer": computer,
        "UserName": user, "MapDescription": desc, "RemoteHost": remote,
        "PayloadData1": pd[0], "PayloadData2": pd[1], "PayloadData3": pd[2],
        "PayloadData4": pd[3], "PayloadData5": pd[4], "PayloadData6": pd[5],
        "ExecutableInfo": "", "Payload": payload,
    }


# --------------------------------------------------------------------------- #
# Sysmon JSONL rows
# --------------------------------------------------------------------------- #
def sm_process(host, time, guid, pid, image, cmd, user, pguid, ppid, pimage, pcmd,
               sha256="", sha1="", md5=""):
    hashes = []
    if sha256:
        hashes.append(f"SHA256={sha256}")
    if sha1:
        hashes.append(f"SHA1={sha1}")
    if md5:
        hashes.append(f"MD5={md5}")
    return {
        "EventID": 1, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
        "ProcessId": pid, "Image": image, "CommandLine": cmd, "User": user,
        "ParentProcessGuid": pguid, "ParentProcessId": ppid, "ParentImage": pimage,
        "ParentCommandLine": pcmd, "Hashes": ";".join(hashes),
    }


def sm_net(host, time, guid, pid, image, user, dip, dport, dhost="", proto="tcp"):
    return {
        "EventID": 3, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
        "ProcessId": pid, "Image": image, "User": user, "Protocol": proto,
        "SourceIp": S.HOSTS[host]["ip"], "DestinationIp": dip,
        "DestinationPort": dport, "DestinationHostname": dhost, "Initiated": True,
    }


def sm_imageload(host, time, guid, pid, image, loaded, signed, signature):
    return {
        "EventID": 7, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
        "ProcessId": pid, "Image": image, "ImageLoaded": loaded,
        "Signed": signed, "Signature": signature,
    }


def sm_lsass(host, time, sguid, spid, simage, granted, call_trace=""):
    return {
        "EventID": 10, "Computer": host, "UtcTime": time,
        "SourceProcessGUID": sguid, "SourceProcessId": spid, "SourceImage": simage,
        "TargetProcessGUID": S.G["ws_lsass"], "TargetImage":
            r"C:\Windows\System32\lsass.exe", "GrantedAccess": granted,
        "CallTrace": call_trace,
    }


def sm_filecreate(host, time, guid, pid, image, target, user):
    return {
        "EventID": 11, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
        "ProcessId": pid, "Image": image, "TargetFilename": target, "User": user,
    }


def sm_regset(host, time, guid, pid, image, target, details):
    return {
        "EventID": 13, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
        "ProcessId": pid, "Image": image, "TargetObject": target, "Details": details,
    }


def sm_wmi_filter(host, time, name, query):
    return {"EventID": 19, "Computer": host, "UtcTime": time, "Operation": "Created",
            "Name": name, "EventNamespace": "root\\cimv2", "Query": query}


def sm_wmi_consumer(host, time, name, command):
    return {"EventID": 20, "Computer": host, "UtcTime": time, "Operation": "Created",
            "Name": name, "Type": "CommandLineEventConsumer", "Destination": command}


def sm_wmi_binding(host, time, consumer, flt):
    return {"EventID": 21, "Computer": host, "UtcTime": time, "Operation": "Created",
            "Consumer": consumer, "Filter": flt}


def sm_dns(host, time, guid, pid, image, query, result):
    return {"EventID": 22, "Computer": host, "UtcTime": time, "ProcessGuid": guid,
            "ProcessId": pid, "Image": image, "QueryName": query, "QueryResults": result}


# =========================================================================== #
#  Build each host
# =========================================================================== #
def build_ws_acct_07():
    host = "WS-ACCT-07"
    d = CASE / host
    explorer = r"C:\Windows\explorer.exe"
    outlook = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
    winword = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload = S.PAYLOAD_PATH
    schtasks = r"C:\Windows\System32\schtasks.exe"
    services = r"C:\Windows\System32\services.exe"
    sys_svchost = r"C:\Windows\System32\svchost.exe"
    ccmexec = r"C:\Windows\CCM\CcmExec.exe"

    # ---- Sysmon JSONL (attack chain + benign) ----
    sm = []
    # benign baseline: services.exe -> svchost.exe in System32 (must NOT flag)
    sm.append(sm_process(host, utc("12:40:00"), S.G["ws_svchost_ok"], 980, sys_svchost,
                         r"C:\Windows\System32\svchost.exe -k netsvcs -p", "NT AUTHORITY\\SYSTEM",
                         S.G["ws_services"], 712, services,
                         r"C:\Windows\System32\services.exe",
                         sha1=S.LEGIT_SVCHOST_SHA1))
    # benign: SCCM-managed PowerShell spawned by CcmExec (must NOT flag)
    sm.append(sm_process(host, utc("12:50:00"), S.G["ws_sccm_ps"], 3344, powershell,
                         "powershell.exe -ExecutionPolicy Bypass -File "
                         r"C:\Windows\CCM\ScriptStore\inventory.ps1",
                         S.SVC_SCCM, S.G["ws_ccmexec"], 2200, ccmexec,
                         r"C:\Windows\CCM\CcmExec.exe"))
    # Attack: explorer -> OUTLOOK
    sm.append(sm_process(host, utc("13:05:10"), S.G["ws_outlook"], 4120, outlook,
                         '"OUTLOOK.EXE" /recycle', S.VICTIM, S.G["ws_explorer"], 3900,
                         explorer, r"C:\Windows\explorer.exe"))
    # OUTLOOK -> WINWORD (open the macro doc)
    sm.append(sm_process(host, utc("13:05:30"), S.G["ws_winword"], 4680, winword,
                         '"WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\Invoice_Oct.docm"',
                         S.VICTIM, S.G["ws_outlook"], 4120, outlook, '"OUTLOOK.EXE" /recycle'))
    # WINWORD -> powershell -enc  (Office -> script host: the key anomaly)
    sm.append(sm_process(host, utc("13:06:00"), S.G["ws_powershell"], 5012, powershell,
                         f"powershell.exe -nop -w hidden -enc {S.ENC_PS_B64}",
                         S.VICTIM, S.G["ws_winword"], 4680, winword,
                         '"WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\Invoice_Oct.docm"'))
    # powershell network connect to C2
    sm.append(sm_net(host, utc("13:06:05"), S.G["ws_powershell"], 5012, powershell,
                     S.VICTIM, S.C2_IP, 443, S.C2_DOMAIN))
    sm.append(sm_dns(host, utc("13:06:04"), S.G["ws_powershell"], 5012, powershell,
                     S.C2_DOMAIN, f"type:  5 {S.C2_IP};"))
    # payload dropped in APPDATA (FileCreate)
    sm.append(sm_filecreate(host, utc("13:06:30"), S.G["ws_powershell"], 5012, powershell,
                            payload, S.VICTIM))
    # payload process start (masquerade: svchost.exe outside System32, parent powershell)
    sm.append(sm_process(host, utc("13:06:31"), S.G["ws_payload"], 6102, payload,
                         f'"{payload}"', S.VICTIM, S.G["ws_powershell"], 5012, powershell,
                         f"powershell.exe -nop -w hidden -enc {S.ENC_PS_B64}",
                         sha256=S.PAYLOAD_SHA256, sha1=S.PAYLOAD_SHA1, md5=S.PAYLOAD_MD5))
    # payload loads a renamed/unsigned image (ImageLoad)
    sm.append(sm_imageload(host, utc("13:06:33"), S.G["ws_payload"], 6102, payload,
                           r"C:\Users\jsmith\AppData\Roaming\Microsoft\vcruntime.dll",
                           "false", "-"))
    # persistence: Run key set by payload
    sm.append(sm_regset(host, utc("13:06:40"), S.G["ws_payload"], 6102, payload,
                        r"HKU\S-1-5-21-1988-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
                        payload))
    # payload -> schtasks (scheduled task persistence)
    sm.append(sm_process(host, utc("13:06:45"), S.G["ws_schtasks"], 6240, schtasks,
                         'schtasks /create /tn "MicrosoftEdgeUpdateTaskUser" /tr '
                         f'"{payload}" /sc onlogon /rl highest',
                         S.VICTIM, S.G["ws_payload"], 6102, payload, f'"{payload}"'))
    # LSASS access by payload (credential access)
    sm.append(sm_lsass(host, utc("13:07:10"), S.G["ws_payload"], 6102, payload,
                       "0x1410", call_trace="C:\\Windows\\SYSTEM32\\ntdll.dll+9c534|"
                       "UNKNOWN(svchost.exe)"))
    # WMI event subscription (persistence T1546.003)
    sm.append(sm_wmi_filter(host, utc("13:08:00"), "NorthwindUpdater",
                            "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                            "WHERE TargetInstance ISA 'Win32_PerfFormattedData'"))
    sm.append(sm_wmi_consumer(host, utc("13:08:01"), "NorthwindUpdater",
                              f'"{payload}"'))
    sm.append(sm_wmi_binding(host, utc("13:08:02"), "NorthwindUpdater", "NorthwindUpdater"))
    # benign: Teams drops its own shortcut in the user's Startup folder (must NOT flag)
    sm.append(sm_filecreate(host, utc("12:55:00"), S.G["ws_teams"], 2950,
                            r"C:\Users\jsmith\AppData\Local\Microsoft\Teams\current\Teams.exe",
                            r"C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu"
                            r"\Programs\Startup\Microsoft Teams.lnk", S.VICTIM))
    # discovery (local) net user
    sm.append(sm_process(host, utc("13:08:30"), S.G["ws_net_disc"], 6400,
                         r"C:\Windows\System32\net.exe", "net user /domain",
                         S.VICTIM, S.G["ws_payload"], 6102, payload, f'"{payload}"'))
    write_jsonl(d / "sysmon.jsonl", sm)

    # ---- EvtxECmd: Security ----
    sec = []
    n = 1
    sec.append(evtx_row(n, ts("13:02:00"), 4624, "Security", host,
                        "An account was successfully logged on", provider="Microsoft-Windows-Security-Auditing",
                        user="jsmith", pd=["LogonType 2", "jsmith", S.NETBIOS, "10.20.5.17", "Interactive"],
                        payload="Logon Type: 2")); n += 1
    sec.append(evtx_row(n, ts("13:07:00"), 4698, "Security", host,
                        "A scheduled task was created", provider="Microsoft-Windows-Security-Auditing",
                        user="jsmith", pd=["MicrosoftEdgeUpdateTaskUser", S.PAYLOAD_PATH, "onlogon"],
                        payload="Task Name: \\MicrosoftEdgeUpdateTaskUser")); n += 1
    # 4688 process create for payload (gives a non-Sysmon execution witness)
    sec.append(evtx_row(n, ts("13:06:31"), 4688, "Security", host,
                        "A new process has been created", provider="Microsoft-Windows-Security-Auditing",
                        user="jsmith", pd=["0x17e6", S.PAYLOAD_PATH, powershell_name(),
                                           S.PAYLOAD_PATH],
                        payload=f"New Process Name: {S.PAYLOAD_PATH}")); n += 1
    # benign 4648: SCCM client using explicit creds against localhost (must NOT flag)
    sec.append(evtx_row(n, ts("12:49:58"), 4648, "Security", host,
                        "A logon was attempted using explicit credentials",
                        provider="Microsoft-Windows-Security-Auditing", user="svc_sccm",
                        remote="127.0.0.1",
                        pd=["svc_sccm", "svc_sccm", "localhost", "127.0.0.1",
                            r"C:\Windows\CCM\CcmExec.exe"],
                        payload="Target Server: localhost; Process: CcmExec.exe")); n += 1
    write_evtx(d / "Security_EvtxECmd.csv", sec)

    # ---- EvtxECmd: PowerShell Operational (4104 script block) ----
    ps = []
    ps.append(evtx_row(1, ts("13:06:02"), 4104, "Microsoft-Windows-PowerShell/Operational", host,
                       "Creating Scriptblock text", provider="Microsoft-Windows-PowerShell",
                       level="Warning", user="jsmith",
                       pd=["1 of 1", "ScriptBlock ID", S.DECODED_PS],
                       payload=S.DECODED_PS))
    # benign SCCM script block
    ps.append(evtx_row(2, ts("12:50:01"), 4104, "Microsoft-Windows-PowerShell/Operational", host,
                       "Creating Scriptblock text", provider="Microsoft-Windows-PowerShell",
                       level="Verbose", user="svc_sccm",
                       pd=["1 of 1", "ScriptBlock ID", "Get-WmiObject Win32_Product | Export-Csv inventory.csv"],
                       payload="Get-WmiObject Win32_Product | Export-Csv inventory.csv"))
    write_evtx(d / "PowerShell_EvtxECmd.csv", ps)

    # ---- EvtxECmd: Defender ----
    dfn = []
    dfn.append(evtx_row(1, ts("13:09:00"), 5001, "Microsoft-Windows-Windows Defender/Operational", host,
                        "Real-time protection was disabled", provider="Microsoft-Windows-Windows Defender",
                        level="Warning", user="jsmith",
                        pd=["Real-Time Protection", "Disabled"],
                        payload="Microsoft Defender Real-time Protection disabled"))
    dfn.append(evtx_row(2, ts("13:09:05"), 5007, "Microsoft-Windows-Windows Defender/Operational", host,
                        "Defender configuration changed", provider="Microsoft-Windows-Windows Defender",
                        level="Information", user="jsmith",
                        pd=["DisableRealtimeMonitoring", "0 -> 1"],
                        payload="HKLM\\...\\Real-Time Protection\\DisableRealtimeMonitoring = 1"))
    write_evtx(d / "Defender_EvtxECmd.csv", dfn)

    # ---- PECmd prefetch ----
    write_csv(d / "prefetch_PECmd.csv", PECMD_HEADER, [
        # payload: ran at drop time, then at the next two logons via its persistence
        pecmd_row(S.PAYLOAD_PATH, "1A2B3C4D", 3, ["14:02:11", "13:31:05", "13:06:31"]),
        pecmd_row(powershell_name(True), "9F8E7D6C", 12,
                  ["13:06:00", "12:50:00", "11:10:00", "09:45:12"]),
        pecmd_row(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                  "5B6C7D8E", 44, ["13:05:30", "09:14:00"]),
        pecmd_row(r"C:\Windows\System32\schtasks.exe", "2C3D4E5F", 5, ["13:06:45"]),
        pecmd_row(r"C:\Windows\System32\net.exe", "7A8B9C0D", 9, ["13:08:30"]),
    ])

    # ---- AmcacheParser (Associated file entries) ----
    write_csv(d / "amcache_AmcacheParserAssociated.csv", AMCACHE_HEADER, [
        amcache_row("13:06:31", S.PAYLOAD_SHA1, S.PAYLOAD_PATH, "svchost.exe",
                    size=184320, publisher="", product=""),
        amcache_row("12:40:00", S.LEGIT_SVCHOST_SHA1, r"C:\Windows\System32\svchost.exe",
                    "svchost.exe", size=55320, publisher="Microsoft Corporation",
                    product="Microsoft Windows Operating System"),
        amcache_row("13:06:00", S._sha("ps", "sha1"), powershell_name(True),
                    "powershell.exe", size=452608, publisher="Microsoft Corporation",
                    product="Microsoft Windows Operating System"),
    ])

    # ---- AppCompatCacheParser (shimcache) : Win10 => Executed is 'NA' ----
    write_csv(d / "appcompatcache_AppCompatCacheParser.csv", SHIM_HEADER, [
        # LastModifiedTimeUTC is the file's $SI modified time, NOT a run time:
        # the stomped payload therefore shows the backdated 2019 value.
        shim_row(0, S.PAYLOAD_PATH, "2019-03-19 04:10:11", executed="NA", literal=True),
        # present (user browsed the folder) but never executed: shimcache-only
        shim_row(1, S.SHIM_ONLY_PATH, "2026-10-12 16:22:40", executed="NA", literal=True),
        shim_row(2, r"C:\Windows\System32\svchost.exe", "2021-06-08 11:00:00",
                 executed="NA", literal=True),
        shim_row(3, powershell_name(True), "2021-06-08 11:00:00", executed="NA", literal=True),
        shim_row(4, r"C:\Windows\System32\schtasks.exe", "2021-06-08 11:00:00",
                 executed="NA", literal=True),
    ])

    # ---- RECmd Run keys ----
    write_csv(d / "runkeys_RECmd.csv", RECMD_HEADER, [
        recmd_row("13:06:40", r"Software\Microsoft\Windows\CurrentVersion\Run",
                  "OneDriveSync", S.PAYLOAD_PATH,
                  r"C:\Users\jsmith\NTUSER.DAT", "Run key autostart"),
        # benign: signed updater under Program Files (must NOT flag)
        recmd_row("2026-09-01 08:00:00", r"Software\Microsoft\Windows\CurrentVersion\Run",
                  "GoogleUpdate",
                  r'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c',
                  r"C:\Users\jsmith\NTUSER.DAT", "Run key autostart", literal_time=True),
    ])

    # ---- Scheduled task XML (malicious + benign) ----
    write_text(d / "tasks" / "MicrosoftEdgeUpdateTaskUser.xml",
               task_xml("MicrosoftEdgeUpdateTaskUser", S.PAYLOAD_PATH, S.VICTIM,
                        "2026-10-19T13:06:45", trigger="LogonTrigger", highest=True))
    write_text(d / "tasks" / "NorthwindBackup.xml",
               task_xml("NorthwindBackup", r"C:\Program Files\Northwind\backup.exe",
                        "NT AUTHORITY\\SYSTEM", "2025-04-02T02:00:00", trigger="CalendarTrigger",
                        highest=False))

    # ---- MFTECmd $MFT subset (timestomp: $SI created < $FN created) ----
    write_csv(d / "mft_MFTECmd.csv", MFT_HEADER, [
        mft_row(45120, "svchost.exe", r"\Users\jsmith\AppData\Roaming\Microsoft",
                si_created="2019-03-19T04:10:11.0000000",   # stomped back years
                fn_created="2026-10-19T13:06:30.1120000",   # true drop time
                si_modified="2019-03-19T04:10:11.0000000",
                size=184320),
        mft_row(31002, "svchost.exe", r"\Windows\System32",
                si_created="2019-03-19T04:10:11.0000000",
                fn_created="2019-03-19T04:10:11.0000000",   # legit: SI == FN
                si_modified="2021-06-08T11:00:00.0000000",
                size=55320),
        mft_row(52231, "Invoice_Oct.docm", r"\Users\jsmith\Downloads",
                si_created="2026-10-19T13:04:55.0000000",
                fn_created="2026-10-19T13:04:55.0000000",
                si_modified="2026-10-19T13:05:00.0000000",
                size=38211),
    ])


def powershell_name(full: bool = False) -> str:
    p = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return p if full else "powershell.exe"


# --------------------------------------------------------------------------- #
# FS-01 (file server): lateral via service, staging, log clear
# --------------------------------------------------------------------------- #
def build_fs_01():
    host = "FS-01"
    d = CASE / host
    services = r"C:\Windows\System32\services.exe"
    psexesvc = r"C:\Windows\PSEXESVC.exe"
    cmd = r"C:\Windows\System32\cmd.exe"
    archiver = r"C:\Users\Public\7za.exe"
    net = r"C:\Windows\System32\net.exe"
    vendorsvc = r"C:\Program Files\Contoso\Agent\ContosoAgent.exe"

    sm = []
    # service.exe -> PSEXESVC (lateral tool exec)
    sm.append(sm_process(host, utc("13:15:20"), S.G["fs_psexesvc"], 2608, psexesvc,
                         r"C:\Windows\PSEXESVC.exe", "NT AUTHORITY\\SYSTEM",
                         S.G["fs_services"], 704, services, r"C:\Windows\System32\services.exe"))
    # PSEXESVC -> cmd
    sm.append(sm_process(host, utc("13:15:30"), S.G["fs_cmd"], 2710, cmd,
                         r"cmd.exe /c", "NT AUTHORITY\\SYSTEM",
                         S.G["fs_psexesvc"], 2608, psexesvc, r"C:\Windows\PSEXESVC.exe"))
    # discovery from the file server shell
    sm.append(sm_process(host, utc("13:16:00"), S.G["fs_net_disc"], 2900, net,
                         'net view \\\\DC-01', "NT AUTHORITY\\SYSTEM",
                         S.G["fs_cmd"], 2710, cmd, r"cmd.exe /c"))
    # staging: archiver writes to C:\PerfLogs
    sm.append(sm_process(host, utc("13:25:00"), S.G["fs_archiver"], 3120, archiver,
                         r'7za.exe a -p<redacted> C:\PerfLogs\data.7z \\FS-01\Finance\*',
                         "NT AUTHORITY\\SYSTEM", S.G["fs_cmd"], 2710, cmd, r"cmd.exe /c"))
    sm.append(sm_filecreate(host, utc("13:25:40"), S.G["fs_archiver"], 3120, archiver,
                            r"C:\PerfLogs\data.7z", "NT AUTHORITY\\SYSTEM"))
    # benign vendor service process (signed) - must NOT flag
    sm.append(sm_process(host, utc("11:00:00"), S.G["fs_vendorsvc"], 1500, vendorsvc,
                         r'"C:\Program Files\Contoso\Agent\ContosoAgent.exe" --run',
                         "NT AUTHORITY\\SYSTEM", S.G["fs_services"], 704, services,
                         r"C:\Windows\System32\services.exe"))
    write_jsonl(d / "sysmon.jsonl", sm)

    # Security: network logon (type 3) + 4672 + 7045 service install + 1102 clear
    sec = []
    n = 1
    sec.append(evtx_row(n, ts("13:15:10"), 4624, "Security", host,
                        "An account was successfully logged on",
                        provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                        remote="10.20.5.17",
                        pd=["LogonType 3", "jsmith", S.NETBIOS, "10.20.5.17", "Network"],
                        payload="Logon Type: 3")); n += 1
    sec.append(evtx_row(n, ts("13:15:11"), 4672, "Security", host,
                        "Special privileges assigned to new logon",
                        provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                        pd=["SeDebugPrivilege", "SeTcbPrivilege", "jsmith"],
                        payload="Privileges: SeDebugPrivilege")); n += 1
    sec.append(evtx_row(n, ts("13:15:15"), 4697, "Security", host,
                        "A service was installed in the system",
                        provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                        pd=["PSEXESVC", r"C:\Windows\PSEXESVC.exe", "own process"],
                        payload="Service Name: PSEXESVC")); n += 1
    # 1102 audit log cleared (defense evasion)
    sec.append(evtx_row(n, ts("13:30:00"), 1102, "Security", host,
                        "The audit log was cleared",
                        provider="Microsoft-Windows-Eventlog", level="Information",
                        user="jsmith", pd=["jsmith", S.NETBIOS],
                        payload="The audit log was cleared by NORTHWIND\\jsmith")); n += 1
    write_evtx(d / "Security_EvtxECmd.csv", sec)

    # System: 7045 service install (malicious PSEXESVC + benign Contoso signed)
    system = []
    system.append(evtx_row(1, ts("13:15:15"), 7045, "System", host,
                           "A new service was installed",
                           provider="Service Control Manager", user="SYSTEM",
                           pd=["PSEXESVC", r"%SystemRoot%\PSEXESVC.exe", "user input", "unsigned"],
                           payload="Service Name: PSEXESVC; Image: %SystemRoot%\\PSEXESVC.exe"))
    system.append(evtx_row(2, ts("11:00:05"), 7045, "System", host,
                           "A new service was installed",
                           provider="Service Control Manager", user="SYSTEM",
                           pd=["ContosoAgent", r"C:\Program Files\Contoso\Agent\ContosoAgent.exe",
                               "auto start", "signed:Contoso Ltd"],
                           payload="Service Name: ContosoAgent; signed by Contoso Ltd"))
    write_evtx(d / "System_EvtxECmd.csv", system)

    # Prefetch on FS-01
    write_csv(d / "prefetch_PECmd.csv", PECMD_HEADER, [
        pecmd_row(r"C:\Windows\PSEXESVC.exe", "4D5E6F70", 1, ["13:15:20"]),
        pecmd_row(r"C:\Users\Public\7za.exe", "8E9F0A1B", 1, ["13:25:00"]),
    ])
    # Amcache
    write_csv(d / "amcache_AmcacheParserAssociated.csv", AMCACHE_HEADER, [
        amcache_row("13:15:20", S._sha("psexesvc", "sha1"), r"C:\Windows\PSEXESVC.exe",
                    "PSEXESVC.exe", size=165280, publisher="", product="Sysinternals PsExec"),
        amcache_row("13:25:00", S._sha("7za", "sha1"), r"C:\Users\Public\7za.exe",
                    "7za.exe", size=632320, publisher="", product="7-Zip"),
    ])
    # Shimcache
    write_csv(d / "appcompatcache_AppCompatCacheParser.csv", SHIM_HEADER, [
        shim_row(0, r"C:\Windows\PSEXESVC.exe", "13:15:20", executed="NA"),
        shim_row(1, r"C:\Users\Public\7za.exe", "13:25:00", executed="NA"),
    ])


# --------------------------------------------------------------------------- #
# DC-01: RDP in + Kerberoasting + discovery
# --------------------------------------------------------------------------- #
def build_dc_01():
    host = "DC-01"
    d = CASE / host
    cmd = r"C:\Windows\System32\cmd.exe"
    net = r"C:\Windows\System32\net.exe"
    nltest = r"C:\Windows\System32\nltest.exe"
    whoami = r"C:\Windows\System32\whoami.exe"

    sm = []
    explorer = r"C:\Windows\explorer.exe"
    # RDP session shell: userinit -> explorer -> cmd (parent of the discovery)
    sm.append(sm_process(host, utc("13:20:05"), S.G["dc_explorer"], 3980, explorer,
                         r"C:\Windows\Explorer.EXE", S.VICTIM, S.G["dc_userinit"], 3960,
                         r"C:\Windows\System32\userinit.exe", r"C:\Windows\system32\userinit.exe"))
    sm.append(sm_process(host, utc("13:20:20"), S.G["dc_rdp_shell"], 4100, cmd,
                         r'"C:\Windows\System32\cmd.exe"', S.VICTIM, S.G["dc_explorer"], 3980,
                         explorer, r"C:\Windows\Explorer.EXE"))
    # a shell from the RDP session running discovery
    sm.append(sm_process(host, utc("13:20:30"), S.G["dc_netgroup"], 4400, net,
                         'net group "domain admins" /domain', S.VICTIM,
                         S.G["dc_rdp_shell"], 4100, cmd, r'"C:\Windows\System32\cmd.exe"'))
    sm.append(sm_process(host, utc("13:20:45"), S.G["dc_nltest"], 4420, nltest,
                         "nltest /dclist:northwind.example", S.VICTIM,
                         S.G["dc_rdp_shell"], 4100, cmd, r'"C:\Windows\System32\cmd.exe"'))
    sm.append(sm_process(host, utc("13:21:00"), S.G["dc_whoami"], 4440, whoami,
                         "whoami /all", S.VICTIM,
                         S.G["dc_rdp_shell"], 4100, cmd, r'"C:\Windows\System32\cmd.exe"'))
    write_jsonl(d / "sysmon.jsonl", sm)

    # Security: 4624 type10 (attacker RDP), 4672, and 4769 Kerberoast TGS
    sec = []
    n = 1
    sec.append(evtx_row(n, ts("13:20:00"), 4624, "Security", host,
                        "An account was successfully logged on",
                        provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                        remote="10.20.5.17",
                        pd=["LogonType 10", "jsmith", S.NETBIOS, "10.20.5.17", "RemoteInteractive"],
                        payload="Logon Type: 10")); n += 1
    sec.append(evtx_row(n, ts("13:20:01"), 4672, "Security", host,
                        "Special privileges assigned to new logon",
                        provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                        pd=["SeDebugPrivilege", "SeBackupPrivilege", "jsmith"],
                        payload="Privileges: SeDebugPrivilege")); n += 1
    # benign admin RDP from the jump host in business hours (allowlisted, ticket CHG0012345)
    sec.append(evtx_row(n, ts("15:30:00"), 4624, "Security", host,
                        "An account was successfully logged on",
                        provider="Microsoft-Windows-Security-Auditing", user="admin.rdp",
                        remote="10.20.0.50",
                        pd=["LogonType 10", "admin.rdp", S.NETBIOS, "10.20.0.50", "RemoteInteractive"],
                        payload="Logon Type: 10")); n += 1
    # 4769 Kerberoasting: several SPNs, RC4 (0x17), one requesting account, short window
    kerb_times = ["13:10:00", "13:10:12", "13:10:25", "13:10:41"]
    for (svc, spn), tt in zip(S.KERBEROAST_TARGETS, kerb_times):
        sec.append(evtx_row(n, ts(tt), 4769, "Security", host,
                            "A Kerberos service ticket was requested",
                            provider="Microsoft-Windows-Security-Auditing", user="jsmith",
                            remote="10.20.5.17",
                            pd=[svc, "jsmith@NORTHWIND.EXAMPLE", "0x17", "0x0", "10.20.5.17"],
                            payload=f"Service Name: {svc} (SPN {spn}); Ticket Encryption Type: 0x17 (RC4)")); n += 1
    # benign 4769 with AES (0x12) for a normal service - must NOT be Kerberoast
    sec.append(evtx_row(n, ts("08:05:00"), 4769, "Security", host,
                        "A Kerberos service ticket was requested",
                        provider="Microsoft-Windows-Security-Auditing", user="bwilliams",
                        remote="10.20.5.40",
                        pd=["FS-01$", "bwilliams@NORTHWIND.EXAMPLE",
                            "0x12", "0x0", "10.20.5.40"],
                        payload="Ticket Encryption Type: 0x12 (AES256)")); n += 1
    write_evtx(d / "Security_EvtxECmd.csv", sec)

    # TerminalServices: 1149 for both attacker and benign admin
    tsl = []
    tsl.append(evtx_row(1, ts("13:19:58"), 1149,
                        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                        host, "Remote Desktop Services: User authentication succeeded",
                        provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                        user="jsmith", remote="10.20.5.17",
                        pd=["jsmith", S.NETBIOS, "10.20.5.17"],
                        payload="User: jsmith Source Network Address: 10.20.5.17"))
    tsl.append(evtx_row(2, ts("15:29:58"), 1149,
                        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                        host, "Remote Desktop Services: User authentication succeeded",
                        provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                        user="admin.rdp", remote="10.20.0.50",
                        pd=["admin.rdp", S.NETBIOS, "10.20.0.50"],
                        payload="User: admin.rdp Source Network Address: 10.20.0.50"))
    write_evtx(d / "TerminalServices_EvtxECmd.csv", tsl)


# --------------------------------------------------------------------------- #
# format headers + row builders
# --------------------------------------------------------------------------- #
PECMD_HEADER = ["Note", "SourceFilename", "SourceCreated", "SourceModified", "ExecutableName",
                "Hash", "Size", "Version", "RunCount", "LastRun",
                "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3",
                "PreviousRun4", "PreviousRun5", "PreviousRun6",
                "Volume0Name", "Volume0Serial", "Directories", "FilesLoaded"]


def pecmd_row(exe_path, pf_hash, run_count, runs):
    """``runs`` is newest-first; PECmd puts runs[0] in LastRun and up to seven
    earlier runs in PreviousRun0..6 (Windows 8+ keeps the last eight)."""
    exe = exe_path.rsplit("\\", 1)[-1].upper()
    stamps = [f"{D} {r}.0000000" for r in runs][:8]
    prev = (stamps[1:] + [""] * 7)[:7]
    vol_path = "\\VOLUME{01dc2b6f7a1e2c40-3e5b8c11}" + exe_path[2:].upper()
    row = {
        "Note": "", "SourceFilename": f"C:\\Windows\\Prefetch\\{exe}-{pf_hash}.pf",
        "SourceCreated": stamps[-1], "SourceModified": stamps[0],
        "ExecutableName": exe, "Hash": pf_hash, "Size": 90112, "Version": "Windows 10 or Windows 11",
        "RunCount": run_count, "LastRun": stamps[0],
        "Volume0Name": "\\VOLUME{01dc2b6f7a1e2c40-3e5b8c11}", "Volume0Serial": "3E5B8C11",
        "Directories": vol_path.rsplit("\\", 1)[0],
        "FilesLoaded": f"\\VOLUME{{01dc2b6f7a1e2c40-3e5b8c11}}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, {vol_path}",
    }
    for i, v in enumerate(prev):
        row[f"PreviousRun{i}"] = v
    return row


AMCACHE_HEADER = ["ApplicationName", "FileKeyLastWriteTimestamp", "SHA1", "FullPath",
                  "Name", "Size", "LinkDate", "ProductName", "Publisher",
                  "IsOsComponent"]


def amcache_row(write_time, sha1, fullpath, name, size, publisher="", product=""):
    return {
        "ApplicationName": "Unassociated", "FileKeyLastWriteTimestamp": f"{D} {write_time}.0000000",
        "SHA1": sha1, "FullPath": fullpath, "Name": name, "Size": size,
        "LinkDate": "", "ProductName": product, "Publisher": publisher,
        "IsOsComponent": "true" if publisher == "Microsoft Corporation" else "false",
    }


SHIM_HEADER = ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC",
               "Executed", "Duplicate", "SourceFile"]


def shim_row(pos, path, lmt, executed="NA", literal=False):
    return {
        "ControlSet": "ControlSet001", "CacheEntryPosition": pos, "Path": path,
        "LastModifiedTimeUTC": f"{lmt}.0000000" if literal else f"{D} {lmt}.0000000",
        "Executed": executed,
        "Duplicate": "false", "SourceFile": "SYSTEM",
    }


RECMD_HEADER = ["LastWriteTimestamp", "KeyPath", "ValueName", "ValueData",
                "ValueData2", "Deleted", "HivePath", "Comment"]


def recmd_row(write_time, keypath, value_name, value_data, hive, comment, literal_time=False):
    t = write_time if literal_time else f"{D} {write_time}.0000000"
    return {
        "LastWriteTimestamp": t, "KeyPath": keypath, "ValueName": value_name,
        "ValueData": value_data, "ValueData2": "", "Deleted": "false",
        "HivePath": hive, "Comment": comment,
    }


MFT_HEADER = ["EntryNumber", "SequenceNumber", "InUse", "ParentPath", "FileName",
              "Extension", "FileSize", "Created0x10", "Created0x30",
              "LastModified0x10", "LastModified0x30", "LastRecordChange0x10"]


def mft_row(entry, filename, parent, si_created, fn_created, si_modified, size):
    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    return {
        "EntryNumber": entry, "SequenceNumber": 1, "InUse": "True",
        "ParentPath": parent, "FileName": filename, "Extension": ext,
        "FileSize": size, "Created0x10": si_created, "Created0x30": fn_created,
        "LastModified0x10": si_modified, "LastModified0x30": fn_created,
        "LastRecordChange0x10": si_modified,
    }


def task_xml(name, exe, principal, created, trigger="LogonTrigger", highest=True):
    level = "HighestAvailable" if highest else "LeastPrivilege"
    trig = ("    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>\n"
            if trigger == "LogonTrigger"
            else "    <CalendarTrigger>\n      <StartBoundary>2025-04-02T02:00:00</StartBoundary>\n"
                 "      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n"
                 "    </CalendarTrigger>\n")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{created}</Date>
    <Author>{principal}</Author>
    <URI>\\{name}</URI>
  </RegistrationInfo>
  <Triggers>
{trig}  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{principal}</UserId>
      <RunLevel>{level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>{'true' if highest and name.startswith('Microsoft') else 'false'}</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
    </Exec>
  </Actions>
</Task>
"""


def resolve_benign_rows(case_dir: Path) -> list[dict]:
    """Map each benign look-alike marker to the artifact row that holds it."""
    out = []
    for label, host, fname, marker in S.BENIGN:
        hits = list((case_dir / host).rglob(fname))
        if not hits:
            raise SystemExit(f"benign artifact missing: {host}/{fname}")
        path = hits[0]
        row = 0
        if marker is not None:
            lines = path.read_text(encoding="utf-8").splitlines()
            start = 1 if path.suffix == ".csv" else 0   # skip CSV header
            matches = [i - start + 1 for i, ln in enumerate(lines)
                       if i >= start and marker in ln]
            if len(matches) != 1:
                raise SystemExit(f"benign marker {marker!r} matched {len(matches)} rows in {fname}")
            row = matches[0]
        out.append({"label": label, "host": host, "source": fname, "row": row})
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse
    global CASE
    ap = argparse.ArgumentParser(description="Generate the synthetic Northwind case.")
    ap.add_argument("--out", default=str(ROOT / "case"), help="case output directory")
    ap.add_argument("--ground-truth", default=str(GROUND_TRUTH),
                    help="where to write ground_truth.json")
    args = ap.parse_args(argv)
    CASE = Path(args.out)
    build_ws_acct_07()
    build_fs_01()
    build_dc_01()
    gt = S.ground_truth(resolve_benign_rows(CASE))
    gt_path = Path(args.ground_truth)
    gt_path.parent.mkdir(parents=True, exist_ok=True)
    gt_path.write_text(json.dumps(gt, indent=2) + "\n", encoding="utf-8")
    print(f"Generated synthetic case under {CASE}")
    for host in S.HOSTS:
        files = sorted(p.name for p in (CASE / host).glob("*") if p.is_file())
        tasks = sorted(p.name for p in (CASE / host / "tasks").glob("*.xml"))
        extra = f" + tasks/{len(tasks)}" if tasks else ""
        print(f"  {host}: {len(files)} files{extra}")
    print(f"Ground truth: {gt_path} ({len(gt['expected_findings'])} planted facts, "
          f"{len(gt['benign'])} benign look-alikes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
