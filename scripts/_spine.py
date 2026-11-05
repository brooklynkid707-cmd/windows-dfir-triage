"""The incident 'spine': every planted fact for the Northwind Logistics case.

This module holds the *story* as structured Python so that both the artifact
generator (scripts/generate_case.py) and the ground-truth file used by the
tests (tests/ground_truth.json) read from one source. Nothing in this file is
executable attacker code; command lines are evidence strings only, and all
network indicators use RFC 5737 / RFC 1918 ranges.

Case:   Northwind Logistics (fictional), internal domain northwind.example
Hosts:  WS-ACCT-07 (patient zero), FS-01 (file server), DC-01 (domain controller)
Date:   2026-10-19, all times UTC (Houston office = UTC-5 in October)
"""
from __future__ import annotations

import hashlib

DOMAIN = "northwind.example"
NETBIOS = "NORTHWIND"
DATE = "2026-10-19"

HOSTS = {
    "WS-ACCT-07": {"ip": "10.20.5.17", "role": "workstation", "os": "Windows 10 22H2"},
    "FS-01": {"ip": "10.20.1.10", "role": "file-server", "os": "Windows Server 2019"},
    "DC-01": {"ip": "10.20.1.5", "role": "domain-controller", "os": "Windows Server 2019"},
}
JUMP_HOST = {"name": "JUMP-01", "ip": "10.20.0.50"}

ATTACKER_IP = "203.0.113.10"        # RFC 5737 documentation range
C2_DOMAIN = "sync-cdn.example"
C2_IP = "198.51.100.25"             # RFC 5737 documentation range

VICTIM = f"{NETBIOS}\\jsmith"
SVC_SCCM = f"{NETBIOS}\\svc_sccm"


def _sha(label: str, algo: str) -> str:
    """Hashes derived from fixed labels: reproducible and obviously synthetic."""
    return hashlib.new(algo, label.encode()).hexdigest()


PAYLOAD_LABEL = "northwind-synthetic-payload-svchost-v1"
PAYLOAD_SHA256 = _sha(PAYLOAD_LABEL, "sha256")
PAYLOAD_SHA1 = _sha(PAYLOAD_LABEL, "sha1")
PAYLOAD_MD5 = _sha(PAYLOAD_LABEL, "md5")
PAYLOAD_PATH = r"C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe"
STAGED_ARCHIVE = r"C:\PerfLogs\data.7z"
# A portable tool the user downloaded a week earlier and never ran: it is in
# Shimcache (the folder was browsed) and nowhere else.
SHIM_ONLY_PATH = r"C:\Users\jsmith\Downloads\ProcessExplorer\procexp64.exe"

LEGIT_SVCHOST = r"C:\Windows\System32\svchost.exe"
LEGIT_SVCHOST_SHA1 = _sha("legit-system32-svchost", "sha1")

# Kerberoast targets: (service account, SPN registered on it).
# Real 4769 events log the *service account* as "Service Name", not the SPN.
KERBEROAST_TARGETS = [
    ("svc_sql", "MSSQLSvc/fs-01.northwind.example:1433"),
    ("svc_web", "HTTP/intranet.northwind.example"),
    ("svc_fileshare", "CIFS/fs-01.northwind.example"),
    ("svc_erp", "MSSQLSvc/fs-01.northwind.example:ERP"),
]

# Hand-assigned GUIDs so parent/child references line up across events.
G = {
    "ws_explorer": "{a1b2c3d4-1001-0000-0000-000000000001}",
    "ws_outlook": "{a1b2c3d4-1001-0000-0000-000000000002}",
    "ws_winword": "{a1b2c3d4-1001-0000-0000-000000000003}",
    "ws_powershell": "{a1b2c3d4-1001-0000-0000-000000000004}",
    "ws_payload": "{a1b2c3d4-1001-0000-0000-000000000005}",
    "ws_schtasks": "{a1b2c3d4-1001-0000-0000-000000000006}",
    "ws_net_disc": "{a1b2c3d4-1001-0000-0000-000000000007}",
    "ws_lsass": "{a1b2c3d4-1001-0000-0000-00000000000a}",
    "ws_services": "{a1b2c3d4-1001-0000-0000-0000000000a0}",
    "ws_svchost_ok": "{a1b2c3d4-1001-0000-0000-0000000000a1}",
    "ws_ccmexec": "{a1b2c3d4-1001-0000-0000-0000000000a2}",
    "ws_sccm_ps": "{a1b2c3d4-1001-0000-0000-0000000000a3}",
    "ws_teams": "{a1b2c3d4-1001-0000-0000-0000000000a4}",
    "fs_services": "{b1b2c3d4-2001-0000-0000-0000000000a0}",
    "fs_psexesvc": "{b1b2c3d4-2001-0000-0000-000000000010}",
    "fs_cmd": "{b1b2c3d4-2001-0000-0000-000000000011}",
    "fs_archiver": "{b1b2c3d4-2001-0000-0000-000000000012}",
    "fs_net_disc": "{b1b2c3d4-2001-0000-0000-000000000013}",
    "fs_vendorsvc": "{b1b2c3d4-2001-0000-0000-0000000000b0}",
    "dc_userinit": "{c1b2c3d4-3001-0000-0000-00000000001e}",
    "dc_explorer": "{c1b2c3d4-3001-0000-0000-00000000001f}",
    "dc_rdp_shell": "{c1b2c3d4-3001-0000-0000-000000000020}",
    "dc_nltest": "{c1b2c3d4-3001-0000-0000-000000000021}",
    "dc_netgroup": "{c1b2c3d4-3001-0000-0000-000000000022}",
    "dc_whoami": "{c1b2c3d4-3001-0000-0000-000000000023}",
}

# The -enc argument and its "decoded" 4104 text are inert evidence strings: the
# base64 is a truncated placeholder, and the decoded text only names the
# documentation-range C2. Neither is runnable.
ENC_PS_B64 = "SQBFAFgAIAAoAEkATgBFAFIAVAAtAFMAQQBNAFAATABFACkA"
DECODED_PS = (
    "# INERT SAMPLE DATA - reconstructed script block, not runnable; "
    "$u = 'http://sync-cdn.example/u'; $ip = '203.0.113.10'; "
    "<download-and-run stub removed>"
)


def expected_findings() -> list[dict]:
    """Planted facts as (technique, host) pairs a correct triage must recover."""
    ws, fs, dc = "WS-ACCT-07", "FS-01", "DC-01"
    return [
        {"id": "IA-1", "tactic": "Initial Access", "technique": "T1566.001", "host": ws,
         "fact": "Macro document opened in WINWORD launched PowerShell"},
        {"id": "EX-1", "tactic": "Execution", "technique": "T1059.001", "host": ws,
         "fact": "WINWORD.EXE spawned powershell.exe -enc"},
        {"id": "C2-1", "tactic": "Command and Control", "technique": "T1071.001", "host": ws,
         "fact": "PowerShell connected to sync-cdn.example (198.51.100.25:443)"},
        {"id": "DE-1", "tactic": "Defense Evasion", "technique": "T1036.005", "host": ws,
         "fact": "svchost.exe running from %APPDATA%\\Microsoft"},
        {"id": "DE-2", "tactic": "Defense Evasion", "technique": "T1070.006", "host": ws,
         "fact": "Payload $SI created backdated before $FN created"},
        {"id": "DE-3", "tactic": "Defense Evasion", "technique": "T1562.001", "host": ws,
         "fact": "Defender real-time protection disabled (5001)"},
        {"id": "PE-1", "tactic": "Persistence", "technique": "T1547.001", "host": ws,
         "fact": "HKCU Run value OneDriveSync -> payload"},
        {"id": "PE-2", "tactic": "Persistence", "technique": "T1053.005", "host": ws,
         "fact": "Scheduled task MicrosoftEdgeUpdateTaskUser -> payload"},
        {"id": "PE-3", "tactic": "Persistence", "technique": "T1546.003", "host": ws,
         "fact": "WMI subscription NorthwindUpdater -> payload"},
        {"id": "CA-1", "tactic": "Credential Access", "technique": "T1003.001", "host": ws,
         "fact": "Payload opened LSASS with GrantedAccess 0x1410"},
        {"id": "DI-1", "tactic": "Discovery", "technique": "T1087.002", "host": ws,
         "fact": "net user /domain"},
        {"id": "CA-2", "tactic": "Credential Access", "technique": "T1558.003", "host": dc,
         "fact": "4 RC4 (0x17) TGS requests for 4 service accounts in 41 s"},
        {"id": "LM-1", "tactic": "Lateral Movement", "technique": "T1021.002", "host": fs,
         "fact": "Type 3 logon + PSEXESVC service install from WS-ACCT-07"},
        {"id": "PE-4", "tactic": "Persistence", "technique": "T1543.003", "host": fs,
         "fact": "PSEXESVC service installed from C:\\Windows (7045)"},
        {"id": "DI-2", "tactic": "Discovery", "technique": "T1135", "host": fs,
         "fact": "net view \\\\DC-01"},
        {"id": "CO-1", "tactic": "Collection", "technique": "T1560.001", "host": fs,
         "fact": "7za.exe archived the Finance share with a password"},
        {"id": "CO-2", "tactic": "Collection", "technique": "T1074.001", "host": fs,
         "fact": "Archive staged at C:\\PerfLogs\\data.7z"},
        {"id": "DE-4", "tactic": "Defense Evasion", "technique": "T1070.001", "host": fs,
         "fact": "Security log cleared (1102)"},
        {"id": "LM-2", "tactic": "Lateral Movement", "technique": "T1021.001", "host": dc,
         "fact": "RDP (Type 10 + 1149) from WS-ACCT-07 as jsmith"},
        {"id": "DI-3", "tactic": "Discovery", "technique": "T1069.002", "host": dc,
         "fact": "net group \"domain admins\" /domain"},
        {"id": "DI-4", "tactic": "Discovery", "technique": "T1018", "host": dc,
         "fact": "nltest /dclist:northwind.example"},
        {"id": "DI-5", "tactic": "Discovery", "technique": "T1033", "host": dc,
         "fact": "whoami /all"},
    ]


# Benign look-alikes: (label, host, artifact file, marker string that appears
# in exactly the benign record). The generator resolves each marker to a row so
# the ground truth can say "no finding may cite this row".
BENIGN = [
    ("Signed updater Run key under Program Files (GoogleUpdate)",
     "WS-ACCT-07", "runkeys_RECmd.csv", "GoogleUpdate"),
    ("IT scheduled task NorthwindBackup (Program Files, SYSTEM)",
     "WS-ACCT-07", "NorthwindBackup.xml", None),
    ("Admin RDP from JUMP-01 in business hours, ticket CHG0012345 (4624)",
     "DC-01", "Security_EvtxECmd.csv", "admin.rdp"),
    ("Admin RDP from JUMP-01 in business hours, ticket CHG0012345 (1149)",
     "DC-01", "TerminalServices_EvtxECmd.csv", "admin.rdp"),
    ("SCCM PowerShell spawned by CcmExec.exe (Sysmon 1)",
     "WS-ACCT-07", "sysmon.jsonl", "CcmExec.exe"),
    ("SCCM inventory script block (4104)",
     "WS-ACCT-07", "PowerShell_EvtxECmd.csv", "svc_sccm"),
    ("svchost.exe in System32 spawned by services.exe (Sysmon 1)",
     "WS-ACCT-07", "sysmon.jsonl", "-k netsvcs"),
    ("svchost.exe in System32 ($MFT, $SI == $FN)",
     "WS-ACCT-07", "mft_MFTECmd.csv", "\\Windows\\System32"),
    ("Signed vendor service ContosoAgent (7045)",
     "FS-01", "System_EvtxECmd.csv", "ContosoAgent"),
    ("Signed vendor service ContosoAgent process (Sysmon 1)",
     "FS-01", "sysmon.jsonl", "ContosoAgent"),
    ("AES (0x12) Kerberos service ticket for a normal user",
     "DC-01", "Security_EvtxECmd.csv", "bwilliams"),
    ("Teams shortcut written to the Startup folder by Teams.exe",
     "WS-ACCT-07", "sysmon.jsonl", "Microsoft Teams.lnk"),
    ("4648 explicit credentials to localhost by SCCM",
     "WS-ACCT-07", "Security_EvtxECmd.csv", "localhost"),
]


def ground_truth(benign_rows: list[dict]) -> dict:
    """Planted facts a correct triage must recover (read only by tests/scoring)."""
    return {
        "case": "Northwind Logistics intrusion (synthetic)",
        "patient_zero": "WS-ACCT-07",
        "payload": {
            "name": "svchost.exe", "path": PAYLOAD_PATH,
            "sha256": PAYLOAD_SHA256, "sha1": PAYLOAD_SHA1,
            "execution_confidence": "confirmed", "prefetch_run_count": 3,
        },
        "shimcache_only": {"path": SHIM_ONLY_PATH, "host": "WS-ACCT-07",
                           "execution_confidence": "possible"},
        "expected_findings": expected_findings(),
        "lateral_edges": [
            {"src": "WS-ACCT-07", "dst": "FS-01", "method": "service"},
            {"src": "WS-ACCT-07", "dst": "DC-01", "method": "rdp"},
        ],
        "kerberoast": {"requester": "jsmith", "host": "DC-01",
                       "service_accounts": sorted(a for a, _ in KERBEROAST_TARGETS)},
        "iocs": {
            "sha256": [PAYLOAD_SHA256],
            "paths": sorted([PAYLOAD_PATH, STAGED_ARCHIVE]),
            "ips": sorted([ATTACKER_IP, C2_IP]),
            "domains": [C2_DOMAIN],
        },
        "benign": benign_rows,
    }
