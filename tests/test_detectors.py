"""Persistence, credential access, lateral movement and evasion detectors:
each fires on the planted activity and stays quiet on its benign look-alike."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dfirt import credential, evasion, lateral, persistence
from dfirt.model import Event

from conftest import cited_rows

T0 = datetime(2026, 10, 19, 13, 10, tzinfo=timezone.utc)


def tgs(i, svc, etype="0x17", acct="eve@NORTHWIND.EXAMPLE", dt=10):
    return Event(T0 + timedelta(seconds=i * dt), "DC", "security", "kerberos_tgs",
                 {"event_id": 4769, "service_name": svc, "account": acct,
                  "ticket_encryption": etype}, source="Security_EvtxECmd.csv", row=i + 1)


# --------------------------------------------------------------- persistence
def test_run_key_payload_fires_with_both_sources(result):
    f = next(f for f in result.findings if f.technique == "T1547.001")
    assert "OneDriveSync" in f.title
    assert {e.source for e in f.evidence} == {"runkeys_RECmd.csv", "sysmon.jsonl"}


def test_googleupdate_run_key_is_quiet(case):
    found = persistence.detect_run_keys(case.events, "WS-ACCT-07")
    assert [f.key for f in found] == ["persistence:run_key:WS-ACCT-07:onedrivesync"]


def test_run_key_named_like_allowlist_but_in_appdata_still_fires():
    ev = Event(T0, "H", "registry", "run_key",
               {"value_name": "GoogleUpdate", "key_path": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "value_data": r"C:\Users\x\AppData\Local\Temp\GoogleUpdate.exe"}, "r.csv", 1)
    assert len(persistence.detect_run_keys([ev], "H")) == 1


def test_scheduled_task_payload_fires_backup_task_quiet(case):
    found = persistence.detect_scheduled_tasks(case.tasks, case.events, "WS-ACCT-07")
    assert [f.key for f in found] == ["persistence:task:WS-ACCT-07:microsoftedgeupdatetaskuser"]
    assert any(e.source == "Security_EvtxECmd.csv" for e in found[0].evidence)   # 4698 corroborates


def test_service_psexesvc_fires_signed_vendor_quiet(case):
    found = persistence.detect_services(case.events, "FS-01")
    assert [f.key for f in found] == ["persistence:service:FS-01:psexesvc"]


def test_wmi_subscription_cites_filter_consumer_binding(case):
    (f,) = persistence.detect_wmi(case.events, "WS-ACCT-07")
    assert f.technique == "T1546.003"
    assert len(f.evidence) == 3


def test_startup_folder_teams_quiet_unknown_writer_fires(case):
    assert persistence.detect_startup_folder(case.events, "WS-ACCT-07") == []
    ev = Event(T0, "H", "sysmon", "file_create",
               {"image": r"C:\Users\x\AppData\Roaming\upd.exe",
                "target_filename": r"C:\Users\x\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\upd.lnk"},
               "sysmon.jsonl", 9)
    assert len(persistence.detect_startup_folder([ev], "H")) == 1


# ---------------------------------------------------------------- credential
def test_kerberoast_fires_on_case(case, gt):
    (f,) = credential.detect_kerberoasting(case.events, "DC-01")
    assert f.technique == "T1558.003" and f.severity == "critical"
    for svc in gt["kerberoast"]["service_accounts"]:
        assert svc in f.description


def test_kerberoast_aes_tickets_do_not_fire():
    evs = [tgs(i, f"svc_{i}", etype="0x12") for i in range(6)]
    assert credential.detect_kerberoasting(evs, "DC") == []


def test_kerberoast_spn_count_threshold():
    n = credential.KERBEROAST_MIN_SPNS
    below = [tgs(i, f"svc_{i}") for i in range(n - 1)]
    at = [tgs(i, f"svc_{i}") for i in range(n)]
    repeat = [tgs(i, "svc_sql") for i in range(10)]        # many tickets, one SPN
    assert credential.detect_kerberoasting(below, "DC") == []
    assert len(credential.detect_kerberoasting(at, "DC")) == 1
    assert credential.detect_kerberoasting(repeat, "DC") == []


def test_kerberoast_spread_over_hours_does_not_fire():
    evs = [tgs(i, f"svc_{i}", dt=3600) for i in range(5)]
    assert credential.detect_kerberoasting(evs, "DC") == []


def test_kerberoast_machine_accounts_ignored():
    evs = [tgs(i, f"HOST{i}$") for i in range(5)]
    assert credential.detect_kerberoasting(evs, "DC") == []


def test_lsass_access_payload_fires_system_reader_quiet(case):
    (f,) = credential.detect_lsass_access(case.events, "WS-ACCT-07")
    assert "0x1410" in f.description
    ok = Event(T0, "H", "sysmon", "process_access",
               {"source_image": r"C:\Windows\System32\wininit.exe",
                "target_image": r"C:\Windows\System32\lsass.exe", "granted_access": "0x1410"}, "s", 1)
    assert credential.detect_lsass_access([ok], "H") == []


# ----------------------------------------------------------------- lateral
def test_lateral_edges_exactly_match_ground_truth(result, gt):
    got = {(e.src, e.dst, e.method) for e in lateral.attack_edges(result.edges)}
    assert got == {(e["src"], e["dst"], e["method"]) for e in gt["lateral_edges"]}


def test_admin_rdp_from_jump_host_is_allowlisted(result):
    ok = [e for e in result.edges if e.allowlisted]
    assert [(e.src, e.dst, e.account, e.allowlisted) for e in ok] == \
        [("JUMP-01", "DC-01", "admin.rdp", "CHG0012345")]
    assert not any(f.technique == "T1021.001" and "admin.rdp" in f.title for f in result.findings)


def test_admin_rdp_outside_business_hours_is_not_allowlisted():
    late = Event(datetime(2026, 10, 19, 3, 0, tzinfo=timezone.utc), "DC-01", "security", "logon",
                 {"event_id": 4624, "logon_type": 10, "user": "admin.rdp",
                  "remote_host": "10.20.0.50"}, "Security_EvtxECmd.csv", 1)
    edges, findings = lateral.analyze([late])
    assert edges[0].allowlisted == "" and len(findings) == 1


def test_rdp_finding_corroborated_by_1149_and_4672(result):
    f = next(f for f in result.findings if f.key == "lateral:rdp:WS-ACCT-07->DC-01:jsmith")
    assert f.severity == "critical"
    assert {e.source for e in f.evidence} == {"Security_EvtxECmd.csv", "TerminalServices_EvtxECmd.csv"}


def test_service_lateral_needs_preceding_network_logon(case):
    svc_only = [e for e in case.events if e.host == "FS-01" and e.action == "service_install"]
    edges, _ = lateral.analyze(svc_only)
    assert edges == []


def test_4648_to_localhost_is_quiet(case):
    _, findings = lateral.analyze(case.events)
    assert not any(f.technique == "T1550" for f in findings)


def test_mermaid_graph(result):
    m = lateral.movement_mermaid(result.edges)
    assert m.startswith("flowchart LR")
    assert 'WS_ACCT_07 ==>|"service as jsmith"| FS_01' in m
    assert 'WS_ACCT_07 ==>|"rdp as jsmith"| DC_01' in m
    assert "JUMP_01 -.->" in m


# ----------------------------------------------------------------- evasion
def test_log_clear_fires_on_fs01_only(case):
    assert len(evasion.detect_log_clearing(case.events, "FS-01")) == 1
    assert evasion.detect_log_clearing(case.events, "DC-01") == []


def test_defender_rtp_disabled(case):
    (f,) = evasion.detect_defender_tamper(case.events, "WS-ACCT-07")
    assert f.technique == "T1562.001"


def test_timestomp_payload_only(case):
    found = evasion.detect_timestomping(case.mft_rows, "WS-ACCT-07")
    assert len(found) == 1 and "svchost.exe" in found[0].title
    assert "AppData" in found[0].key or "appdata" in found[0].key


def test_timestomp_threshold():
    fn = datetime(2026, 10, 19, 13, 6, 30, tzinfo=timezone.utc)
    for delta, fires in [(timedelta(0), False), (timedelta(hours=2), False),
                         (timedelta(days=1), True), (timedelta(days=2500), True),
                         (-timedelta(days=30), False)]:          # $SI newer than $FN: normal
        row = {"host": "H", "filename": "x.exe", "parent": r"\Temp", "si_created": fn - delta,
               "fn_created": fn, "source": "mft.csv", "row": 1}
        assert bool(evasion.detect_timestomping([row], "H")) is fires, delta


def test_no_benign_look_alike_is_cited(result, gt):
    cited = cited_rows(result.findings)
    for b in gt["benign"]:
        if b["row"]:
            assert (b["host"], b["source"], b["row"]) not in cited, b["label"]
        else:
            assert not any(h == b["host"] and s == b["source"] for h, s, _ in cited), b["label"]
