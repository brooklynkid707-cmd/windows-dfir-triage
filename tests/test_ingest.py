"""Parsers: each export format maps to the common model with the right fields."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dfirt.ingest import amcache, evtx, mft, prefetch, recmd, shimcache, sysmon, tasks
from dfirt.model import is_masquerade, parse_time


def test_load_case_hosts_and_counts(case):
    assert case.hosts == ["DC-01", "FS-01", "WS-ACCT-07"]
    assert len(case.processes) == 18
    assert len(case.tasks) == 2
    assert len(case.mft_rows) == 3
    kinds = {a.kind for a in case.exec_artifacts}
    assert kinds == {"prefetch", "amcache", "shimcache"}


def test_sysmon_process_fields_and_hashes(case_dir):
    procs, events = sysmon.parse(case_dir / "WS-ACCT-07" / "sysmon.jsonl", "WS-ACCT-07")
    payload = next(p for p in procs if "AppData" in p.image)
    assert payload.name == "svchost.exe"
    assert payload.parent_name == "powershell.exe"
    assert len(payload.sha256) == 64
    assert payload.guid.startswith("{") and payload.parent_guid != payload.guid
    actions = {e.action for e in events}
    assert {"process_create", "network_connect", "image_load", "process_access",
            "file_create", "registry_set", "wmi_subscription", "dns_query"} <= actions


def test_sysmon_lsass_access_fields(case):
    ev = next(e for e in case.events if e.action == "process_access")
    assert ev.get("granted_access") == "0x1410"
    assert ev.get("target_image").lower().endswith("lsass.exe")


def test_evtx_kerberos_and_logon_fields(case_dir):
    evs = evtx.parse(case_dir / "DC-01" / "Security_EvtxECmd.csv", "DC-01")
    tgs = [e for e in evs if e.eid == 4769]
    assert len(tgs) == 5
    rc4 = [e for e in tgs if e.get("ticket_encryption") == "0x17"]
    assert sorted(e.get("service_name") for e in rc4) == ["svc_erp", "svc_fileshare", "svc_sql", "svc_web"]
    rdp = [e for e in evs if e.eid == 4624 and e.get("logon_type") == 10]
    assert {e.get("remote_host") for e in rdp} == {"10.20.5.17", "10.20.0.50"}


def test_evtx_channel_kinds(case):
    kinds = {e.kind for e in case.events if e.source.endswith("_EvtxECmd.csv")}
    assert kinds == {"security", "system", "powershell", "terminalservices", "defender"}


def test_evtx_record_numbers_follow_time(case_dir):
    import csv
    with (case_dir / "DC-01" / "Security_EvtxECmd.csv").open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["TimeCreated"] for r in rows] == sorted(r["TimeCreated"] for r in rows)
    nums = [int(r["RecordNumber"]) for r in rows]
    assert nums == sorted(nums) and len(set(nums)) == len(nums)


def test_prefetch_run_times_and_full_path(case_dir):
    arts = prefetch.parse(case_dir / "WS-ACCT-07" / "prefetch_PECmd.csv", "WS-ACCT-07")
    pf = next(a for a in arts if "appdata" in a.path.lower())
    assert pf.path == r"C:\USERS\JSMITH\APPDATA\ROAMING\MICROSOFT\SVCHOST.EXE"
    assert pf.run_count == 3 and pf.proves_execution
    assert [t.strftime("%H:%M:%S") for t in pf.run_times] == ["14:02:11", "13:31:05", "13:06:31"]


def test_amcache_sha1_and_not_proof(case_dir):
    arts = amcache.parse(case_dir / "WS-ACCT-07" / "amcache_AmcacheParserAssociated.csv", "WS-ACCT-07")
    payload = next(a for a in arts if "appdata" in a.path.lower())
    assert len(payload.sha1) == 40
    assert payload.proves_execution is False


def test_shimcache_executed_na_is_not_proof(case_dir):
    arts = shimcache.parse(case_dir / "WS-ACCT-07" / "appcompatcache_AppCompatCacheParser.csv", "WS-ACCT-07")
    assert arts and all(not a.proves_execution for a in arts)
    payload = next(a for a in arts if "appdata" in a.path.lower())
    assert payload.first_seen.year == 2019   # $SI modified time, backdated by the attacker


def test_recmd_run_keys(case_dir):
    evs = recmd.parse(case_dir / "WS-ACCT-07" / "runkeys_RECmd.csv", "WS-ACCT-07")
    assert {e.get("value_name") for e in evs} == {"OneDriveSync", "GoogleUpdate"}
    assert all(e.action == "run_key" for e in evs)


def test_task_xml_parse(case_dir):
    t = tasks.parse_task_xml(case_dir / "WS-ACCT-07" / "tasks" / "MicrosoftEdgeUpdateTaskUser.xml",
                             "WS-ACCT-07")
    assert t["name"] == "MicrosoftEdgeUpdateTaskUser"
    assert t["command"].endswith(r"AppData\Roaming\Microsoft\svchost.exe")
    assert t["triggers"] == ["LogonTrigger"] and t["run_level"] == "HighestAvailable"
    assert t["hidden"] is True


def test_mft_si_and_fn_columns(case_dir):
    rows = mft.parse(case_dir / "WS-ACCT-07" / "mft_MFTECmd.csv", "WS-ACCT-07")
    payload = next(r for r in rows if "AppData" in r["parent"])
    assert payload["si_created"] < payload["fn_created"]


def test_parse_time_formats_and_rejects_garbage():
    want = datetime(2026, 10, 19, 13, 6, 31, tzinfo=timezone.utc)
    assert parse_time("2026-10-19 13:06:31.0000000") == want          # EvtxECmd / PECmd (7 digits)
    assert parse_time("2026-10-19 13:06:31.123") == want.replace(microsecond=123000)  # Sysmon
    assert parse_time("2026-10-19T13:06:31Z") == want
    assert parse_time("") is None
    with pytest.raises(ValueError):
        parse_time("yesterday afternoon")


def test_masquerade_helper():
    cases = {
        r"C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe": True,
        r"C:\Windows\System32\svchost.exe": False,
        r"C:\Windows\SysWOW64\svchost.exe": False,
        r"C:\ProgramData\lsass.exe": True,
        r"C:\Users\jsmith\AppData\Local\notepad++.exe": False,   # not a protected name
    }
    for path, expected in cases.items():
        assert is_masquerade(path) is expected, path
