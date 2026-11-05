"""Process-tree reconstruction and anomalous-lineage detection."""
from __future__ import annotations

from datetime import datetime, timezone

from dfirt import proctree
from dfirt.model import Process

from conftest import techniques


def _p(guid, image, parent_guid, parent_image, cmd="", user="NORTHWIND\\u", host="H"):
    return Process(time=datetime(2026, 1, 1, tzinfo=timezone.utc), host=host, guid=guid, pid=1,
                   image=image, command_line=cmd or image, user=user, parent_guid=parent_guid,
                   parent_pid=2, parent_image=parent_image, parent_command_line="", row=1,
                   source="sysmon.jsonl")


def test_tree_links_by_guid_not_pid(case):
    tree = proctree.build_tree(case.processes, "WS-ACCT-07")
    word = next(n for n in tree.by_guid.values() if n.name == "winword.exe")
    assert [c.name for c in word.children] == ["powershell.exe"]
    ps = word.children[0]
    assert [c.name for c in ps.children] == ["svchost.exe"]
    assert sorted(c.name for c in ps.children[0].children) == ["net.exe", "schtasks.exe"]


def test_tree_roots_are_processes_whose_parent_is_absent(case):
    tree = proctree.build_tree(case.processes, "WS-ACCT-07")
    assert [r.name for r in tree.roots] == ["svchost.exe", "powershell.exe", "outlook.exe"]
    assert all(r.proc.parent_guid not in tree.by_guid for r in tree.roots)


def test_render_patient_zero_chain(result):
    text = result.trees["WS-ACCT-07"].render(detail=False)
    assert "outlook.exe\n    └── winword.exe" in text.replace("└── outlook.exe", "outlook.exe")
    assert "        └── powershell.exe" in text
    assert "├── schtasks.exe" in text and "└── net.exe" in text


def test_render_groups_siblings_under_one_missing_parent():
    procs = [_p("{a}", r"C:\Windows\System32\net.exe", "{x}", r"C:\Windows\System32\cmd.exe"),
             _p("{b}", r"C:\Windows\System32\whoami.exe", "{x}", r"C:\Windows\System32\cmd.exe")]
    text = proctree.build_tree(procs, "H").render(detail=False)
    assert text.count("[parent not in log: cmd.exe") == 1
    assert "├── net.exe" in text and "└── whoami.exe" in text


def test_office_spawning_powershell_fires(result):
    keys = {f.key for f in result.findings}
    assert "proctree:office_child:WS-ACCT-07:powershell.exe" in keys


def test_sccm_powershell_from_ccmexec_is_quiet(case):
    findings = proctree.detect(case.processes, "WS-ACCT-07")
    assert not any("ccmexec" in e.note.lower() for f in findings for e in f.evidence)
    assert sum(1 for f in findings if f.technique == "T1059.001") == 1


def test_masquerade_fires_and_system32_svchost_is_quiet(case):
    findings = proctree.detect(case.processes, "WS-ACCT-07")
    masq = [f for f in findings if f.technique == "T1036.005"]
    assert len(masq) == 1 and "AppData" in masq[0].title
    assert not any(r"C:\Windows\System32\svchost.exe" in e.note
                   for f in masq for e in f.evidence)


def test_svchost_with_wrong_parent_fires():
    procs = [_p("{a}", r"C:\Windows\System32\svchost.exe", "{x}", r"C:\Windows\explorer.exe")]
    f = proctree.detect(procs, "H")
    assert [x.key.split(":")[1] for x in f] == ["svchost_parent"]


def test_services_child_signed_vendor_quiet_psexesvc_fires(case):
    findings = proctree.detect(case.processes, "FS-01")
    titles = " ".join(f.title for f in findings)
    assert "psexesvc.exe" in titles
    assert "contosoagent" not in titles.lower()


def test_lsass_access_by_payload_flagged(case, result):
    lsass = [e for e in case.events if e.action == "process_access"]
    flags = proctree.anomaly_flags(case.processes, "WS-ACCT-07", lsass)
    payload_guid = next(p.guid for p in case.processes if "AppData" in p.image)
    assert "opened LSASS 0x1410" in flags[payload_guid]
    assert "T1003.001" in techniques(result.findings, "WS-ACCT-07")
