"""Evidence-of-execution confidence model, including the Shimcache nuance."""
from __future__ import annotations

from datetime import datetime, timezone

from dfirt import execution
from dfirt.model import ExecArtifact

T = datetime(2026, 10, 1, tzinfo=timezone.utc)
PAYLOAD = r"C:\Users\jsmith\AppData\Roaming\Microsoft\svchost.exe"


def art(kind, proves=False, path=r"C:\Tools\tool.exe"):
    return ExecArtifact(host="H", target="tool.exe", path=path, kind=kind,
                        first_seen=T, last_seen=T, proves_execution=proves,
                        run_count=2 if kind == "prefetch" else None,
                        run_times=[T] if kind == "prefetch" else [])


def test_confidence_levels():
    table = [
        ([], "none"),
        (["shimcache"], "possible"),
        (["amcache"], "probable"),
        (["amcache", "shimcache"], "probable"),
        (["prefetch"], "confirmed"),
        (["prefetch", "shimcache"], "confirmed"),
    ]
    for kinds, expected in table:
        arts = [art(k, proves=(k == "prefetch")) for k in kinds]
        assert execution.assess("tool.exe", "H", arts).confidence == expected, kinds


def test_shimcache_alone_never_proves_execution():
    a = execution.assess("tool.exe", "H", [art("shimcache")])
    assert a.proves_execution is False
    assert "NOT evidence of execution" in a.rationale
    assert "Windows 8.1/10/11" in a.rationale


def test_shimcache_executed_flag_ignored_on_win10(case):
    shim = [a for a in case.exec_artifacts if a.kind == "shimcache"]
    assert all(a.executed_flag == "NA" for a in shim)
    assert not any(a.proves_execution for a in shim)


def test_amcache_alone_carries_caveat():
    a = execution.assess("tool.exe", "H", [art("amcache")])
    assert not a.proves_execution and "compatibility scanning" in a.rationale


def test_payload_confirmed_with_all_five_sources(case, gt):
    a = execution.assess(PAYLOAD, "WS-ACCT-07", case.exec_artifacts, case.processes, case.events)
    assert a.confidence == gt["payload"]["execution_confidence"]
    assert a.sources == ["amcache", "evt4688", "prefetch", "shimcache", "sysmon1"]
    assert a.run_count == gt["payload"]["prefetch_run_count"]
    assert len(a.run_times) == 3


def test_shim_only_binary_in_case_is_possible(case, gt):
    so = gt["shimcache_only"]
    a = execution.assess(so["path"], so["host"], case.exec_artifacts, case.processes, case.events)
    assert a.confidence == so["execution_confidence"] == "possible"
    assert a.sources == ["shimcache"]


def test_full_path_never_borrows_evidence_from_same_name(case):
    legit = execution.assess(r"C:\Windows\System32\svchost.exe", "WS-ACCT-07",
                             case.exec_artifacts, case.processes, case.events)
    assert "prefetch" not in legit.sources and "evt4688" not in legit.sources
    split = execution.assess_all("svchost.exe", "WS-ACCT-07", case.exec_artifacts,
                                 case.processes, case.events)
    assert len(split) == 2
    assert {a.path.lower() for a in split} == {PAYLOAD.lower(),
                                              r"c:\windows\system32\svchost.exe"}


def test_matrix_rows_for_report(result):
    rows = {r["path"]: r for r in result.exec_matrix}
    p = rows[PAYLOAD]
    assert (p["prefetch"], p["sysmon1"], p["evt4688"], p["amcache"], p["shimcache"]) == (True,) * 5
    assert p["confidence"] == "confirmed"
    assert any(r["confidence"] == "possible" and r["shimcache"] and not r["prefetch"]
               for r in result.exec_matrix)
