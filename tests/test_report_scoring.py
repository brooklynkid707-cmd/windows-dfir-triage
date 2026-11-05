"""Triage orchestration, ground-truth scoring, timeline and report sections."""
from __future__ import annotations

from dfirt import report, scoring, timeline

SECTIONS = [
    "## 1. Executive summary", "## 2. Evidence integrity", "## 3. Scope",
    "## 4. Patient zero and initial access", "## 5. Findings by tactic",
    "## 6. ATT&CK techniques observed", "## 7. Host-to-host movement",
    "## 8. Execution-evidence matrix", "## 9. Indicators of compromise",
    "## 10. Sigma rule hits", "## 11. Recommended containment and eradication",
    "## 12. Collection gaps and caveats",
]


def test_patient_zero(result, gt):
    assert result.patient_zero == gt["patient_zero"]


def test_score_precision_recall_perfect(result, gt):
    s = scoring.score(result.findings, gt, result.edges)
    assert s.missed == [] and s.false_positives == [] and s.benign_cited == []
    assert (s.precision, s.recall) == (1.0, 1.0)
    assert s.edges_exact


def test_scoring_penalises_fp_and_fn(result, gt):
    findings = [f for f in result.findings if f.technique != "T1558.003"]
    s = scoring.score(findings, gt)
    assert s.missed == ["CA-2"] and s.recall < 1.0
    from dfirt.findings import Finding
    bogus = Finding("x", "Impact", "T1486", "Data Encrypted", "high", "FS-01", "bogus")
    s2 = scoring.score(result.findings + [bogus], gt)
    assert s2.fp == 1 and s2.precision < 1.0


def test_scoring_counts_cited_benign_row_as_fp(result, gt):
    from dfirt.findings import Finding
    b = next(x for x in gt["benign"] if x["source"] == "runkeys_RECmd.csv")
    f = Finding("x", "Persistence", "T1547.001", "Run Keys", "high", b["host"], "noisy")
    f.add(b["source"], b["row"])
    s = scoring.score(result.findings + [f], gt)
    assert s.benign_cited == [b["label"]]


def test_every_finding_cites_evidence(result):
    for f in result.findings:
        assert f.evidence, f.title
        assert all(e.source for e in f.evidence)


def test_iocs_match_ground_truth(result, gt):
    assert result.iocs["sha256"] == gt["iocs"]["sha256"]
    assert sorted(result.iocs["paths"]) == gt["iocs"]["paths"]
    assert result.iocs["ips"] == gt["iocs"]["ips"]
    assert result.iocs["domains"] == gt["iocs"]["domains"]
    assert all("[.]" in i for i in result.iocs["ips_defanged"])


def test_report_has_every_section_in_order(result):
    md = report.build_report(result)
    positions = [md.index(s) for s in SECTIONS]
    assert positions == sorted(positions)


def test_report_content(result):
    md = report.build_report(result)
    assert "**Patient zero** | WS-ACCT-07" in md
    assert "```mermaid" in md and "flowchart LR" in md
    assert "| WS-ACCT-07 | `C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\svchost.exe` | yes | yes | yes | yes | yes | 3 | **confirmed** |" in md
    assert "**possible**" in md
    assert "198[.]51[.]100[.]25" in md and "198.51.100.25" not in md
    assert "<-- Office spawned script host" in md
    assert "`WS-ACCT-07/sysmon.jsonl:" in md          # evidence references artifact + row
    for tech in ("T1566.001", "T1558.003", "T1021.002", "T1021.001", "T1070.006"):
        assert f"| {tech} |" in md


def test_report_is_deterministic(result):
    assert report.build_report(result) == report.build_report(result)


def test_timeline_sorted_across_hosts(case):
    rows = timeline.build(case)
    times = [r.time for r in rows if r.time]
    assert times == sorted(times)
    assert {r.host for r in rows} == {"WS-ACCT-07", "FS-01", "DC-01"}


def test_key_events_is_attack_focused(case, result):
    key = timeline.key_events(timeline.build(case), findings=result.findings)
    text = "\n".join(r.detail for r in key)
    assert "sync-cdn.example" in text and "PSEXESVC" in text and "etype=0x17" in text
    assert "inventory.ps1" not in text          # SCCM noise filtered
    assert "etype=0x12" not in text             # benign AES ticket filtered
    assert "admin.rdp" not in " ".join(r.actor for r in key)   # allowlisted RDP filtered
    assert len(key) < len(timeline.build(case))


def test_key_events_cover_every_cited_row(case, result):
    key = {(r.host, r.source, r.row) for r in timeline.key_events(timeline.build(case),
                                                                    findings=result.findings)}
    for f in result.findings:
        for e in f.evidence:
            assert (e.host or f.host, e.source, e.row) in key, (f.title, e.cite())


def test_timeline_csv_header_and_rows(case):
    rows = timeline.build(case)
    csv_text = timeline.to_csv(rows)
    lines = csv_text.splitlines()
    assert lines[0] == "time,host,source,row,kind,actor,detail"
    assert len(lines) == len(rows) + 1


def test_benign_only_environment_produces_no_findings(case):
    """Negative control: strip every attacker record (anything a planted-fact
    detector cites, plus the attacker's own processes) and the remaining benign
    baseline - SCCM, Teams, backup task, vendor service, admin RDP, AES tickets,
    System32 svchost - must yield zero findings."""
    import copy
    from dfirt import triage as tri
    attack_users = ("jsmith",)
    benign = copy.copy(case)
    benign.processes = [p for p in case.processes
                        if not any(u in p.user.lower() for u in attack_users)
                        and "psexesvc" not in p.image.lower() and p.parent_name != "psexesvc.exe"
                        and p.parent_name != "cmd.exe"]
    def blob(e):
        return " ".join(str(v) for v in e.data.values()).lower()

    benign.events = [e for e in case.events
                     if "jsmith" not in str(e.get("user", "")).lower()
                     and "jsmith" not in str(e.get("account", "")).lower()
                     and "appdata\\roaming\\microsoft\\svchost" not in blob(e)
                     and "psexesvc" not in blob(e) and "7za" not in blob(e)
                     and e.action not in ("wmi_subscription", "process_access", "log_cleared",
                                          "network_connect", "dns_query")]
    benign.tasks = [t for t in case.tasks if t["name"] == "NorthwindBackup"]
    benign.mft_rows = [m for m in case.mft_rows if "AppData" not in m["parent"]]
    assert benign.processes and benign.events          # the baseline is not empty
    r = tri.run(benign)
    assert r.findings == [], [f.title for f in r.findings]
    assert [e for e in r.edges if not e.allowlisted] == []
