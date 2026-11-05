"""Bundled Sigma rules: each fires on the attack and not on the benign data,
plus unit tests for the minimal evaluator."""
from __future__ import annotations

from collections import defaultdict

import pytest

from dfirt import sigma
from dfirt.model import Event

from conftest import cited_rows

RULES = {r["id"]: r for r in sigma.load_rules()}

# rule id -> (host, artifact file) of the attack event(s) it must hit
EXPECTED = {
    "dfirt-0001-office-script-child": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0002-svchost-masquerade": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0003-lsass-access": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0004-kerberoast-rc4": {("DC-01", "Security_EvtxECmd.csv")},
    "dfirt-0005-run-key-userland": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0006-log-cleared": {("FS-01", "Security_EvtxECmd.csv")},
    "dfirt-0007-defender-rtp-off": {("WS-ACCT-07", "Defender_EvtxECmd.csv")},
    "dfirt-0008-psexesvc-install": {("FS-01", "System_EvtxECmd.csv")},
    "dfirt-0009-encoded-powershell": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0010-wmi-subscription": {("WS-ACCT-07", "sysmon.jsonl")},
    "dfirt-0011-rdp-not-jumphost": {("DC-01", "Security_EvtxECmd.csv")},
}


@pytest.fixture(scope="module")
def hits(case):
    by_rule = defaultdict(list)
    for h in sigma.evaluate(list(RULES.values()), case.events):
        by_rule[h["id"]].append(h)
    return by_rule


def test_every_rule_is_valid_sigma_shape():
    assert set(RULES) == set(EXPECTED)
    for r in RULES.values():
        assert {"title", "id", "logsource", "detection", "level", "tags"} <= set(r)
        assert "condition" in r["detection"]
        assert any(t.startswith("attack.t") for t in r["tags"])


def test_every_rule_fires_on_its_attack_artifact(hits):
    for rule_id, expected in sorted(EXPECTED.items()):
        got = {(h["host"], h["source"]) for h in hits[rule_id]}
        assert got == expected, rule_id
    assert len(hits["dfirt-0004-kerberoast-rc4"]) == 4      # the four RC4 tickets, not the AES one


def test_no_rule_hits_a_benign_look_alike(case, gt):
    all_hits = sigma.evaluate(list(RULES.values()), case.events)
    hit_rows = {(h["host"], h["source"], h["row"]) for h in all_hits}
    for b in gt["benign"]:
        if b["row"]:
            assert (b["host"], b["source"], b["row"]) not in hit_rows, b["label"]


def test_sigma_hits_are_a_subset_of_triage_evidence(case, result):
    """Every Sigma hit points at a row some triage finding already cites."""
    cited = cited_rows(result.findings)
    for h in sigma.evaluate(list(RULES.values()), case.events):
        assert (h["host"], h["source"], h["row"]) in cited, h


def _ev(**data):
    action = data.pop("action", "process_create")
    kind = data.pop("kind", "sysmon")
    return Event(None, "H", kind, action, data, "s", 1)


def test_evaluator_modifiers_and_not_filter():
    rule = {"logsource": {"product": "windows", "category": "process_access"},
            "detection": {"sel": {"TargetImage|endswith": "\\lsass.exe",
                                  "GrantedAccess|startswith": "0x14"},
                          "filter": {"SourceImage|endswith": "\\wininit.exe"},
                          "condition": "sel and not filter"}}
    bad = _ev(action="process_access", source_image=r"C:\x\evil.exe",
              target_image=r"C:\Windows\System32\lsass.exe", granted_access="0x1410")
    good = _ev(action="process_access", source_image=r"C:\Windows\System32\wininit.exe",
               target_image=r"C:\Windows\System32\lsass.exe", granted_access="0x1410")
    assert sigma.rule_matches(rule, bad) and not sigma.rule_matches(rule, good)


def test_evaluator_one_of_and_logsource_gate():
    rule = {"logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection_a": {"CommandLine|contains": "nltest"},
                          "selection_b": {"CommandLine|contains": "whoami"},
                          "condition": "1 of selection*"}}
    assert sigma.rule_matches(rule, _ev(command_line="whoami /all"))
    assert not sigma.rule_matches(rule, _ev(command_line="notepad.exe"))
    # same fields on a non-process event: blocked by the logsource category
    assert not sigma.rule_matches(rule, _ev(action="dns_query", command_line="whoami"))
