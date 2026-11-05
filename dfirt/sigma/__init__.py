"""Minimal Sigma rule set + evaluator over normalized dfirt events.

This is a deliberately small, self-contained Sigma implementation: enough of the
detection/condition grammar to express the top detections for this case and to
*prove*, in tests, that each rule fires on the attack and stays quiet on the
benign look-alikes. It is not a full Sigma engine (no backends, no pipelines).

Supported condition grammar: ``selection``, ``selection and filter``,
``selection and not filter``, ``1 of selection*`` / ``all of selection*``.
Field modifiers: ``contains``, ``endswith``, ``startswith``, ``re``, ``all``
(list = AND) and the default (list = OR / equals, case-insensitive).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..model import Event

RULES_DIR = Path(__file__).resolve().parent / "rules"


def load_rules(rules_dir: Path | str | None = None) -> list[dict]:
    d = Path(rules_dir) if rules_dir else RULES_DIR
    rules = []
    for f in sorted(d.glob("*.yml")):
        rules.append(yaml.safe_load(f.read_text(encoding="utf-8")))
    return rules


def _event_fields(ev: Event) -> dict[str, Any]:
    """Flatten an Event into the field names the rules reference."""
    fields: dict[str, Any] = {
        "Channel": ev.get("channel", ""),
        "EventID": ev.eid,
        "Computer": ev.host,
        "Image": ev.get("image", ""),
        "ParentImage": ev.get("parent_image", ""),
        "CommandLine": ev.get("command_line", ""),
        "TargetImage": ev.get("target_image", ""),
        "SourceImage": ev.get("source_image", ""),
        "TargetObject": ev.get("target_object", ""),
        "Details": ev.get("details", ""),
        "TargetFilename": ev.get("target_filename", ""),
        "GrantedAccess": ev.get("granted_access", ""),
        "DestinationIp": ev.get("dest_ip", ""),
        "DestinationHostname": ev.get("dest_host", ""),
        "ServiceName": ev.get("service_name", ""),
        "ServiceImage": ev.get("service_image", ""),
        "TicketEncryptionType": ev.get("ticket_encryption", ""),
        "ServiceFileName": ev.get("service_image", ""),
        "LogonType": ev.get("logon_type", ""),
        "IpAddress": ev.get("remote_host", ""),
        "TargetUserName": ev.get("account", "") or ev.get("user", ""),
        "ScriptBlockText": ev.get("payload", "") if ev.action == "scriptblock" else "",
        "action": ev.action,
        "kind": ev.kind,
    }
    return fields


def _match_value(field_val: Any, modifier: str, expected: Any) -> bool:
    fv = "" if field_val is None else str(field_val)
    fvl = fv.lower()

    def one(exp) -> bool:
        es = str(exp)
        esl = es.lower()
        if modifier == "contains":
            return esl in fvl
        if modifier == "endswith":
            return fvl.endswith(esl)
        if modifier == "startswith":
            return fvl.startswith(esl)
        if modifier == "re":
            return re.search(es, fv, re.I) is not None
        return fvl == esl

    if isinstance(expected, list):
        return any(one(e) for e in expected)
    return one(expected)


def _match_selection(fields: dict, selection: dict) -> bool:
    # selection can be a dict (AND over keys) or list of dicts (OR)
    if isinstance(selection, list):
        return any(_match_selection(fields, s) for s in selection)
    for key, expected in selection.items():
        if "|" in key:
            name, modifier = key.split("|", 1)
        else:
            name, modifier = key, ""
        # 'all' modifier: every item in the list must match (AND)
        if modifier.endswith("all"):
            base_mod = modifier[:-3].rstrip("|") or ""
            vals = expected if isinstance(expected, list) else [expected]
            if not all(_match_value(fields.get(name), base_mod, v) for v in vals):
                return False
            continue
        if not _match_value(fields.get(name), modifier, expected):
            return False
    return True


def _eval_condition(condition: str, detection: dict, fields: dict) -> bool:
    cond = condition.strip()

    # "1 of selection*" / "all of selection*"
    m = re.match(r"(1|all) of (\w+)\*?$", cond)
    if m:
        quant, prefix = m.group(1), m.group(2)
        prefix = prefix.rstrip("*")
        names = [k for k in detection if k != "condition" and k.startswith(prefix)]
        results = [_match_selection(fields, detection[k]) for k in names]
        return any(results) if quant == "1" else all(results)

    # tokens joined by and / not
    # supported shapes: "A", "A and B", "A and not B", "A and not 1 of f*"
    tokens = cond.split()
    if not tokens:
        return False

    # evaluate left to right with 'and' / 'not'
    def sel_value(name: str) -> bool:
        if name not in detection:
            return False
        return _match_selection(fields, detection[name])

    # Handle "A and not 1 of filter*"
    neg_oneof = re.match(r"(\w+) and not 1 of (\w+)\*$", cond)
    if neg_oneof:
        a, prefix = neg_oneof.group(1), neg_oneof.group(2)
        filters = [k for k in detection if k.startswith(prefix)]
        return sel_value(a) and not any(_match_selection(fields, detection[k]) for k in filters)

    result = None
    negate_next = False
    op = None
    for tok in tokens:
        if tok == "and":
            op = "and"
            continue
        if tok == "not":
            negate_next = True
            continue
        val = sel_value(tok)
        if negate_next:
            val = not val
            negate_next = False
        if result is None:
            result = val
        elif op == "and":
            result = result and val
    return bool(result)


# Sigma logsource -> which normalized events a rule may see.
_CATEGORY = {
    "process_creation": lambda ev: ev.action == "process_create",
    "process_access": lambda ev: ev.action == "process_access",
    "registry_set": lambda ev: ev.action == "registry_set",
    "file_event": lambda ev: ev.action == "file_create",
    "network_connection": lambda ev: ev.action == "network_connect",
    "dns_query": lambda ev: ev.action == "dns_query",
    "image_load": lambda ev: ev.action == "image_load",
    "wmi_event": lambda ev: ev.action == "wmi_subscription",
    "ps_script": lambda ev: ev.action == "scriptblock",
}
_SERVICE = {
    "security": "security", "system": "system", "sysmon": "sysmon",
    "windefend": "defender", "powershell": "powershell",
    "terminalservices-localsessionmanager": "terminalservices",
}


def logsource_matches(rule: dict, ev: Event) -> bool:
    ls = rule.get("logsource", {}) or {}
    if ls.get("product", "windows") != "windows":
        return False
    cat = ls.get("category")
    if cat and not _CATEGORY.get(cat, lambda _e: False)(ev):
        return False
    svc = ls.get("service")
    if svc and _SERVICE.get(svc) != ev.kind:
        return False
    return True


def rule_matches(rule: dict, ev: Event) -> bool:
    if not logsource_matches(rule, ev):
        return False
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    fields = _event_fields(ev)
    return _eval_condition(condition, detection, fields)


def evaluate(rules: list[dict], events: Iterable[Event]) -> list[dict]:
    """Return one hit record per (rule, matching event)."""
    hits = []
    events = list(events)
    for rule in rules:
        for ev in events:
            if rule_matches(rule, ev):
                hits.append({
                    "rule": rule.get("title", rule.get("id", "?")),
                    "id": rule.get("id", ""),
                    "level": rule.get("level", "medium"),
                    "host": ev.host, "source": ev.source, "row": ev.row,
                    "technique": _technique(rule),
                })
    return hits


def _technique(rule: dict) -> str:
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t"):
            return tag.split(".", 1)[1].upper()
    return ""
