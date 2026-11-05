"""Parse scheduled-task XML (as collected by KAPE) into dict records.

We use the stdlib XML parser with external entity resolution disabled (the
default for ElementTree) and strip the task namespace so the fields are easy to
read. Each record carries the task name, the command it runs, the principal,
run level, trigger type and the registration date.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import parse_time

_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _text(elem, tag: str, default: str = "") -> str:
    if elem is None:
        return default
    found = elem.find(f"{_NS}{tag}")
    if found is None:
        found = elem.find(tag)
    return (found.text or "").strip() if found is not None and found.text else default


def parse_task_xml(path: Path, host: str) -> dict:
    tree = ET.parse(path)  # ET does not resolve external entities
    root = tree.getroot()
    reg = root.find(f"{_NS}RegistrationInfo")
    triggers = root.find(f"{_NS}Triggers")
    principals = root.find(f"{_NS}Principals")
    actions = root.find(f"{_NS}Actions")
    settings = root.find(f"{_NS}Settings")

    trigger_types = []
    if triggers is not None:
        for child in list(triggers):
            trigger_types.append(child.tag.replace(_NS, ""))

    command = ""
    arguments = ""
    if actions is not None:
        exec_el = actions.find(f"{_NS}Exec")
        command = _text(exec_el, "Command")
        arguments = _text(exec_el, "Arguments")

    principal = principals.find(f"{_NS}Principal") if principals is not None else None
    user_id = _text(principal, "UserId")
    run_level = _text(principal, "RunLevel")

    uri = _text(reg, "URI")
    name = uri.lstrip("\\") if uri else path.stem
    hidden = _text(settings, "Hidden").lower() == "true"

    return {
        "host": host,
        "name": name,
        "command": command,
        "arguments": arguments,
        "user_id": user_id,
        "run_level": run_level,
        "triggers": trigger_types,
        "registration_date": parse_time(_text(reg, "Date")) if _text(reg, "Date") else None,
        "hidden": hidden,
        "author": _text(reg, "Author"),
        "source": str(path.name),
        "row": 0,
    }
