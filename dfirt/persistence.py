"""Persistence detection: Run/RunOnce keys, services, scheduled tasks, WMI
event subscriptions and the Startup folder.

Each mechanism is judged on *where it points* and *who wrote it*, then checked
against config/allowlist.yml. The benign look-alikes in the case (a signed
updater Run key under Program Files, an IT backup task, a signed vendor
service, Teams writing its own Startup shortcut) stay quiet; the planted
persistence fires.
"""
from __future__ import annotations

from . import allowlist
from .findings import Finding
from .model import Event, image_name, is_masquerade, norm_path

TRUSTED_DIRS = (
    "c:\\program files\\", "c:\\program files (x86)\\",
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
)
SUSPICIOUS_DIRS = ("\\appdata\\", "\\users\\public\\", "\\downloads\\", "\\temp\\",
                   "\\programdata\\", "\\perflogs")
STARTUP_DIR = "\\start menu\\programs\\startup\\"
# Writers that legitimately drop their own Startup shortcut.
STARTUP_WRITERS = {"teams.exe", "onedrive.exe", "explorer.exe", "msiexec.exe"}


def extract_path(value: str) -> str:
    v = (value or "").strip()
    if v.startswith('"'):
        end = v.find('"', 1)
        return v[1:end] if end != -1 else v[1:]
    return v.split(" ")[0]


def is_suspicious_path(path: str) -> bool:
    p = norm_path(path)
    return any(s in p for s in SUSPICIOUS_DIRS) or is_masquerade(p)


def is_trusted_path(path: str) -> bool:
    return any(norm_path(path).startswith(t) for t in TRUSTED_DIRS)


def _run_key_finding(host: str, name: str, path: str) -> Finding:
    return Finding(
        detector="persistence", tactic="Persistence", technique="T1547.001",
        technique_name="Boot or Logon Autostart: Registry Run Keys",
        severity="high", host=host,
        title=f"Run key '{name}' launches {path}",
        description=("A Run-key autostart points into a user-writable path; legitimate "
                     "installers register autostarts under Program Files or System32."),
        key=f"persistence:run_key:{host}:{name.lower()}")


def detect_run_keys(events: list[Event], host: str, allow: dict | None = None) -> list[Finding]:
    found: dict[str, Finding] = {}
    for e in events:
        if e.host != host:
            continue
        if e.action == "run_key":                      # RECmd export
            name, data = e.get("value_name", ""), e.get("value_data", "")
            note = f"{e.get('key_path', '')}\\{name} = {data}"
        elif e.action == "registry_set" and \
                "\\currentversion\\run" in e.get("target_object", "").lower():  # Sysmon 13
            name = e.get("target_object", "").rsplit("\\", 1)[-1]
            data = e.get("details", "")
            note = f"Sysmon 13 by {image_name(e.get('image', ''))}: {data}"
        else:
            continue
        path = extract_path(data)
        if allowlist.run_key_allowed(name, path, allow) or not is_suspicious_path(path):
            continue
        f = found.setdefault(name.lower(), _run_key_finding(host, name, path))
        f.add(e.source, e.row, note)
    return list(found.values())


def detect_services(events: list[Event], host: str, allow: dict | None = None) -> list[Finding]:
    found: dict[str, Finding] = {}
    for e in events:
        if e.host != host or e.action != "service_install":
            continue
        name, image = e.get("service_name", ""), e.get("service_image", "")
        info = f"{e.get('service_info', '')} {e.get('payload', '')}"
        if allowlist.service_allowed(name, image, info, allow):
            continue
        resolved = norm_path(image.replace("%SystemRoot%", "C:\\Windows")
                             .replace("%systemroot%", "C:\\Windows"))
        if "unsigned" not in info.lower() and is_trusted_path(resolved) \
                and "psexesvc" not in name.lower():
            continue
        f = found.setdefault(name.lower(), Finding(
            detector="persistence", tactic="Persistence", technique="T1543.003",
            technique_name="Create or Modify System Process: Windows Service",
            severity="high", host=host,
            title=f"Service '{name}' installed from {image}",
            description=("New service with an unsigned image outside Program Files/System32 "
                         "(remote-execution service pattern)."),
            key=f"persistence:service:{host}:{name.lower()}"))
        f.add(e.source, e.row, f"EventID {e.eid} image={image}")
    return list(found.values())


def detect_scheduled_tasks(tasks: list[dict], events: list[Event], host: str,
                           allow: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    for t in tasks:
        if t["host"] != host:
            continue
        name, command = t["name"], t["command"]
        if allowlist.task_allowed(name, command, t.get("user_id", ""), allow):
            continue
        if not (is_suspicious_path(command) or t.get("hidden")):
            continue
        f = Finding(
            detector="persistence", tactic="Persistence", technique="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            severity="high", host=host,
            title=f"Scheduled task '{name}' runs {command}",
            description=(f"Task action points into a user-writable path"
                         f"{'; task is hidden' if t.get('hidden') else ''}; "
                         f"trigger {','.join(t['triggers'])}, run level {t.get('run_level', '')}."),
            key=f"persistence:task:{host}:{name.lower()}")
        f.add(f"tasks/{t['source']}", 0, f"<Command>{command}</Command>")
        for e in events:
            if e.host == host and e.action == "task_create" and \
                    e.get("task_name", "").strip("\\").lower() == name.lower():
                f.add(e.source, e.row, "4698 scheduled task created")
        out.append(f)
    return out


def detect_wmi(events: list[Event], host: str) -> list[Finding]:
    subs = [e for e in events if e.host == host and e.action == "wmi_subscription"]
    out: list[Finding] = []
    for c in (e for e in subs if e.eid == 20):
        f = Finding(
            detector="persistence", tactic="Persistence", technique="T1546.003",
            technique_name="Event Triggered Execution: WMI Event Subscription",
            severity="high", host=host,
            title=f"WMI subscription '{c.get('name', '')}' runs {c.get('destination', '')}",
            description="Permanent WMI filter + CommandLineEventConsumer + binding (fileless persistence).",
            key=f"persistence:wmi:{host}:{c.get('name', '').lower()}")
        for e in subs:
            if c.get("name") in (e.get("name"), e.get("consumer")):
                f.add(e.source, e.row, f"Sysmon {e.eid}")
        out.append(f)
    return out


def detect_startup_folder(events: list[Event], host: str) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        if e.host != host or e.action != "file_create":
            continue
        target = e.get("target_filename", "")
        if STARTUP_DIR not in norm_path(target):
            continue
        if image_name(e.get("image", "")) in STARTUP_WRITERS:
            continue
        f = Finding(
            detector="persistence", tactic="Persistence", technique="T1547.001",
            technique_name="Boot or Logon Autostart: Startup Folder",
            severity="high", host=host,
            title=f"File written to Startup folder: {target}",
            description=f"Written by {e.get('image', '')}, not a known self-registering app.",
            key=f"persistence:startup:{host}:{target.lower()}")
        f.add(e.source, e.row, f"Sysmon 11 by {image_name(e.get('image', ''))}")
        out.append(f)
    return out


def detect(events: list[Event], tasks: list[dict], host: str,
           allow: dict | None = None) -> list[Finding]:
    return (detect_run_keys(events, host, allow) + detect_services(events, host, allow)
            + detect_scheduled_tasks(tasks, events, host, allow) + detect_wmi(events, host)
            + detect_startup_folder(events, host))
