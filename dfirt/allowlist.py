"""Load the environment allowlist (config/allowlist.yml).

Detectors suppress a benign look-alike only on an *exact* allowlist match
(account + source + time window, or name + path prefix), never on a name alone:
an attacker can name a Run key ``GoogleUpdate`` but cannot also make it point
into ``Program Files`` without admin rights.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "allowlist.yml"


@lru_cache(maxsize=8)
def _load(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load(path: str | Path | None = None) -> dict:
    return _load(str(path or DEFAULT_PATH))


def rdp_allowed(account: str, source_ip: str, target: str, hour_utc: int | None,
                allow: dict | None = None) -> str | None:
    """Return the ticket id if this RDP logon is sanctioned, else None."""
    for e in (allow if allow is not None else load()).get("rdp", []):
        if e.get("account", "").lower() != account.lower():
            continue
        if e.get("source_ip") != source_ip:
            continue
        if target not in e.get("targets", []):
            continue
        lo, hi = e.get("business_hours_utc", [0, 24])
        if hour_utc is not None and not (lo <= hour_utc < hi):
            continue
        return e.get("ticket", "allowlisted")
    return None


def _prefix(path: str, prefix: str) -> bool:
    return path.strip('"').lower().startswith(prefix.lower())


def run_key_allowed(value_name: str, target_path: str, allow: dict | None = None) -> bool:
    for e in (allow if allow is not None else load()).get("run_keys", []):
        if e.get("value_name", "").lower() == value_name.lower() and \
                _prefix(target_path, e.get("path_prefix", "\0")):
            return True
    return False


def task_allowed(name: str, command: str, principal: str, allow: dict | None = None) -> bool:
    for e in (allow if allow is not None else load()).get("scheduled_tasks", []):
        if e.get("name", "").lower() == name.lower() and \
                _prefix(command, e.get("command_prefix", "\0")) and \
                e.get("principal", "").lower() == principal.lower():
            return True
    return False


def service_allowed(name: str, image: str, info: str, allow: dict | None = None) -> bool:
    for e in (allow if allow is not None else load()).get("services", []):
        if e.get("name", "").lower() == name.lower() and \
                _prefix(image, e.get("image_prefix", "\0")) and \
                e.get("signer", "\0").lower() in info.lower():
            return True
    return False
