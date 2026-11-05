"""Ingest adapters: tool-specific exports -> common model.

``load_case(case_dir)`` walks a ``case/<host>/`` tree, dispatches each file to
the right parser by filename convention, and returns a :class:`Case` holding
normalized events, processes and execution artifacts across every host.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..model import Event, ExecArtifact, Process
from . import amcache, evtx, mft, prefetch, recmd, shimcache, sysmon, tasks


@dataclass
class Case:
    root: Path
    hosts: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    processes: list[Process] = field(default_factory=list)
    exec_artifacts: list[ExecArtifact] = field(default_factory=list)
    tasks: list[dict] = field(default_factory=list)
    mft_rows: list[dict] = field(default_factory=list)

    def host_events(self, host: str) -> list[Event]:
        return [e for e in self.events if e.host == host]

    def host_processes(self, host: str) -> list[Process]:
        return [p for p in self.processes if p.host == host]


def _host_from_dir(d: Path) -> str:
    return d.name


def load_host(host_dir: Path, case: Case) -> None:
    host = _host_from_dir(host_dir)
    if host not in case.hosts:
        case.hosts.append(host)
    for f in sorted(host_dir.glob("*")):
        if f.is_dir():
            if f.name == "tasks":
                for xml in sorted(f.glob("*.xml")):
                    case.tasks.append(tasks.parse_task_xml(xml, host))
            continue
        name = f.name.lower()
        if name == "sysmon.jsonl" or name.endswith("_sysmon.jsonl"):
            procs, evs = sysmon.parse(f, host)
            case.processes.extend(procs)
            case.events.extend(evs)
        elif name.endswith("_evtxecmd.csv"):
            case.events.extend(evtx.parse(f, host))
        elif "pecmd" in name or name.startswith("prefetch"):
            case.exec_artifacts.extend(prefetch.parse(f, host))
        elif "amcache" in name:
            case.exec_artifacts.extend(amcache.parse(f, host))
        elif "appcompatcache" in name or "shimcache" in name:
            case.exec_artifacts.extend(shimcache.parse(f, host))
        elif "recmd" in name or "runkey" in name:
            case.events.extend(recmd.parse(f, host))
        elif "mft" in name:
            case.mft_rows.extend(mft.parse(f, host))


def _is_host_dir(d: Path) -> bool:
    return (d / "sysmon.jsonl").exists() or any(d.glob("*_EvtxECmd.csv"))


def load_case(case_dir: str | Path) -> Case:
    """Load a case directory (``case/<HOST>/...``) or a single host directory."""
    root = Path(case_dir)
    if not root.is_dir():
        raise FileNotFoundError(str(root))
    case = Case(root=root)
    if _is_host_dir(root):
        load_host(root, case)
    else:
        for d in sorted(p for p in root.iterdir() if p.is_dir() and _is_host_dir(p)):
            load_host(d, case)
    case.events.sort(key=lambda e: (e.time or _min_dt(), e.host, e.source, e.row))
    case.processes.sort(key=lambda p: (p.time or _min_dt(), p.host, p.row))
    return case


def _min_dt():
    from datetime import datetime, timezone
    return datetime.min.replace(tzinfo=timezone.utc)
