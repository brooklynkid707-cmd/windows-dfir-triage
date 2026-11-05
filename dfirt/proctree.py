"""Process-tree reconstruction and anomalous-lineage detection.

Builds a per-host forest from Sysmon EventID 1 records keyed by ProcessGuid /
ParentProcessGuid, then flags lineages that are suspicious on Windows:

  * Office application (winword/excel/outlook/...) spawning a script host
    (powershell/cmd/wscript/cscript/mshta)  -> T1566.001 / T1059
  * services.exe spawning an unexpected child                 -> T1543.003 hint
  * a system-binary *name* (svchost.exe, lsass.exe, ...) running from a
    non-System32 path, or with the wrong parent                -> T1036.005
  * LSASS access by a non-system process                       -> T1003.001

Benign look-alikes stay quiet: services.exe -> svchost.exe in System32, a
SCCM-managed powershell.exe under CcmExec, svchost.exe in System32 from
services.exe.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .findings import Finding
from .model import Process, image_name, in_system_dir, is_masquerade, norm_path

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
               "msaccess.exe", "mspub.exe", "onenote.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
# Directories a legitimately-installed service image lives in.
TRUSTED_INSTALL_DIRS = (
    "c:\\program files\\", "c:\\program files (x86)\\",
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
)


def _untrusted_service_path(path: str) -> bool:
    """True when a service image is NOT in a normal install directory.

    A signed vendor service under Program Files is trusted; PSEXESVC dropped in
    the Windows root, or anything in AppData/Public/Temp, is not.
    """
    p = norm_path(path)
    return not any(p.startswith(t) for t in TRUSTED_INSTALL_DIRS)


@dataclass
class TreeNode:
    proc: Process
    children: list["TreeNode"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.proc.name


@dataclass
class ProcessTree:
    host: str
    roots: list[TreeNode]
    by_guid: dict[str, TreeNode]

    def render(self, detail: bool = True, flags: Optional[dict] = None,
               width: int = 96) -> str:
        """Text tree. Roots whose parent is not in the log are shown under a
        synthetic ``[parent not in log: name (pid)]`` line so the lineage is
        still readable. ``flags`` maps ProcessGuid -> short anomaly label."""
        flags = flags or {}
        lines: list[str] = []

        def label(n: TreeNode) -> str:
            p = n.proc
            if not detail:
                return n.name
            t = p.time.strftime("%H:%M:%S") if p.time else "--:--:--"
            user = (p.user or "-").split("\\")[-1]
            text = f"{n.name} ({p.pid}) {t} {user}"
            args = _args_only(p.command_line)
            if args:
                text += f"  {args}"
            if len(text) > width:
                text = text[: width - 3] + "..."
            if p.guid in flags:
                text += f"   <-- {flags[p.guid]}"
            return text

        def walk(node: TreeNode, prefix: str, last: bool, top: bool) -> None:
            if top:
                lines.append(prefix + label(node))
                child_prefix = prefix
            else:
                lines.append(prefix + ("└── " if last else "├── ") + label(node))
                child_prefix = prefix + ("    " if last else "│   ")
            for i, kid in enumerate(node.children):
                walk(kid, child_prefix, i == len(node.children) - 1, False)

        # Group orphan roots by their (missing) parent so siblings share one header.
        groups: list[tuple[str, list[TreeNode]]] = []
        index: dict[str, int] = {}
        for r in self.roots:
            p = r.proc
            key = p.parent_guid if (p.parent_image and p.parent_guid not in self.by_guid) else ""
            if key and key in index:
                groups[index[key]][1].append(r)
                continue
            if key:
                index[key] = len(groups)
            groups.append((key, [r]))
        for key, nodes in groups:
            if not key:
                walk(nodes[0], "", True, True)
                continue
            p = nodes[0].proc
            lines.append(f"[parent not in log: {p.parent_name} ({p.parent_pid})]")
            for i, n in enumerate(nodes):
                walk(n, "", i == len(nodes) - 1, False)
        return "\n".join(lines)

    def subtree(self, guid: str) -> "ProcessTree":
        """Tree restricted to the root that contains ``guid``."""
        node = self.by_guid[guid]
        while node.proc.parent_guid in self.by_guid:
            node = self.by_guid[node.proc.parent_guid]
        return ProcessTree(self.host, [node], self.by_guid)


def _args_only(cmdline: str) -> str:
    """Drop the leading image token (quoted or bare) and keep the arguments."""
    c = (cmdline or "").strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[end + 1:].strip() if end != -1 else ""
    return c.split(" ", 1)[1].strip() if " " in c else ""


def build_tree(processes: list[Process], host: str) -> ProcessTree:
    procs = [p for p in processes if p.host == host]
    by_guid: dict[str, TreeNode] = {p.guid: TreeNode(p) for p in procs}
    roots: list[TreeNode] = []
    for node in by_guid.values():
        parent = by_guid.get(node.proc.parent_guid)
        if parent is not None and parent is not node:
            parent.children.append(node)
        else:
            roots.append(node)
    # deterministic ordering
    def keyf(n: TreeNode):
        return (n.proc.time or _min_dt(), n.proc.row)
    for node in by_guid.values():
        node.children.sort(key=keyf)
    roots.sort(key=keyf)
    return ProcessTree(host=host, roots=roots, by_guid=by_guid)


def _min_dt():
    from datetime import datetime, timezone
    return datetime.min.replace(tzinfo=timezone.utc)


def detect(processes: list[Process], host: str,
           lsass_events: Optional[list] = None) -> list[Finding]:
    """Return anomalous-lineage findings for one host."""
    findings: list[Finding] = []
    procs = [p for p in processes if p.host == host]

    for p in procs:
        parent = p.parent_name
        child = p.name
        # Office -> script host
        if parent in OFFICE_APPS and child in SCRIPT_HOSTS:
            f = Finding(
                detector="proctree", tactic="Execution", technique="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                severity="high", host=host,
                title=f"{parent} spawned {child} (Office application spawning a script host)",
                description=(f"{parent} is not expected to launch {child}; this is the "
                             "classic macro-execution lineage."),
                key=f"proctree:office_child:{host}:{child}")
            f.add(p.source, p.row, f"{parent} -> {child}: {p.command_line[:60]}")
            findings.append(f)
        # masquerading system binary (wrong path)
        if is_masquerade(p.image):
            f = Finding(
                detector="proctree", tactic="Defense Evasion", technique="T1036.005",
                technique_name="Masquerading: match legitimate name or location",
                severity="high", host=host,
                title=f"{child} running from non-System32 path {p.image}",
                description=("A protected Windows binary name is executing from a "
                             "user-writable directory - name masquerading."),
                key=f"proctree:masquerade:{host}:{p.image.lower()}")
            f.add(p.source, p.row, f"image={p.image}, parent={p.parent_image}")
            findings.append(f)
        # system binary with wrong parent (svchost not from services.exe)
        if child == "svchost.exe" and in_system_dir(p.image) and parent and parent != "services.exe":
            f = Finding(
                detector="proctree", tactic="Defense Evasion", technique="T1036.005",
                technique_name="Masquerading: svchost with unexpected parent",
                severity="medium", host=host,
                title=f"svchost.exe spawned by {parent} instead of services.exe",
                description="System32 svchost.exe should be a child of services.exe.",
                key=f"proctree:svchost_parent:{host}:{p.guid}")
            f.add(p.source, p.row, f"parent={p.parent_image}")
            findings.append(f)
        # services.exe spawning a service image from a user-writable path.
        # A signed vendor service under Program Files stays quiet; only images
        # in AppData/Public/Temp/ProgramData/Windows-root etc. fire.
        if parent == "services.exe" and child not in (
                "svchost.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe") \
                and _untrusted_service_path(p.image):
            f = Finding(
                detector="proctree", tactic="Persistence", technique="T1543.003",
                technique_name="Create or modify system process: Windows service",
                severity="medium", host=host,
                title=f"services.exe spawned {child} from {p.image}",
                description="A new service's image is running from outside Program Files/System32.",
                key=f"persistence:service:{host}:{child.rsplit('.', 1)[0]}")
            f.add(p.source, p.row, f"image={p.image}")
            findings.append(f)

    # LSASS access by a non-system process (from Sysmon 10)
    for ev in (lsass_events or []):
        if ev.host != host:
            continue
        simg = ev.get("source_image", "")
        sname = image_name(simg)
        if "lsass.exe" not in ev.get("target_image", "").lower():
            continue
        if in_system_dir(simg) and sname in ("wininit.exe", "services.exe", "csrss.exe",
                                             "lsass.exe", "msmpeng.exe"):
            continue  # legitimate system access
        f = Finding(
            detector="proctree", tactic="Credential Access", technique="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            severity="critical", host=host,
            title=f"LSASS accessed by non-system process {sname or simg}",
            description=(f"{simg} opened a handle to lsass.exe with "
                         f"GrantedAccess {ev.get('granted_access','')}."),
            key=f"proctree:lsass:{host}:{simg.lower()}")
        f.add(ev.source, ev.row, f"GrantedAccess={ev.get('granted_access','')}")
        findings.append(f)
    return findings


def anomaly_flags(processes: list[Process], host: str,
                  lsass_events: Optional[list] = None) -> dict[str, str]:
    """ProcessGuid -> short label for every process the lineage rules flag."""
    flags: dict[str, list[str]] = {}
    for p in processes:
        if p.host != host:
            continue
        if p.parent_name in OFFICE_APPS and p.name in SCRIPT_HOSTS:
            flags.setdefault(p.guid, []).append("Office spawned script host")
        if is_masquerade(p.image):
            flags.setdefault(p.guid, []).append(f"{p.name} outside System32")
        if p.parent_name == "services.exe" and _untrusted_service_path(p.image) \
                and p.name not in ("svchost.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe"):
            flags.setdefault(p.guid, []).append("service image outside Program Files/System32")
    by_image = {p.image.lower(): p.guid for p in processes if p.host == host}
    for e in (lsass_events or []):
        if e.host == host and "lsass" in e.get("target_image", "").lower():
            g = by_image.get(e.get("source_image", "").lower())
            if g and not in_system_dir(e.get("source_image", "")):
                flags.setdefault(g, []).append(f"opened LSASS {e.get('granted_access', '')}")
    return {g: "; ".join(v) for g, v in flags.items()}
