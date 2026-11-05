"""Triage orchestrator: run every detector over a loaded case and assemble one
de-duplicated finding set plus the derived artefacts the report needs
(process trees, movement graph, execution matrix, IOC list, patient zero).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import allowlist, credential, evasion, execution, lateral, persistence, proctree
from .findings import Finding, sort_findings
from .ingest import Case
from .model import defang_ip, image_name, norm_path

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

# Keys emitted by more than one detector for the same underlying fact. The
# orchestrator keeps one finding per fact and merges the evidence.
_ALIASES = {
    "proctree:lsass": "credential:lsass",
    "proctree:masquerade": "evasion:masquerade",
}

DISCOVERY = [
    ('net group "domain admins"', "T1069.002", "Permission Groups Discovery: Domain Groups"),
    ("nltest /dclist", "T1018", "Remote System Discovery"),
    ("whoami /all", "T1033", "System Owner/User Discovery"),
    ("net view", "T1135", "Network Share Discovery"),
    ("net user /domain", "T1087.002", "Account Discovery: Domain Account"),
]
ARCHIVERS = {"7z.exe", "7za.exe", "rar.exe", "winrar.exe", "makecab.exe"}
STAGING_DIRS = ("c:\\perflogs", "c:\\users\\public\\", "c:\\programdata\\", "\\temp\\")


@dataclass
class TriageResult:
    case: Case
    findings: list[Finding]
    edges: list
    trees: dict
    exec_matrix: list[dict]
    payload_assessment: execution.ExecutionAssessment
    iocs: dict
    patient_zero: Optional[str]
    sigma_hits: list[dict]

    def by_tactic(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.tactic, []).append(f)
        return out


def _canonical(key: str) -> str:
    for old, new in _ALIASES.items():
        if key.startswith(old + ":"):
            return new + key[len(old):]
    return key


def dedupe(findings: list[Finding]) -> list[Finding]:
    out: dict[str, Finding] = {}
    for f in findings:
        k = _canonical(f.key or f"{f.detector}:{f.host}:{f.title}")
        if k not in out:
            f.key = k
            out[k] = f
            continue
        keep = out[k]
        seen = {(e.source, e.row) for e in keep.evidence}
        for e in f.evidence:
            if (e.source, e.row) not in seen:
                keep.evidence.append(e)
                seen.add((e.source, e.row))
    return list(out.values())


def _initial_access(case: Case) -> list[Finding]:
    out = []
    for p in case.processes:
        if p.parent_name in proctree.OFFICE_APPS and p.name in proctree.SCRIPT_HOSTS:
            f = Finding(
                detector="triage", tactic="Initial Access", technique="T1566.001",
                technique_name="Phishing: Spearphishing Attachment", severity="high", host=p.host,
                title=f"Macro document opened in {p.parent_name} launched {p.name}",
                description=("Office opened a macro-enabled document from the user's Downloads "
                             "folder and the macro started an encoded PowerShell command."),
                key=f"triage:initial_access:{p.host}")
            f.add(p.source, p.row, f"parent cmd: {p.parent_command_line}")
            out.append(f)
    return out


def _discovery(case: Case) -> list[Finding]:
    out = []
    for p in case.processes:
        cl = p.command_line.lower()
        for needle, tech, name in DISCOVERY:
            if needle in cl:
                f = Finding(
                    detector="triage", tactic="Discovery", technique=tech, technique_name=name,
                    severity="medium", host=p.host, title=f"`{p.command_line}` on {p.host}",
                    description=f"Built-in discovery command run as {p.user} (parent {p.parent_name}).",
                    key=f"triage:discovery:{p.host}:{tech}")
                f.add(p.source, p.row, p.command_line)
                out.append(f)
    return out


def _collection(case: Case) -> list[Finding]:
    out = []
    for p in case.processes:
        if p.name in ARCHIVERS:
            f = Finding(
                detector="triage", tactic="Collection", technique="T1560.001",
                technique_name="Archive Collected Data: Archive via Utility", severity="high",
                host=p.host, title=f"{p.name} archived data on {p.host}",
                description=f"Archiver run from {p.image} (password-protected archive).",
                key=f"triage:archive:{p.host}")
            f.add(p.source, p.row, p.command_line)
            out.append(f)
    for e in case.events:
        if e.action != "file_create":
            continue
        tgt = norm_path(e.get("target_filename", ""))
        if tgt.endswith((".7z", ".zip", ".rar", ".cab")) and any(d in tgt for d in STAGING_DIRS):
            f = Finding(
                detector="triage", tactic="Collection", technique="T1074.001",
                technique_name="Data Staged: Local Data Staging", severity="high", host=e.host,
                title=f"Archive staged at {e.get('target_filename')}",
                description="Archive written to a directory commonly abused for staging.",
                key=f"triage:staging:{e.host}")
            f.add(e.source, e.row, f"Sysmon 11 by {image_name(e.get('image', ''))}")
            out.append(f)
    return out


def _c2(case: Case) -> list[Finding]:
    out = []
    dns = {e.get("query_name"): e for e in case.events if e.action == "dns_query"}
    for e in case.events:
        if e.action != "network_connect":
            continue
        dip, dhost = e.get("dest_ip", ""), e.get("dest_host", "")
        if dip.startswith(("10.", "192.168.", "172.16.", "127.")):
            continue
        f = Finding(
            detector="triage", tactic="Command and Control", technique="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols", severity="high", host=e.host,
            title=f"{image_name(e.get('image', ''))} connected to {defang_ip(dip)}:{e.get('dest_port')} "
                  f"({dhost.replace('.', '[.]')})",
            description="Outbound HTTPS from a script host seconds after macro execution.",
            key=f"triage:c2:{e.host}:{dip}")
        if dhost in dns:
            f.add(dns[dhost].source, dns[dhost].row, f"Sysmon 22 DNS {dhost}")
        f.add(e.source, e.row, f"Sysmon 3 -> {dip}:{e.get('dest_port')}")
        out.append(f)
    return out


def collect_iocs(case: Case) -> dict:
    hashes, paths, ips, domains = set(), set(), set(), set()
    for p in case.processes:
        if p.sha256 and (persistence.is_suspicious_path(p.image)):
            hashes.add(p.sha256)
            paths.add(p.image)
    for e in case.events:
        if e.action == "network_connect" and not e.get("dest_ip", "").startswith("10."):
            ips.add(e.get("dest_ip"))
            if e.get("dest_host"):
                domains.add(e.get("dest_host"))
        if e.action == "scriptblock":
            import re
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", e.get("payload", "")):
                if not ip.startswith(("10.", "127.")):
                    ips.add(ip)
        if e.action == "file_create":
            tgt = e.get("target_filename", "")
            if tgt.lower().endswith(".7z"):
                paths.add(tgt)
    return {"sha256": sorted(hashes), "paths": sorted(paths), "ips": sorted(ips),
            "ips_defanged": [defang_ip(i) for i in sorted(ips)],
            "domains": sorted(domains),
            "domains_defanged": [d.replace(".", "[.]") for d in sorted(domains)]}


def patient_zero(case: Case, edges: list) -> Optional[str]:
    """The host that only ever appears as a movement *source*, cross-checked
    against the initial-access lineage."""
    attack = lateral.attack_edges(edges)
    srcs, dsts = {e.src for e in attack}, {e.dst for e in attack}
    roots = sorted(s for s in srcs - dsts if s in case.hosts)
    ia_hosts = {p.host for p in case.processes
                if p.parent_name in proctree.OFFICE_APPS and p.name in proctree.SCRIPT_HOSTS}
    both = [h for h in roots if h in ia_hosts]
    if both:
        return both[0]
    if roots:
        return roots[0]
    return sorted(ia_hosts)[0] if ia_hosts else None


def payload_targets(case: Case) -> list[tuple[str, str]]:
    seen, out = set(), []
    for p in case.processes:
        if persistence.is_suspicious_path(p.image) or p.name in ("psexesvc.exe",) or \
                p.name in ARCHIVERS:
            k = (p.image, p.host)
            if k not in seen:
                seen.add(k)
                out.append(k)
    return out


def run(case: Case, allow: dict | None = None) -> TriageResult:
    from . import sigma

    allow = allow if allow is not None else allowlist.load()
    raw: list[Finding] = []
    lsass = [e for e in case.events if e.action == "process_access"]
    for host in case.hosts:
        raw += proctree.detect(case.processes, host, lsass)
        raw += persistence.detect(case.events, case.tasks, host, allow)
        raw += credential.detect(case.events, host)
        raw += evasion.detect(case.events, case.mft_rows, case.processes, host)
    edges, lat = lateral.analyze(case.events, allow)
    raw += lat + _initial_access(case) + _discovery(case) + _collection(case) + _c2(case)
    findings = sort_findings(dedupe(sort_findings(raw)))   # strongest finding names the fact

    targets = payload_targets(case)
    # Contrast rows: binaries seen ONLY in Shimcache (presence, not execution).
    proven = {norm_path(a.path) for a in case.exec_artifacts if a.kind != "shimcache"}
    proven |= {norm_path(p.image) for p in case.processes}
    contrast = [(a.path, a.host) for a in case.exec_artifacts
                if a.kind == "shimcache" and norm_path(a.path) not in proven]
    matrix = execution.matrix(targets + contrast, case.exec_artifacts,
                              case.processes, case.events)
    pz = patient_zero(case, edges)
    payload = next(((t, h) for t, h in targets if h == pz), targets[0] if targets else ("", ""))
    pa = execution.assess(payload[0], payload[1], case.exec_artifacts, case.processes, case.events)
    hits = sigma.evaluate(sigma.load_rules(), case.events)
    return TriageResult(case=case, findings=findings, edges=edges,
                        trees={h: proctree.build_tree(case.processes, h) for h in case.hosts},
                        exec_matrix=matrix, payload_assessment=pa, iocs=collect_iocs(case),
                        patient_zero=pz, sigma_hits=hits)
