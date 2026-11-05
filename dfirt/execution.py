"""Evidence-of-execution correlation with a forensic confidence model.

Given a target binary (by name or full path), gather every supporting artifact
across Prefetch, Amcache, Shimcache, Sysmon EventID 1 and Security 4688, and
assign an overall confidence that the binary *executed*. The model encodes the
real nuance that separates a Tier 2 analyst from an alert-closer:

  * Prefetch  -> PROVES execution; also yields run count + last run times.
                 (A .pf file is only created when the program runs.)
  * Sysmon 1 / 4688 -> PROVES execution (a process actually started).
  * Amcache   -> indicates presence, and usually execution, WITH caveats
                 (entries can be created by compatibility scanning). Treated as
                 strong-but-not-proof on its own.
  * Shimcache -> presence/enumeration only. On Windows 8.1/10/11 the 'Executed'
                 flag is NOT set, so Shimcache ALONE does NOT prove execution.

Confidence:
  confirmed  - at least one proof-grade source (prefetch / sysmon1 / 4688)
  probable   - amcache present (execution likely) but no proof-grade source
  possible   - only shimcache (presence/enumeration; NOT proof of execution)
  none       - no supporting artifact
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .findings import Finding
from .model import ExecArtifact, iso, image_name, norm_path

PROOF_KINDS = {"prefetch", "sysmon1", "evt4688"}


@dataclass
class ExecutionAssessment:
    host: str
    target: str
    confidence: str                      # confirmed | probable | possible | none
    proves_execution: bool
    rationale: str
    run_count: Optional[int] = None
    run_times: list = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    artifacts: list[ExecArtifact] = field(default_factory=list)

    @property
    def path(self) -> str:
        full = [a.path for a in self.artifacts if "\\" in a.path]
        return full[0] if full else self.target

    def to_dict(self) -> dict:
        return {
            "host": self.host, "target": self.target, "path": self.path,
            "confidence": self.confidence,
            "proves_execution": self.proves_execution, "rationale": self.rationale,
            "run_count": self.run_count,
            "run_times": [iso(t) for t in self.run_times],
            "sources": self.sources,
        }


def _matches(art_target: str, art_path: str, target: str) -> bool:
    """Bare name -> match by image name. Full path -> match by full path only,
    so C:\\Windows\\System32\\svchost.exe never corroborates a masquerading
    svchost.exe in AppData (and vice versa)."""
    if "\\" in target or "/" in target:
        return norm_path(art_path) == norm_path(target)
    t = target.lower()
    return art_target.lower() == t or image_name(art_path) == t


def collect_for(target: str, host: str,
                exec_artifacts: list[ExecArtifact],
                processes: Optional[list] = None,
                security_events: Optional[list] = None) -> list[ExecArtifact]:
    """Return every ExecArtifact (incl. synthesized Sysmon1/4688) for a target."""
    found: list[ExecArtifact] = []
    for a in exec_artifacts:
        if a.host == host and _matches(a.target, a.path, target):
            found.append(a)
    # Sysmon EventID 1 is itself proof of execution.
    for p in (processes or []):
        if p.host == host and _matches(p.name, p.image, target):
            found.append(ExecArtifact(
                host=host, target=p.name, path=p.image, kind="sysmon1",
                first_seen=p.time, last_seen=p.time, proves_execution=True,
                source=p.source, row=p.row))
    # Security 4688 process-create is also proof ("New Process Name").
    for e in (security_events or []):
        if e.host != host or e.eid != 4688:
            continue
        pds = e.get("pd", []) or []
        candidate = pds[1] if len(pds) > 1 else ""
        if candidate and _matches(image_name(candidate), candidate, target):
            found.append(ExecArtifact(
                host=host, target=image_name(candidate), path=candidate, kind="evt4688",
                first_seen=e.time, last_seen=e.time, proves_execution=True,
                source=e.source, row=e.row))
    return found


def assess(target: str, host: str, exec_artifacts: list[ExecArtifact],
           processes: Optional[list] = None,
           security_events: Optional[list] = None) -> ExecutionAssessment:
    arts = collect_for(target, host, exec_artifacts, processes, security_events)
    kinds = {a.kind for a in arts}
    sources = sorted(kinds)

    proof = kinds & PROOF_KINDS
    run_count = None
    run_times: list = []
    for a in arts:
        if a.kind == "prefetch":
            run_count = a.run_count
            run_times = list(a.run_times)

    if not arts:
        return ExecutionAssessment(host, image_name(target) or target, "none", False,
                                   "No execution or presence artifact found for this target.",
                                   None, [], sources, arts)
    if proof:
        why = []
        if "prefetch" in kinds:
            why.append(f"Prefetch proves execution (run count {run_count}, "
                       f"last run {iso(run_times[0]) if run_times else 'n/a'})")
        if "sysmon1" in kinds:
            why.append("Sysmon EventID 1 recorded the process starting")
        if "evt4688" in kinds:
            why.append("Security 4688 recorded the process starting")
        if "amcache" in kinds:
            why.append("Amcache corroborates presence")
        if "shimcache" in kinds:
            why.append("Shimcache shows the path was enumerated (not proof on its own)")
        return ExecutionAssessment(host, image_name(target) or target, "confirmed", True,
                                   "; ".join(why), run_count, run_times, sources, arts)
    if "amcache" in kinds:
        note = ("Amcache indicates the file was present and most likely executed, "
                "but Amcache entries can also be created by compatibility scanning, "
                "so this is not proof on its own.")
        if "shimcache" in kinds:
            note += " Shimcache corroborates presence but, on Windows 10+, does not prove execution."
        return ExecutionAssessment(host, image_name(target) or target, "probable", False,
                                   note, run_count, run_times, sources, arts)
    # shimcache-only
    return ExecutionAssessment(
        host, image_name(target) or target, "possible", False,
        "Only Shimcache references this path. Shimcache records that the file "
        "existed and was enumerated by the shim engine; on Windows 8.1/10/11 the "
        "'Executed' flag is not populated, so this is NOT evidence of execution.",
        run_count, run_times, sources, arts)


def assess_all(target: str, host: str, exec_artifacts: list[ExecArtifact],
               processes: Optional[list] = None,
               security_events: Optional[list] = None) -> list[ExecutionAssessment]:
    """Assess a bare name per distinct full path on the host.

    Two binaries can share a name (System32 svchost.exe vs. a masquerading copy
    in AppData); evidence for one must never be counted for the other.
    """
    if "\\" in target or "/" in target:
        return [assess(target, host, exec_artifacts, processes, security_events)]
    arts = collect_for(target, host, exec_artifacts, processes, security_events)
    paths = sorted({norm_path(a.path) for a in arts if "\\" in a.path})
    if not paths:
        return [assess(target, host, exec_artifacts, processes, security_events)]
    out = []
    for p in paths:
        original = next(a.path for a in arts if norm_path(a.path) == p)
        out.append(assess(original, host, exec_artifacts, processes, security_events))
    return out


def matrix(targets: list[tuple[str, str]], exec_artifacts: list[ExecArtifact],
           processes: Optional[list] = None,
           security_events: Optional[list] = None) -> list[dict]:
    """Build an execution-evidence matrix row per (target, host)."""
    rows = []
    for target, host in targets:
        a = assess(target, host, exec_artifacts, processes, security_events)
        present = {k: (k in a.sources) for k in
                   ("prefetch", "sysmon1", "evt4688", "amcache", "shimcache")}
        rows.append({
            "host": host, "target": a.target, "path": target, "confidence": a.confidence,
            "prefetch": present["prefetch"], "sysmon1": present["sysmon1"],
            "evt4688": present["evt4688"], "amcache": present["amcache"],
            "shimcache": present["shimcache"],
            "run_count": a.run_count, "rationale": a.rationale,
        })
    return rows


def to_finding(a: ExecutionAssessment) -> Optional[Finding]:
    if a.confidence == "none":
        return None
    sev = {"confirmed": "high", "probable": "medium", "possible": "low"}[a.confidence]
    f = Finding(
        detector="execution", tactic="Execution", technique="T1204.002",
        technique_name="User Execution / evidence of execution",
        severity=sev, host=a.host,
        title=f"Execution evidence for {a.target}: {a.confidence}",
        description=a.rationale, confidence=a.confidence,
        key=f"execution:{a.host}:{a.target.lower()}")
    for art in a.artifacts:
        f.add(art.source, art.row, art.kind)
    return f
