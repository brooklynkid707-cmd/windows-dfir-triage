"""Score triage findings against a ground-truth file (precision / recall).

Matching rule: a planted fact is *recovered* when at least one finding has the
same ATT&CK technique and the same host. A finding is a *true positive* when it
matches some planted fact, and a *false positive* otherwise. Separately, every
benign look-alike row listed in the ground truth must be cited by **zero**
findings - a benign row cited as evidence counts as a false positive too.

Ground truth is generated alongside the case by scripts/generate_case.py and
lives in tests/ so the detectors never read it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding


@dataclass
class Score:
    tp: int
    fp: int
    fn: int
    recovered: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    benign_cited: list[str] = field(default_factory=list)
    by_tactic: dict = field(default_factory=dict)
    edges_exact: bool = False

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        total = self.tp_facts + self.fn
        return self.tp_facts / total if total else 1.0

    @property
    def tp_facts(self) -> int:
        return len(self.recovered)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_ground_truth(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cites(f: Finding, host: str, source: str, row: int) -> bool:
    for e in f.evidence:
        src = e.source.rsplit("/", 1)[-1]
        if (e.host or f.host) == host and src == source and (row == 0 or e.row == row):
            return True
    return False


def score(findings: list[Finding], gt: dict, edges: list | None = None) -> Score:
    facts = gt["expected_findings"]
    fact_keys = {(x["technique"], x["host"]) for x in facts}
    recovered, missed = [], []
    by_tactic: dict[str, list[int]] = {}
    for x in facts:
        hit = any(f.technique == x["technique"] and f.host == x["host"] for f in findings)
        (recovered if hit else missed).append(x["id"])
        t = by_tactic.setdefault(x["tactic"], [0, 0])
        t[1] += 1
        t[0] += int(hit)
    tp = fp = 0
    fps = []
    for f in findings:
        if (f.technique, f.host) in fact_keys:
            tp += 1
        else:
            fp += 1
            fps.append(f"{f.host} {f.technique} {f.title}")
    benign_cited = []
    for b in gt.get("benign", []):
        if any(_cites(f, b["host"], b["source"], b["row"]) for f in findings):
            benign_cited.append(b["label"])
    fp += len(benign_cited)
    edges_exact = False
    if edges is not None:
        got = {(e.src, e.dst, e.method) for e in edges if not getattr(e, "allowlisted", "")}
        want = {(e["src"], e["dst"], e["method"]) for e in gt["lateral_edges"]}
        edges_exact = got == want
    return Score(tp=tp, fp=fp, fn=len(missed), recovered=recovered, missed=missed,
                 false_positives=fps, benign_cited=benign_cited, by_tactic=by_tactic,
                 edges_exact=edges_exact)


def to_markdown(s: Score, gt: dict) -> str:
    lines = [
        "| Metric | Value |", "| --- | --- |",
        f"| Planted facts recovered (recall) | {s.tp_facts}/{s.tp_facts + s.fn} = {s.recall:.2f} |",
        f"| Findings that match a planted fact (precision) | {s.tp}/{s.tp + s.fp} = {s.precision:.2f} |",
        f"| F1 | {s.f1:.2f} |",
        f"| Benign look-alikes cited by any finding | {len(s.benign_cited)}/{len(gt.get('benign', []))} |",
        f"| Movement graph edges equal ground truth | {'yes' if s.edges_exact else 'no'} |",
        "", "| Tactic | Recovered / planted |", "| --- | --- |",
    ]
    order = ["Initial Access", "Execution", "Persistence", "Defense Evasion",
             "Credential Access", "Discovery", "Lateral Movement", "Collection",
             "Command and Control"]
    for t in sorted(s.by_tactic, key=lambda x: order.index(x) if x in order else 99):
        got, total = s.by_tactic[t]
        lines.append(f"| {t} | {got}/{total} |")
    if s.missed:
        lines += ["", "Missed: " + ", ".join(s.missed)]
    if s.false_positives or s.benign_cited:
        lines += ["", "False positives: " + "; ".join(s.false_positives + s.benign_cited)]
    return "\n".join(lines) + "\n"
