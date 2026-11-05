"""CLI end-to-end, generator determinism, and committed examples up to date."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys

from conftest import CASE, GT_PATH, ROOT

EXAMPLES = ROOT / "examples"


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "dfirt", *args], cwd=cwd,
                          capture_output=True, text=True)


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_generator_reproduces_committed_case(tmp_path):
    out, gt = tmp_path / "case", tmp_path / "gt.json"
    r = subprocess.run([sys.executable, "scripts/generate_case.py", "--out", str(out),
                        "--ground-truth", str(gt)], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert tree_hashes(out) == tree_hashes(CASE)
    assert gt.read_bytes() == GT_PATH.read_bytes()


def test_help_lists_subcommands():
    r = run("--help")
    assert r.returncode == 0
    for cmd in ("manifest", "verify", "triage", "proctree", "timeline", "execution", "sigma"):
        assert cmd in r.stdout


def test_cli_manifest_then_verify_then_tamper(tmp_path):
    case = tmp_path / "case"
    shutil.copytree(CASE, case)
    assert run("manifest", str(case)).returncode == 0
    ok = run("verify", str(case))
    assert ok.returncode == 0 and "integrity OK" in ok.stdout
    f = case / "WS-ACCT-07" / "sysmon.jsonl"
    f.write_bytes(f.read_bytes().replace(b"0x1410", b"0x1010", 1))
    bad = run("verify", str(case))
    assert bad.returncode == 1 and "MODIFIED WS-ACCT-07/sysmon.jsonl" in bad.stdout
    refused = run("triage", str(case), "--manifest", str(case / "MANIFEST.json"),
                  "--out", str(tmp_path / "r.md"))
    assert refused.returncode == 1 and not (tmp_path / "r.md").exists()


def test_cli_triage_outputs(tmp_path):
    r = run("triage", "case", "--out", str(tmp_path / "r.md"), "--json", str(tmp_path / "f.json"),
            "--score", str(GT_PATH))
    assert r.returncode == 0, r.stderr
    assert "precision 1.00, recall 1.00" in r.stdout
    data = json.loads((tmp_path / "f.json").read_text())
    assert data["patient_zero"] == "WS-ACCT-07"
    assert "# Triage Report" in (tmp_path / "r.md").read_text()


def test_cli_proctree_execution_timeline(tmp_path):
    pt = run("proctree", "case/WS-ACCT-07")
    assert pt.returncode == 0 and "winword.exe" in pt.stdout and "<-- Office spawned" in pt.stdout
    ex = run("execution", "case", "procexp64.exe")
    assert "POSSIBLE (proves execution: False)" in ex.stdout
    tl = run("timeline", "case", "--key-events", "--csv", str(tmp_path / "t.csv"))
    assert tl.returncode == 0 and (tmp_path / "t.csv").read_text().startswith("time,host")


def test_cli_errors():
    assert run("triage", "no-such-case").returncode == 2
    r = run("proctree", "case/NO-SUCH-HOST")
    assert r.returncode == 2 and "not in case" in r.stderr


def test_committed_examples_are_current(tmp_path):
    """`make demo` output committed under examples/ matches a fresh run."""
    out = tmp_path / "ex"
    out.mkdir()
    r = run("triage", "case", "--manifest", "examples/MANIFEST.json",
            "--out", str(out / "triage-report.md"), "--json", str(out / "findings.json"),
            "--score", str(GT_PATH), "--score-out", str(out / "score.md"))
    assert r.returncode == 0, r.stderr
    assert run("timeline", "case", "--csv", str(out / "timeline.csv")).returncode == 0
    assert run("timeline", "case", "--key-events", "--md",
               str(out / "timeline-key-events.md")).returncode == 0
    for name in ("triage-report.md", "findings.json", "score.md", "timeline.csv",
                 "timeline-key-events.md"):
        assert (out / name).read_text() == (EXAMPLES / name).read_text(), name
