"""Shared fixtures: repo paths, the loaded case, and one triage run."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dfirt import triage  # noqa: E402
from dfirt.ingest import load_case  # noqa: E402

CASE = ROOT / "case"
GT_PATH = ROOT / "tests" / "ground_truth.json"


@pytest.fixture(scope="session")
def case_dir() -> Path:
    return CASE


@pytest.fixture(scope="session")
def case():
    return load_case(CASE)


@pytest.fixture(scope="session")
def result(case):
    return triage.run(case)


@pytest.fixture(scope="session")
def gt() -> dict:
    return json.loads(GT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def findings_by_key(result):
    return {f.key: f for f in result.findings}


def techniques(findings, host=None):
    return {f.technique for f in findings if host is None or f.host == host}


def cited_rows(findings):
    return {(e.host, e.source.rsplit("/", 1)[-1], e.row) for f in findings for e in f.evidence}
