"""Evidence manifest and tamper detection."""
from __future__ import annotations

import json
import shutil

import pytest

from dfirt import integrity


@pytest.fixture()
def case_copy(tmp_path, case_dir):
    dst = tmp_path / "case"
    shutil.copytree(case_dir, dst)
    integrity.write_manifest(dst)
    return dst


def test_manifest_hashes_every_artifact(case_dir):
    m = integrity.build_manifest(case_dir)
    files = {f.path for f in m.files}
    assert len(files) == 20
    assert "WS-ACCT-07/tasks/MicrosoftEdgeUpdateTaskUser.xml" in files
    assert all(len(f.sha256) == 64 for f in m.files)
    assert {f.host for f in m.files} == {"DC-01", "FS-01", "WS-ACCT-07"}
    assert [c.action for c in m.custody] == ["acquired", "received"]


def test_manifest_is_deterministic(case_dir):
    assert integrity.build_manifest(case_dir).to_json() == integrity.build_manifest(case_dir).to_json()


def test_verify_clean_case_ok(case_copy):
    r = integrity.verify(case_copy, case_copy / integrity.MANIFEST_NAME)
    assert r.ok and r.summary.startswith("integrity OK")


def test_verify_detects_single_byte_change(case_copy):
    target = case_copy / "DC-01" / "Security_EvtxECmd.csv"
    data = bytearray(target.read_bytes())
    idx = data.index(b"0x17")
    data[idx + 3] = ord("2")          # 0x17 -> 0x12: one byte, same size
    target.write_bytes(bytes(data))
    r = integrity.verify(case_copy, case_copy / integrity.MANIFEST_NAME)
    assert not r.ok and r.modified == ["DC-01/Security_EvtxECmd.csv"]
    assert r.missing == [] and r.added == []


def test_verify_detects_missing_and_added_files(case_copy):
    (case_copy / "FS-01" / "System_EvtxECmd.csv").unlink()
    (case_copy / "FS-01" / "extra.csv").write_text("x\n")
    r = integrity.verify(case_copy, case_copy / integrity.MANIFEST_NAME)
    assert r.missing == ["FS-01/System_EvtxECmd.csv"]
    assert r.added == ["FS-01/extra.csv"]
    assert "1 missing" in r.summary and "1 added" in r.summary


def test_manifest_roundtrip_json(case_copy):
    text = (case_copy / integrity.MANIFEST_NAME).read_text()
    m = integrity.Manifest.from_json(text)
    assert json.loads(m.to_json()) == json.loads(text)


def test_committed_example_manifest_matches_case(case_dir):
    from conftest import ROOT
    r = integrity.verify(case_dir, ROOT / "examples" / "MANIFEST.json")
    assert r.ok, r.summary
