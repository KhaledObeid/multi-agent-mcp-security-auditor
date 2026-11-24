"""Offline checks for the OSV tool and its cache (OWNER: Member C). A fake requests.post replaces OSV.dev."""
from __future__ import annotations

import dataclasses
import json

import pytest
import requests

from mcp_security_auditor.tools import osv

PYYAML_RESPONSE = {"vulns": [  # same flaw listed by two databases + one flaw without a CVE alias
    {"id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343", "PYSEC-2021-142"], "summary": "Arbitrary code execution"},
    {"id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"], "summary": "Same flaw, other database"},
    {"id": "GHSA-xxxx-only", "aliases": [], "details": "No CVE assigned"},
]}
CACHE = {"fetched": "2026-11-15", "entries": {"PyPI:pyyaml==5.3": {"vuln_ids": ["CVE-cached"], "summaries": ["s"]}}}


class _Resp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Cache file in tmp_path; returns a dict to choose the network behaviour and count calls."""
    path = tmp_path / "osv_cache.json"
    path.write_text(json.dumps(CACHE), encoding="utf-8")
    monkeypatch.setattr(osv, "CACHE_PATH", path)
    osv._load_cache.cache_clear()
    net = {"up": True, "calls": 0}

    def fake_post(url, json, timeout):
        net["calls"] += 1
        if not net["up"]:
            raise requests.ConnectionError("network down")
        return _Resp(PYYAML_RESPONSE if json["package"]["name"] == "pyyaml" else {})

    monkeypatch.setattr(osv.requests, "post", fake_post)
    yield net, path, monkeypatch
    osv._load_cache.cache_clear()


def _offline(monkeypatch, value):
    monkeypatch.setattr(osv, "settings", dataclasses.replace(osv.settings, offline=value))  # Settings is frozen


def test_live_lookup_reports_each_flaw_once_by_cve_id(env):
    net, _, mp = env
    _offline(mp, False)
    v = osv.query_osv_one("pyyaml", "5.3")
    assert v.vuln_ids == ["CVE-2020-14343", "GHSA-xxxx-only"] and v.error is None
    assert v.summaries == ["Arbitrary code execution", "No CVE assigned"]


def test_online_prefers_live_and_falls_back_to_cache(env):
    net, _, mp = env
    _offline(mp, False)
    assert osv.query_osv_one("pyyaml", "5.3").vuln_ids[0] == "CVE-2020-14343"   # live wins
    net["up"] = False
    cached = osv.query_osv_one("pyyaml", "5.3")
    assert cached.vuln_ids == ["CVE-cached"] and cached.error is None          # counts as a successful lookup


def test_offline_uses_cache_without_network(env):
    net, _, mp = env
    _offline(mp, True)
    assert osv.query_osv_one("PyYAML", "5.3").vuln_ids == ["CVE-cached"]      # name case does not matter
    assert net["calls"] == 0


def test_offline_cache_miss_tries_live_then_reports_error(env):
    net, _, mp = env
    _offline(mp, True)
    assert osv.query_osv_one("httpx", "0.27.0").error is None and net["calls"] == 1
    net["up"] = False
    assert osv.query_osv_one("httpx", "0.27.0").error.startswith("ConnectionError")


def test_refresh_writes_cache_and_never_writes_a_partial_one(env, tmp_path):
    net, path, _ = env
    samples = tmp_path / "samples"
    samples.mkdir()
    pkg = {"name": "p", "version": "1", "claimed_purpose": "x", "tools": [],
           "dependencies": [{"name": "pyyaml", "version": "5.3"}, {"name": "httpx", "version": "0.27.0"}]}
    (samples / "p.json").write_text(json.dumps(pkg), encoding="utf-8")
    (samples / "labels.json").write_text("{}", encoding="utf-8")

    data = osv.refresh_cache(samples, path)
    assert set(data["entries"]) == {"PyPI:pyyaml==5.3", "PyPI:httpx==0.27.0"}
    assert json.loads(path.read_text(encoding="utf-8")) == data

    before = path.read_text(encoding="utf-8")
    net["up"] = False
    with pytest.raises(RuntimeError, match="cache not written"):
        osv.refresh_cache(samples, path)
    assert path.read_text(encoding="utf-8") == before


def test_refresh_reads_every_sample_folder(env, tmp_path):
    """The default refresh covers data/samples and data/holdout, so neither set loses its cached entries."""
    _, path, _ = env
    for folder, dep in (("samples", "pyyaml"), ("holdout", "httpx")):
        (tmp_path / folder).mkdir()
        pkg = {"name": folder, "version": "1", "claimed_purpose": "x", "tools": [],
               "dependencies": [{"name": dep, "version": "5.3" if dep == "pyyaml" else "0.27.0"}]}
        (tmp_path / folder / "p.json").write_text(json.dumps(pkg), encoding="utf-8")
    data = osv.refresh_cache((tmp_path / "samples", tmp_path / "holdout"), path)
    assert set(data["entries"]) == {"PyPI:pyyaml==5.3", "PyPI:httpx==0.27.0"}
    assert osv.SAMPLE_DIRS[1].name == "holdout"
