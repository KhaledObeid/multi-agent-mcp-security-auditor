"""Tool: OSV.dev vulnerability lookup, with a local cache. OWNER: Member C.

Free public API, no key needed. Docs: https://google.github.io/osv.dev/api/
POST https://api.osv.dev/v1/query with {"package": {...}, "version": "..."}.

Cache (data/osv_cache.json): saved OSV answers for the dependencies of data/samples, so
audits do not depend on the network.
  online mode   live lookup first; the cache only if the lookup fails
  offline mode  cache first; a live lookup only for a dependency the cache does not hold
A cached answer is a successful lookup (error=None), so it does not trigger the report's
"dependencies could not be checked" rule. Refresh it (internet, no Gemini quota) with:
    python -m mcp_security_auditor.tools.osv --refresh

Not done, on purpose:
  - /v1/querybatch: returns ids only (details need one more call per vuln), and our packages
    have at most 3 dependencies, so it would add calls rather than save them.
  - CVSS severity: DependencyVuln has no severity field and schemas.py is frozen (11 Nov).
"""
from __future__ import annotations

import json
import sys
from datetime import date
from functools import lru_cache
from pathlib import Path

import requests

from mcp_security_auditor.config import ROOT, settings
from mcp_security_auditor.schemas import DependencyVuln, ToolPackage

OSV_URL = "https://api.osv.dev/v1/query"
CACHE_PATH = ROOT / "data" / "osv_cache.json"


def _key(name: str, version: str, ecosystem: str) -> str:
    return f"{ecosystem}:{name.lower()}=={version}"


@lru_cache(maxsize=1)
def _load_cache() -> dict:
    """Read the cache file once per process (call _load_cache.cache_clear() after changing it)."""
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"fetched": None, "entries": {}}


def _from_cache(name: str, version: str, ecosystem: str) -> DependencyVuln | None:
    entry = _load_cache()["entries"].get(_key(name, version, ecosystem))
    return DependencyVuln(package=name, version=version, **entry) if entry is not None else None


def _query_live(name: str, version: str, ecosystem: str) -> DependencyVuln:
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        r = requests.post(OSV_URL, json=payload, timeout=settings.osv_timeout_s)
        r.raise_for_status()
        ids, summaries = [], []
        for v in r.json().get("vulns", []):
            # OSV lists the same flaw once per advisory database (GHSA-..., PYSEC-...):
            # use its CVE alias when it has one, and keep each flaw only once
            vid = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id", ""))
            if vid not in ids:
                ids.append(vid)
                summaries.append((v.get("summary") or v.get("details", ""))[:200])
        return DependencyVuln(package=name, version=version, vuln_ids=ids[:10], summaries=summaries[:5])
    except Exception as e:  # network down, rate limited, bad ecosystem name...
        return DependencyVuln(package=name, version=version, error=f"{type(e).__name__}: {e}")


def query_osv_one(name: str, version: str, ecosystem: str = "PyPI") -> DependencyVuln:
    if settings.offline and (hit := _from_cache(name, version, ecosystem)):
        return hit
    live = _query_live(name, version, ecosystem)
    if live.error and (hit := _from_cache(name, version, ecosystem)):
        return hit
    return live


def refresh_cache(samples_dir: Path = ROOT / "data" / "samples", path: Path | None = None) -> dict:
    """Query OSV live for every dependency of every sample and rewrite the cache file."""
    path = path or CACHE_PATH
    entries, failed = {}, []
    for p in sorted(samples_dir.glob("*.json")):
        if p.name == "labels.json":
            continue
        for d in ToolPackage.model_validate_json(p.read_text(encoding="utf-8")).dependencies:
            key = _key(d.name, d.version, d.ecosystem)
            if key in entries:
                continue
            v = _query_live(d.name, d.version, d.ecosystem)
            if v.error:
                failed.append(f"{key}: {v.error}")
            else:
                entries[key] = {"vuln_ids": v.vuln_ids, "summaries": v.summaries}
    if failed:  # never overwrite a good cache with a partial one
        raise RuntimeError("OSV lookups failed, cache not written:\n  " + "\n  ".join(failed))
    data = {"fetched": date.today().isoformat(), "source": OSV_URL, "entries": entries}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _load_cache.cache_clear()
    return data


if __name__ == "__main__":
    if sys.argv[1:] != ["--refresh"]:
        sys.exit("usage: python -m mcp_security_auditor.tools.osv --refresh")
    out = refresh_cache()
    for k, e in out["entries"].items():
        print(f"{k:28s} {len(e['vuln_ids']):2d} vulns  {', '.join(e['vuln_ids'][:4])}")
    print(f"Wrote {CACHE_PATH} ({len(out['entries'])} dependencies, fetched {out['fetched']})")
