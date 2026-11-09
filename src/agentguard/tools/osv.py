"""Tool: OSV.dev vulnerability lookup. OWNER: Member C.

Free public API, no key needed. Docs: https://google.github.io/osv.dev/api/
POST https://api.osv.dev/v1/query with {"package": {...}, "version": "..."}.

TODO (Member C):
  - Switch to /v1/querybatch when there are many dependencies.
  - Cache responses in a small JSON file so demos do not depend on the network.
  - Pull severity (CVSS) out of each vuln record and pass it to the analyst.
"""
from __future__ import annotations

import requests

from agentguard.config import settings
from agentguard.schemas import DependencyVuln

OSV_URL = "https://api.osv.dev/v1/query"


def query_osv_one(name: str, version: str, ecosystem: str = "PyPI") -> DependencyVuln:
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        r = requests.post(OSV_URL, json=payload, timeout=settings.osv_timeout_s)
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
        return DependencyVuln(
            package=name,
            version=version,
            vuln_ids=[v.get("id", "") for v in vulns][:10],
            summaries=[(v.get("summary") or v.get("details", ""))[:200] for v in vulns][:5],
        )
    except Exception as e:  # network down, rate limited, bad ecosystem name...
        return DependencyVuln(package=name, version=version, error=f"{type(e).__name__}: {e}")
