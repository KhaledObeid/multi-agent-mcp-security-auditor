"""Intake node (not an LLM agent). OWNER: Member A.

1. Hashes the package and each tool description.
2. Compares with the last NON-BLOCKED audit of the same package name stored in
   audit_history (this only works because MemorySaver keeps state per thread_id),
   and flags a rug pull if any previously approved tool changed, or if the new
   version adds a tool, a permission or a dependency.
3. Resets the per-run fields so a second audit on the same thread starts clean
   while audit_history survives (conversation management).
"""
from __future__ import annotations

import hashlib
import json

from langchain_core.messages import RemoveMessage
from langgraph.graph.message import REMOVE_ALL_MESSAGES

from mcp_security_auditor.schemas import Verdict
from mcp_security_auditor.state import AuditState


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def intake_node(state: AuditState) -> dict:
    pkg = state.package
    tool_hashes = {t.name: _h(t.description + json.dumps(t.input_schema, sort_keys=True)) for t in pkg.tools}
    manifest_hash = _h(pkg.model_dump_json())

    previous = [r for r in state.audit_history if r.package_name == pkg.name and r.verdict != Verdict.BLOCK]
    changes: list[str] = []
    if previous:
        last = previous[-1]
        for name, h in tool_hashes.items():
            if name in last.tool_hashes and last.tool_hashes[name] != h:
                changes.append(f"tool '{name}' changed since approved v{last.package_version}")
            elif name not in last.tool_hashes:
                changes.append(f"new tool '{name}' added since v{last.package_version}")
        # a rug pull can also keep the descriptions and widen what the package may do.
        # Only ADDITIONS count: dropping a permission is safe, and a version bump of an
        # existing dependency is a normal update (OSV checks its CVEs separately).
        for perm in pkg.permissions:
            if perm not in last.permissions:
                changes.append(f"new permission '{perm}' requested since v{last.package_version}")
        for dep in pkg.dependencies:
            if dep.name not in last.dependencies:
                changes.append(f"new dependency '{dep.name}=={dep.version}' added since v{last.package_version}")

    clear = [RemoveMessage(id=REMOVE_ALL_MESSAGES)]
    return {
        "run_count": state.run_count + 1,
        "manifest_hash": manifest_hash,
        "tool_hashes": tool_hashes,
        "rug_pull_detected": bool(changes),
        "rug_pull_changes": changes,
        # reset per-run fields
        "inspector_messages": clear,
        "analyst_messages": clear,
        "redteam_messages": clear,
        "scan_report": None,
        "permission_diff": None,
        "dependency_vulns": [],
        "retrieved_sources": [],
        "findings": None,
        "needs_red_team": False,
        "red_team_results": [],
        "final_report": None,
        "policy_floor": None,
        "policy_reason": "",
        "patched_manifest": None,
        "patch_changes": [],
        "tool_rounds": {},
        "errors": [],
    }
