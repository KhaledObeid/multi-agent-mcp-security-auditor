"""Deterministic manifest patcher used by the Report agent. OWNER: Member A.

Kept deterministic on purpose: an LLM should not be trusted to rewrite a
security-relevant manifest, so it only explains the patch, it does not write it.

TODO (Member A):
  - Narrow wildcard scopes to the closest justified family instead of dropping them.
  - Pin vulnerable dependencies to the first fixed version reported by OSV.
"""
from __future__ import annotations

import re

from mcp_security_auditor.schemas import PermissionDiff, ScanReport, ToolPackage
from mcp_security_auditor.tools.manifest_scanner import strip_invisible


def patch_manifest(pkg: ToolPackage, scan: ScanReport | None, diff: PermissionDiff | None) -> tuple[dict, list[str]]:
    changes: list[str] = []
    patched = pkg.model_copy(deep=True)

    bad_evidence = {}
    if scan:
        for f in scan.flags:
            if f.kind in ("hidden_instruction", "sensitive_path") and f.tool_name:
                bad_evidence.setdefault(f.tool_name, []).append(f.evidence)

    for t in patched.tools:
        clean = strip_invisible(t.description)
        if clean != t.description:
            changes.append(f"{t.name}: removed invisible Unicode characters")
        # remove <IMPORTANT>...</IMPORTANT> blocks and HTML comments entirely
        new = re.sub(r"<\s*important\s*>.*?<\s*/\s*important\s*>", "", clean, flags=re.I | re.S)
        new = re.sub(r"<!--.*?-->", "", new, flags=re.S)
        # drop any remaining sentence that contains flagged evidence
        if t.name in bad_evidence:
            sentences = re.split(r"(?<=[.!?])\s+", new)
            kept = [s for s in sentences if not any(ev.lower() in s.lower() for ev in bad_evidence[t.name])]
            new = " ".join(kept)
        new = re.sub(r"\s{2,}", " ", new).strip()
        if new != clean:
            changes.append(f"{t.name}: removed injected instructions from description")
        t.description = new

    if diff and diff.unjustified_permissions:
        patched.permissions = [p for p in patched.permissions if p not in diff.unjustified_permissions]
        changes.append(f"removed unjustified permissions: {', '.join(diff.unjustified_permissions)}")

    return patched.model_dump(), changes
