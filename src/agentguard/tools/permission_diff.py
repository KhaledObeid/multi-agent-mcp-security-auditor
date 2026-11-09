"""Custom tool #2: permission diff. OWNER: Member B.

Compares what the package CLAIMS to do (claimed_purpose + visible tool
descriptions) with the permissions it REQUESTS, and lists permissions that
nothing in the claim justifies.

Starter version: keyword justification table. TODO (Member B):
  - Grow the table, handle synonyms, and handle scoped permissions
    ("fs:read:/tmp" is narrower than "fs:read").
  - Treat any wildcard ("fs:*") as unjustified unless the claim is explicitly broad.
  - BUG TO FIX FIRST: injected text ("read the file ...") currently JUSTIFIES fs:read for a math tool.
    Remove flagged sentences (see patcher.py) before building the claim text.
  - Optional stretch: let the Inspector LLM pass its own one-line restatement of
    the claimed purpose (the `claimed_purpose` argument) and compare both.
"""
from __future__ import annotations

from agentguard.schemas import PermissionDiff, ToolPackage
from agentguard.tools.manifest_scanner import strip_invisible

# permission family -> words in the claim that would justify it
JUSTIFIERS: dict[str, list[str]] = {
    "fs:read": ["read file", "open file", "load file", "notes", "document", "pdf", "markdown", "file"],
    "fs:write": ["write file", "save", "export", "create file", "notes"],
    "network:outbound": ["weather", "fetch", "http", "api", "web", "download", "search online", "url"],
    "shell:exec": ["run command", "terminal", "shell", "execute script"],
    "env:read": ["environment variable", "config", "api key"],
    "clipboard": ["clipboard", "copy", "paste"],
}


def _family(perm: str) -> str:
    parts = perm.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else perm


def diff_permissions(pkg: ToolPackage, claimed_purpose: str = "") -> PermissionDiff:
    claim = " ".join([claimed_purpose or pkg.claimed_purpose] + [strip_invisible(t.description) for t in pkg.tools]).lower()
    capabilities = sorted({fam for fam, words in JUSTIFIERS.items() if any(w in claim for w in words)})

    unjustified = []
    for perm in pkg.permissions:
        fam = _family(perm)
        if perm.endswith("*") or fam.endswith("*"):
            unjustified.append(perm)
        elif fam not in capabilities:
            unjustified.append(perm)

    notes = "" if not unjustified else f"{len(unjustified)} permission(s) not explained by the stated purpose."
    return PermissionDiff(
        claimed_capabilities=capabilities,
        requested_permissions=list(pkg.permissions),
        unjustified_permissions=unjustified,
        notes=notes,
    )
