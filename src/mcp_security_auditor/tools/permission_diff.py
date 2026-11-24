"""Custom tool #2: permission diff. OWNER: Member B.

Compares what the package CLAIMS to do (claimed_purpose + visible tool
descriptions) with the permissions it REQUESTS, and lists permissions that
nothing in the claim justifies.

Keyword justification table + description cleaning. The cleaning step is the
security fix: an attacker's hidden text must never be allowed to justify a
permission (see clean_description / _claim_text below).

TODO (Member B):
  - Grow the table, handle synonyms, and handle scoped permissions
    ("fs:read:/tmp" is narrower than "fs:read").
  - Optional stretch: weight the honest claimed_purpose line above descriptions.

FIXED (was "BUG TO FIX FIRST"): injected text ("read the file ...") used to
JUSTIFY fs:read for a math tool, because the claim was built from raw tool
descriptions. We now strip <IMPORTANT> blocks, HTML comments, invisible Unicode
and any scanner-flagged sentence before matching, so the attack can no longer
vouch for itself. Regression tests live in tests/test_scanner.py.
"""
from __future__ import annotations

import re

from mcp_security_auditor.schemas import PermissionDiff, ToolPackage
from mcp_security_auditor.tools.manifest_scanner import scan_package, strip_invisible

# permission family -> words in the (cleaned) claim that would justify it.
# NOTE: bare "file" and "markdown" were removed from fs:read -- they justified
# file access for tools that merely format strings or happen to mention a file.
JUSTIFIERS: dict[str, list[str]] = {
    "fs:read": ["read file", "read the file", "open file", "load file", "pdf", "document", "notes"],
    "fs:write": ["write file", "save", "export", "create file", "notes"],
    "network:outbound": ["weather", "fetch", "http", "api", "web", "download", "search online", "url"],
    "shell:exec": ["run command", "terminal", "shell", "execute script"],
    "env:read": ["environment variable", "config", "api key"],
    "clipboard": ["clipboard", "copy", "paste"],
}

_IMPORTANT_BLOCK = re.compile(r"<\s*important\s*>.*?<\s*/\s*important\s*>", re.I | re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
# kinds of flag whose evidence marks a sentence as attacker-controlled
_INJECTION_FLAG_KINDS = ("hidden_instruction", "invisible_unicode", "sensitive_path")


def clean_description(text: str, evidence: list[str]) -> str:
    """Return a tool description with attacker-controlled text removed, so it can
    be used as honest evidence of what the package claims. Mirrors patcher.py.

    Steps: strip invisible Unicode, drop <IMPORTANT>...</IMPORTANT> blocks and
    HTML comments, then drop any remaining sentence containing flagged evidence
    from the scanner.
    """
    clean = strip_invisible(text)
    clean = _IMPORTANT_BLOCK.sub(" ", clean)
    clean = _HTML_COMMENT.sub(" ", clean)
    if evidence:
        sentences = re.split(r"(?<=[.!?])\s+", clean)
        clean = " ".join(s for s in sentences
                         if not any(ev.lower() in s.lower() for ev in evidence))
    return re.sub(r"\s{2,}", " ", clean).strip()


def _claim_text(pkg: ToolPackage, claimed_purpose: str) -> str:
    """Build the text that represents what the package HONESTLY claims to do:
    the stated purpose plus each tool description after the attacker's text has
    been stripped out."""
    scan = scan_package(pkg)
    evidence_by_tool: dict[str, list[str]] = {}
    for f in scan.flags:
        if f.kind in _INJECTION_FLAG_KINDS and f.tool_name:
            evidence_by_tool.setdefault(f.tool_name, []).append(f.evidence)

    parts = [claimed_purpose or pkg.claimed_purpose]
    for t in pkg.tools:
        parts.append(clean_description(t.description, evidence_by_tool.get(t.name, [])))
    return " ".join(parts).lower()


def _family(perm: str) -> str:
    parts = perm.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else perm


def diff_permissions(pkg: ToolPackage, claimed_purpose: str = "") -> PermissionDiff:
    claim = _claim_text(pkg, claimed_purpose)
    capabilities = sorted({fam for fam, words in JUSTIFIERS.items() if any(w in claim for w in words)})

    unjustified = []
    for perm in pkg.permissions:
        fam = _family(perm)
        if perm.endswith("*") or fam.endswith("*"):
            unjustified.append(perm)  # a wildcard is never justified by a specific claim
        elif fam not in capabilities:
            unjustified.append(perm)

    notes = "" if not unjustified else f"{len(unjustified)} permission(s) not explained by the stated purpose."
    return PermissionDiff(
        claimed_capabilities=capabilities,
        requested_permissions=list(pkg.permissions),
        unjustified_permissions=unjustified,
        notes=notes,
    )
