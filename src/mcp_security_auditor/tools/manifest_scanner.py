"""Custom tool #1: manifest scanner. OWNER: Member B.

Deterministic (no LLM). Takes a ToolPackage and returns a ScanReport.
The starter rules below already work on the sample packages; your job is to
extend them, reduce false positives, and write tests in tests/test_scanner.py.

TODO (Member B):
  - Add more injection phrasings (look at the incident write-ups in data/corpus).
  - Detect base64 / hex blobs and decode them before matching.
  - Detect Unicode homoglyphs in tool NAMES (tool shadowing, e.g. "send_emaiI").
  - Detect a tool description that mentions ANOTHER tool by name (cross-tool shadowing).
  - Tune severity_hint and the risk_score weights.
"""
from __future__ import annotations

import re
import unicodedata

from mcp_security_auditor.schemas import ScanFlag, ScanReport, Severity, ToolPackage

# --- pattern tables ---------------------------------------------------------
INJECTION_PATTERNS = [
    r"<\s*important\s*>",
    r"<!--.*?-->",
    r"\bignore (all |any )?(previous|prior|above) (instructions|rules)\b",
    r"\bdo not (tell|mention|inform|reveal)\b.*\b(user|human)\b",
    r"\bbefore (using|calling|invoking) (this|any) tool\b",
    r"\byou must (first|always)\b",
    r"\balways (call|send|include|pass|forward)\b",
    r"\b(secretly|silently|without (the )?user)\b",
    r"\bsystem prompt\b",
    r"\b(sidenote|side note)\b",
]
SENSITIVE_PATHS = [r"~/\.ssh", r"id_rsa", r"\.env\b", r"/etc/passwd", r"mcp\.json", r"credentials", r"\.aws/"]
SHELL_PATTERNS = [r"\bsubprocess\b", r"\bos\.system\b", r"\beval\(", r"\bexec\(", r"bash -c", r"child_process", r"\bshell=True\b"]
FS_PATTERNS = [r"\bopen\(", r"\bos\.remove\b", r"\bshutil\.", r"\bfs\.(write|read)File", r"\bPath\(.*\)\.(write|read)_"]
URL_PATTERN = r"https?://[^\s\"'<>)]+"
BROAD_SCOPE = [r":\*$", r"^\*$", r"\badmin\b", r":all$"]

WEIGHTS = {
    Severity.CRITICAL: 0.5,
    Severity.HIGH: 0.3,
    Severity.MEDIUM: 0.15,
    Severity.LOW: 0.05,
    Severity.INFO: 0.0,
}


def find_invisible_chars(text: str) -> list[str]:
    """Return code points of zero-width / format / Unicode-tag characters."""
    hits = []
    for ch in text:
        cp = ord(ch)
        if unicodedata.category(ch) == "Cf" or 0xE0000 <= cp <= 0xE007F:
            hits.append(f"U+{cp:04X}")
    return hits


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not (unicodedata.category(ch) == "Cf" or 0xE0000 <= ord(ch) <= 0xE007F))


def _search(patterns: list[str], text: str) -> list[str]:
    out = []
    for p in patterns:
        for m in re.finditer(p, text, flags=re.IGNORECASE | re.DOTALL):
            out.append(m.group(0)[:160])
    return out


def scan_package(pkg: ToolPackage, tool_name: str = "*") -> ScanReport:
    flags: list[ScanFlag] = []
    tools = pkg.tools if tool_name in ("*", "", None) else [t for t in pkg.tools if t.name == tool_name]

    for t in tools:
        raw = t.description
        invisible = find_invisible_chars(raw)
        if invisible:
            flags.append(ScanFlag(kind="invisible_unicode", tool_name=t.name,
                                  evidence=f"{len(invisible)} hidden chars: {', '.join(sorted(set(invisible)))[:120]}",
                                  severity_hint=Severity.HIGH))
        text = strip_invisible(raw)
        for ev in _search(INJECTION_PATTERNS, text):
            flags.append(ScanFlag(kind="hidden_instruction", tool_name=t.name, evidence=ev, severity_hint=Severity.CRITICAL))
        for ev in _search(SENSITIVE_PATHS, text):
            flags.append(ScanFlag(kind="sensitive_path", tool_name=t.name, evidence=ev, severity_hint=Severity.CRITICAL))
        for ev in re.findall(URL_PATTERN, text):
            flags.append(ScanFlag(kind="outbound_url", tool_name=t.name, evidence=ev, severity_hint=Severity.LOW))

    for snippet in pkg.code_snippets:
        for ev in _search(SHELL_PATTERNS, snippet):
            flags.append(ScanFlag(kind="shell_access", evidence=ev, severity_hint=Severity.HIGH))
        for ev in _search(FS_PATTERNS, snippet):
            flags.append(ScanFlag(kind="filesystem_access", evidence=ev, severity_hint=Severity.MEDIUM))
        for ev in _search(SENSITIVE_PATHS, snippet):
            flags.append(ScanFlag(kind="sensitive_path", evidence=ev, severity_hint=Severity.HIGH))
        for ev in re.findall(URL_PATTERN, snippet):
            flags.append(ScanFlag(kind="outbound_url", evidence=ev, severity_hint=Severity.MEDIUM))

    for perm in pkg.permissions:
        if _search(BROAD_SCOPE, perm):
            flags.append(ScanFlag(kind="broad_scope", evidence=perm, severity_hint=Severity.MEDIUM))
        if perm.startswith("shell"):
            flags.append(ScanFlag(kind="shell_access", evidence=perm, severity_hint=Severity.HIGH))

    score = min(1.0, sum(WEIGHTS[f.severity_hint] for f in flags))
    return ScanReport(package_name=pkg.name, flags=flags, risk_score=round(score, 3))
