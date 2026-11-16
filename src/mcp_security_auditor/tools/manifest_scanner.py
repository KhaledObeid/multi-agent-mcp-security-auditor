"""Custom tool #1: manifest scanner. OWNER: Member B.

Deterministic (no LLM). Takes a ToolPackage and returns a ScanReport.
The starter rules below already work on the sample packages; your job is to
extend them, reduce false positives, and write tests in tests/test_scanner.py.

Implemented rules: hidden-instruction phrasing, invisible Unicode, sensitive
paths, shell/fs access, outbound URLs, broad scopes, base64/hex encoded payloads,
homoglyph tool names (tool shadowing), and cross-tool shadowing.

TODO (Member B):
  - Add more injection phrasings (look at the incident write-ups in data/corpus).
  - Tune severity_hint and the risk_score weights.
"""
from __future__ import annotations

import base64
import binascii
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


# --- extended rules (Member B) ---------------------------------------------
# Tool names from OTHER servers that a poisoned description tries to pull in
# (data exfiltration / privilege abuse). Snake_case ids, so they do not collide
# with ordinary English words in a benign description.
COMMON_EXTERNAL_TOOLS = [
    "send_email", "send_message", "send_mail", "read_file", "write_file",
    "delete_file", "run_command", "http_request", "get_secret", "read_secret",
    "list_files", "upload_file", "download_file", "execute_code", "read_env",
]

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# an uppercase I or O standing in a lowercase name (emaiI, listO): classic l/1->I, o->0 swap
_HOMOGLYPH_CASE_RE = re.compile(r"(?<=[a-z])[IO](?=$|[^A-Za-z])")


def _looks_textual(data: bytes) -> str | None:
    """Decode bytes to text only if they are plausibly a human-readable string,
    so random base64-looking tokens are not treated as hidden payloads."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < 6:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r ")
    return s if printable / len(s) >= 0.8 else None


def decode_blobs(text: str) -> list[tuple[str, str]]:
    """Find base64/hex blobs that decode to readable text and return
    (raw_blob, decoded_text) pairs. The RAW blob is kept so a caller can both
    re-scan the decoded text and later remove the original blob from the source."""
    out: list[tuple[str, str]] = []
    for m in _B64_RE.finditer(text):
        raw = m.group(0)
        if len(raw) % 4:
            continue
        try:
            dec = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _looks_textual(dec)
        if s:
            out.append((raw, s))
    for m in _HEX_RE.finditer(text):
        raw = m.group(0)
        if len(raw) % 2:
            continue
        try:
            dec = bytes.fromhex(raw)
        except ValueError:
            continue
        s = _looks_textual(dec)
        if s:
            out.append((raw, s))
    return out


def homoglyph_reason(name: str) -> str | None:
    """Return why a tool NAME looks like an impersonation of another tool, or None."""
    non_ascii = sorted({ch for ch in name if ord(ch) > 0x7F})
    if non_ascii:
        return "non-ASCII look-alike character(s): " + ", ".join(f"U+{ord(c):04X}" for c in non_ascii)
    if _HOMOGLYPH_CASE_RE.search(name):
        return "uppercase I/O used in place of a lowercase letter"
    return None


def _search(patterns: list[str], text: str) -> list[str]:
    out = []
    for p in patterns:
        for m in re.finditer(p, text, flags=re.IGNORECASE | re.DOTALL):
            out.append(m.group(0)[:160])
    return out


def scan_package(pkg: ToolPackage, tool_name: str = "*") -> ScanReport:
    flags: list[ScanFlag] = []
    tools = pkg.tools if tool_name in ("*", "", None) else [t for t in pkg.tools if t.name == tool_name]
    own_names = {t.name for t in pkg.tools}

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

        # (1) encoded payloads: decode base64/hex, re-scan the result, flag with the RAW blob
        # as evidence so the cleaners (patcher / permission-diff) can strip it from the source.
        for raw_blob, decoded in decode_blobs(text):
            if _search(INJECTION_PATTERNS, decoded) or _search(SENSITIVE_PATHS, decoded) or re.findall(URL_PATTERN, decoded):
                flags.append(ScanFlag(kind="hidden_instruction", tool_name=t.name,
                                      evidence=raw_blob[:160], severity_hint=Severity.CRITICAL))

        # (2) homoglyph / look-alike tool name (tool shadowing)
        reason = homoglyph_reason(t.name)
        if reason:
            flags.append(ScanFlag(kind="other", tool_name=t.name,
                                  evidence=f"tool name '{t.name}': {reason}", severity_hint=Severity.HIGH))

        # (3) cross-tool shadowing: a description that directs another tool -- one of this
        # package's other snake_case tools, or a known tool from another server (send_email, ...).
        candidates = {n for n in own_names if "_" in n and n != t.name} | set(COMMON_EXTERNAL_TOOLS)
        for other in sorted(candidates):
            if other == t.name:
                continue
            m = re.search(r"[^.!?\n]*\b" + re.escape(other) + r"\b[^.!?\n]*", text, flags=re.IGNORECASE)
            if m:
                flags.append(ScanFlag(kind="hidden_instruction", tool_name=t.name,
                                      evidence=m.group(0).strip()[:160], severity_hint=Severity.CRITICAL))

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
