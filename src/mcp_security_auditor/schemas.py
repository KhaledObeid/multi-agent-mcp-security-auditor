"""Shared data contracts for the Multi-Agent MCP Security Auditor.

OWNER: Member A (integration). FROZEN AFTER WEEK 1 (Nov 11, 2026), enforced by
tests/test_contract_freeze.py.
Every other module imports from here, so changing a field name breaks other
people's code. If you need a change, open a PR titled "contract:" and tell the
team before merging. Adding a new Optional field is always safe; renaming or
removing one is not.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class OwaspCategory(str, Enum):
    """OWASP Top 10 for Agentic Applications (2026 edition, published Dec 2025)
    plus the LLM Top 10 entries most relevant to tool packages.

    Verified by Member C on Nov 10, 2026 against the ingested PDFs: ASI01-ASI10
    match the Agentic 2026 document, and the LLM ids follow the LLM Top 10
    **2025** edition (the 2026 edition renumbers entries). State this in the report.
    """
    ASI01 = "ASI01 Agent Goal Hijack"
    ASI02 = "ASI02 Tool Misuse and Exploitation"
    ASI03 = "ASI03 Identity and Privilege Abuse"
    ASI04 = "ASI04 Agentic Supply Chain Vulnerabilities"
    ASI05 = "ASI05 Unexpected Code Execution"
    ASI06 = "ASI06 Memory and Context Poisoning"
    ASI07 = "ASI07 Insecure Inter-Agent Communication"
    ASI08 = "ASI08 Cascading Failures"
    ASI09 = "ASI09 Human-Agent Trust Exploitation"
    ASI10 = "ASI10 Rogue Agents"
    LLM01 = "LLM01 Prompt Injection"
    LLM02 = "LLM02 Sensitive Information Disclosure"
    LLM03 = "LLM03 Supply Chain"
    LLM06 = "LLM06 Excessive Agency"
    OTHER = "Other"


class Verdict(str, Enum):
    INSTALL = "install"
    INSTALL_WITH_MITIGATIONS = "install_with_mitigations"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return ["install", "install_with_mitigations", "block"].index(self.value)


# --------------------------------------------------------------------------- #
# Input: the tool package a user submits
# --------------------------------------------------------------------------- #
class ToolSpec(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str = "PyPI"  # OSV ecosystem names: PyPI, npm, Go, crates.io, ...


class ToolPackage(BaseModel):
    name: str
    version: str = "0.0.0"
    claimed_purpose: str = ""
    tools: list[ToolSpec]
    permissions: list[str] = Field(default_factory=list)  # e.g. "fs:read", "network:outbound", "shell:exec", "fs:*"
    dependencies: list[Dependency] = Field(default_factory=list)
    code_snippets: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Inspector outputs (deterministic custom tools)
# --------------------------------------------------------------------------- #
FlagKind = Literal[
    "hidden_instruction",
    "invisible_unicode",
    "shell_access",
    "filesystem_access",
    "sensitive_path",
    "outbound_url",
    "broad_scope",
    "other",
]


class ScanFlag(BaseModel):
    kind: FlagKind
    tool_name: Optional[str] = None  # None = package-level flag
    evidence: str
    severity_hint: Severity


class ScanReport(BaseModel):
    package_name: str
    flags: list[ScanFlag] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)

    @property
    def has_injection_indicators(self) -> bool:
        return any(f.kind in ("hidden_instruction", "invisible_unicode") for f in self.flags)


class PermissionDiff(BaseModel):
    claimed_capabilities: list[str] = Field(default_factory=list)
    requested_permissions: list[str] = Field(default_factory=list)
    unjustified_permissions: list[str] = Field(default_factory=list)
    notes: str = ""


class DependencyVuln(BaseModel):
    package: str
    version: str
    vuln_ids: list[str] = Field(default_factory=list)
    summaries: list[str] = Field(default_factory=list)
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Threat Analyst output -- STRUCTURED OUTPUT MODE target
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    owasp_category: OwaspCategory
    severity: Severity
    title: str = Field(description="One-line name of the issue")
    evidence: str = Field(description="Exact text or observation from the package that supports this finding")
    confidence: float = Field(ge=0.0, le=1.0, description="0 to 1")
    mitigation: str
    affected_tool: Optional[str] = None
    references: list[str] = Field(default_factory=list, description="Corpus sources or OSV ids")


class AuditFindings(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


# --------------------------------------------------------------------------- #
# Red-Team output
# --------------------------------------------------------------------------- #
class RedTeamResult(BaseModel):
    target_tool: str
    attack_prompt: str
    mock_agent_obeyed: Optional[bool] = None  # None = test could not run (offline / error)
    observed_tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    canary_hits: list[str] = Field(default_factory=list)
    notes: str = ""


# --------------------------------------------------------------------------- #
# Report agent output -- second STRUCTURED OUTPUT MODE target
# --------------------------------------------------------------------------- #
class FinalReport(BaseModel):
    verdict: Verdict
    rationale: str
    required_mitigations: list[str] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """One completed audit. Kept across runs on the same thread (checkpointing)
    so a later version of the same package can be compared for rug pulls."""
    package_name: str
    package_version: str
    manifest_hash: str
    tool_hashes: dict[str, str]
    verdict: Optional[Verdict] = None
