"""LangGraph state for the Multi-Agent MCP Security Auditor (Pydantic BaseModel, as the guidelines require).

OWNER: Member A. FROZEN AFTER WEEK 1 (Nov 11, 2026; same rule as schemas.py),
enforced by tests/test_contract_freeze.py.

Design notes for the report (State Design section):
- Each agent has its OWN message channel (inspector_messages, analyst_messages,
  redteam_messages). This keeps every agent's context small and role-specific,
  and makes the HumanMessage / AIMessage / ToolMessage trace easy to print.
- Fields mix many types: Pydantic sub-models, enums, bools, ints, dicts, lists.
- Optional fields are None until the node that owns them runs.
- audit_history uses an append reducer and is NEVER reset, so with MemorySaver
  a second audit on the same thread_id can detect a rug pull.
"""
from __future__ import annotations

import operator
from typing import Annotated, Optional

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from mcp_security_auditor.schemas import (
    AuditFindings,
    AuditRecord,
    DependencyVuln,
    FinalReport,
    PermissionDiff,
    RedTeamResult,
    ScanReport,
    ToolPackage,
    Verdict,
)


class AuditState(BaseModel):
    # ---- input -------------------------------------------------------------
    package: Optional[ToolPackage] = None

    # ---- bookkeeping / checkpoint continuity (written by intake + report) --
    run_count: int = 0
    manifest_hash: Optional[str] = None
    tool_hashes: dict[str, str] = Field(default_factory=dict)
    audit_history: Annotated[list[AuditRecord], operator.add] = Field(default_factory=list)
    rug_pull_detected: bool = False
    rug_pull_changes: list[str] = Field(default_factory=list)

    # ---- per-agent message channels ---------------------------------------
    inspector_messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)
    analyst_messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)
    redteam_messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)

    # ---- Inspector outputs (Member B) -------------------------------------
    scan_report: Optional[ScanReport] = None
    permission_diff: Optional[PermissionDiff] = None

    # ---- Threat Analyst outputs (Member C) --------------------------------
    dependency_vulns: list[DependencyVuln] = Field(default_factory=list)
    retrieved_sources: list[str] = Field(default_factory=list)
    findings: Optional[AuditFindings] = None
    needs_red_team: bool = False

    # ---- Red-Team outputs (Member B) --------------------------------------
    red_team_results: list[RedTeamResult] = Field(default_factory=list)

    # ---- Report outputs (Member A) ----------------------------------------
    final_report: Optional[FinalReport] = None
    # guardrail transparency: the minimum verdict the deterministic policy allowed
    # (kept out of FinalReport on purpose: that is the LLM's SOM target, and the
    # LLM must never be the one to fill in its own floor)
    policy_floor: Optional[Verdict] = None
    policy_reason: str = ""
    patched_manifest: Optional[dict] = None
    patch_changes: list[str] = Field(default_factory=list)

    # ---- control / safety -------------------------------------------------
    tool_rounds: dict[str, int] = Field(default_factory=dict)  # agent -> tool loops used
    errors: list[str] = Field(default_factory=list)
