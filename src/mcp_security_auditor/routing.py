"""Conditional edges. OWNER: Member A.

Two kinds of routing:
  1. Tool loops: after an agent turn, go to its tools node if the last AIMessage
     requested tool calls, otherwise move on.
  2. The main business decision: after findings, run the Red-Team agent only
     when the package looks actively dangerous (should_red_team).
"""
from __future__ import annotations

from mcp_security_auditor.schemas import Severity
from mcp_security_auditor.state import AuditState
from mcp_security_auditor.utils.messages import last_ai


def _wants_tools(messages) -> bool:
    ai = last_ai(messages)
    return bool(ai and ai.tool_calls)


def route_inspector(state: AuditState) -> str:
    return "inspector_tools" if _wants_tools(state.inspector_messages) else "threat_analyst"


def route_analyst(state: AuditState) -> str:
    return "analyst_tools" if _wants_tools(state.analyst_messages) else "analyst_findings"


def route_red_team(state: AuditState) -> str:
    return "redteam_tools" if _wants_tools(state.redteam_messages) else "report"


def should_red_team(state: AuditState) -> bool:
    """The key conditional edge. Red-team when there is evidence of injection,
    a rug pull, or a high/critical finding on a SPECIFIC TOOL. Explain this rule in the report.

    The sandbox attacks tool descriptions, so a high finding with no affected tool
    (e.g. a dependency with known CVEs) gives it nothing to test: skipping it saves
    several LLM calls per audit on a free tier of about 20 calls a day."""
    if state.rug_pull_detected:
        return True
    if state.scan_report and state.scan_report.has_injection_indicators:
        return True
    findings = state.findings.findings if state.findings else []
    return any(f.affected_tool and f.severity.rank >= Severity.HIGH.rank for f in findings)


def route_after_findings(state: AuditState) -> str:
    return "red_team" if state.needs_red_team else "report"
