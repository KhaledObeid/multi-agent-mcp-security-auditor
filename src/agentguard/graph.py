"""LangGraph wiring. OWNER: Member A.

START -> intake -> inspector <-> inspector_tools
                -> threat_analyst <-> analyst_tools
                -> analyst_findings (SOM)
                -> [conditional] red_team <-> redteam_tools -> report
                                 or straight to report
report -> END
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agentguard.agents.inspector import inspector_node, inspector_tools_node
from agentguard.agents.intake import intake_node
from agentguard.agents.red_team import red_team_node, redteam_tools_node
from agentguard.agents.report import report_node
from agentguard.agents.threat_analyst import analyst_findings_node, analyst_tools_node, threat_analyst_node
from agentguard.routing import route_after_findings, route_analyst, route_inspector, route_red_team
from agentguard.state import AuditState


def build_graph(checkpointer=None):
    g = StateGraph(AuditState)

    g.add_node("intake", intake_node)
    g.add_node("inspector", inspector_node)
    g.add_node("inspector_tools", inspector_tools_node)
    g.add_node("threat_analyst", threat_analyst_node)
    g.add_node("analyst_tools", analyst_tools_node)
    g.add_node("analyst_findings", analyst_findings_node)
    g.add_node("red_team", red_team_node)
    g.add_node("redteam_tools", redteam_tools_node)
    g.add_node("report", report_node)

    g.add_edge(START, "intake")
    g.add_edge("intake", "inspector")
    g.add_conditional_edges("inspector", route_inspector, ["inspector_tools", "threat_analyst"])
    g.add_edge("inspector_tools", "inspector")
    g.add_conditional_edges("threat_analyst", route_analyst, ["analyst_tools", "analyst_findings"])
    g.add_edge("analyst_tools", "threat_analyst")
    g.add_conditional_edges("analyst_findings", route_after_findings, ["red_team", "report"])
    g.add_conditional_edges("red_team", route_red_team, ["redteam_tools", "report"])
    g.add_edge("redteam_tools", "red_team")
    g.add_edge("report", END)

    return g.compile(checkpointer=checkpointer if checkpointer is not None else make_checkpointer())


def make_checkpointer() -> MemorySaver:
    """MemorySaver that is explicitly allowed to restore our Pydantic/enum types."""
    allowed = [("agentguard.schemas", name) for name in (
        "ToolPackage", "ToolSpec", "Dependency", "ScanFlag", "ScanReport", "PermissionDiff", "DependencyVuln",
        "Finding", "AuditFindings", "RedTeamResult", "FinalReport", "AuditRecord", "Severity", "OwaspCategory", "Verdict")]
    try:
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        return MemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=allowed))
    except TypeError:  # older langgraph without this option
        return MemorySaver()


def draw_mermaid() -> str:
    """Paste the output into https://mermaid.live for the report's architecture diagram."""
    return build_graph().get_graph().draw_mermaid()
