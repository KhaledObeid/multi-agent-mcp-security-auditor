"""Agent 1: Inspector. OWNER: Member B.

Role: extract the attack surface of the package.
Toolset: scan_manifest, check_permissions (both custom, deterministic).
Reads:  package, inspector_messages, tool_rounds
Writes: inspector_messages, scan_report, permission_diff, tool_rounds

TODO (Member B): improve INSPECTOR_SYSTEM (role, steps, output expectations)
and make the final AIMessage a short attack-surface summary.
"""
from __future__ import annotations

from langchain_core.tools import tool

from agentguard.schemas import ScanReport, PermissionDiff, ToolPackage
from agentguard.state import AuditState
from agentguard.tools.manifest_scanner import scan_package
from agentguard.tools.permission_diff import diff_permissions
from agentguard.utils.agent_loop import agent_turn
from agentguard.utils.messages import last_ai, msg_text
from agentguard.utils.text import UNTRUSTED_RULE, package_brief
from agentguard.utils.tool_exec import bump_round, run_tool_calls

AGENT = "inspector"

INSPECTOR_SYSTEM = f"""You are the Inspector in a security audit team that vets third-party MCP servers and agent tools.
Your only job is to map the package's attack surface. You do not give a verdict.
Steps:
1. Call scan_manifest with tool_name="*" to scan every tool.
2. Call check_permissions, passing a one-sentence restatement of what the package claims to do.
3. If one tool looks suspicious, you may call scan_manifest again on that tool only.
4. Finish with a short summary listing each suspicious tool and why.
{UNTRUSTED_RULE}"""


def make_inspector_tools(pkg: ToolPackage):
    @tool
    def scan_manifest(tool_name: str = "*") -> str:
        """Scan tool descriptions, code snippets and permissions for hidden instructions, invisible Unicode,
        shell or file-system access, sensitive paths, outbound URLs and broad scopes.
        tool_name: one tool's name, or "*" for the whole package."""
        return scan_package(pkg, tool_name).model_dump_json()

    @tool
    def check_permissions(claimed_purpose: str = "") -> str:
        """Compare what the package claims to do with the permissions it requests and list
        permissions that the claim does not justify. claimed_purpose: your one-sentence restatement."""
        return diff_permissions(pkg, claimed_purpose).model_dump_json()

    return [scan_manifest, check_permissions]


def inspector_node(state: AuditState) -> dict:
    pkg = state.package
    tools = make_inspector_tools(pkg)
    new = agent_turn(
        channel=state.inspector_messages,
        system_prompt=INSPECTOR_SYSTEM,
        brief=lambda: "Inspect this package:\n" + package_brief(pkg),
        tools=tools,
        rounds_used=state.tool_rounds.get(AGENT, 0),
        offline_calls=lambda: [
            {"name": "scan_manifest", "args": {"tool_name": "*"}},
            {"name": "check_permissions", "args": {"claimed_purpose": pkg.claimed_purpose}},
        ],
        offline_final="Inspection complete (offline mode).",
    )
    update: dict = {"inspector_messages": new}

    # safety net: if the agent finished without ever scanning, run the tools ourselves
    finished = not getattr(new[-1], "tool_calls", None)
    if finished and state.scan_report is None:
        update["scan_report"] = scan_package(pkg)
    if finished and state.permission_diff is None:
        update["permission_diff"] = diff_permissions(pkg)
    return update


def inspector_tools_node(state: AuditState) -> dict:
    ai = last_ai(state.inspector_messages)
    tool_msgs = run_tool_calls(ai, make_inspector_tools(state.package))
    update: dict = {"inspector_messages": tool_msgs, "tool_rounds": bump_round(state.tool_rounds, AGENT)}

    for tm in tool_msgs:
        if getattr(tm, "status", "success") == "error":
            continue
        if tm.name == "scan_manifest":
            new_scan = ScanReport.model_validate_json(msg_text(tm))
            if state.scan_report is None:
                update["scan_report"] = new_scan
            else:  # merge a focused re-scan into the existing report
                seen = {(f.kind, f.tool_name, f.evidence) for f in state.scan_report.flags}
                merged = state.scan_report.flags + [f for f in new_scan.flags if (f.kind, f.tool_name, f.evidence) not in seen]
                update["scan_report"] = state.scan_report.model_copy(update={"flags": merged})
        elif tm.name == "check_permissions":
            update["permission_diff"] = PermissionDiff.model_validate_json(msg_text(tm))
    return update
