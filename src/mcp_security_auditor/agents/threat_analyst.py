"""Agent 2: Threat Analyst. OWNER: Member C.

Role: turn the Inspector's raw flags into OWASP-mapped, evidence-backed findings.
Toolset: search_security_kb (vectorized RAG, mandatory), query_osv (OSV.dev API).
Structured Output Mode: analyst_findings_node returns a validated AuditFindings.

Nodes:
  threat_analyst_node       -> LLM turn (may request tool calls)
  analyst_tools_node        -> executes them, stores dependency_vulns / retrieved_sources
  analyst_findings_node     -> SOM call -> AuditFindings, plus a rule-based safety net

TODO (Member C):
  - Improve both prompts (ANALYST_SYSTEM, FINDINGS_SYSTEM): category definitions,
    severity rubric, "cite the corpus source in references".
  - Tune rule_based_findings(); it doubles as the non-LLM baseline in eval.
"""
from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from mcp_security_auditor.config import settings
from mcp_security_auditor.schemas import AuditFindings, DependencyVuln, Finding, OwaspCategory, Severity
from mcp_security_auditor.state import AuditState
from mcp_security_auditor.tools.osv import query_osv_one
from mcp_security_auditor.utils.agent_loop import agent_turn
from mcp_security_auditor.utils.messages import last_ai, msg_text
from mcp_security_auditor.utils.text import UNTRUSTED_RULE
from mcp_security_auditor.utils.tool_exec import bump_round, run_tool_calls

AGENT = "analyst"

ANALYST_SYSTEM = f"""You are the Threat Analyst in a security audit team for MCP servers and agent tools.
You receive the Inspector's scan results. For each suspicious signal:
1. Call search_security_kb to find the matching OWASP Agentic Top 10 / LLM Top 10 category and its mitigations.
2. Call query_osv once per dependency to find known vulnerabilities.
Then write a short analysis tying each signal to a category, with evidence. Do not give a final verdict.
{UNTRUSTED_RULE}"""

FINDINGS_SYSTEM = """Convert the audit dossier into an AuditFindings object.
One Finding per distinct issue. Severity rubric: critical = the tool can make an agent leak secrets or act against the
user; high = code execution, hidden or invisible instructions, or known exploitable CVEs; medium = excessive or
unjustified permissions; low = notable but expected behaviour; info = observation only.
evidence must quote or describe something actually present in the dossier. confidence is between 0 and 1.
references should name corpus sources or OSV ids from the dossier."""


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
@tool
def search_security_kb(query: str, k: int = 4) -> str:
    """Semantic search over the security knowledge base (OWASP Agentic Top 10, OWASP LLM Top 10,
    MCP security guidance, incident write-ups). Returns the top-k passages with their source."""
    if settings.offline:
        return "KB unavailable in offline mode."
    from mcp_security_auditor.tools.rag import search_kb

    hits = search_kb(query, k=k)
    return "\n\n".join(f"[source: {h['source']} | ids: {h['owasp_ids']}]\n{h['text']}" for h in hits)


@tool
def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> str:
    """Look up known vulnerabilities for one dependency in the OSV.dev database.
    ecosystem examples: PyPI, npm, Go, crates.io."""
    return query_osv_one(package_name, version, ecosystem).model_dump_json()


ANALYST_TOOLS = [search_security_kb, query_osv]


def _brief(state: AuditState) -> str:
    scan = state.scan_report.model_dump_json(indent=1) if state.scan_report else "none"
    diff = state.permission_diff.model_dump_json(indent=1) if state.permission_diff else "none"
    deps = [d.model_dump() for d in state.package.dependencies]
    rug = f"RUG PULL DETECTED vs previously approved version: {state.rug_pull_changes}" if state.rug_pull_detected else "No rug pull detected."
    return (f"Package {state.package.name} v{state.package.version}\n"
            f"Inspector scan report:\n<untrusted>{scan}</untrusted>\n"
            f"Permission diff:\n{diff}\nDependencies: {json.dumps(deps)}\n{rug}")


# --------------------------------------------------------------------------- #
# nodes
# --------------------------------------------------------------------------- #
def threat_analyst_node(state: AuditState) -> dict:
    flags = state.scan_report.flags if state.scan_report else []

    def offline_calls():
        calls = [{"name": "search_security_kb", "args": {"query": f"{k} in MCP tool description", "k": 3}}
                 for k in sorted({f.kind for f in flags})[:2]]
        calls += [{"name": "query_osv", "args": {"package_name": d.name, "version": d.version, "ecosystem": d.ecosystem}}
                  for d in state.package.dependencies]
        return calls

    new = agent_turn(
        channel=state.analyst_messages,
        system_prompt=ANALYST_SYSTEM,
        brief=lambda: _brief(state),
        tools=ANALYST_TOOLS,
        rounds_used=state.tool_rounds.get(AGENT, 0),
        offline_calls=offline_calls,
        offline_final="Analysis complete (offline mode).",
    )
    return {"analyst_messages": new}


def analyst_tools_node(state: AuditState) -> dict:
    ai = last_ai(state.analyst_messages)
    tool_msgs = run_tool_calls(ai, ANALYST_TOOLS)
    vulns = list(state.dependency_vulns)
    sources = list(state.retrieved_sources)
    for tm in tool_msgs:
        if getattr(tm, "status", "success") == "error":
            continue
        if tm.name == "query_osv":
            vulns.append(DependencyVuln.model_validate_json(msg_text(tm)))
        elif tm.name == "search_security_kb":
            for line in msg_text(tm).splitlines():
                if line.startswith("[source:"):
                    src = line.split("|")[0].replace("[source:", "").strip()
                    if src not in sources:
                        sources.append(src)
    return {"analyst_messages": tool_msgs, "dependency_vulns": vulns, "retrieved_sources": sources,
            "tool_rounds": bump_round(state.tool_rounds, AGENT)}


# rule-based mapping: offline mode, baseline in eval, and safety net for the LLM
FLAG_MAP = {
    "hidden_instruction": (OwaspCategory.ASI01, "Hidden instruction in tool description (tool poisoning)",
                           "Remove the instruction; pin and review descriptions; show full descriptions to users."),
    "invisible_unicode": (OwaspCategory.LLM01, "Invisible Unicode characters in tool description",
                          "Strip format/tag characters before the description reaches the model."),
    "sensitive_path": (OwaspCategory.ASI02, "References to secrets or credential files",
                       "Deny access to credential paths; sandbox file access to an allow-list."),
    "shell_access": (OwaspCategory.ASI05, "Shell / code execution capability",
                     "Run in a container without shell, or require human approval per command."),
    "filesystem_access": (OwaspCategory.ASI02, "File-system access in code",
                          "Restrict to a scoped directory; read-only where possible."),
    "outbound_url": (OwaspCategory.ASI02, "Outbound network destination",
                     "Allow-list destinations; block URLs that come from tool descriptions."),
    "broad_scope": (OwaspCategory.ASI03, "Wildcard or admin scope requested",
                    "Grant the narrowest scope that the stated purpose needs."),
}


def rule_based_findings(state: AuditState) -> AuditFindings:
    findings: list[Finding] = []
    seen = set()
    for f in (state.scan_report.flags if state.scan_report else []):
        key = (f.kind, f.tool_name)
        if key in seen:
            continue
        seen.add(key)
        cat, title, mit = FLAG_MAP.get(f.kind, (OwaspCategory.OTHER, f.kind, "Review manually."))
        findings.append(Finding(owasp_category=cat, severity=f.severity_hint, title=title, evidence=f.evidence,
                                confidence=0.7, mitigation=mit, affected_tool=f.tool_name))
    if state.permission_diff and state.permission_diff.unjustified_permissions:
        findings.append(Finding(owasp_category=OwaspCategory.ASI03, severity=Severity.MEDIUM,
                                title="Permissions not justified by the stated purpose",
                                evidence=", ".join(state.permission_diff.unjustified_permissions), confidence=0.6,
                                mitigation="Remove or narrow these permissions."))
    for v in state.dependency_vulns:
        if v.vuln_ids:
            findings.append(Finding(owasp_category=OwaspCategory.ASI04, severity=Severity.HIGH,
                                    title=f"Known vulnerabilities in {v.package}=={v.version}",
                                    evidence="; ".join(v.vuln_ids[:5]), confidence=0.9,
                                    mitigation="Upgrade to a fixed version.", references=v.vuln_ids[:5]))
    if state.rug_pull_detected:
        findings.append(Finding(owasp_category=OwaspCategory.ASI04, severity=Severity.HIGH,
                                title="Tool definitions changed since the last approved audit (possible rug pull)",
                                evidence="; ".join(state.rug_pull_changes), confidence=0.8,
                                mitigation="Re-approve only after reviewing the diff; pin tool versions/hashes."))
    return AuditFindings(findings=findings, summary=f"{len(findings)} rule-based finding(s).")


def _dossier(state: AuditState) -> str:
    parts = [_brief(state), "\nAnalyst conversation (tool results and analysis):"]
    for m in state.analyst_messages[2:]:  # skip system + brief
        label = f"TOOL {m.name}" if isinstance(m, ToolMessage) else "ANALYST"
        parts.append(f"{label}: {msg_text(m)[:1500]}")
    return "\n".join(parts)


def analyst_findings_node(state: AuditState) -> dict:
    from mcp_security_auditor.routing import should_red_team

    baseline = rule_based_findings(state)
    errors = list(state.errors)
    if settings.offline:
        findings = baseline
    else:
        from mcp_security_auditor.llm import get_llm

        try:
            raw = get_llm().with_structured_output(AuditFindings).invoke(
                [SystemMessage(FINDINGS_SYSTEM), HumanMessage(_dossier(state))])
            findings = raw if isinstance(raw, AuditFindings) else AuditFindings.model_validate(raw)
        except Exception as e:  # parsing / validation failure -> fall back, never crash the audit
            errors.append(f"analyst SOM failed, using rule-based findings: {type(e).__name__}: {e}")
            findings = baseline
        # safety net: never let the LLM silently drop a critical deterministic finding
        have = {(f.owasp_category, f.affected_tool) for f in findings.findings}
        missing = [f for f in baseline.findings if f.severity == Severity.CRITICAL and (f.owasp_category, f.affected_tool) not in have]
        if missing:
            findings = findings.model_copy(update={"findings": findings.findings + missing})

    probe = state.model_copy(update={"findings": findings})
    return {"findings": findings, "needs_red_team": should_red_team(probe), "errors": errors}
