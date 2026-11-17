"""Agent 2: Threat Analyst. OWNER: Member C.

Role: turn the Inspector's raw flags into OWASP-mapped, evidence-backed findings.
Toolset: search_security_kb (vectorized RAG, mandatory), query_osv (OSV.dev API).
Structured Output Mode: analyst_findings_node returns a validated AuditFindings.

Nodes:
  threat_analyst_node       -> LLM turn (may request tool calls)
  analyst_tools_node        -> executes them, stores dependency_vulns / retrieved_sources
  analyst_findings_node     -> SOM call -> AuditFindings, plus a rule-based safety net

Prompts (week 2): one-line category definitions from the OWASP chapters, a severity
rubric that never goes below the Inspector's severity_hint, a two-round research plan
(behaviour search, then the chosen chapter's mitigations via the category filter),
and references copied verbatim from the [source: ...] citations or OSV results.
The dossier keeps every citation of a search result (see _compact_kb).

TODO (Member C):
  - Tune rule_based_findings(); it doubles as the non-LLM baseline in eval.
"""
from __future__ import annotations

import json
import re

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

# One line per category, summarised from each chapter's "Description" in the corpus PDFs.
CATEGORY_GUIDE = """OWASP categories (pick the single best fit):
- ASI01 Agent Goal Hijack: content (e.g. a tool description) that redirects the agent's goals or instructions.
- ASI02 Tool Misuse and Exploitation: a legitimate tool used unsafely: data exfiltration, unintended actions, chaining.
- ASI03 Identity and Privilege Abuse: excess privileges, scopes or credentials beyond the stated purpose; escalation.
- ASI04 Agentic Supply Chain Vulnerabilities: malicious, compromised or tampered third-party tools, packages or
  updates, including known-vulnerable dependencies and tool definitions changed after approval (rug pull).
- ASI05 Unexpected Code Execution: shell, code or command execution reachable through the tool.
- ASI06 Memory and Context Poisoning: malicious data stored in memory or context that biases later sessions.
- ASI07 Insecure Inter-Agent Communication: unauthenticated or tamperable messages between agents.
- ASI08 Cascading Failures: one fault propagating across agents or tools.
- ASI09 Human-Agent Trust Exploitation: misleading the user into approving harmful actions.
- ASI10 Rogue Agents: an agent acting outside its intended scope after compromise or drift.
- LLM01 Prompt Injection: inputs, visible or invisible (e.g. Unicode tag characters), that alter the model's behaviour.
- LLM02 Sensitive Information Disclosure: exposure of credentials, personal or confidential data.
- LLM03 Supply Chain: vulnerable or tampered third-party components (models, data, libraries).
- LLM06 Excessive Agency: more functionality, permissions or autonomy than the task needs."""

ANALYST_SYSTEM = f"""You are the Threat Analyst in a security audit team for MCP servers and agent tools.
You receive the Inspector's scan report (each flag has a kind, a tool, evidence and a severity_hint), the permission
diff, the dependencies and the rug-pull status.
Research plan (you may request several tool calls in one turn; do each step in one turn):
1. For each distinct kind of signal (flag kind, unjustified permissions, rug pull), call search_security_kb with a
   query that describes the behaviour, e.g. "tool description tells the agent to read SSH keys". In the same turn,
   call query_osv once for every dependency.
2. For each OWASP category you settle on, call search_security_kb with category set to its id (e.g. "ASI01") and a
   query such as "prevention and mitigation" to retrieve that chapter's mitigations.
Then write a short analysis: for each signal give the category, the scanner's severity_hint, the evidence, and the
citations (the text after "[source:") that support it. Do not give a final verdict.
{CATEGORY_GUIDE}
{UNTRUSTED_RULE}"""

FINDINGS_SYSTEM = f"""Convert the audit dossier into an AuditFindings object.
One Finding per distinct issue (one signal on one tool); do not repeat an issue under a second category.
Severity rubric:
- critical: the package can make an agent leak secrets or credentials or act against the user, including any hidden
  or invisible instruction that points the agent at secret files, data exfiltration or actions the user did not ask for.
- high: code or shell execution; hidden or invisible instructions without such a target; a rug pull; known CVEs.
- medium: excessive or unjustified permissions or scopes.
- low: notable but expected behaviour for the stated purpose.
- info: observation only.
A finding's severity must never be lower than the severity_hint of the Inspector flag it is based on.
evidence must quote or describe something actually present in the dossier. confidence is between 0 and 1.
references: copy citations exactly as written after "[source:" in the dossier (e.g.
"OWASP-Agentic-Top10-2026.pdf p.22 (ASI05)") and vulnerability ids from query_osv results. Never invent or reword a
reference; leave the list empty when nothing in the dossier supports the finding.
{CATEGORY_GUIDE}
{UNTRUSTED_RULE}"""


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
@tool
def search_security_kb(query: str, k: int = 4, category: str = "") -> str:
    """Semantic search over the security knowledge base (OWASP Agentic Top 10, OWASP LLM Top 10,
    MCP security guidance, incident write-ups). Returns the top-k passages, each with a citation
    (file, page, OWASP chapter) to copy into references.
    category: optional OWASP id (e.g. "ASI05", "LLM01") to search only that chapter, for example
    to fetch its mitigations once you know the category. Leave empty to search everything."""
    if settings.offline:
        return "KB unavailable in offline mode."
    from mcp_security_auditor.tools.rag import search_kb

    hits = search_kb(query, k=k, category=category or None)
    return "\n\n".join(f"[source: {h['cite']} | ids: {h['owasp_ids']}]\n{h['text']}" for h in hits)


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


KB_EXCERPT = 400   # characters kept from each retrieved passage in the dossier
MSG_LIMIT = 3000   # characters kept from any other message
_KB_BLOCK = re.compile(r"^(?=\[source:)", re.M)


def _compact_kb(text: str) -> str:
    """Keep every '[source: ...]' citation line of a search result, each with a short excerpt.

    Cutting the whole result at a fixed length (as before) dropped passages 3-4 and their citations.
    """
    out = []
    for block in _KB_BLOCK.split(text):
        if not block.strip():
            continue
        head, _, body = block.partition("\n")
        body = " ".join(body.split())
        out.append(head if not body else f"{head}\n{body[:KB_EXCERPT]}{'...' if len(body) > KB_EXCERPT else ''}")
    return "\n".join(out)


def _dossier(state: AuditState) -> str:
    parts = [_brief(state), "\nAnalyst conversation (tool results and analysis):"]
    for m in state.analyst_messages[2:]:  # skip system + brief
        text = msg_text(m)
        if isinstance(m, ToolMessage):
            label = f"TOOL {m.name}"
            text = _compact_kb(text) if m.name == "search_security_kb" else text[:MSG_LIMIT]
        else:
            label, text = "ANALYST", text[:MSG_LIMIT]
        parts.append(f"{label}: {text}")
    return "\n".join(parts)


NET_MAX_REFS = 3  # citations attached to a rule-based finding used in an online audit


def _with_chapter_citations(f: Finding, sources: list[str]) -> Finding:
    """Add the citations of f's own OWASP chapter that this audit's searches retrieved (never invented)."""
    chapter = [c for c in sources if c.endswith(f"({f.owasp_category.name})") and c not in f.references]
    return f.model_copy(update={"references": [*f.references, *chapter[:NET_MAX_REFS]]}) if chapter else f


def apply_safety_net(findings: AuditFindings, baseline: AuditFindings,
                     sources: list[str] = ()) -> tuple[AuditFindings, list[str]]:
    """Never let the LLM drop or under-rate a critical deterministic finding.

    Matches on (category, tool): a missing critical finding is added back, an under-rated one is raised to critical.
    A re-added finding also gets the citations of its own chapter that this audit's searches retrieved
    (sources = state.retrieved_sources, e.g. "... p.13 (ASI02)"), so it is backed by the corpus, never invented.
    Returns the corrected findings and a note per correction (for state.errors, like the report's policy floor).
    """
    out, notes = list(findings.findings), []
    for b in baseline.findings:
        if b.severity != Severity.CRITICAL:
            continue
        i = next((i for i, f in enumerate(out) if (f.owasp_category, f.affected_tool) == (b.owasp_category, b.affected_tool)), None)
        if i is None:
            out.append(_with_chapter_citations(b, sources))
            notes.append(f"analyst safety net: added critical finding '{b.title}' ({b.affected_tool})")
        elif out[i].severity != Severity.CRITICAL:
            notes.append(f"analyst safety net: raised '{out[i].title}' ({b.affected_tool}) from {out[i].severity.value} to critical")
            out[i] = out[i].model_copy(update={"severity": Severity.CRITICAL})
    return (findings.model_copy(update={"findings": out}) if notes else findings), notes


def analyst_findings_node(state: AuditState) -> dict:
    from mcp_security_auditor.routing import should_red_team

    baseline = rule_based_findings(state)
    errors = list(state.errors)
    if settings.offline:
        findings = baseline
    else:
        from mcp_security_auditor.llm import get_llm

        def ask() -> AuditFindings:
            raw = get_llm().with_structured_output(AuditFindings).invoke(
                [SystemMessage(FINDINGS_SYSTEM), HumanMessage(_dossier(state))])
            return raw if isinstance(raw, AuditFindings) else AuditFindings.model_validate(raw)

        try:
            findings = ask()
            # An empty list is schema-valid (findings defaults to []), so a model that omits it "validates".
            # When the scanner found something, ask once more before falling back.
            if not findings.findings and baseline.findings:
                findings = ask()
                if findings.findings:
                    errors.append("analyst SOM empty, retry succeeded")
                else:
                    errors.append("analyst SOM empty twice, using rule-based findings")
                    findings = baseline.model_copy(update={"findings": [
                        _with_chapter_citations(f, state.retrieved_sources) for f in baseline.findings]})
        except Exception as e:  # parsing / validation failure -> fall back, never crash the audit
            errors.append(f"analyst SOM failed, using rule-based findings: {type(e).__name__}: {e}")
            findings = baseline.model_copy(update={"findings": [
                _with_chapter_citations(f, state.retrieved_sources) for f in baseline.findings]})
        findings, notes = apply_safety_net(findings, baseline, state.retrieved_sources)
        errors += notes

    probe = state.model_copy(update={"findings": findings})
    return {"findings": findings, "needs_red_team": should_red_team(probe), "errors": errors}
