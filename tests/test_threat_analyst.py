"""Offline checks for the Threat Analyst prompts, dossier and safety net (OWNER: Member C). No API calls."""
from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from mcp_security_auditor.agents.threat_analyst import (
    ANALYST_SYSTEM, FINDINGS_SYSTEM, KB_EXCERPT, _compact_kb, _dossier, apply_safety_net)
from mcp_security_auditor.schemas import AuditFindings, Finding, OwaspCategory, Severity, ToolPackage
from mcp_security_auditor.state import AuditState

CITES = ["OWASP-Agentic-Top10-2026.pdf p.10 (ASI01)", "OWASP-Agentic-Top10-2026.pdf p.11 (ASI01)",
         "OWASP-LLM-Top10-2025.pdf p.7 (LLM01)", "mcp_incidents_notes.md (ASI02)"]
KB_RESULT = "\n\n".join(f"[source: {c} | ids: X]\n" + "word " * 180 for c in CITES)  # ~3,600 chars, like k=4


def _finding(cat, sev, tool="add", title="t"):
    return Finding(owasp_category=cat, severity=sev, title=title, evidence="e", confidence=0.7,
                   mitigation="m", affected_tool=tool)


def test_compact_kb_keeps_every_citation_and_shortens_passages():
    out = _compact_kb(KB_RESULT)
    assert all(f"[source: {c} | ids: X]" in out for c in CITES)
    assert len(out) < len(KB_RESULT) / 2
    assert all(len(line) <= KB_EXCERPT + 3 for line in out.splitlines() if not line.startswith("[source:"))


def test_dossier_keeps_all_citations_of_a_search():
    pkg = ToolPackage.model_validate({"name": "p", "version": "1", "claimed_purpose": "x", "tools": []})
    msgs = [SystemMessage("s"), HumanMessage("brief"), AIMessage("calling tools"),
            ToolMessage(KB_RESULT, name="search_security_kb", tool_call_id="1")]
    dossier = _dossier(AuditState(package=pkg, analyst_messages=msgs))
    assert all(c in dossier for c in CITES)   # before: cut at 1,500 chars, citations 3-4 lost


def test_safety_net_raises_underrated_critical():
    base = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.CRITICAL)])
    llm = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.HIGH, title="Hidden instruction")])
    out, notes = apply_safety_net(llm, base)
    assert [f.severity for f in out.findings] == [Severity.CRITICAL]
    assert out.findings[0].title == "Hidden instruction"        # the LLM's wording is kept
    assert len(notes) == 1 and "from high to critical" in notes[0]


def test_safety_net_adds_missing_critical_and_leaves_correct_findings_alone():
    base = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.CRITICAL),
                                   _finding(OwaspCategory.ASI05, Severity.HIGH, tool="run")])
    llm = AuditFindings(findings=[_finding(OwaspCategory.ASI02, Severity.HIGH)])
    out, notes = apply_safety_net(llm, base)
    assert [(f.owasp_category, f.severity) for f in out.findings] == [
        (OwaspCategory.ASI02, Severity.HIGH), (OwaspCategory.ASI01, Severity.CRITICAL)]  # only critical is enforced
    assert len(notes) == 1 and "added" in notes[0]
    same, none = apply_safety_net(base, base)
    assert same is base and none == []


def test_prompts_carry_rubric_categories_citation_rule_and_untrusted_rule():
    for prompt in (ANALYST_SYSTEM, FINDINGS_SYSTEM):
        assert all(cat.name in prompt for cat in OwaspCategory if cat is not OwaspCategory.OTHER)
        assert "<untrusted>" in prompt
    assert "never be lower than the severity_hint" in FINDINGS_SYSTEM
    assert "Never invent" in FINDINGS_SYSTEM
    assert "category set to its id" in ANALYST_SYSTEM and "query_osv once for every dependency" in ANALYST_SYSTEM
