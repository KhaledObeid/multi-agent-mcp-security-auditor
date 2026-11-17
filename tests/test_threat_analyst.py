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


def _load_run_eval():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "eval" / "run_eval.py"
    spec = importlib.util.spec_from_file_location("run_eval", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_run_eval_analyst_check_counts_valid_and_invented_references(monkeypatch):
    import dataclasses

    from mcp_security_auditor.schemas import DependencyVuln

    ev = _load_run_eval()
    monkeypatch.setattr(ev, "settings", dataclasses.replace(ev.settings, offline=False))
    f = _finding(OwaspCategory.ASI01, Severity.CRITICAL)
    findings = AuditFindings(findings=[
        f.model_copy(update={"references": [CITES[0], "OWASP made-up p.99"]}),   # one valid, one invented
        f.model_copy(update={"references": ["CVE-2020-14343"]}),                 # OSV id: valid
        f.model_copy(update={"references": []})])                                # no reference
    out = {"findings": findings, "retrieved_sources": [CITES[0]],
           "dependency_vulns": [DependencyVuln(package="pyyaml", version="5.3", vuln_ids=["CVE-2020-14343"])],
           "errors": ["analyst safety net: raised 'x' (add) from high to critical", "inspector: something"]}
    c = ev.analyst_check(out)
    assert (c["som"], c["findings"], c["cited"], c["invented"]) == ("ok", 3, 2, ["OWASP made-up p.99"])
    assert len(c["net"]) == 1 and c["other_errors"] == ["inspector: something"]

    out["errors"] = ["analyst SOM failed, using rule-based findings: ValidationError: ..."]
    assert ev.analyst_check(out)["som"] == "FALLBACK"
    out["errors"] = ["analyst SOM empty twice, using rule-based findings"]
    assert (ev.analyst_check(out)["som"], ev.analyst_check(out)["by_llm"]) == ("EMPTY", 0)
    out["errors"] = ["analyst SOM empty, retry succeeded", "analyst safety net: added critical finding 'x' (add)"]
    assert (ev.analyst_check(out)["som"], ev.analyst_check(out)["by_llm"]) == ("retry", 2)


def test_run_eval_records_a_crash_and_continues():
    ev = _load_run_eval()

    class CrashingGraph:
        def invoke(self, *a, **k):
            raise RuntimeError("429 RESOURCE_EXHAUSTED")

    row = ev.run_one(CrashingGraph(), "benign_weather")
    assert row["verdict"] == "ERROR" and "RESOURCE_EXHAUSTED" in row["crash"]


def test_run_eval_main_prints_details_and_saves_for_a_normal_run(monkeypatch, tmp_path, capsys):
    """Regression: a run without crashes failed while printing 'Details' and never saved its results."""
    import dataclasses
    import json
    import sys
    from types import SimpleNamespace

    ev = _load_run_eval()
    monkeypatch.setattr(ev, "settings", dataclasses.replace(ev.settings, offline=False))
    monkeypatch.setattr(ev, "RESULTS", tmp_path)
    som_error = "analyst SOM failed, using rule-based findings: ValidationError: bad field"

    class FakeGraph:
        def invoke(self, *a, **k):
            return {"final_report": SimpleNamespace(verdict=SimpleNamespace(value="block")),
                    "findings": AuditFindings(), "errors": [som_error]}

    monkeypatch.setattr(ev, "build_graph", lambda: FakeGraph())
    monkeypatch.setattr(sys, "argv", ["run_eval.py", "--only", "poisoned_math"])
    ev.main()
    out = capsys.readouterr().out
    assert "FALLBACK" in out and som_error in out          # the reason is printed
    saved = json.loads(next(tmp_path.glob("eval_*.json")).read_text(encoding="utf-8"))
    assert saved["rows"]["poisoned_math"]["som_error"] == [som_error]


def test_safety_net_cites_retrieved_sources_of_the_added_findings_chapter():
    base = AuditFindings(findings=[_finding(OwaspCategory.ASI02, Severity.CRITICAL).model_copy(
        update={"references": ["CVE-x"]})])
    llm = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.CRITICAL)])
    sources = [CITES[0], "OWASP-Agentic-Top10-2026.pdf p.13 (ASI02)", "mcp_incidents_notes.md (ASI02)",
               "MCP-Security-Best-Practices.pdf p.8"]
    out, _ = apply_safety_net(llm, base, sources)
    assert out.findings[1].references == ["CVE-x", "OWASP-Agentic-Top10-2026.pdf p.13 (ASI02)",
                                          "mcp_incidents_notes.md (ASI02)"]   # own chapter only, from this audit
    out, _ = apply_safety_net(llm, base, [CITES[0]])                          # nothing of its chapter retrieved
    assert out.findings[1].references == ["CVE-x"]


def _run_findings_node(monkeypatch, answers):
    """Run analyst_findings_node on poisoned_math with an LLM that returns the given answers in turn."""
    import dataclasses
    import json
    from pathlib import Path

    from mcp_security_auditor import llm as llm_module
    from mcp_security_auditor.agents import threat_analyst
    from mcp_security_auditor.tools.manifest_scanner import scan_package

    calls = []

    class ScriptedLLM:
        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            calls.append(1)
            return answers[len(calls) - 1]

    monkeypatch.setattr(threat_analyst, "settings", dataclasses.replace(threat_analyst.settings, offline=False))
    monkeypatch.setattr(llm_module, "get_llm", lambda: ScriptedLLM())
    path = Path(__file__).resolve().parents[1] / "data" / "samples" / "poisoned_math.json"
    pkg = ToolPackage.model_validate(json.loads(path.read_text(encoding="utf-8")))
    state = AuditState(package=pkg, scan_report=scan_package(pkg),
                       retrieved_sources=["OWASP-Agentic-Top10-2026.pdf p.10 (ASI01)"])
    return threat_analyst.analyst_findings_node(state), len(calls)


def test_empty_llm_answer_is_retried_once(monkeypatch):
    good = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.CRITICAL, title="Hidden instruction")])
    out, calls = _run_findings_node(monkeypatch, [AuditFindings(), good])
    assert calls == 2 and "analyst SOM empty, retry succeeded" in out["errors"]
    assert "Hidden instruction" in [f.title for f in out["findings"].findings]


def test_empty_llm_answer_twice_falls_back_to_cited_rule_based_findings(monkeypatch):
    out, calls = _run_findings_node(monkeypatch, [AuditFindings(), AuditFindings()])
    assert calls == 2 and "analyst SOM empty twice, using rule-based findings" in out["errors"]
    asi01 = [f for f in out["findings"].findings if f.owasp_category is OwaspCategory.ASI01]
    assert asi01 and "OWASP-Agentic-Top10-2026.pdf p.10 (ASI01)" in asi01[0].references
