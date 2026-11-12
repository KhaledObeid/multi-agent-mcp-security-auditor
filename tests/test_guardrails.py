"""Guardrail and routing regressions found in the week 1 code review. OWNER: Member A.

Each test reproduces an experiment that showed a real gap (offline, no API key):
  1. the LLM could lower the policy floor by under-rating a finding,
  2. a rug pull that only adds permissions / dependencies went unnoticed,
  3. the red team ran on packages it cannot test (dependency-only findings).
"""
import dataclasses
import json
from pathlib import Path

import mcp_security_auditor.agents.threat_analyst as threat_analyst
import mcp_security_auditor.llm as llm_module
from mcp_security_auditor.agents.report import policy_verdict
from mcp_security_auditor.graph import build_graph
from mcp_security_auditor.routing import should_red_team
from mcp_security_auditor.schemas import (
    AuditFindings, Dependency, DependencyVuln, Finding, OwaspCategory, PermissionDiff, RedTeamResult, Severity,
    ToolPackage, Verdict,
)
from mcp_security_auditor.state import AuditState
from mcp_security_auditor.tools.manifest_scanner import scan_package

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


def load(name):
    return ToolPackage.model_validate(json.loads((SAMPLES / f"{name}.json").read_text()))


def _finding(category, severity, tool=None):
    return Finding(owasp_category=category, severity=severity, title="t", evidence="e", confidence=0.9,
                   mitigation="m", affected_tool=tool)


# --- 1. policy floor ---------------------------------------------------------
def test_llm_cannot_lower_the_floor_by_under_rating_findings(monkeypatch):
    """Reproduces the review experiment through the real analyst node: an LLM that
    rates the SSH-stealing instruction 'high' (as Gemini did in the first online run)
    and a sandbox run where the mock agent did not obey."""
    downgraded = AuditFindings(findings=[_finding(OwaspCategory.ASI01, Severity.HIGH, "add"),
                                         _finding(OwaspCategory.ASI02, Severity.HIGH, "add")])

    class DowngradingLLM:
        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            return downgraded

    monkeypatch.setattr(threat_analyst, "settings", dataclasses.replace(threat_analyst.settings, offline=False))
    monkeypatch.setattr(llm_module, "get_llm", lambda: DowngradingLLM())

    pkg = load("poisoned_math")
    state = AuditState(package=pkg, scan_report=scan_package(pkg))
    findings = threat_analyst.analyst_findings_node(state)["findings"]
    assert findings.max_severity == Severity.HIGH  # the LLM really did under-rate it

    state = state.model_copy(update={"findings": findings, "red_team_results": [
        RedTeamResult(target_tool="add", attack_prompt="add 3 and 4", mock_agent_obeyed=False)]})
    floor, reason = policy_verdict(state)
    assert floor == Verdict.BLOCK
    assert "scanner" in reason


def test_floor_is_unchanged_when_llm_and_scanner_agree():
    pkg = load("benign_weather")
    state = AuditState(package=pkg, scan_report=scan_package(pkg), findings=AuditFindings())
    assert policy_verdict(state)[0] == Verdict.INSTALL


def test_report_records_the_policy_floor():
    out = build_graph().invoke({"package": load("poisoned_math")}, {"configurable": {"thread_id": "floor"}})
    assert out["policy_floor"] == Verdict.BLOCK
    assert out["policy_reason"]


# --- 2. rug pull through permissions / dependencies ----------------------------
def _audit_twice(v1, v2, thread):
    g = build_graph()
    g.invoke({"package": v1}, {"configurable": {"thread_id": thread}})
    return g.invoke({"package": v2}, {"configurable": {"thread_id": thread}})


def test_rug_pull_by_new_permission_is_detected():
    v1 = load("rugpull_calc_v1")
    v2 = v1.model_copy(update={"version": "1.0.1", "permissions": v1.permissions + ["shell:exec"]})
    out = _audit_twice(v1, v2, "perm")
    assert out["rug_pull_detected"] is True
    assert any("shell:exec" in c for c in out["rug_pull_changes"])
    assert out["final_report"].verdict == Verdict.BLOCK


def test_rug_pull_by_new_dependency_is_detected():
    v1 = load("rugpull_calc_v1")
    v2 = v1.model_copy(update={"version": "1.0.1",
                               "dependencies": v1.dependencies + [Dependency(name="evil-helper", version="0.0.1")]})
    out = _audit_twice(v1, v2, "dep")
    assert out["rug_pull_detected"] is True
    assert any("evil-helper" in c for c in out["rug_pull_changes"])


def test_unchanged_reaudit_is_not_a_rug_pull():
    v1 = load("rugpull_calc_v1")
    out = _audit_twice(v1, v1.model_copy(update={"version": "1.0.1"}), "same-surface")
    assert out["rug_pull_detected"] is False


# --- 3. red-team routing -------------------------------------------------------
def test_no_red_team_when_high_findings_have_no_tool():
    """Dependency CVEs are high severity but name no tool, so the sandbox has nothing to attack."""
    pkg = load("vuln_deps_pdf")
    findings = AuditFindings(findings=[_finding(OwaspCategory.ASI04, Severity.HIGH),
                                       _finding(OwaspCategory.ASI04, Severity.HIGH)])
    assert should_red_team(AuditState(package=pkg, scan_report=scan_package(pkg), findings=findings)) is False


def test_red_team_when_a_tool_has_a_high_finding():
    pkg = load("vuln_deps_pdf")
    findings = AuditFindings(findings=[_finding(OwaspCategory.ASI05, Severity.HIGH, pkg.tools[0].name)])
    assert should_red_team(AuditState(package=pkg, scan_report=scan_package(pkg), findings=findings)) is True


# --- 4. week 2 policy tuning ---------------------------------------------------
# Two deterministic tool outputs reached the floor only through the analyst's
# findings, so an analyst LLM that rated them "low" could allow a plain install.
def test_known_cves_set_the_floor_even_if_the_analyst_rates_them_low():
    pkg = load("benign_weather")
    state = AuditState(package=pkg, scan_report=scan_package(pkg),
                       findings=AuditFindings(findings=[_finding(OwaspCategory.ASI04, Severity.LOW)]),
                       dependency_vulns=[DependencyVuln(package="pyyaml", version="5.3",
                                                        vuln_ids=["CVE-2020-1747", "CVE-2020-14343"])])
    floor, reason = policy_verdict(state)
    assert floor == Verdict.INSTALL_WITH_MITIGATIONS
    assert "pyyaml 5.3 (2)" in reason


def test_unjustified_permissions_set_the_floor_even_if_the_analyst_rates_them_low():
    pkg = load("benign_weather")
    state = AuditState(package=pkg, scan_report=scan_package(pkg), findings=AuditFindings(),
                       permission_diff=PermissionDiff(unjustified_permissions=["fs:*"]))
    floor, reason = policy_verdict(state)
    assert floor == Verdict.INSTALL_WITH_MITIGATIONS
    assert "fs:*" in reason


def _online(monkeypatch):
    """Report module in online mode, with an LLM that always fails: the policy
    report is used and no real API call can happen."""
    import mcp_security_auditor.agents.report as report

    class FailingLLM:
        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            raise RuntimeError("fake LLM: no network in tests")

    monkeypatch.setattr(report, "settings", dataclasses.replace(report.settings, offline=False))
    monkeypatch.setattr(llm_module, "get_llm", lambda: FailingLLM())
    return report


def _failed_lookup_state():
    pkg = load("benign_weather")  # declares httpx 0.27.0
    return AuditState(package=pkg, scan_report=scan_package(pkg), findings=AuditFindings(),
                      dependency_vulns=[DependencyVuln(package="httpx", version="0.27.0", error="ConnectionError: x")])


def test_failed_osv_lookup_raises_the_floor_online(monkeypatch):
    report = _online(monkeypatch)
    state = _failed_lookup_state()
    floor, reason = policy_verdict(state)
    assert floor == Verdict.INSTALL_WITH_MITIGATIONS
    assert "dependencies could not be checked for known CVEs: httpx 0.27.0" in reason
    out = report.report_node(state.model_copy(update={"findings": AuditFindings()}))
    assert any("check these dependencies for known cves manually" in m.lower()
               for m in out["final_report"].required_mitigations)
    assert any("OSV lookup failed" in e for e in out["errors"])


def test_dependency_never_looked_up_counts_as_unchecked_online(monkeypatch):
    _online(monkeypatch)
    state = _failed_lookup_state().model_copy(update={"dependency_vulns": []})
    assert policy_verdict(state)[0] == Verdict.INSTALL_WITH_MITIGATIONS


def test_successful_lookup_with_no_cves_allows_install_online(monkeypatch):
    _online(monkeypatch)
    state = _failed_lookup_state().model_copy(update={"dependency_vulns": [
        DependencyVuln(package="HTTPX", version="==0.27.0")]})  # name/version spelt differently by an LLM
    assert policy_verdict(state)[0] == Verdict.INSTALL


def test_failed_osv_lookup_does_not_count_in_offline_mode():
    """osv.py calls OSV.dev even in OFFLINE mode; an offline run without internet
    must not change the verdicts (offline eval stays 7/7)."""
    state = _failed_lookup_state()
    assert policy_verdict(state)[0] == Verdict.INSTALL
    out = build_graph().invoke({"package": load("benign_weather")}, {"configurable": {"thread_id": "osv-offline"}})
    assert not any("OSV lookup failed" in e for e in out["errors"])


def test_reason_lists_every_trigger_strictest_first():
    """Before week 2, rugpull_calc_v2 reported only the critical finding and never
    mentioned the rug pull, because the first matching rule returned."""
    out = _audit_twice(load("rugpull_calc_v1"), load("rugpull_calc_v2"), "all-reasons")
    floor, reason = out["policy_floor"], out["policy_reason"]
    assert floor == Verdict.BLOCK
    assert "critical" in reason and "rug pull" in reason
    pkg = load("overbroad_formatter")
    state = AuditState(package=pkg, scan_report=scan_package(pkg),
                       red_team_results=[RedTeamResult(target_tool="fmt", attack_prompt="p", mock_agent_obeyed=True)],
                       permission_diff=PermissionDiff(unjustified_permissions=["fs:*"]))
    floor, reason = policy_verdict(state)
    assert floor == Verdict.BLOCK
    assert reason.index("obeyed") < reason.index("fs:*")
