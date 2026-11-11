"""Agent 4: Report. OWNER: Member A.

Role: decide install / install_with_mitigations / block, explain why, and
produce a patched manifest.
Toolset: none bound to the LLM (patching is deterministic, see tools/patcher.py),
so its toolset differs from every other agent.
Structured Output Mode: FinalReport.

Responsible-AI guardrail: a deterministic policy computes the MINIMUM verdict
(policy_floor) from the findings AND the scanner's own severities, so the LLM
can neither lower it directly nor by under-rating a finding. The LLM may make
the verdict stricter, never more lenient.

TODO (Member A): tune policy_verdict(); improve REPORT_SYSTEM.
"""
from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from mcp_security_auditor.config import settings
from mcp_security_auditor.schemas import AuditRecord, FinalReport, Severity, Verdict
from mcp_security_auditor.state import AuditState
from mcp_security_auditor.tools.patcher import patch_manifest

REPORT_SYSTEM = """You are the Report agent of a security audit team. Using the findings and red-team results,
decide whether the user should install the package, install it with mitigations, or block it.
Write a rationale a non-expert can follow (3-6 sentences) and list concrete required mitigations.
The minimum verdict allowed by policy is given; you may choose it or a stricter one, never a more lenient one."""


def _highest(severities) -> Severity:
    return max(severities, key=lambda s: s.rank, default=Severity.INFO)


def policy_verdict(state: AuditState) -> tuple[Verdict, str]:
    # The floor must not depend on the LLM alone: if the analyst LLM rates a
    # critical scanner flag as "high", the floor would drop and the LLM could make
    # the verdict MORE lenient. So take the highest of the findings and of the
    # deterministic scanner's own severity hints.
    llm_sev = state.findings.max_severity if state.findings else Severity.INFO
    scan_sev = _highest(f.severity_hint for f in state.scan_report.flags) if state.scan_report else Severity.INFO
    sev = _highest([llm_sev, scan_sev])
    obeyed = any(r.mock_agent_obeyed for r in state.red_team_results)
    if obeyed:
        return Verdict.BLOCK, "the mock agent obeyed injected instructions in the sandbox"
    if sev == Severity.CRITICAL:
        source = "the scanner flagged" if scan_sev == Severity.CRITICAL and llm_sev != Severity.CRITICAL else "there is"
        return Verdict.BLOCK, f"{source} at least one critical finding"
    if state.rug_pull_detected:
        return Verdict.BLOCK, "tool definitions changed after a previous approval"
    if sev.rank >= Severity.MEDIUM.rank:
        return Verdict.INSTALL_WITH_MITIGATIONS, f"highest severity is {sev.value}"
    return Verdict.INSTALL, "no finding above low severity"


def _context(state: AuditState, floor: Verdict, reason: str) -> str:
    findings = state.findings.model_dump(mode="json") if state.findings else {}
    rt = [r.model_dump(mode="json") for r in state.red_team_results]
    return (f"Package: {state.package.name} v{state.package.version}\n"
            f"Minimum verdict allowed by policy: {floor.value} (reason: {reason})\n"
            f"Findings: {json.dumps(findings)[:6000]}\nRed-team results: {json.dumps(rt)[:3000]}\n"
            f"Rug pull detected: {state.rug_pull_detected} {state.rug_pull_changes}")


def report_node(state: AuditState) -> dict:
    floor, reason = policy_verdict(state)
    errors = list(state.errors)
    report = FinalReport(verdict=floor, rationale=f"Policy decision: {reason}.",
                         required_mitigations=[f.mitigation for f in (state.findings.findings if state.findings else [])
                                               if f.severity.rank >= Severity.MEDIUM.rank])

    if not settings.offline:
        from mcp_security_auditor.llm import get_llm

        try:
            raw = get_llm().with_structured_output(FinalReport).invoke(
                [SystemMessage(REPORT_SYSTEM), HumanMessage(_context(state, floor, reason))])
            llm_report = raw if isinstance(raw, FinalReport) else FinalReport.model_validate(raw)
            if llm_report.verdict.rank < floor.rank:  # guardrail
                errors.append(f"LLM proposed {llm_report.verdict.value}; raised to policy floor {floor.value}")
                llm_report = llm_report.model_copy(update={"verdict": floor})
            report = llm_report
        except Exception as e:
            errors.append(f"report SOM failed, using policy report: {type(e).__name__}: {e}")

    patched, changes = patch_manifest(state.package, state.scan_report, state.permission_diff)
    pkg = state.package
    record = AuditRecord(package_name=pkg.name, package_version=pkg.version,
                         manifest_hash=state.manifest_hash or "", tool_hashes=state.tool_hashes, verdict=report.verdict,
                         permissions=list(pkg.permissions), dependencies=[d.name for d in pkg.dependencies])
    return {"final_report": report, "policy_floor": floor, "policy_reason": reason, "patched_manifest": patched,
            "patch_changes": changes, "audit_history": [record], "errors": errors}
