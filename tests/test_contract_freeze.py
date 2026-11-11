"""Contract freeze guard (frozen end of week 1, Nov 11 2026). OWNER: Member A.

schemas.py and state.py are shared by every agent. After the freeze:
  - existing fields and enum values may NOT be removed or renamed,
  - new fields are allowed only if they have a default (Optional / default value),
  - new enum values are allowed.
If this test fails, your change breaks someone else's code. Open a PR titled
"contract: ..." and agree it with the team before changing the snapshot below.
"""
import typing

from mcp_security_auditor import schemas
from mcp_security_auditor.state import AuditState

FROZEN_FIELDS = {
    "ToolSpec": ["name", "description", "input_schema"],
    "Dependency": ["name", "version", "ecosystem"],
    "ToolPackage": ["name", "version", "claimed_purpose", "tools", "permissions", "dependencies", "code_snippets"],
    "ScanFlag": ["kind", "tool_name", "evidence", "severity_hint"],
    "ScanReport": ["package_name", "flags", "risk_score"],
    "PermissionDiff": ["claimed_capabilities", "requested_permissions", "unjustified_permissions", "notes"],
    "DependencyVuln": ["package", "version", "vuln_ids", "summaries", "error"],
    "Finding": ["owasp_category", "severity", "title", "evidence", "confidence", "mitigation", "affected_tool",
                "references"],
    "AuditFindings": ["findings", "summary"],
    "RedTeamResult": ["target_tool", "attack_prompt", "mock_agent_obeyed", "observed_tool_calls", "canary_hits",
                      "notes"],
    "FinalReport": ["verdict", "rationale", "required_mitigations"],
    "AuditRecord": ["package_name", "package_version", "manifest_hash", "tool_hashes", "verdict"],
    "AuditState": ["package", "run_count", "manifest_hash", "tool_hashes", "audit_history", "rug_pull_detected",
                   "rug_pull_changes", "inspector_messages", "analyst_messages", "redteam_messages", "scan_report",
                   "permission_diff", "dependency_vulns", "retrieved_sources", "findings", "needs_red_team",
                   "red_team_results", "final_report", "patched_manifest", "patch_changes", "tool_rounds", "errors"],
}

FROZEN_ENUMS = {
    "Severity": ["info", "low", "medium", "high", "critical"],
    "Verdict": ["install", "install_with_mitigations", "block"],
    "OwaspCategory": ["ASI01 Agent Goal Hijack", "ASI02 Tool Misuse and Exploitation",
                      "ASI03 Identity and Privilege Abuse", "ASI04 Agentic Supply Chain Vulnerabilities",
                      "ASI05 Unexpected Code Execution", "ASI06 Memory and Context Poisoning",
                      "ASI07 Insecure Inter-Agent Communication", "ASI08 Cascading Failures",
                      "ASI09 Human-Agent Trust Exploitation", "ASI10 Rogue Agents", "LLM01 Prompt Injection",
                      "LLM02 Sensitive Information Disclosure", "LLM03 Supply Chain", "LLM06 Excessive Agency",
                      "Other"],
}

FROZEN_FLAG_KINDS = ["hidden_instruction", "invisible_unicode", "shell_access", "filesystem_access",
                     "sensitive_path", "outbound_url", "broad_scope", "other"]


def _model(name):
    return AuditState if name == "AuditState" else getattr(schemas, name)


def test_frozen_fields_still_exist():
    for name, fields in FROZEN_FIELDS.items():
        missing = set(fields) - set(_model(name).model_fields)
        assert not missing, f"{name} lost frozen field(s) {sorted(missing)}: open a 'contract:' PR first"


def test_new_fields_are_optional():
    for name, fields in FROZEN_FIELDS.items():
        for field, info in _model(name).model_fields.items():
            if field not in fields:
                assert not info.is_required(), f"new field {name}.{field} must have a default (additive only)"


def test_frozen_enum_values_still_exist():
    for name, values in FROZEN_ENUMS.items():
        current = {m.value for m in getattr(schemas, name)}
        missing = set(values) - current
        assert not missing, f"{name} lost frozen value(s) {sorted(missing)}"
    missing_kinds = set(FROZEN_FLAG_KINDS) - set(typing.get_args(schemas.FlagKind))
    assert not missing_kinds, f"FlagKind lost frozen value(s) {sorted(missing_kinds)}"
