"""Every sample must parse into the shared contract. Run: pytest -q"""
import json
from pathlib import Path

from mcp_security_auditor.schemas import AuditFindings, Finding, OwaspCategory, Severity, ToolPackage

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


def test_all_samples_parse():
    for p in SAMPLES.glob("*.json"):
        if p.name == "labels.json":
            continue
        ToolPackage.model_validate(json.loads(p.read_text()))


def test_findings_validation():
    f = Finding(owasp_category=OwaspCategory.ASI01, severity=Severity.HIGH, title="t", evidence="e",
                confidence=0.5, mitigation="m")
    assert AuditFindings(findings=[f]).max_severity == Severity.HIGH
    try:
        Finding(owasp_category=OwaspCategory.ASI01, severity=Severity.HIGH, title="t", evidence="e",
                confidence=1.5, mitigation="m")
        raise AssertionError("confidence > 1 must be rejected")
    except ValueError:
        pass
