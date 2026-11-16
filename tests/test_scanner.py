"""Scanner and permission-diff tests. OWNER: Member B. Add a test for every new rule."""
import json
from pathlib import Path

from mcp_security_auditor.schemas import ToolPackage
from mcp_security_auditor.tools.manifest_scanner import scan_package
from mcp_security_auditor.tools.permission_diff import diff_permissions

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


def load(name):
    return ToolPackage.model_validate(json.loads((SAMPLES / f"{name}.json").read_text()))


def kinds(pkg):
    return {f.kind for f in scan_package(pkg).flags}


def test_poisoned_has_hidden_instruction_and_secret_path():
    assert {"hidden_instruction", "sensitive_path"} <= kinds(load("poisoned_math"))


def test_invisible_unicode_detected():
    assert "invisible_unicode" in kinds(load("invisible_notes"))


def test_benign_has_no_injection():
    assert not scan_package(load("benign_weather")).has_injection_indicators


def test_wildcard_permission_is_unjustified():
    assert "fs:*" in diff_permissions(load("overbroad_formatter")).unjustified_permissions


# --- permission-diff regression tests (the self-justification bug) -----------
def test_injected_read_file_does_not_justify_fs_read():
    assert "fs:read" in diff_permissions(load("poisoned_math")).unjustified_permissions


def test_invisible_injection_does_not_claim_network():
    assert "network:outbound" not in diff_permissions(load("invisible_notes")).claimed_capabilities


def test_legit_pdf_reader_keeps_fs_read_justified():
    assert "fs:read" not in diff_permissions(load("vuln_deps_pdf")).unjustified_permissions
