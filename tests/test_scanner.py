"""Scanner and permission-diff tests. OWNER: Member B. Add a test for every new rule."""
import json
from pathlib import Path

from agentguard.schemas import ToolPackage
from agentguard.tools.manifest_scanner import scan_package
from agentguard.tools.permission_diff import diff_permissions

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
