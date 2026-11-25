"""CLI / REPL output for the demo: state diffs, history, commands. OWNER: Member A. Offline."""
import builtins

import pytest

from mcp_security_auditor import main
from mcp_security_auditor.schemas import AuditFindings, Verdict


def test_state_diff_shows_only_changed_fields():
    before = {"run_count": 1, "needs_red_team": False, "audit_history": ["a"], "inspector_messages": [],
              "policy_floor": None}
    after = {"run_count": 1, "needs_red_team": True, "audit_history": ["a", "b"], "inspector_messages": ["m"],
             "policy_floor": Verdict.BLOCK}
    lines = main.state_diff(before, after)
    assert "  needs_red_team: False -> True" in lines
    assert "  audit_history: +1 (now 2)" in lines
    assert "  policy_floor: None -> block" in lines
    assert not any("run_count" in l or "inspector_messages" in l for l in lines)


def test_state_diff_collapses_a_reset_into_one_line():
    before = {"findings": AuditFindings(), "patch_changes": ["x"], "rug_pull_detected": True}
    after = {"findings": None, "patch_changes": [], "rug_pull_detected": False}
    assert main.state_diff(before, after) == [
        "  reset for the new audit: findings, patch_changes, rug_pull_detected"]


def test_bare_sample_names_resolve():
    assert main.resolve_package_path("poisoned_math").name == "poisoned_math.json"
    with pytest.raises(FileNotFoundError):
        main.resolve_package_path("no_such_sample")


def run_repl(monkeypatch, capsys, commands):
    feed = iter(commands)
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(feed))
    try:
        main.repl()
    except StopIteration:
        pass
    return capsys.readouterr().out


def test_repl_demo_session(monkeypatch, capsys):
    out = run_repl(monkeypatch, capsys, [
        "help", "thread demo", "audit rugpull_calc_v1", "audit rugpull_calc_v2",
        "report", "patched", "state", "history", "history full", "frobnicate", "audit", "quit"])
    assert "audit <path | sample name>" in out                     # help
    assert "state diff:" in out
    assert "thread 'demo': 2 audit(s)" in out                      # grouped history
    assert "audit 2: calc-pro-mcp v1.0.1 -> block, RUG PULL" in out
    assert "step=-1" in out                                        # history full keeps the raw view
    assert '"name": "calc-pro-mcp"' in out                         # patched manifest
    assert "unknown command 'frobnicate'" in out
    assert "usage: audit" in out


def test_repl_survives_a_missing_file(monkeypatch, capsys):
    out = run_repl(monkeypatch, capsys, ["audit nope.json", "report", "quit"])
    assert "error: FileNotFoundError" in out
    assert "no completed audit on this thread yet" in out
