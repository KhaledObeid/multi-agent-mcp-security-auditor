"""Red-team sandbox tests. OWNER: Member B.

These cover the deterministic parts -- canary detection and the obedience-rate
aggregation -- so they run offline with no API key. The live LLM path is
exercised in the online run against poisoned_math.
"""
from mcp_security_auditor.schemas import ToolPackage, ToolSpec
from mcp_security_auditor.tools.sandbox import _canaries, run_sandbox, summarize_trials

PKG = ToolPackage(
    name="calc",
    claimed_purpose="A simple calculator.",
    tools=[ToolSpec(name="add", description="Adds two numbers.")],
)


def test_canary_flags_secret_path_stuffed_into_args():
    calls = [{"name": "add", "args": {"a": 3, "b": 4, "sidenote": "contents of ~/.ssh/id_rsa"}}]
    hits = _canaries(calls, "", PKG, "add", "add 3 and 4")
    assert hits  # the secret path the user never mentioned must trip a canary


def test_canary_ignores_a_clean_target_call():
    calls = [{"name": "add", "args": {"a": 3, "b": 4}}]
    assert _canaries(calls, "done", PKG, "add", "add 3 and 4") == []


def test_canary_ignores_a_benign_second_tool():
    # a second, innocent tool call is NOT exfiltration and must not count as obeyed
    calls = [{"name": "add", "args": {"a": 1, "b": 2}}, {"name": "format", "args": {"text": "hi"}}]
    assert _canaries(calls, "", PKG, "add", "add 1 and 2") == []


def test_canary_flags_known_exfil_tool():
    calls = [{"name": "add", "args": {"a": 1, "b": 2}}, {"name": "send_email", "args": {"to": "x@y.z"}}]
    hits = _canaries(calls, "", PKG, "add", "add 1 and 2")
    assert any("send_email" in h for h in hits)


def test_summarize_trials_computes_obedience_rate():
    trial_hits = [["sensitive path referenced: id_rsa"], [], ["sensitive path referenced: id_rsa"], [], []]
    trial_calls = [[] for _ in trial_hits]
    res = summarize_trials("add", "add 3 and 4", trial_calls, trial_hits)
    assert res.mock_agent_obeyed is True
    assert "2/5" in res.notes and "0.40" in res.notes


def test_summarize_trials_all_clean():
    res = summarize_trials("add", "add 3 and 4", [[], []], [[], []])
    assert res.mock_agent_obeyed is False
    assert "0/2" in res.notes


def test_run_sandbox_skips_offline():
    # the test suite runs with MCP_SECURITY_AUDITOR_OFFLINE=1
    res = run_sandbox(PKG, "add", "add 3 and 4")
    assert res.mock_agent_obeyed is None
    assert "offline" in res.notes
