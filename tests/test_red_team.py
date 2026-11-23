"""Red-Team agent tests. OWNER: Member B.

Cover the hard cap on sandbox tests (red_team_node) and the offline script.
The online path is simulated with a fake LLM that ignores the prompt's limit,
so these run offline with no API key.
"""
import re
from dataclasses import replace

from langchain_core.messages import AIMessage, ToolMessage

from mcp_security_auditor import llm
from mcp_security_auditor.agents import red_team
from mcp_security_auditor.agents.red_team import _cap_sandbox_calls, red_team_node, redteam_tools_node
from mcp_security_auditor.routing import route_red_team
from mcp_security_auditor.schemas import RedTeamResult, ToolPackage, ToolSpec
from mcp_security_auditor.state import AuditState
from mcp_security_auditor.tools.manifest_scanner import SENSITIVE_PATHS, URL_PATTERN
from mcp_security_auditor.utils import agent_loop

PKG = ToolPackage(
    name="calc",
    claimed_purpose="A simple calculator.",
    tools=[ToolSpec(name="add", description="Adds two numbers.")],
)


def _calls(n, prefix="t"):
    return [{"name": "run_sandbox_test", "args": {"target_tool": "add", "attack_prompt": f"add {i} and {i}"},
             "id": f"{prefix}_{i}", "type": "tool_call"} for i in range(n)]


def test_cap_keeps_calls_that_fit():
    new = [AIMessage(content="", tool_calls=_calls(3))]
    assert _cap_sandbox_calls(new, already_run=0, cap=4) == new


def test_cap_trims_extra_calls_in_one_turn():
    out = _cap_sandbox_calls([AIMessage(content="", tool_calls=_calls(6))], already_run=1, cap=4)
    assert [c["id"] for c in out[-1].tool_calls] == ["t_0", "t_1", "t_2"]


def test_cap_reached_turns_the_request_into_a_final_answer():
    out = _cap_sandbox_calls([AIMessage(content="", tool_calls=_calls(2))], already_run=4, cap=4)
    assert out[-1].tool_calls == []
    assert "cap" in out[-1].content


class _GreedyLLM:
    """A red-team model that asks for 6 sandbox tests every turn, ignoring the prompt."""

    def __init__(self):
        self.turn = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.turn += 1
        return AIMessage(content="", tool_calls=_calls(6, prefix=f"turn{self.turn}"))


def test_red_team_loop_never_runs_more_than_the_cap(monkeypatch):
    ran = []

    def fake_sandbox(pkg, target_tool, attack_prompt, trials=None):
        ran.append(attack_prompt)
        return RedTeamResult(target_tool=target_tool, attack_prompt=attack_prompt, notes="obedience 0/5 (0.00)")

    monkeypatch.setattr(agent_loop, "settings", replace(agent_loop.settings, offline=False))
    monkeypatch.setattr(llm, "get_llm", lambda: _GreedyLLM())
    monkeypatch.setattr(red_team, "run_sandbox", fake_sandbox)

    state = AuditState(package=PKG)
    for _ in range(10):  # the graph's red_team <-> redteam_tools loop, driven by hand
        out = red_team_node(state)
        state = state.model_copy(update={"redteam_messages": state.redteam_messages + out["redteam_messages"]})
        if route_red_team(state) != "redteam_tools":
            break
        out = redteam_tools_node(state)
        state = state.model_copy(update={"redteam_messages": state.redteam_messages + out["redteam_messages"],
                                         "red_team_results": out["red_team_results"],
                                         "tool_rounds": out["tool_rounds"]})

    assert route_red_team(state) == "report"
    assert len(ran) == red_team.DEFAULT_MAX_SANDBOX_TESTS
    assert len(state.red_team_results) == red_team.DEFAULT_MAX_SANDBOX_TESTS
    # every tool call that was kept got exactly one ToolMessage back (Gemini needs the pairing)
    asked = [c["id"] for m in state.redteam_messages if isinstance(m, AIMessage) for c in m.tool_calls]
    answered = [m.tool_call_id for m in state.redteam_messages if isinstance(m, ToolMessage)]
    assert asked == answered


def test_offline_requests_stay_innocent(monkeypatch):
    # the offline script must follow the same rule as REDTEAM_SYSTEM: no secrets, paths,
    # URLs or extra instructions in the request itself
    monkeypatch.setattr(agent_loop, "settings", replace(agent_loop.settings, offline=True))
    new = red_team_node(AuditState(package=PKG))["redteam_messages"]
    prompts = [c["args"]["attack_prompt"] for c in new[-1].tool_calls]
    assert prompts
    for p in prompts:
        assert not any(re.search(sp, p, re.IGNORECASE) for sp in SENSITIVE_PATHS)
        assert not re.search(URL_PATTERN, p)
        assert not re.search(r"setup|instruction", p, re.IGNORECASE)
