"""agent_turn must survive a failing LLM call. OWNER: Member A.

Found in the first ONLINE audit (Nov 11): Gemini answered 503 "model overloaded",
the exception escaped agent_turn and crashed the whole audit. Now a failed call
falls back to the scripted rule-based step. No network or API key is used here:
the LLM is replaced by a fake that always raises.
"""
import dataclasses

from langchain_core.messages import AIMessage, ToolMessage

import mcp_security_auditor.llm as llm_module
import mcp_security_auditor.utils.agent_loop as agent_loop


class _BrokenLLM:
    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        raise RuntimeError("503 UNAVAILABLE: model overloaded")


def _go_online_with_broken_llm(monkeypatch):
    monkeypatch.setattr(agent_loop, "settings", dataclasses.replace(agent_loop.settings, offline=False))
    monkeypatch.setattr(llm_module, "get_llm", lambda: _BrokenLLM())


def _turn(channel):
    return agent_loop.agent_turn(
        channel=channel,
        system_prompt="system",
        brief=lambda: "brief",
        tools=[],
        rounds_used=0,
        offline_calls=lambda: [{"name": "scan_manifest", "args": {"tool_name": "*"}}],
        offline_final="Inspection complete.",
    )


def test_llm_failure_falls_back_to_scripted_tool_calls(monkeypatch):
    _go_online_with_broken_llm(monkeypatch)
    new = _turn([])
    ai = new[-1]
    assert isinstance(ai, AIMessage)
    assert [c["name"] for c in ai.tool_calls] == ["scan_manifest"]
    assert "rule-based fallback" in ai.content
    assert "503" in ai.content


def test_llm_failure_after_tools_finishes_the_turn(monkeypatch):
    _go_online_with_broken_llm(monkeypatch)
    first = _turn([])
    call_id = first[-1].tool_calls[0]["id"]
    channel = first + [ToolMessage(content="{}", tool_call_id=call_id, name="scan_manifest")]
    ai = _turn(channel)[-1]
    assert not ai.tool_calls
    assert "rule-based fallback" in ai.content
    assert ai.content.endswith("Inspection complete.")


def test_agent_does_not_retry_llm_after_it_failed_once(monkeypatch):
    _go_online_with_broken_llm(monkeypatch)
    first = _turn([])
    calls = []

    class _CountingLLM(_BrokenLLM):
        def invoke(self, messages):
            calls.append(1)
            raise AssertionError("LLM must not be called again after it failed in this audit")

    monkeypatch.setattr(llm_module, "get_llm", lambda: _CountingLLM())
    call_id = first[-1].tool_calls[0]["id"]
    channel = first + [ToolMessage(content="{}", tool_call_id=call_id, name="scan_manifest")]
    ai = _turn(channel)[-1]
    assert calls == []
    assert "earlier in this audit" in ai.content
