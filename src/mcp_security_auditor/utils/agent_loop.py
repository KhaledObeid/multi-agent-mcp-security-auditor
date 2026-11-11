"""One reusable "agent turn" used by every tool-calling agent. OWNER: Member A.

A turn either asks the LLM for its next step (which may be tool calls) or, in
OFFLINE mode, plays back a scripted step. On the first turn it seeds the
agent's channel with its SystemMessage and a HumanMessage brief.
"""
from __future__ import annotations

from typing import Callable

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool

from mcp_security_auditor.config import settings

# Prefix of the AIMessage written when the LLM call fails (see agent_turn).
FALLBACK_TAG = "[LLM unavailable"


def agent_turn(
    channel: list[BaseMessage],
    system_prompt: str,
    brief: Callable[[], str],
    tools: list[BaseTool],
    rounds_used: int,
    offline_calls: Callable[[], list[dict]],
    offline_final: str,
) -> list[BaseMessage]:
    """Return the NEW messages to append to this agent's channel."""
    new: list[BaseMessage] = []
    if not channel:
        new = [SystemMessage(system_prompt), HumanMessage(brief())]
    convo = list(channel) + new

    # hard stop: tool budget used up -> close the loop without another LLM call
    if rounds_used >= settings.max_tool_rounds:
        new.append(AIMessage("Tool budget exhausted; finishing with the evidence collected so far."))
        return new

    if settings.offline:
        new.append(_scripted_step(convo, offline_calls, offline_final))
        return new

    # this agent's LLM already failed earlier in this audit: don't wait on it again
    if any(isinstance(m, AIMessage) and str(m.content).startswith(FALLBACK_TAG) for m in convo):
        new.append(_scripted_step(convo, offline_calls, offline_final,
                                  note=f"{FALLBACK_TAG} earlier in this audit; using rule-based fallback]"))
        return new

    from mcp_security_auditor.llm import get_llm

    try:
        ai = get_llm().bind_tools(tools).invoke(convo)
    except Exception as e:
        # Error handling: the LLM call failed even after its retries (e.g. 503
        # "model overloaded", 429 quota, network down). Instead of crashing the
        # whole audit, play the scripted rule-based step for this turn, and say
        # so in the message so the fallback is visible in the trace.
        note = f"{FALLBACK_TAG} ({type(e).__name__}: {str(e)[:160]}); using rule-based fallback]"
        ai = _scripted_step(convo, offline_calls, offline_final, note=note)
    new.append(ai)
    return new


def _scripted_step(
    convo: list[BaseMessage],
    offline_calls: Callable[[], list[dict]],
    offline_final: str,
    note: str = "",
) -> AIMessage:
    """Rule-based step used in OFFLINE mode and as the fallback when the LLM fails:
    request the scripted tool calls once, then finish."""
    already_used_tools = any(isinstance(m, ToolMessage) for m in convo)
    calls = [] if already_used_tools else offline_calls()
    if calls:
        return AIMessage(content=note, tool_calls=[
            {**c, "id": f"offline_{i}_{c['name']}", "type": "tool_call"} for i, c in enumerate(calls)])
    return AIMessage(content=f"{note} {offline_final}".strip())
