"""One reusable "agent turn" used by every tool-calling agent. OWNER: Member A.

A turn either asks the LLM for its next step (which may be tool calls) or, in
OFFLINE mode, plays back a scripted step. On the first turn it seeds the
agent's channel with its SystemMessage and a HumanMessage brief.
"""
from __future__ import annotations

from typing import Callable

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool

from agentguard.config import settings


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
        already_used_tools = any(isinstance(m, ToolMessage) for m in convo)
        calls = [] if already_used_tools else offline_calls()
        if calls:
            new.append(AIMessage(content="", tool_calls=[{**c, "id": f"offline_{i}_{c['name']}", "type": "tool_call"} for i, c in enumerate(calls)]))
        else:
            new.append(AIMessage(content=offline_final))
        return new

    from agentguard.llm import get_llm

    ai = get_llm().bind_tools(tools).invoke(convo)
    new.append(ai)
    return new
