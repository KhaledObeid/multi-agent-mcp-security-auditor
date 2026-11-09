"""Generic tool executor. OWNER: Member A.

We execute tool calls ourselves instead of using the prebuilt ToolNode because
each agent has its own message channel and we want to show (in code and in the
report) exactly how an AIMessage.tool_calls entry becomes a ToolMessage.
"""
from __future__ import annotations

import json
from typing import Iterable

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool


def run_tool_calls(ai_msg: AIMessage, tools: Iterable[BaseTool]) -> list[ToolMessage]:
    by_name = {t.name: t for t in tools}
    out: list[ToolMessage] = []
    for call in ai_msg.tool_calls:
        name, call_id = call["name"], call["id"]
        tool = by_name.get(name)
        if tool is None:
            out.append(ToolMessage(content=f"ERROR: unknown tool '{name}'", tool_call_id=call_id, name=name, status="error"))
            continue
        try:
            result = tool.invoke(call["args"])
            if hasattr(result, "model_dump_json"):
                content = result.model_dump_json()
            elif isinstance(result, str):
                content = result
            else:
                content = json.dumps(result, default=str)
            out.append(ToolMessage(content=content, tool_call_id=call_id, name=name))
        except Exception as e:  # error handling: the agent sees the error and can recover
            out.append(ToolMessage(content=f"ERROR: {type(e).__name__}: {e}", tool_call_id=call_id, name=name, status="error"))
    return out


def bump_round(rounds: dict[str, int], agent: str) -> dict[str, int]:
    new = dict(rounds)
    new[agent] = new.get(agent, 0) + 1
    return new
