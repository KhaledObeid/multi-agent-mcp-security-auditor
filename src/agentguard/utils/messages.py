"""Message inspection helpers (guideline section E). OWNER: Member A.

print_message() distinguishes the four cases the guidelines ask for:
SystemMessage, HumanMessage, AIMessage that is a plain answer, AIMessage that
REQUESTS tool calls, and ToolMessage that carries a tool RESULT.
"""
from __future__ import annotations

import json

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

MAX_CHARS = 600  # truncate long contents in the console


def msg_text(m: BaseMessage) -> str:
    """Return message content as plain text (Gemini may return a list of parts)."""
    c = m.content
    if isinstance(c, str):
        return c
    parts = []
    for p in c:
        if isinstance(p, dict):
            parts.append(p.get("text", ""))
        else:
            parts.append(str(p))
    return "".join(parts)


def _short(s: str) -> str:
    s = s.strip()
    return s if len(s) <= MAX_CHARS else s[:MAX_CHARS] + f" ...[+{len(s) - MAX_CHARS} chars]"


def print_message(m: BaseMessage, channel: str = "") -> None:
    tag = f"[{channel}] " if channel else ""
    if isinstance(m, SystemMessage):
        print(f"{tag}SystemMessage: {_short(msg_text(m))}")
    elif isinstance(m, HumanMessage):
        print(f"{tag}HumanMessage: {_short(msg_text(m))}")
    elif isinstance(m, AIMessage) and m.tool_calls:
        print(f"{tag}AIMessage (TOOL CALL REQUEST)")
        if msg_text(m).strip():
            print(f"    text: {_short(msg_text(m))}")
        for tc in m.tool_calls:
            print(f"    -> {tc['name']}({json.dumps(tc['args'])})  id={tc['id']}")
    elif isinstance(m, AIMessage):
        print(f"{tag}AIMessage (FINAL ANSWER): {_short(msg_text(m))}")
    elif isinstance(m, ToolMessage):
        status = getattr(m, "status", "success")
        print(f"{tag}ToolMessage name={m.name} tool_call_id={m.tool_call_id} status={status}")
        print(f"    result: {_short(msg_text(m))}")
    else:
        print(f"{tag}{type(m).__name__}: {_short(msg_text(m))}")


def last_ai(messages: list[BaseMessage]) -> AIMessage | None:
    for m in reversed(messages):
        if isinstance(m, AIMessage):
            return m
    return None
