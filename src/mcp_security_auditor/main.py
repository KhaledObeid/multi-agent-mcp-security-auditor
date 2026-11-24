"""Command-line entry point. OWNER: Member A.

Examples
    python -m mcp_security_auditor.main audit data/samples/poisoned_math.json
    python -m mcp_security_auditor.main audit rugpull_calc_v1 rugpull_calc_v2 --thread demo
    python -m mcp_security_auditor.main repl
    python -m mcp_security_auditor.main graph

A bare sample name (e.g. ``poisoned_math``) is looked up in data/samples/.

Auditing two files with the same --thread in ONE process is the checkpointing
demo: MemorySaver is in-memory, so continuity lasts for the life of the process.

The trace prints, for every node, the messages it added and a STATE DIFF: only
the fields whose value changed, as "before -> after".

In the REPL, any line that is not a command goes to the Report chat
(agents/report_chat.py), which answers questions about the audit on the current
thread and can start a new audit itself.
"""
from __future__ import annotations

import argparse
import json
from enum import Enum
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, RemoveMessage, ToolMessage
from pydantic import BaseModel

from mcp_security_auditor.agents.report_chat import ChatTurn, ReportChat
from mcp_security_auditor.graph import build_graph
from mcp_security_auditor.schemas import AuditFindings, FinalReport, PermissionDiff, ScanReport, ToolPackage
from mcp_security_auditor.utils.messages import print_message

CHANNELS = {"inspector_messages": "Inspector", "analyst_messages": "Analyst", "redteam_messages": "RedTeam",
            "chat_messages": "Chat"}
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"
MAX_VALUE_CHARS = 120

HELP = """Commands:
  audit <path | sample name>   audit a package on the current thread (e.g. audit poisoned_math)
  samples                      list the sample packages
  thread <id>                  switch thread (each thread has its own checkpoints and audit history)
  state                        current state of this thread, one field per line
  report                       the last verdict, rationale and mitigations again
  patched                      the patched manifest from the last audit
  history [full]               checkpoints grouped by audit, with the node and fields of each step
  help | quit
Anything else goes to the Report chat, for example:
  I think data/samples/poisoned_math.json is compromised    (the chat audits it)
  which tool?  /  why?  /  what did the sandbox show?        (one level deeper each time)
  I'm technical  /  plain language please                    (answer style, kept on this thread)
  re-audit                                                   (audit the last sample again)"""
# commands that take no argument: a longer line starting with one of these words goes to the chat
BARE_COMMANDS = {"samples", "state", "report", "patched", "help", "quit", "exit"}


# --------------------------------------------------------------------------- #
# Loading packages
# --------------------------------------------------------------------------- #
def resolve_package_path(arg: str) -> Path:
    """A path as given, or a bare sample name looked up in data/samples/."""
    p = Path(arg)
    if p.is_file():
        return p
    for candidate in (SAMPLES_DIR / arg, SAMPLES_DIR / f"{arg}.json"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no file '{arg}' and no sample of that name (try: samples)")


def load_package(path: str) -> ToolPackage:
    return ToolPackage.model_validate(json.loads(resolve_package_path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# Describing values and state diffs
# --------------------------------------------------------------------------- #
def _short(s: str) -> str:
    return s if len(s) <= MAX_VALUE_CHARS else s[:MAX_VALUE_CHARS] + "..."


def describe(value) -> str:
    """A one-line, human-readable summary of a state value."""
    if value is None:
        return "None"
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, ToolPackage):
        return f"{value.name} v{value.version} ({len(value.tools)} tool(s))"
    if isinstance(value, ScanReport):
        kinds = sorted({f.kind for f in value.flags})
        return f"{len(value.flags)} flag(s) {kinds}, risk {value.risk_score:.2f}"
    if isinstance(value, PermissionDiff):
        return f"unjustified {value.unjustified_permissions} of requested {value.requested_permissions}"
    if isinstance(value, AuditFindings):
        return f"{len(value.findings)} finding(s), max severity {value.max_severity.value}"
    if isinstance(value, FinalReport):
        return f"verdict {value.verdict.value}, {len(value.required_mitigations)} mitigation(s)"
    if isinstance(value, BaseModel):
        return _short(value.model_dump_json())
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    if isinstance(value, dict):
        return _short(json.dumps(value, default=str)) if value else "{}"
    if isinstance(value, str):
        return _short(repr(value))
    return repr(value)


def _is_empty(value) -> bool:
    return value is None or value == [] or value == {} or value == "" or value is False or value == 0


def state_diff(before: dict, after: dict) -> list[str]:
    """Lines describing every field whose value changed, message channels excluded
    (their new messages are printed in full). Fields reset to empty in one step
    (intake starting a new audit on a used thread) are collapsed into one line."""
    lines, cleared = [], []
    for key in after:
        if key in CHANNELS:
            continue
        old, new = before.get(key), after[key]
        if old == new:
            continue
        if _is_empty(new) and not _is_empty(old):
            cleared.append(key)
        elif isinstance(new, list) and isinstance(old, list | None):
            added = len(new) - len(old or [])
            change = f"+{added}" if added > 0 else "updated"
            lines.append(f"  {key}: {change} (now {len(new)})")
        else:
            d_old, d_new = describe(old), describe(new)
            lines.append(f"  {key}: {d_old} -> {d_new}" if d_old != d_new else f"  {key}: updated ({d_new})")
    if cleared:
        lines.append(f"  reset for the new audit: {', '.join(cleared)}")
    return lines


def _changed_fields(before: dict, after: dict) -> list[str]:
    out = []
    for key, new in after.items():
        old = before.get(key)
        if old == new:
            continue
        if key in CHANNELS:
            out.append(f"{key}(+{len(new) - len(old or [])})" if len(new) >= len(old or []) else key)
        else:
            out.append(key)
    return out


# --------------------------------------------------------------------------- #
# Running an audit
# --------------------------------------------------------------------------- #
def print_verdict(values: dict) -> None:
    rep = values.get("final_report")
    print("\n================ VERDICT ================")
    if not rep:
        print("no completed audit on this thread yet")
        return
    print(f"verdict:   {rep.verdict.value}")
    if values.get("policy_floor"):
        print(f"policy minimum: {values['policy_floor'].value} ({values.get('policy_reason')})")
    print(f"rationale: {rep.rationale}")
    for m in rep.required_mitigations:
        print(f"  - {m}")
    if values.get("rug_pull_detected"):
        print("RUG PULL:", values.get("rug_pull_changes"))
    if values.get("patch_changes"):
        print("patch:", values.get("patch_changes"))
    if values.get("errors"):
        print("errors:", values.get("errors"))


def run_audit(graph, pkg: ToolPackage, thread_id: str, show_messages: bool = True) -> dict:
    config = {"configurable": {"thread_id": thread_id}}
    print(f"\n######## AUDIT {pkg.name} v{pkg.version}  (thread={thread_id}) ########")
    before: dict = {}
    node = None
    for mode, chunk in graph.stream({"package": pkg}, config, stream_mode=["updates", "values"]):
        if mode == "updates":
            for node, update in chunk.items():
                print(f"\n=== node: {node} ===")
                if not update:
                    continue
                print("partial state update keys:", sorted(update.keys()))
                for key, value in update.items():
                    if key in CHANNELS and show_messages:
                        for m in value:
                            if isinstance(m, BaseMessage) and not isinstance(m, RemoveMessage):
                                print_message(m, CHANNELS[key])
        else:  # "values": the full state after the node above
            if node is not None:
                diff = state_diff(before, chunk)
                if diff:
                    print("state diff:")
                    print("\n".join(diff))
            before = chunk

    values = graph.get_state(config).values
    print_verdict(values)
    return values


# --------------------------------------------------------------------------- #
# Inspecting a thread
# --------------------------------------------------------------------------- #
def show_state(graph, thread_id: str) -> None:
    values = graph.get_state({"configurable": {"thread_id": thread_id}}).values
    if not values:
        print(f"thread '{thread_id}' has no state yet")
        return
    width = max(len(k) for k in values)
    for key, value in values.items():
        shown = f"{len(value)} message(s)" if key in CHANNELS else describe(value)
        print(f"  {key.ljust(width)}  {shown}")


def show_history(graph, thread_id: str, full: bool = False) -> None:
    """Checkpoints oldest first, grouped by audit. Each line names the node that
    wrote the checkpoint and the fields it changed (the state progression)."""
    config = {"configurable": {"thread_id": thread_id}}
    snaps = list(graph.get_state_history(config))[::-1]  # LangGraph returns newest first
    if not snaps:
        print(f"thread '{thread_id}' has no checkpoints yet")
        return
    if full:
        for snap in reversed(snaps):
            v = snap.values
            print(f"step={snap.metadata.get('step')} next={snap.next} run_count={v.get('run_count')} "
                  f"audits_stored={len(v.get('audit_history', []))} "
                  f"checkpoint=...{snap.config['configurable']['checkpoint_id'][-8:]}")
        return

    # one group per audit: each audit starts with an "input" checkpoint
    groups: list[list[tuple]] = []
    prev = None
    for snap in snaps:
        if snap.metadata.get("source") == "input":
            groups.append([])
        if not groups:  # the chat wrote to this thread before its first audit
            groups.append([])
        if snap.metadata.get("source") == "update":
            writer = "chat"
        else:
            writer = "input" if prev is None or snap.metadata.get("source") == "input" else (prev.next or ("?",))[0]
        groups[-1].append((snap, writer, _changed_fields(prev.values, snap.values) if prev else []))
        prev = snap

    audits = sum(1 for g in groups if g[0][0].metadata.get("source") == "input")
    print(f"thread '{thread_id}': {audits} audit(s), {len(snaps)} checkpoint(s), oldest first")
    for i, group in enumerate(groups, 1):
        last = group[-1][0].values
        pkg, rep = last.get("package"), last.get("final_report")
        title = f"{pkg.name} v{pkg.version}" if pkg else "(chat only, no audit yet)"
        outcome = rep.verdict.value if rep and not group[-1][0].next else "not finished"
        rug = ", RUG PULL" if last.get("rug_pull_detected") else ""
        print(f"\naudit {i}: {title} -> {outcome}{rug}  "
              f"(audit_history now holds {len(last.get('audit_history', []))} record(s))")
        for snap, writer, changed in group:
            cid = snap.config["configurable"]["checkpoint_id"][-8:]
            fields = ", ".join(changed) if changed else "-"
            print(f"  step {snap.metadata.get('step'):>3}  ...{cid}  {writer:<17} {fields}")


# --------------------------------------------------------------------------- #
# REPL and CLI
# --------------------------------------------------------------------------- #
def print_chat_turn(turn: ChatTurn) -> None:
    print(f"\nChat: {turn.reply}")
    for e in turn.errors:
        print(f"  (note: {e})")


def _is_command(cmd: str, arg: str) -> bool:
    if cmd in BARE_COMMANDS:
        return not arg
    if cmd == "history":
        return arg in ("", "full")
    if cmd == "thread":
        return len(arg.split()) <= 1
    return cmd == "audit"


def repl() -> None:
    graph, thread = build_graph(), "default"
    chat = ReportChat(graph, run_audit=lambda pkg, t: run_audit(graph, pkg, t),
                      echo=lambda m: print_message(m, "Chat") if isinstance(m, AIMessage | ToolMessage) else None)
    print("Multi-Agent MCP Security Auditor REPL. Type 'help' for commands, or ask the Report chat a question.")
    while True:
        try:
            line = input(f"mcp-security-auditor[{thread}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        cmd, _, arg = line.partition(" ")
        arg = arg.strip()
        config = {"configurable": {"thread_id": thread}}
        try:
            if line and not _is_command(cmd, arg):
                print_chat_turn(chat.turn(thread, line))
            elif cmd == "audit":
                if not arg:
                    print("usage: audit <path | sample name>")
                else:
                    run_audit(graph, load_package(arg), thread)
            elif cmd == "samples":
                for p in sorted(SAMPLES_DIR.glob("*.json")):
                    if p.stem != "labels":
                        print(f"  {p.stem}")
            elif cmd == "thread":
                thread = arg or "default"
            elif cmd == "state":
                show_state(graph, thread)
            elif cmd == "report":
                print_verdict(graph.get_state(config).values)
            elif cmd == "patched":
                patched = graph.get_state(config).values.get("patched_manifest")
                print(json.dumps(patched, indent=2) if patched else "no patched manifest on this thread yet")
            elif cmd == "history":
                show_history(graph, thread, full=(arg == "full"))
            elif cmd == "help":
                print(HELP)
            elif cmd in ("quit", "exit"):
                break
        except Exception as e:  # keep the REPL alive on bad input
            print(f"error: {type(e).__name__}: {e}")


def main() -> None:
    p = argparse.ArgumentParser(prog="python -m mcp_security_auditor.main")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("paths", nargs="+", help="package files or sample names")
    a.add_argument("--thread", default="cli")
    a.add_argument("--quiet", action="store_true", help="hide message trace")
    sub.add_parser("repl")
    sub.add_parser("graph")
    args = p.parse_args()

    if args.cmd == "graph":
        from mcp_security_auditor.graph import draw_mermaid

        print(draw_mermaid())
    elif args.cmd == "repl":
        repl()
    else:
        graph = build_graph()
        for path in args.paths:
            run_audit(graph, load_package(path), args.thread, show_messages=not args.quiet)
        print("\n--- checkpoint history ---")
        show_history(graph, args.thread)


if __name__ == "__main__":
    main()
