"""Command-line entry point. OWNER: Member A.

Examples
    python -m agentguard.main audit data/samples/poisoned_math.json
    python -m agentguard.main audit data/samples/rugpull_calc_v1.json data/samples/rugpull_calc_v2.json --thread demo
    python -m agentguard.main repl
    python -m agentguard.main graph

Auditing two files with the same --thread in ONE process is the checkpointing
demo: MemorySaver is in-memory, so continuity lasts for the life of the process.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from langchain_core.messages import BaseMessage, RemoveMessage

from agentguard.graph import build_graph
from agentguard.schemas import ToolPackage
from agentguard.utils.messages import print_message

CHANNELS = {"inspector_messages": "Inspector", "analyst_messages": "Analyst", "redteam_messages": "RedTeam"}


def load_package(path: str) -> ToolPackage:
    return ToolPackage.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


def _summarise_value(v) -> str:
    if hasattr(v, "model_dump"):
        v = v.model_dump(mode="json")
    elif isinstance(v, list):
        v = [x.model_dump(mode="json") if hasattr(x, "model_dump") else x for x in v]
    s = json.dumps(v, default=str)
    return s if len(s) < 160 else s[:160] + "..."


def run_audit(graph, pkg: ToolPackage, thread_id: str, show_messages: bool = True) -> dict:
    config = {"configurable": {"thread_id": thread_id}}
    print(f"\n######## AUDIT {pkg.name} v{pkg.version}  (thread={thread_id}) ########")
    for chunk in graph.stream({"package": pkg}, config, stream_mode="updates"):
        for node, update in chunk.items():
            print(f"\n=== node: {node} ===")
            if not update:
                continue
            print("partial state update keys:", sorted(update.keys()))
            for key, value in update.items():
                if key in CHANNELS:
                    if show_messages:
                        for m in value:
                            if isinstance(m, BaseMessage) and not isinstance(m, RemoveMessage):
                                print_message(m, CHANNELS[key])
                elif node not in ("intake",) and value not in (None, [], {}):
                    print(f"  {key} = {_summarise_value(value)}")

    values = graph.get_state(config).values
    rep = values.get("final_report")
    print("\n================ VERDICT ================")
    if rep:
        print(f"verdict:   {rep.verdict.value}")
        print(f"rationale: {rep.rationale}")
        for m in rep.required_mitigations:
            print(f"  - {m}")
    if values.get("rug_pull_detected"):
        print("RUG PULL:", values.get("rug_pull_changes"))
    if values.get("patch_changes"):
        print("patch:", values.get("patch_changes"))
    if values.get("errors"):
        print("errors:", values.get("errors"))
    return values


def show_history(graph, thread_id: str) -> None:
    config = {"configurable": {"thread_id": thread_id}}
    for snap in graph.get_state_history(config):
        v = snap.values
        print(f"step={snap.metadata.get('step')} next={snap.next} run_count={v.get('run_count')} "
              f"audits_stored={len(v.get('audit_history', []))} checkpoint=...{snap.config['configurable']['checkpoint_id'][-8:]}")


def repl() -> None:
    graph, thread = build_graph(), "default"
    print("AgentGuard REPL. Commands: audit <path> | thread <id> | state | history | quit")
    while True:
        try:
            line = input(f"agentguard[{thread}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        cmd, _, arg = line.partition(" ")
        try:
            if cmd == "audit":
                run_audit(graph, load_package(arg), thread)
            elif cmd == "thread":
                thread = arg or "default"
            elif cmd == "state":
                v = graph.get_state({"configurable": {"thread_id": thread}}).values
                print({k: _summarise_value(val) for k, val in v.items() if k not in CHANNELS})
            elif cmd == "history":
                show_history(graph, thread)
            elif cmd in ("quit", "exit"):
                break
            elif cmd:
                print("unknown command")
        except Exception as e:  # keep the REPL alive on bad input
            print(f"error: {type(e).__name__}: {e}")


def main() -> None:
    p = argparse.ArgumentParser(prog="agentguard")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("paths", nargs="+")
    a.add_argument("--thread", default="cli")
    a.add_argument("--quiet", action="store_true", help="hide message trace")
    sub.add_parser("repl")
    sub.add_parser("graph")
    args = p.parse_args()

    if args.cmd == "graph":
        from agentguard.graph import draw_mermaid

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
