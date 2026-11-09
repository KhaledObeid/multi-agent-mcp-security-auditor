"""End-to-end graph tests in OFFLINE mode (no API key, no quota). OWNER: Member A.

Must stay green on main at all times: if your PR breaks this, the graph is broken for everyone.
"""
import json
import os
from pathlib import Path

os.environ["MCP_SECURITY_AUDITOR_OFFLINE"] = "1"

from mcp_security_auditor.graph import build_graph  # noqa: E402
from mcp_security_auditor.schemas import ToolPackage  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


def load(name):
    return ToolPackage.model_validate(json.loads((SAMPLES / f"{name}.json").read_text()))


def run(graph, name, thread):
    return graph.invoke({"package": load(name)}, {"configurable": {"thread_id": thread}})


def test_benign_skips_red_team():
    out = run(build_graph(), "benign_weather", "t1")
    assert out["final_report"].verdict.value == "install"
    assert out["red_team_results"] == []


def test_poisoned_goes_through_red_team_and_blocks():
    out = run(build_graph(), "poisoned_math", "t2")
    assert out["needs_red_team"] is True
    assert out["red_team_results"]
    assert out["final_report"].verdict.value == "block"


def test_rug_pull_detected_across_runs_on_same_thread():
    g = build_graph()
    run(g, "rugpull_calc_v1", "same")
    out = run(g, "rugpull_calc_v2", "same")
    assert out["rug_pull_detected"] is True
    assert len(out["audit_history"]) == 2


def test_fresh_thread_has_no_memory():
    g = build_graph()
    run(g, "rugpull_calc_v1", "a")
    out = run(g, "rugpull_calc_v2", "b")
    assert out["rug_pull_detected"] is False
