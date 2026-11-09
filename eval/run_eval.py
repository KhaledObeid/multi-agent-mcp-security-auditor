"""Quantitative evaluation. OWNER: Member C.

Runs every sample in data/samples against its expected verdict in labels.json,
each on a fresh thread, and prints accuracy plus a confusion matrix.

    python eval/run_eval.py                      # full LLM system
    AGENTGUARD_OFFLINE=1 python eval/run_eval.py # rule-based baseline

Comparing the two runs is the core of the Results section.

TODO (Member C):
  - Grow the labelled set to ~20 packages (Member B writes new samples).
  - Add metrics: block recall (did we catch every malicious package?),
    false-block rate on benign ones, red-team obedience rate, avg LLM calls/latency.
  - Save results to eval/results/*.csv for the report tables.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentguard.config import settings  # noqa: E402
from agentguard.graph import build_graph  # noqa: E402
from agentguard.main import load_package  # noqa: E402

SAMPLES = ROOT / "data" / "samples"


def main() -> None:
    labels = json.loads((SAMPLES / "labels.json").read_text())
    graph = build_graph()
    rows, confusion = [], Counter()
    for name, expected in labels.items():
        pkg = load_package(str(SAMPLES / f"{name}.json"))
        t0 = time.time()
        out = graph.invoke({"package": pkg}, {"configurable": {"thread_id": f"eval-{name}"}})
        got = out["final_report"].verdict.value
        red = bool(out.get("red_team_results"))
        rows.append((name, expected, got, red, round(time.time() - t0, 1)))
        confusion[(expected, got)] += 1

    mode = "OFFLINE baseline" if settings.offline else f"LLM ({settings.llm_model})"
    print(f"\nMode: {mode}")
    print(f"{'sample':24} {'expected':26} {'got':26} red_team  secs")
    for r in rows:
        mark = "" if r[1] == r[2] else "  <-- wrong"
        print(f"{r[0]:24} {r[1]:26} {r[2]:26} {str(r[3]):8} {r[4]}{mark}")
    acc = sum(1 for r in rows if r[1] == r[2]) / len(rows)
    print(f"\naccuracy = {acc:.2f} on {len(rows)} samples")
    print("confusion (expected -> got):", dict(confusion))


if __name__ == "__main__":
    main()
