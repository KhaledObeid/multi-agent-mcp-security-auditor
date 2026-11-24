"""Quantitative evaluation. OWNER: Member C.

Runs every sample in data/samples against its expected verdict in labels.json,
each on a fresh thread, and prints accuracy plus a confusion matrix.

    python eval/run_eval.py                      # full LLM system
    MCP_SECURITY_AUDITOR_OFFLINE=1 python eval/run_eval.py # rule-based baseline
    python eval/run_eval.py --only poisoned_math # one sample (cheap online trial)

Comparing the two runs is the core of the Results section.

Per sample it also checks the Threat Analyst (week 2 target):
  SOM      "ok" if the AuditFindings structured output validated with findings;
           "retry" if the first answer had no findings but the retry did;
           "EMPTY" if both answers had no findings although the scanner flagged issues
           (an empty list is schema-valid), and "FALLBACK" if the call failed; in both
           cases the rule-based findings are used. "-" offline
  by LLM   findings written by the LLM (the rest come from the rule-based layer)
  cited    findings with at least one valid reference / all findings; a reference is
           valid when it appears in that audit's retrieved_sources (search citations)
           or is a vulnerability id returned by OSV
  invented references that are neither (should be 0)
  net      corrections by the analyst safety net (critical finding added or raised)
A sample that crashes (e.g. quota exhausted) is recorded and the run continues.
Results are saved to eval/results/eval_<mode>_<time>.json.

Summary metrics (also saved under "metrics"):
  block recall        packages labelled block that were blocked (a crash counts as a miss)
  false-block rate    packages labelled install that were blocked
  over-mitigation     packages labelled install that got install_with_mitigations
  red-team rate       audits that reached the Red-Team agent
  obedience rate      trials where the mock agent obeyed / trials that ran (skipped tests excluded)
  LLM calls, tokens   per audit, counted by a callback (0 offline; SDK-internal retries not counted)
  rug-pull detection  each <name>_v1/<name>_v2 pair also runs v1 then v2 on ONE shared thread;
                      detected = rug_pull_detected on v2. The fresh-thread runs above are the
                      control and must never report a rug pull.

TODO (Member C):
  - Grow the labelled set to ~20 packages (Member B writes new samples).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from langchain_core.callbacks import BaseCallbackHandler  # noqa: E402

from mcp_security_auditor.config import settings  # noqa: E402
from mcp_security_auditor.graph import build_graph  # noqa: E402
from mcp_security_auditor.main import load_package  # noqa: E402

SAMPLES = ROOT / "data" / "samples"
RESULTS = ROOT / "eval" / "results"


def analyst_check(out: dict) -> dict:
    """SOM status, reference validity and safety-net corrections for one audit's final state."""
    errors = [str(e) for e in out.get("errors", [])]
    findings = out["findings"].findings if out.get("findings") else []
    valid = set(out.get("retrieved_sources", []))
    valid |= {i for v in out.get("dependency_vulns", []) for i in v.vuln_ids}
    refs = [[r.strip() for r in f.references] for f in findings]
    som_notes = [e for e in errors if e.startswith("analyst SOM")]
    if settings.offline:
        som = "-"
    elif any(e.startswith("analyst SOM failed") for e in som_notes):
        som = "FALLBACK"
    elif any(e.startswith("analyst SOM empty twice") for e in som_notes):
        som = "EMPTY"
    else:
        som = "retry" if som_notes else "ok"
    added = sum(e.startswith("analyst safety net: added") for e in errors)
    return {
        "som": som,
        "findings": len(findings),
        "by_llm": 0 if som in ("-", "FALLBACK", "EMPTY") else len(findings) - added,
        "cited": sum(any(r in valid for r in rs) for rs in refs),
        "invented": sorted({r for rs in refs for r in rs if r not in valid}),
        "som_error": som_notes,
        "net": [e for e in errors if e.startswith("analyst safety net")],
        "other_errors": [e for e in errors if not e.startswith(("analyst safety net", "analyst SOM"))],
        "severities": [f"{f.owasp_category.value}:{f.severity.value}" for f in findings],
        "references": [f.references for f in findings],
        "sources": list(out.get("retrieved_sources", [])),
    }


class LLMCounter(BaseCallbackHandler):
    """Counts chat-model calls and tokens; the graph passes run callbacks down to every node's LLM."""

    def __init__(self) -> None:
        self.calls = self.tokens = 0

    def on_chat_model_start(self, *args, **kwargs) -> None:
        self.calls += 1

    def on_llm_end(self, response, **kwargs) -> None:
        for gens in response.generations:
            for g in gens:
                usage = getattr(getattr(g, "message", None), "usage_metadata", None) or {}
                self.tokens += usage.get("total_tokens", 0)


def obedience(r) -> list[int] | None:
    """[obeyed, trials] for one red-team test; None if it did not run."""
    # shortcut: B's sandbox puts the per-trial count only in notes ("obedience 4/5"); read a numeric field if B adds one
    m = re.search(r"obedience (\d+)/(\d+)", r.notes)
    if m:
        return [int(m[1]), int(m[2])]
    return None if r.mock_agent_obeyed is None else [int(r.mock_agent_obeyed), 1]


def run_one(graph, name: str, thread: str | None = None) -> dict:
    pkg = load_package(str(SAMPLES / f"{name}.json"))
    counter = LLMCounter()
    t0 = time.time()
    try:
        out = graph.invoke({"package": pkg}, {"configurable": {"thread_id": thread or f"eval-{name}"},
                                              "callbacks": [counter]})
        results = out.get("red_team_results", [])
        row = {"verdict": out["final_report"].verdict.value, "red_team": bool(results),
               "obeyed": [obedience(r) for r in results],
               "rug_pull": bool(out.get("rug_pull_detected")), **analyst_check(out)}
    except Exception as e:  # one failing sample must not stop (and waste) the whole run
        row = {"verdict": "ERROR", "red_team": False, "crash": f"{type(e).__name__}: {str(e)[:300]}"}
    row.update(secs=round(time.time() - t0, 1), llm_calls=counter.calls, tokens=counter.tokens)
    return row


def run_pairs(graph, names) -> dict:
    """v1 then v2 on one shared thread, so intake can compare v2 with the approved v1."""
    pairs = {}
    for base in sorted(n[:-3] for n in names if n.endswith("_v1") and f"{n[:-3]}_v2" in names):
        print(f"auditing {base}_v1 -> {base}_v2 on one thread ...", flush=True)
        first = run_one(graph, f"{base}_v1", f"eval-pair-{base}")
        second = run_one(graph, f"{base}_v2", f"eval-pair-{base}")
        pairs[base] = {"detected": second.get("rug_pull", False), "v2_verdict": second["verdict"],
                       "crash": first.get("crash") or second.get("crash"),
                       "secs": first["secs"] + second["secs"],
                       "llm_calls": first["llm_calls"] + second["llm_calls"],
                       "tokens": first["tokens"] + second["tokens"]}
    return pairs


def summarize(rows: dict, pairs: dict) -> dict:
    vals = list(rows.values())

    def rate(expected: str | None, hit) -> float | None:
        sel = [r for r in vals if expected is None or r["expected"] == expected]
        return round(sum(map(hit, sel)) / len(sel), 2) if sel else None

    tests = [o for r in vals for o in r.get("obeyed", []) if o is not None]
    obeyed, trials = sum(o[0] for o in tests), sum(o[1] for o in tests)
    avg = lambda k: round(sum(r[k] for r in vals) / len(vals), 1)  # noqa: E731
    return {
        "samples": len(vals),
        "accuracy": rate(None, lambda r: r["verdict"] == r["expected"]),
        "block_recall": rate("block", lambda r: r["verdict"] == "block"),
        "false_block_rate": rate("install", lambda r: r["verdict"] == "block"),
        "over_mitigation_rate": rate("install", lambda r: r["verdict"] == "install_with_mitigations"),
        "red_team_rate": rate(None, lambda r: r["red_team"]),
        "obedience_rate": round(obeyed / trials, 2) if trials else None,
        "obedience_tests": len(tests),
        "obedience_trials": trials,
        "avg_llm_calls": avg("llm_calls"),
        "avg_tokens": avg("tokens"),
        "avg_secs": avg("secs"),
        "rug_pull_pairs": len(pairs),
        "rug_pull_detected": sum(p["detected"] for p in pairs.values()),
        "control_false_rug_pulls": sum(r.get("rug_pull", False) for r in vals),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", metavar="SAMPLE", help="run only these samples, e.g. --only poisoned_math")
    args = ap.parse_args()
    labels = json.loads((SAMPLES / "labels.json").read_text())
    if args.only:
        unknown = set(args.only) - set(labels)
        if unknown:
            sys.exit(f"unknown sample(s): {', '.join(sorted(unknown))}; choose from {', '.join(labels)}")
        labels = {k: v for k, v in labels.items() if k in args.only}

    graph = build_graph()
    rows, confusion = {}, Counter()
    for name, expected in labels.items():
        print(f"auditing {name} ...", flush=True)
        rows[name] = {"expected": expected, **run_one(graph, name)}
        confusion[(expected, rows[name]["verdict"])] += 1
    pairs = run_pairs(graph, labels)
    metrics = summarize(rows, pairs)

    mode = "OFFLINE baseline" if settings.offline else f"LLM ({settings.llm_model})"
    print(f"\nMode: {mode}")
    print(f"{'sample':22} {'expected':25} {'got':25} {'SOM':8} {'by LLM':6} {'cited':6} {'invented':8} {'net':3} "
          f"{'calls':5} secs")
    for name, r in rows.items():
        mark = "" if r["expected"] == r["verdict"] else "  <-- wrong"
        cited = f"{r['cited']}/{r['findings']}" if "findings" in r else "-"
        print(f"{name:22} {r['expected']:25} {r['verdict']:25} {r.get('som', '-'):8} {r.get('by_llm', '-')!s:6} {cited:6} "
              f"{len(r.get('invented', [])):<8} {len(r.get('net', [])):<3} {r['llm_calls']:<5} {r['secs']}{mark}")
    m = metrics
    print(f"\naccuracy = {m['accuracy']:.2f} on {m['samples']} samples")
    print("confusion (expected -> got):", dict(confusion))
    print(f"block recall = {m['block_recall']}, false-block rate = {m['false_block_rate']}, "
          f"over-mitigation rate = {m['over_mitigation_rate']} (None = no sample with that label)")
    print(f"red team ran on {m['red_team_rate']} of audits; obedience rate = {m['obedience_rate']} "
          f"over {m['obedience_trials']} trials in {m['obedience_tests']} sandbox tests")
    print(f"per audit: {m['avg_llm_calls']} LLM calls, {m['avg_tokens']} tokens, {m['avg_secs']} s")
    print(f"rug pull: detected {m['rug_pull_detected']}/{m['rug_pull_pairs']} pairs on a shared thread, "
          f"{m['control_false_rug_pulls']} false detections on fresh threads (should be 0)")
    for base, p in pairs.items():
        print(f"  {base}: detected={p['detected']}, v2 verdict={p['v2_verdict']}" + (f", crash: {p['crash']}" if p["crash"] else ""))
    done = [r for r in rows.values() if "findings" in r]
    if done and not settings.offline:
        tot = lambda k: sum(r[k] for r in done)  # noqa: E731
        print(f"findings: {tot('findings')} ({tot('by_llm')} by LLM), {tot('cited')} with a valid reference, "
              f"{sum(len(r['invented']) for r in done)} invented references; SOM "
              + ", ".join(f"{s} {sum(r['som'] == s for r in done)}" for s in ("ok", "retry", "EMPTY", "FALLBACK")))

    # save before printing anything else, so a printing problem can never lose a paid-for run
    RESULTS.mkdir(exist_ok=True)
    tag = "offline" if settings.offline else settings.llm_model
    path = RESULTS / f"eval_{tag}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps({"mode": mode, "metrics": metrics, "pairs": pairs, "rows": rows}, indent=2, ensure_ascii=False), encoding="utf-8")

    details = []
    for n, r in rows.items():
        if r.get("crash"):
            details.append((n, "crash", r["crash"]))
        for k in ("invented", "net", "other_errors", "som_error"):
            details += [(n, k, v) for v in r.get(k, [])]
    if details:
        print("\nDetails:")
        for n, k, v in details:
            print(f"  {n} [{k}] {v}")
    print(f"\nSaved {path}")


if __name__ == "__main__":
    main()
