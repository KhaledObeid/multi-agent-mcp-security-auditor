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

TODO (Member C):
  - Grow the labelled set to ~20 packages (Member B writes new samples).
  - Add metrics: block recall (did we catch every malicious package?),
    false-block rate on benign ones, red-team obedience rate, avg LLM calls/latency.
  - Run rug-pull pairs (v1 then v2) on one shared thread so rug-pull detection is evaluated.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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


def run_one(graph, name: str) -> dict:
    pkg = load_package(str(SAMPLES / f"{name}.json"))
    t0 = time.time()
    try:
        out = graph.invoke({"package": pkg}, {"configurable": {"thread_id": f"eval-{name}"}})
        row = {"verdict": out["final_report"].verdict.value, "red_team": bool(out.get("red_team_results")),
               **analyst_check(out)}
    except Exception as e:  # one failing sample must not stop (and waste) the whole run
        row = {"verdict": "ERROR", "red_team": False, "crash": f"{type(e).__name__}: {str(e)[:300]}"}
    row["secs"] = round(time.time() - t0, 1)
    return row


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

    mode = "OFFLINE baseline" if settings.offline else f"LLM ({settings.llm_model})"
    print(f"\nMode: {mode}")
    print(f"{'sample':22} {'expected':25} {'got':25} {'SOM':8} {'by LLM':6} {'cited':6} {'invented':8} {'net':3} secs")
    for name, r in rows.items():
        mark = "" if r["expected"] == r["verdict"] else "  <-- wrong"
        cited = f"{r['cited']}/{r['findings']}" if "findings" in r else "-"
        print(f"{name:22} {r['expected']:25} {r['verdict']:25} {r.get('som', '-'):8} {r.get('by_llm', '-')!s:6} {cited:6} "
              f"{len(r.get('invented', [])):<8} {len(r.get('net', [])):<3} {r['secs']}{mark}")
    acc = sum(r["expected"] == r["verdict"] for r in rows.values()) / len(rows)
    print(f"\naccuracy = {acc:.2f} on {len(rows)} samples")
    print("confusion (expected -> got):", dict(confusion))
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
    path.write_text(json.dumps({"mode": mode, "rows": rows}, indent=2, ensure_ascii=False), encoding="utf-8")

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
