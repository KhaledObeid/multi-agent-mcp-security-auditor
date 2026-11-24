"""Retrieval quality of the security knowledge base. OWNER: Member C.

Grades search_kb-style retrieval on hand-labelled analyst queries: a returned
chunk is a hit when its owasp_ids (the chapter tags written by rag/ingest.py)
contain one of the query's expected OWASP ids.

    python eval/retrieval_eval.py          # needs the built .chroma store and a Gemini key

Cost: one embedding request per query (the query vector is reused for every
method), i.e. len(QUERIES) requests in total.

Metrics per method, over all queries:
  hit@1   first chunk is from a correct chapter
  hit@k   at least one of the k chunks is from a correct chapter
  P@k     share of all returned chunks that are from a correct chapter
  MRR     mean of 1/rank of the first correct chunk (0 when none)
  dup     mean number of the k slots repeating an already returned citation
          (same PDF page and chapter, or same section of a notes file)

Limitation: chunks without a chapter (e.g. the MCP best-practices guide) can be
relevant but always count as misses, so the scores are lower bounds.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
K = 4

# (query, expected OWASP ids). Queries 1-5 are the Week 1 manual test (member_c_notes.md section 5).
QUERIES: list[tuple[str, set[str]]] = [
    ("tool poisoning: hidden instructions in a tool description", {"ASI01", "LLM01"}),
    ("tool definition changed after the user approved it (rug pull)", {"ASI04"}),
    ("tool can run shell commands or execute arbitrary code", {"ASI05"}),
    ("text formatter requests wildcard file system access it does not need", {"ASI03", "LLM06"}),
    ("invisible Unicode characters hide injected instructions from human reviewers", {"LLM01", "ASI01"}),
    ("tool reads ~/.ssh/id_rsa and sends its contents in a hidden parameter", {"ASI02", "LLM02"}),
    ("tool sends user data to an external URL written in its description", {"ASI02", "LLM02"}),
    ("dependency pinned to a version with known CVEs", {"ASI04", "LLM03"}),
    ("attacker text saved in the agent's long-term memory affects later sessions", {"ASI06"}),
    ("tool can delete or modify files without asking the user", {"LLM06", "ASI02"}),
    ("one MCP server's tool description changes how another server's tools are used", {"ASI01", "ASI02"}),
    ("agent output passed straight to a shell or a browser without validation", {"LLM05", "ASI05"}),
]

# name -> function(store, query_vector) returning the top-K documents
METHODS = {
    "similarity (default)": lambda s, v: s.similarity_search_by_vector(v, k=K),
    "MMR lambda=0.7": lambda s, v: s.max_marginal_relevance_search_by_vector(v, k=K, fetch_k=20, lambda_mult=0.7),
    "MMR lambda=0.5": lambda s, v: s.max_marginal_relevance_search_by_vector(v, k=K, fetch_k=20, lambda_mult=0.5),
}


def _ids(doc) -> set[str]:
    return set(filter(None, doc.metadata.get("owasp_ids", "").split(",")))


def _cite(doc) -> str:
    from mcp_security_auditor.tools.rag import cite

    return cite(doc.metadata)


def grade(docs, expected: set[str]) -> dict:
    """Score one ranked result list against the expected ids."""
    hits = [bool(_ids(d) & expected) for d in docs]
    first = next((i for i, h in enumerate(hits, 1) if h), 0)
    cites = [_cite(d) for d in docs]
    return {"hit1": hits[:1] == [True], "hitk": any(hits), "correct": sum(hits), "rr": 1 / first if first else 0.0,
            "dup": len(cites) - len(set(cites)), "results": cites, "hits": hits}


def evaluate(store, vectors: list[list[float]], queries=QUERIES, methods=METHODS) -> dict:
    """{method: {"per_query": [...], "summary": {...}}} for precomputed query vectors."""
    out = {}
    for name, search in methods.items():
        rows = [dict(grade(search(store, v), exp), query=q, expected=sorted(exp))
                for (q, exp), v in zip(queries, vectors)]
        n = len(rows)
        out[name] = {"per_query": rows, "summary": {
            "hit@1": sum(r["hit1"] for r in rows) / n, f"hit@{K}": sum(r["hitk"] for r in rows) / n,
            f"P@{K}": sum(r["correct"] for r in rows) / (n * K),
            "MRR": sum(r["rr"] for r in rows) / n, "dup": sum(r["dup"] for r in rows) / n}}
    return out


def table(results: dict, n: int) -> str:
    lines = [f"| Method | hit@1 | hit@{K} | correct chunks (P@{K}) | MRR | duplicates per query |",
             "|---|---|---|---|---|---|"]
    for name, r in results.items():
        s = r["summary"]
        lines.append(f"| {name} | {round(s['hit@1'] * n)}/{n} | {round(s[f'hit@{K}'] * n)}/{n} "
                     f"| {round(s[f'P@{K}'] * n * K)}/{n * K} ({s[f'P@{K}']:.2f}) | {s['MRR']:.2f} | {s['dup']:.2f} |")
    return "\n".join(lines)


def main() -> None:
    from mcp_security_auditor.tools.rag import _store

    store = _store()
    # embed_query (not embed_documents): Gemini embeds queries in RETRIEVAL_QUERY mode, as search_kb does
    vectors = [store.embeddings.embed_query(q) for q, _ in QUERIES]
    results = evaluate(store, vectors)
    print(table(results, len(QUERIES)))
    print("\nPer query (+ = chunk from a correct chapter, - = not):")
    for i, (q, _) in enumerate(QUERIES):
        print(f"\n{i + 1}. {q}")
        for name, r in results.items():
            row = r["per_query"][i]
            print(f"   {name:24s} " + " | ".join(("+ " if h else "- ") + c for h, c in zip(row["hits"], row["results"])))

    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"retrieval_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved {path}")


if __name__ == "__main__":
    main()
