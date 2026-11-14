"""Tool: vectorized RAG over the security corpus (MANDATORY tool). OWNER: Member C.

Retrieval: MMR by default (relevant but mutually different chunks, so two
neighbouring chunks of one page do not fill two of the k slots), with an
optional OWASP category filter on the per-id flags written by rag/ingest.py.
Both cost one embedding request per query, like plain similarity search.

TODO (Member C):
  - Measure retrieval quality: for ~10 hand-written queries, is the right
    category in the top-k? Put the hit rate in the report.
"""
from __future__ import annotations

import re
from functools import lru_cache

from mcp_security_auditor.config import settings
from mcp_security_auditor.llm import get_embeddings


@lru_cache(maxsize=1)
def _store():
    from langchain_chroma import Chroma

    if not settings.chroma_dir.exists():
        raise RuntimeError("Vector store not built. Run: python -m mcp_security_auditor.rag.ingest")
    return Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(),
        persist_directory=str(settings.chroma_dir),
    )


def cite(meta: dict) -> str:
    """Citation for one chunk, e.g. 'OWASP-Agentic-Top10-2026.pdf p.24 (ASI05)'."""
    text = meta.get("source", "?")
    if meta.get("page"):
        text += f" p.{meta['page']}"
    if meta.get("section"):
        text += f" ({meta['section']})"
    return text


OWASP_CATEGORY = re.compile(r"(ASI|LLM)\d{2}")


def search_kb(query: str, k: int = 4, category: str | None = None, mmr: bool = True,
              fetch_k: int = 20, lambda_mult: float = 0.5) -> list[dict]:
    """Return [{source, page, section, owasp_ids, cite, text}] for the top-k chunks.

    category: an OWASP id such as "ASI05" restricts the search to chunks tagged with it;
              anything else (or a category with no chunks) falls back to the whole corpus.
    mmr:      Maximal Marginal Relevance over the fetch_k most similar chunks; lambda_mult
              trades relevance (1.0) against diversity (0.0).
    """
    store = _store()
    cat = (category or "").strip().upper()
    filt = {cat: True} if OWASP_CATEGORY.fullmatch(cat) else None

    def run(f):
        if mmr:
            return store.max_marginal_relevance_search(query, k=k, fetch_k=fetch_k, lambda_mult=lambda_mult, filter=f)
        return store.similarity_search(query, k=k, filter=f)

    docs = run(filt) if filt else []
    if not docs:
        docs = run(None)
    return [
        {"source": d.metadata.get("source", "?"), "page": d.metadata.get("page"),
         "section": d.metadata.get("section", ""), "owasp_ids": d.metadata.get("owasp_ids", ""),
         "cite": cite(d.metadata), "text": d.page_content}
        for d in docs
    ]
