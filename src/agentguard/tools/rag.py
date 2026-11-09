"""Tool: vectorized RAG over the security corpus (MANDATORY tool). OWNER: Member C.

TODO (Member C):
  - Try MMR retrieval (search_type="mmr") to avoid near-duplicate chunks.
  - Add a metadata filter by OWASP id when the analyst asks about one category.
  - Measure retrieval quality: for ~10 hand-written queries, is the right
    category in the top-k? Put the hit rate in the report.
"""
from __future__ import annotations

from functools import lru_cache

from agentguard.config import settings
from agentguard.llm import get_embeddings


@lru_cache(maxsize=1)
def _store():
    from langchain_chroma import Chroma

    if not settings.chroma_dir.exists():
        raise RuntimeError("Vector store not built. Run: python -m agentguard.rag.ingest")
    return Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(),
        persist_directory=str(settings.chroma_dir),
    )


def search_kb(query: str, k: int = 4) -> list[dict]:
    """Return [{source, owasp_ids, text}] for the top-k chunks."""
    docs = _store().similarity_search(query, k=k)
    return [
        {"source": d.metadata.get("source", "?"), "owasp_ids": d.metadata.get("owasp_ids", ""), "text": d.page_content}
        for d in docs
    ]
