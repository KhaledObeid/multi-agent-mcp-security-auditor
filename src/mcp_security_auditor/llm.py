"""LLM and embedding factories. OWNER: Member A.

Everyone gets their model from here so the provider can be swapped in one place
(e.g. to OpenAI) without touching agent code.
"""
from __future__ import annotations

from functools import lru_cache

from mcp_security_auditor.config import settings


@lru_cache(maxsize=1)
def get_llm():
    from langchain_google_genai import ChatGoogleGenerativeAI

    # Only pass temperature when it is set explicitly (see config.py). If it is
    # omitted, the model's own default applies, as Google recommends for Gemini 3+.
    extra = {} if settings.temperature is None else {"temperature": settings.temperature}
    return ChatGoogleGenerativeAI(
        model=settings.llm_model,
        max_retries=3,  # free tier rate limits: retry instead of crashing
        **extra,
    )


@lru_cache(maxsize=1)
def get_embeddings():
    from langchain_google_genai import GoogleGenerativeAIEmbeddings

    return GoogleGenerativeAIEmbeddings(model=settings.embedding_model)
