"""LLM and embedding factories. OWNER: Member A.

Everyone gets their model from here so the provider can be swapped in one place
(e.g. to OpenAI) without touching agent code.
"""
from __future__ import annotations

from functools import lru_cache

from agentguard.config import settings


@lru_cache(maxsize=1)
def get_llm():
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=settings.llm_model,
        temperature=settings.temperature,
        max_retries=3,  # free tier rate limits: retry instead of crashing
    )


@lru_cache(maxsize=1)
def get_embeddings():
    from langchain_google_genai import GoogleGenerativeAIEmbeddings

    return GoogleGenerativeAIEmbeddings(model=settings.embedding_model)
