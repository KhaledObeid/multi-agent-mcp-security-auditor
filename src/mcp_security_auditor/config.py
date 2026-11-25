"""Central settings, read from environment variables (.env). OWNER: Member A."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parents[2]


def _flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes")


def _optional_float(name: str) -> float | None:
    raw = os.getenv(name, "").strip()
    return float(raw) if raw else None


@dataclass(frozen=True)
class Settings:
    # LLM provider (course uses Gemini free tier). As of Nov 2026, gemini-3.8-flash
    # is the strongest free-tier model with no announced shutdown date.
    llm_model: str = os.getenv("MCP_SECURITY_AUDITOR_LLM_MODEL", "gemini-3.8-flash")
    embedding_model: str = os.getenv("MCP_SECURITY_AUDITOR_EMBED_MODEL", "models/gemini-embedding-001")
    # Unset by default, so the model uses its own sampling settings. Google advises
    # against custom temperature on Gemini 3+ (it can cause looping and weaker
    # reasoning). Only set this when using an older model.
    temperature: float | None = _optional_float("MCP_SECURITY_AUDITOR_TEMPERATURE")
    # Per-request limit, so an overloaded model fails fast (and agent_turn falls
    # back to rule-based steps) instead of hanging the audit for minutes.
    llm_timeout_s: float = float(os.getenv("MCP_SECURITY_AUDITOR_LLM_TIMEOUT_S", "30"))
    # Retries per LLM call (with growing waits in between). Each retry on a busy
    # model adds tens of seconds; lower it for the live demo.
    llm_max_retries: int = int(os.getenv("MCP_SECURITY_AUDITOR_LLM_MAX_RETRIES", "3"))

    # OFFLINE=1 runs every agent with scripted, rule-based behaviour and no LLM
    # calls. Use it to develop the graph before the agents exist, to run tests
    # without burning quota, and as the non-LLM baseline in the evaluation.
    offline: bool = _flag("MCP_SECURITY_AUDITOR_OFFLINE")

    # Paths
    corpus_dir: Path = ROOT / "data" / "corpus"
    chroma_dir: Path = ROOT / os.getenv("MCP_SECURITY_AUDITOR_CHROMA_DIR", ".chroma")
    chroma_collection: str = "mcp_security_auditor_kb"

    # Safety limits
    max_tool_rounds: int = int(os.getenv("MCP_SECURITY_AUDITOR_MAX_TOOL_ROUNDS", "3"))
    osv_timeout_s: float = 10.0


settings = Settings()
