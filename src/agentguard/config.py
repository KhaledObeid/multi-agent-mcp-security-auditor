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


@dataclass(frozen=True)
class Settings:
    # LLM provider (course uses Gemini free tier)
    llm_model: str = os.getenv("AGENTGUARD_LLM_MODEL", "gemini-2.5-flash")
    embedding_model: str = os.getenv("AGENTGUARD_EMBED_MODEL", "models/gemini-embedding-001")
    temperature: float = float(os.getenv("AGENTGUARD_TEMPERATURE", "0"))

    # OFFLINE=1 runs every agent with scripted, rule-based behaviour and no LLM
    # calls. Use it to develop the graph before the agents exist, to run tests
    # without burning quota, and as the non-LLM baseline in the evaluation.
    offline: bool = _flag("AGENTGUARD_OFFLINE")

    # Paths
    corpus_dir: Path = ROOT / "data" / "corpus"
    chroma_dir: Path = ROOT / os.getenv("AGENTGUARD_CHROMA_DIR", ".chroma")
    chroma_collection: str = "agentguard_security_kb"

    # Safety limits
    max_tool_rounds: int = int(os.getenv("AGENTGUARD_MAX_TOOL_ROUNDS", "3"))
    osv_timeout_s: float = 10.0


settings = Settings()
