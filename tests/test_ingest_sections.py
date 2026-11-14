"""Offline checks for section tagging in rag/ingest.py (OWNER: Member C).

Reads the PDFs in data/corpus only: no embedding or LLM calls.
"""
from __future__ import annotations

from collections import defaultdict

import pytest

from mcp_security_auditor.config import settings
from mcp_security_auditor.rag.ingest import load_corpus, split

AGENTIC = "OWASP-Agentic-Top10-2026.pdf"
LLM = "OWASP-LLM-Top10-2025.pdf"


@pytest.fixture(scope="module")
def chunks():
    return split(load_corpus(settings.corpus_dir))  # parsed once for all tests


@pytest.fixture(scope="module")
def sections(chunks):
    """(source, page) -> set of sections of that page's chunks."""
    out = defaultdict(set)
    for c in chunks:
        if "page" in c.metadata:
            out[(c.metadata["source"], c.metadata["page"])].add(c.metadata["section"])
    return out


@pytest.mark.parametrize("page, expected", [(10, "ASI01"), (12, "ASI01"), (22, "ASI05"), (23, "ASI05"),
                                            (24, "ASI05"), (37, "ASI10"), (39, "ASI10")])
def test_agentic_pages_inherit_their_chapter(sections, page, expected):
    assert sections[(AGENTIC, page)] == {expected}


@pytest.mark.parametrize("page, expected", [(7, "LLM01"), (10, "LLM01"), (26, "LLM06"), (29, "LLM06"), (42, "LLM10")])
def test_llm_pages_inherit_their_chapter(sections, page, expected):
    assert sections[(LLM, page)] == {expected}


@pytest.mark.parametrize("source, page", [(AGENTIC, 3), (AGENTIC, 9), (AGENTIC, 40), (AGENTIC, 47), (LLM, 3), (LLM, 43)])
def test_contents_summary_and_appendix_pages_have_no_chapter(sections, source, page):
    assert sections[(source, page)] == {""}


def test_cross_references_do_not_add_labels(chunks):
    # p.10 (ASI01) mentions ASI06, ASI10 and LLM01 as related categories
    p10 = [c for c in chunks if c.metadata["source"] == AGENTIC and c.metadata.get("page") == 10]
    assert p10 and all(c.metadata["owasp_ids"] == "ASI01" for c in p10)
    assert not any(c.metadata.get("ASI10") for c in p10)


def test_flags_match_owasp_ids(chunks):
    for c in chunks:
        ids = set(filter(None, c.metadata["owasp_ids"].split(",")))
        flags = {k for k, v in c.metadata.items() if v is True}
        assert flags == ids, (c.metadata["source"], c.metadata.get("page"))


def test_incident_notes_tagged_by_heading(chunks):
    tagged = {c.metadata["section"] for c in chunks if c.metadata["source"] == "mcp_incidents_notes.md"}
    assert {"ASI01", "ASI02", "ASI04"} <= tagged


@pytest.mark.parametrize("meta, expected", [
    ({"source": AGENTIC, "page": 24, "section": "ASI05"}, f"{AGENTIC} p.24 (ASI05)"),
    ({"source": AGENTIC, "page": 45, "section": ""}, f"{AGENTIC} p.45"),
    ({"source": "mcp_incidents_notes.md", "section": "ASI04"}, "mcp_incidents_notes.md (ASI04)"),
    ({}, "?"),
])
def test_citation_format(meta, expected):
    from mcp_security_auditor.tools.rag import cite

    assert cite(meta) == expected


def test_every_chunk_gets_a_page_level_citation(chunks):
    from mcp_security_auditor.tools.rag import cite

    pdf = [c for c in chunks if c.metadata["source"].endswith(".pdf")]
    assert pdf and all(f" p.{c.metadata['page']}" in cite(c.metadata) for c in pdf)


class _FakeStore:
    """Stands in for Chroma: records each call, returns nothing when asked for an empty category."""

    def __init__(self):
        self.calls = []

    def _docs(self, f):
        from langchain_core.documents import Document

        if f == {"ASI99": True}:
            return []
        return [Document(page_content="text", metadata={"source": AGENTIC, "page": 22, "section": "ASI05",
                                                        "owasp_ids": "ASI05"})]

    def max_marginal_relevance_search(self, query, k, fetch_k, lambda_mult, filter):
        self.calls.append(("mmr", filter))
        return self._docs(filter)

    def similarity_search(self, query, k, filter):
        self.calls.append(("similarity", filter))
        return self._docs(filter)


@pytest.fixture
def fake_store(monkeypatch):
    from mcp_security_auditor.tools import rag

    store = _FakeStore()
    monkeypatch.setattr(rag, "_store", lambda: store)
    return store


@pytest.mark.parametrize("kwargs, expected_calls", [
    ({}, [("similarity", None)]),                                        # similarity is the default
    ({"mmr": True}, [("mmr", None)]),
    ({"category": " asi05 "}, [("similarity", {"ASI05": True})]),        # normalised id
    ({"category": "Agent Goal Hijack"}, [("similarity", None)]),         # not an id: no filter
    ({"category": "ASI99"}, [("similarity", {"ASI99": True}), ("similarity", None)]),  # empty chapter: fall back
    ({"category": "ASI05", "mmr": True}, [("mmr", {"ASI05": True})]),
])
def test_search_kb_mmr_and_category_filter(fake_store, kwargs, expected_calls):
    from mcp_security_auditor.tools.rag import search_kb

    hits = search_kb("shell access", **kwargs)
    assert fake_store.calls == expected_calls
    assert hits[0]["cite"] == f"{AGENTIC} p.22 (ASI05)"


def test_retrieval_eval_grading():
    import importlib.util
    from pathlib import Path

    from langchain_core.documents import Document

    path = Path(__file__).resolve().parents[1] / "eval" / "retrieval_eval.py"
    spec = importlib.util.spec_from_file_location("retrieval_eval", path)
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)

    def doc(ids, page=None, section="", source="mcp_incidents_notes.md"):
        return Document(page_content="", metadata={"owasp_ids": ids, "page": page, "section": section, "source": source})

    docs = [doc("ASI02", section="ASI02"), doc("ASI01", section="ASI01"),       # notes: two sections, no page
            doc("ASI05", 22, "ASI05", AGENTIC), doc("ASI05", 22, "ASI05", AGENTIC)]  # same PDF page twice
    g = ev.grade(docs, {"ASI01", "ASI05"})
    assert (g["hit1"], g["hitk"], g["correct"], g["rr"], g["dup"]) == (False, True, 3, 0.5, 1)
