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
