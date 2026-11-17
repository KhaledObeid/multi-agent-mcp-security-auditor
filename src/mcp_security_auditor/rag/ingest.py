"""Build the vector store from data/corpus. OWNER: Member C.

Run once (and again whenever the corpus changes):
    python -m mcp_security_auditor.rag.ingest

Reads .md, .txt and .pdf files, splits them into chunks, embeds them with the
Gemini embedding model and persists them to Chroma in .chroma/.

Chunk metadata (used by tools/rag.py and cited by the Threat Analyst):
  source     file name;  page  PDF page number (PDFs only)
  section    the OWASP category whose chapter the chunk belongs to ("" if none)
  owasp_ids  comma-joined ids: the section, or for text outside any chapter
             (appendices, tables) the ids it mentions
  ASI05 ...  one True flag per id in owasp_ids, so Chroma can filter on a
             single category: filter={"ASI05": True}

Section rule (PDF): a page that holds exactly one heading of its document's own
family ("ASI05: ..." in the Agentic list, "LLM06:2025 ..." in the LLM list)
opens that chapter, and the following pages inherit it. A page with several
headings (contents, summary tables) or an "Appendix" heading closes it.
Markdown: each "## " block is a section if its heading starts with an id.

TODO (Member C):
  - Experiment with chunk_size / overlap and report the effect (nice for
    the Results section of the report).
"""
from __future__ import annotations

import re
import shutil
import time
from collections import Counter
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from mcp_security_auditor.config import settings
from mcp_security_auditor.llm import get_embeddings

OWASP_ID = re.compile(r"\b(ASI\d{2}|LLM\d{2})\b")
PDF_HEADING = re.compile(r"^\s*(ASI\d{2}|LLM\d{2})(?::2025)?\s*[:\-–]\s*\S", re.M)  # "ASI05: ..." / "LLM06:2025 ..."
APPENDIX = re.compile(r"^\s*Appendix\b", re.M)
MD_BLOCK = re.compile(r"^(?=## )", re.M)          # split before each level-2 heading
ID_AT_START = re.compile(r"##\s+(ASI\d{2}|LLM\d{2})\b")
SKIP_TEXT = {"README.MD", "SOURCES.MD"}

EMBED_BATCH = 90     # Gemini free tier allows 100 embedding requests per minute (1 per chunk)
EMBED_PAUSE_S = 62   # so send at most 90, then wait until a full minute has passed


def _load_pdf(path: Path) -> list[Document]:
    from pypdf import PdfReader

    texts = [p.extract_text() or "" for p in PdfReader(str(path)).pages]
    heads = [PDF_HEADING.findall(t) for t in texts]
    family = Counter(h[:3] for hs in heads for h in hs).most_common(1)  # "ASI" or "LLM"
    family = family[0][0] if family else None
    docs, section = [], ""
    for i, (text, hs) in enumerate(zip(texts, heads), start=1):
        own = [h for h in hs if h.startswith(family)] if family else []
        if len(own) == 1:
            section = own[0]              # chapter title page
        elif len(own) > 1 or APPENDIX.search(text):
            section = ""                  # contents, summary table or appendix
        docs.append(Document(page_content=text, metadata={"source": path.name, "page": i, "section": section}))
    return docs


def _load_text(path: Path) -> list[Document]:
    docs = []
    for block in MD_BLOCK.split(path.read_text(encoding="utf-8")):
        if block.strip():
            m = ID_AT_START.match(block)
            docs.append(Document(page_content=block, metadata={"source": path.name, "section": m.group(1) if m else ""}))
    return docs


def load_corpus(corpus_dir: Path) -> list[Document]:
    docs: list[Document] = []
    for path in sorted(corpus_dir.rglob("*")):
        suffix = path.suffix.lower()
        if suffix in (".md", ".txt") and path.name.upper() not in SKIP_TEXT:
            docs += _load_text(path)
        elif suffix == ".pdf":
            docs += _load_pdf(path)
    return docs


def split(docs: list[Document], chunk_size: int = 900, overlap: int = 150) -> list[Document]:
    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=overlap)
    chunks = splitter.split_documents(docs)
    for c in chunks:
        section = c.metadata.get("section", "")
        ids = [section] if section else sorted(set(OWASP_ID.findall(c.page_content)))
        c.metadata["owasp_ids"] = ",".join(ids)  # Chroma metadata must be scalar
        c.metadata.update(dict.fromkeys(ids, True))  # one filterable flag per id
    return chunks


def build(reset: bool = True) -> int:
    from langchain_chroma import Chroma

    if reset and settings.chroma_dir.exists():
        shutil.rmtree(settings.chroma_dir)
    chunks = split(load_corpus(settings.corpus_dir))
    if not chunks:
        raise SystemExit(f"No documents found in {settings.corpus_dir}")
    store = Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(),
        persist_directory=str(settings.chroma_dir),
    )
    for start in range(0, len(chunks), EMBED_BATCH):
        t0 = time.monotonic()
        store.add_documents(chunks[start:start + EMBED_BATCH])
        done = min(start + EMBED_BATCH, len(chunks))
        print(f"  embedded {done}/{len(chunks)} chunks")
        if done < len(chunks):  # wait out the rest of the minute before the next group
            time.sleep(max(0.0, EMBED_PAUSE_S - (time.monotonic() - t0)))
    return len(chunks)


if __name__ == "__main__":
    n = build()
    print(f"Indexed {n} chunks into {settings.chroma_dir}")
