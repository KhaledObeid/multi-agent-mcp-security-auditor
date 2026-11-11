"""Build the vector store from data/corpus. OWNER: Member C.

Run once (and again whenever the corpus changes):
    python -m mcp_security_auditor.rag.ingest

Reads .md, .txt and .pdf files, splits them into chunks, embeds them with the
Gemini embedding model and persists them to Chroma in .chroma/.

TODO (Member C):
  - Download the primary sources listed in data/corpus/SOURCES.md.
  - Tag each chunk with an owasp_id in metadata (e.g. "ASI01") so the analyst
    can cite it, and so you can filter retrieval by category.
  - Experiment with chunk_size / overlap and report the effect (nice for
    the Results section of the report).
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from mcp_security_auditor.config import settings
from mcp_security_auditor.llm import get_embeddings

OWASP_ID = re.compile(r"\b(ASI\d{2}|LLM\d{2})\b")

EMBED_BATCH = 90     # Gemini free tier allows 100 embedding requests per minute (1 per chunk)
EMBED_PAUSE_S = 62   # so send at most 90, then wait until a full minute has passed


def load_corpus(corpus_dir: Path) -> list[Document]:
    docs: list[Document] = []
    for path in sorted(corpus_dir.rglob("*")):
        if path.suffix.lower() in (".md", ".txt"):
            if path.name.upper() in ("README.MD", "SOURCES.MD"):
                continue
            docs.append(Document(page_content=path.read_text(encoding="utf-8"), metadata={"source": path.name}))
        elif path.suffix.lower() == ".pdf":
            from pypdf import PdfReader

            reader = PdfReader(str(path))
            for i, page in enumerate(reader.pages):
                docs.append(Document(page_content=page.extract_text() or "", metadata={"source": path.name, "page": i + 1}))
    return docs


def split(docs: list[Document], chunk_size: int = 900, overlap: int = 150) -> list[Document]:
    splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=overlap)
    chunks = splitter.split_documents(docs)
    for c in chunks:
        ids = sorted(set(OWASP_ID.findall(c.page_content)))
        c.metadata["owasp_ids"] = ",".join(ids)  # Chroma metadata must be scalar
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
