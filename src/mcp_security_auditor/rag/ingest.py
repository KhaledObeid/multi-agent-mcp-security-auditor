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
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from mcp_security_auditor.config import settings
from mcp_security_auditor.llm import get_embeddings

OWASP_ID = re.compile(r"\b(ASI\d{2}|LLM\d{2})\b")


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
    Chroma.from_documents(
        chunks,
        embedding=get_embeddings(),
        collection_name=settings.chroma_collection,
        persist_directory=str(settings.chroma_dir),
    )
    return len(chunks)


if __name__ == "__main__":
    n = build()
    print(f"Indexed {n} chunks into {settings.chroma_dir}")
