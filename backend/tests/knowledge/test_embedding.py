"""Embedding pipeline + pgvector RAG retrieval (ADR-0019 §5-6).

Deterministic, network-free: a fake embedder maps text → a fixed-width vector so
chunking, supersession (no orphans), and cosine top-k ranking are exact. The
pgvector ``VECTOR`` column + HNSW index are PostgreSQL-only DDL exercised by the
migration integration test; here the ``with_variant`` TEXT fallback stores the
vector as JSON and the cosine ranking is computed in Python.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.knowledge.embedding import (
    Chunk,
    OllamaEmbedder,
    chunk_document,
    embed_document,
    retrieve,
)
from app.models import Base, Document, DocumentFormat, DocumentKind, Embedding
from app.models.config_mgmt import EMBEDDING_DIM


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with FK enforcement and the model schema."""
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


class FakeEmbedder:
    """Deterministic embedder: text → a stable :data:`EMBEDDING_DIM` vector.

    A hash of the text seeds the first few components so distinct chunks get
    distinct vectors and an identical query embeds to an identical vector — which
    makes the cosine top-k assertion exact without any network or model.
    """

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.seen.extend(texts)
        return [self._vector(text) for text in texts]

    @staticmethod
    def _vector(text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        vector = [0.0] * EMBEDDING_DIM
        for i in range(min(len(digest), EMBEDDING_DIM)):
            vector[i] = digest[i] / 255.0
        return vector


async def _make_document(
    session: AsyncSession,
    *,
    kind: DocumentKind,
    fmt: DocumentFormat,
    content: str,
    title: str = "doc",
) -> Document:
    document = Document(kind=kind, title=title, format=fmt, content=content)
    session.add(document)
    await session.flush()
    return document


# --- structure-aware chunking ------------------------------------------------


async def test_chunk_markdown_splits_per_section(session: AsyncSession) -> None:
    content = "# Title\nintro\n\n## Devices\ncore-01\n\n## Routes\n0.0.0.0/0\n"
    document = await _make_document(
        session, kind=DocumentKind.RUNBOOK, fmt=DocumentFormat.MD, content=content
    )
    chunks = chunk_document(document)
    texts = [c.text for c in chunks]
    assert [c.index for c in chunks] == [0, 1, 2]
    assert texts[0].startswith("# Title")
    assert any("## Devices" in t and "core-01" in t for t in texts)
    assert any("## Routes" in t and "0.0.0.0/0" in t for t in texts)


async def test_chunk_csv_carries_header_per_row(session: AsyncSession) -> None:
    content = "hostname,vendor\ncore-01,cisco_ios\nedge-02,eos\n"
    document = await _make_document(
        session, kind=DocumentKind.INVENTORY, fmt=DocumentFormat.CSV, content=content
    )
    chunks = chunk_document(document)
    assert len(chunks) == 2
    assert chunks[0].text == "hostname,vendor\ncore-01,cisco_ios"
    assert chunks[1].text == "hostname,vendor\nedge-02,eos"


async def test_chunk_mermaid_splits_per_statement(session: AsyncSession) -> None:
    """Each statement chunk must independently carry the directive header.

    Previously _split_mermaid emitted the bare directive line as its own orphan
    chunk, leaving statement chunks without context.  Now every chunk must start
    with the header so a retrieved chunk is self-describing (ADR-0019 §6).
    """
    content = "graph TD\n  A --> B\n  B --> C\n"
    document = await _make_document(
        session, kind=DocumentKind.DIAGRAM, fmt=DocumentFormat.MERMAID, content=content
    )
    chunks = chunk_document(document)
    texts = [c.text for c in chunks]

    # Two statement chunks, not three (no bare-directive orphan chunk).
    assert len(chunks) == 2

    # Each individual chunk must contain the directive and its statement.
    assert all("graph TD" in t for t in texts), (
        "Every Mermaid chunk must independently contain the directive header"
    )
    assert any("A --> B" in t for t in texts)
    assert any("B --> C" in t for t in texts)

    # The directive must not appear as a standalone chunk (no orphan).
    assert not any(t.strip() == "graph TD" for t in texts), (
        "Bare directive must not appear as its own chunk"
    )


async def test_chunk_empty_document_yields_no_chunks(session: AsyncSession) -> None:
    document = await _make_document(
        session, kind=DocumentKind.INVENTORY, fmt=DocumentFormat.CSV, content="\n"
    )
    assert chunk_document(document) == []


# --- embed + persist ----------------------------------------------------------


async def test_embed_document_persists_one_row_per_chunk(session: AsyncSession) -> None:
    content = "host,vendor\ncore-01,cisco_ios\nedge-02,eos\n"
    document = await _make_document(
        session, kind=DocumentKind.INVENTORY, fmt=DocumentFormat.CSV, content=content
    )
    embedder = FakeEmbedder()

    rows = await embed_document(session, document, embedder=embedder)

    assert len(rows) == 2
    persisted = (
        (await session.execute(select(Embedding).where(Embedding.document_id == document.id)))
        .scalars()
        .all()
    )
    assert {r.chunk_index for r in persisted} == {0, 1}
    assert all(r.embedding is not None for r in persisted)
    # The fake embedded exactly the structure-aware chunk texts.
    assert "host,vendor\ncore-01,cisco_ios" in embedder.seen


async def test_embed_document_supersedes_prior_chunks_no_orphans(session: AsyncSession) -> None:
    document = await _make_document(
        session,
        kind=DocumentKind.INVENTORY,
        fmt=DocumentFormat.CSV,
        content="host,vendor\ncore-01,cisco_ios\nedge-02,eos\nspine-03,eos\n",
    )
    embedder = FakeEmbedder()
    first = await embed_document(session, document, embedder=embedder)
    assert len(first) == 3

    # Regenerate the artifact with fewer rows; re-embed must replace, not append.
    document.content = "host,vendor\ncore-01,cisco_ios\n"
    second = await embed_document(session, document, embedder=embedder)
    assert len(second) == 1

    remaining = (
        (await session.execute(select(Embedding).where(Embedding.document_id == document.id)))
        .scalars()
        .all()
    )
    assert len(remaining) == 1  # no orphans from the first generation
    assert remaining[0].chunk_index == 0


async def test_embed_empty_document_writes_nothing(session: AsyncSession) -> None:
    document = await _make_document(
        session, kind=DocumentKind.INVENTORY, fmt=DocumentFormat.CSV, content=""
    )
    rows = await embed_document(session, document, embedder=FakeEmbedder())
    assert rows == []
    count = (
        (await session.execute(select(Embedding).where(Embedding.document_id == document.id)))
        .scalars()
        .all()
    )
    assert count == []


# --- retrieval ----------------------------------------------------------------


async def test_retrieve_returns_relevant_chunk_with_citation(session: AsyncSession) -> None:
    runbook = await _make_document(
        session,
        kind=DocumentKind.RUNBOOK,
        fmt=DocumentFormat.MD,
        title="core-01 runbook",
        content="# Summary\noverview text\n\n## BGP\nneighbor 10.0.0.1 is down\n",
    )
    embedder = FakeEmbedder()
    await embed_document(session, runbook, embedder=embedder)

    # The query is verbatim the BGP chunk text → identical vector → top hit.
    chunks = chunk_document(runbook)
    bgp_chunk = next(c for c in chunks if "BGP" in c.text)
    results = await retrieve(session, bgp_chunk.text, top_k=3, embedder=embedder)

    assert results
    top = results[0]
    assert "neighbor 10.0.0.1 is down" in top.chunk_text
    assert top.score == pytest.approx(1.0, abs=1e-6)
    assert top.citation.document_id == runbook.id
    assert top.citation.title == "core-01 runbook"
    assert top.citation.kind is DocumentKind.RUNBOOK


async def test_retrieve_honors_top_k_ordering(session: AsyncSession) -> None:
    document = await _make_document(
        session,
        kind=DocumentKind.INVENTORY,
        fmt=DocumentFormat.CSV,
        content="host\ncore-01\nedge-02\nspine-03\nleaf-04\n",
    )
    embedder = FakeEmbedder()
    await embed_document(session, document, embedder=embedder)

    results = await retrieve(session, "host\ncore-01", top_k=2, embedder=embedder)
    assert len(results) == 2
    assert results[0].score >= results[1].score
    assert results[0].chunk_text == "host\ncore-01"


async def test_retrieve_rejects_non_positive_top_k(session: AsyncSession) -> None:
    with pytest.raises(ValueError, match="top_k must be positive"):
        await retrieve(session, "q", top_k=0, embedder=FakeEmbedder())


async def test_retrieve_empty_store_returns_empty(session: AsyncSession) -> None:
    assert await retrieve(session, "anything", embedder=FakeEmbedder()) == []


# --- A9 redaction at the embedding boundary -----------------------------------


async def test_default_embedder_redacts_before_provider_call(monkeypatch: Any) -> None:
    """The default embedder routes every text through A9 redaction (ADR-0017 §3).

    A secret-bearing string must reach the provider already redacted; we stub the
    Ollama client to capture exactly what it was handed.  The stub exposes
    ``aembed_documents`` (async) because OllamaEmbedder.embed() now calls the
    async method to avoid blocking the event loop (finding 1 fix).
    """
    captured: dict[str, list[str]] = {}

    class _StubOllamaEmbeddings:
        def __init__(self, **_: Any) -> None:
            pass

        async def aembed_documents(self, texts: list[str]) -> list[list[float]]:
            captured["texts"] = texts
            return [[0.0] * EMBEDDING_DIM for _ in texts]

    import langchain_ollama

    monkeypatch.setattr(langchain_ollama, "OllamaEmbeddings", _StubOllamaEmbeddings)

    secret_line = "username admin password Sup3rSecret!"
    await OllamaEmbedder(base_url="http://localhost:11434").embed([secret_line])

    assert "texts" in captured
    sent = captured["texts"][0]
    assert "Sup3rSecret!" not in sent


def test_chunk_dataclass_is_ordered() -> None:
    """A Chunk carries its persisted ordinal and body (sanity on the value type)."""
    chunk = Chunk(index=3, text="body")
    assert chunk.index == 3
    assert chunk.text == "body"
