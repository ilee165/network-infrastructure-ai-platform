"""Real-embedder RAG retrieval eval (manual gate).

Validates that the ``knowledge/`` RAG pipeline retrieves the RELEVANT chunk of a
platform-generated document — with its citation — for a held-out, paraphrased
query, using a REAL local embedding model (``nomic-embed-text`` via Ollama), not
the deterministic ``FakeEmbedder`` the in-CI suite uses.

Which layer this proves
-----------------------
The deterministic layer (``test_m4_exit_criteria.py``
``TestCriterion5RagReturnsRelevantChunkWithCitation``) proves the retrieval
*mechanism*: under a fixed embedder, the expected chunk is returned with its
``(document_id, title, kind)`` citation. That mechanism test embeds the query as
the VERBATIM chunk text, so it cannot prove relevance — an identity vector is not
judgment.

THIS eval proves the model-judgment facet of MVP.md §6 criterion 5: a real
embedding model must rank the semantically-relevant chunk first for a query that
is a PARAPHRASE of the chunk (different words, same meaning), never a copy of it.
That is genuine retrieval relevance and only a real embedder can demonstrate it.

Held-out discipline
-------------------
Every reference query below is a paraphrase whose salient terms differ from the
target chunk's wording (e.g. the chunk says "peers with 10.0.0.2 in AS 65002";
the query asks "which autonomous system does the edge router BGP-peer with?").
If a query were the chunk text verbatim, the embedder could "pass" by identity
rather than by relevance — measuring nothing. The expected chunk is asserted by a
stable substring of the target chunk, plus the document citation triple.

Non-deterministic + needs a running Ollama with the embedding model pulled, so —
like provider parity and the routing eval — it is opt-in and skipped in CI:

    ollama pull nomic-embed-text
    export NETOPS_RUN_RAG_EVAL=1
    pytest -m rag backend/tests/agents/eval/test_rag_retrieval_eval.py -q
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.knowledge.embedding import get_default_embedder
from app.models import Base, Document, DocumentFormat, DocumentKind
from app.models.config_mgmt import Embedding  # noqa: F401 - registers the table

_FLAG = "NETOPS_RUN_RAG_EVAL"

pytestmark = pytest.mark.rag

if not os.environ.get(_FLAG):
    pytest.skip(
        f"RAG retrieval eval is a manual gate; set {_FLAG}=1 (needs a local Ollama with "
        "nomic-embed-text pulled) to run it.",
        allow_module_level=True,
    )

# The generated runbook under test. Three distinct, well-separated sections so a
# relevant query has exactly one right home; the BGP and NTP facts share the
# device name but differ sharply in meaning.
_RUNBOOK_CONTENT = (
    "# Overview\n"
    "edge-1 is a Cisco IOS edge router at the datacenter perimeter.\n\n"
    "## BGP\n"
    "edge-1 peers with 10.0.0.2 in AS 65002 over its WAN uplink.\n\n"
    "## NTP\n"
    "edge-1 synchronizes its clock to the NTP server at 10.0.0.53.\n\n"
    "## Interfaces\n"
    "GigabitEthernet0/0 is the WAN uplink; GigabitEthernet0/1 faces the core.\n"
)

# (held-out paraphrased query, substring that must appear in the top chunk).
# None of the query wordings copy the target chunk — they paraphrase it, so a
# correct top hit reflects relevance, not lexical identity.
_REFERENCE_QUERIES: list[tuple[str, str]] = [
    (
        "Which autonomous system does the edge router establish a BGP session with?",
        "AS 65002",
    ),
    (
        "Where does this device get its time synchronization from?",
        "10.0.0.53",
    ),
    (
        "Which physical port connects edge-1 to the wide-area network?",
        "WAN uplink",
    ),
]


@pytest.fixture()
async def session() -> AsyncIterator[AsyncSession]:
    """In-memory SQLite session with the model schema + FK enforcement.

    The embedder is real (Ollama), but the vector store is the SQLite
    ``with_variant`` fallback — retrieval relevance is a property of the
    embedding model and the Python cosine ranking, not of the pgvector index.
    """
    engine: AsyncEngine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        yield db
    await engine.dispose()


@pytest.fixture()
async def embedded_runbook(session: AsyncSession) -> Document:
    """Persist + embed the runbook with the REAL local embedder (Ollama)."""
    from app.knowledge.embedding import embed_document

    runbook = Document(
        kind=DocumentKind.RUNBOOK,
        title="edge-1 runbook",
        format=DocumentFormat.MD,
        content=_RUNBOOK_CONTENT,
    )
    session.add(runbook)
    await session.flush()
    await embed_document(session, runbook, embedder=get_default_embedder())
    await session.commit()
    return runbook


@pytest.mark.parametrize(("query", "expected_substring"), _REFERENCE_QUERIES)
async def test_paraphrased_query_retrieves_relevant_chunk_with_citation(
    session: AsyncSession,
    embedded_runbook: Document,
    query: str,
    expected_substring: str,
) -> None:
    from app.knowledge.embedding import retrieve

    results = await retrieve(session, query, top_k=3, embedder=get_default_embedder())

    assert results, f"retrieval returned nothing for {query!r}"
    top = results[0]
    # Relevance: the semantically-correct chunk ranks first for a paraphrase.
    assert expected_substring in top.chunk_text, (
        f"{query!r} retrieved {top.chunk_text!r}; expected a chunk containing "
        f"{expected_substring!r}"
    )
    # Citation triple (ADR-0019 §6) accompanies the chunk.
    assert top.citation.document_id == embedded_runbook.id
    assert top.citation.title == "edge-1 runbook"
    assert top.citation.kind is DocumentKind.RUNBOOK
