"""Document embedding pipeline + pgvector RAG retrieval (ADR-0019 §5-6).

This module is the engine/service-layer half of the Documentation Agent's
knowledge stack. It does two things, both read-only with respect to the network:

1. **Embed a document** (:func:`embed_document`). A generated
   :class:`~app.models.Document` (inventory / diagram / runbook) is split into
   **structure-aware chunks** (Markdown headings, CSV rows, Mermaid edges — never
   blind fixed-width windows), each chunk is embedded via the configured D9
   embedding profile, and the chunks are written to the ``embeddings`` table.
   Re-embedding a document **supersedes** its prior chunks in the same
   transaction, so a regenerated artifact never leaves orphan vectors
   (ADR-0019 §5 — the ``(document_id, chunk_index)`` uniqueness is upheld by a
   delete-then-insert, not an upsert race).

2. **Retrieve** (:func:`retrieve`). A query string is embedded and a cosine
   top-k search over ``embeddings`` returns the best chunks, each carried with
   its :class:`Document` citation (id, title, kind) so any agent can cite a
   platform-generated artifact (ADR-0019 §6, "Explain all AI decisions"). This
   helper is **read-only**: it never writes, and it is the service-layer core the
   agent-facing typed tool wrapper (shipped with the Documentation Agent) calls.

Embedding profile / A9 redaction. The default embedder resolves the D9 ``local``
profile (``nomic-embed-text`` via Ollama) and routes every text — chunk *and*
query — through the A9 redaction layer (:func:`app.llm.redaction.redact_prompt`)
*before* the provider call, exactly as :class:`~app.llm.redaction.RedactingChatModel`
does for chat models: the embedding endpoint is an LLM boundary, and config /
inventory chunks can carry secret-bearing fields (ADR-0017 §3). The
:class:`Embedder` protocol is injectable so tests use a deterministic fake with
no network.

Portability. On PostgreSQL the ``embeddings.embedding`` column is a pgvector
``VECTOR`` and an HNSW/cosine index serves the search; on the SQLite unit-test
backend the column is ``TEXT`` (``with_variant``) and pgvector operators are
unavailable, so the cosine ranking is computed in Python over the candidate
rows. The same :func:`retrieve` API serves both — the SQLite path is the
test/dev fallback, the pgvector index is the production path.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable
from uuid import UUID

import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.llm.redaction import redact_prompt
from app.models.config_mgmt import EMBEDDING_DIM, Document, DocumentKind, Embedding

__all__ = [
    "Chunk",
    "Citation",
    "Embedder",
    "OllamaEmbedder",
    "RetrievedChunk",
    "chunk_document",
    "embed_document",
    "get_default_embedder",
    "retrieve",
]

logger = structlog.get_logger(__name__)

#: Default D9 embedding model for the ``local`` profile (ADR-0009 §6 /
#: ADR-0004 §3): ``nomic-embed-text`` produces :data:`EMBEDDING_DIM`-wide
#: vectors, which is why ``embeddings.embedding`` is fixed at that width.
DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"


@runtime_checkable
class Embedder(Protocol):
    """Embeds text into fixed-width vectors (the D9 embedding-profile seam).

    Implementations MUST return one vector of length :data:`EMBEDDING_DIM` per
    input string, in order. The production implementation
    (:class:`OllamaEmbedder`) redacts each text at the LLM boundary before the
    provider call; tests inject a deterministic fake.
    """

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector per text in *texts*, order-preserved."""
        ...


class OllamaEmbedder:
    """Default D9 embedder: ``nomic-embed-text`` via Ollama, redacted (A9).

    Mirrors :func:`app.llm.providers.get_chat_model`: the provider class is
    imported lazily (importing this module touches no network and loads no
    provider package) and every text passes through
    :func:`~app.llm.redaction.redact_prompt` first, so a secret-bearing config
    line can never reach the embedding endpoint un-redacted — the redaction is
    bypass-proof, not a caller responsibility.
    """

    def __init__(
        self, *, model: str = DEFAULT_EMBEDDING_MODEL, base_url: str | None = None
    ) -> None:
        self._model = model
        self._base_url = base_url

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed *texts* via Ollama after A9 redaction of each string.

        Uses ``aembed_documents`` (the async Ollama client method) so the
        HTTP round-trip is never blocking on the event loop — fixing the
        sync-in-async stall that would occur with ``embed_documents``.
        """
        from langchain_ollama import OllamaEmbeddings

        from app.core.config import get_settings

        base_url = self._base_url if self._base_url is not None else get_settings().ollama_base_url
        client = OllamaEmbeddings(model=self._model, base_url=base_url)
        redacted = [redact_prompt(t) for t in texts]
        return await client.aembed_documents(list(redacted))


def get_default_embedder() -> Embedder:
    """Return the process default embedder (the redacted D9 Ollama profile)."""
    return OllamaEmbedder()


@dataclass(frozen=True)
class Chunk:
    """One structure-aware slice of a document, ready to embed.

    ``index`` is the stable ``chunk_index`` persisted on the
    :class:`~app.models.Embedding` row (ordinal within the document); ``text``
    is the chunk body.
    """

    index: int
    text: str


@dataclass(frozen=True)
class Citation:
    """The document a retrieved chunk came from (ADR-0019 §6 citation triple)."""

    document_id: UUID
    title: str
    kind: DocumentKind


@dataclass(frozen=True)
class RetrievedChunk:
    """A retrieved chunk with its similarity score and source citation."""

    chunk_index: int
    chunk_text: str
    score: float
    citation: Citation


def _split_markdown(content: str) -> list[str]:
    """Split Markdown into one chunk per top-level section (heading + body).

    A heading line (``#``..``######``) opens a new chunk; content before the
    first heading forms a leading chunk. Blank-only chunks are dropped. This
    keeps a section's heading attached to its prose so a retrieved chunk is
    self-describing.
    """
    sections: list[list[str]] = []
    current: list[str] = []
    for line in content.splitlines():
        if line.lstrip().startswith("#") and current and any(c.strip() for c in current):
            sections.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append(current)
    return ["\n".join(section).strip() for section in sections if any(c.strip() for c in section)]


def _split_rows(content: str) -> list[str]:
    """Split CSV into a header-prefixed chunk per data row (header carried).

    Each data row is emitted as ``"<header>\\n<row>"`` so a retrieved row stays
    interpretable without the rest of the table. A header-only or empty document
    yields a single chunk (the header) so it is still searchable.
    """
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return []
    header, *rows = lines
    if not rows:
        return [header]
    return [f"{header}\n{row}" for row in rows]


_MERMAID_DIRECTIVE_PREFIXES = (
    "graph ",
    "graph\t",
    "flowchart ",
    "flowchart\t",
    "sequenceDiagram",
    "classDiagram",
    "stateDiagram",
    "erDiagram",
    "journey",
    "gantt",
    "pie",
    "gitGraph",
    "mindmap",
    "timeline",
    "xychart",
    "block-beta",
    "quadrantChart",
    "requirementDiagram",
    "c4Context",
    "c4Container",
    "c4Component",
    "c4Dynamic",
    "c4Deployment",
    "sankey-beta",
    "packet-beta",
)


def _split_mermaid(content: str) -> list[str]:
    """Split Mermaid source into one self-describing chunk per statement line.

    The graph directive header (e.g. ``graph TD``, ``flowchart LR``,
    ``sequenceDiagram``) is parsed out and then **prepended to every
    subsequent statement chunk** so each retrieved chunk carries enough
    context to be interpreted independently without the rest of the diagram.
    Blank lines are skipped.

    Example::

        graph TD
          A --> B
          B --> C

    yields two chunks::

        graph TD
        A --> B

        graph TD
        B --> C
    """
    lines = [line.rstrip() for line in content.splitlines() if line.strip()]
    if not lines:
        return []

    # Identify the directive header (first line starting with a known keyword).
    header: str | None = None
    statement_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if header is None and any(stripped.startswith(p) for p in _MERMAID_DIRECTIVE_PREFIXES):
            header = stripped
        else:
            statement_lines.append(stripped)

    if header is None:
        # No recognised directive; fall back to returning each non-blank line.
        return lines

    if not statement_lines:
        # Only the directive line itself.
        return [header]

    return [f"{header}\n{stmt}" for stmt in statement_lines]


def chunk_document(document: Document) -> list[Chunk]:
    """Split *document* into structure-aware :class:`Chunk` s by its format.

    Markdown → per-section; CSV → per data row (header carried); Mermaid → per
    statement. The dispatch is on :attr:`Document.format` so the same pipeline
    handles every ADR-0019 artifact type without a fixed-width window.
    """
    from app.models.config_mgmt import DocumentFormat

    if document.format is DocumentFormat.CSV:
        bodies = _split_rows(document.content)
    elif document.format is DocumentFormat.MERMAID:
        bodies = _split_mermaid(document.content)
    else:
        bodies = _split_markdown(document.content)
    return [Chunk(index=i, text=body) for i, body in enumerate(bodies)]


def _to_vector(values: list[float]) -> list[float]:
    """Validate an embedding vector's width against :data:`EMBEDDING_DIM`."""
    if len(values) != EMBEDDING_DIM:
        raise ValueError(f"embedding vector has width {len(values)}, expected {EMBEDDING_DIM}")
    return values


async def embed_document(
    session: AsyncSession,
    document: Document,
    *,
    embedder: Embedder | None = None,
) -> list[Embedding]:
    """Chunk, embed, and persist *document*, superseding any prior chunks.

    Structure-aware chunks (:func:`chunk_document`) are embedded via *embedder*
    (default: the redacted D9 Ollama profile) and written as
    :class:`~app.models.Embedding` rows. Existing chunks for the document are
    **deleted first in the same transaction**, so regenerating an artifact
    replaces its vectors atomically and leaves no orphans (ADR-0019 §5). The
    caller owns the transaction boundary; this function only flushes.

    Returns the freshly persisted embedding rows (empty if the document has no
    embeddable content).
    """
    used_embedder = embedder if embedder is not None else get_default_embedder()
    chunks = chunk_document(document)

    # Supersede prior chunks deterministically (no upsert race, no orphans).
    await session.execute(delete(Embedding).where(Embedding.document_id == document.id))

    if not chunks:
        await session.flush()
        logger.info(
            "knowledge.document_embedded",
            document_id=str(document.id),
            kind=document.kind.value,
            chunks=0,
        )
        return []

    vectors = await used_embedder.embed([chunk.text for chunk in chunks])
    if len(vectors) != len(chunks):
        raise ValueError(f"embedder returned {len(vectors)} vectors for {len(chunks)} chunks")

    rows: list[Embedding] = []
    for chunk, vector in zip(chunks, vectors, strict=True):
        row = Embedding(
            document_id=document.id,
            chunk_index=chunk.index,
            chunk_text=chunk.text,
            embedding=_serialize_vector(session, _to_vector(vector)),
        )
        session.add(row)
        rows.append(row)
    await session.flush()
    logger.info(
        "knowledge.document_embedded",
        document_id=str(document.id),
        kind=document.kind.value,
        chunks=len(rows),
    )
    return rows


def _serialize_vector(session: AsyncSession, vector: list[float]) -> object:
    """Adapt a vector to the bound dialect's column type.

    On PostgreSQL pgvector accepts the Python list directly; on the SQLite
    unit-test backend the column is ``TEXT`` (``with_variant``), so the vector is
    stored as a JSON string the retrieval path parses back.
    """
    if session.bind is not None and session.bind.dialect.name == "sqlite":
        return json.dumps(vector)
    return vector


def _deserialize_vector(stored: object) -> list[float]:
    """Inverse of :func:`_serialize_vector` for the cosine fallback path."""
    if isinstance(stored, str):
        return [float(v) for v in json.loads(stored)]
    return [float(v) for v in cast("Iterable[Any]", stored)]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two equal-width vectors (0.0 for a zero vector)."""
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


async def retrieve(
    session: AsyncSession,
    query: str,
    *,
    top_k: int = 5,
    embedder: Embedder | None = None,
) -> list[RetrievedChunk]:
    """Embed *query* and return the cosine top-*k* chunks with citations.

    Read-only (ADR-0019 §6): embeds the query through *embedder* (default: the
    redacted D9 profile), ranks ``embeddings`` by cosine similarity, and returns
    the best :data:`top_k` chunks each joined to its :class:`Document` citation
    (id, title, kind). On PostgreSQL the pgvector HNSW/cosine index serves this;
    on the SQLite test backend the ranking is computed in Python over the
    candidate rows (no pgvector operators there).

    Raises ``ValueError`` for a non-positive *top_k*.
    """
    if top_k <= 0:
        raise ValueError(f"top_k must be positive, got {top_k}")

    used_embedder = embedder if embedder is not None else get_default_embedder()
    query_vector = _to_vector((await used_embedder.embed([query]))[0])

    # Determine the backend dialect to choose the retrieval strategy.
    # On PostgreSQL: delegate ranking to the pgvector HNSW/cosine index using
    # the ``<=>`` (cosine distance) operator and ORDER BY ... LIMIT top_k so
    # the index is actually used (O(log N) via HNSW), fulfilling ADR-0019 §6.
    # On SQLite (unit-test / dev fallback): full Python cosine ranking over all
    # rows — acceptable because the table is small and pgvector is unavailable.
    dialect_name: str = ""
    if session.bind is not None:
        dialect_name = session.bind.dialect.name

    if dialect_name == "postgresql":
        # Serialize query vector as a PostgreSQL ARRAY literal understood by the
        # pgvector cast.  The ``<=>`` operator returns cosine *distance*
        # (0 = identical, 2 = opposite), so we convert to similarity as
        # ``1 - distance`` for a consistent score in [−1, 1].
        qv_literal = "[" + ",".join(str(v) for v in query_vector) + "]"
        stmt = text(
            "SELECT e.id, e.document_id, e.chunk_index, e.chunk_text, e.embedding,"
            "       d.id AS doc_id, d.title, d.kind,"
            "       (1.0 - (e.embedding <=> CAST(:qv AS vector))) AS score"
            " FROM embeddings e"
            " JOIN documents d ON d.id = e.document_id"
            " ORDER BY e.embedding <=> CAST(:qv AS vector)"
            " LIMIT :limit"
        )
        raw_rows = (await session.execute(stmt, {"qv": qv_literal, "limit": top_k})).all()
        return [
            RetrievedChunk(
                chunk_index=row.chunk_index,
                chunk_text=row.chunk_text,
                score=float(row.score),
                citation=Citation(
                    document_id=row.document_id,
                    title=row.title,
                    kind=DocumentKind(row.kind),
                ),
            )
            for row in raw_rows
        ]

    # SQLite / fallback: Python cosine ranking (no pgvector operators).
    rows = (
        await session.execute(
            select(Embedding, Document).join(Document, Embedding.document_id == Document.id)
        )
    ).all()

    scored: list[RetrievedChunk] = []
    for embedding, document in rows:
        score = _cosine(query_vector, _deserialize_vector(embedding.embedding))
        scored.append(
            RetrievedChunk(
                chunk_index=embedding.chunk_index,
                chunk_text=embedding.chunk_text,
                score=score,
                citation=Citation(
                    document_id=document.id,
                    title=document.title,
                    kind=document.kind,
                ),
            )
        )
    scored.sort(key=lambda rc: rc.score, reverse=True)
    return scored[:top_k]
