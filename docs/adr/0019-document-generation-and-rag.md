# ADR-0019: Document Generation and RAG

**Status:** Accepted | **Date:** 2026-06-14 | **Milestone:** M4 (new capability — `REPO-STRUCTURE.md` §6)

## Context

CLAUDE.md "Documentation" requires automatically generating **Diagrams**, **Runbooks**, **Network inventories** (Incident reports are M5), and the platform must "Explain all AI decisions" with retrievable, cited sources. ADR-0004 §2 already declares `documents` + `embeddings` (pgvector, HNSW/cosine). MVP.md §6 PROPOSES Markdown/CSV inventories, Mermaid+PNG diagrams, and template+LLM runbooks, all chunked + embedded for RAG. This ADR fixes the generation, storage, and retrieval model for the Documentation Agent (`docs` queue, ADR-0008).

## Decision

**The Documentation Agent generates three artifact types on the `docs` queue, stores each in `documents`, chunks + embeds every artifact into `embeddings`, and exposes a `knowledge/` RAG retrieval tool that returns chunks with citations. Diagrams are emitted as Mermaid source (the diagram-of-record); PNG is a client-side render/export, not a server-side dependency.**

1. **`documents` model.** `{ id, kind: inventory|diagram|runbook, title, format: md|csv|mermaid, content, source_refs (device/site/run ids the artifact was generated from), generated_at, generated_by_session_id }`. Every artifact is downloadable via the `docs` router (`/api/v1/docs`) and listed in the UI document library.

2. **Inventories** — deterministic render of normalized tables to **Markdown + CSV** (no LLM): devices, interfaces, neighbors, routes, scoped by site/vendor. Exit criterion is a round-trip equality test against normalized-table content, so generation is pure/templated, not model-narrated.

3. **Diagrams** — **Mermaid source** generated deterministically from the Neo4j projection (nodes/edges → Mermaid `graph` syntax). Mermaid is the stored, diffable, embeddable diagram-of-record; it satisfies the exit criterion (diagram node/edge set matches the projection) by construction. **PNG is rendered client-side** (frontend renders the Mermaid for view and offers a PNG export/download). No headless-browser dependency is added to the `worker` image in M4; server-side PNG rendering is a production-hardening item.

4. **Runbooks** — **template + LLM narrative grounded in inventory/topology**. A per-device/per-site Markdown template is filled with deterministic facts (from normalized tables + the projection); the LLM writes only the narrative sections, grounded in those facts and instructed to cite them. **All grounding content passes through the A9 redaction layer** before reaching the model (configs/inventory can carry secret-bearing fields — ADR-0017 §3). Provider via the D9 registry (`local` default).

5. **Chunking + embedding.** On generation, each artifact is chunked (structure-aware: headings/rows) and embedded via the configured embedding profile (D9) into `embeddings` (pgvector, HNSW/cosine per ADR-0004 §3). Re-generation supersedes prior chunks for that artifact (no orphan vectors).

6. **RAG retrieval tool (`knowledge/`).** A typed, read-only agent tool: given a query, embed it, cosine-search `embeddings`, return the top chunks **with their `documents` citation** (id, title, kind). Available to all agents so answers can cite platform-generated docs. Exit criterion: a query against a generated runbook returns the relevant chunk with citation.

## Consequences

**Positive**
- Mermaid-as-source keeps diagrams diffable, embeddable, and dependency-light; PNG remains available to users without a chromium-in-worker liability.
- Deterministic inventories/diagrams are exactly testable (round-trip / set-equality); only the runbook narrative is model-generated, and it is grounded + cited + redacted.
- One retrieval path (`knowledge/` over pgvector) serves every agent; citations make generated docs first-class evidence ("Explain all AI decisions").

**Negative**
- No server-stored PNG in M4 — a consumer needing a rendered image outside the UI must render the Mermaid themselves (acceptable; revisited in production).
- Runbook quality depends on the local model; the narrative is bounded by templated facts so a weak model degrades prose, not correctness. Covered by a grounded-generation eval (`wf-eval-designer`).
- Embedding-model change requires a re-embed migration (already noted in ADR-0004 §3).

## Alternatives considered

1. **Server-side PNG rendering (mermaid-cli/puppeteer in the worker).** Rejected for M4: adds a heavy headless-browser dependency + image weight and a new CVE surface to the `worker` for an artifact the frontend can render client-side. Production-hardening candidate.
2. **LLM-generated inventories/diagrams.** Rejected: inventories and diagrams must exactly match source data (round-trip/set-equality exit criteria); determinism beats narration here. LLM is reserved for runbook prose.
3. **A dedicated vector store for doc RAG.** Rejected: ADR-0004 already fixes pgvector as the single system of record for embeddings; a second store reintroduces the dual-master problem D5/D4 avoid.
