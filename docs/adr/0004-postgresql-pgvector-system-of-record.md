# ADR-0004: PostgreSQL 16 + pgvector as the System of Record

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D4

## Context

CLAUDE.md mandates **PostgreSQL** and **pgvector** in its Architecture list, and three design principles dictate what the relational store must carry:

- **Audit everything** → an append-only audit log with actor, action, target, before/after state, reasoning-trace link (brief §7).
- **Secure by default / Human approval for changes** → encrypted device credentials and the full `ChangeRequest`/approval lifecycle must live somewhere transactional (D11).
- **Local first / Self hosted** → RAG over platform documents ("Documentation generation", runbooks, incident reports) needs vector search *without* adding a managed cloud service or another stateful container.

Additionally, the vendor plugin contract (brief §4) requires that **all raw command output is stored verbatim** before normalization — large, semi-structured payloads per discovery run.

## Decision

**A single PostgreSQL 16 instance with the pgvector extension is the system of record. JSONB holds raw artifacts. Alembic owns the schema.** (brief §2 D4, §6)

1. **One database, the authoritative one.** Postgres holds everything the platform cannot afford to lose. Neo4j is a rebuildable projection of it (ADR-0005) and never holds unique data.

2. **Schema families** (brief §6), all created and evolved exclusively through Alembic migrations (ADR-0002):
   - Inventory: `devices`, `device_credentials` (AES-256-GCM envelope-encrypted columns, D11), `discovery_runs`.
   - Evidence: `raw_artifacts` — verbatim device output as `JSONB` + text, keyed to device/run/command, satisfying the plugin contract's auditability requirement; `normalized_*` tables (interfaces, routes, neighbors, BGP peers, ACL entries, DNS records, …) holding the parsed Pydantic-model rows engines consume.
   - Config management: `config_snapshots`, `compliance_policies`.
   - Change control: `change_requests`, `approvals` — lifecycle `draft → pending_approval → approved → executing → completed | failed → rolled_back` (brief §7) enforced with a status enum + transition checks in the service layer.
   - Audit: `audit_log` — **append-only**: the application role receives `INSERT`/`SELECT` only; `UPDATE`/`DELETE` grants are withheld at the database level (brief §7), so immutability does not depend on application code.
   - Identity: `users`, `roles` (D10).
   - AI: `documents` + `embeddings` (pgvector `vector` column), `agent_sessions`, `reasoning_traces`.
   - Packet: `pcap_metadata` (pcap bytes live on a disk volume, not in Postgres — D14).

3. **pgvector usage.** The `embeddings` table stores chunk embeddings for RAG over `documents` (runbooks, configs, vendor docs) queried by `knowledge/` (brief §3).
   - **PROPOSED (brief silent):** index with **HNSW, cosine distance** (`vector_cosine_ops`) — pgvector's recommended default for recall/latency balance at MVP scale; embedding dimension is a column of the configured embedding model profile (D9), and changing models requires a re-embed migration, not a schema redesign.

4. **JSONB discipline.** `JSONB` is for *raw/opaque* payloads (`raw_artifacts`, provider responses) — never for data that engines filter or join on. Anything queried structurally gets promoted to a typed column or `normalized_*` table via migration.

5. **Deployment.** The `postgres` container (PostgreSQL 16 + pgvector image) per brief §1; single instance for MVP/dev via docker-compose (D13). HA/replication is explicitly a production-roadmap item routed through the Consultant (brief §9).

## Consequences

**Positive**

- One backup/restore story covers inventory, credentials, change control, audit, AI memory, and vectors — the most important property for self-hosted operators.
- Transactional consistency across domains: approving a ChangeRequest, writing the audit entry, and linking the reasoning trace commit atomically — impossible if vectors or audit lived in a separate store.
- Grant-level append-only audit is tamper-resistant even against application bugs.
- Verbatim `raw_artifacts` make every normalized row re-derivable and every agent claim evidence-backed ("Explain all AI decisions").

**Negative**

- pgvector at very large corpus sizes (tens of millions of vectors) underperforms dedicated vector engines; acceptable at MVP scale, revisit if RAG corpus growth demands it.
- `raw_artifacts` will dominate storage growth (full `show running-config`/`show tech` style output per run); a retention/compaction policy is required — retention targets are an open Consultant item (brief §9).
- Single instance is a single point of failure until the production roadmap adds HA; the platform's availability ceiling is Postgres's.
- Append-only audit plus raw artifacts means the database only grows; operators need documented archival procedures (Documentation Agent scope, M4).

## Alternatives considered

1. **Dedicated vector database (Qdrant, Weaviate, Milvus) alongside Postgres.**
   Rejected: adds a fourth stateful service to a self-hosted stack for a corpus that is platform documentation and configs — well within pgvector's envelope. It also splits RAG metadata from vectors across systems, breaking transactional writes and doubling the backup story. Contradicts CLAUDE.md's explicit pgvector mandate and the "Local first" bias toward fewer moving parts.

2. **MySQL/MariaDB as the relational store.**
   Rejected: no pgvector equivalent of comparable maturity (would force alternative #1), weaker JSONB-style indexing for `raw_artifacts`, no transactional DDL (riskier Alembic migrations), and—decisively—CLAUDE.md names PostgreSQL.

3. **Storing embeddings/knowledge in Neo4j (Neo4j 5 vector indexes).**
   Rejected: Neo4j is architecturally a *rebuildable projection* (D5); putting the only copy of embeddings there would make it a second system of record, exactly the dual-master problem D5 exists to prevent. Neo4j Community's backup tooling is also weaker than Postgres's.

4. **Separate audit store (e.g. immutable log service / OpenSearch).**
   Rejected for MVP: the audit log's integrity requirement is met more simply by withholding UPDATE/DELETE grants in Postgres, keeping audit entries joinable to change requests and traces. An export pipeline to a SIEM can be added later without changing the system of record.
