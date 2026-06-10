# ADR-0002: Backend Stack — Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Alembic

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D2

## Context

CLAUDE.md's Architecture section mandates **Python** and **FastAPI** outright, and the rest of the constitution makes Python the only viable host language anyway: LangGraph (agent orchestration, D3), netmiko/pysnmp/pyshark (device and packet tooling, D7/D14), and the pgvector/Neo4j client ecosystems are all Python-first. The platform needs:

- A REST + WebSocket API (`api` container, brief §1) — WebSockets carry agent chat streams and reasoning traces to the React UI ("Explain all AI decisions").
- Heavy, schema-validated data shapes: normalized network models (`NormalizedInterface`, `NormalizedRoute`, … brief §4), agent tool inputs/outputs, and API contracts — CLAUDE.md requires API documentation for every feature.
- Disciplined schema evolution for a Postgres system of record holding audit and credential data (D4, D11) — "Audit everything" forbids ad-hoc schema drift.
- Async I/O at the API layer (many concurrent device/agent sessions) while tolerating blocking libraries (netmiko) in workers (ADR-0008).

## Decision

The backend is a single Python application (ADR-0001) on this exact stack:

| Concern | Choice | Notes |
|---|---|---|
| Language | **Python 3.11+** | minimum 3.11 for `asyncio` TaskGroups, `StrEnum` (used by the `Capability` enum, brief §4), and exception groups |
| Web framework | **FastAPI** | app factory in `backend/app/main.py`; routers under `app/api/v1/`: `devices`, `discovery`, `topology`, `agents`, `changes`, `ddi`, `packets`, `docs`, `auth`, `audit` (brief §3) |
| ASGI server | **uvicorn** (PROPOSED — brief does not name a server; uvicorn is the conservative FastAPI default) | |
| ORM | **SQLAlchemy 2.0, async** with the **asyncpg** driver (PROPOSED — brief specifies SQLAlchemy 2.0 async; asyncpg is the standard async PostgreSQL driver) | models in `app/models/`, 2.0-style `Mapped[]`/`mapped_column()` declarative only |
| Validation/serialization | **Pydantic v2** | all request/response schemas and normalized network models in `app/schemas/`; also the structured-output layer for LLM calls (D9) |
| Migrations | **Alembic** | lives at `backend/alembic/`; **Alembic owns the schema** (D4) — no `create_all()` outside tests, every schema change is a reviewed migration |
| Packaging | **`backend/pyproject.toml`** | single package; ruff + mypy configured here (D16) |

Patterns fixed by this ADR:

1. **App factory:** `app/main.py` exposes `create_app() -> FastAPI`; tests and the ASGI server both use it. Configuration is loaded once in `app/core/` (pydantic-settings — PROPOSED, the natural Pydantic-v2 companion) from environment variables, matching the env/file secret model of D11.
2. **Async-first API, sync-tolerant workers:** all API path operations and services use `async def` with the async SQLAlchemy session; blocking vendor I/O (netmiko, pysnmp sync calls, pyVmomi) never runs on the event loop — it runs in Celery workers (ADR-0008).
3. **One schema language:** Pydantic v2 models are the single contract for API bodies, agent tool signatures (D3), plugin outputs (D6), and LLM structured outputs (D9). FastAPI's generated OpenAPI is the API documentation CLAUDE.md requires.
4. **Versioned API surface:** everything mounts under `/api/v1`; breaking changes require `/api/v2`, never in-place mutation.

## Consequences

**Positive**

- Zero impedance mismatch with the mandated AI stack: LangGraph nodes, plugin capability methods, and FastAPI endpoints all speak Pydantic v2.
- OpenAPI docs come for free and satisfy the "API documentation" development standard on every endpoint.
- SQLAlchemy 2.0 typed ORM + mypy (D16) catches model/query drift at CI time; Alembic gives every schema change an auditable, reviewable artifact — consistent with "Audit everything".
- asyncpg + async sessions let one `api` replica multiplex many concurrent agent/WebSocket sessions cheaply.

**Negative**

- Python's GIL and interpreter overhead cap single-process throughput; CPU-bound work (pcap parsing, embedding generation) must be pushed to workers or it stalls the API.
- The async/sync split is a standing foot-gun: calling a blocking netmiko function from an endpoint will pass tests and fail under load. Mitigation: module boundaries (ADR-0001) keep device I/O behind engines, which run in workers.
- SQLAlchemy 2.0 async sessions are not safely shareable across tasks; session-per-request discipline must be enforced via FastAPI dependencies.
- Pydantic v2 validation on large discovery payloads (thousands of interfaces) has measurable cost; bulk paths may need `model_construct()`-style escapes, to be benchmarked in M1.

## Alternatives considered

1. **Django + Django REST Framework.**
   Rejected: Django's ORM and request cycle are sync-first heritage; async support remains partial (ORM async wrappers, channels for WebSockets) and fights the LangGraph/streaming model. Its batteries (admin, templates) target CRUD apps, not an agent platform. Also conflicts directly with CLAUDE.md's explicit FastAPI mandate.

2. **Litestar (or Flask + extensions).**
   Litestar is technically credible (fast, typed, Pydantic-friendly) but rejected because CLAUDE.md names FastAPI, FastAPI's ecosystem/contributor pool is far larger (relevant for a long-lived enterprise product), and Litestar would buy nothing the brief needs. Flask rejected outright: no native async, no built-in validation/OpenAPI — we would reassemble FastAPI from plugins.

3. **Go (or TypeScript/NestJS) backend with Python sidecars for AI/device tooling.**
   Rejected: violates the CLAUDE.md architecture list, and splitting "platform" from "Python tooling" recreates the microservice tax ADR-0001 rejects — every netmiko/LangGraph call would cross a process boundary with serialized normalized models on both sides.

4. **Raw asyncpg / SQL without an ORM.**
   Rejected: the data model (brief §6: ~18 table families including encrypted credentials and append-only audit) needs relationships, migrations, and typed rows more than it needs the last 10% of query performance. Alembic's autogenerate against SQLAlchemy models is the cheapest way to keep "Alembic owns schema" true.
