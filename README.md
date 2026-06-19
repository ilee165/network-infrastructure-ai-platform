# AI Network Operations Platform

A self-hosted, AI-powered Network Operations Platform for enterprise infrastructure teams. It functions as an AI Network Engineer: discovery, troubleshooting, packet analysis, configuration management, DDI management, documentation generation, and automation execution across multi-vendor environments — local-first, secure by default, with a human approving every change and every AI decision explained and audited.

> **Status:** Milestone **M1** (inventory, credential vault, discovery engine, first three vendor plugins) complete on `release/m1`. Milestone **M2** (topology engine: Postgres→Neo4j projection with incremental sync + full rebuild, L2/L3 builders, topology API, and the Cytoscape.js topology UI with L2/L3 layer toggle and run-to-run diff view) is **build-complete on `feature/m2-topology-engine`, pending lab validation + merge approval**; see the [MVP roadmap](docs/roadmap/MVP.md). Not yet feature-complete — M3 (agent framework + troubleshooting) is next.

## Architecture at a glance

| Component | Technology | Purpose |
|---|---|---|
| `api` | Python 3.11+ / FastAPI | REST + WebSocket API, authn/z, agent sessions |
| `worker` | Celery (queues: discovery, config, packet, docs) | Long-running jobs |
| `frontend` | React 18 + TypeScript + Vite | Ops console: chat, topology, inventory, approvals, audit |
| `postgres` | PostgreSQL 16 + pgvector | System of record + embeddings |
| `neo4j` | Neo4j 5 | Topology & knowledge graph (rebuildable projection) |
| `redis` | Redis 7 | Celery broker, cache |
| `ollama` | Ollama (optional, `--profile local-llm`) | Local-first LLM inference |

Agents are orchestrated with LangGraph (Master Architect supervisor + 9 specialists); vendors integrate through a capability-based plugin system. Supported DDI vendors: **Infoblox** (WAPI, ADR-0022) and **SpatiumDDI** (self-hostable OSS DDI backend, ADR-0024). Full design:

- [Decisions brief (D1–D16)](docs/architecture/DECISIONS-BRIEF.md) · [ADRs](docs/adr/README.md) · [Diagrams](docs/architecture/DIAGRAMS.md) · [Repo structure](docs/architecture/REPO-STRUCTURE.md)
- [MVP roadmap](docs/roadmap/MVP.md) · [Production roadmap](docs/roadmap/PRODUCTION.md)
- [Consultant: open questions & working assumptions](docs/consultant/QUESTIONS.md)

## Quickstart (Docker Compose)

```bash
cp .env.example .env          # then set NETOPS_SECRET_KEY and NETOPS_NEO4J_PASSWORD
docker compose -f deploy/docker/docker-compose.yml up -d
# with a local LLM:
docker compose -f deploy/docker/docker-compose.yml --profile local-llm up -d
```

- Frontend: http://localhost:8080 · API docs: http://localhost:8000/docs · Health: `GET /api/v1/health/ready`

Details: [deploy/docker/README.md](deploy/docker/README.md). Kubernetes/Helm arrives per the [production roadmap](docs/roadmap/PRODUCTION.md).

## Development

**Backend** (Python ≥3.11):

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate   # Windows; use bin/activate on Unix
pip install -e ".[dev]"
pytest                      # unit tests run without Postgres/Neo4j/Redis
ruff check . && ruff format --check . && mypy
uvicorn app.main:create_app --factory --reload
```

**Frontend** (Node 20):

```bash
cd frontend
npm install
npm run dev                 # proxies /api -> http://localhost:8000
npm run lint && npm run typecheck && npm test && npm run build
```

## Contributing

Every feature requires tests, documentation, and API documentation before merge (see [CLAUDE.md](CLAUDE.md), the platform constitution). Architecture changes require an ADR in [docs/adr/](docs/adr/README.md). CI (GitHub Actions) gates on lint, types, tests, builds, and image vulnerability scans.
