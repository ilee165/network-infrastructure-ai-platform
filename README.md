# AI Network Operations Platform

A self-hosted, AI-powered Network Operations Platform for enterprise infrastructure teams. It functions as an AI Network Engineer: discovery, troubleshooting, packet analysis, configuration management, DDI management, documentation generation, and automation execution across multi-vendor environments — local-first, secure by default, with a human approving every change and every AI decision explained and audited.

> **Status:** **MVP feature-complete** — milestones **M1–M5** all shipped: inventory + credential vault + discovery engine (M1), topology engine with Postgres→Neo4j projection and Cytoscape.js UI (M2), the LangGraph agent framework + Troubleshooting Agent + chat UI (M3), config management + Documentation Agent (M4), and the ChangeRequest write-path workflow + Automation/DDI/Packet Analysis agents (M5). Production hardening (**P1**) is **in progress**: Vendor Wave 1 plugins (Cisco NX-OS, Juniper JunOS, BlueCat), OIDC/SSO, and the Kubernetes/Helm + backup/DR track. See the [MVP roadmap](docs/roadmap/MVP.md) and [production roadmap](docs/roadmap/PRODUCTION.md). Live-lab validation gates per milestone remain a manual pre-release step.

## Architecture at a glance

| Component | Technology | Purpose |
|---|---|---|
| `api` | Python 3.11+ / FastAPI | REST + WebSocket API, authn/z, agent sessions |
| `worker` | Celery (queues: discovery, config, packet, docs) | Long-running jobs |
| `frontend` | React 19 + TypeScript + Vite | Ops console: chat, topology, inventory, approvals, audit |
| `postgres` | PostgreSQL 16 + pgvector | System of record + embeddings |
| `neo4j` | Neo4j 5 | Topology & knowledge graph (rebuildable projection) |
| `redis` | Redis 7 | Celery broker, cache |
| `ollama` | Ollama (optional, `--profile local-llm`) | Local-first LLM inference |

Agents are orchestrated with LangGraph (Master Architect supervisor + 9 specialists); vendors integrate through a capability-based plugin system. Certified vendor plugins: **Cisco IOS / IOS-XE / NX-OS**, **Juniper JunOS**, **Arista EOS** for route/switch, plus DDI backends **Infoblox** (WAPI, ADR-0022), **BlueCat** (Address Manager, ADR-0027), and **SpatiumDDI** (self-hostable OSS DDI backend, ADR-0024). Full design:

- [Decisions brief (D1–D16)](docs/architecture/DECISIONS-BRIEF.md) · [ADRs](docs/adr/README.md) · [Diagrams](docs/architecture/DIAGRAMS.md) · [Repo structure](docs/architecture/REPO-STRUCTURE.md)
- [MVP roadmap](docs/roadmap/MVP.md) · [Production roadmap](docs/roadmap/PRODUCTION.md)
- [Consultant: open questions & working assumptions](docs/consultant/QUESTIONS.md)

## Quickstart (Docker Compose)

```bash
cp .env.example .env          # then set NETOPS_SECRET_KEY, NETOPS_NEO4J_PASSWORD, NETOPS_ADMIN_PASSWORD
# --env-file .env is REQUIRED: with `-f deploy/docker/...` compose interpolates the
# neo4j credential from the compose dir/shell, not the root .env (deploy/docker/README.md §2).
docker compose --env-file .env -f deploy/docker/docker-compose.yml up -d
# with a local LLM:
docker compose --env-file .env -f deploy/docker/docker-compose.yml --profile local-llm up -d
```

- Frontend: http://localhost:8080 · API docs: http://localhost:8000/docs · Health: `GET /api/v1/health/ready`
- First-run schema: `docker compose --env-file .env -f deploy/docker/docker-compose.yml exec api alembic upgrade head` (applies migrations `0001`→`0010`; the `0001` baseline seeds the bootstrap `admin` user from `NETOPS_ADMIN_PASSWORD`, defaulting to `admin`/`admin` with a loud warning when unset — set it and rotate after first login).

Details: [deploy/docker/README.md](deploy/docker/README.md). Kubernetes/Helm arrives per the [production roadmap](docs/roadmap/PRODUCTION.md).

## Development

**Backend** (Python ≥3.11):

```bash
cd backend
python -m venv .venv                 # ALWAYS use a venv — see note below
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                      # unit tests run without Postgres/Neo4j/Redis
ruff check . && ruff format --check . && mypy
lint-imports                # module-boundary contracts (import-linter)
uvicorn app.main:create_app --factory --reload
```

> Install into the **venv**, never the system/global interpreter. On a
> distro-managed Python (e.g. Debian/Ubuntu base images) a global
> `pip install -e ".[dev]"` aborts the whole transaction trying to replace the
> OS-owned PyYAML — `Cannot uninstall PyYAML 6.0.1, RECORD file not found ...
> installed by debian` — leaving the environment half-installed. The venv has no
> such conflict.

**Frontend** (Node 20):

```bash
cd frontend
npm install
npm run dev                 # proxies /api -> http://localhost:8000
npm run lint && npm run typecheck && npm test && npm run build
```

## Contributing

Every feature requires tests, documentation, and API documentation before merge (see [CLAUDE.md](CLAUDE.md), the platform constitution). Architecture changes require an ADR in [docs/adr/](docs/adr/README.md). CI (GitHub Actions) gates on lint, types, tests, builds, and image vulnerability scans.
