# Architecture Decisions Brief

**Project:** AI Network Operations Platform
**Status:** Draft v0.1 — Iteration 1 (Phase 1: Architecture)
**Date:** 2026-06-09
**Authority:** `CLAUDE.md` is the platform constitution. This brief translates it into concrete, buildable decisions. Every Phase 1 artifact (ADRs, diagrams, roadmaps, repo structure) and all Phase 2 code MUST be consistent with this document. Each decision D1–D16 is expanded into a numbered ADR in `docs/adr/`.

---

## 1. System overview

A self-hosted, multi-vendor AI Network Operations Platform that acts as an AI Network Engineer: it discovers infrastructure, maintains a living topology and knowledge graph, troubleshoots routing/DNS/DHCP/ACL/firewall issues, analyzes packets, manages configuration and DDI, generates documentation, and executes automation — with a human approving every change, every AI decision explained, and everything audited.

### Containers (C4 level 2)

| Container | Technology | Responsibility |
|---|---|---|
| `frontend` | React 19 + TypeScript + Vite, served by nginx | Chat console, topology visualization, inventory, change approvals, audit views |
| `api` | Python 3.11+ / FastAPI | REST + WebSocket API, authn/z, agent session orchestration |
| `worker` | Celery workers (same codebase as `api`) | Long-running jobs: discovery runs, config backups, packet captures, doc generation |
| `postgres` | PostgreSQL 16 + pgvector | System of record: inventory, credentials (encrypted), change requests, audit log, embeddings |
| `neo4j` | Neo4j 5 Community | Topology + knowledge graph (L2, L3, DNS, application dependencies) |
| `redis` | Redis 7 | Celery broker/result backend, cache, rate limiting |
| `ollama` (optional profile) | Ollama | Local-first LLM inference; external providers are opt-in |

## 2. Binding decisions (D1–D16)

| ID | Decision | Key choices | ADR |
|---|---|---|---|
| D1 | Monorepo, modular-monolith backend | Single repo; backend is one deployable with enforced internal module boundaries; services extracted later only if scale demands | 0001 |
| D2 | Backend stack | Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Alembic migrations | 0002 |
| D3 | Agent orchestration | LangGraph supervisor pattern: Master Architect Agent supervises; 9 specialist agents as subgraphs; shared tool/audit/approval layers | 0003 |
| D4 | Relational + vector store | PostgreSQL 16 with pgvector for embeddings; JSONB for raw artifacts; Alembic owns schema | 0004 |
| D5 | Graph store | Neo4j 5 for topology/knowledge graph; Postgres remains system of record, Neo4j is a projection rebuilt from it | 0005 |
| D6 | Vendor plugin system | Capability-interface ABCs + plugin registry; plugins discovered via Python entry points (`netops.plugins`); one package per vendor | 0006 |
| D7 | Device connectivity | netmiko (SSH, vendor breadth) + ntc-templates/TextFSM parsing → normalized Pydantic models; pysnmp (SNMP v2c/v3); httpx for REST/XML APIs (PAN-OS, F5 iControl, Infoblox WAPI, BlueCat); boto3 / azure SDK / pyVmomi for cloud & VMware | 0007 |
| D8 | Async jobs | Celery + Redis; dedicated queues: `discovery`, `config`, `packet`, `docs` | 0008 |
| D9 | Multi-LLM abstraction | LangChain chat-model interface behind an internal `llm/` provider registry; profiles: `local` (Ollama, default), `anthropic`, `openai`, `azure`; all prompts versioned in-repo; structured outputs via Pydantic | 0009 |
| D10 | AuthN/AuthZ | Local users + OIDC (pluggable); short-lived JWT access tokens; RBAC roles: `viewer`, `operator`, `engineer`, `admin` | 0010 |
| D11 | Security model | Device credentials in an encrypted vault table (AES-256-GCM envelope encryption, master key from env/file/KMS); append-only audit log; every state-changing action goes through a ChangeRequest with human approval; agent reasoning traces stored and linked to audit entries | 0011 |
| D12 | Frontend stack | React 19, TypeScript strict, Vite, TanStack Query, Zustand, Tailwind CSS; topology rendering with Cytoscape.js | 0012 |
| D13 | Deployment | Docker Compose for MVP/dev (with optional `ollama` profile); Kubernetes via Helm chart for production; one image per container | 0013 |
| D14 | Packet analysis | tshark/pyshark executed in sandboxed worker context; pcap artifacts stored on disk volume with metadata + retention policy in Postgres; capture orchestration on devices via plugin capability | 0014 |
| D15 | Observability | structlog JSON logging, Prometheus `/metrics`, OpenTelemetry tracing (optional collector); health/readiness endpoints on every container | 0015 |
| D16 | Testing & CI/CD | pytest + pytest-asyncio, coverage gate ≥80% on core modules; ruff (format+lint) + mypy; frontend: vitest + testing-library + eslint + tsc; GitHub Actions: lint → typecheck → test → build images → Trivy scan | 0016 |

## 3. Repository layout (blueprint)

```
network-infrastructure-ai-platform/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app factory
│   │   ├── core/                # config, logging, security, audit, errors
│   │   ├── api/v1/              # routers: devices, discovery, topology, agents, changes, ddi, packets, docs, auth, audit
│   │   ├── models/              # SQLAlchemy models
│   │   ├── schemas/             # Pydantic request/response + normalized network models
│   │   ├── services/            # business logic (inventory, change mgmt, credentials, audit)
│   │   ├── agents/
│   │   │   ├── framework/       # base agent, registry, tool wrappers, reasoning traces, approval gate
│   │   │   └── <agent_name>/    # master_architect, consultant, discovery, troubleshooting, packet_analysis, configuration, ddi, documentation, security, automation
│   │   ├── plugins/
│   │   │   ├── base.py          # VendorPlugin ABC + Capability enum + capability interfaces
│   │   │   ├── registry.py      # (vendor, capability) -> implementation resolution
│   │   │   └── vendors/         # cisco_ios, cisco_iosxe, cisco_nxos, junos, eos, panos, fortios, f5_bigip, bluecat, infoblox, aws, azure, vmware
│   │   ├── engines/
│   │   │   ├── discovery/       # seed expansion, job planning, normalization pipeline
│   │   │   ├── topology/        # graph projection Postgres -> Neo4j, L2/L3 builders, diff
│   │   │   ├── packet/          # capture orchestration, pcap analysis (pyshark)
│   │   │   └── config_mgmt/     # backup, restore, drift detection, compliance checks
│   │   ├── knowledge/           # Neo4j client, graph queries, RAG over pgvector
│   │   ├── llm/                 # provider registry, prompt templates, model profiles
│   │   └── workers/             # Celery app + task definitions
│   ├── tests/                   # mirrors app/ structure; unit + integration
│   ├── alembic/
│   └── pyproject.toml
├── frontend/                    # React + TS + Vite
├── deploy/
│   ├── docker/                  # Dockerfiles, docker-compose.yml
│   └── kubernetes/              # Helm chart
├── docs/
│   ├── adr/                     # ADR-0001..0032 + index
│   ├── architecture/            # this brief, DIAGRAMS.md, REPO-STRUCTURE.md
│   ├── roadmap/                 # MVP.md, PRODUCTION.md
│   └── consultant/              # GAP-ANALYSIS.md, QUESTIONS.md, ASSUMPTIONS.md
├── .github/workflows/           # CI/CD
└── scripts/
```

**Module boundary rules** (enforced by import-linter in CI, Phase 2): `plugins` may not import `agents`; `agents` use engines/services only through typed tool wrappers in `agents/framework`; `engines` depend on `plugins` only via the registry; `core` imports nothing from feature modules.

## 4. Vendor plugin system contract

```python
class Capability(StrEnum):
    DISCOVERY_SSH, DISCOVERY_SNMP, DISCOVERY_API,
    INTERFACES, ROUTES, NEIGHBORS_LLDP, NEIGHBORS_CDP,
    BGP, OSPF, ACL, FIREWALL_POLICY,
    CONFIG_BACKUP, CONFIG_RESTORE, CONFIG_DEPLOY,
    DDI_DNS, DDI_DHCP, DDI_IPAM,
    PACKET_CAPTURE, HA_STATUS

class VendorPlugin(ABC):
    vendor_id: str                  # e.g. "cisco_iosxe"
    display_name: str
    capabilities: frozenset[Capability]
```

- Each capability has a typed interface (e.g. `InterfacesCapability.get_interfaces() -> list[NormalizedInterface]`).
- All raw command output is stored verbatim (auditability), then parsed to **normalized Pydantic models** (`NormalizedInterface`, `NormalizedRoute`, `NormalizedNeighbor`, `NormalizedBgpPeer`, `NormalizedAclEntry`, `NormalizedDnsRecord`, …) so engines and agents are vendor-agnostic.
- Registry resolves `(vendor_id, capability)`; plugins self-register via entry points so third-party vendor packages can be added without modifying core.

## 5. Agent framework contract

- **Master Architect Agent** is the LangGraph supervisor: receives user intent, plans, routes to specialists, synthesizes.
- **Consultant Agent** owns requirement clarification: when intent is ambiguous it asks the user; in autonomous contexts it records questions with recommended defaults in `docs/consultant/QUESTIONS.md` and proceeds on the defaults.
- Each specialist agent = a LangGraph subgraph declaring: name, description, input schema, and a set of **typed tools** that wrap engine/service functions.
- **Read vs. write separation:** read-only tools execute directly; any state-changing tool call (config deploy, DDI record change, automation) creates a `ChangeRequest` and blocks until human approval — no exceptions. (One ratified carve-out, ADR-0014: **bounded diagnostic** actions — device packet captures with mandatory duration/size caps — are a third tool classification that executes without a ChangeRequest at `operator`+, always audited.)
- **Explainability:** every agent run produces a reasoning trace (steps, tool calls, evidence) persisted and linked from the audit log and the UI.

## 6. Data architecture

**PostgreSQL (system of record):** `devices`, `device_credentials` (encrypted), `discovery_runs`, `raw_artifacts` (JSONB + text), `normalized_*` tables, `config_snapshots`, `compliance_policies`, `change_requests`, `approvals`, `audit_log` (append-only), `users`/`roles`, `documents` + `embeddings` (pgvector), `agent_sessions`, `reasoning_traces`, `pcap_metadata`.

**Neo4j (projection, rebuildable):** node labels `Device`, `Interface`, `Vlan`, `Subnet`, `IPAddress`, `VRF`, `DnsZone`, `DnsRecord`, `Application`, `Site`; relationships `CONNECTED_TO` (L2), `L3_ADJACENT`, `ROUTES_TO`, `HAS_INTERFACE`, `IN_SUBNET`, `RESOLVES_TO`, `DEPENDS_ON`, `MEMBER_OF`, `LOCATED_AT`. The projection is derived from Postgres and can be fully rebuilt — Neo4j never holds data that exists nowhere else.

## 7. Security architecture

- Secrets: platform master key via env/file (KMS-compatible interface); device credentials AES-256-GCM envelope-encrypted, never returned by any API.
- RBAC enforced at the API layer; agents inherit the invoking user's permissions — an agent can never do what its user cannot.
- ChangeRequest lifecycle: `draft → pending_approval → approved → executing → completed | failed → rolled_back`; approvals require a different user than the requester (configurable).
- Audit log is append-only (no UPDATE/DELETE grants); records actor (human or agent), action, target, before/after state, and reasoning-trace link.
- Network: TLS everywhere in production; containers run non-root; K8s NetworkPolicies restrict east-west traffic.

## 8. MVP milestones (summary — expanded in docs/roadmap/MVP.md)

- **M0** — Repo scaffold, CI, docker-compose, health endpoints, auth skeleton.
- **M1** — Inventory + credential vault + discovery engine; first 3 plugins: Cisco IOS, Cisco IOS-XE, Arista EOS (SSH + SNMP; interfaces, routes, LLDP/CDP).
- **M2** — Topology engine: Neo4j projection + frontend topology visualization.
- **M3** — Agent framework + Troubleshooting Agent (read-only) + chat UI with reasoning traces.
- **M4** — Config management: backup, drift detection, compliance checks + Documentation Agent (inventories, diagrams, runbooks).
- **M5** — DDI (Infoblox first), packet analysis basics, ChangeRequest approval workflow + Automation Agent.

Remaining vendors, Route53/BlueCat, HA, OIDC, K8s hardening → production roadmap.

## 9. Open items routed to the Consultant Agent

Scale targets (device count/sites), HA/DR expectations, multi-tenancy, SSO provider, compliance regimes, air-gapped operation, GPU availability for local LLM, telemetry/streaming (gNMI/NetFlow — absent from CLAUDE.md), IPv6 scope, data retention, existing source-of-truth integrations (e.g. NetBox), commercial API licensing. Full list with recommended defaults: `docs/consultant/QUESTIONS.md`. The build proceeds on the recommended defaults until the owner answers.
