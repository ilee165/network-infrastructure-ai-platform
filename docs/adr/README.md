# ADR Index

**Project:** AI Network Operations Platform
**Scope:** One ADR per binding decision D1–D16 in `docs/architecture/DECISIONS-BRIEF.md` §2. This file is the ADR index referenced by the brief (§3), `MVP.md` M0, and `REPO-STRUCTURE.md` §1.

| ADR | Title | Status | Decision |
|---|---|---|---|
| [0001](0001-monorepo-modular-monolith.md) | Monorepo with a Modular-Monolith Backend | Accepted | D1 |
| [0002](0002-backend-stack-python-fastapi-sqlalchemy.md) | Backend Stack — Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Alembic | Accepted | D2 |
| [0003](0003-agent-orchestration-langgraph-supervisor.md) | Agent Orchestration — LangGraph Supervisor Pattern | Accepted | D3 |
| [0004](0004-postgresql-pgvector-system-of-record.md) | PostgreSQL 16 + pgvector as the System of Record | Accepted | D4 |
| [0005](0005-neo4j-topology-graph-projection.md) | Neo4j 5 as a Rebuildable Topology/Knowledge Graph Projection | Accepted | D5 |
| [0006](0006-vendor-plugin-system-capability-interfaces.md) | Vendor Plugin System — Capability Interfaces, Registry, Entry Points | Accepted | D6 |
| [0007](0007-device-connectivity-stack.md) | Device Connectivity — netmiko + ntc-templates, pysnmp, httpx, Cloud SDKs | Accepted | D7 |
| [0008](0008-async-jobs-celery-redis.md) | Async Jobs — Celery + Redis with Dedicated Queues | Accepted | D8 |
| [0009](0009-multi-llm-provider-abstraction.md) | Multi-LLM Provider Abstraction | Accepted | D9 |
| [0010](0010-authentication-and-authorization.md) | Authentication and Authorization | Accepted | D10 |
| [0011](0011-security-model-credential-vault-audit-and-change-approval.md) | Security Model — Credential Vault, Append-Only Audit, and Change Approval | Accepted | D11 |
| [0012](0012-frontend-stack.md) | Frontend Stack | Accepted | D12 |
| [0013](0013-deployment-docker-compose-and-kubernetes-helm.md) | Deployment — Docker Compose for MVP, Kubernetes via Helm for Production | Accepted | D13 |
| [0014](0014-packet-analysis-pipeline.md) | Packet Analysis Pipeline | Accepted | D14 |
| [0015](0015-observability-logging-metrics-tracing.md) | Observability — Structured Logging, Metrics, Tracing, Health Endpoints | Accepted | D15 |
| [0016](0016-testing-and-ci-cd.md) | Testing and CI/CD | Accepted | D16 |
| [0017](0017-config-snapshot-storage-and-drift.md) | Configuration Snapshot Storage and Drift Detection | Accepted | M4 |
| [0018](0018-compliance-policy-rule-format.md) | Compliance Policy Rule Format | Accepted | M4 |
| [0019](0019-document-generation-and-rag.md) | Document Generation and RAG | Accepted | M4 |
| [0020](0020-changerequest-workflow-and-four-eyes-approval.md) | ChangeRequest Workflow and Four-Eyes Approval | Accepted | M5 |
| [0021](0021-config-deploy-restore-and-structured-rollback.md) | Config Deploy/Restore and Structured Rollback | Accepted | M5 |
| [0022](0022-infoblox-wapi-plugin-and-ddi-capability-interfaces.md) | Infoblox WAPI Plugin and DDI Capability Interfaces | Accepted | M5 |
| [0023](0023-packet-analysis-sandbox-and-pcap-retention.md) | Packet Analysis Sandbox and pcap Retention | Accepted | M5 |

**Conventions:** every binding decision D1–D16 has a current ADR; any deviation requires a superseding ADR (no silent drift — see `PRODUCTION.md` gate G-MNT). New capabilities, normalized models, agents, or vendors beyond the CLAUDE.md lists require an ADR *before* implementation (`REPO-STRUCTURE.md` §6–§7).
