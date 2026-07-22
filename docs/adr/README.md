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
| [0024](0024-spatiumddi-client-and-endpoint-capability-mapping.md) | SpatiumDDI Client and Endpoint↔Capability Mapping | Accepted | M-DDI |
| [0025](0025-cisco-nxos-plugin.md) | Cisco NX-OS Vendor Plugin | Accepted | P1 W0 |
| [0026](0026-juniper-junos-plugin.md) | Juniper JunOS Vendor Plugin | Accepted | P1 W0 |
| [0027](0027-bluecat-address-manager-plugin.md) | BlueCat Address Manager DDI Plugin | Accepted | P1 W0 |
| [0028](0028-oidc-sso-identity-federation.md) | OIDC / SSO Identity Federation | Accepted | P1 W0 |
| [0029](0029-kubernetes-helm-ga-chart-and-hardening.md) | Kubernetes/Helm GA Chart and Hardening Round 1 | Accepted | P1 W0 |
| [0030](0030-backup-and-disaster-recovery-baseline.md) | Backup and Disaster Recovery Baseline | Accepted | P1 W0 |
| [0031](0031-packet-sandbox-os-isolation.md) | Packet Capture Sandbox OS-Level Isolation | Accepted | P1 W0 |
| [0032](0032-kms-backed-master-key-and-rotation.md) | KMS-Backed Master Key and Rotation | Accepted | P1 W0 |
| [0033](0033-prompt-injection-eval-suite.md) | Prompt-Injection Eval Suite | Accepted | P1 W7 |
| [0034](0034-firewall-policy-capability-and-normalized-models.md) | `FIREWALL_POLICY` Capability + `NormalizedFirewallRule` / `NormalizedNatRule` | Accepted | P2 W0 |
| [0035](0035-palo-alto-panos-plugin.md) | Palo Alto PAN-OS Vendor Plugin (XML API) | Accepted | P2 W0 |
| [0036](0036-fortinet-fortios-plugin.md) | Fortinet FortiOS Vendor Plugin (REST + SSH fallback) | Accepted | P2 W0 |
| [0037](0037-security-agent.md) | Security Agent (Read-Only Analysis, Findings, Remediation→CR) | Accepted | P2 W0 |
| [0038](0038-audit-log-hash-chaining.md) | Audit-Log Hash Chaining + Daily Verification | Accepted | P2 W0 |
| [0039](0039-mtls-between-containers.md) | mTLS Between Containers (cert-manager) | Accepted | P2 W0 |
| [0040](0040-device-credential-rotation.md) | Device Credential Rotation + Per-Credential Scoping | Accepted | P2 W0 |
| [0041](0041-collector-network-segmentation.md) | Collector Network Segmentation (NetworkPolicy Egress) | Accepted | P2 W0 |
| [0042](0042-postgres-ha-cloudnativepg-sync-audit.md) | Postgres HA — CloudNativePG (1 primary + 2 replicas) + PgBouncer + Synchronous Audit Write Path | Accepted | P3 W0 |
| [0043](0043-api-hpa-keda-autoscaling.md) | api Horizontal Pod Autoscaler + KEDA Per-Queue Worker Autoscaling | Accepted | P3 W0 |
| [0044](0044-redis-sentinel-websocket-fanout.md) | Redis Sentinel + Stateless WebSocket Fan-Out via Redis Pub/Sub | Accepted | P3 W0 |
| [0045](0045-audit-siem-export.md) | Audit→SIEM Export (RFC5424 syslog + CEF over TLS + HTTPS/JSON push, at-least-once, export-lag SLO) | Accepted | P3 W0 |
| [0046](0046-observability-slo-enforcement.md) | Observability-SLO Enforcement (recording rules, multi-window burn-rate alerts, golden-signal dashboards, fault-injection MTTD) | Accepted | P3 W0 |
| [0047](0047-reliability-scale-drill-harness.md) | Reliability/Scale Drill Harness + N-2 Upgrade Rehearsal (reduced-scale mechanism proof + named certified-scale ceiling) | Accepted | P3 W0 |
| [0048](0048-kind-harness-gate-promotion.md) | kind-harness Gate Promotion — mTLS-handshake + collector-egress-deny live assertions → blocking in `all-gates` | Rejected | P3 W0 |
| [0049](0049-packet-analysis-sandbox-resolution.md) | Packet-Analysis Sandbox Resolution — executor-split (short-lived seccomp'd capture child), not a weaker worker | Accepted | Audit W3 |
| [0050](0050-f5-bigip-plugin.md) | F5 BIG-IP Vendor Plugin (iControl REST) — `ADC_SERVICES` Capability, Normalized ADC Models, UCS Archive Backup | Accepted | P4 |
| [0051](0051-vmware-plugin.md) | VMware vSphere Vendor Plugin (pyVmomi) — `VIRTUALIZATION_INVENTORY` Capability, Normalized Virtualization Models, Read-Only vCenter Role | Accepted | P4 |
| [0052](0052-application-dependency-topology.md) | Application-Dependency Topology — PG-Backed `Application`/`DEPENDS_ON` Layer, Four Derivation Sources, Direct-Write Tagging Under RBAC | Accepted | P4 |
| [0053](0053-compliance-audit-reporting.md) | Compliance & Audit Reporting Suite — Report Engine, Air-Gap CSV/PDF Rendering, Redaction Contract, SOC 2 CC-Series Default | Accepted | P4 |
| [0054](0054-retention-and-partitioning.md) | Retention and Partitioning Policy — Checkpoint-Anchored Audit Pruning, Archive-Then-Drop, and Bounded Snapshot Cleanup | Proposed | Audit W7 |
| [0055](0055-cloud-credential-and-normalization-model.md) | Shared Cloud Credentials and Network Normalization | Proposed | P5 W0 |
| [0056](0056-aws-plugin-route53.md) | AWS Network and Route53 Plugin | Proposed | P5 W0 |
| [0057](0057-azure-plugin.md) | Azure Network Plugin | Proposed | P5 W0 |
| [0058](0058-hybrid-topology-stitching.md) | Hybrid Cloud Topology Stitching | Proposed | P5 W0 |
| [0059](0059-durable-dispatch-outbox.md) | Durable Dispatch via Report Outbox and Platform Ratchet | Proposed | P5 W0 |
| [0060](0060-scale-certification-methodology.md) | Scale Certification Methodology | Proposed | P5 W0 |

**Conventions:** every binding decision D1–D16 has a current ADR; any deviation requires a superseding ADR (no silent drift — see `PRODUCTION.md` gate G-MNT). New capabilities, normalized models, agents, or vendors beyond the CLAUDE.md lists require an ADR *before* implementation (`REPO-STRUCTURE.md` §6–§7).
