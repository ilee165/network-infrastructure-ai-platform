# Working-Assumption Register

**Project:** AI Network Operations Platform
**Author:** Consultant Agent
**Date:** 2026-06-09
**Status:** Active. Each assumption `An` is the in-force default for open question `Qn` in `QUESTIONS.md`; the build proceeds on these until the platform owner answers. When an answer arrives, the assumption is marked `CONFIRMED` or `OVERTURNED`, and every location in its "where baked in" list is reviewed.

**Lifecycle:** `ACTIVE → CONFIRMED | OVERTURNED (→ rework ticket per baked-in location)`

## Summary

| ID | Q-ref | Assumption (short) | Risk if wrong |
|----|-------|--------------------|---------------|
| A1 | Q1 | 2k devices / 50 sites / 25 users; ceiling 10k | High |
| A2 | Q2 | Tiered active/passive; RPO 24h→5min by tier | Medium |
| A3 | Q3 | Single-tenant per deployment | **Severe** |
| A4 | Q4 | Global roles; `engineer`+ approves | Medium |
| A5 | Q5 | Keycloak reference IdP; generic OIDC + PKCE | Low |
| A6 | Q6 | Built-in vault; manual rotation; Vault-Transit-ready interface | Medium |
| A7 | Q7 | SOC2-aligned; no FedRAMP/PCI in v1 | High |
| A8 | Q8 | Air-gap-capable core; egress features optional | Medium |
| A9 | Q9 | 24 GB GPU / 8–14B model; mandatory prompt redaction | High |
| A10 | Q10 | Telemetry out of scope through M5; enum names reserved | Medium |
| A11 | Q11 | Dual-stack data model from M1 | **Severe** (if reversed late) |
| A12 | Q12 | Window fields + maintenance flag, additive to D11 | Low |
| A13 | Q13 | Per-class retention defaults (pcap 30d … audit never) | Medium |
| A14 | Q14 | In-app + SMTP + generic webhook notifications | Low |
| A15 | Q15 | Platform-authoritative observed state; NetBox import post-MVP | Medium |
| A16 | Q16 | Customer-provided vendor licenses; fixture-based CI | Medium |
| A17 | Q17 | pg_dump + volume snapshots; Neo4j never backed up | Low |
| A18 | Q18 | 24h sweep; ≤2/device, ≤50 global sessions | Low |
| A19 | Q19 | One CR = one logical change, atomic approval | Medium |

---

## A1 — Scale design point *(→ Q1)*

**Assumption:** v1 is sized for 2,000 devices / 50 sites / 25 concurrent users, with a 10,000-device architectural ceiling.

**Impact if wrong:** larger targets force Postgres re-partitioning beyond the monthly scheme, Neo4j Community memory limits, Celery fleet redesign, and a topology UI rework; smaller targets mean mild over-engineering only.

**Where baked in:** first Alembic migration (monthly partitions on `raw_artifacts`, `audit_log` — `backend/alembic/`); Celery concurrency defaults (`backend/app/workers/`, `deploy/docker/docker-compose.yml`, Helm values); site-scoped topology rendering in `frontend/` (Cytoscape.js, D12); Neo4j heap settings in `deploy/`.

## A2 — HA/DR tiers *(→ Q2)*

**Assumption:** Compose tier = RPO 24h / RTO 4h; K8s tier = Postgres streaming replica, RPO ≤5 min / RTO ≤1h, active/passive. No active/active.

**Impact if wrong:** active/active demand invalidates the single-writer Postgres design and Neo4j Community choice (D5) — major re-architecture; stricter RPO alone is absorbable (PITR via pgBackRest).

**Where baked in:** `deploy/docker/` backup cron + `scripts/backup`; Helm chart replica topology (`deploy/kubernetes/`); D5's rebuildable-projection rule (the stated justification for not backing up Neo4j); restore runbook in `docs/`.

## A3 — Single tenancy *(→ Q3)*

**Assumption:** one deployment serves exactly one organization; MSPs run one instance per customer.

**Impact if wrong:** **the most expensive reversal in the register** — `tenant_id` retrofit across every table in brief §6, Neo4j label partitioning, JWT claim and RBAC changes, plugin credential resolution. Weeks of rework plus migration risk on a credential-holding system.

**Where baked in:** every SQLAlchemy model in `backend/app/models/` (no tenant column); Neo4j schema (§6 labels, unpartitioned); JWT claims in `core/security.py`; mitigation: all data access flows through `backend/app/services/` so a central tenant filter has exactly one insertion point.

## A4 — Global RBAC; engineer-level approval *(→ Q4)*

**Assumption:** the four D10 roles are global (no site/device-group scoping) in v1; ChangeRequest approval requires `engineer` or `admin` with requester ≠ approver (D11).

**Impact if wrong:** scoped RBAC touches every API dependency and agent tool authorization (agents inherit user permissions, brief §7); contained because permission checks are centralized.

**Where baked in:** single permission-check module `backend/app/core/security.py`; FastAPI router dependencies in `backend/app/api/v1/`; approval validation in `services/` change management; agent tool-wrapper authorization in `agents/framework/`.

## A5 — Keycloak reference IdP *(→ Q5)*

**Assumption:** Keycloak is the reference OIDC IdP; implementation is strict generic OIDC discovery + PKCE with configurable claim→role mapping; local accounts remain as break-glass; no SAML.

**Impact if wrong:** low — generic OIDC means an Entra ID/Okta answer is config, not code. A SAML mandate adds a dependency and login flow (bounded, M0-localized rework).

**Where baked in:** OIDC client in `backend/app/core/security.py` (M0 auth skeleton); Keycloak service in the dev Compose profile (`deploy/docker/`); claim-mapping config in `core/config.py`; frontend login flow.

## A6 — Built-in credential vault, manual rotation *(→ Q6)*

**Assumption:** D11's encrypted vault table is the v1 store; per-device credentials with site defaults; manual rotation with 90-day age warnings; master-key interface designed to accept a HashiCorp Vault Transit driver later (PROPOSED); no automated device-password rotation; no plaintext retrieval.

**Impact if wrong:** a hard "CyberArk/Vault only, no local storage" mandate replaces the vault table with broker-pattern retrieval — significant change to `services/credentials.py` and every plugin connection path; the keyed interface limits blast radius for the master-key half.

**Where baked in:** `device_credentials` table (brief §6); `backend/app/services/credentials.py`; master-key provider interface in `core/security.py` (env/file/KMS per D11, Transit-ready); credential-age report query; plugin connection bootstrap in `plugins/base.py`.

## A7 — SOC2-aligned, no FedRAMP/PCI *(→ Q7)*

**Assumption:** v1 builds SOC2 Type II-aligned controls; no FedRAMP or PCI commitments.

**Impact if wrong:** FedRAMP would impose FIPS-validated modules, US-person and boundary documentation — effectively a different product timeline. Mitigated: crypto uses the `cryptography` library (FIPS-capable backend), so FIPS mode is configuration; D11 audit log and Q13 retention already exceed PCI floors.

**Where baked in:** crypto library choice in `core/security.py`; audit-log design (D11, append-only); retention defaults in `core/config.py` (A13); control-mapping doc planned in `docs/`.

## A8 — Air-gap-capable core *(→ Q8)*

**Assumption:** the core platform runs with zero egress; releases ship as offline bundles (images + Ollama models + pinned `ntc-templates`); AWS/Azure/Route53 plugins, hosted LLM profiles, and CVE feeds are optional and absent from the air-gapped profile.

**Impact if wrong:** if air-gap is *not* required, we carry mild packaging overhead (acceptable). If air-gap is *stricter* (no removable-media updates), an update-server story is needed — packaging-level, not architectural.

**Where baked in:** release bundle tooling in `scripts/`; `ntc-templates` pinned in `backend/pyproject.toml` (D7); plugin optionality via the D6 registry (cloud plugins simply not installed); D9 `local` profile as default; no egress on the discovery/topology/config critical path (enforced by code review + the D16 CI image scan running offline-capable).

## A9 — LLM reference hardware + mandatory redaction *(→ Q9)*

**Assumption:** reference local target is one 24 GB GPU running an 8–14B instruct model via Ollama (CPU = documented degraded mode); a mandatory redaction layer strips vendor secret patterns from all prompt content for all providers; vault credentials never enter prompts; an agent-eval suite ships with M3; hosted profiles receive only redacted content and are admin-enabled.

**Impact if wrong:** if customers lack any GPU, local agent quality disappoints (reputational, mitigated by honest degraded-mode UX per GAP-ANALYSIS C6); if owner permits raw-config egress, redaction becomes optional config (easy); if owner *forbids* hosted profiles entirely, D9 external profiles are disabled (trivial).

**Where baked in:** redaction pipeline + provider registry in `backend/app/llm/` (PROPOSED module addition, D9); Ollama Compose profile defaults (`deploy/docker/`); eval suite in `backend/tests/` landing with M3; model recommendations in docs; per-agent model overrides in the D9 registry.

## A10 — Streaming telemetry deferred; enum names reserved *(→ Q10)*

**Assumption:** gNMI/NetFlow/sFlow are out of scope through M5; `TELEMETRY_GNMI`, `FLOW_NETFLOW`, `FLOW_SFLOW` are reserved in the `Capability` enum (names only — PROPOSED addition to brief §4); ingestion engine deferred to a production-roadmap ADR.

**Impact if wrong:** if telemetry is wanted in MVP, M4/M5 scope must be displaced and a collector subsystem designed — major schedule impact; the reserved names ensure no plugin-contract break either way.

**Where baked in:** `Capability` enum in `backend/app/plugins/base.py`; absence of a telemetry module under `backend/app/engines/`; Troubleshooting Agent evidence model (snapshot-based) in `agents/troubleshooting/`; production roadmap entry in `docs/roadmap/PRODUCTION.md`.

## A11 — Dual-stack IPv6 data model from M1 *(→ Q11)*

**Assumption:** all address/prefix storage is family-agnostic (Python `ipaddress`, Postgres `inet`/`cidr`) from the first migration; Tier-1 parsers collect IPv6 from M1; BGP analysis covers both AFs; OSPFv3 ships with OSPF; IPv6-only management transport is code-supported but untested in v1.

**Impact if wrong:** essentially riskless in the stated direction (dual-stack costs little). The severe risk is only if this default were *reversed* to IPv4-only and IPv6 demanded later — schema and parser rewrite. Holding this assumption removes a one-way door.

**Where baked in:** normalized Pydantic models in `backend/app/schemas/` (D7); `inet`/`cidr` columns in `models/`; Neo4j `IPAddress`/`Subnet` nodes (§6); Tier-1 plugin parsers in `plugins/vendors/{cisco_ios,cisco_iosxe,eos}/`; routing-analysis prompts in `llm/` templates.

## A12 — Change windows + maintenance mode (additive) *(→ Q12)*

**Assumption:** ChangeRequests gain optional `execute_not_before`/`execute_not_after` (worker holds approved CRs; lapse → `failed: window_expired`; admin override with mandatory audited justification); devices gain `maintenance_until` suppressing drift/topology *alerts* while snapshots/diffs are still *recorded*. Both PROPOSED, additive to D11's state machine.

**Impact if wrong:** if a full freeze-calendar subsystem is required, the fields remain valid primitives beneath it — low rework; if windows are rejected outright, two nullable columns are dropped.

**Where baked in:** `change_requests` columns + executor logic in `services/` and `workers/` (M5); `devices.maintenance_until` + alert-suppression checks in `engines/config_mgmt/` drift detection and `engines/topology/` diff (M4); approval UI in `frontend/`.

## A13 — Retention defaults *(→ Q13)*

**Assumption:** pcaps 30 days + 50 GB volume cap; `raw_artifacts` 90 days; `reasoning_traces` 365 days; `config_snapshots` indefinite; `audit_log` never auto-purged (7-year guidance, export tooling); `discovery_runs` metadata 180 days. All configurable.

**Impact if wrong:** values are config, so changes are cheap — *except* data already deleted under a too-short default is unrecoverable (pcap/raw-artifact classes). Conservative defaults chosen for exactly that reason.

**Where baked in:** retention settings in `backend/app/core/config.py`; scheduled cleanup tasks in `workers/` on D8 queues; `pcap_metadata` + volume management in `engines/packet/` (D14); audit-export tool in `scripts/`.

## A14 — Notification channels *(→ Q14)*

**Assumption:** v1 ships in-app, SMTP, and one generic signed webhook (covers Slack/Teams/PagerDuty inbound); PROPOSED `backend/app/services/notifications.py`, landing with M5; launch events: CR pending/executed/failed, drift detected, discovery failed, credential-age warning.

**Impact if wrong:** native connectors are additive channel drivers behind the same service interface — low rework; channel abstraction designed for it.

**Where baked in:** `services/notifications.py` (PROPOSED); event emission points in change-management `services/`, `engines/config_mgmt/`, `engines/discovery/`; SMTP/webhook settings in `core/config.py`; in-app notification UI in `frontend/`.

## A15 — Platform-authoritative observed state *(→ Q15)*

**Assumption:** the platform owns discovered (observed) inventory; no NetBox/ITSM integration in v1; one-way NetBox import post-MVP; read-only intended-vs-observed comparison on the production roadmap; no bidirectional sync without a dedicated ADR; ServiceNow bridged via the A14 webhook if needed.

**Impact if wrong:** a "NetBox is authoritative" mandate inverts the inventory model — devices seeded from NetBox rather than discovery-first; medium rework in `engines/discovery/` seed logic and inventory `services/`, schema largely survives.

**Where baked in:** discovery-first seed expansion in `engines/discovery/`; inventory ownership in `services/`; absence of sync workers; planned import utility in `scripts/` (post-MVP).

## A16 — Customer-provided vendor licenses; fixture-based CI *(→ Q16)*

**Assumption:** no project budget for Infoblox/BlueCat/F5/PAN-OS/FortiOS licenses; CI tests those plugins against recorded/mocked API fixtures (httpx transport mocks) in-repo; live integration tests use free/virtual platforms (cEOS-lab, containerlab, FRR) for Tier-1; plugin READMEs document prerequisites.

**Impact if wrong (i.e., no licensed instances ever materialize):** commercial-vendor plugins ship validated against fixtures only — risk of real-world API drift at first customer contact; mitigated by fixture versioning against documented API versions and the C2 tiering that defers most of them past v1.0.

**Where baked in:** test strategy under `backend/tests/` mirroring `plugins/vendors/` (D16); fixture stores in-repo; CI workflow in `.github/workflows/`; M1 plugin ordering (IOS/IOS-XE/EOS first, brief §8).

## A17 — Platform backup = pg_dump + volume snapshots; Neo4j excluded *(→ Q17)*

**Assumption:** scheduled `pg_dump` + pcap/config volume snapshots (Compose cron + `scripts/backup`; Helm CronJob on K8s); documented, CI-rehearsed restore; Neo4j never backed up — its restore is a `rebuild-projection` command per D5; pgBackRest PITR on the production roadmap.

**Impact if wrong:** stricter PITR demands move the roadmap item forward (additive); if anyone ever writes Neo4j-only data the exclusion becomes a data-loss bug — guarded by D5's projection rule and the `knowledge/`-only Cypher boundary (GAP-ANALYSIS C1).

**Where baked in:** `scripts/backup` + restore runbook; Helm CronJob in `deploy/kubernetes/`; `rebuild-projection` management command in `engines/topology/`; restore rehearsal job in `.github/workflows/`.

## A18 — Discovery cadence & safety caps *(→ Q18)*

**Assumption:** full sweep every 24h + on-demand runs; ≤2 concurrent sessions per device; ≤50 platform-wide; read-only command allowlist during discovery; exponential backoff. All configurable.

**Impact if wrong:** pure configuration — values change without code impact; the *existence* of the cap/allowlist machinery is the architectural part, and removing it would never be requested.

**Where baked in:** job planner concurrency caps in `engines/discovery/`; Celery `discovery` queue concurrency (D8) in `workers/` and deploy configs; per-device session semaphore in the connection layer over netmiko (D7); command allowlist in `plugins/base.py` discovery capabilities.

## A19 — One ChangeRequest = one logical change *(→ Q19)*

**Assumption:** a ChangeRequest groups all device operations of one logical change and is approved atomically by a human (`engineer`+, requester ≠ approver), with per-device diff preview and per-device rollback. Pre-approved templates / auto-approval are parked pending an explicit owner decision (constitution amendment — CLAUDE.md "Human approval for changes").

**Impact if wrong:** per-device approval demanded → UI/UX change plus approval fan-out, model survives (operations are already child rows); auto-approval permitted → additive policy engine on top of the same lifecycle.

**Where baked in:** `change_requests` + child operation rows in `models/` (brief §6); approval gate in `agents/framework/` (§5 read/write separation — "blocks until human approval"); diff-preview and rollback UX in `frontend/` approval views (M5); D11 lifecycle unchanged.

---

*Cross-references: gaps in `GAP-ANALYSIS.md`, questions/defaults in `QUESTIONS.md`. Any owner answer that overturns an assumption requires a sweep of that entry's "where baked in" list before further milestone work in the affected area.*
