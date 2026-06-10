# Open Questions for the Platform Owner

**Project:** AI Network Operations Platform
**Author:** Consultant Agent
**Date:** 2026-06-09
**Status:** Owner offline — per `DECISIONS-BRIEF.md` §9 and §5, the build proceeds on each **RECOMMENDED DEFAULT** below until answered. Each question maps 1:1 to assumption `An` in `ASSUMPTIONS.md` and to the matching gap in `GAP-ANALYSIS.md`.

**Answering:** reply with the question ID and either "accept default" or your answer. Any changed answer triggers a review of the linked assumption's "where baked in" list.

---

## Q1 — Scale targets

**Question:** How many managed devices, sites, and concurrent users must v1 support, and what is the architectural ceiling we must not preclude?

**Why it matters:** drives Postgres partitioning of `raw_artifacts`/`audit_log` in the first migration, Celery worker sizing (D8), Neo4j heap, and the topology rendering strategy (Cytoscape.js degrades past a few thousand visible nodes).

**Options considered:**
- (a) Small: 500 devices / 10 sites / 10 users — trivially easy, undersells "enterprise".
- (b) Mid: 2,000 devices / 50 sites / 25 users, ceiling 10,000 — covers most single-org enterprises.
- (c) Large: 25,000+ devices — forces sharding, TimescaleDB-style partitioning, and clustered Neo4j (not available in Community) now.

**RECOMMENDED DEFAULT:** **(b) Design point 2,000 devices / 50 sites / 25 concurrent users; ceiling 10,000 devices.** Partition `raw_artifacts` and `audit_log` by month from migration one (cheap insurance); everything else sized for the design point.

## Q2 — HA/DR expectations

**Question:** What RPO/RTO must the platform meet, and is active/active required?

**Why it matters:** Postgres holds the credential vault and the only normalized network record. Neo4j Community (D5) cannot cluster or hot-backup — acceptable only because it is a rebuildable projection.

**Options considered:**
- (a) Best effort: nightly backups only.
- (b) Tiered: MVP/Compose = RPO 24h / RTO 4h; production/K8s = streaming-replica Postgres, RPO ≤5 min / RTO ≤1h, active/passive.
- (c) Active/active multi-site — requires distributed Postgres and a Neo4j edition change; disproportionate for a NetOps tool.

**RECOMMENDED DEFAULT:** **(b) Tiered active/passive.** Neo4j excluded from backup scope by design (rebuilt from Postgres per D5); Redis treated as disposable.

## Q3 — Multi-tenancy

**Question:** Does one deployment ever serve multiple organizations (MSP model), or is it strictly one org per instance?

**Why it matters:** tenancy touches every table in brief §6, Neo4j labels, JWT claims, and RBAC. It is the single most expensive retrofit in the system and must be decided before the first Alembic migration (M1).

**Options considered:**
- (a) Single-tenant; MSPs deploy one instance per customer (cheap via the D13 Helm chart).
- (b) Soft multi-tenancy: `tenant_id` column everywhere + row-level filtering — pervasive complexity, weak isolation for a credential-holding system.
- (c) Hard multi-tenancy: schema-per-tenant — heavy operational machinery.

**RECOMMENDED DEFAULT:** **(a) Single-tenant per deployment.** Containment: all data access flows through the service layer so a tenant filter could later be introduced centrally; no raw table access from routers or agents.

## Q4 — RBAC granularity

**Question:** Are the four D10 roles (`viewer`/`operator`/`engineer`/`admin`) global, or scoped to sites/device groups? And which roles may approve ChangeRequests?

**Why it matters:** scoped RBAC changes the permission model, every API dependency, and agent tool authorization (agents inherit user permissions per brief §7).

**Options considered:**
- (a) Global roles only; approval = `engineer`+.
- (b) Site-scoped role assignments — realistic enterprise ask, significant M0/M1 complexity.
- (c) Full ABAC/policy engine (OPA) — overkill for v1.

**RECOMMENDED DEFAULT:** **(a) Global roles in v1; ChangeRequest approval requires `engineer` or `admin`, and requester ≠ approver per D11.** Device-group scoping goes on the production roadmap; the permission-check call site is kept to one module (`core/security.py`) so scoping lands in one place.

## Q5 — SSO/OIDC provider

**Question:** Which IdP must work out of the box, and how do IdP groups map to roles?

**Why it matters:** D10 says "OIDC (pluggable)" but M0's auth skeleton needs a concrete provider to develop and test against; group→role mapping determines whether admins manage users in the IdP or in the platform.

**Options considered:**
- (a) Keycloak as reference (self-hostable, fits "local first"), generic OIDC discovery + PKCE so Entra ID/Okta work unmodified.
- (b) Entra ID first — most common enterprise IdP, but not self-hostable; awkward for air-gapped (Q8).
- (c) SAML support too — legacy reach, large surface; defer.

**RECOMMENDED DEFAULT:** **(a) Keycloak as the reference IdP (ships in the dev Compose profile); strict generic OIDC + PKCE; configurable claim→role mapping; local accounts remain enabled as break-glass.** SAML deferred until a customer demands it.

## Q6 — Credential management & rotation

**Question:** Is the built-in D11 vault sufficient, or is integration with an enterprise secret store (HashiCorp Vault, CyberArk) required? What rotation policy applies?

**Why it matters:** M1 cannot ship discovery without credential handling; some enterprises mandate centralized secret stores and will reject a tool with its own vault.

**Options considered:**
- (a) Built-in vault only (D11), manual rotation + age reporting.
- (b) (a) + pluggable secret-backend driver, HashiCorp Vault Transit implemented post-MVP.
- (c) Automated rotation (platform changes device passwords) — high blast radius; a failed rotation locks the platform out of the device.

**RECOMMENDED DEFAULT:** **(b).** Built-in vault per D11 for v1; per-device credentials with site-level defaults; manual rotation with a 90-day age warning report; the D11 master-key interface designed now to accept a Vault Transit driver later (PROPOSED). No automated device-password rotation in v1; no plaintext break-glass retrieval ever.

## Q7 — Compliance regimes

**Question:** Which compliance regime(s) must v1 satisfy: SOC2, PCI-DSS, FedRAMP, ISO 27001, none?

**Why it matters:** FedRAMP forces FIPS-validated crypto and documentation that would consume the MVP; PCI sets audit-retention floors; SOC2 mostly aligns with what D11/D16 already build.

**Options considered:**
- (a) SOC2 Type II-aligned controls, no formal certification claims.
- (b) PCI-ready: adds segmentation attestation, 1-year minimum audit retention (already exceeded by Q13 default).
- (c) FedRAMP — different product; do not attempt in v1.

**RECOMMENDED DEFAULT:** **(a) SOC2 Type II-aligned.** Use the `cryptography` library (FIPS-capable OpenSSL backend) so a future FIPS mode is configuration, not rewrite. Document the control mapping in `docs/` as features land.

## Q8 — Air-gapped operation

**Question:** Must the platform operate with zero internet access, and what is the offline update mechanism?

**Why it matters:** decides model distribution (Ollama files), image delivery, `ntc-templates` pinning (D7), and which plugins/features can be on the critical path.

**Options considered:**
- (a) Internet assumed; air-gap unsupported.
- (b) Air-gap-capable core: offline release bundle (images + models + templates); egress-requiring features (AWS/Azure/Route53 plugins, hosted LLM profiles, CVE feeds) optional and absent in the air-gapped profile.
- (c) Air-gap-only posture — forbids hosted LLM profiles entirely, contradicting D9's opt-in providers.

**RECOMMENDED DEFAULT:** **(b) Air-gap-capable core with an offline release bundle.** Nothing on the discovery/topology/troubleshooting/config-management critical path may require egress.

## Q9 — LLM hosting constraints (GPU, egress policy)

**Question:** What GPU hardware can deployments assume, and what data may leave the environment when an external LLM profile (D9) is enabled?

**Why it matters:** model capability on available hardware determines agent quality (D3 supervisor needs reliable tool calling). Prompts will contain device configs, which contain secret material — egress policy is a security decision, not a preference.

**Options considered:**
- (a) CPU-only baseline — agents too slow/weak; bad first impression.
- (b) One 24 GB GPU (L4/RTX 4090 class) running an 8–14B instruct model; CPU documented as degraded mode.
- (c) Multi-GPU 70B-class baseline — excludes most buyers.

**RECOMMENDED DEFAULT:** **(b), plus two PROPOSED security requirements:** (1) a mandatory redaction layer in `backend/app/llm/` that strips vendor secret patterns (SNMP communities, type-7/9 material, SNMPv3 strings, BGP/RADIUS keys) from all prompt content for **all** providers; vault credentials never enter prompts under any profile. (2) An agent-eval suite (golden troubleshooting transcripts) shipping with M3 to qualify local models. Default egress policy: **no device-derived data to external providers unless an admin explicitly enables a hosted profile**, and then only redacted content.

## Q10 — Streaming telemetry (gNMI / NetFlow / sFlow)

**Question:** CLAUDE.md omits streaming telemetry entirely. Is it intentionally out of scope, and if not, when is it wanted?

**Why it matters:** without it, the Troubleshooting Agent reasons over poll-time snapshots only — no "what changed at 14:32", no flow-level evidence for ACL/firewall analysis. Also affects the plugin contract: adding capabilities later must not break D6.

**Options considered:**
- (a) Out of scope permanently.
- (b) Out of scope through M5; reserve `TELEMETRY_GNMI`, `FLOW_NETFLOW`, `FLOW_SFLOW` capability names in the §4 enum now (PROPOSED); telemetry ingestion engine on the production roadmap with its own ADR.
- (c) In MVP — would displace M4/M5 deliverables; collectors are a substantial subsystem.

**RECOMMENDED DEFAULT:** **(b).** Cheap now (enum names only), preserves the plugin contract, defers the real cost to a deliberate ADR.

## Q11 — IPv6 scope

**Question:** Must v1 discover, model, and troubleshoot IPv6, and must the platform manage devices over IPv6 transport?

**Why it matters:** address-family assumptions fossilize in the M1 schema (normalized models, `inet`/`cidr` columns, Neo4j `IPAddress`/`Subnet` nodes). Dual-stack is nearly free now and a rewrite later.

**Options considered:**
- (a) IPv4-only v1 — guaranteed rework.
- (b) Dual-stack data model + Tier-1 parser support from M1; IPv6-only management plane code-supported but untested in v1.
- (c) Full IPv6 parity including IPv6-only management, certified — testing burden too high for v1.

**RECOMMENDED DEFAULT:** **(b).** All address fields family-agnostic (`ipaddress` types, Postgres `inet`/`cidr`); BGP analysis covers both AFs; OSPFv3 ships alongside OSPF.

## Q12 — Change windows & maintenance-mode behavior

**Question:** Must approved changes execute only inside defined windows, and how should the platform behave during planned maintenance (drift alarms, topology churn)?

**Why it matters:** D11's lifecycle executes immediately on approval — most enterprises forbid that. Without maintenance mode, M4 drift detection generates false alarms during every planned work and trains operators to ignore alerts.

**Options considered:**
- (a) Execute on approval only; no windows (status quo D11).
- (b) PROPOSED additive fields: optional `execute_not_before`/`execute_not_after` on ChangeRequests (worker holds until window; lapse → `failed: window_expired`; admin emergency override with mandatory justification, audited) + `maintenance_until` flag on devices suppressing drift/topology *alerts* while still *recording* snapshots and diffs.
- (c) Full calendar/freeze-period subsystem with recurrence — production roadmap material.

**RECOMMENDED DEFAULT:** **(b).** Additive to D11 (no state-machine change); preserves audit-everything — only the alerting is suppressed, never the recording.

## Q13 — Data retention (pcaps, configs, audit, artifacts)

**Question:** What are the retention periods per data class?

**Why it matters:** pcaps may contain payload credentials/PII (long retention = liability); audit logs are the inverse (short retention = liability). Cleanup jobs must exist or volumes fill.

**Options considered:**
- (a) Keep everything forever — disk growth, pcap liability.
- (b) Per-class configurable defaults: pcaps 30 days + 50 GB cap; `raw_artifacts` 90 days; `reasoning_traces` 365 days; `config_snapshots` indefinite; `audit_log` never auto-purged (7-year guidance + export tooling); `discovery_runs` metadata 180 days.
- (c) Aggressive minimal (everything 30 days) — destroys diagnostic and audit value.

**RECOMMENDED DEFAULT:** **(b)**, enforced by scheduled Celery cleanup tasks on the existing D8 queues, configurable in `core/config.py`.

## Q14 — Alerting & notification channels

**Question:** How are humans notified (pending approvals, drift, failed jobs), and through which channels?

**Why it matters:** the entire D11 approval workflow stalls if no one learns a ChangeRequest is pending. Neither CLAUDE.md nor the brief defines any notification mechanism.

**Options considered:**
- (a) In-app only — approvals rot until someone logs in.
- (b) In-app + SMTP email + one generic signed webhook (reaches Slack/Teams/PagerDuty inbound webhooks without per-product connectors); air-gap safe.
- (c) Native Slack/Teams/PagerDuty connectors — three integrations to maintain in v1.

**RECOMMENDED DEFAULT:** **(b)**, as a PROPOSED `services/notifications.py` module landing with M5. Launch events: CR pending/executed/failed, drift detected, discovery run failed, credential age warning.

## Q15 — Existing source-of-truth integrations (NetBox, ITSM)

**Question:** Is the platform's inventory authoritative, or subordinate to an existing NetBox/Nautobot or CMDB? Is ServiceNow change integration required?

**Why it matters:** determines whether we build sync (conflict-prone) or import (simple), and whether ChangeRequests must mirror into an ITSM.

**Options considered:**
- (a) Platform-authoritative observed state; no integrations v1.
- (b) (a) + one-way NetBox import (seed devices/sites) post-MVP, then a read-only intended-vs-observed comparison on the production roadmap.
- (c) Bidirectional NetBox sync — conflict resolution machinery; reject without a dedicated ADR.

**RECOMMENDED DEFAULT:** **(b).** The platform owns *observed* state (its core value); NetBox remains the *intended* source where present. ServiceNow deferred — the Q14 webhook can post CR events to ServiceNow inbound APIs as a bridge.

## Q16 — Licensing for commercial vendor APIs

**Question:** Who provides licensed instances of Infoblox, BlueCat, F5 BIG-IP, PAN-OS, FortiOS for development and CI?

**Why it matters:** D16 requires tests for every feature, but five committed vendor APIs (D7) require licensed products to exercise. This sequences plugin development.

**Options considered:**
- (a) Project purchases lab licenses — budget unknown, assume none.
- (b) Customer/owner-provided instances; CI uses recorded/mocked API fixtures (httpx transport mocks) in-repo; free/virtual platforms (Arista cEOS-lab, containerlab, FRR) for live Tier-1 integration tests.
- (c) Skip commercial-vendor plugins until licenses appear — breaks v1.0 GA tiering (GAP-ANALYSIS C2).

**RECOMMENDED DEFAULT:** **(b).** Each plugin README documents license/API-version prerequisites; M1's IOS/IOS-XE/EOS order stands because it front-loads license-free vendors.

## Q17 — Backup/restore of the platform itself

**Question:** What is the supported backup/restore mechanism for the platform's own data?

**Why it matters:** Postgres holds the credential vault, audit log, and all normalized state; pcap/config volumes live outside the DB. No backup statement exists in either document.

**Options considered:**
- (a) Operator's problem — undermines "enterprise ready".
- (b) Built-in: scheduled `pg_dump` + pcap/config volume snapshot; Compose = cron + `scripts/backup`; K8s = Helm CronJob; documented restore runbook; **Neo4j explicitly excluded** (rebuildable projection per D5) with a `rebuild-projection` command as its "restore".
- (c) Full backup operator/PITR (pgBackRest) — production roadmap.

**RECOMMENDED DEFAULT:** **(b)** for v1, with pgBackRest PITR noted on the production roadmap. Restore is rehearsed in CI at least once before v1.0 (a restore that has never run is not a backup).

## Q18 — Discovery cadence & device-safety guardrails

**Question:** How often does discovery run, and what concurrency/command limits protect fragile devices?

**Why it matters:** unbounded SSH/SNMP fan-out can spike control planes on older devices; discovery is the platform's highest-frequency device interaction and the first thing that will get it banned from a production network.

**Options considered:**
- (a) Continuous aggressive polling — best freshness, highest risk.
- (b) Full sweep every 24h + on-demand per-device/site runs; ≤2 concurrent sessions per device; ≤50 platform-wide (Celery `discovery` queue concurrency, D8); read-only command allowlist for discovery; exponential backoff on failures.
- (c) Manual-only discovery — stale topology defeats the mission.

**RECOMMENDED DEFAULT:** **(b)**, all limits configurable. Streaming freshness is the Q10 telemetry item, not a polling-rate problem.

## Q19 — Approval throughput at scale (unit of approval)

**Question:** When one logical change touches hundreds of devices, is approval per-device or per-ChangeRequest? Are pre-approved change templates ever acceptable?

**Why it matters:** per-device approval at fleet scale trains approvers to rubber-stamp — worse security than fewer, meaningful approvals. But CLAUDE.md mandates human approval for changes; any auto-approval mechanism is a constitution-level call.

**Options considered:**
- (a) One ChangeRequest per device operation — unusable at scale.
- (b) One ChangeRequest = one logical change containing N device operations, approved atomically, with per-device diff preview and per-device rollback. Consistent with D11's letter and spirit.
- (c) Pre-approved templates / policy auto-approval — **constitution amendment**; requires explicit owner sign-off; deferred.

**RECOMMENDED DEFAULT:** **(b).** Option (c) stays parked on the production roadmap behind an owner decision; the build never backs into it silently.

---

*Register of the working assumptions these defaults create: `docs/consultant/ASSUMPTIONS.md` (A1–A19).*
