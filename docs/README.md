# Documentation Index

**Project:** AI Network Operations Platform — self-hosted, multi-vendor AI Network Engineer.
**Constitution:** [`../CLAUDE.md`](../CLAUDE.md) (requirements, vendors, agents, principles). Everything below derives from it.

## architecture/

| Document | Description |
|---|---|
| [DECISIONS-BRIEF.md](architecture/DECISIONS-BRIEF.md) | The binding decisions D1–D16 translating CLAUDE.md into a buildable architecture; every other artifact must be consistent with it. |
| [DIAGRAMS.md](architecture/DIAGRAMS.md) | C4 context/container diagrams, agent orchestration, discovery pipeline, Neo4j data model, change-approval sequence, deployment topologies (Mermaid). |
| [REPO-STRUCTURE.md](architecture/REPO-STRUCTURE.md) | Normative file-level repository blueprint for Phase 2 scaffolding: trees, module-boundary rules, naming conventions, test layout, plugin/agent checklists, PROPOSED register. |

## adr/

| Document | Description |
|---|---|
| [README.md](adr/README.md) | Index of ADR-0001..0053. ADRs 0001–0016 are the binding D1–D16 decisions (Accepted); 0017–0024 are M4/M5/M-DDI milestone-feature ADRs (Accepted); 0025–0033 are P1 wave ADRs (Accepted); 0034–0041 are P2 wave ADRs (Accepted); 0042–0049 are P3-wave/audit ADRs (Accepted, except 0048 Rejected); 0050–0053 are P4 wave ADRs (Proposed). |
| `0001`–`0016` | One ADR per binding decision: monorepo, backend stack, LangGraph orchestration, Postgres+pgvector, Neo4j projection, plugin system, device connectivity, Celery jobs, multi-LLM abstraction, authn/z, security model, frontend stack, deployment, packet analysis, observability, testing/CI-CD. |
| `0017`–`0024` | Milestone-feature ADRs: config snapshot/drift, compliance rules, doc generation/RAG, ChangeRequest workflow, config deploy/restore, Infoblox WAPI/DDI capability interfaces, packet sandbox, SpatiumDDI client. |
| `0025`–`0033` | P1 wave ADRs: NX-OS/JunOS/BlueCat plugins, OIDC/SSO, K8s/Helm GA chart, backup/DR baseline, packet-sandbox OS isolation, KMS-backed master key, prompt-injection eval suite. |
| `0034`–`0041` | P2 wave ADRs: firewall-policy capability + normalized models, PAN-OS/FortiOS plugins, Security Agent, audit-log hash chaining, mTLS between containers, device credential rotation, collector network segmentation. |
| `0042`–`0049` | P3-wave/audit ADRs: Postgres HA (CloudNativePG), api HPA/KEDA autoscaling, Redis Sentinel + WebSocket fan-out, audit→SIEM export, observability-SLO enforcement, reliability/scale drill harness, kind-harness gate promotion (Rejected), packet-analysis sandbox resolution. |
| `0050`–`0053` | P4 wave ADRs (Proposed): F5 BIG-IP plugin, VMware vSphere plugin, application-dependency topology, compliance & audit reporting suite. |

## roadmap/

| Document | Description |
|---|---|
| [MVP.md](roadmap/MVP.md) | Milestones M0–M5 (scaffold → discovery → topology → agents → config mgmt → ChangeRequest/DDI/packet), with binding scope lists, exit criteria, and a full CLAUDE.md traceability table. |
| [PRODUCTION.md](roadmap/PRODUCTION.md) | Post-MVP path to enterprise production: four phases (P1–P4), vendor waves for all 13 families, HA/scale-out, OIDC, security hardening, SLOs, DR, K8s hardening, readiness gates. |
| [LESSONS.md](roadmap/LESSONS.md) | Cross-wave lessons learned (what bit CI → rule for next time). Wave retros also live as `P*-W*-LESSONS.md`. |

## features/

Feature-scoped plans (done vs remaining) for operator-facing product slices that span multiple milestone waves.

| Document | Description |
|---|---|
| [settings-hub/](features/settings-hub/) | Settings hub: role-gated operator configuration (PRs #124–#127 done; SIEM lag + full audit browser remaining). |

## consultant/

| Document | Description |
|---|---|
| [GAP-ANALYSIS.md](consultant/GAP-ANALYSIS.md) | Missing/underspecified requirements with severity, working defaults, and seven challenged assumptions (C1–C7). |
| [QUESTIONS.md](consultant/QUESTIONS.md) | Open questions Q1–Q19 for the platform owner, each with options considered and the recommended default the build proceeds on. |
| [ASSUMPTIONS.md](consultant/ASSUMPTIONS.md) | Working-assumption register A1–A19 (in-force defaults for Q1–Q19) with risk-if-wrong and "where baked in" lists. |

**Reading order for newcomers:** `CLAUDE.md` → `architecture/DECISIONS-BRIEF.md` → `architecture/DIAGRAMS.md` → `roadmap/MVP.md` → `architecture/REPO-STRUCTURE.md`; consult `consultant/` for every open item and its in-force default, and `adr/` for the rationale behind any individual decision. Feature slices (e.g. Settings) live under `features/`.
