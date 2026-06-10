# Architecture Diagrams

**Project:** AI Network Operations Platform
**Status:** Draft v0.1 — Iteration 1 (Phase 1: Architecture)
**Date:** 2026-06-09
**Sources of truth:** `CLAUDE.md` (platform constitution) and `docs/architecture/DECISIONS-BRIEF.md` (binding decisions D1–D16). Every element in these diagrams traces to one of those two documents; anything the brief does not cover is marked **PROPOSED** inline.

Diagrams:

1. [System context (C4 L1)](#1-system-context-c4-l1)
2. [Container diagram (C4 L2)](#2-container-diagram-c4-l2)
3. [Agent orchestration (LangGraph supervisor)](#3-agent-orchestration-langgraph-supervisor)
4. [Discovery pipeline flow](#4-discovery-pipeline-flow)
5. [Neo4j topology data model](#5-neo4j-topology-data-model)
6. [Change-approval sequence](#6-change-approval-sequence)
7. [Deployment topologies](#7-deployment-topologies)

---

## 1. System context (C4 L1)

The platform is a single self-hosted system. Three human roles interact with it over HTTPS: **network engineers** drive discovery, troubleshooting, and change requests; **approvers** review and approve/reject ChangeRequests (a different user than the requester, per D11/section 7); **auditors** read the append-only audit log and reasoning traces. The platform reaches **managed infrastructure** — the 13 vendor families required by `CLAUDE.md` — over SSH, SNMP, and vendor HTTPS APIs (D7). LLM inference is **local-first via Ollama**; external providers (the `anthropic`, `openai`, `azure` profiles from D9) are strictly opt-in, shown dashed. Authentication uses local users plus a pluggable **OIDC identity provider** (D10).

```mermaid
flowchart TB
    engineer["Network Engineer<br/>RBAC: operator / engineer"]
    approver["Change Approver<br/>RBAC: engineer / admin, different user than requester"]
    auditor["Auditor<br/>RBAC: viewer with audit access"]

    platform["AI Network Operations Platform<br/>self-hosted, local-first<br/>discovery, troubleshooting, packet analysis,<br/>config mgmt, DDI, documentation, automation"]

    idp["Identity Provider<br/>OIDC, pluggable - local users as fallback"]

    subgraph llm_ext["External LLM providers - optional, opt-in per D9"]
        anthropic["Anthropic API"]
        openai["OpenAI API"]
        azureoai["Azure OpenAI"]
    end

    subgraph managed["Managed infrastructure - 13 vendor families"]
        subgraph nos["Network OS - SSH and SNMP"]
            ios["Cisco IOS"]
            iosxe["Cisco IOS-XE"]
            nxos["Cisco NX-OS"]
            junos["Juniper JunOS"]
            eos["Arista EOS"]
        end
        subgraph secadc["Security and ADC - API plus SSH"]
            panos["Palo Alto PAN-OS"]
            fortios["Fortinet FortiOS"]
            f5["F5 BIG-IP"]
        end
        subgraph ddifam["DDI - HTTPS API"]
            bluecat["BlueCat"]
            infoblox["Infoblox"]
        end
        subgraph cloudv["Cloud and virtualization - SDK APIs"]
            aws["AWS"]
            azure["Azure"]
            vmware["VMware"]
        end
    end

    engineer -->|"HTTPS - chat, topology, inventory, packet analysis"| platform
    approver -->|"HTTPS - reviews and approves ChangeRequests"| platform
    auditor -->|"HTTPS - audit log and reasoning traces"| platform
    platform -->|"OIDC / OAuth2"| idp
    platform -.->|"HTTPS - only when LLM profile is not local"| llm_ext
    platform -->|"SSH 22, SNMP 161"| nos
    platform -->|"HTTPS API and SSH"| secadc
    platform -->|"HTTPS - Infoblox WAPI, BlueCat API"| ddifam
    platform -->|"HTTPS - boto3, Azure SDK, pyVmomi"| cloudv
```

---

## 2. Container diagram (C4 L2)

The seven containers from brief section 1, with the protocols on each edge. `frontend` is React 18 + TypeScript + Vite served by nginx; `api` is FastAPI exposing REST and WebSocket; `worker` runs Celery from the **same codebase** as `api` (D1, D8) and is the only container that talks to managed devices — long-running discovery, config backup, packet capture, and doc-generation jobs run there on the dedicated `discovery`, `config`, `packet`, and `docs` queues. Postgres is the system of record; Neo4j is a rebuildable projection (D5). `ollama` runs only when its compose profile / Helm value is enabled; external LLM calls (dashed) exist only in non-`local` D9 profiles.

```mermaid
flowchart LR
    user["Browser<br/>engineer, approver, auditor"]

    subgraph platform["AI Network Operations Platform"]
        frontend["frontend<br/>React 18 + TypeScript + Vite, served by nginx"]
        api["api<br/>Python 3.11+ FastAPI<br/>REST + WebSocket, authn/z, agent sessions"]
        worker["worker<br/>Celery - queues: discovery, config, packet, docs"]
        postgres[("postgres<br/>PostgreSQL 16 + pgvector<br/>system of record")]
        neo4j[("neo4j<br/>Neo4j 5 Community<br/>topology projection")]
        redis[("redis<br/>Redis 7<br/>broker, cache, rate limiting")]
        ollama["ollama<br/>optional profile - local LLM inference"]
    end

    devices["Managed infrastructure<br/>13 vendor families"]
    extllm["External LLM providers<br/>opt-in per D9"]

    user -->|"HTTPS 443"| frontend
    frontend -->|"HTTPS - REST /api/v1 + WS /api/v1/agents/sessions/{session_id}/ws"| api
    api -->|"asyncpg TCP 5432"| postgres
    api -->|"Bolt TCP 7687"| neo4j
    api -->|"RESP TCP 6379 - enqueue, cache"| redis
    worker -->|"RESP TCP 6379 - broker and results"| redis
    worker -->|"asyncpg TCP 5432"| postgres
    worker -->|"Bolt TCP 7687"| neo4j
    api -.->|"HTTP 11434"| ollama
    worker -.->|"HTTP 11434"| ollama
    api -.->|"HTTPS 443"| extllm
    worker -->|"SSH 22 netmiko, SNMP 161 pysnmp, HTTPS httpx and SDKs"| devices
```

---

## 3. Agent orchestration (LangGraph supervisor)

D3 / brief section 5: the **Master Architect Agent** is the LangGraph supervisor — it receives user intent, plans, routes to the nine specialist subgraphs, and synthesizes the answer. The **Consultant Agent** is the one specialist with a loop back to the user: it asks clarifying questions when intent is ambiguous (or records them with defaults in `docs/consultant/QUESTIONS.md`). All specialists act only through the **shared typed tool layer** in `agents/framework`. Read-only tools execute immediately against engines/services; **every state-changing tool call hits the approval gate**, which creates a ChangeRequest and blocks until a human (different user) approves — no exceptions. Every run persists a reasoning trace; audit-log entries link back to traces (D11). Agents inherit the invoking user's RBAC permissions — an agent can never do what its user cannot.

```mermaid
flowchart TD
    user["User intent<br/>chat via api WebSocket session"]
    supervisor["Master Architect Agent<br/>LangGraph supervisor: plan, route, synthesize"]

    subgraph specialists["9 specialist agents - LangGraph subgraphs with name, description, input schema"]
        consultant["Consultant Agent<br/>requirement clarification"]
        discovery["Discovery Agent"]
        troubleshooting["Troubleshooting Agent"]
        packet["Packet Analysis Agent"]
        configuration["Configuration Agent"]
        ddi_agent["DDI Agent"]
        documentation["Documentation Agent"]
        security["Security Agent"]
        automation["Automation Agent"]
    end

    subgraph toollayer["Shared tool layer - agents/framework typed tool wrappers"]
        readtools["Read-only tools<br/>execute immediately"]
        writetools["State-changing tools<br/>config deploy, DDI record change, automation"]
    end

    gate{"Approval gate"}
    cr["ChangeRequest<br/>pending_approval"]
    human["Human approver<br/>different user than requester"]
    engines["Engines and services<br/>discovery, topology, packet, config_mgmt, knowledge"]
    plugins["Vendor plugin registry<br/>vendor_id + capability"]
    traces[("reasoning_traces<br/>Postgres - steps, tool calls, evidence")]
    audit[("audit_log<br/>Postgres - append-only")]

    user --> supervisor
    consultant -.->|"clarifying questions - do not assume"| user
    supervisor -->|"routes by intent"| specialists
    specialists -->|"tool calls"| readtools
    specialists -->|"tool calls"| writetools
    readtools --> engines
    writetools --> gate
    gate -->|"creates and blocks"| cr
    human -->|"approve or reject"| cr
    cr -->|"approved - execution dispatched"| engines
    engines --> plugins
    supervisor -->|"persists every run"| traces
    specialists -->|"persists every run"| traces
    gate -->|"records every decision"| audit
    audit -.->|"links to"| traces
```

---

## 4. Discovery pipeline flow

Brief sections 4 and 6, D6–D8. A discovery run starts from a **seed** (IP ranges / hostnames plus a credential reference — credentials never leave the vault). The discovery engine expands the seed and plans jobs onto the Celery `discovery` queue. The plugin registry resolves `(vendor_id, capability)` to a driver: netmiko for SSH, pysnmp for SNMP v2c/v3, httpx/SDKs for APIs. **All raw output is stored verbatim first** (`raw_artifacts`, JSONB + text) for auditability, then CLI output is parsed with ntc-templates/TextFSM into **normalized Pydantic models** (structured SNMP/API payloads map through typed normalizers to the same models — D7). Normalized rows land in Postgres `normalized_*` tables (system of record), and the topology engine projects them into Neo4j — a projection that can always be fully rebuilt from Postgres (D5). LLDP/CDP neighbor results feed back into seed expansion, which is how the network is walked.

```mermaid
flowchart LR
    seed["Seed<br/>IP ranges, hostnames, credential reference"]
    plan["Discovery engine<br/>seed expansion + job planning"]
    queue["Celery queue: discovery<br/>Redis broker"]
    registry["Plugin registry<br/>resolves vendor_id + capability"]

    subgraph driver["Vendor plugin driver"]
        ssh["SSH<br/>netmiko"]
        snmp["SNMP v2c/v3<br/>pysnmp"]
        apidrv["REST / XML API<br/>httpx, boto3, Azure SDK, pyVmomi"]
    end

    raw[("raw_artifacts<br/>verbatim output, JSONB + text")]
    parse["TextFSM parse<br/>ntc-templates - CLI output<br/>typed normalizers for SNMP and API payloads"]
    norm["Normalized Pydantic models<br/>NormalizedInterface, NormalizedRoute,<br/>NormalizedNeighbor, NormalizedBgpPeer, ..."]
    pg[("Postgres<br/>normalized_* tables, discovery_runs<br/>system of record")]
    proj["Topology engine<br/>graph projection, L2/L3 builders, diff"]
    neo[("Neo4j<br/>rebuildable projection")]

    seed --> plan
    plan --> queue
    queue --> registry
    registry --> driver
    ssh --> raw
    snmp --> raw
    apidrv --> raw
    raw --> parse
    parse --> norm
    norm --> pg
    pg --> proj
    proj --> neo
    pg -.->|"LLDP and CDP neighbors feed seed expansion"| plan
```

---

## 5. Neo4j topology data model

Brief section 6, exactly: node labels `Device`, `Interface`, `Vlan`, `Subnet`, `IPAddress`, `VRF`, `DnsZone`, `DnsRecord`, `Application`, `Site`; relationship types `CONNECTED_TO` (L2), `L3_ADJACENT`, `ROUTES_TO`, `HAS_INTERFACE`, `IN_SUBNET`, `RESOLVES_TO`, `DEPENDS_ON`, `MEMBER_OF`, `LOCATED_AT`. The brief fixes the names but not every endpoint pairing; the pairings below are the canonical mapping for the projection builder. `MEMBER_OF` is deliberately reused for three containment pairings (Interface→Vlan, Subnet→VRF, DnsRecord→DnsZone). One edge the brief does not name is needed to attach addresses to interfaces: **`ASSIGNED_IP` (Interface→IPAddress) — PROPOSED**, shown dashed; it must be ratified in ADR-0005 before the projection builder ships. Neo4j never holds data that exists nowhere else — everything here is derived from Postgres.

```mermaid
flowchart LR
    Device["Device"]
    Interface["Interface"]
    Vlan["Vlan"]
    Subnet["Subnet"]
    IPAddress["IPAddress"]
    VRF["VRF"]
    DnsZone["DnsZone"]
    DnsRecord["DnsRecord"]
    Application["Application"]
    Site["Site"]

    Device -->|"HAS_INTERFACE"| Interface
    Interface -->|"CONNECTED_TO - L2"| Interface
    Device -->|"L3_ADJACENT"| Device
    Device -->|"ROUTES_TO"| Subnet
    IPAddress -->|"IN_SUBNET"| Subnet
    DnsRecord -->|"RESOLVES_TO"| IPAddress
    Application -->|"DEPENDS_ON"| DnsRecord
    Application -->|"DEPENDS_ON"| Application
    Interface -->|"MEMBER_OF"| Vlan
    Subnet -->|"MEMBER_OF"| VRF
    DnsRecord -->|"MEMBER_OF"| DnsZone
    Device -->|"LOCATED_AT"| Site
    Interface -.->|"ASSIGNED_IP - PROPOSED"| IPAddress
```

Coverage of the four required topology views (`CLAUDE.md`): **L2** = `CONNECTED_TO` + `MEMBER_OF` Vlan; **L3** = `L3_ADJACENT` + `ROUTES_TO` + `IN_SUBNET` + VRF membership; **DNS dependencies** = `RESOLVES_TO` + `MEMBER_OF` DnsZone; **application dependencies** = `DEPENDS_ON`.

---

## 6. Change-approval sequence

D11 / brief section 7. Any state-changing tool call — config deploy, DDI record change, automation — is intercepted by the approval gate, which creates a `ChangeRequest` and blocks. The lifecycle is `draft → pending_approval → approved → executing → completed | failed → rolled_back`; a rejection returns the ChangeRequest to `draft` for rework with the approver's comments (ADR-0011 state machine — rejection is not terminal). The approver must be a **different user** than the requester (configurable). Execution is dispatched to the **Automation Agent** on the Celery `config` queue; it snapshots the pre-change state first (`CONFIG_BACKUP`) so the rollback path is always available. Every transition appends to the append-only `audit_log` with actor, action, target, before/after state, and a link to the reasoning trace.

```mermaid
sequenceDiagram
    actor ENG as Network Engineer
    participant SA as Specialist Agent
    participant GATE as Approval Gate
    participant PG as Postgres
    actor APP as Approver
    participant AA as Automation Agent
    participant DEV as Managed Device

    ENG->>SA: Request change in chat session
    SA->>PG: Persist reasoning trace - steps, tool calls, evidence
    SA->>GATE: Invoke state-changing tool
    GATE->>PG: INSERT change_requests status=draft
    GATE->>PG: Transition status=pending_approval
    GATE-->>SA: Blocked - awaiting human approval
    SA-->>ENG: CR-42 pending approval, with proposed diff and trace link
    APP->>GATE: Review CR-42 diff, evidence, reasoning trace
    Note over APP,GATE: RBAC enforced - approver must be a different user than requester
    alt Approved
        GATE->>PG: status=approved, INSERT approvals row, append audit_log
        GATE->>AA: Dispatch execution on Celery config queue
        AA->>PG: status=executing
        AA->>DEV: CONFIG_BACKUP - snapshot pre-change state
        AA->>DEV: CONFIG_DEPLOY - apply approved change via vendor plugin
        alt Execution succeeds
            AA->>PG: status=completed
            AA->>PG: Append audit_log - actor, action, target, before and after state, trace link
            AA-->>ENG: Completed with evidence
        else Execution fails
            AA->>DEV: CONFIG_RESTORE - roll back to pre-change snapshot
            AA->>PG: status=failed then status=rolled_back
            AA->>PG: Append audit_log entries for failure and rollback
            AA-->>ENG: Failed and rolled back, with evidence
        end
    else Rejected
        GATE->>PG: status=draft - returned for rework, append audit_log with approver comment
        GATE-->>ENG: Change rejected with comments - CR back in draft for rework
    end
```

---

## 7. Deployment topologies

D13: **Docker Compose for MVP/dev**, one image per container, with `ollama` behind an optional compose profile; **Kubernetes via Helm chart for production**. The pcap volume implements D14 (pcap artifacts on a disk volume, metadata + retention in Postgres). In production, TLS terminates at the ingress, all containers run non-root, NetworkPolicies restrict east-west traffic, and the platform master key arrives through a KMS-compatible secrets interface (section 7). Every container exposes health/readiness endpoints and Prometheus metrics (D15).

### 7a. Docker Compose (MVP / dev)

```mermaid
flowchart TB
    browser["Browser"]
    subgraph host["Single Docker host - MVP and dev"]
        subgraph compose["docker-compose project - one image per container"]
            cfrontend["frontend<br/>nginx, ports 80 and 443"]
            capi["api<br/>FastAPI + uvicorn, port 8000 internal"]
            cworker["worker<br/>Celery queues: discovery, config, packet, docs"]
            cpostgres[("postgres<br/>PostgreSQL 16 + pgvector")]
            cneo4j[("neo4j<br/>Neo4j 5 Community")]
            credis[("redis<br/>Redis 7")]
            collama["ollama<br/>compose profile: ollama - optional"]
        end
        vol_pg[/"pgdata volume"/]
        vol_neo[/"neo4j volume"/]
        vol_pcap[/"pcap volume - retention policy in Postgres"/]
        vol_llm[/"ollama models volume"/]
    end
    netdev["Managed infrastructure"]

    browser -->|"HTTPS 443"| cfrontend
    cfrontend -->|"proxy /api/v1 - REST + WebSocket upgrade"| capi
    capi --> cpostgres
    capi --> cneo4j
    capi --> credis
    cworker --> credis
    cworker --> cpostgres
    cworker --> cneo4j
    capi -.-> collama
    cworker -.-> collama
    cworker -->|"SSH, SNMP, HTTPS"| netdev
    cpostgres --- vol_pg
    cneo4j --- vol_neo
    cworker --- vol_pcap
    collama --- vol_llm
```

### 7b. Kubernetes via Helm (production)

```mermaid
flowchart TB
    users["Users<br/>engineers, approvers, auditors"]
    subgraph cluster["Kubernetes cluster - deployed by the netops Helm chart"]
        subgraph ns["Namespace: netops - NetworkPolicies restrict east-west traffic"]
            ing["Ingress<br/>TLS termination, routes / and /api"]
            svcfe["Service: frontend"]
            svcapi["Service: api"]
            dfe["Deployment: frontend<br/>2+ replicas"]
            dapi["Deployment: api<br/>2+ replicas, HPA"]
            dworker["Deployment: worker<br/>scaled per queue"]
            sspg["StatefulSet: postgres<br/>pgvector, PVC"]
            ssneo["StatefulSet: neo4j<br/>PVC"]
            ssredis["StatefulSet: redis<br/>PVC"]
            dollama["Deployment: ollama<br/>optional - GPU node selector"]
            secrets["Secrets<br/>master key via KMS-compatible interface"]
            pvc_pcap[/"PVC: pcap artifacts"/]
        end
    end
    netdev2["Managed infrastructure"]
    extllm2["External LLM providers - opt-in egress"]

    users -->|"HTTPS 443"| ing
    ing --> svcfe
    svcfe --> dfe
    ing --> svcapi
    svcapi --> dapi
    dapi --> sspg
    dapi --> ssneo
    dapi --> ssredis
    dworker --> ssredis
    dworker --> sspg
    dworker --> ssneo
    dapi -.-> dollama
    dworker -.-> dollama
    secrets -.-> dapi
    secrets -.-> dworker
    dworker --- pvc_pcap
    dworker -->|"SSH, SNMP, HTTPS"| netdev2
    dapi -.->|"HTTPS - only in non-local LLM profiles"| extllm2
```

**PROPOSED (not covered by the brief):** Postgres/Neo4j/Redis run as in-cluster StatefulSets by default; pointing the Helm chart at externally managed database instances is a values-level override. HA/DR posture is an open item routed to the Consultant Agent (brief section 9).
