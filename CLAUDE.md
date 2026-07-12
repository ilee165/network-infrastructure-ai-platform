# AI Network Operations Platform

## Mission

Build a self-hosted AI-powered Network Operations Platform for enterprise infrastructure teams.

The platform must function as an AI Network Engineer capable of:

- Discovery
- Troubleshooting
- Packet analysis
- Configuration management
- DDI management
- Documentation generation
- Automation execution

The platform must support multi-vendor environments.

## Vendors

Required support:

- Cisco IOS
- Cisco IOS-XE
- Cisco NX-OS
- Juniper JunOS
- Arista EOS
- Palo Alto PAN-OS
- Fortinet FortiOS
- F5 BIG-IP
- BlueCat
- Infoblox
- AWS
- Azure
- VMware

## Architecture

Use:

- Python
- FastAPI
- React
- TypeScript
- LangGraph
- PostgreSQL
- Neo4j
- pgvector
- Docker
- Kubernetes

## Core Agents

1. Master Architect Agent
2. Consultant Agent
3. Discovery Agent
4. Troubleshooting Agent
5. Packet Analysis Agent
6. Configuration Agent
7. DDI Agent
8. Documentation Agent
9. Security Agent
10. Automation Agent

## Design Principles

- Local first
- Self hosted
- Enterprise ready
- Secure by default
- Audit everything
- Human approval for changes
- Explain all AI decisions
- Support multiple LLMs

## Required Features

### Discovery

- SNMP
- SSH
- APIs
- LLDP
- CDP
- Route collection
- Interface inventory

### Topology

Maintain:

- L2 topology
- L3 topology
- DNS dependencies
- Application dependencies

Store relationships in Neo4j.

### Troubleshooting

Support:

- Routing analysis
- BGP analysis
- OSPF analysis
- DNS troubleshooting
- DHCP troubleshooting
- ACL analysis
- Firewall analysis

### DDI

Support:

- BlueCat
- Infoblox
- Route53

### Packet Analysis

Support:

- tcpdump
- tshark
- Wireshark

### Config Management

Support:

- Backup
- Restore
- Drift detection
- Compliance checks

### Documentation

Automatically generate:

- Diagrams
- Runbooks
- Incident reports
- Network inventories

## Development Standards

Before implementation:

1. Architecture design
2. ADR creation
3. Data model design
4. API design
5. Security review

Every feature must include:

- Tests
- Documentation
- API documentation

### PR review authority

Claude Code is the implementation authority — it owns design, architecture,
refactors, naming, and documentation. CodeRabbit is an advisory PR reviewer
bounded to four domains only: **correctness, security, test gaps, performance
regressions**. Comments on architecture, refactors, style, naming, doc
rewrites, or speculative improvements are out of scope and are rejected. The
contract is machine-enforced in `.coderabbit.yaml` and documented in
`docs/CODERABBIT_REVIEW_POLICY.md`.

### Orchestrated builds

Milestones are built with the multi-agent Workflow tool. The build process,
role/model tiers, and cost policy live in `.claude/agents/README.md` and
`.claude/workflows/README.md` — read them before launching a workflow. Standing
discipline derived from prior milestones:

- **Atomic commit per task** is the unit of resumability — committed work is
  never re-paid and survives any mid-run kill.
- **Arm a baseline-relative usage guard** on long runs (`budget.spent()` is
  session-cumulative, not per-turn): stop near a ceiling, save via commits,
  summarize.
- **After a kill (session-limit OR transient API 5xx), trust git, not the
  result object.** Salvage any coherent uncommitted tree (validate gates, then
  commit) and focused-rerun only the gaps; never `reset --hard` to discard.
- **Escalate every secret-surface role to the strong model** (KMS/KEK, auth,
  credential vault, any pipeline touching secret material).
- **Confirm a CI fix makes the gate RUN and BITE** — a gate failing at setup
  masks the findings it would have produced.
- **When a component gains a new API import, update every `vi.mock` of that
  module** — sibling test files (route gates, page tests, layout) that partially
  mock `../api/*` will fail at runtime with “No X export is defined on the mock”
  if they omit the new export (Settings hub Path A: `getRotationStatus` /
  `getOidcStatus`; see `docs/roadmap/LESSONS.md` **L-FE-1**).
- **Frontend image Trivy RED on a fixable Alpine package → bump the
  `apk upgrade` cache-bust date** in `deploy/docker/frontend.Dockerfile` so GHA
  layer cache does not re-ship the pre-patch packages (e.g. c-ares CVE-2026-33630
  on 2026-07-10; see `docs/roadmap/LESSONS.md` **L-IMG-1**). Do **not** silence
  the finding in `.trivyignore-image` when an upstream patch exists.
- **Device write / SSH transport (L-XPORT-1):** string-recording fakes do not
  certify CLI mode, handshake phase, or device echo. Pin exit/re-enter for
  multi-mode CLIs; enforce host-key pins at handshake (serialize any global
  policy monkey-patch); check each multi-step finalize command before the next;
  use anchored integrity tokens and never scan intermediate `set body` / `puts`
  echoes for error markers. See `docs/roadmap/LESSONS.md` **L-XPORT-1**.

### Build & runtime verification

The documented build/start/test procedures (README "Development" + "Quickstart",
`deploy/docker/README.md`) are verified working. Standing facts an agent
re-validating the platform should know:

- **Backend installs into a venv, never the system interpreter.** A global
  `pip install -e ".[dev]"` on a distro-managed Python aborts trying to replace
  the OS-owned PyYAML (`Cannot uninstall PyYAML ... RECORD file not found`). The
  unit suite (`pytest`) needs no external services and is the fastest full-stack
  smoke; runtime gates are `ruff check . && ruff format --check . && mypy &&
  lint-imports`.
- **Compose needs `--env-file .env`.** With `-f deploy/docker/...` the neo4j
  credential is interpolated from the compose dir/shell, not the root `.env`;
  omitting it starts neo4j with the wrong password.
- **`alembic upgrade head` is a required first-run step** (migrations are
  sequential — `upgrade head` applies the whole `0001`-onward chain) and seeds
  the bootstrap `admin` from `NETOPS_ADMIN_PASSWORD` (insecure
  `admin`/`admin` default + warning when unset). `NETOPS_ADMIN_PASSWORD` is read
  by the migration, not `config.py` — the one documented exception to the
  `.env.example` ↔ `config.py` 1:1 rule.
- **`.env.example` is GENERATED, not hand-edited (H3 closed, AR-W1-T1).**
  `backend/scripts/generate_env_example.py` introspects `Settings` and is the
  single source; the `config-drift` CI gate re-generates it and fails on any
  diff, so it documents every field 1:1. Regenerate after any `Settings` change:
  `cd backend && python scripts/generate_env_example.py --write`. The only
  hand-maintained blocks are the two non-`Settings` exceptions (`NETOPS_ADMIN_PASSWORD`
  above and the pgBackRest backup-tier). The same generator's `--check-chart`
  enforces the C5/C6 seam (every Helm-rendered `NETOPS_*` key is a `Settings`
  field or a documented exception; no secret material in a plaintext ConfigMap).
- **`NETOPS_CORS_ORIGINS` is a JSON list** — let compose/uvicorn read `.env`
  directly; hand-sourcing it in a shell strips the quotes and breaks parsing.
- **Image builds need egress to base registries + PyPI/npm and apk repos.** In a
  restricted/air-gapped or CA-intercepting environment the in-container `pip`/`apk`
  layers fail TLS unless the egress CA is trusted inside the build (see
  `docs/security/supply-chain-scanning.md`); the Dockerfiles themselves are sound
  and build under normal CI egress.
- **Frontend Dockerfile `apk upgrade` is cache-busted by date comment.** CI
  reuses the GHA build layer; a new *fixable* OS CVE in the Trivy image gate
  means re-run upgrade by bumping that date (not by ignoring the CVE).

## Consultant Agent

If requirements are unclear:

- Ask questions
- Refine requirements
- Do not assume

## Production Readiness

Every iteration should improve:

- Security
- Reliability
- Scalability
- Observability
- Maintainability

The final product should be deployable on-premises using Docker or Kubernetes.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
