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
