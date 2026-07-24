"""Documentation Agent — deterministic inventory, diagrams, and runbooks (M4 T10).

CLAUDE.md Core Agent #8 / MVP.md §6 / ADR-0019. The Documentation Agent
generates three artifact types on the ``docs`` Celery queue:

1. **Network inventories** (T10, this file) — Markdown + CSV from normalized
   tables.  No LLM: pure deterministic rendering, so the M4 exit criterion
   "generated inventory matches normalized-table content exactly" is satisfied
   by construction (ADR-0019 §2).
2. **Diagrams** (T11) — Mermaid source generated deterministically from the
   Neo4j topology projection; PNG is rendered client-side (ADR-0019 §3).
3. **Runbooks** (T12) — per-device template + grounded LLM narrative: every
   grounding fact is redacted (A9) at the LLM boundary before reaching the
   provider (D9 ``local`` default), so no secret value is exposed (ADR-0019 §4,
   ADR-0017 §3).

Artifact rendering and report lookup tools are READ_ONLY. The durable report
generation request is STATE_CHANGING because it persists a run, dispatch
envelope, and audit evidence; the framework approval gate intercepts that tool
before its body can execute.

Module boundary: this agent imports *only* ``agents.framework`` and its own
``tools`` submodule.  The tools module is the sole crossing point into data
sources (engines, models) — the import-linter contract (REPO-STRUCTURE §3.2
row 11) enforces that agents never reach engines or services directly.

Graph topology (default ReAct loop from BaseSpecialistAgent):
    The inventory tool is deterministic and needs no classify->narrate flow —
    a caller can invoke it directly (the worker does this). The LangGraph
    subgraph compiles the standard ReAct loop so the agent is composable with
    the Master Architect supervisor (registered in T13).
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.documentation.tools import DOCUMENTATION_TOOLS
from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
DOCUMENTATION_NAME = "documentation"


class DocumentationAgent(BaseSpecialistAgent):
    """Documentation specialist (CLAUDE.md Core Agent #8, MVP.md §6, ADR-0019).

    Generates network inventories (deterministic), topology diagrams (Mermaid),
    and runbooks (template + grounded LLM narrative) from live platform data.
    Rendering and lookup tools are READ_ONLY; durable report generation
    requests are STATE_CHANGING and approval-gated.

    The agent can be instantiated fresh for tests — the default no-arg
    constructor produces a valid, fully-functional agent.
    """

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return DOCUMENTATION_NAME

    @property
    def description(self) -> str:
        return (
            "Generates platform documentation artifacts: network inventories (Markdown "
            "and CSV tables of devices, interfaces, neighbors, and routes), topology "
            "diagrams (Mermaid source from the Neo4j projection), and runbooks "
            "(per-device or per-site Markdown grounded in inventory and topology). "
            "Route here when the user wants to generate, view, or download a network "
            "inventory, a topology diagram, or a runbook. This is NOT configuration — "
            "it does not explain config drift, compliance posture, or policy violations "
            "(that is the configuration specialist's job). It is NOT troubleshooting — "
            "it does not diagnose routing/BGP/OSPF/ACL faults or live control-plane "
            "problems (that is the troubleshooting specialist). Rendering and lookup "
            "are read-only. Requesting report generation persists platform state and "
            "is approval-gated; no device configuration or network state is modified."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Documentation Agent for an AI Network Operations Platform.\n\n"
            "Your purpose is to generate accurate, grounded documentation artifacts "
            "from the platform's live normalized data:\n\n"
            "- **Network inventories**: Markdown or CSV tables of devices, interfaces, "
            "  neighbors, and routes — rendered deterministically from normalized tables, "
            "  scoped by site or vendor if requested.\n"
            "- **Topology diagrams**: Mermaid source generated deterministically "
            "  from the Neo4j projection (nodes/edges); PNG is rendered "
            "  client-side.\n"
            "- **Runbooks**: per-device Markdown — deterministic fact tables plus a "
            "  grounded, redacted LLM narrative (Overview, Operational Procedures). "
            "  Every grounding fact is redacted (A9) before reaching the model.\n\n"
            "Guidelines:\n"
            "- Always use the inventory tool with the caller-supplied normalized-table "
            "  data; never guess or fabricate device details.\n"
            "- When a scope (site, vendor) is requested, apply it precisely — do not "
            "  include out-of-scope devices.\n"
            "- Report the ``kind``, ``format``, and ``title`` of each generated "
            "  artifact so the caller can persist it in the ``documents`` table.\n"
            "- You never modify device configuration or network state. Report generation "
            "  requests persist platform records and must pass the approval gate.\n"
            "- If the gate returns a draft change request, say it is awaiting human "
            "  approval; do not claim the report was queued.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """Classified documentation tools, including the gated report request."""
        return DOCUMENTATION_TOOLS
