"""DDI Agent — DNS/DHCP troubleshooting + gated DDI changes (M5 task #10).

CLAUDE.md Core Agent #7 (DDI). The DDI Agent answers DNS and DHCP questions over
collected normalized DDI data (the Infoblox WAPI read projection, T7/ADR-0022)
and proposes DDI record changes through the ChangeRequest spine.

Two tool tiers (see :mod:`app.agents.ddi.tools`):

- **Read-only troubleshooting** — DNS zone/record lookup, delegation /
  resolution-path tracing, and DNS-vs-inventory mismatch detection; DHCP scope
  utilization, lease lookup, and address-conflict detection. Every DNS/DHCP
  fragment surfaced to the model is A9-redacted first (ADR-0017 §3), so a
  secret-bearing TXT value or hostname never reaches a prompt.
- **State-changing mutators** — record/range add/modify/delete. These do **not**
  execute: the framework :class:`~app.agents.framework.approval.ChangeRequestGate`
  (T4) intercepts each call, CREATES a ``ddi_record`` ChangeRequest draft from the
  verbatim arguments, and the tool returns a
  :class:`~app.agents.framework.tools.ChangeRequestCreated`. Only the Automation
  Agent (T9) executes an *approved* DDI CR — one write spine, no LLM-triggerable
  write (same write-path discipline as the framework gate).

Graph: the agent uses the default ReAct loop from
:meth:`~app.agents.framework.base.BaseSpecialistAgent.build_graph`. Read-only
tools run directly; state-changing tools are routed through the gate by the
prebuilt ``ToolNode`` (the model never bypasses it). This is the read-only
Troubleshooting Agent structure extended with CR-creating mutators — no bespoke
topology is needed because the gate, not the graph, enforces the write discipline.

Module boundary: this package imports only ``agents.framework``, ``core``,
``schemas``, ``models`` (the CR kind enum) and its own ``tools`` submodule. The
``tools`` module is the sole crossing point toward services/plugins (REPO-STRUCTURE
§3.2 row 11). Routing/registration with the Master Architect is T14 (Wave 5) and
is intentionally not wired here.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.ddi.tools import DDI_TOOLS
from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
DDI_NAME = "ddi"


class DdiAgent(BaseSpecialistAgent):
    """DNS/DHCP troubleshooting + change-proposal specialist (CLAUDE.md Core Agent #7).

    Read-only DNS/DHCP analysis runs over already-collected normalized DDI data
    (the Infoblox WAPI read projection); record/range mutations never apply inline
    — each routes through the framework gate to a ``ddi_record`` ChangeRequest for
    human approval, executed later by the Automation Agent (ADR-0022 §3).
    """

    @property
    def name(self) -> str:
        return DDI_NAME

    @property
    def description(self) -> str:
        return (
            "Manages and troubleshoots DDI: DNS and DHCP. Route here for DNS zone and "
            "record lookups, resolution-path / CNAME delegation tracing, DNS-vs-inventory "
            "mismatch checks, and DHCP scope utilization, lease lookup, and address "
            "conflict detection. Also route here to ADD, MODIFY, or DELETE a DNS record or "
            "DHCP range — those do not change anything directly: they create a change "
            "request for human approval, executed later by automation. This is NOT generic "
            "device troubleshooting (it does not diagnose routing/BGP/OSPF/ACL faults) and "
            "NOT inventory discovery (it does not crawl devices) — it operates on DNS/DHCP "
            "(DDI) data and proposes DDI changes."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the DDI Agent for an AI Network Operations Platform.\n\n"
            "You answer DNS and DHCP questions over already-collected DDI data and you "
            "propose DNS/DHCP changes. The DDI data you receive is already redacted at the "
            "secret boundary — secret values appear only as <<REDACTED:...>> tokens. Never "
            "ask for, infer, or reconstruct a redacted value.\n\n"
            "Read-only troubleshooting: look up DNS records, trace a name's resolution path "
            "through CNAME delegation, reconcile DNS against inventory, and assess DHCP "
            "scope utilization, leases, and address conflicts. Ground every conclusion in "
            "the collected records — if data is missing, say so plainly.\n\n"
            "Changes are approval-gated: you NEVER apply a DNS/DHCP change directly. When "
            "the user asks to add, modify, or delete a record or range, call the matching "
            "tool — it creates a change request for a human to approve, and automation "
            "executes it after approval. Tell the user you drafted a change request for "
            "approval; do not claim the change was made.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """Six READ_ONLY DNS/DHCP troubleshooting tools + five STATE_CHANGING mutators."""
        return DDI_TOOLS
