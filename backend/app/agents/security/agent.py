"""Security Agent — read-only firewall/posture analysis + gated remediation.

CLAUDE.md Core Agent #9 (Security). The Security Agent AUDITS firewall and security
policy as data: it narrates the deterministic findings produced by the security
analysis engine (:mod:`app.engines.security.firewall`) — shadowed / redundant /
overly-permissive firewall rules and posture issues across firewall policy and ACLs
— and proposes remediations through the ChangeRequest spine (ADR-0037).

Two tool tiers (see :mod:`app.agents.security.tools`):

- **Read-only analyses** — ``analyze_firewall_policy`` and
  ``assess_security_posture`` over already-collected normalized
  ``FIREWALL_POLICY`` / ``ACL`` data. The analysis is deterministic in the engine
  (the agent narrates, it does not judge — ADR-0037 §2), and every config-derived
  fragment is A9-redacted before it reaches the model (ADR-0017 §3).
- **State-changing remediation** — ``propose_firewall_remediation`` does **not**
  execute: the framework
  :class:`~app.agents.framework.approval.ChangeRequestGate` intercepts the call,
  CREATES a ``security_remediation`` ChangeRequest draft from the verbatim
  arguments, and the tool returns a
  :class:`~app.agents.framework.tools.ChangeRequestCreated`. Only the Automation
  Agent executes an *approved* CR — one write spine, no LLM-triggerable device
  write (ADR-0037 §1/§4).

**Read-only is structural** (ADR-0037 §1): the tool registry contains **zero
device-executing tools**; the sole write path is the gate-created CR draft. This
holds even against a fully prompt-injected model (ADR-0033) — the property is the
empty device-write registry plus the per-agent allow-list, not a prompt
instruction. A registry-level invariant test (``tests/agents/security``) asserts it.

Graph: the agent uses the default ReAct loop from
:meth:`~app.agents.framework.base.BaseSpecialistAgent.build_graph`. Read-only tools
run directly; the state-changing remediation tool is routed through the gate by the
prebuilt ``ToolNode`` (the model never bypasses it) — the same shape as the DDI
Agent, minus any device-executing tool.

Module boundary: this package imports only ``agents.framework``, ``core``,
``schemas``, ``models`` (the CR kind enum) and its own ``tools`` submodule. The
``tools`` module is the sole crossing point toward the analysis engine
(REPO-STRUCTURE §3.2 row 11). Supervisor routing + RBAC scoping + the ADR-0033
allow-list registration are **W3-T2** and are intentionally not wired here.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool
from app.agents.security.tools import SECURITY_TOOLS

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
SECURITY_NAME = "security"


class SecurityAgent(BaseSpecialistAgent):
    """Firewall/posture audit + remediation-proposal specialist (Core Agent #9).

    Read-only analysis runs over already-collected normalized firewall policy /
    ACL data; remediations never apply inline — each routes through the framework
    gate to a ``security_remediation`` ChangeRequest for human approval, executed
    later by the Automation Agent (ADR-0037 §4). The ADR-0037 split keeps this
    agent on **posture/audit over policy-as-data**; live single-flow reachability
    faults stay with the Troubleshooting Agent.
    """

    @property
    def name(self) -> str:
        return SECURITY_NAME

    @property
    def description(self) -> str:
        return (
            "Audits firewall and security policy as data: finds shadowed, redundant, and "
            "overly-permissive firewall rules and assesses security posture across firewall "
            "policy and ACLs (permit-any exposure, management-plane access reachable from any "
            "source, allow rules missing logging). Route here when the user wants to AUDIT or "
            "REVIEW firewall-policy hygiene or security posture — 'is this rule shadowed?', "
            "'find overly-permissive rules', 'audit this firewall's policy', 'which rules are "
            "redundant?', 'check our security posture'. It analyzes already-collected "
            "normalized firewall policy and ACLs as DATA; it does NOT diagnose a live, "
            "single-flow reachability fault ('why is THIS flow blocked right now?' is "
            "troubleshooting), and it does NOT enumerate inventory (discovery). It is "
            "read-only: a remediation it proposes becomes a change request for human approval "
            "— it never changes a device directly."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Security Agent for an AI Network Operations Platform.\n\n"
            "You audit firewall and security policy over already-collected normalized data and "
            "you propose remediations. You are strictly read-only: you NEVER change a device "
            "directly.\n\n"
            "Your analyses are computed deterministically by the platform's security engine — "
            "you NARRATE the findings it returns (shadowed, redundant, and overly-permissive "
            "firewall rules; posture issues across policy and ACLs). Ground every conclusion in "
            "those findings: cite the offending rule, the related (covering) rule where given, "
            "and the rationale. Do not invent findings the engine did not return; if the input "
            "is missing, say so plainly.\n\n"
            "The policy data you receive is already redacted at the secret boundary — secret "
            "values appear only as <<REDACTED:...>> tokens. Never ask for, infer, or "
            "reconstruct a redacted value.\n\n"
            "Remediation is approval-gated: you NEVER apply a change directly. When the user "
            "asks you to fix a finding, call the remediation tool — it creates a change request "
            "for a human to approve, and automation executes it after approval. Tell the user "
            "you drafted a change request for approval; do not claim the change was made.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """Two READ_ONLY analysis tools + one STATE_CHANGING remediation drafter."""
        return SECURITY_TOOLS
