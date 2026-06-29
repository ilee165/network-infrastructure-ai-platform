"""P2 W5-T2 cross-vendor + Security-Agent routing re-run — DETERMINISTIC layer (CI).

Sibling of the P1 W7-T3 ``test_p1_cross_vendor_routing.py``, extended for P2: the
two new Vendor-Wave-2 plugins (``panos`` ADR-0035 / ``fortios`` ADR-0036) and the
new **Security Agent** (``security`` ADR-0037, registered to the supervisor in
W3-T2). This module is the **deterministic, CI-collected half** of W5-T2 (the
PRODUCTION.md §2.6 "no cross-vendor eval regression" gate). The real-LLM routing
re-run lives in ``test_routing_eval.py`` (Ollama-gated, module-skipped without
``NETOPS_RUN_ROUTING_EVAL=1``), which this file deliberately does NOT depend on so
the guardrails below run on every CI push.

What layer proves what (``.claude/agents/wf-eval-designer.md`` discipline)
-------------------------------------------------------------------------

* **This file (deterministic, in CI):** proves *wiring / coverage / no-regression
  structure* — that:

  1. the two Vendor-Wave-2 plugins are present in the registry the platform routes
     their intents through (``panos`` / ``fortios``);
  2. the Security Agent is registered to the composition root AND is a routable
     specialist the supervisor can route to;
  3. **no routing regression in roster shape**: the eight prior specialists are
     STILL routable after adding ``security`` (W5-T2 requirement 1 — adding the
     ninth specialist must not drop or rename a prior one), and the routable roster
     is registry-derived (auto-includes a new agent, never a hardcoded list);
  4. the **ADR-0033 injection-boundary carry** (W5-T2 requirement 3): the Security
     Agent's per-agent tool allow-list is confined to its OWN read-only analysis
     tools plus its single gate-routed remediation drafter — no device-executing
     tool and no foreign agent's tool is nameable from it, so a prompt-coerced
     model cannot escape the read-only set (the boundary is the enumerated
     registry, not a prompt instruction).

  It does NOT prove a model routes a PAN-OS policy audit to ``security`` or a
  FortiGate routing fault to ``troubleshooting`` — that is model judgment a
  scripted replay cannot validate.

* **The real-LLM re-run (``test_routing_eval.py``, manual gate):** proves *routing
  quality* — a real local model routes each security-domain prompt to the Security
  Agent and each new vendor's held-out intents to the correct existing specialist,
  with no drift on the prior matrix. Deferred-accepted when no local model is
  available (no hardware, same posture as the prior matrices). The held-out
  security + panos/fortios cases were added to that file.

Roster source — CONFIRMED registry-derived, NOT a hardcoded list (W5-T2 req. 4)
-------------------------------------------------------------------------------

Two distinct "rosters" are in play, mirroring W7-T3:

1. **Routing specialist roster** — what the Master Architect supervisor decides
   over. Built from ``build_default_registry().list()`` minus the supervisor
   (``app/agents/__init__.py``). It is **registry-derived**: ``security`` appears
   because it was registered to the composition root in W3-T2, with no edit to the
   routing harness. ``panos`` / ``fortios`` do NOT appear here because they are
   ``VendorPlugin`` drivers (``app/plugins/``), not routable specialist agents —
   their intents are routed to the EXISTING owning specialist (PAN-OS policy audit
   -> security; FortiOS routing fault -> troubleshooting; FortiOS config drift ->
   configuration). The specialist roster grows by exactly one (eight -> nine).

2. **Vendor plugin roster** — what ``app/plugins/registry.get_default_registry``
   resolves ``(vendor_id, capability)`` over, built from ``iter_builtin_plugins()``.
   This is the roster P2 W2 grew. It is registry-derived, but a registry-derived
   list can still silently *lose* a member (a dropped ``yield``); the assertion
   below is the guardrail — it fails in CI if ``panos`` or ``fortios`` is absent,
   with no live model required.
"""

from __future__ import annotations

from app.agents import build_default_registry
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.agents.framework.tools import ToolClassification
from app.plugins.registry import get_default_registry

#: The two P2 Vendor-Wave-2 plugins whose intents W5-T2 re-runs routing for
#: (``vendor_id`` values, ADR-0035 panos / ADR-0036 fortios). The supervisor
#: routes their intents to existing specialists (PAN-OS firewall-policy audit ->
#: security; FortiOS routing fault -> troubleshooting; FortiOS config drift ->
#: configuration); the plugins themselves are vendor drivers, not routing targets.
_WAVE2_VENDOR_PLUGINS = frozenset({"panos", "fortios"})

#: The specialist agent each Wave-2 vendor's intents can route to. Pinned so the
#: guardrail also documents the cross-vendor routing contract the real-LLM re-run
#: exercises: each owning specialist must be a live routable target, or its
#: held-out routing cases in ``test_routing_eval.py`` would have no valid target.
#: A vendor can map to several owners (intent-dependent); both panos and fortios
#: reach ``security`` (policy audit), ``troubleshooting`` (live fault), and
#: ``configuration`` (drift) — the union below is what must be routable.
_WAVE2_OWNING_SPECIALISTS = frozenset({"security", "troubleshooting", "configuration"})

#: The eight specialists that were routable BEFORE P2 W3 added ``security``. The
#: no-regression contract (W5-T2 req. 1): all eight must STILL be routable after
#: the ninth lands — adding the Security Agent must not drop or rename a prior one.
_PRIOR_ROUTABLE_SPECIALISTS = frozenset(
    {
        "consultant",
        "discovery",
        "troubleshooting",
        "configuration",
        "documentation",
        "automation",
        "ddi",
        "packet_analysis",
    }
)

#: The new ninth specialist (ADR-0037, registered W3-T2).
_SECURITY_SPECIALIST = "security"

#: The Security Agent's complete per-agent tool allow-list (ADR-0037 §1 / W3-T1):
#: two READ_ONLY analyses + one gate-routed STATE_CHANGING remediation drafter.
#: This is the ADR-0033 injection boundary the carry below asserts is confined.
_SECURITY_READ_ONLY_TOOLS = frozenset({"analyze_firewall_policy", "assess_security_posture"})
_SECURITY_STATE_CHANGING_TOOLS = frozenset({"propose_firewall_remediation"})
_SECURITY_ALLOW_LIST = _SECURITY_READ_ONLY_TOOLS | _SECURITY_STATE_CHANGING_TOOLS


def test_wave2_vendor_plugins_present_in_registry() -> None:
    """The 2 P2 Vendor-Wave-2 plugins are registered in the vendor plugin roster.

    Registry-derived (``iter_builtin_plugins`` -> ``get_default_registry``) but a
    dropped ``yield`` could silently remove one, so this CI-collected assertion is
    the guardrail W5-T2 requires: absence is caught with no live model. This is the
    "deterministic plugins-present-in-roster assertion green in CI" half of the
    cross-vendor re-run.
    """
    registered = set(get_default_registry().vendor_ids())
    missing = _WAVE2_VENDOR_PLUGINS - registered
    assert not missing, (
        f"P2 Vendor-Wave-2 plugin(s) {sorted(missing)} absent from the registry "
        f"(registered: {sorted(registered)}) — cross-vendor routing for them "
        f"cannot work; check app/plugins/vendors/__init__.iter_builtin_plugins()."
    )


def test_security_agent_is_registered_and_routable() -> None:
    """The Security Agent (ADR-0037) is in the composition root AND routable.

    W5-T2 requirement 2 — the new agent must be reachable by the supervisor. It is
    registry-derived: ``security`` appears in the routable roster because W3-T2
    registered it to ``build_default_registry``, with no edit to the routing
    harness. If it were absent, its held-out security cases in
    ``test_routing_eval.py`` would have no valid target.
    """
    registry = build_default_registry()
    routable = {agent.name for agent in registry.list() if agent.name != SUPERVISOR_NAME}
    assert _SECURITY_SPECIALIST in routable, (
        f"the Security Agent ({_SECURITY_SPECIALIST!r}) is not a routable specialist "
        f"(routable: {sorted(routable)}) — its W5-T2 routing cases have no target. "
        f"Check app/agents/__init__.build_default_registry."
    )


def test_routing_roster_grew_by_exactly_security_no_prior_regression() -> None:
    """No routing regression: the 8 prior specialists stay routable; security is added.

    W5-T2 requirement 1 (PRODUCTION.md §2.6) — adding the ninth specialist must not
    drop, rename, or steal a prior routing target's identity. The routable roster
    is exactly the eight prior specialists plus ``security``. The roster is
    registry-derived (built from the composition root minus the supervisor), so a
    new agent auto-appears and this assertion needs no edit when a future agent
    lands; it bites only on a *prior-case* roster regression, which is the
    no-regression contract. Vendor plugins are NOT routable specialists (they are
    drivers), so they correctly never appear here.
    """
    registry = build_default_registry()
    routable = {agent.name for agent in registry.list() if agent.name != SUPERVISOR_NAME}

    # No prior specialist was lost or renamed.
    dropped = _PRIOR_ROUTABLE_SPECIALISTS - routable
    assert not dropped, (
        f"prior routable specialist(s) {sorted(dropped)} disappeared after P2 W3 "
        f"added the Security Agent — that is a routing regression the W5-T2 "
        f"no-regression gate forbids (routable now: {sorted(routable)})."
    )

    # The roster is exactly the prior eight plus the new security agent — no
    # accidental extra routing target, and no vendor plugin leaked in as one.
    assert routable == _PRIOR_ROUTABLE_SPECIALISTS | {_SECURITY_SPECIALIST}, (
        f"routable roster {sorted(routable)} is not exactly the prior eight plus "
        f"{_SECURITY_SPECIALIST!r}; an unexpected routing target appeared or a "
        f"vendor plugin leaked into the specialist roster."
    )

    # Vendor plugins are drivers, not routable specialists — never in the roster.
    leaked_vendors = _WAVE2_VENDOR_PLUGINS & routable
    assert not leaked_vendors, (
        f"vendor plugin id(s) {sorted(leaked_vendors)} appeared as routable "
        f"specialists — Vendor-Wave-2 plugins are drivers, not routing targets."
    )

    # Every Wave-2 vendor's owning specialist must be a live routing target.
    missing_owners = _WAVE2_OWNING_SPECIALISTS - routable
    assert not missing_owners, (
        f"specialist(s) {sorted(missing_owners)} that own Wave-2 vendor intents are "
        f"absent from the routable roster {sorted(routable)} — their cross-vendor "
        f"routing cases in test_routing_eval.py have no valid target."
    )


def test_security_agent_allow_list_confined_to_read_only_set() -> None:
    """ADR-0033 injection-boundary carry: the security allow-list cannot be escaped.

    W5-T2 requirement 3 (the ADR-0033 boundary extends to the new agent). The
    Security Agent's per-agent tool allow-list is the enumerated set of tools
    registered to it — two READ_ONLY analyses plus one gate-routed STATE_CHANGING
    remediation drafter (ADR-0037 §1). The boundary is STRUCTURAL: it is the
    enumerated registry, not a prompt instruction, so it holds even against a
    fully prompt-injected model.

    The assertions below are exactly the property a scope-hop injection cannot
    break — a prompt coercing the model to name a tool from another agent cannot
    summon it because it is simply not in the security allow-list. Cross-agent
    tool exclusion is further validated dynamically (against the live registry) by
    ``test_security_agent_does_not_share_tools_with_other_agents``. (The
    behavioural proof that an *injected* ``propose_firewall_remediation`` only
    drafts a four-eyes CR and never executes lives in
    ``test_p1_prompt_injection.py::TestSecurityRemediationModelToolBoundary``; this
    is the registry-level invariant W5-T2 re-asserts after the agent was wired into
    the routing roster.)
    """
    registry = build_default_registry()
    security = registry.get(_SECURITY_SPECIALIST)
    tool_names = {tool.name for tool in security.tools}

    # The allow-list is EXACTLY the security agent's own tools — no more, no less.
    assert tool_names == _SECURITY_ALLOW_LIST, (
        f"security allow-list {sorted(tool_names)} != the declared read-only set "
        f"{sorted(_SECURITY_ALLOW_LIST)} — the ADR-0033 boundary drifted."
    )

    # The only STATE_CHANGING surface is the gate-routed remediation drafter; every
    # other tool is READ_ONLY. No DIAGNOSTIC (device-executing) tool exists — the
    # read-only invariant (ADR-0037 §1) the supervisor routes a security prompt into.
    state_changing = {
        tool.name
        for tool in security.tools
        if tool.classification is ToolClassification.STATE_CHANGING
    }
    assert state_changing == _SECURITY_STATE_CHANGING_TOOLS, (
        f"security state-changing surface {sorted(state_changing)} != "
        f"{sorted(_SECURITY_STATE_CHANGING_TOOLS)} — only the gate-routed CR drafter "
        f"may be state-changing."
    )
    assert not any(
        tool.classification is ToolClassification.DIAGNOSTIC for tool in security.tools
    ), "security agent registered a DIAGNOSTIC (device-executing) tool — ADR-0037 §1 violated."


def test_security_agent_does_not_share_tools_with_other_agents() -> None:
    """No cross-agent tool leakage to or from the Security Agent (ADR-0033).

    Complements the confinement test from the other direction: the Security
    Agent's tools are unique to it — no other routable specialist carries any of
    them, and it carries none of theirs. A scope/agent-hop injection therefore has
    no shared tool to pivot through (the allow-lists are disjoint enumerated sets,
    not an open API).
    """
    registry = build_default_registry()
    agents = [a for a in registry.list() if a.name != SUPERVISOR_NAME]
    tools_by_agent = {a.name: {t.name for t in a.tools} for a in agents}
    security_tools = tools_by_agent[_SECURITY_SPECIALIST]

    for other, names in tools_by_agent.items():
        if other == _SECURITY_SPECIALIST:
            continue
        shared = security_tools & names
        assert not shared, (
            f"security shares tool(s) {sorted(shared)} with {other!r} — the "
            f"per-agent allow-list boundary (ADR-0033) leaks across agents."
        )
