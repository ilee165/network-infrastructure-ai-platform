"""W7-T3 cross-vendor routing re-run — DETERMINISTIC layer (runs in CI).

Sibling deliverable to the prompt-injection suite (ADR-0033 §5: the cross-vendor
routing re-run is "a sibling W7 deliverable, not part of [the injection]
corpus"). This module is the **deterministic, CI-collected half** of W7-T3; the
real-LLM routing re-run lives in ``test_routing_eval.py`` (Ollama-gated,
module-skipped without ``NETOPS_RUN_ROUTING_EVAL=1``), which this file
deliberately does NOT depend on so the guardrail below runs on every CI push.

What layer proves what
----------------------

* **This file (deterministic, in CI):** proves *wiring/coverage* — that the three
  P1 Wave-1 vendor plugins (``cisco_nxos``, ``junos``, ``bluecat``) are present in
  the registry the platform routes their intents through, and that the routing
  *specialist* roster the supervisor decides over is and stays registry-derived
  and complete. It does NOT prove a model routes a Junos fault to troubleshooting
  — that is model judgment a scripted replay cannot validate
  (``.claude/agents/wf-eval-designer.md``).
* **The real-LLM re-run (``test_routing_eval.py``, manual gate):** proves
  *routing quality* — a real local model routes each new vendor's held-out
  intents to the correct existing specialist. Deferred-accepted when no local
  model is available (no hardware, same posture as P1 W1/W2). The held-out
  cross-vendor cases for the 3 new plugins were added to that file.

Roster source — CONFIRMED registry-derived, NOT a hardcoded list
----------------------------------------------------------------

The W7-T3 spec's first exit criterion is to confirm whether the routing roster
is registry-derived (auto-includes new plugins) or a hardcoded list needing
extension. Two distinct "rosters" are in play and the grounding check (the three
plugin names are not referenced inline in ``test_routing_eval.py`` today) is
explained by *which* roster each is:

1. **Routing specialist roster** — what the Master Architect supervisor decides
   over. Built by ``_routable_roster()`` from ``build_default_registry().list()``
   minus the supervisor (``app/agents/__init__.py``). It is **registry-derived**:
   any agent added to the composition root auto-appears. The three Wave-1 names do
   NOT appear here because **they are not routable specialist agents** — they are
   ``VendorPlugin`` drivers (``app/plugins/``) consumed by the *existing*
   configuration / troubleshooting / ddi specialists. The specialist roster is
   therefore correctly unchanged at eight, and there is no specialist-roster
   regression for the supervisor to suffer (W7-T3 requirement 1).

2. **Vendor plugin roster** — what ``app/plugins/registry.get_default_registry``
   resolves ``(vendor_id, capability)`` over. This is the roster P1 W1 actually
   grew. It is **also registry-derived** (built from
   ``iter_builtin_plugins()``), so the new plugins auto-register — but a
   registry-derived list can still silently *lose* a member (a dropped
   ``yield``), which is exactly the risk W7-T3 names. The assertion below is the
   guardrail: it fails in CI if any of the three Wave-1 plugins is absent, with no
   live model required.

No new routing reference cases belong here: the new vendors do not add routing
*targets*, so the held-out ``(intent -> expected specialist)`` cases that confirm
each vendor's intents reach the right existing specialist are model-judgment and
live in the Ollama-gated ``test_routing_eval.py``.
"""

from __future__ import annotations

from app.agents import build_default_registry
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.plugins.registry import get_default_registry

#: The three P1 Wave-1 vendor plugins whose intents W7-T3 re-runs routing for
#: (``vendor_id`` values, ADR-0025 cisco_nxos / ADR-0026 junos / ADR-0027
#: bluecat). The supervisor routes their intents to existing specialists
#: (NX-OS config drift -> configuration, JunOS routing fault -> troubleshooting,
#: BlueCat DNS record -> ddi); the plugins themselves are vendor drivers, not
#: routing targets.
_WAVE1_VENDOR_PLUGINS = frozenset({"cisco_nxos", "junos", "bluecat"})

#: The specialist agent each Wave-1 vendor's intents route to. Pinned so the
#: guardrail also documents the cross-vendor routing contract the real-LLM
#: re-run exercises: a vendor plugin must have a live routable specialist owning
#: its intents, or its held-out routing cases would have no valid target.
_VENDOR_TO_SPECIALIST = {
    "cisco_nxos": "configuration",
    "junos": "troubleshooting",
    "bluecat": "ddi",
}


def test_wave1_vendor_plugins_present_in_registry() -> None:
    """The 3 P1 Wave-1 plugins are registered in the vendor plugin roster.

    Registry-derived (``iter_builtin_plugins`` -> ``get_default_registry``) but a
    dropped ``yield`` could silently remove one, so this CI-collected assertion is
    the guardrail W7-T3 requires: absence is caught with no live model. This is
    the "deterministic plugins-present-in-roster assertion green in CI" exit
    criterion.
    """
    registered = set(get_default_registry().vendor_ids())
    missing = _WAVE1_VENDOR_PLUGINS - registered
    assert not missing, (
        f"P1 Wave-1 vendor plugin(s) {sorted(missing)} absent from the registry "
        f"(registered: {sorted(registered)}) — cross-vendor routing for them "
        f"cannot work; check app/plugins/vendors/__init__.iter_builtin_plugins()."
    )


def test_routing_specialist_roster_is_registry_derived_and_complete() -> None:
    """The supervisor's specialist roster is registry-derived; vendors are NOT in it.

    Confirms the W7-T3 roster-source question: the routing roster auto-derives
    from the composition root (``build_default_registry`` minus the supervisor),
    so it never needs a hardcoded edit when a vendor plugin lands. It also pins
    the architectural boundary the spec's grounding check observed — the three
    Wave-1 plugin names are *not* routing targets, so they correctly never appear
    in the specialist roster. Every Wave-1 vendor's owning specialist, however,
    MUST be a live routable specialist, or its cross-vendor routing cases would
    have no valid target.
    """
    registry = build_default_registry()
    routable = {agent.name for agent in registry.list() if agent.name != SUPERVISOR_NAME}

    # Vendor plugins are drivers, not routable specialists — never in the roster.
    leaked_vendors = _WAVE1_VENDOR_PLUGINS & routable
    assert not leaked_vendors, (
        f"vendor plugin id(s) {sorted(leaked_vendors)} appeared as routable "
        f"specialists — vendor plugins are drivers, not routing targets."
    )

    # Each Wave-1 vendor's owning specialist must be a live routing target.
    owners = set(_VENDOR_TO_SPECIALIST.values())
    missing_owners = owners - routable
    assert not missing_owners, (
        f"specialist(s) {sorted(missing_owners)} that own Wave-1 vendor intents "
        f"are absent from the routable roster {sorted(routable)} — their "
        f"cross-vendor routing cases in test_routing_eval.py have no valid target."
    )
