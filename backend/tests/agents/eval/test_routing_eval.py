"""Real-LLM supervisor routing eval (manual gate) — NINE-way roster (P2 W5-T2).

Validates that the Master Architect routes each intent to the correct specialist
across the FULL roster — troubleshooting (fault diagnosis), discovery
(inventory enumeration), **configuration** (drift / compliance narration),
**documentation** (inventory / diagram / runbook generation), ddi, packet
analysis, automation, consultant, and **security** (firewall-policy / posture
audit, P2 W3) — using a REAL local model (not the ``ScriptedChatModel`` the
deterministic suite uses, which replays a fixed ``RoutingDecision`` and so cannot
test routing quality).

P2 W5-T2 cross-vendor + Security-Agent routing re-run
-----------------------------------------------------
This module is the **real-LLM half** of W5-T2 (PRODUCTION.md §2.6 — no
cross-vendor eval regression). It is the same harness the M4 5-way / M5 8-way /
P1 W7-T3 routing re-runs used (requirement 4: same harness => apples-to-apples
comparison). W5-T2 extends it for P2's two new pieces:

* **Security Agent (P2 W3, ADR-0037):** held-out cases that must route to the new
  ``security`` specialist — firewall-policy hygiene audits (shadowed /
  overly-permissive rule review) and posture checks. The no-regression guard is
  that adding this ninth specialist did NOT steal routing from troubleshooting /
  configuration / ddi (W5-T2 risk: a broad security description pulls
  diagnosis/config prompts). Every prior case below is unchanged in wording and
  expected label, so any drift in the prior matrix bites here.
* **panos / fortios (P2 W2, ADR-0035/0036):** like the P1 Wave-1 plugins, these
  are vendor DRIVERS, not routing targets — their intents route to the EXISTING
  specialist that owns the capability (PAN-OS firewall-policy audit -> security;
  FortiOS routing fault -> troubleshooting; FortiOS config drift -> configuration).
  Held-out cases name each new vendor's hardware explicitly so a pass reflects the
  audit-vs-diagnose-vs-narrate boundary holding under vendor-specific phrasing.

The deterministic, CI-collected guardrail for W5-T2 (panos/fortios present in the
vendor registry, the security specialist registered + routable, the prior 8
specialists not lost, and the ADR-0033 read-only allow-list confined to the
security agent's own tools) lives in the sibling ``test_p2_cross_vendor_routing.py``
(runs without a local model); the live re-run here is **deferred-accepted** when
no local model is available (no hardware, same posture as the prior matrices).

M4 widens the supervisor's decision from three routable specialists to five
(M4 risk #2: the wider disambiguation surface is exactly the failure the M3
routing fix addressed). This eval is the real-LLM proof that routing prompt v4 +
the sharpened five specialist descriptions hold the new boundaries —
configuration (narrate existing config state) vs documentation (produce
artifacts) vs troubleshooting (diagnose a live fault) — under a real model.

Scope — this eval tests the ROUTING DECISION, not specialist execution. It
reproduces exactly what the supervisor's ``route`` node does
(``app.agents.framework.supervisor.build_supervisor_graph``, ~lines 187-205):

    prompt  = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)          # latest == v3
    roster  = "\\n".join(f"- {a.name}: {a.description}" for a in routable_agents)
    system  = SystemMessage(prompt.text.format(specialists=roster))
    router  = llm.with_structured_output(RoutingDecision)
    decision = await router.ainvoke([system, *messages])

It deliberately does NOT call ``run_supervisor`` / drive the full graph: that
would execute the chosen specialist's subgraph, whose real tools
(``list_devices``, ``get_device_routes``, ...) need a live Postgres/device
backend — which is why the provider-parity eval fakes them via
``build_eval_registry`` / ``bgp_tool_patched``. Backend availability is
orthogonal to *routing quality*, so coupling to it would make this gate flaky
for reasons unrelated to the fix it guards. The roster is the real production
roster (real specialist ``description`` properties under test) built from
``build_default_registry`` minus the supervisor, identical to what the graph
routes over.

W7-T3 cross-vendor re-run (P1 Wave-1 plugins)
---------------------------------------------
This is also the cross-vendor routing re-run for the three P1 Wave-1 vendor
plugins (``cisco_nxos``, ``junos``, ``bluecat``) — ADR-0033 §5's "sibling W7
deliverable, not part of [the injection] corpus". Three held-out cases at the end
of ``_CASES`` route each new vendor's intents to its owning *existing* specialist
(NX-OS config drift -> configuration, JunOS routing fault -> troubleshooting,
BlueCat DNS lookup -> ddi). Roster source is **registry-derived**: the routing
roster comes from ``build_default_registry()`` minus the supervisor, so it needs
no hardcoded edit for a new vendor — and the three Wave-1 names are correctly
*absent* from it because they are vendor drivers, not routing targets (the
specialist roster is unchanged at eight). The deterministic, CI-collected
guardrail that those plugins are present in the *vendor* registry lives in the
sibling ``test_p1_cross_vendor_routing.py`` (runs without a local model); the
live re-run here is **deferred-accepted** when no local model is available (no
hardware, same posture as W1/W2).

Non-deterministic + needs a running Ollama, so — like provider parity and the
M1/M2 live-lab gates — it is opt-in and skipped in CI:

    ollama pull qwen3:8b                     # or any capable local model
    export NETOPS_RUN_ROUTING_EVAL=1
    export NETOPS_LLM_LOCAL_MODEL=qwen3:8b   # model under test
    pytest -m routing backend/tests/agents/eval/test_routing_eval.py -q
"""

from __future__ import annotations

import os

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents import build_default_registry
from app.agents.framework.supervisor import SUPERVISOR_NAME, RoutingDecision
from app.core.config import Settings
from app.llm.prompts import SUPERVISOR_ROUTING_PROMPT_ID, get_prompt
from app.llm.providers import get_chat_model

_FLAG = "NETOPS_RUN_ROUTING_EVAL"

pytestmark = pytest.mark.routing

if not os.environ.get(_FLAG):
    pytest.skip(
        f"routing eval is a manual gate; set {_FLAG}=1 (needs a local Ollama) to run it.",
        allow_module_level=True,
    )

# (intent, expected specialist). Each must route correctly for the eval to pass.
#
# To measure GENERALIZATION rather than in-context echoing, every case below is
# HELD OUT — a distinct protocol / device / subnet / wording from the few-shot
# examples baked into ``SUPERVISOR_ROUTING_PROMPT_V4`` — EXCEPT the first, which
# is intentionally the exact production regression query (it overlaps a few-shot
# example by design, and asserts that the specific reported bug stays dead). If
# a case were a verbatim copy of a prompt example, a model could pass it by
# pattern-matching the demonstration instead of applying the diagnosis-vs-
# enumeration-vs-config-vs-docs rules and the sharpened five specialist
# descriptions the route node actually relies on.
#
# The configuration and documentation cases (added for the M4 five-way roster)
# are deliberately worded UNLIKE the v4 few-shot examples: v4 demonstrates
# 'What changed in core-1's config…' and 'Generate a network inventory…'; the
# held-out cases below say 'how does its current config compare to the signed-off
# baseline' and 'I need a CSV listing of every interface' — same intent, fresh
# wording, so a pass reflects the config-vs-docs boundary, not echoing.
_CASES = [
    # Exact regression anchor — overlaps a v4 few-shot example on purpose.
    (
        "Why can't guest users on 10.0.99.0/24 reach the internet? Read the routing "
        "table on the edge firewall edge-fw-01.",
        "troubleshooting",
    ),
    # Held-out troubleshooting (none of these appear in the v4 few-shot block):
    (
        "core-sw-02 stopped advertising 192.168.40.0/24 to its OSPF neighbor — read "
        "its routing table and tell me why.",
        "troubleshooting",
    ),
    (
        "The OSPF adjacency to core-sw-01 is stuck in EXSTART — what is wrong?",
        "troubleshooting",
    ),
    (
        "Tenant VLAN 30 lost connectivity after last night's change; check the "
        "firewall ACLs to find the cause.",
        "troubleshooting",
    ),
    # Held-out discovery / enumeration (none appear in the v4 few-shot block):
    ("Show me every Cisco device we currently manage.", "discovery"),
    ("How many switches are in the inventory right now?", "discovery"),
    ("Show me the LLDP neighbors of core-sw-01.", "discovery"),
    # Held-out CONFIGURATION — drift / compliance narration of EXISTING config
    # state (read-only). Worded apart from the v4 demonstrations, and apart from
    # troubleshooting: these ask "what diverged" / "does it meet policy", never
    # "why is something broken".
    (
        "How does dist-sw-07's running config compare to the signed-off baseline "
        "we approved last quarter?",
        "configuration",
    ),
    (
        "Does access-sw-12 satisfy our hardening standard, and list any rules it "
        "fails with their severity.",
        "configuration",
    ),
    (
        "Walk me through every line that diverged from baseline on border-rtr-03.",
        "configuration",
    ),
    # Held-out DOCUMENTATION — PRODUCE an artifact (inventory / diagram /
    # runbook). Worded apart from the v4 demonstrations; the intent is to
    # generate/export a document, not to explain config or diagnose a fault.
    (
        "I need a CSV listing of every interface and its neighbor for the west-campus "
        "site to hand to the auditors.",
        "documentation",
    ),
    (
        "Draw up a Mermaid topology of the distribution layer so I can drop it in the design doc.",
        "documentation",
    ),
    (
        "Put together an operational runbook for border-rtr-03 covering its role and "
        "health checks.",
        "documentation",
    ),
    # Held-out DDI — DNS/DHCP analysis and DNS/DHCP record change DRAFTING (M5
    # T14). Worded apart from the v5 demonstrations. The change case must route
    # to ddi (it DRAFTS a change request), never to automation (M5-PLAN risk #4).
    (
        "Which IP does the host record for billing-app.corp.example resolve to right now?",
        "ddi",
    ),
    (
        "Is the DHCP pool for the guest-wifi VLAN close to exhausting its leases?",
        "ddi",
    ),
    (
        "Please create an A record for printer-09.corp.example pointing at 10.2.3.40.",
        "ddi",
    ),
    # Held-out PACKET_ANALYSIS — summarize/query a FINISHED capture (M5 T14).
    (
        "From the capture we pulled off span-port-2, who were the busiest talkers?",
        "packet_analysis",
    ),
    (
        "In that pcap from this morning, how many TCP retransmissions did you see?",
        "packet_analysis",
    ),
    # Held-out AUTOMATION — EXECUTE an ALREADY-APPROVED change request only.
    (
        "Change request CR-1009 has been approved — go ahead and run it.",
        "automation",
    ),
    # Held-out CONSULTANT — ambiguous / multi-intent requests where the correct
    # action is to escalate for clarification rather than to act unilaterally.
    # Worded to be genuinely ambiguous across multiple specialists so a capable
    # model escalates instead of guessing. These are HELD OUT: none of these
    # phrasings appear in the v5 routing prompt few-shot examples.
    (
        "Can you help with the network issues we've been seeing"
        " and maybe sort out the DNS at the same time?",
        "consultant",
    ),
    (
        "Something is wrong — devices are unreachable, configs look off,"
        " and I think we need new DNS records too. Where do we start?",
        "consultant",
    ),
    # ------------------------------------------------------------------ #
    # W7-T3 cross-vendor re-run — the three P1 Wave-1 plugins (cisco_nxos,
    # junos, bluecat). These plugins are vendor DRIVERS, not routing targets:
    # the supervisor routes their intents to the EXISTING specialist that owns
    # the vendor's capability. The re-run confirms no routing regression when a
    # query is phrased around a new vendor's device/feature. Each case names the
    # new vendor's hardware/feature explicitly and is HELD OUT — fresh device
    # names, subnets, and wording distinct from the v5 few-shot examples — so a
    # pass reflects the diagnose-vs-narrate-vs-DDI boundary holding under
    # vendor-specific phrasing, not echoing a demonstration.
    #
    # cisco_nxos (NX-OS): config drift / compliance narration -> configuration.
    (
        "Compare nxos-agg-04's running config against the VXLAN baseline we signed "
        "off — which NX-OS features drifted?",
        "configuration",
    ),
    # junos (JunOS): live routing-fault diagnosis -> troubleshooting.
    (
        "Our Juniper mx-edge-02 stopped exporting 172.20.8.0/22 into BGP overnight — "
        "read its route table and tell me why.",
        "troubleshooting",
    ),
    # bluecat (BlueCat DDI): DNS record analysis / drafting -> ddi.
    (
        "In BlueCat, what address does the host record for vpn-gw.corp.example "
        "currently resolve to?",
        "ddi",
    ),
    # ------------------------------------------------------------------ #
    # P2 W5-T2 — Security Agent (ADR-0037) + Vendor Wave 2 (panos/fortios,
    # ADR-0035/0036) cross-vendor re-run. The Security Agent is the ninth routable
    # specialist; panos/fortios are vendor DRIVERS (not routing targets) whose
    # intents route to the existing owning specialist. Every case below is HELD
    # OUT — fresh device names, vendors, and wording distinct from the routing
    # prompt's few-shot examples — so a pass reflects the audit-vs-diagnose-vs-
    # narrate-vs-DDI boundary holding, not echoing a demonstration. The two
    # security cases also guard W5-T2's no-regression contract from the OTHER
    # direction: a vendor-neutral firewall-hygiene audit must reach security, never
    # be stolen by troubleshooting or configuration.
    #
    # security: firewall-policy hygiene audit (policy-as-data review) -> security.
    # Worded apart from a live single-flow fault ("why is THIS flow blocked now?"
    # would be troubleshooting) and apart from config drift ("compare to baseline"
    # would be configuration): these ask "which rules are shadowed / too broad?".
    (
        "Audit the firewall policy on dc-fw-09 — which rules are shadowed or "
        "overly permissive, and what's the security posture?",
        "security",
    ),
    (
        "Review our perimeter ruleset and tell me which permit rules are redundant "
        "or expose management access from any source.",
        "security",
    ),
    # panos (PAN-OS, ADR-0035): firewall-policy hygiene audit -> security. Names
    # the PAN-OS device explicitly; the intent is policy-hygiene review, which the
    # Security Agent owns regardless of vendor.
    (
        "On the Palo Alto pan-edge-02, which security policy rules are shadowed by "
        "an earlier broader rule? Audit the policy.",
        "security",
    ),
    # fortios (FortiOS, ADR-0036): a LIVE routing fault on a FortiGate ->
    # troubleshooting (diagnose a single broken flow, not audit policy hygiene).
    (
        "Our FortiGate fgt-wan-01 stopped advertising 203.0.113.0/24 to its BGP "
        "peer this morning — read its route table and tell me why.",
        "troubleshooting",
    ),
    # fortios (FortiOS, ADR-0036): config drift / compliance narration ->
    # configuration (what diverged from baseline, not why a flow is broken, not a
    # policy-hygiene audit).
    (
        "How does fgt-branch-14's running config compare to the FortiOS hardening "
        "baseline we signed off last quarter?",
        "configuration",
    ),
]

#: The nine specialists the supervisor routes over after P2 W3 (every routable
#: agent in the production registry except the supervisor itself; ``security``
#: added in W3-T2). Each expected label below must be one of these — a guard so a
#: typo in a case can never silently pass.
_ROUTABLE_SPECIALISTS = {
    "troubleshooting",
    "discovery",
    "configuration",
    "documentation",
    "ddi",
    "packet_analysis",
    "automation",
    "consultant",
    "security",
}


def _routable_roster() -> str:
    """Build the production routing roster (real specialist descriptions).

    Mirrors ``build_supervisor_graph``: every registered agent except the
    supervisor itself, formatted as the ``"- {name}: {description}"`` lines the
    routing prompt's ``{specialists}`` placeholder is filled with. Built from the
    real composition root so the descriptions under test are the production ones.
    """
    registry = build_default_registry()
    agents = [agent for agent in registry.list() if agent.name != SUPERVISOR_NAME]
    return "\n".join(f"- {agent.name}: {agent.description}" for agent in agents)


def test_roster_exposes_the_full_nine_way_set() -> None:
    """Sanity: the production roster the eval routes over holds all nine P2 specialists.

    A guard so the eval can never silently shrink: if a specialist were dropped
    from the composition root, its held-out cases would have no valid target. This
    is also the W5-T2 no-regression anchor for the roster itself — the eight prior
    specialists plus ``security`` must all remain routable. Also pins every
    expected label in ``_CASES`` to a real routable specialist.
    """
    registry = build_default_registry()
    routable = {agent.name for agent in registry.list() if agent.name != SUPERVISOR_NAME}
    assert routable >= _ROUTABLE_SPECIALISTS, (
        f"roster {routable} is missing one of the nine P2 specialists"
    )
    expected_labels = {expected for _, expected in _CASES}
    assert expected_labels <= _ROUTABLE_SPECIALISTS, (
        f"a case expects a non-routable specialist: {expected_labels - _ROUTABLE_SPECIALISTS}"
    )


@pytest.mark.parametrize(("intent", "expected"), _CASES)
async def test_routing_picks_expected_specialist(intent: str, expected: str) -> None:
    settings = Settings()  # reads NETOPS_LLM_LOCAL_MODEL / profile from env
    llm = get_chat_model("local", settings)
    prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)  # latest registered (P2 nine-way)
    system = SystemMessage(content=prompt.text.format(specialists=_routable_roster()))
    router = llm.with_structured_output(RoutingDecision)
    decision = await router.ainvoke([system, HumanMessage(content=intent)])
    assert isinstance(decision, RoutingDecision)
    assert decision.specialist == expected, f"{intent!r} routed to {decision!r}"
