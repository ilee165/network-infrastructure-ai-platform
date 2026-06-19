"""Real-LLM supervisor routing eval (manual gate) — EIGHT-way roster (M5 T14).

Validates that the Master Architect routes each intent to the correct specialist
across the FULL M4 roster — troubleshooting (fault diagnosis), discovery
(inventory enumeration), **configuration** (drift / compliance narration), and
**documentation** (inventory / diagram / runbook generation) — using a REAL
local model (not the ``ScriptedChatModel`` the deterministic suite uses, which
replays a fixed ``RoutingDecision`` and so cannot test routing quality).

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
]

#: The eight specialists the supervisor routes over in M5 (every routable agent
#: in the production registry except the supervisor itself). Each expected label
#: below must be one of these — a guard so a typo in a case can never silently
#: pass.
_ROUTABLE_SPECIALISTS = {
    "troubleshooting",
    "discovery",
    "configuration",
    "documentation",
    "ddi",
    "packet_analysis",
    "automation",
    "consultant",
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


def test_roster_exposes_the_full_eight_way_set() -> None:
    """Sanity: the production roster the eval routes over holds all eight M5 specialists.

    A guard so the eval can never silently shrink: if a specialist were dropped
    from the composition root, its held-out cases would have no valid target.
    Also pins every expected label in ``_CASES`` to a real routable specialist.
    """
    registry = build_default_registry()
    routable = {agent.name for agent in registry.list() if agent.name != SUPERVISOR_NAME}
    assert routable >= _ROUTABLE_SPECIALISTS, (
        f"roster {routable} is missing one of the M5 specialists"
    )
    expected_labels = {expected for _, expected in _CASES}
    assert expected_labels <= _ROUTABLE_SPECIALISTS, (
        f"a case expects a non-routable specialist: {expected_labels - _ROUTABLE_SPECIALISTS}"
    )


@pytest.mark.parametrize(("intent", "expected"), _CASES)
async def test_routing_picks_expected_specialist(intent: str, expected: str) -> None:
    settings = Settings()  # reads NETOPS_LLM_LOCAL_MODEL / profile from env
    llm = get_chat_model("local", settings)
    prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)  # latest registered (v5, eight-way)
    system = SystemMessage(content=prompt.text.format(specialists=_routable_roster()))
    router = llm.with_structured_output(RoutingDecision)
    decision = await router.ainvoke([system, HumanMessage(content=intent)])
    assert isinstance(decision, RoutingDecision)
    assert decision.specialist == expected, f"{intent!r} routed to {decision!r}"
