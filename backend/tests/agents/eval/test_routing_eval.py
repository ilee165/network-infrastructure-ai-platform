"""Real-LLM supervisor routing eval (manual gate).

Validates that the Master Architect routes fault/diagnosis questions to the
``troubleshooting`` specialist and enumeration questions to ``discovery``, using
a REAL local model (not the ``ScriptedChatModel`` the deterministic suite uses,
which replays a fixed ``RoutingDecision`` and so cannot test routing quality).

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
# examples baked into ``SUPERVISOR_ROUTING_PROMPT_V3`` — EXCEPT the first, which
# is intentionally the exact production regression query (it overlaps a few-shot
# example by design, and asserts that the specific reported bug stays dead). If
# a case were a verbatim copy of a prompt example, a model could pass it by
# pattern-matching the demonstration instead of applying the diagnosis-vs-
# enumeration rule and the sharpened specialist descriptions the route node
# actually relies on.
_CASES = [
    # Exact regression anchor — overlaps a v3 few-shot example on purpose.
    (
        "Why can't guest users on 10.0.99.0/24 reach the internet? Read the routing "
        "table on the edge firewall edge-fw-01.",
        "troubleshooting",
    ),
    # Held-out troubleshooting (none of these appear in the v3 few-shot block):
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
    # Held-out discovery / enumeration (none appear in the v3 few-shot block):
    ("Show me every Cisco device we currently manage.", "discovery"),
    ("How many switches are in the inventory right now?", "discovery"),
    ("Show me the LLDP neighbors of core-sw-01.", "discovery"),
]


def _routable_roster() -> str:
    """
    Build the roster string of specialists for the routing prompt.
    
    Each registered agent except the supervisor is formatted as "- {name}: {description}"
    and joined with newlines.
    """
    registry = build_default_registry()
    agents = [agent for agent in registry.list() if agent.name != SUPERVISOR_NAME]
    return "\n".join(f"- {agent.name}: {agent.description}" for agent in agents)


@pytest.mark.parametrize(("intent", "expected"), _CASES)
async def test_routing_picks_expected_specialist(intent: str, expected: str) -> None:
    """
    Verify the supervisor routing node selects the expected specialist for a given intent.
    
    Parameters:
        intent: A user query to evaluate for routing.
        expected: The specialist name that should handle the intent.
    """
    settings = Settings()  # reads NETOPS_LLM_LOCAL_MODEL / profile from env
    llm = get_chat_model("local", settings)
    prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)  # latest registered (v3)
    system = SystemMessage(content=prompt.text.format(specialists=_routable_roster()))
    router = llm.with_structured_output(RoutingDecision)
    decision = await router.ainvoke([system, HumanMessage(content=intent)])
    assert isinstance(decision, RoutingDecision)
    assert decision.specialist == expected, f"{intent!r} routed to {decision!r}"
