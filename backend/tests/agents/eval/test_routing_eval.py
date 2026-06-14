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
_CASES = [
    (
        "Why can't guest users on 10.0.99.0/24 reach the internet? Read the routing "
        "table on the edge firewall edge-fw-01.",
        "troubleshooting",
    ),
    ("Is BGP peer 10.0.0.2 down on edge-1, and why?", "troubleshooting"),
    (
        "The OSPF adjacency to core-sw-01 is stuck in EXSTART — what is wrong?",
        "troubleshooting",
    ),
    ("List all managed devices in the inventory.", "discovery"),
    ("What devices did the last discovery run find?", "discovery"),
    ("Show me the LLDP neighbors of core-sw-01.", "discovery"),
]


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


@pytest.mark.parametrize(("intent", "expected"), _CASES)
async def test_routing_picks_expected_specialist(intent: str, expected: str) -> None:
    settings = Settings()  # reads NETOPS_LLM_LOCAL_MODEL / profile from env
    llm = get_chat_model("local", settings)
    prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)  # latest registered (v3)
    system = SystemMessage(content=prompt.text.format(specialists=_routable_roster()))
    router = llm.with_structured_output(RoutingDecision)
    decision = await router.ainvoke([system, HumanMessage(content=intent)])
    assert isinstance(decision, RoutingDecision)
    assert decision.specialist == expected, f"{intent!r} routed to {decision!r}"
