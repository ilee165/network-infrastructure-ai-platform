"""Security Agent supervisor routing + RBAC + ADR-0033 allow-list (P2 W3-T2).

Wires the W3-T1 Security Agent into the platform: it registers with the
``AgentRegistry`` (so the supervisor routes to it), its read tools are reachable by
a viewer while the remediation drafter requires engineer (ADR-0011), and the
ADR-0033 per-agent tool allow-list extends to it (a tool outside its set is
unreachable regardless of prompt). Routing tests are offline and deterministic — a
scripted fake chat model replays a fixed ``RoutingDecision`` (the routing-quality
re-run is the W5-T2 real-LLM eval), so they prove the wiring, not model judgment.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from app.agents import build_default_registry, build_default_supervisor
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.agents.framework.tools import (
    RbacForbiddenError,
    ToolClassification,
    agent_run_context,
)
from app.agents.security.agent import SECURITY_NAME
from app.core.security import Role
from tests.agents.conftest import scripted_model

DEVICE = "11111111-1111-1111-1111-111111111111"


def _routing_reply(*, specialist: str | None, ambiguous: bool = False) -> AIMessage:
    """A scripted structured-routing reply (a ``RoutingDecision`` tool call)."""
    args: dict[str, Any] = {
        "specialist": specialist,
        "ambiguous": ambiguous,
        "rationale": "scripted decision",
    }
    return AIMessage(
        content="",
        tool_calls=[{"name": "RoutingDecision", "args": args, "id": "route-1"}],
    )


# ---------------------------------------------------------------------------
# Registration (ADR-0003)
# ---------------------------------------------------------------------------


class TestSecurityRegistration:
    def test_security_is_in_the_default_registry(self) -> None:
        assert SECURITY_NAME in set(build_default_registry().names())

    def test_security_is_a_reachable_router_node(self) -> None:
        graph = build_default_supervisor(scripted_model([]))
        assert SECURITY_NAME in set(graph.get_graph().nodes)

    def test_security_description_is_distinct_from_troubleshooting(self) -> None:
        # ADR-0037 §5: the split must be concrete so the router does not oscillate
        # between security and troubleshooting (both own "firewall" in CLAUDE.md).
        registry = build_default_registry()
        security_desc = registry.get(SECURITY_NAME).description
        troubleshooting_desc = registry.get("troubleshooting").description
        assert security_desc.strip()
        assert security_desc != troubleshooting_desc
        # The security description claims posture/audit-over-data and disclaims
        # live single-flow troubleshooting.
        lowered = security_desc.lower()
        assert "audit" in lowered
        assert "troubleshooting" in lowered


# ---------------------------------------------------------------------------
# Routing — the Troubleshooting / Security split (ADR-0037 §5)
# ---------------------------------------------------------------------------


class TestSecurityRouting:
    async def test_policy_audit_routes_to_security(self) -> None:
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist=SECURITY_NAME),
                    AIMessage(content="Rule allow-any is overly permissive (any->any)."),
                ]
            )
        )
        result = await sub.ainvoke(
            {"messages": [HumanMessage(content="audit the firewall policy on fw-1")]}
        )
        assert result["specialist"] == SECURITY_NAME

    async def test_live_flow_fault_routes_to_troubleshooting_not_security(self) -> None:
        # A live single-flow reachability fault stays with troubleshooting — the
        # ADR-0037 split. Scripted, but it pins that the roster makes the decision
        # routable (the description disambiguation is the real signal at runtime).
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist="troubleshooting"),
                    AIMessage(content="ACL 101 line 20 denies 10.0.1.5 -> DB."),
                ]
            )
        )
        result = await sub.ainvoke(
            {
                "messages": [
                    HumanMessage(
                        content="why is traffic from 10.0.1.5 to the DB blocked right now?"
                    )
                ]
            }
        )
        assert result["specialist"] == "troubleshooting"
        assert result["specialist"] != SECURITY_NAME


# ---------------------------------------------------------------------------
# Read-only RBAC (ADR-0011): read tools <= change tool in privilege
# ---------------------------------------------------------------------------


class TestSecurityRbac:
    async def test_viewer_can_run_read_only_analysis(self) -> None:
        # READ_ONLY analysis tools carry the least-privilege min_role (viewer), so
        # a viewer can audit posture — "an agent can never do what its user cannot"
        # does not block a read.
        agent = build_default_registry().get(SECURITY_NAME)
        analyze = {t.name: t for t in agent.tools}["analyze_firewall_policy"]
        with agent_run_context(role=Role.VIEWER):
            result = await analyze.ainvoke({"device_id": DEVICE, "rules": []})
        assert '"findings"' in result  # ran and returned a findings envelope

    def test_read_tools_are_not_above_the_change_tool_in_privilege(self) -> None:
        agent = build_default_registry().get(SECURITY_NAME)
        by_class = {t.name: t for t in agent.tools}
        read_roles = [
            t.min_role
            for t in by_class.values()
            if t.classification is ToolClassification.READ_ONLY
        ]
        change_tool = next(
            t for t in by_class.values() if t.classification is ToolClassification.STATE_CHANGING
        )
        # Every read tool ranks at or below the change-proposal tool.
        for role in read_roles:
            assert change_tool.min_role.can_act_as(role)
        assert change_tool.min_role is Role.ENGINEER

    async def test_viewer_cannot_reach_the_remediation_drafter(self) -> None:
        agent = build_default_registry().get(SECURITY_NAME)
        propose = {t.name: t for t in agent.tools}["propose_firewall_remediation"]
        with agent_run_context(role=Role.VIEWER), pytest.raises(RbacForbiddenError):
            await propose.ainvoke(
                {"device_id": DEVICE, "rule_name": "allow-any", "remediation": "disable"}
            )


# ---------------------------------------------------------------------------
# ADR-0033 per-agent tool allow-list / injection boundary
# ---------------------------------------------------------------------------


class TestSecurityInjectionBoundary:
    def test_security_tools_do_not_leak_into_other_agents(self) -> None:
        registry = build_default_registry()
        agents = [a for a in registry.list() if a.name != SUPERVISOR_NAME]
        tools_by_agent = {a.name: {t.name for t in a.tools} for a in agents}
        security_tools = tools_by_agent[SECURITY_NAME]
        for other, names in tools_by_agent.items():
            if other == SECURITY_NAME:
                continue
            assert not (security_tools & names), f"security shares tools with {other}"

    def test_security_allow_list_excludes_other_agents_write_tools(self) -> None:
        # An injected "now run a config restore / add a DNS record / execute the
        # CR" cannot reach a tool the security agent never registered — the
        # allow-list is an enumerated set, not an open API (ADR-0033 §6).
        registry = build_default_registry()
        security_tool_names = {t.name for t in registry.get(SECURITY_NAME).tools}
        for foreign in (
            "add_dns_record",  # ddi mutator
            "modify_dns_record",
            "summarize_change_request",  # automation
            "explain_drift_diff",  # configuration
            "deploy_config",  # not registered to ANY agent
            "execute_change_request",
            "push_config",
        ):
            assert foreign not in security_tool_names

    def test_security_only_write_surface_is_the_gate_routed_remediation(self) -> None:
        # The single state-changing tool is the gate-routed remediation drafter;
        # there is no device-executing tool. An injected request can at most reach
        # this gate (a blocked CR draft), never a device write (ADR-0037 §1).
        agent = build_default_registry().get(SECURITY_NAME)
        state_changing = [
            t for t in agent.tools if t.classification is ToolClassification.STATE_CHANGING
        ]
        assert [t.name for t in state_changing] == ["propose_firewall_remediation"]
        assert not [t for t in agent.tools if t.classification is ToolClassification.DIAGNOSTIC]
