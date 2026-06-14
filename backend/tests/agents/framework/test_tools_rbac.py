"""RBAC enforcement tests for the tool wrappers (app/agents/framework/tools.py).

Brief §7: "an agent can never do what its user cannot." Every tool declares a
minimum role; the invoking user's role is threaded into the tool run via the
``agent_run_context`` contextvar. A caller below the tool's minimum role is
denied without the tool body ever running, an audit event with
``outcome="denied"`` is recorded (carrying required vs actual role), and a 403
``RbacForbiddenError`` is raised.
"""

from __future__ import annotations

import pytest

from app.agents.framework.tools import (
    NetOpsTool,
    RbacForbiddenError,
    ToolClassification,
    ToolDefinitionError,
    agent_run_context,
    netops_tool,
)
from app.core.security import Role
from tests.agents.conftest import RecordingAuditSink


def _engineer_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(
        classification=ToolClassification.READ_ONLY,
        audit_sink=sink,
        min_role=Role.ENGINEER,
    )
    async def collect_bgp_peers(device: str) -> str:
        """Collect BGP peers from a device (engineer-tier diagnostic read)."""
        return f"peers for {device}"

    return collect_bgp_peers


class TestRbacEnforcement:
    async def test_viewer_denied_on_engineer_tool(self, audit_sink: RecordingAuditSink) -> None:
        tool = _engineer_tool(audit_sink)
        with agent_run_context(role=Role.VIEWER), pytest.raises(RbacForbiddenError) as exc_info:
            await tool.ainvoke({"device": "edge-1"})

        # 403 RFC7807 error, mirrors ApprovalRequiredError.
        assert exc_info.value.status_code == 403
        # Exactly one audit event, recorded BEFORE any execution.
        assert len(audit_sink.events) == 1
        event = audit_sink.events[0]
        assert event.outcome == "denied"
        assert event.tool_name == "collect_bgp_peers"
        # Denial records required vs actual role for the audit trail.
        assert "engineer" in (event.detail or "")
        assert "viewer" in (event.detail or "")

    async def test_viewer_tool_body_never_runs(self, audit_sink: RecordingAuditSink) -> None:
        executed = False

        @netops_tool(
            classification=ToolClassification.READ_ONLY,
            audit_sink=audit_sink,
            min_role=Role.ENGINEER,
        )
        async def collect_bgp_peers(device: str) -> str:
            """Collect BGP peers from a device."""
            nonlocal executed
            executed = True
            return "unreachable"

        with agent_run_context(role=Role.VIEWER), pytest.raises(RbacForbiddenError):
            await collect_bgp_peers.ainvoke({"device": "edge-1"})
        assert executed is False, "the tool body must never run when RBAC denies"

    async def test_engineer_succeeds_on_engineer_tool(self, audit_sink: RecordingAuditSink) -> None:
        tool = _engineer_tool(audit_sink)
        with agent_run_context(role=Role.ENGINEER):
            result = await tool.ainvoke({"device": "edge-1"})
        assert result == "peers for edge-1"
        assert len(audit_sink.events) == 1
        assert audit_sink.events[0].outcome == "success"

    async def test_admin_passes_lower_tier_tool(self, audit_sink: RecordingAuditSink) -> None:
        tool = _engineer_tool(audit_sink)
        with agent_run_context(role=Role.ADMIN):
            result = await tool.ainvoke({"device": "edge-1"})
        assert result == "peers for edge-1"
        assert audit_sink.events[-1].outcome == "success"

    async def test_default_min_role_is_viewer(self, audit_sink: RecordingAuditSink) -> None:
        @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=audit_sink)
        async def list_sites() -> str:
            """List managed sites."""
            return "[]"

        assert list_sites.min_role is Role.VIEWER
        with agent_run_context(role=Role.VIEWER):
            result = await list_sites.ainvoke({})
        assert result == "[]"
        assert audit_sink.events[-1].outcome == "success"

    async def test_missing_run_context_falls_back_to_viewer(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        """No bound run context => least-privileged viewer (can never exceed viewer)."""

        # A viewer-tier tool runs with no context bound.
        @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=audit_sink)
        async def list_sites() -> str:
            """List managed sites."""
            return "[]"

        assert await list_sites.ainvoke({}) == "[]"
        assert audit_sink.events[-1].outcome == "success"

    async def test_missing_run_context_denies_engineer_tool(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        """With no context, the viewer fallback cannot reach an engineer-tier tool."""
        tool = _engineer_tool(audit_sink)
        with pytest.raises(RbacForbiddenError):
            await tool.ainvoke({"device": "edge-1"})
        assert audit_sink.events[-1].outcome == "denied"

    async def test_rbac_denial_precedes_approval_for_state_changing(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        """RBAC is checked before approval: a viewer never reaches the gate."""
        from tests.agents.conftest import ApproveAllGate

        @netops_tool(
            classification=ToolClassification.STATE_CHANGING,
            audit_sink=audit_sink,
            approval_gate=ApproveAllGate(),
            min_role=Role.ENGINEER,
        )
        async def deploy_config(device: str) -> str:
            """Deploy a rendered configuration to a device."""
            return f"deployed to {device}"

        with agent_run_context(role=Role.VIEWER), pytest.raises(RbacForbiddenError):
            await deploy_config.ainvoke({"device": "edge-1"})
        # Denied for RBAC, not approval — no approval decision attached.
        event = audit_sink.events[-1]
        assert event.outcome == "denied"
        assert event.approval is None


class TestRbacDefinitionValidation:
    def test_min_role_accepts_role_name_string(self, audit_sink: RecordingAuditSink) -> None:
        @netops_tool(
            classification=ToolClassification.READ_ONLY,
            audit_sink=audit_sink,
            min_role="engineer",
        )
        async def collect_routes(device: str) -> str:
            """Collect routes from a device."""
            return "[]"

        assert collect_routes.min_role is Role.ENGINEER

    def test_unknown_min_role_rejected(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(
                classification=ToolClassification.READ_ONLY,
                min_role="superuser",
            )
            async def collect_routes() -> str:
                """Collect routes."""
                return "[]"
