"""Tests for the classified, audited tool wrappers (app/agents/framework/tools.py)."""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.tools import BaseTool
from pydantic import ValidationError

from app.agents.framework.approval import ApprovalRequiredError
from app.agents.framework.tools import (
    BoundedExecution,
    NetOpsTool,
    ToolClassification,
    ToolDefinitionError,
    ToolExecutionError,
    netops_tool,
)
from tests.agents.conftest import ApproveAllGate, RecordingAuditSink

_BOUNDS = BoundedExecution(timeout_seconds=5.0, max_packets=1000, max_bytes=1_000_000)


def _read_only_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=sink)
    async def get_device_count(site: str) -> str:
        """Count managed devices at a site."""
        return f"3 devices at {site}"

    return get_device_count


class TestClassificationBehavior:
    async def test_read_only_tool_executes_and_audits_success(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        tool = _read_only_tool(audit_sink)
        result = await tool.ainvoke({"site": "nyc-dc1"})
        assert result == "3 devices at nyc-dc1"
        assert len(audit_sink.events) == 1
        event = audit_sink.events[0]
        assert event.tool_name == "get_device_count"
        assert event.classification is ToolClassification.READ_ONLY
        assert event.outcome == "success"
        assert event.arguments == {"site": "nyc-dc1"}
        assert event.approval is None

    async def test_state_changing_tool_without_approval_raises(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        executed = False

        @netops_tool(classification=ToolClassification.STATE_CHANGING, audit_sink=audit_sink)
        async def deploy_config(device: str) -> str:
            """Deploy a rendered configuration to a device."""
            nonlocal executed
            executed = True
            return "deployed"

        with pytest.raises(ApprovalRequiredError):
            await deploy_config.ainvoke({"device": "edge-1"})
        assert executed is False, "the gated coroutine must never run without approval"
        assert len(audit_sink.events) == 1
        event = audit_sink.events[0]
        assert event.outcome == "denied"
        assert event.classification is ToolClassification.STATE_CHANGING
        assert event.approval is not None
        assert event.approval.approved is False

    async def test_state_changing_tool_executes_when_gate_approves(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        @netops_tool(
            classification=ToolClassification.STATE_CHANGING,
            audit_sink=audit_sink,
            approval_gate=ApproveAllGate(),
        )
        async def deploy_config(device: str) -> str:
            """Deploy a rendered configuration to a device."""
            return f"deployed to {device}"

        result = await deploy_config.ainvoke({"device": "edge-1"})
        assert result == "deployed to edge-1"
        event = audit_sink.events[-1]
        assert event.outcome == "success"
        assert event.approval is not None
        assert event.approval.approved is True
        assert event.approval.change_request_id == "cr-test-0001"

    async def test_diagnostic_tool_executes_within_bounds(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        @netops_tool(
            classification=ToolClassification.DIAGNOSTIC,
            audit_sink=audit_sink,
            bounded_execution=_BOUNDS,
        )
        async def start_capture(interface: str) -> str:
            """Start a bounded packet capture on an interface."""
            return f"capturing on {interface}"

        result = await start_capture.ainvoke({"interface": "ge-0/0/1"})
        assert result == "capturing on ge-0/0/1"
        event = audit_sink.events[-1]
        assert event.outcome == "success"
        assert event.bounded_execution == _BOUNDS

    async def test_diagnostic_tool_times_out_when_bound_exceeded(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        bounds = BoundedExecution(timeout_seconds=0.05, max_packets=10)

        @netops_tool(
            classification=ToolClassification.DIAGNOSTIC,
            audit_sink=audit_sink,
            bounded_execution=bounds,
        )
        async def slow_capture() -> str:
            """Start a packet capture that never finishes."""
            # Event-driven hang so the bound is what times out, not a wall clock.
            await asyncio.Event().wait()
            return "unreachable"

        with pytest.raises(ToolExecutionError):
            await slow_capture.ainvoke({})
        event = audit_sink.events[-1]
        assert event.outcome == "error"
        assert "timeout" in (event.detail or "")

    async def test_exception_detail_is_redacted_in_audit(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        """H13: exception detail carrying secret-shaped config is scrubbed at emit."""

        secret_line = "snmp-server community SuperSecretCommunity RO"

        @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=audit_sink)
        async def parse_config(blob: str) -> str:
            """Parse a config blob (test tool)."""
            raise ValueError(f"bad config near: {secret_line}")

        with pytest.raises(ValueError):
            await parse_config.ainvoke({"blob": secret_line})
        event = audit_sink.events[-1]
        assert event.outcome == "error"
        detail = event.detail or ""
        assert "SuperSecretCommunity" not in detail
        assert "REDACTED" in detail


class TestDefinitionValidation:
    def test_diagnostic_tool_requires_bounded_execution(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(classification=ToolClassification.DIAGNOSTIC)
            async def start_capture() -> str:
                """Start a packet capture."""
                return "capturing"

    def test_bounded_execution_only_allowed_on_diagnostic_tools(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(classification=ToolClassification.READ_ONLY, bounded_execution=_BOUNDS)
            async def list_interfaces() -> str:
                """List interfaces."""
                return "[]"

    def test_approval_gate_only_allowed_on_state_changing_tools(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(
                classification=ToolClassification.READ_ONLY, approval_gate=ApproveAllGate()
            )
            async def list_routes() -> str:
                """List routes."""
                return "[]"

    def test_sync_function_rejected(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(classification=ToolClassification.READ_ONLY)  # type: ignore[arg-type]
            def list_vlans() -> str:
                """List VLANs."""
                return "[]"

    def test_missing_description_rejected(self) -> None:
        with pytest.raises(ToolDefinitionError):

            @netops_tool(classification=ToolClassification.READ_ONLY)
            async def undocumented() -> str:
                return "[]"

    def test_bounded_execution_requires_a_size_cap(self) -> None:
        with pytest.raises(ValidationError):
            BoundedExecution(timeout_seconds=10.0)


class TestLangChainCompatibility:
    def test_tool_is_a_langchain_base_tool(self, audit_sink: RecordingAuditSink) -> None:
        tool = _read_only_tool(audit_sink)
        assert isinstance(tool, BaseTool)
        assert isinstance(tool, NetOpsTool)
        assert tool.name == "get_device_count"
        assert tool.description == "Count managed devices at a site."
        assert tool.classification is ToolClassification.READ_ONLY

    def test_sync_invocation_not_supported(self, audit_sink: RecordingAuditSink) -> None:
        tool = _read_only_tool(audit_sink)
        with pytest.raises(NotImplementedError):
            tool.invoke({"site": "nyc-dc1"})

    async def test_tool_error_is_audited_then_reraised(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=audit_sink)
        async def broken() -> str:
            """A tool whose engine call fails."""
            raise RuntimeError("device unreachable")

        with pytest.raises(RuntimeError, match="device unreachable"):
            await broken.ainvoke({})
        event = audit_sink.events[-1]
        assert event.outcome == "error"
        assert "device unreachable" in (event.detail or "")
