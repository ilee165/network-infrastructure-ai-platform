"""Unit tests for plugins.vendors.cli_common (Wave 3 T4 base package)."""

from __future__ import annotations

from app.plugins.base import PluginCapability
from app.plugins.vendors.cli_common import (
    address_or_none,
    int_or_none,
    statuses_from_link_protocol,
)
from app.plugins.vendors.cli_common.lifecycle import CliConfigWriteMixin
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus


class TestTextfsmHelpers:
    def test_int_or_none(self) -> None:
        assert int_or_none("42") == 42
        assert int_or_none("  ") is None
        assert int_or_none("x") is None
        assert int_or_none(None) is None

    def test_address_or_none(self) -> None:
        assert str(address_or_none("10.0.0.1")) == "10.0.0.1"
        assert str(address_or_none("2001:db8::1")) == "2001:db8::1"
        assert address_or_none("") is None
        assert address_or_none(None) is None
        assert address_or_none("not-an-ip") is None

    def test_statuses_from_link_protocol(self) -> None:
        admin, oper = statuses_from_link_protocol("up", "up")
        assert admin is InterfaceAdminStatus.UP
        assert oper is InterfaceOperStatus.UP
        admin, oper = statuses_from_link_protocol("administratively down", "down")
        assert admin is InterfaceAdminStatus.DOWN
        assert oper is InterfaceOperStatus.DOWN
        admin, oper = statuses_from_link_protocol("down", "down")
        assert admin is InterfaceAdminStatus.UP
        assert oper is InterfaceOperStatus.DOWN
        admin, oper = statuses_from_link_protocol("up", "testing")
        assert oper is InterfaceOperStatus.UNKNOWN


class TestCliConfigWriteMixinShape:
    def test_mixin_is_plugin_capability_subclass(self) -> None:
        assert issubclass(CliConfigWriteMixin, PluginCapability)
        assert hasattr(CliConfigWriteMixin, "_execute")
        assert hasattr(CliConfigWriteMixin, "_diff_summary")
        assert hasattr(CliConfigWriteMixin, "_require_executing")

    def test_diff_summary_counts(self) -> None:
        summary = CliConfigWriteMixin._diff_summary("a\nb\n", "a\nc\n")
        assert summary == ("+1 line(s)", "-1 line(s)")
