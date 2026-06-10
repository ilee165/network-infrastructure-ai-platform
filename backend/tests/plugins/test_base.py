"""Tests for the plugin contract in app/plugins/base.py (D6, ADR-0006)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    CommandTransport,
    ConnectionParams,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RawOutput,
    TransportKind,
    VendorPlugin,
)
from app.schemas.normalized import NormalizedInterface

#: The 19 members fixed by brief §4 / ADR-0006 — order-free, name-exact.
EXPECTED_CAPABILITY_NAMES = {
    "DISCOVERY_SSH",
    "DISCOVERY_SNMP",
    "DISCOVERY_API",
    "INTERFACES",
    "ROUTES",
    "NEIGHBORS_LLDP",
    "NEIGHBORS_CDP",
    "BGP",
    "OSPF",
    "ACL",
    "FIREWALL_POLICY",
    "CONFIG_BACKUP",
    "CONFIG_RESTORE",
    "CONFIG_DEPLOY",
    "DDI_DNS",
    "DDI_DHCP",
    "DDI_IPAM",
    "PACKET_CAPTURE",
    "HA_STATUS",
}


class _DummyInterfaces(InterfacesCapability):
    def get_interfaces(self) -> list[NormalizedInterface]:
        return []


class _DummyPlugin(VendorPlugin):
    vendor_id = "dummy_vendor"
    display_name = "Dummy Vendor"
    capabilities = frozenset({Capability.INTERFACES})

    def _capability_classes(self) -> dict[Capability, type[PluginCapability]]:
        return {Capability.INTERFACES: _DummyInterfaces}


class TestCapabilityEnum:
    def test_capability_has_exactly_the_19_brief_members(self) -> None:
        assert {member.name for member in Capability} == EXPECTED_CAPABILITY_NAMES
        assert len(Capability) == 19

    def test_capability_wire_values_are_lowercase_member_names(self) -> None:
        for member in Capability:
            assert member.value == member.name.lower()


class TestConnectionParams:
    def test_connection_params_defaults_to_ssh_port_22(self) -> None:
        params = ConnectionParams(host="10.0.0.1", credential_ref="cred-123")
        assert params.port == 22
        assert params.transport is TransportKind.SSH

    def test_connection_params_rejects_out_of_range_port(self) -> None:
        with pytest.raises(ValidationError):
            ConnectionParams(host="10.0.0.1", port=0, credential_ref="cred-123")

    def test_connection_params_rejects_unknown_fields_like_raw_secrets(self) -> None:
        # extra="forbid": a caller cannot smuggle a password onto the model.
        with pytest.raises(ValidationError):
            ConnectionParams(
                host="10.0.0.1",
                credential_ref="cred-123",
                password="hunter2",  # type: ignore[call-arg]
            )

    def test_connection_params_is_frozen(self) -> None:
        params = ConnectionParams(host="10.0.0.1", credential_ref="cred-123")
        with pytest.raises(ValidationError):
            params.host = "10.0.0.2"  # type: ignore[misc]


class TestRawOutput:
    def test_raw_output_preserves_text_verbatim(self) -> None:
        text = "Building configuration...\r\n!\n  trailing spaces   \n\x07"
        raw = RawOutput(command="show running-config", output=text)
        assert raw.output == text

    def test_raw_output_default_collected_at_is_timezone_aware(self) -> None:
        raw = RawOutput(command="show version", output="")
        assert raw.collected_at.tzinfo is not None


class TestCommandTransport:
    def test_duck_typed_fake_satisfies_runtime_protocol(self) -> None:
        class Fake:
            def send_command(self, command: str) -> str:
                return command

        assert isinstance(Fake(), CommandTransport)


class TestPluginCapability:
    def test_record_raw_appends_and_returns_output_unchanged(self) -> None:
        capability = _DummyInterfaces()
        returned = capability._record_raw("show interfaces", "raw text")
        assert returned == "raw text"
        assert len(capability.raw_outputs) == 1
        assert capability.raw_outputs[0].command == "show interfaces"
        assert capability.raw_outputs[0].output == "raw text"

    def test_neighbors_capability_serves_both_lldp_and_cdp(self) -> None:
        assert NeighborsCapability.capabilities == frozenset(
            {Capability.NEIGHBORS_LLDP, Capability.NEIGHBORS_CDP}
        )


class TestVendorPlugin:
    def test_get_capability_returns_declared_implementation_class(self) -> None:
        plugin = _DummyPlugin()
        assert plugin.get_capability(Capability.INTERFACES) is _DummyInterfaces

    def test_get_capability_raises_plugin_error_for_undeclared_capability(self) -> None:
        plugin = _DummyPlugin()
        with pytest.raises(PluginError, match="does not implement"):
            plugin.get_capability(Capability.OSPF)

    def test_get_capability_raises_when_declared_without_implementation(self) -> None:
        class BrokenPlugin(VendorPlugin):
            vendor_id = "broken_vendor"
            display_name = "Broken"
            capabilities = frozenset({Capability.ROUTES})

            def _capability_classes(self) -> dict[Capability, type[PluginCapability]]:
                return {}

        with pytest.raises(PluginError, match="no implementation"):
            BrokenPlugin().get_capability(Capability.ROUTES)

    def test_supports_reflects_declared_capabilities(self) -> None:
        plugin = _DummyPlugin()
        assert plugin.supports(Capability.INTERFACES)
        assert not plugin.supports(Capability.DDI_DNS)

    def test_plugin_with_invalid_vendor_id_raises_at_instantiation(self) -> None:
        class BadIdPlugin(VendorPlugin):
            vendor_id = "Bad-Vendor"
            display_name = "Bad"
            capabilities = frozenset()

            def _capability_classes(self) -> dict[Capability, type[PluginCapability]]:
                return {}

        with pytest.raises(PluginError, match="invalid vendor_id"):
            BadIdPlugin()

    def test_plugin_missing_class_attributes_raises_at_instantiation(self) -> None:
        class IncompletePlugin(VendorPlugin):
            vendor_id = "incomplete_vendor"
            # display_name and capabilities intentionally not defined.

            def _capability_classes(self) -> dict[Capability, type[PluginCapability]]:
                return {}

        with pytest.raises(PluginError, match="display_name"):
            IncompletePlugin()
