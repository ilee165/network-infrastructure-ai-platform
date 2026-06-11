"""Tests of the conformance suite itself (M1-07).

The suite is the gate every vendor plugin must pass, so these tests prove it
catches real violations — and that each failure message is actionable: it
names the capability, the method, or the model field at fault.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import Any, ClassVar
from uuid import uuid4

import pytest

from app.plugins.base import (
    Capability,
    CommandTransport,
    ConfigBackupCapability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RoutesCapability,
    VendorPlugin,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedRoute,
    RouteProtocol,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    make_conformance_cases,
)

VENDOR_ID = "dummy_vendor"


def _interface(**overrides: Any) -> NormalizedInterface:
    data: dict[str, Any] = {
        "device_id": uuid4(),
        "collected_at": datetime.now(UTC),
        "source_vendor": VENDOR_ID,
        "name": "eth0",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
    }
    data.update(overrides)
    return NormalizedInterface(**data)


def _route() -> NormalizedRoute:
    return NormalizedRoute(
        device_id=uuid4(),
        collected_at=datetime.now(UTC),
        source_vendor=VENDOR_ID,
        destination=IPv4Network("10.0.0.0/24"),
        protocol=RouteProtocol.STATIC,
    )


def _neighbor(protocol: NeighborProtocol) -> NormalizedNeighbor:
    return NormalizedNeighbor(
        device_id=uuid4(),
        collected_at=datetime.now(UTC),
        source_vendor=VENDOR_ID,
        protocol=protocol,
        local_interface="eth0",
        neighbor_name="peer01",
    )


class _GoodInterfaces(InterfacesCapability):
    def get_interfaces(self) -> list[NormalizedInterface]:
        return [_interface()]


class _GoodRoutes(RoutesCapability):
    def get_routes(self) -> list[NormalizedRoute]:
        return [_route()]


def _plugin(
    caps: frozenset[Capability],
    impl_map: Mapping[Capability, type[PluginCapability]],
    *,
    name: str = "Dummy Vendor",
) -> VendorPlugin:
    """Build a throwaway plugin declaring *caps* mapped through *impl_map*."""

    class _DummyPlugin(VendorPlugin):
        vendor_id: ClassVar[str] = VENDOR_ID
        display_name: ClassVar[str] = name
        capabilities: ClassVar[frozenset[Capability]] = caps

        def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
            return dict(impl_map)

    return _DummyPlugin()


def _no_arg_factory(impl: type[PluginCapability]) -> PluginCapability:
    return impl()


def _cases(plugin: VendorPlugin) -> list[ConformanceCase]:
    return make_conformance_cases(plugin, capability_factory=_no_arg_factory)


def _case(cases: list[ConformanceCase], case_id: str) -> ConformanceCase:
    by_id = {case.id: case for case in cases}
    assert case_id in by_id, f"missing case {case_id!r}; generated: {sorted(by_id)}"
    return by_id[case_id]


class TestCaseGeneration:
    def test_generates_metadata_implementation_and_fixture_cases(self) -> None:
        plugin = _plugin(
            frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _GoodInterfaces}
        )
        ids = [case.id for case in _cases(plugin)]
        assert "metadata:vendor_id" in ids
        assert "metadata:display_name" in ids
        assert "metadata:capabilities" in ids
        assert "implementation:interfaces" in ids
        assert "fixtures:interfaces" in ids

    def test_well_formed_plugin_passes_every_case(self) -> None:
        plugin = _plugin(
            frozenset({Capability.INTERFACES, Capability.ROUTES}),
            {Capability.INTERFACES: _GoodInterfaces, Capability.ROUTES: _GoodRoutes},
        )
        for case in _cases(plugin):
            case.run()

    def test_capability_without_typed_interface_gets_no_fixture_case(self) -> None:
        # DISCOVERY_API has no typed interface in plugins/base.py yet (it lands
        # with its milestone); the suite checks the implementation class only.
        class _Discovery(PluginCapability):
            capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DISCOVERY_API})

        plugin = _plugin(
            frozenset({Capability.DISCOVERY_API}), {Capability.DISCOVERY_API: _Discovery}
        )
        cases = _cases(plugin)
        ids = [case.id for case in cases]
        assert "implementation:discovery_api" in ids
        assert "fixtures:discovery_api" not in ids
        for case in cases:
            case.run()


class TestMetadataChecks:
    def test_blank_display_name_is_reported(self) -> None:
        plugin = _plugin(
            frozenset({Capability.INTERFACES}),
            {Capability.INTERFACES: _GoodInterfaces},
            name="   ",
        )
        case = _case(_cases(plugin), "metadata:display_name")
        with pytest.raises(AssertionError, match="display_name"):
            case.run()

    def test_empty_capability_set_is_reported(self) -> None:
        plugin = _plugin(frozenset(), {})
        case = _case(_cases(plugin), "metadata:capabilities")
        with pytest.raises(AssertionError, match="at least one"):
            case.run()


class TestImplementationChecks:
    def test_declared_capability_without_implementation_names_the_capability(self) -> None:
        plugin = _plugin(frozenset({Capability.ROUTES}), {})
        case = _case(_cases(plugin), "implementation:routes")
        with pytest.raises(AssertionError, match="routes"):
            case.run()

    def test_inherited_abstract_method_names_capability_method_and_class(self) -> None:
        class _AbstractInterfaces(InterfacesCapability):
            pass  # inherits abstract get_interfaces — a non-implementation

        plugin = _plugin(
            frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _AbstractInterfaces}
        )
        case = _case(_cases(plugin), "implementation:interfaces")
        with pytest.raises(AssertionError) as excinfo:
            case.run()
        message = str(excinfo.value)
        assert "interfaces" in message
        assert "get_interfaces" in message
        assert "_AbstractInterfaces" in message

    def test_implementation_outside_the_typed_interface_is_reported(self) -> None:
        class _Untyped(PluginCapability):
            capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.INTERFACES})

            def get_interfaces(self) -> list[NormalizedInterface]:
                return [_interface()]

        plugin = _plugin(frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _Untyped})
        case = _case(_cases(plugin), "implementation:interfaces")
        with pytest.raises(AssertionError, match="InterfacesCapability"):
            case.run()

    def test_implementation_not_declaring_the_capability_is_reported(self) -> None:
        # _GoodInterfaces declares INTERFACES in its `capabilities` ClassVar,
        # so mapping it to ROUTES is a declaration mismatch.
        plugin = _plugin(frozenset({Capability.ROUTES}), {Capability.ROUTES: _GoodInterfaces})
        case = _case(_cases(plugin), "implementation:routes")
        with pytest.raises(AssertionError, match="declare"):
            case.run()


class TestFixtureChecks:
    def test_empty_parser_output_is_reported(self) -> None:
        class _EmptyInterfaces(InterfacesCapability):
            def get_interfaces(self) -> list[NormalizedInterface]:
                return []

        plugin = _plugin(
            frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _EmptyInterfaces}
        )
        case = _case(_cases(plugin), "fixtures:interfaces")
        with pytest.raises(AssertionError, match="no records"):
            case.run()

    def test_invalid_field_value_is_named_in_the_failure(self) -> None:
        class _BadField(InterfacesCapability):
            def get_interfaces(self) -> list[NormalizedInterface]:
                # model_construct bypasses validation — exactly the bug the
                # re-validation pass must catch, naming the field.
                return [
                    NormalizedInterface.model_construct(
                        device_id=uuid4(),
                        collected_at=datetime.now(UTC),
                        source_vendor=VENDOR_ID,
                        name="eth0",
                        admin_status=InterfaceAdminStatus.UP,
                        oper_status=InterfaceOperStatus.UP,
                        mtu=-5,
                    )
                ]

        plugin = _plugin(frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _BadField})
        case = _case(_cases(plugin), "fixtures:interfaces")
        with pytest.raises(AssertionError, match="mtu"):
            case.run()

    def test_wrong_record_type_is_reported(self) -> None:
        class _WrongModel(InterfacesCapability):
            def get_interfaces(self) -> list[NormalizedInterface]:
                return [_route()]  # type: ignore[list-item]

        plugin = _plugin(frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _WrongModel})
        case = _case(_cases(plugin), "fixtures:interfaces")
        with pytest.raises(AssertionError, match="NormalizedInterface"):
            case.run()

    def test_source_vendor_mismatch_is_reported(self) -> None:
        class _ForeignVendor(InterfacesCapability):
            def get_interfaces(self) -> list[NormalizedInterface]:
                return [_interface(source_vendor="other_vendor")]

        plugin = _plugin(
            frozenset({Capability.INTERFACES}), {Capability.INTERFACES: _ForeignVendor}
        )
        case = _case(_cases(plugin), "fixtures:interfaces")
        with pytest.raises(AssertionError, match="source_vendor"):
            case.run()

    def test_neighbor_protocol_mismatch_is_reported(self) -> None:
        class _SwappedNeighbors(NeighborsCapability):
            def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
                return [_neighbor(NeighborProtocol.CDP)]  # wrong protocol

            def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
                return [_neighbor(NeighborProtocol.CDP)]

        plugin = _plugin(
            frozenset({Capability.NEIGHBORS_LLDP}),
            {Capability.NEIGHBORS_LLDP: _SwappedNeighbors},
        )
        case = _case(_cases(plugin), "fixtures:neighbors_lldp")
        with pytest.raises(AssertionError, match="protocol"):
            case.run()

    def test_device_facts_pass_when_vendor_matches(self) -> None:
        class _GoodDiscovery(DiscoverySshCapability):
            def get_device_facts(self) -> DeviceFacts:
                return DeviceFacts(hostname="sw01", vendor_id=VENDOR_ID)

        plugin = _plugin(
            frozenset({Capability.DISCOVERY_SSH}), {Capability.DISCOVERY_SSH: _GoodDiscovery}
        )
        _case(_cases(plugin), "fixtures:discovery_ssh").run()

    def test_device_facts_vendor_mismatch_is_reported(self) -> None:
        class _ForeignDiscovery(DiscoverySnmpCapability):
            def get_device_facts(self) -> DeviceFacts:
                return DeviceFacts(hostname="sw01", vendor_id="other_vendor")

        plugin = _plugin(
            frozenset({Capability.DISCOVERY_SNMP}), {Capability.DISCOVERY_SNMP: _ForeignDiscovery}
        )
        case = _case(_cases(plugin), "fixtures:discovery_snmp")
        with pytest.raises(AssertionError, match="vendor_id"):
            case.run()

    def test_device_facts_wrong_return_type_is_reported(self) -> None:
        class _WrongFacts(DiscoverySshCapability):
            def get_device_facts(self) -> DeviceFacts:
                return {"hostname": "sw01"}  # type: ignore[return-value]

        plugin = _plugin(
            frozenset({Capability.DISCOVERY_SSH}), {Capability.DISCOVERY_SSH: _WrongFacts}
        )
        case = _case(_cases(plugin), "fixtures:discovery_ssh")
        with pytest.raises(AssertionError, match="DeviceFacts"):
            case.run()

    def test_blank_running_config_is_reported(self) -> None:
        class _EmptyBackup(ConfigBackupCapability):
            def fetch_running_config(self) -> str:
                return "   \n"

        plugin = _plugin(
            frozenset({Capability.CONFIG_BACKUP}), {Capability.CONFIG_BACKUP: _EmptyBackup}
        )
        case = _case(_cases(plugin), "fixtures:config_backup")
        with pytest.raises(AssertionError, match="empty"):
            case.run()


class TestFixtureReplayTransport:
    def test_satisfies_the_command_transport_protocol(self) -> None:
        assert isinstance(FixtureReplayTransport({}), CommandTransport)

    def test_replays_known_commands_and_records_them(self) -> None:
        transport = FixtureReplayTransport({"show version": "IOS output"})
        assert transport.send_command("show version") == "IOS output"
        assert transport.commands == ["show version"]

    def test_unknown_command_fails_listing_the_bundled_commands(self) -> None:
        transport = FixtureReplayTransport({"show version": "IOS output"})
        with pytest.raises(AssertionError, match="show version"):
            transport.send_command("show ip route")
