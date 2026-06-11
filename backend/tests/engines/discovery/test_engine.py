"""collect_device orchestration: happy path, partial failure, total failure."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import ClassVar
from uuid import UUID, uuid4

from app.engines.discovery.engine import DeviceCollectionResult, collect_device
from app.plugins.base import (
    Capability,
    CommandTransport,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RoutesCapability,
    SnmpReadTransport,
    TransportKind,
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

DEVICE_ID = uuid4()
VENDOR = "fake_vendor"
NOW = datetime.now(UTC)


class FakeSshTransport:
    """In-memory CommandTransport returning canned text per command."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        return f"output of {command}"


class FakeSnmpTransport:
    def get(self, oids: list[str]) -> dict[str, str]:
        return {oid: f"value-{oid}" for oid in oids}


def _iface() -> NormalizedInterface:
    return NormalizedInterface(
        device_id=DEVICE_ID,
        collected_at=NOW,
        source_vendor=VENDOR,
        name="Gi0/1",
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
    )


def _route() -> NormalizedRoute:
    return NormalizedRoute(
        device_id=DEVICE_ID,
        collected_at=NOW,
        source_vendor=VENDOR,
        destination=IPv4Network("10.0.0.0/24"),
        protocol=RouteProtocol.CONNECTED,
    )


def _neighbor(protocol: NeighborProtocol, name: str) -> NormalizedNeighbor:
    return NormalizedNeighbor(
        device_id=DEVICE_ID,
        collected_at=NOW,
        source_vendor=VENDOR,
        protocol=protocol,
        local_interface="Gi0/1",
        neighbor_name=name,
    )


class FakeDiscoverySsh(DiscoverySshCapability):
    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport

    def get_device_facts(self) -> DeviceFacts:
        self._record_raw("show version", self._transport.send_command("show version"))
        return DeviceFacts(hostname="sw1", vendor_id=VENDOR, model="fake-9000")


class FakeDiscoverySnmp(DiscoverySnmpCapability):
    def __init__(self, snmp: SnmpReadTransport, device_id: UUID) -> None:
        super().__init__()
        self._snmp = snmp

    def get_device_facts(self) -> DeviceFacts:
        values = self._snmp.get(["1.3.6.1.2.1.1.5.0"])
        self._record_raw("SNMP GET sysName", str(values))
        return DeviceFacts(hostname="sw1-snmp", vendor_id=VENDOR)


class FakeInterfaces(InterfacesCapability):
    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport

    def get_interfaces(self) -> list[NormalizedInterface]:
        self._record_raw("show interfaces", self._transport.send_command("show interfaces"))
        return [_iface()]


class FakeRoutes(RoutesCapability):
    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()

    def get_routes(self) -> list[NormalizedRoute]:
        return [_route()]


class BrokenRoutes(RoutesCapability):
    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()

    def get_routes(self) -> list[NormalizedRoute]:
        raise RuntimeError("route table parse exploded")


class FakeNeighbors(NeighborsCapability):
    instances_created: ClassVar[int] = 0

    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()
        type(self).instances_created += 1
        self._transport = transport

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        self._record_raw("show lldp", self._transport.send_command("show lldp"))
        return [_neighbor(NeighborProtocol.LLDP, "nbr-lldp")]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        self._record_raw("show cdp", self._transport.send_command("show cdp"))
        return [_neighbor(NeighborProtocol.CDP, "nbr-cdp")]


class _BrokenBase(PluginCapability):
    def __init__(self, transport: object, device_id: UUID) -> None:
        super().__init__()


class BrokenDiscoverySsh(_BrokenBase, DiscoverySshCapability):
    def get_device_facts(self) -> DeviceFacts:
        raise RuntimeError("ssh facts failed")


class BrokenInterfaces(_BrokenBase, InterfacesCapability):
    def get_interfaces(self) -> list[NormalizedInterface]:
        raise RuntimeError("interfaces failed")


def make_plugin(
    mapping: Mapping[Capability, type[PluginCapability]],
) -> VendorPlugin:
    caps = frozenset(mapping)

    class _Plugin(VendorPlugin):
        vendor_id: ClassVar[str] = VENDOR
        display_name: ClassVar[str] = "Fake Vendor"
        capabilities: ClassVar[frozenset[Capability]] = caps

        def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
            return mapping

    return _Plugin()


FULL_MAPPING: dict[Capability, type[PluginCapability]] = {
    Capability.DISCOVERY_SSH: FakeDiscoverySsh,
    Capability.DISCOVERY_SNMP: FakeDiscoverySnmp,
    Capability.INTERFACES: FakeInterfaces,
    Capability.ROUTES: FakeRoutes,
    Capability.NEIGHBORS_LLDP: FakeNeighbors,
    Capability.NEIGHBORS_CDP: FakeNeighbors,
}


def transports() -> dict[TransportKind, object]:
    return {TransportKind.SSH: FakeSshTransport(), TransportKind.SNMP: FakeSnmpTransport()}


class TestHappyPath:
    def test_all_capabilities_collected(self) -> None:
        result = collect_device(
            make_plugin(FULL_MAPPING),
            transports(),
            list(FULL_MAPPING),
            device_id=DEVICE_ID,
        )
        assert result.errors == {}
        assert result.facts is not None
        assert result.facts.hostname == "sw1"  # SSH facts win (requested first)
        assert [i.name for i in result.interfaces] == ["Gi0/1"]
        assert len(result.routes) == 1
        assert {n.protocol for n in result.neighbors} == {
            NeighborProtocol.LLDP,
            NeighborProtocol.CDP,
        }
        assert result.succeeded is True

    def test_raw_outputs_keyed_by_command(self) -> None:
        result = collect_device(
            make_plugin(FULL_MAPPING),
            transports(),
            list(FULL_MAPPING),
            device_id=DEVICE_ID,
        )
        assert result.raw_outputs["show version"] == "output of show version"
        assert result.raw_outputs["show interfaces"] == "output of show interfaces"
        assert "show lldp" in result.raw_outputs
        assert "show cdp" in result.raw_outputs

    def test_shared_capability_class_instantiated_once(self) -> None:
        FakeNeighbors.instances_created = 0
        collect_device(
            make_plugin(FULL_MAPPING),
            transports(),
            [Capability.NEIGHBORS_LLDP, Capability.NEIGHBORS_CDP],
            device_id=DEVICE_ID,
        )
        assert FakeNeighbors.instances_created == 1


class TestPartialFailure:
    def test_failed_capability_recorded_others_collected(self) -> None:
        mapping = dict(FULL_MAPPING)
        mapping[Capability.ROUTES] = BrokenRoutes
        result = collect_device(
            make_plugin(mapping),
            transports(),
            [Capability.INTERFACES, Capability.ROUTES, Capability.NEIGHBORS_LLDP],
            device_id=DEVICE_ID,
        )
        assert len(result.interfaces) == 1
        assert len(result.neighbors) == 1
        assert result.routes == []
        assert list(result.errors) == [Capability.ROUTES]
        assert "RuntimeError" in result.errors[Capability.ROUTES]
        assert result.succeeded is False

    def test_ssh_facts_failure_falls_back_to_snmp_facts(self) -> None:
        mapping = dict(FULL_MAPPING)
        mapping[Capability.DISCOVERY_SSH] = BrokenDiscoverySsh
        result = collect_device(
            make_plugin(mapping),
            transports(),
            [Capability.DISCOVERY_SSH, Capability.DISCOVERY_SNMP],
            device_id=DEVICE_ID,
        )
        assert result.facts is not None
        assert result.facts.hostname == "sw1-snmp"
        assert Capability.DISCOVERY_SSH in result.errors

    def test_undeclared_capability_recorded_as_error(self) -> None:
        mapping = {Capability.INTERFACES: FakeInterfaces}
        result = collect_device(
            make_plugin(mapping),
            transports(),
            [Capability.INTERFACES, Capability.ROUTES],
            device_id=DEVICE_ID,
        )
        assert len(result.interfaces) == 1
        assert Capability.ROUTES in result.errors
        assert "does not implement" in result.errors[Capability.ROUTES]

    def test_missing_transport_recorded_as_error(self) -> None:
        result = collect_device(
            make_plugin(FULL_MAPPING),
            {TransportKind.SSH: FakeSshTransport()},  # no SNMP transport
            [Capability.DISCOVERY_SSH, Capability.DISCOVERY_SNMP],
            device_id=DEVICE_ID,
        )
        assert result.facts is not None  # SSH still produced facts
        assert Capability.DISCOVERY_SNMP in result.errors
        assert "transport" in result.errors[Capability.DISCOVERY_SNMP]

    def test_unsupported_capability_recorded_as_error(self) -> None:
        result = collect_device(
            make_plugin(FULL_MAPPING),
            transports(),
            [Capability.CONFIG_BACKUP],
            device_id=DEVICE_ID,
        )
        assert Capability.CONFIG_BACKUP in result.errors


class TestTotalFailure:
    def test_every_capability_fails_partial_result_is_empty(self) -> None:
        mapping: dict[Capability, type[PluginCapability]] = {
            Capability.DISCOVERY_SSH: BrokenDiscoverySsh,
            Capability.INTERFACES: BrokenInterfaces,
            Capability.ROUTES: BrokenRoutes,
        }
        requested = list(mapping)
        result = collect_device(make_plugin(mapping), transports(), requested, device_id=DEVICE_ID)
        assert result.facts is None
        assert result.interfaces == []
        assert result.routes == []
        assert result.neighbors == []
        assert set(result.errors) == set(requested)
        assert result.succeeded is False


class TestDeviceCollectionResultDefaults:
    def test_empty_result_defaults(self) -> None:
        result = DeviceCollectionResult()
        assert result.facts is None
        assert result.interfaces == []
        assert result.routes == []
        assert result.neighbors == []
        assert result.raw_outputs == {}
        assert result.errors == {}
        assert result.succeeded is True
