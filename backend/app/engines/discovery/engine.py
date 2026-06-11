"""Per-device collection orchestration (M1-12).

:func:`collect_device` drives a vendor plugin's capability implementations
over already-connected transports and assembles a
:class:`DeviceCollectionResult`. Failures are isolated per capability: one
broken parser or unreachable protocol never aborts the whole device —
partial results are kept and the failure is recorded in ``errors`` (the
M1-13 persistence layer stores both).

Capability implementations follow the plugin convention (see
``cisco_ios/plugin.py``): constructed per device session as
``ImplClass(transport, device_id)``, where the transport is a
:class:`~app.plugins.base.CommandTransport` for CLI capabilities and an
:class:`~app.plugins.base.SnmpReadTransport` for ``DISCOVERY_SNMP``.

No DB access here (M1-13) and no Celery wiring (M1-14) — pure logic over
the D6 plugin contract.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast
from uuid import UUID

import structlog

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RoutesCapability,
    TransportKind,
    VendorPlugin,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import NormalizedInterface, NormalizedNeighbor, NormalizedRoute

__all__ = ["DeviceCollectionResult", "collect_device"]

logger = structlog.get_logger(__name__)


@dataclass
class DeviceCollectionResult:
    """Everything collected from one device in one discovery pass.

    ``raw_outputs`` maps executed command text to its verbatim output (the
    audit trail persisted to ``raw_artifacts`` in M1-13). ``errors`` maps
    each failed capability to a short diagnostic (exception type + message —
    transports guarantee no secret material in exception text, D11).
    """

    facts: DeviceFacts | None = None
    interfaces: list[NormalizedInterface] = field(default_factory=list)
    routes: list[NormalizedRoute] = field(default_factory=list)
    neighbors: list[NormalizedNeighbor] = field(default_factory=list)
    raw_outputs: dict[str, str] = field(default_factory=dict)
    errors: dict[Capability, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """Whether every requested capability collected without error."""
        return not self.errors


#: Which transport each collectible capability needs.
_CAPABILITY_TRANSPORT: dict[Capability, TransportKind] = {
    Capability.DISCOVERY_SSH: TransportKind.SSH,
    Capability.DISCOVERY_SNMP: TransportKind.SNMP,
    Capability.INTERFACES: TransportKind.SSH,
    Capability.ROUTES: TransportKind.SSH,
    Capability.NEIGHBORS_LLDP: TransportKind.SSH,
    Capability.NEIGHBORS_CDP: TransportKind.SSH,
}


def _collect_facts_ssh(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, DiscoverySshCapability):
        raise PluginError(f"{type(instance).__name__} is not a DiscoverySshCapability")
    facts = instance.get_device_facts()
    if result.facts is None:
        result.facts = facts


def _collect_facts_snmp(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, DiscoverySnmpCapability):
        raise PluginError(f"{type(instance).__name__} is not a DiscoverySnmpCapability")
    facts = instance.get_device_facts()
    if result.facts is None:
        result.facts = facts


def _collect_interfaces(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, InterfacesCapability):
        raise PluginError(f"{type(instance).__name__} is not an InterfacesCapability")
    result.interfaces.extend(instance.get_interfaces())


def _collect_routes(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, RoutesCapability):
        raise PluginError(f"{type(instance).__name__} is not a RoutesCapability")
    result.routes.extend(instance.get_routes())


def _collect_lldp(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, NeighborsCapability):
        raise PluginError(f"{type(instance).__name__} is not a NeighborsCapability")
    result.neighbors.extend(instance.get_lldp_neighbors())


def _collect_cdp(instance: PluginCapability, result: DeviceCollectionResult) -> None:
    if not isinstance(instance, NeighborsCapability):
        raise PluginError(f"{type(instance).__name__} is not a NeighborsCapability")
    result.neighbors.extend(instance.get_cdp_neighbors())


_Collector = Callable[[PluginCapability, DeviceCollectionResult], None]

#: Dispatch table: capability -> collector. First successful facts win, so
#: requesting DISCOVERY_SSH before DISCOVERY_SNMP prefers the richer CLI
#: facts with SNMP as fallback.
_COLLECTORS: dict[Capability, _Collector] = {
    Capability.DISCOVERY_SSH: _collect_facts_ssh,
    Capability.DISCOVERY_SNMP: _collect_facts_snmp,
    Capability.INTERFACES: _collect_interfaces,
    Capability.ROUTES: _collect_routes,
    Capability.NEIGHBORS_LLDP: _collect_lldp,
    Capability.NEIGHBORS_CDP: _collect_cdp,
}


def collect_device(
    plugin: VendorPlugin,
    transports: Mapping[TransportKind, object],
    capabilities: Sequence[Capability],
    *,
    device_id: UUID,
) -> DeviceCollectionResult:
    """Collect *capabilities* from one device through *plugin*.

    Each capability is attempted independently; any failure (undeclared
    capability, missing transport, transport/parse exception) is recorded in
    ``result.errors`` under that capability and collection continues —
    partial results are first-class.

    Implementation classes are instantiated at most once per device pass
    (``NEIGHBORS_LLDP``/``NEIGHBORS_CDP`` commonly share one class), and all
    verbatim command outputs they recorded are merged into
    ``result.raw_outputs`` keyed by command text.

    :param plugin: the vendor plugin matching the device.
    :param transports: connected transports keyed by :class:`TransportKind`
        (``SSH`` → :class:`~app.plugins.base.CommandTransport`, ``SNMP`` →
        :class:`~app.plugins.base.SnmpReadTransport`).
    :param capabilities: capabilities to collect, in order (facts: first
        success wins).
    :param device_id: inventory UUID stamped onto normalized records.
    """
    result = DeviceCollectionResult()
    instances: dict[type[PluginCapability], PluginCapability] = {}

    for capability in capabilities:
        collector = _COLLECTORS.get(capability)
        transport_kind = _CAPABILITY_TRANSPORT.get(capability)
        if collector is None or transport_kind is None:
            result.errors[capability] = (
                f"capability {capability.value!r} is not collectible by the discovery engine"
            )
            continue

        try:
            impl_cls = plugin.get_capability(capability)
        except PluginError as exc:
            result.errors[capability] = f"{type(exc).__name__}: {exc}"
            continue

        transport = transports.get(transport_kind)
        if transport is None:
            result.errors[capability] = (
                f"no {transport_kind.value!r} transport provided for "
                f"capability {capability.value!r}"
            )
            continue

        instance = instances.get(impl_cls)
        if instance is None:
            try:
                ctor = cast("Callable[[object, UUID], PluginCapability]", impl_cls)
                instance = ctor(transport, device_id)
            except Exception as exc:
                result.errors[capability] = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "discovery.capability_init_failed",
                    vendor_id=plugin.vendor_id,
                    capability=capability.value,
                    error_type=type(exc).__name__,
                )
                continue
            instances[impl_cls] = instance

        try:
            collector(instance, result)
        except Exception as exc:
            result.errors[capability] = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "discovery.capability_failed",
                vendor_id=plugin.vendor_id,
                capability=capability.value,
                error_type=type(exc).__name__,
            )

    for instance in instances.values():
        for raw in instance.raw_outputs:
            result.raw_outputs[raw.command] = raw.output

    return result
