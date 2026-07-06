"""VMware vSphere plugin: pyVmomi vCenter inventory (ADR-0051).

The platform's **first virtualization vendor** (``vmware``), declaring
``DISCOVERY_API`` (vCenter identity) plus the new ``VIRTUALIZATION_INVENTORY``
capability (VM / host / cluster / port-group inventory with nested vNICs /
pNICs). The inventory ``device`` row is the **vCenter Server** (one API
endpoint managing many downstream objects, the DDI-grid pattern); ESXi hosts,
VMs, clusters, and port groups are discovered objects carried in normalized
records whose provenance points at the vCenter device (ADR-0051 §4).

**No write path** (ADR-0051 §3): ``vmware`` declares no config/DDI/archive write
capability. The least-privilege story is the read-only vCenter role, not CR
gating.

Raw-first (ADR-0051 §7 — the named deviation): pyVmomi hands the plugin
deserialized objects, so the raw artifact is a deterministic **property-set
JSON** rendering of every ``RetrievePropertiesEx`` batch, recorded via
``_record_raw`` *before* normalization. The ``VsphereClient.fetch_*`` methods
return exactly those documents, and conformance fixtures replay them, so
fixtures and raw artifacts share one format. Datacenter is a collection-context
attribute (which datacenter's folder was traversed), attached to each document
alongside the pyVmomi property paths — it scopes the name joins (§5.5). The
login exchange and session cookie are never part of any recorded batch (§2).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, ClassVar

from app.plugins.base import (
    Capability,
    DiscoveryApiCapability,
    PluginCapability,
    VendorPlugin,
    VirtualizationInventoryCapability,
)
from app.plugins.vendors.vmware.client import PropertySetDoc, VsphereClient
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    DiscoveredObjectKind,
    HostConnectionState,
    NormalizedComputeCluster,
    NormalizedDiscoveredObject,
    NormalizedHypervisorHost,
    NormalizedPhysicalNic,
    NormalizedPortGroup,
    NormalizedVirtualMachine,
    NormalizedVirtualNic,
    VirtualSwitchType,
    VmPowerState,
)

__all__ = [
    "VmwareDiscoveryApi",
    "VmwarePlugin",
    "VmwareVirtualizationInventory",
    "_map_connection_state",
    "_map_power_state",
    "_standard_pnic_name",
]

VENDOR_ID = "vmware"

#: Strip an F5-style not-applicable; here strip the host-pnic key prefix vSphere
#: uses in a vSwitch's ``pnic`` list (``key-vim.host.PhysicalNic-vmnic0``).
_PNIC_KEY_PREFIX = "key-vim.host.PhysicalNic-"

_POWER_STATE_MAP: Mapping[str, VmPowerState] = {
    "poweredOn": VmPowerState.POWERED_ON,
    "poweredOff": VmPowerState.POWERED_OFF,
    "suspended": VmPowerState.SUSPENDED,
}

_CONNECTION_STATE_MAP: Mapping[str, HostConnectionState] = {
    "connected": HostConnectionState.CONNECTED,
    "disconnected": HostConnectionState.DISCONNECTED,
    "notResponding": HostConnectionState.NOT_RESPONDING,
}


def _map_power_state(value: str | None) -> VmPowerState:
    """Map a vSphere ``runtime.powerState`` to :class:`VmPowerState` (default UNKNOWN)."""
    return _POWER_STATE_MAP.get(value or "", VmPowerState.UNKNOWN)


def _map_connection_state(value: str | None) -> HostConnectionState:
    """Map a vSphere ``runtime.connectionState`` to :class:`HostConnectionState` (def. UNKNOWN)."""
    return _CONNECTION_STATE_MAP.get(value or "", HostConnectionState.UNKNOWN)


def _standard_pnic_name(value: str) -> str:
    """Normalize a pNIC reference to its bare device name (``vmnic0``)."""
    if value.startswith(_PNIC_KEY_PREFIX):
        return value[len(_PNIC_KEY_PREFIX) :]
    return value


def _parse_ip(value: object) -> IPv4Address | IPv6Address | None:
    """Parse an IP string (zone/prefix suffix stripped); ``None`` when unparseable."""
    if not isinstance(value, str) or not value:
        return None
    candidate = value.split("%", 1)[0].split("/", 1)[0].strip()
    try:
        return ip_address(candidate)
    except ValueError:
        return None


def _collect_ips(values: object) -> tuple[IPv4Address | IPv6Address, ...]:
    """Deduplicate + deterministically sort a sequence of IP strings (ADR-0051 §5.3)."""
    if not isinstance(values, (list, tuple)):
        return ()
    seen: dict[str, IPv4Address | IPv6Address] = {}
    for value in values:
        parsed = _parse_ip(value)
        if parsed is not None:
            seen[str(parsed)] = parsed
    return tuple(sorted(seen.values(), key=lambda ip: (ip.version, int(ip))))


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Shared capability base
# ---------------------------------------------------------------------------


class _VmwareCapability(PluginCapability):
    """Shared base: holds the pyVmomi client + device context, records raw-first.

    Collections are fetched at most once per instance and cached, so a single
    conformance/discovery pass records every batch exactly once even when
    several ``get_*`` methods need the same collection to build a join index
    (e.g. VM placement needs the host + cluster indexes).
    """

    def __init__(self, client: VsphereClient, device_id: uuid.UUID) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id
        self._cache: dict[str, list[PropertySetDoc]] = {}

    def _collect(self, key: str, fetch_method: str, label: str) -> list[PropertySetDoc]:
        """Fetch a collection's batches, record each batch raw, return flattened docs."""
        if key in self._cache:
            return self._cache[key]
        docs: list[PropertySetDoc] = []
        batches = getattr(self._client, fetch_method)()
        for index, batch in enumerate(batches):
            # Raw-first: deterministic property-set JSON per batch (ADR-0051 §7).
            self._record_raw(f"vmware:{label}[batch={index}]", json.dumps(batch, sort_keys=True))
            docs.extend(item for item in batch if isinstance(item, dict))
        self._cache[key] = docs
        return docs

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }


# ---------------------------------------------------------------------------
# DISCOVERY_API — vCenter identity (ADR-0051 §4)
# ---------------------------------------------------------------------------


class VmwareDiscoveryApi(_VmwareCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: ``ServiceInstance.content.about`` → vCenter identity (ADR-0051 §4)."""

    def discover(self) -> list[NormalizedDiscoveredObject]:
        facts = self._collect_facts()
        provenance = self._provenance()
        attributes: list[tuple[str, str]] = []
        if facts.model:
            attributes.append(("model", facts.model))
        if facts.os_version:
            attributes.append(("os_version", facts.os_version))
        if facts.serial:
            attributes.append(("instance_uuid", facts.serial))
        return [
            NormalizedDiscoveredObject(
                **provenance,
                kind=DiscoveredObjectKind.OTHER,
                identifier=facts.hostname,
                display_name=f"{facts.hostname} ({facts.model or 'vCenter'})",
                object_ref=facts.serial,
                attributes=tuple(attributes),
            )
        ]

    def get_device_facts(self) -> DeviceFacts:
        return self._collect_facts()

    def _collect_facts(self) -> DeviceFacts:
        about = self._client.fetch_about()
        self._record_raw("vmware:service_instance_about", json.dumps(about, sort_keys=True))
        props = _as_dict(about.get("properties"))
        hostname = props.get("name") or props.get("fullName") or "vcenter"
        return DeviceFacts(
            hostname=str(hostname),
            vendor_id=VENDOR_ID,
            model=props.get("apiType") or "vCenter",
            os_version=props.get("version") or None,
            serial=props.get("instanceUuid") or None,
        )


# ---------------------------------------------------------------------------
# VIRTUALIZATION_INVENTORY (ADR-0051 §5)
# ---------------------------------------------------------------------------


class VmwareVirtualizationInventory(_VmwareCapability, VirtualizationInventoryCapability):
    """``VIRTUALIZATION_INVENTORY``: VMs / hosts / clusters / port groups (ADR-0051 §5).

    All four methods normalize over the recorded property-set documents. VM
    placement (``host_name``/``cluster_name``) and vNIC port-group names are
    resolved at collection time from the host / cluster / distributed-portgroup
    indexes, so consumers join on a single field (§5.3/§5.5). Missing optional
    properties (no VMware Tools ⇒ no guest IPs) normalize to ``None``/``()`` —
    empty-not-error, never a ``PluginError`` (ADR-0025 §4 / ADR-0051 §5).
    """

    # -- collection helpers (cached) --------------------------------------

    def _cluster_docs(self) -> list[PropertySetDoc]:
        return self._collect("clusters", "fetch_compute_clusters", "compute_clusters")

    def _host_docs(self) -> list[PropertySetDoc]:
        return self._collect("hosts", "fetch_hypervisor_hosts", "hypervisor_hosts")

    def _vm_docs(self) -> list[PropertySetDoc]:
        return self._collect("vms", "fetch_virtual_machines", "virtual_machines")

    def _dvs_docs(self) -> list[PropertySetDoc]:
        return self._collect("dvswitches", "fetch_distributed_switches", "distributed_switches")

    def _dvpg_docs(self) -> list[PropertySetDoc]:
        return self._collect("dvpgs", "fetch_distributed_portgroups", "distributed_portgroups")

    # -- join indexes -----------------------------------------------------

    def _cluster_index(self) -> dict[str, dict[str, Any]]:
        index: dict[str, dict[str, Any]] = {}
        for doc in self._cluster_docs():
            props = _as_dict(doc.get("properties"))
            index[str(doc.get("moref"))] = {
                "name": props.get("name"),
                "datacenter": doc.get("datacenter"),
            }
        return index

    def _host_index(self) -> dict[str, dict[str, Any]]:
        clusters = self._cluster_index()
        index: dict[str, dict[str, Any]] = {}
        for doc in self._host_docs():
            props = _as_dict(doc.get("properties"))
            parent = props.get("parent")
            cluster = clusters.get(str(parent)) if parent is not None else None
            index[str(doc.get("moref"))] = {
                "name": props.get("name"),
                "cluster_name": cluster["name"] if cluster else None,
            }
        return index

    def _dvpg_name_index(self) -> dict[str, str | None]:
        index: dict[str, str | None] = {}
        for doc in self._dvpg_docs():
            props = _as_dict(doc.get("properties"))
            index[str(doc.get("moref"))] = props.get("config.name")
        return index

    def _dvs_index(self) -> dict[str, dict[str, Any]]:
        """Map dvSwitch moref → {name, uplink_names, uplink_map} (ADR-0051 §5.3)."""
        index: dict[str, dict[str, Any]] = {}
        for doc in self._dvs_docs():
            props = _as_dict(doc.get("properties"))
            names, uplink_map = _dvs_uplink_map(props)
            index[str(doc.get("moref"))] = {
                "name": props.get("name"),
                "uplink_names": names,
                "uplink_map": uplink_map,
            }
        return index

    # -- capability methods ----------------------------------------------

    def get_virtual_machines(self) -> list[NormalizedVirtualMachine]:
        hosts = self._host_index()
        dvpgs = self._dvpg_name_index()
        provenance = self._provenance()
        vms: list[NormalizedVirtualMachine] = []
        for doc in self._vm_docs():
            props = _as_dict(doc.get("properties"))
            name = props.get("name")
            moref = doc.get("moref")
            if not name or not moref:
                continue
            host = hosts.get(str(props.get("runtime.host"))) if props.get("runtime.host") else None
            guest_net = _as_list(props.get("guest.net"))
            guest_ips: list[Any] = []
            primary = props.get("guest.ipAddress")
            if primary:
                guest_ips.append(primary)
            for net in guest_net:
                guest_ips.extend(_as_list(_as_dict(net).get("ipAddress")))
            vms.append(
                NormalizedVirtualMachine(
                    **provenance,
                    name=str(name),
                    moref=str(moref),
                    instance_uuid=props.get("config.instanceUuid") or None,
                    is_template=bool(props.get("config.template", False)),
                    power_state=_map_power_state(props.get("runtime.powerState")),
                    guest_hostname=props.get("guest.hostName") or None,
                    guest_ip_addresses=_collect_ips(guest_ips),
                    host_name=(host or {}).get("name"),
                    cluster_name=(host or {}).get("cluster_name"),
                    datacenter=doc.get("datacenter"),
                    nics=_parse_vnics(props, guest_net, dvpgs),
                    description=props.get("config.annotation") or None,
                )
            )
        return vms

    def get_hypervisor_hosts(self) -> list[NormalizedHypervisorHost]:
        clusters = self._cluster_index()
        provenance = self._provenance()
        hosts: list[NormalizedHypervisorHost] = []
        for doc in self._host_docs():
            props = _as_dict(doc.get("properties"))
            name = props.get("name")
            moref = doc.get("moref")
            if not name or not moref:
                continue
            parent = props.get("parent")
            cluster = clusters.get(str(parent)) if parent is not None else None
            network = _as_dict(props.get("config.network"))
            hosts.append(
                NormalizedHypervisorHost(
                    **provenance,
                    name=str(name),
                    moref=str(moref),
                    cluster_name=cluster["name"] if cluster else None,
                    datacenter=doc.get("datacenter"),
                    vendor=props.get("hardware.systemInfo.vendor") or None,
                    model=props.get("hardware.systemInfo.model") or None,
                    hypervisor_version=props.get("config.product.fullName") or None,
                    connection_state=_map_connection_state(props.get("runtime.connectionState")),
                    in_maintenance_mode=bool(props.get("runtime.inMaintenanceMode", False)),
                    management_ip=_host_management_ip(network),
                    pnics=_parse_pnics(network),
                )
            )
        return hosts

    def get_compute_clusters(self) -> list[NormalizedComputeCluster]:
        provenance = self._provenance()
        clusters: list[NormalizedComputeCluster] = []
        for doc in self._cluster_docs():
            props = _as_dict(doc.get("properties"))
            name = props.get("name")
            moref = doc.get("moref")
            if not name or not moref:
                continue
            clusters.append(
                NormalizedComputeCluster(
                    **provenance,
                    name=str(name),
                    moref=str(moref),
                    datacenter=doc.get("datacenter"),
                    drs_enabled=_opt_bool(props.get("configuration.drsConfig.enabled")),
                    ha_enabled=_opt_bool(props.get("configuration.dasConfig.enabled")),
                )
            )
        return clusters

    def get_port_groups(self) -> list[NormalizedPortGroup]:
        provenance = self._provenance()
        groups: list[NormalizedPortGroup] = []
        groups.extend(self._standard_port_groups(provenance))
        groups.extend(self._distributed_port_groups(provenance))
        return groups

    def _standard_port_groups(self, provenance: dict[str, Any]) -> list[NormalizedPortGroup]:
        groups: list[NormalizedPortGroup] = []
        for host_doc in self._host_docs():
            host_props = _as_dict(host_doc.get("properties"))
            host_name = host_props.get("name")
            network = _as_dict(host_props.get("config.network"))
            vswitches = {
                _as_dict(vs).get("name"): _vswitch_uplinks(_as_dict(vs))
                for vs in _as_list(network.get("vswitch"))
            }
            for pg in _as_list(network.get("portgroup")):
                spec = _as_dict(_as_dict(pg).get("spec"))
                name = spec.get("name")
                switch_name = spec.get("vswitchName")
                if not name or not switch_name:
                    continue
                override = _team_active_nics(_as_dict(spec.get("policy")))
                uplinks = override if override else vswitches.get(switch_name, ())
                groups.append(
                    NormalizedPortGroup(
                        **provenance,
                        name=str(name),
                        switch_name=str(switch_name),
                        switch_type=VirtualSwitchType.STANDARD,
                        datacenter=host_doc.get("datacenter"),
                        host_name=str(host_name) if host_name else None,
                        vlan_id=_standard_vlan(spec.get("vlanId")),
                        moref=None,
                        uplink_pnic_names=uplinks,
                    )
                )
        return groups

    def _distributed_port_groups(self, provenance: dict[str, Any]) -> list[NormalizedPortGroup]:
        dvs = self._dvs_index()
        groups: list[NormalizedPortGroup] = []
        for doc in self._dvpg_docs():
            props = _as_dict(doc.get("properties"))
            name = props.get("config.name")
            moref = doc.get("moref")
            if not name or not moref:
                continue
            dvs_entry = dvs.get(str(props.get("config.distributedVirtualSwitch")), {})
            switch_name = dvs_entry.get("name") or "unknown-dvswitch"
            groups.append(
                NormalizedPortGroup(
                    **provenance,
                    name=str(name),
                    switch_name=str(switch_name),
                    switch_type=VirtualSwitchType.DISTRIBUTED,
                    datacenter=doc.get("datacenter"),
                    host_name=None,
                    vlan_id=_distributed_vlan(props.get("config.defaultPortConfig.vlan")),
                    moref=str(moref),
                    uplink_pnic_names=_resolve_dvpg_uplinks(props, dvs_entry),
                )
            )
        return groups


# ---------------------------------------------------------------------------
# Parsing helpers (module-level, independently unit-tested — ADR-0051 §5.3)
# ---------------------------------------------------------------------------


def _opt_bool(value: object) -> bool | None:
    return bool(value) if isinstance(value, bool) else None


def _parse_vnics(
    props: dict[str, Any],
    guest_net: list[Any],
    dvpg_names: dict[str, str | None],
) -> tuple[NormalizedVirtualNic, ...]:
    """Build a VM's vNICs from ``config.hardware.device`` (ADR-0051 §5.3).

    A device is a vNIC iff it carries a ``macAddress`` (only a
    ``VirtualEthernetCard`` does). Per-NIC IPs are matched from ``guest.net`` by
    ``deviceConfigId`` ↔ device ``key``; the backing resolves the port group
    (standard → ``deviceName``; distributed → ``port.portgroupKey`` → name).
    """
    ips_by_key: dict[Any, list[Any]] = {}
    for net in guest_net:
        entry = _as_dict(net)
        ips_by_key.setdefault(entry.get("deviceConfigId"), []).extend(
            _as_list(entry.get("ipAddress"))
        )
    nics: list[NormalizedVirtualNic] = []
    for device in _as_list(props.get("config.hardware.device")):
        dev = _as_dict(device)
        mac = dev.get("macAddress")
        if not mac:
            continue
        label = _as_dict(dev.get("deviceInfo")).get("label") or f"nic-{dev.get('key')}"
        port_group_name, switch_type = _resolve_vnic_backing(
            _as_dict(dev.get("backing")), dvpg_names
        )
        nics.append(
            NormalizedVirtualNic(
                label=str(label),
                mac_address=str(mac),
                port_group_name=port_group_name,
                switch_type=switch_type,
                connected=bool(_as_dict(dev.get("connectable")).get("connected", False)),
                ip_addresses=_collect_ips(ips_by_key.get(dev.get("key"), [])),
            )
        )
    return tuple(nics)


def _resolve_vnic_backing(
    backing: dict[str, Any], dvpg_names: dict[str, str | None]
) -> tuple[str | None, VirtualSwitchType | None]:
    """Resolve a vNIC backing to ``(port_group_name, switch_type)`` (ADR-0051 §5.3)."""
    port = _as_dict(backing.get("port"))
    key = port.get("portgroupKey")
    if key:
        return dvpg_names.get(str(key)), VirtualSwitchType.DISTRIBUTED
    device_name = backing.get("deviceName")
    if device_name:
        return str(device_name), VirtualSwitchType.STANDARD
    return None, None


def _parse_pnics(network: dict[str, Any]) -> tuple[NormalizedPhysicalNic, ...]:
    """Build a host's physical NICs from ``config.network.pnic`` (ADR-0051 §5.3)."""
    pnics: list[NormalizedPhysicalNic] = []
    for pnic in _as_list(network.get("pnic")):
        entry = _as_dict(pnic)
        name = entry.get("device")
        mac = entry.get("mac")
        if not name or not mac:
            continue
        speed = _as_dict(entry.get("linkSpeed")).get("speedMb")
        pnics.append(
            NormalizedPhysicalNic(
                name=str(name),
                mac_address=str(mac),
                link_speed_mbps=speed if isinstance(speed, int) and speed >= 0 else None,
            )
        )
    return tuple(pnics)


def _host_management_ip(network: dict[str, Any]) -> IPv4Address | IPv6Address | None:
    """First parseable vmkernel address from ``config.network.vnic`` (ADR-0051 §5.3)."""
    for vnic in _as_list(network.get("vnic")):
        ip = _as_dict(_as_dict(_as_dict(vnic).get("spec")).get("ip")).get("ipAddress")
        parsed = _parse_ip(ip)
        if parsed is not None:
            return parsed
    return None


def _vswitch_uplinks(vswitch: dict[str, Any]) -> tuple[str, ...]:
    """Effective uplink pNICs of a standard vSwitch (teaming order, else its pnic list)."""
    active = _team_active_nics(_as_dict(_as_dict(vswitch.get("spec")).get("policy")))
    if active:
        return active
    return tuple(_standard_pnic_name(str(p)) for p in _as_list(vswitch.get("pnic")))


def _team_active_nics(policy: dict[str, Any]) -> tuple[str, ...]:
    """Active NICs from a standard NIC-teaming policy override; () when none set."""
    active = _as_dict(_as_dict(policy.get("nicTeaming")).get("nicOrder")).get("activeNic")
    return tuple(_standard_pnic_name(str(n)) for n in _as_list(active))


def _standard_vlan(value: object) -> int | None:
    """Map a standard port group ``vlanId`` (0 = untagged, 4095 = trunk → None)."""
    if not isinstance(value, int):
        return None
    if 1 <= value <= 4094:
        return value
    return None if value != 0 else 0


def _distributed_vlan(spec: object) -> int | None:
    """Map a distributed port group VLAN spec to an access VLAN id or ``None`` (trunk/pvlan)."""
    vlan = _as_dict(spec)
    vlan_id = vlan.get("vlanId")
    if isinstance(vlan_id, int) and 1 <= vlan_id <= 4094:
        return vlan_id
    return None


def _dvs_uplink_map(dvs_props: dict[str, Any]) -> tuple[tuple[str, ...], dict[str, str]]:
    """Build ``(uplink_port_names, {uplink_port_name: pnic})`` for a dvSwitch (ADR-0051 §5.3).

    The uplink port names come from ``config.uplinkPortPolicy.uplinkPortName``;
    the per-name pNIC binding is read from the first host member's
    ``config.host[].config.backing.pnicSpec`` (``uplinkPortKey`` indexes into the
    uplink-name list). Per-host uplink binding may differ — the first host is the
    representative LCD value, with fidelity validated in the live lab (§9.3).
    """
    uplink_policy = _as_dict(dvs_props.get("config.uplinkPortPolicy"))
    names = tuple(str(n) for n in _as_list(uplink_policy.get("uplinkPortName")))
    uplink_map: dict[str, str] = {}
    for host in _as_list(dvs_props.get("config.host")):
        backing = _as_dict(_as_dict(_as_dict(host).get("config")).get("backing"))
        pnic_specs = _as_list(backing.get("pnicSpec"))
        for spec in pnic_specs:
            entry = _as_dict(spec)
            pnic = entry.get("pnicDevice")
            key = entry.get("uplinkPortKey")
            if pnic is None or key is None:
                continue
            try:
                idx = int(key)
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(names):
                uplink_map[names[idx]] = str(pnic)
        if pnic_specs:
            break  # first host member is the representative binding
    return names, uplink_map


def _resolve_dvpg_uplinks(dvpg_props: dict[str, Any], dvs_entry: dict[str, Any]) -> tuple[str, ...]:
    """Resolve a distributed port group's effective uplink pNIC names (ADR-0051 §5.3).

    A per-portgroup teaming override (``uplinkTeamingPolicy.uplinkPortOrder.
    activeUplinkPort``) selects a subset of uplink ports; without one the port
    group inherits the dvSwitch's uplink set. Each active uplink port name is
    mapped to its bound pNIC.
    """
    uplink_map: dict[str, str] = dvs_entry.get("uplink_map", {})
    order = _as_dict(
        _as_dict(dvpg_props.get("config.defaultPortConfig.uplinkTeamingPolicy")).get(
            "uplinkPortOrder"
        )
    )
    active = _as_list(order.get("activeUplinkPort"))
    port_names = [str(n) for n in active] if active else list(dvs_entry.get("uplink_names", ()))
    return tuple(uplink_map[name] for name in port_names if name in uplink_map)


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


class VmwarePlugin(VendorPlugin):
    """VMware vSphere (``vendor_id="vmware"``) — pyVmomi vCenter inventory (ADR-0051).

    Declares exactly two **read-only** capabilities: ``DISCOVERY_API`` (vCenter
    identity) and the new ``VIRTUALIZATION_INVENTORY`` (VM / host / cluster /
    port-group inventory). The platform's first virtualization vendor and its
    first read-only-only plugin — **no write path at all** (ADR-0051 §3).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "VMware vSphere"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_API,
            Capability.VIRTUALIZATION_INVENTORY,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_API: VmwareDiscoveryApi,
            Capability.VIRTUALIZATION_INVENTORY: VmwareVirtualizationInventory,
        }
