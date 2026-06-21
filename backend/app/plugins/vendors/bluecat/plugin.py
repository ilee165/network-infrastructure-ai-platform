"""BlueCat Address Manager plugin: BAM v2 REST-backed DDI + API-discovery (ADR-0027).

The platform's third **API-based** DDI vendor plugin (after Infoblox ADR-0022 and
SpatiumDDI ADR-0024): all four capabilities (``DISCOVERY_API`` + ``DDI_DNS`` /
``DDI_DHCP`` / ``DDI_IPAM``) read through a single
:class:`~app.plugins.vendors.bluecat.client.BamClient` over the BAM RESTful v2
API (9.5+). Every BAM response is recorded verbatim via
``PluginCapability._record_raw`` before parsing (ADR-0006 §3 raw-first), so each
normalized row is re-derivable.

Mutations never write: each ``add_*``/``modify_*``/``delete_*`` method returns a
:class:`~app.plugins.base.ChangeRequestDraft` carrying the intended BAM
verb/path/body and the inverse-change rollback spec (ADR-0027 §3). Only the
Automation Agent turns a draft into an actual write, and only for an ``approved``
ChangeRequest — so the capability layer has no write path that skips the CR spine.

**Delete-inverse (ADR-0027 §3).** BAM ``DELETE`` is a **hard delete** — there is
no soft-delete / trash subsystem (contrast SpatiumDDI ADR-0024 §3). The delete-
inverse is therefore a **re-create from the captured prior body**, matching the
Infoblox posture (ADR-0022 §3). The plugin **never** emits a RESTORE inverse.

**``object_ref``** = the BAM numeric entity ``id`` (stable, immutable, globally
unique across the appliance — no ``_ref``-rotation retry path like Infoblox).

**Mutator signatures extend the ADR-0022 interface** with explicit parent ids
(``zone_id``, ``block_id``, ``network_id``) because BAM resource addresses are
hierarchical: a record lives at ``/zones/{zone_id}/resourceRecords`` and its
re-create inverse must pin the parent ``zone_id`` (ADR-0027 §3). These ids are
non-secret server-assigned integers passed in the draft ``body`` so the Automation
executor can reconstruct the URL without an extra lookup (parity with SpatiumDDI's
``(group_id, zone_id)`` embedding, ADR-0024 §1).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    ChangeRequestDraft,
    ChangeVerb,
    DdiDhcpCapability,
    DdiDnsCapability,
    DdiIpamCapability,
    DiscoveryApiCapability,
    PluginCapability,
    VendorPlugin,
)
from app.plugins.vendors.bluecat.client import BamClient, join_raw
from app.schemas.normalized import (
    DhcpLeaseState,
    DiscoveredObjectKind,
    DnsRecordType,
    NormalizedDhcpLease,
    NormalizedDhcpRange,
    NormalizedDiscoveredObject,
    NormalizedDnsRecord,
    NormalizedNetwork,
)

__all__ = [
    "BluecatDdiDhcp",
    "BluecatDdiDns",
    "BluecatDdiIpam",
    "BluecatDiscoveryApi",
    "BluecatPlugin",
]

VENDOR_ID = "bluecat"

#: BAM v2 record ``type`` string → normalized DnsRecordType (ADR-0027 §1).
#: Types not in the lowest-common-denominator enum (CAA, NAPTR, etc.) map to OTHER.
_DNS_TYPE_MAP: Mapping[str, DnsRecordType] = {
    "A": DnsRecordType.A,
    "AAAA": DnsRecordType.AAAA,
    "CNAME": DnsRecordType.CNAME,
    "MX": DnsRecordType.MX,
    "NS": DnsRecordType.NS,
    "PTR": DnsRecordType.PTR,
    "SOA": DnsRecordType.SOA,
    "SRV": DnsRecordType.SRV,
    "TXT": DnsRecordType.TXT,
}

#: BAM v2 DHCP-state filter mandated by ADR-0027 §2 DDI_DHCP: ``get_leases`` must
#: fetch ONLY leased addresses (DHCP_ALLOCATED + DHCP_RESERVED), never DHCP_FREE.
#: Matches :meth:`BamClient.get_leases`'s filter verbatim so the capability and the
#: client agree on the query parameter sent to BAM.
_DHCP_LEASE_FILTER = "state:in('DHCP_ALLOCATED','DHCP_RESERVED')"

#: BAM v2 address ``state`` → normalized DhcpLeaseState (ADR-0027 §2 DDI_DHCP).
_LEASE_STATE_MAP: Mapping[str, DhcpLeaseState] = {
    "DHCP_ALLOCATED": DhcpLeaseState.ACTIVE,
    "DHCP_FREE": DhcpLeaseState.FREE,
    "DHCP_RESERVED": DhcpLeaseState.STATIC,
    "DHCP_ABANDONED": DhcpLeaseState.ABANDONED,
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _BamCapability(PluginCapability):
    """Shared base: holds the BAM client + device context.

    ``_read_list`` issues a BAM v2 ``list()`` call, records every response
    verbatim (one raw artifact per path call) before parsing — the audit hook
    the discovery runner persists to ``raw_artifacts`` (ADR-0006 §3).
    """

    def __init__(self, client: BamClient, device_id: UUID) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id

    def _read_list(
        self, path: str, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        objects = self._client.get_list(path, params=params)
        self._record_raw(f"GET {path}", join_raw(path, objects))
        return objects

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }


class BluecatDiscoveryApi(_BamCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: BAM configurations + blocks + networks + views + zones.

    Read-only fan-out (no single discovery endpoint server-side — ADR-0027 §1):
    ``GET /configurations`` → for each, fetch blocks, networks, views, zones →
    emit :class:`NormalizedDiscoveredObject` records.
    """

    def discover(self) -> list[NormalizedDiscoveredObject]:
        provenance = self._provenance()
        objects: list[NormalizedDiscoveredObject] = []

        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue

            # Blocks (aggregate containers — ADR-0027 §1 DISCOVERY_API).
            blocks = self._read_list(f"/configurations/{config_id}/blocks")
            for block in blocks:
                block_range = block.get("range")
                if not block_range:
                    continue
                objects.append(
                    NormalizedDiscoveredObject(
                        **provenance,
                        kind=DiscoveredObjectKind.NETWORK,
                        identifier=str(block_range),
                        display_name=block.get("name"),
                        object_ref=_opt_str(block.get("id")),
                        attributes=_attrs(block, ("configurationId", "type")),
                    )
                )

            # Networks (IPv4Network — ADR-0027 §1 DISCOVERY_API).
            for block in blocks:
                block_id = block.get("id")
                if not block_id:
                    continue
                networks = self._read_list(f"/blocks/{block_id}/networks")
                for net in networks:
                    cidr = net.get("range")
                    if not cidr:
                        continue
                    objects.append(
                        NormalizedDiscoveredObject(
                            **provenance,
                            kind=DiscoveredObjectKind.NETWORK,
                            identifier=str(cidr),
                            display_name=net.get("name"),
                            object_ref=_opt_str(net.get("id")),
                            attributes=_attrs(net, ("blockId", "gateway")),
                        )
                    )

            # Views + zones (DNS side — ADR-0027 §1 DISCOVERY_API).
            views = self._read_list(f"/configurations/{config_id}/views")
            for view in views:
                view_id = view.get("id")
                if not view_id:
                    continue
                zones = self._read_list(f"/views/{view_id}/zones")
                for zone in zones:
                    zone_name = zone.get("absoluteName") or zone.get("name")
                    if not zone_name:
                        continue
                    objects.append(
                        NormalizedDiscoveredObject(
                            **provenance,
                            kind=DiscoveredObjectKind.DNS_ZONE,
                            identifier=str(zone_name),
                            display_name=zone.get("name"),
                            object_ref=_opt_str(zone.get("id")),
                            attributes=_attrs(zone, ("viewId", "type", "deployable")),
                        )
                    )

        return objects


class BluecatDdiDns(_BamCapability, DdiDnsCapability):
    """``DDI_DNS``: read zones + records; mutations produce ChangeRequestDrafts.

    The default ``get_zones``/``get_records`` methods fan out over all
    configurations and views discovered from the client. Mutators accept an
    explicit ``zone_id`` (the BAM integer id) so the executor can construct the
    full URL ``/zones/{zone_id}/resourceRecords`` (ADR-0027 §2).
    """

    def get_zones(self) -> list[str]:
        zones: list[str] = []
        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue
            views = self._read_list(f"/configurations/{config_id}/views")
            for view in views:
                view_id = view.get("id")
                if not view_id:
                    continue
                view_zones = self._read_list(f"/views/{view_id}/zones")
                for zone in view_zones:
                    name = zone.get("absoluteName") or zone.get("name")
                    if name:
                        zones.append(str(name))
        return zones

    def get_records(self, zone: str | None = None) -> list[NormalizedDnsRecord]:
        provenance = self._provenance()
        records: list[NormalizedDnsRecord] = []
        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue
            views = self._read_list(f"/configurations/{config_id}/views")
            for view in views:
                view_id = view.get("id")
                if not view_id:
                    continue
                view_zones = self._read_list(f"/views/{view_id}/zones")
                for zone_obj in view_zones:
                    zone_name = zone_obj.get("absoluteName") or zone_obj.get("name")
                    if zone is not None and zone_name != zone:
                        continue
                    zone_id = zone_obj.get("id")
                    if not zone_id:
                        continue
                    recs = self._read_list(f"/zones/{zone_id}/resourceRecords")
                    for obj in recs:
                        zone_label = str(zone_name) if zone_name else None
                        record = _normalize_record(obj, zone_label, provenance)
                        if record is not None:
                            records.append(record)
        return records

    def add_record(
        self, record: NormalizedDnsRecord, zone_id: int | None = None
    ) -> ChangeRequestDraft:
        """Draft a BAM resource-record create (ADR-0027 §2 DDI_DNS.add_record).

        ``zone_id`` is the parent BAM Zone integer id (required to construct
        ``POST /zones/{zone_id}/resourceRecords``). The inverse is
        ``DELETE /resourceRecords/{new_id}`` (new id unknown until write commits).
        """
        if zone_id is None:
            raise PluginError(
                "bluecat: add_record requires zone_id (BAM Zone integer id) "
                "to construct POST /zones/{zone_id}/resourceRecords"
            )
        rtype = record.record_type.value.upper()
        body = _record_body(zone_id, record, rtype)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource=f"bluecat:resourceRecord:{rtype}",
            body=body,
            summary=f"add {rtype} record {record.name} in zone id={zone_id}",
            # Inverse: DELETE the newly-created record (id unknown until Automation Agent writes).
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource=f"bluecat:resourceRecord:{rtype}",
                object_ref=None,
                summary=f"delete the newly-added {rtype} record {record.name}",
            ),
        )

    def modify_record(
        self,
        object_ref: str,
        changes: NormalizedDnsRecord,
        current: NormalizedDnsRecord | None = None,
    ) -> ChangeRequestDraft:
        """Draft a BAM resource-record PUT (full replace, ADR-0027 §2).

        ``type`` is immutable on update per BAM semantics (ADR-0027 §2). The
        inverse re-applies the prior field values (ADR-0027 §3 update-inverse).
        """
        rtype = changes.record_type.value.upper()
        body = _record_update_body(changes, rtype)
        if current is not None:
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.UPDATE,
                resource=f"bluecat:resourceRecord:{rtype}",
                object_ref=object_ref,
                body=_record_update_body(current, current.record_type.value.upper()),
                summary=f"restore prior {rtype} value of {current.name}",
            )
            summary = f"modify {rtype} record {changes.name}"
        else:
            inverse = None
            summary = (
                f"modify {rtype} record {changes.name} "
                "(rollback needs a fresh pre-image — none captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=ChangeVerb.UPDATE,
            resource=f"bluecat:resourceRecord:{rtype}",
            object_ref=object_ref,
            body=body,
            summary=summary,
            inverse=inverse,
        )

    def delete_record(
        self,
        object_ref: str,
        current: NormalizedDnsRecord | None = None,
        zone_id: int | None = None,
    ) -> ChangeRequestDraft:
        """Draft a BAM resource-record hard DELETE (ADR-0027 §3 delete-inverse).

        BAM hard-deletes the record (no trash). The inverse is a re-create
        ``POST /zones/{zone_id}/resourceRecords`` with the captured prior body
        (new id minted — ADR-0027 §3, explicitly NOT a RESTORE).

        ``zone_id`` is the parent BAM Zone integer id — required when ``current``
        is provided so the re-create inverse can pin the parent.

        :raises PluginError: if ``current`` is provided but ``zone_id`` is missing —
            emitting a re-create inverse pinned to a nonexistent parent would push a
            structurally-invalid body into the CR pipeline (ADR-0027 §3).
        """
        if current is not None:
            rtype = current.record_type.value.upper()
            # zone_id is required to pin the re-create inverse's parent. Refuse to emit a
            # structurally-invalid inverse pinned to a nonexistent parent (ADR-0027 §3) —
            # matches SpatiumDDI._record_parents, keeping invalid bodies out of the CR pipeline.
            if zone_id is None:
                raise PluginError(
                    "bluecat: delete_record with current= requires zone_id (BAM Zone integer id) "
                    "so the re-create inverse can pin the parent — refusing to emit an inverse "
                    "pinned to a nonexistent parent (ADR-0027 §3)"
                )
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.CREATE,
                resource=f"bluecat:resourceRecord:{rtype}",
                body=_record_body(zone_id, current, rtype),
                summary=f"re-create the hard-deleted {rtype} record {current.name}",
            )
            summary = f"hard-delete {rtype} record {current.name}"
        else:
            inverse = None
            summary = (
                f"hard-delete DNS record {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        rtype_str = current.record_type.value.upper() if current else "resourceRecord"
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource=f"bluecat:{rtype_str}",
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


class BluecatDdiDhcp(_BamCapability, DdiDhcpCapability):
    """``DDI_DHCP``: read ranges + leases; mutations produce ChangeRequestDrafts."""

    def get_ranges(self) -> list[NormalizedDhcpRange]:
        provenance = self._provenance()
        ranges: list[NormalizedDhcpRange] = []
        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue
            blocks = self._read_list(f"/configurations/{config_id}/blocks")
            for block in blocks:
                block_id = block.get("id")
                if not block_id:
                    continue
                networks = self._read_list(f"/blocks/{block_id}/networks")
                for net in networks:
                    network_id = net.get("id")
                    if not network_id:
                        continue
                    net_ranges = self._read_list(f"/networks/{network_id}/ranges")
                    for obj in net_ranges:
                        start = obj.get("start")
                        end = obj.get("end")
                        if not start or not end:
                            continue
                        ranges.append(
                            NormalizedDhcpRange(
                                **provenance,
                                start_address=ip_address(str(start)),
                                end_address=ip_address(str(end)),
                                name=obj.get("name"),
                                network=net.get("range"),
                                object_ref=_opt_str(obj.get("id")),
                            )
                        )
        return ranges

    def get_leases(self) -> list[NormalizedDhcpLease]:
        provenance = self._provenance()
        leases: list[NormalizedDhcpLease] = []
        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue
            blocks = self._read_list(f"/configurations/{config_id}/blocks")
            for block in blocks:
                block_id = block.get("id")
                if not block_id:
                    continue
                networks = self._read_list(f"/blocks/{block_id}/networks")
                for net in networks:
                    network_id = net.get("id")
                    if not network_id:
                        continue
                    addrs = self._read_list(
                        f"/networks/{network_id}/addresses",
                        params={"filter": _DHCP_LEASE_FILTER},
                    )
                    for obj in addrs:
                        address = obj.get("address")
                        if not address:
                            continue
                        state_str = str(obj.get("state", "")).upper()
                        lease_state = _LEASE_STATE_MAP.get(state_str, DhcpLeaseState.OTHER)
                        leases.append(
                            NormalizedDhcpLease(
                                **provenance,
                                ip_address=ip_address(str(address)),
                                state=lease_state,
                                mac_address=obj.get("macAddress") or None,
                                ends_at=_parse_dt(obj.get("expiryTime")),
                                network=net.get("range"),
                                object_ref=_opt_str(obj.get("id")),
                            )
                        )
        return leases

    def add_range(
        self, dhcp_range: NormalizedDhcpRange, network_id: int | None = None
    ) -> ChangeRequestDraft:
        """Draft a BAM DHCPv4Range create (ADR-0027 §2 DDI_DHCP.add_range).

        ``network_id`` is the parent IPv4Network integer id (required to construct
        ``POST /networks/{network_id}/ranges``). The inverse is
        ``DELETE /ranges/{new_id}`` (new id unknown until Automation Agent writes).
        """
        if network_id is None:
            raise PluginError(
                "bluecat: add_range requires network_id (BAM IPv4Network integer id) "
                "to construct POST /networks/{network_id}/ranges"
            )
        body = _range_body(network_id, dhcp_range)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource="bluecat:dhcpv4Range",
            body=body,
            summary=f"add DHCP range {dhcp_range.start_address}-{dhcp_range.end_address}",
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource="bluecat:dhcpv4Range",
                object_ref=None,
                summary="hard-delete the newly-added DHCP range",
            ),
        )

    def delete_range(
        self,
        object_ref: str,
        current: NormalizedDhcpRange | None = None,
        network_id: int | None = None,
    ) -> ChangeRequestDraft:
        """Draft a BAM DHCPv4Range hard DELETE (ADR-0027 §3 delete-inverse).

        BAM hard-deletes the range (no trash). The inverse re-creates from the
        captured prior body (ADR-0027 §3 — NOT a RESTORE).

        ``network_id`` is the parent IPv4Network integer id — required when
        ``current`` is provided so the re-create inverse can pin the parent.

        :raises PluginError: if ``current`` is provided but ``network_id`` is missing —
            emitting a re-create inverse pinned to a nonexistent parent would push a
            structurally-invalid body into the CR pipeline (ADR-0027 §3).
        """
        if current is not None:
            # network_id is required to pin the re-create inverse's parent. Refuse to emit a
            # structurally-invalid inverse pinned to a nonexistent parent (ADR-0027 §3) —
            # matches SpatiumDDI._record_parents, keeping invalid bodies out of the CR pipeline.
            if network_id is None:
                raise PluginError(
                    "bluecat: delete_range with current= requires network_id (BAM IPv4Network "
                    "integer id) so the re-create inverse can pin the parent — refusing to emit "
                    "an inverse pinned to a nonexistent parent (ADR-0027 §3)"
                )
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.CREATE,
                resource="bluecat:dhcpv4Range",
                body=_range_body(network_id, current),
                summary=f"re-create the hard-deleted DHCP range "
                f"{current.start_address}-{current.end_address}",
            )
            summary = f"hard-delete DHCP range {current.start_address}-{current.end_address}"
        else:
            inverse = None
            summary = (
                f"hard-delete DHCP range {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource="bluecat:dhcpv4Range",
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


class BluecatDdiIpam(_BamCapability, DdiIpamCapability):
    """``DDI_IPAM``: read networks; mutations produce ChangeRequestDrafts."""

    def get_networks(self) -> list[NormalizedNetwork]:
        provenance = self._provenance()
        networks: list[NormalizedNetwork] = []
        configs = self._read_list("/configurations")
        for config in configs:
            config_id = config.get("id")
            if not config_id:
                continue
            blocks = self._read_list(f"/configurations/{config_id}/blocks")
            for block in blocks:
                block_id = block.get("id")
                if not block_id:
                    continue
                nets = self._read_list(f"/blocks/{block_id}/networks")
                for obj in nets:
                    cidr = obj.get("range")
                    if not cidr:
                        continue
                    util = obj.get("utilization")
                    networks.append(
                        NormalizedNetwork(
                            **provenance,
                            network=ip_network(str(cidr), strict=False),
                            comment=obj.get("name"),
                            network_view=None,
                            utilization_percent=_utilization(util),
                            object_ref=_opt_str(obj.get("id")),
                        )
                    )
        return networks

    def get_next_available_ip(self, network: str) -> str:
        """Server-side next-IP peek (ADR-0027 §2 DDI_IPAM.get_next_available_ip).

        Resolves the network id by CIDR, then calls the BAM server-side function
        ``getNextAvailableIP4Address`` (``/networks/{id}/addresses/next``). We do
        NOT compute free space client-side (ADR-0027 §2 alt #4 rejected).
        """
        # Resolve the network's BAM id by scanning known blocks/networks.
        network_id: int | None = None
        configs = self._read_list("/configurations")
        outer: bool = False
        for config in configs:
            if outer:
                break
            config_id = config.get("id")
            if not config_id:
                continue
            blocks = self._read_list(f"/configurations/{config_id}/blocks")
            for block in blocks:
                block_id = block.get("id")
                if not block_id:
                    continue
                nets = self._read_list(f"/blocks/{block_id}/networks")
                for net in nets:
                    if str(net.get("range")) == network and net.get("id"):
                        network_id = int(net["id"])
                        outer = True
                        break
                if outer:
                    break

        if network_id is None:
            raise PluginError(f"bluecat: no such network {network!r} in IPAM")
        result = self._client.get_next_available_ip(network_id)
        self._record_raw(
            f"GET /networks/{network_id}/addresses/next",
            join_raw(f"/networks/{network_id}/addresses/next", [result]),
        )
        address = result.get("address")
        if not address:
            raise PluginError(
                f"bluecat: getNextAvailableIP4Address returned no address for {network!r}"
            )
        return str(address)

    def add_network(
        self, network: NormalizedNetwork, block_id: int | None = None
    ) -> ChangeRequestDraft:
        """Draft a BAM IPv4Network create (ADR-0027 §2 DDI_IPAM.add_network).

        ``block_id`` is the parent IPv4Block integer id (required to construct
        ``POST /blocks/{block_id}/networks``). The inverse is
        ``DELETE /networks/{new_id}`` (new id unknown until Automation Agent writes).
        """
        if block_id is None:
            raise PluginError(
                "bluecat: add_network requires block_id (BAM IPv4Block integer id) "
                "to construct POST /blocks/{block_id}/networks"
            )
        body = _network_body(block_id, network)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource="bluecat:ipv4Network",
            body=body,
            summary=f"add network {network.network}",
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource="bluecat:ipv4Network",
                object_ref=None,
                summary=f"hard-delete the newly-added network {network.network}",
            ),
        )

    def delete_network(
        self,
        object_ref: str,
        current: NormalizedNetwork | None = None,
        block_id: int | None = None,
    ) -> ChangeRequestDraft:
        """Draft a BAM IPv4Network hard DELETE (ADR-0027 §3 delete-inverse).

        BAM hard-deletes the network (no trash). The inverse re-creates from the
        captured prior body (ADR-0027 §3 — NOT a RESTORE).

        ``block_id`` is the parent IPv4Block integer id — required when ``current``
        is provided so the re-create inverse can pin the parent.

        :raises PluginError: if ``current`` is provided but ``block_id`` is missing —
            emitting a re-create inverse pinned to a nonexistent parent would push a
            structurally-invalid body into the CR pipeline (ADR-0027 §3).
        """
        if current is not None:
            # block_id is required to pin the re-create inverse's parent. Refuse to emit a
            # structurally-invalid inverse pinned to a nonexistent parent (ADR-0027 §3) —
            # matches SpatiumDDI._record_parents, keeping invalid bodies out of the CR pipeline.
            if block_id is None:
                raise PluginError(
                    "bluecat: delete_network with current= requires block_id (BAM IPv4Block "
                    "integer id) so the re-create inverse can pin the parent — refusing to emit "
                    "an inverse pinned to a nonexistent parent (ADR-0027 §3)"
                )
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.CREATE,
                resource="bluecat:ipv4Network",
                body=_network_body(block_id, current),
                summary=f"re-create the hard-deleted network {current.network}",
            )
            summary = f"hard-delete network {current.network}"
        else:
            inverse = None
            summary = (
                f"hard-delete network {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource="bluecat:ipv4Network",
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


# ---------------------------------------------------------------------------
# Parsing / draft-body helpers (no secrets ever flow through these)
# ---------------------------------------------------------------------------


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _attrs(obj: Mapping[str, Any], keys: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Flatten selected BAM fields into a secret-free (key, value) tuple list."""
    out: list[tuple[str, str]] = []
    for key in keys:
        value = obj.get(key)
        if value is None:
            continue
        out.append((key, str(value)))
    return tuple(out)


def _utilization(util: Any) -> float | None:
    """Extract the ``percentUsed`` field from a BAM utilization object."""
    if isinstance(util, dict):
        pct = util.get("percentUsed")
    elif isinstance(util, (int, float)):
        pct = util
    else:
        return None
    if not isinstance(pct, (int, float)):
        return None
    result = round(float(pct), 2)
    if result < 0 or result > 100:
        return None
    return result


def _dns_value(record_type: DnsRecordType, rdata: Mapping[str, Any]) -> str | None:
    """Extract the record value from a BAM v2 ``rdata`` object by type (ADR-0027 §1)."""
    if record_type == DnsRecordType.A:
        return _opt_str(rdata.get("address"))
    if record_type == DnsRecordType.AAAA:
        return _opt_str(rdata.get("address"))
    if record_type == DnsRecordType.CNAME:
        return _opt_str(rdata.get("linkedRecord") or rdata.get("alias"))
    if record_type == DnsRecordType.MX:
        return _opt_str(rdata.get("linkedRecord") or rdata.get("mailExchanger"))
    if record_type == DnsRecordType.SRV:
        return _opt_str(rdata.get("linkedRecord") or rdata.get("target"))
    if record_type == DnsRecordType.TXT:
        return _opt_str(rdata.get("text"))
    if record_type == DnsRecordType.PTR:
        return _opt_str(rdata.get("dname") or rdata.get("ptrdname"))
    if record_type == DnsRecordType.NS:
        return _opt_str(rdata.get("nameServer") or rdata.get("linkedRecord"))
    # Fallback for OTHER types: try common rdata field names.
    for key in ("value", "data", "text", "address", "linkedRecord", "dname"):
        v = rdata.get(key)
        if v:
            return str(v)
    return None


def _dns_value_field(record_type: DnsRecordType) -> str:
    """BAM v2 rdata field name holding the record value, per type."""
    return {
        DnsRecordType.A: "address",
        DnsRecordType.AAAA: "address",
        DnsRecordType.CNAME: "linkedRecord",
        DnsRecordType.MX: "linkedRecord",
        DnsRecordType.SRV: "linkedRecord",
        DnsRecordType.TXT: "text",
        DnsRecordType.PTR: "dname",
        DnsRecordType.NS: "nameServer",
    }.get(record_type, "value")


def _normalize_record(
    obj: Mapping[str, Any],
    zone_name: str | None,
    provenance: Mapping[str, Any],
) -> NormalizedDnsRecord | None:
    """Normalize a BAM v2 ResourceRecord object into a :class:`NormalizedDnsRecord`."""
    name = obj.get("name") or obj.get("absoluteName")
    rtype_str = str(obj.get("type", "")).upper()
    record_type = _DNS_TYPE_MAP.get(rtype_str, DnsRecordType.OTHER)
    rdata = obj.get("rdata") or {}
    value = _dns_value(record_type, rdata if isinstance(rdata, dict) else {})
    if not name or not value:
        return None
    return NormalizedDnsRecord(
        **provenance,
        name=str(name),
        record_type=record_type,
        value=str(value),
        ttl=obj.get("ttl"),
        zone=zone_name or _opt_str(obj.get("zoneId")),
        object_ref=_opt_str(obj.get("id")),
    )


def _record_body(
    zone_id: int, record: NormalizedDnsRecord, rtype: str
) -> tuple[tuple[str, str], ...]:
    """ResourceRecordCreate body (ADR-0027 §2 add_record)."""
    value_field = _dns_value_field(record.record_type)
    body: list[tuple[str, str]] = [
        ("zone_id", str(zone_id)),
        ("type", rtype),
        ("name", record.name),
        (value_field, record.value),
    ]
    if record.ttl is not None:
        body.append(("ttl", str(record.ttl)))
    return tuple(body)


def _record_update_body(record: NormalizedDnsRecord, rtype: str) -> tuple[tuple[str, str], ...]:
    """ResourceRecordUpdate body (``type`` is immutable; not sent — ADR-0027 §2)."""
    value_field = _dns_value_field(record.record_type)
    body: list[tuple[str, str]] = [(value_field, record.value)]
    if record.ttl is not None:
        body.append(("ttl", str(record.ttl)))
    return tuple(body)


def _range_body(network_id: int, dhcp_range: NormalizedDhcpRange) -> tuple[tuple[str, str], ...]:
    """DHCPv4RangeCreate body (ADR-0027 §2 add_range)."""
    body: list[tuple[str, str]] = [
        ("network_id", str(network_id)),
        ("start", str(dhcp_range.start_address)),
        ("end", str(dhcp_range.end_address)),
    ]
    if dhcp_range.name:
        body.append(("name", dhcp_range.name))
    return tuple(body)


def _network_body(block_id: int, network: NormalizedNetwork) -> tuple[tuple[str, str], ...]:
    """IPv4NetworkCreate body (ADR-0027 §2 add_network)."""
    body: list[tuple[str, str]] = [
        ("block_id", str(block_id)),
        ("range", str(network.network)),
    ]
    if network.comment:
        body.append(("name", network.comment))
    return tuple(body)


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp (BAM lease expiryTime) to aware UTC."""
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


class BluecatPlugin(VendorPlugin):
    """BlueCat Address Manager (``vendor_id="bluecat"``) — BAM v2 DDI plugin (ADR-0027).

    Declares the four BAM RESTful v2-backed capabilities: ``DISCOVERY_API`` plus
    ``DDI_DNS`` / ``DDI_DHCP`` / ``DDI_IPAM``. No SSH/SNMP/config-write
    capabilities — BAM is a DDI appliance, the partial-capability model ADR-0006
    intends. Completes the on-prem DDI pair (Infoblox + BlueCat) required by
    CLAUDE.md, and proves the DDI abstraction is vendor-neutral across three
    identity models: Infoblox ``_ref``, SpatiumDDI UUID, and BAM numeric ``id``.
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "BlueCat Address Manager"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_API,
            Capability.DDI_DNS,
            Capability.DDI_DHCP,
            Capability.DDI_IPAM,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_API: BluecatDiscoveryApi,
            Capability.DDI_DNS: BluecatDdiDns,
            Capability.DDI_DHCP: BluecatDdiDhcp,
            Capability.DDI_IPAM: BluecatDdiIpam,
        }
