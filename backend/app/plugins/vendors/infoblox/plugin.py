"""Infoblox plugin: WAPI-backed DDI + API-discovery capabilities (ADR-0022).

The platform's first **API-based** vendor plugin (no SSH/SNMP): all four
capabilities (``DISCOVERY_API`` + ``DDI_DNS``/``DDI_DHCP``/``DDI_IPAM``) read
through a single :class:`~app.plugins.vendors.infoblox.wapi.WapiClient` over
Infoblox WAPI. Every WAPI response is recorded verbatim via
``PluginCapability._record_raw`` before parsing (ADR-0006 §3 raw-first), so
each normalized row is re-derivable.

Mutations never write: each ``add_*``/``modify_*``/``delete_*`` method returns a
:class:`~app.plugins.base.ChangeRequestDraft` carrying the intended WAPI
verb/body and an inverse-change rollback spec (ADR-0022 §3). Only the Automation
Agent turns a draft into an actual write, and only for an ``approved``
ChangeRequest — so the capability layer has no write path that skips the CR
spine.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    ChangeRequestDraft,
    DdiDhcpCapability,
    DdiDnsCapability,
    DdiIpamCapability,
    DiscoveryApiCapability,
    PluginCapability,
    VendorPlugin,
    WapiVerb,
)
from app.plugins.vendors.infoblox.wapi import WapiClient, join_raw
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
    "InfobloxDdiDhcp",
    "InfobloxDdiDns",
    "InfobloxDdiIpam",
    "InfobloxDiscoveryApi",
    "InfobloxPlugin",
]

VENDOR_ID = "infoblox"

#: WAPI object types each capability reads (return_fields kept minimal — the
#: lowest-common-denominator normalized models, ADR-0006 negative).
_WAPI_NETWORK = "network"
_WAPI_ZONE = "zone_auth"
_WAPI_MEMBER = "member"
_WAPI_RANGE = "range"
_WAPI_LEASE = "lease"

#: WAPI record:<type> -> normalized DnsRecordType. The DNS read pulls the common
#: record types Infoblox exposes as distinct objects.
_DNS_OBJECT_TYPES: tuple[tuple[str, DnsRecordType], ...] = (
    ("record:a", DnsRecordType.A),
    ("record:aaaa", DnsRecordType.AAAA),
    ("record:cname", DnsRecordType.CNAME),
    ("record:ptr", DnsRecordType.PTR),
    ("record:mx", DnsRecordType.MX),
    ("record:txt", DnsRecordType.TXT),
)

#: WAPI lease binding_state -> normalized DhcpLeaseState.
_LEASE_STATE_MAP: Mapping[str, DhcpLeaseState] = {
    "ACTIVE": DhcpLeaseState.ACTIVE,
    "FREE": DhcpLeaseState.FREE,
    "EXPIRED": DhcpLeaseState.EXPIRED,
    "ABANDONED": DhcpLeaseState.ABANDONED,
    "OFFERED": DhcpLeaseState.OFFERED,
    "STATIC": DhcpLeaseState.STATIC,
    "BACKUP": DhcpLeaseState.BACKUP,
}


def _epoch_to_dt(value: Any) -> datetime | None:
    """WAPI lease times are UNIX epoch ints; map to aware UTC datetimes."""
    if not isinstance(value, int):
        return None
    return datetime.fromtimestamp(value, tz=UTC)


class _InfobloxCapability(PluginCapability):
    """Shared base: holds the WAPI client + device context.

    ``_read`` records every WAPI response verbatim (one RawOutput per object
    type) before parsing — the audit hook the discovery runner persists to
    ``raw_artifacts`` (ADR-0006 §3).
    """

    def __init__(self, client: WapiClient, device_id: UUID) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id

    def _read(
        self, objtype: str, params: Mapping[str, str] | None = None
    ) -> list[dict[str, Any]]:
        objects = self._client.get(objtype, params)
        self._record_raw(f"GET {objtype}", join_raw(objtype, objects))
        return objects

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": self._now(),
            "source_vendor": VENDOR_ID,
        }


class InfobloxDiscoveryApi(_InfobloxCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: WAPI networks + zones + members -> discovered objects.

    The first API-based discovery path (ADR-0022 §2): read-only, feeds the
    discovery engine and the DNS-dependency topology layer (M5 task #13).
    """

    def discover(self) -> list[NormalizedDiscoveredObject]:
        provenance = self._provenance()
        objects: list[NormalizedDiscoveredObject] = []

        for net in self._read(_WAPI_NETWORK):
            cidr = net.get("network")
            if not cidr:
                continue
            objects.append(
                NormalizedDiscoveredObject(
                    **provenance,
                    kind=DiscoveredObjectKind.NETWORK,
                    identifier=str(cidr),
                    display_name=net.get("comment"),
                    object_ref=net.get("_ref"),
                    attributes=_attrs(net, ("network_view",)),
                )
            )
        for zone in self._read(_WAPI_ZONE):
            fqdn = zone.get("fqdn")
            if not fqdn:
                continue
            objects.append(
                NormalizedDiscoveredObject(
                    **provenance,
                    kind=DiscoveredObjectKind.DNS_ZONE,
                    identifier=str(fqdn),
                    display_name=zone.get("comment"),
                    object_ref=zone.get("_ref"),
                    attributes=_attrs(zone, ("view", "zone_format")),
                )
            )
        for member in self._read(_WAPI_MEMBER):
            host = member.get("host_name")
            if not host:
                continue
            objects.append(
                NormalizedDiscoveredObject(
                    **provenance,
                    kind=DiscoveredObjectKind.MEMBER,
                    identifier=str(host),
                    display_name=member.get("comment"),
                    object_ref=member.get("_ref"),
                    attributes=_attrs(member, ("vip_setting",)),
                )
            )
        return objects


class InfobloxDdiDns(_InfobloxCapability, DdiDnsCapability):
    """``DDI_DNS``: read records; mutations produce ChangeRequestDrafts."""

    def get_zones(self) -> list[str]:
        zones: list[str] = []
        for obj in self._read(_WAPI_ZONE):
            fqdn = obj.get("fqdn")
            if fqdn:
                zones.append(str(fqdn))
        return zones

    def get_records(self, zone: str | None = None) -> list[NormalizedDnsRecord]:
        provenance = self._provenance()
        records: list[NormalizedDnsRecord] = []
        params = {"zone": zone} if zone else None
        for objtype, record_type in _DNS_OBJECT_TYPES:
            for obj in self._read(objtype, params):
                name = obj.get("name")
                value = _dns_value(record_type, obj)
                if not name or not value:
                    continue
                records.append(
                    NormalizedDnsRecord(
                        **provenance,
                        name=str(name),
                        record_type=record_type,
                        value=str(value),
                        ttl=obj.get("ttl"),
                        zone=obj.get("zone"),
                        object_ref=obj.get("_ref"),
                    )
                )
        return records

    def add_record(self, record: NormalizedDnsRecord) -> ChangeRequestDraft:
        wapi_object = f"record:{record.record_type.value}"
        body = (("name", record.name), (_dns_value_field(record.record_type), record.value))
        return ChangeRequestDraft(
            verb=WapiVerb.CREATE,
            wapi_object=wapi_object,
            body=body,
            summary=f"add {record.record_type.value.upper()} record {record.name}",
            inverse=ChangeRequestDraft(
                verb=WapiVerb.DELETE,
                wapi_object=wapi_object,
                object_ref=None,
                summary=f"delete the newly-added {record.record_type.value.upper()} "
                f"record {record.name}",
            ),
        )

    def modify_record(
        self,
        object_ref: str,
        changes: NormalizedDnsRecord,
        current: NormalizedDnsRecord | None = None,
    ) -> ChangeRequestDraft:
        wapi_object = f"record:{changes.record_type.value}"
        value_field = _dns_value_field(changes.record_type)
        body = ((value_field, changes.value),)
        # The inverse can only restore the prior value if we have the pre-image.
        # Without it we must NOT emit a blind empty-body "restore" (ADR-0022 §3).
        if current is not None:
            inverse = ChangeRequestDraft(
                verb=WapiVerb.UPDATE,
                wapi_object=f"record:{current.record_type.value}",
                object_ref=object_ref,
                body=((_dns_value_field(current.record_type), current.value),),
                summary=f"restore prior {current.record_type.value.upper()} "
                f"value of {current.name}",
            )
            summary = f"modify {changes.record_type.value.upper()} record {changes.name}"
        else:
            inverse = None
            summary = (
                f"modify {changes.record_type.value.upper()} record {changes.name} "
                "(rollback needs a fresh pre-image — none captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=WapiVerb.UPDATE,
            wapi_object=wapi_object,
            object_ref=object_ref,
            body=body,
            summary=summary,
            inverse=inverse,
        )

    def delete_record(
        self, object_ref: str, current: NormalizedDnsRecord | None = None
    ) -> ChangeRequestDraft:
        # The inverse re-create is only possible with the deleted record's full
        # pre-image; otherwise delete is non-reversible (ADR-0022 §3).
        if current is not None:
            inverse = ChangeRequestDraft(
                verb=WapiVerb.CREATE,
                wapi_object=f"record:{current.record_type.value}",
                body=(
                    ("name", current.name),
                    (_dns_value_field(current.record_type), current.value),
                ),
                summary=f"re-create the deleted {current.record_type.value.upper()} "
                f"record {current.name}",
            )
            summary = f"delete {current.record_type.value.upper()} record {current.name}"
        else:
            inverse = None
            summary = (
                f"delete DNS record {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=WapiVerb.DELETE,
            wapi_object=f"record:{current.record_type.value}" if current else "record",
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


class InfobloxDdiDhcp(_InfobloxCapability, DdiDhcpCapability):
    """``DDI_DHCP``: read ranges + leases; mutations produce ChangeRequestDrafts."""

    def get_ranges(self) -> list[NormalizedDhcpRange]:
        provenance = self._provenance()
        ranges: list[NormalizedDhcpRange] = []
        for obj in self._read(_WAPI_RANGE):
            start = obj.get("start_addr")
            end = obj.get("end_addr")
            if not start or not end:
                continue
            ranges.append(
                NormalizedDhcpRange(
                    **provenance,
                    start_address=str(start),
                    end_address=str(end),
                    network=obj.get("network"),
                    name=obj.get("name") or obj.get("comment"),
                    member=_member_name(obj.get("member")),
                    object_ref=obj.get("_ref"),
                )
            )
        return ranges

    def get_leases(self) -> list[NormalizedDhcpLease]:
        provenance = self._provenance()
        leases: list[NormalizedDhcpLease] = []
        for obj in self._read(_WAPI_LEASE):
            address = obj.get("address")
            if not address:
                continue
            binding = str(obj.get("binding_state", "")).upper()
            leases.append(
                NormalizedDhcpLease(
                    **provenance,
                    ip_address=str(address),
                    state=_LEASE_STATE_MAP.get(binding, DhcpLeaseState.OTHER),
                    mac_address=obj.get("hardware") or None,
                    hostname=obj.get("client_hostname") or None,
                    network=obj.get("network"),
                    starts_at=_epoch_to_dt(obj.get("starts")),
                    ends_at=_epoch_to_dt(obj.get("ends")),
                    object_ref=obj.get("_ref"),
                )
            )
        return leases

    def add_range(self, dhcp_range: NormalizedDhcpRange) -> ChangeRequestDraft:
        body = (
            ("start_addr", str(dhcp_range.start_address)),
            ("end_addr", str(dhcp_range.end_address)),
        )
        return ChangeRequestDraft(
            verb=WapiVerb.CREATE,
            wapi_object=_WAPI_RANGE,
            body=body,
            summary=f"add DHCP range {dhcp_range.start_address}-{dhcp_range.end_address}",
            inverse=ChangeRequestDraft(
                verb=WapiVerb.DELETE,
                wapi_object=_WAPI_RANGE,
                summary="delete the newly-added DHCP range",
            ),
        )

    def delete_range(
        self, object_ref: str, current: NormalizedDhcpRange | None = None
    ) -> ChangeRequestDraft:
        # Re-creating the deleted range needs its full pre-image; otherwise the
        # delete is non-reversible and we emit no misleading draft (ADR-0022 §3).
        if current is not None:
            inverse = ChangeRequestDraft(
                verb=WapiVerb.CREATE,
                wapi_object=_WAPI_RANGE,
                body=(
                    ("start_addr", str(current.start_address)),
                    ("end_addr", str(current.end_address)),
                ),
                summary=f"re-create the deleted DHCP range "
                f"{current.start_address}-{current.end_address}",
            )
            summary = (
                f"delete DHCP range {current.start_address}-{current.end_address}"
            )
        else:
            inverse = None
            summary = (
                f"delete DHCP range {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=WapiVerb.DELETE,
            wapi_object=_WAPI_RANGE,
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


class InfobloxDdiIpam(_InfobloxCapability, DdiIpamCapability):
    """``DDI_IPAM``: read networks; mutations produce ChangeRequestDrafts."""

    def get_networks(self) -> list[NormalizedNetwork]:
        provenance = self._provenance()
        networks: list[NormalizedNetwork] = []
        for obj in self._read(_WAPI_NETWORK):
            cidr = obj.get("network")
            if not cidr:
                continue
            networks.append(
                NormalizedNetwork(
                    **provenance,
                    network=str(cidr),
                    comment=obj.get("comment"),
                    network_view=obj.get("network_view"),
                    utilization_percent=_utilization(obj.get("utilization")),
                    object_ref=obj.get("_ref"),
                )
            )
        return networks

    def get_next_available_ip(self, network: str) -> str:
        # Resolve the network's WAPI _ref by its CIDR, then call the appliance's
        # next_available_ip function on it (ADR-0022 §2 read interface).
        ref: str | None = None
        for obj in self._read(_WAPI_NETWORK, {"network": network}):
            if str(obj.get("network")) == network and obj.get("_ref"):
                ref = str(obj["_ref"])
                break
        if ref is None:
            raise PluginError(f"infoblox: no such network {network!r} in IPAM")
        result = self._client.get_function(ref, "next_available_ip", {"num": 1})
        ips = result.get("ips")
        if not isinstance(ips, list) or not ips:
            raise PluginError(
                f"infoblox: next_available_ip returned no address for {network!r}"
            )
        return str(ips[0])

    def add_network(self, network: NormalizedNetwork) -> ChangeRequestDraft:
        body: tuple[tuple[str, str], ...] = (("network", str(network.network)),)
        if network.comment:
            body = (*body, ("comment", network.comment))
        return ChangeRequestDraft(
            verb=WapiVerb.CREATE,
            wapi_object=_WAPI_NETWORK,
            body=body,
            summary=f"add network {network.network}",
            inverse=ChangeRequestDraft(
                verb=WapiVerb.DELETE,
                wapi_object=_WAPI_NETWORK,
                summary=f"delete the newly-added network {network.network}",
            ),
        )

    def delete_network(
        self, object_ref: str, current: NormalizedNetwork | None = None
    ) -> ChangeRequestDraft:
        # Re-creating the deleted network needs its full pre-image; otherwise the
        # delete is non-reversible and we emit no misleading draft (ADR-0022 §3).
        if current is not None:
            body: tuple[tuple[str, str], ...] = (("network", str(current.network)),)
            if current.comment:
                body = (*body, ("comment", current.comment))
            inverse = ChangeRequestDraft(
                verb=WapiVerb.CREATE,
                wapi_object=_WAPI_NETWORK,
                body=body,
                summary=f"re-create the deleted network {current.network}",
            )
            summary = f"delete network {current.network}"
        else:
            inverse = None
            summary = (
                f"delete network {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=WapiVerb.DELETE,
            wapi_object=_WAPI_NETWORK,
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


# ---------------------------------------------------------------------------
# Parsing helpers (no secrets ever flow through these)
# ---------------------------------------------------------------------------


def _attrs(obj: Mapping[str, Any], keys: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Flatten selected WAPI fields into a secret-free (key, value) tuple list."""
    out: list[tuple[str, str]] = []
    for key in keys:
        value = obj.get(key)
        if value is None:
            continue
        out.append((key, str(value)))
    return tuple(out)


def _dns_value_field(record_type: DnsRecordType) -> str:
    """WAPI field name holding the record's value, per record type."""
    return {
        DnsRecordType.A: "ipv4addr",
        DnsRecordType.AAAA: "ipv6addr",
        DnsRecordType.CNAME: "canonical",
        DnsRecordType.PTR: "ptrdname",
        DnsRecordType.MX: "mail_exchanger",
        DnsRecordType.TXT: "text",
    }.get(record_type, "value")


def _dns_value(record_type: DnsRecordType, obj: Mapping[str, Any]) -> str | None:
    """Extract the record value from a WAPI DNS object by its typed field."""
    value = obj.get(_dns_value_field(record_type))
    return None if value is None else str(value)


def _member_name(member: Any) -> str | None:
    """A WAPI ``member`` field may be a string or an object with ``name``."""
    if isinstance(member, Mapping):
        name = member.get("name")
        return str(name) if name else None
    return str(member) if member else None


def _utilization(value: Any) -> float | None:
    """WAPI ``utilization`` is in per-mille (0–1000); map to a 0–100 percent."""
    if not isinstance(value, (int, float)):
        return None
    return round(float(value) / 10.0, 2)


class InfobloxPlugin(VendorPlugin):
    """Infoblox (``vendor_id="infoblox"``) — first API-based DDI plugin (ADR-0022).

    Declares the four WAPI-backed capabilities: ``DISCOVERY_API`` (first
    API-based discovery) plus ``DDI_DNS``/``DDI_DHCP``/``DDI_IPAM``. No
    SSH/SNMP/config-write capabilities — Infoblox is a DDI appliance, the
    partial-capability model ADR-0006 intends.
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Infoblox"
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
            Capability.DISCOVERY_API: InfobloxDiscoveryApi,
            Capability.DDI_DNS: InfobloxDdiDns,
            Capability.DDI_DHCP: InfobloxDdiDhcp,
            Capability.DDI_IPAM: InfobloxDdiIpam,
        }
