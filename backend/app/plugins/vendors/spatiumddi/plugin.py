"""SpatiumDDI plugin: REST-backed DDI + API-discovery capabilities (ADR-0024).

The platform's second **API-based** vendor plugin (after Infoblox): all four
capabilities (``DISCOVERY_API`` + ``DDI_DNS``/``DDI_DHCP``/``DDI_IPAM``) read
through a single :class:`~app.plugins.vendors.spatiumddi.client.SpatiumClient`
over the SpatiumDDI REST API. Every REST response is recorded verbatim via
``PluginCapability._record_raw`` before parsing (ADR-0006 §3 raw-first), so each
normalized row is re-derivable.

Mutations never write: each ``add_*``/``modify_*``/``delete_*`` method returns a
vendor-neutral :class:`~app.plugins.base.ChangeRequestDraft` carrying the
intended verb/resource/body and an inverse-change rollback spec (ADR-0024 §3).
Only the Automation Agent turns a draft into an actual write, and only for an
``approved`` ChangeRequest — so the capability layer has no write path that skips
the CR spine.

**Soft-delete inverse (ADR-0024 §3).** SpatiumDDI ``DELETE`` is a *soft* delete
for the six ``SOFT_DELETE_RESOURCE_TYPES`` (``dns_record``, ``dns_zone``,
``subnet``, ``dhcp_scope``, ``ip_block``, ``ip_space``): the row is moved to a
30-day trash and the rollback inverse is a **RESTORE** (``POST
/admin/trash/{type}/{row_id}/restore``), *not* a re-create — re-creating would
orphan the trash row and lose the original id/batch identity. Hard-delete
resources (``dhcp_pool``, ``dhcp_static``) have no trash row, so their inverse is
a **re-create**. The plugin selects the inverse by resource type; the ``resource``
strings are chosen to match the ``SOFT_DELETE_RESOURCE_TYPES`` trash vocabulary so
the Automation executor can route a restore by ``(resource, object_ref)``.

**Async bridge.** :class:`SpatiumClient` is async (SpatiumDDI is an HTTP
backend); the ADR-0022 capability interface is synchronous (the discovery runner
and conformance suite call read methods synchronously). Each capability runs the
client coroutine on a private event loop via :meth:`_run` — never reusing a loop
the caller may already own, so there is no nested-loop hazard.
"""

from __future__ import annotations

import json
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, ClassVar, TypeVar
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
from app.plugins.vendors.spatiumddi.client import SpatiumClient
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
    "SpatiumContext",
    "SpatiumDdiDhcp",
    "SpatiumDdiDns",
    "SpatiumDdiIpam",
    "SpatiumDiscoveryApi",
    "SpatiumddiPlugin",
]

VENDOR_ID = "spatiumddi"

_T = TypeVar("_T")

# -- resource-string vocabulary (ADR-0024 §3) --------------------------------
# These strings are the draft ``resource`` values. The six soft-delete types are
# spelled exactly as SpatiumDDI's SOFT_DELETE_RESOURCE_TYPES / trash ``{type}``
# path segment, so the Automation executor can route a restore by resource name.
RESOURCE_DNS_RECORD = "dns_record"
RESOURCE_DNS_ZONE = "dns_zone"
RESOURCE_SUBNET = "subnet"
RESOURCE_DHCP_SCOPE = "dhcp_scope"
RESOURCE_IP_BLOCK = "ip_block"
RESOURCE_IP_SPACE = "ip_space"
#: Hard-delete resources (no trash row; inverse = re-create, ADR-0024 §3).
RESOURCE_DHCP_POOL = "dhcp_pool"
RESOURCE_DHCP_STATIC = "dhcp_static"

#: The six types whose delete is soft and whose delete-inverse is a RESTORE.
SOFT_DELETE_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        RESOURCE_IP_SPACE,
        RESOURCE_IP_BLOCK,
        RESOURCE_SUBNET,
        RESOURCE_DNS_ZONE,
        RESOURCE_DNS_RECORD,
        RESOURCE_DHCP_SCOPE,
    }
)

#: SpatiumDDI record_type string -> normalized DnsRecordType. Types outside the
#: lowest-common-denominator enum (SVCB/HTTPS/DNAME/ALIAS/LUA/…) map to OTHER;
#: the verbatim type string is preserved in mutation bodies (ADR-0006 negative).
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

#: SpatiumDDI lease ``state`` -> normalized DhcpLeaseState.
_LEASE_STATE_MAP: Mapping[str, DhcpLeaseState] = {
    "active": DhcpLeaseState.ACTIVE,
    "free": DhcpLeaseState.FREE,
    "expired": DhcpLeaseState.EXPIRED,
    "abandoned": DhcpLeaseState.ABANDONED,
    "offered": DhcpLeaseState.OFFERED,
    "static": DhcpLeaseState.STATIC,
    "backup": DhcpLeaseState.BACKUP,
}


@dataclass(frozen=True)
class SpatiumContext:
    """Non-secret SpatiumDDI addressing context for a device session.

    SpatiumDDI resources are addressed by parent ids (DNS is group→zone→record,
    DHCP is group→scope→pool, IPAM is space→block→subnet). The no-arg read
    methods of the ADR-0022 interface need a starting point, so the device's
    connection config supplies these ids. All values are non-secret server ids.

    ``dns_group_ids`` / ``dhcp_group_ids`` scope the DNS/DHCP fan-out; an empty
    tuple means "enumerate from the server roots" (``get_dns_groups`` /
    ``get_dhcp_scopes`` discovery). ``lease_server_ids`` lists the DHCP servers
    whose live leases :meth:`SpatiumDdiDhcp.get_leases` reads (no server
    enumeration endpoint exists server-side). ``space_id``/``block_id`` are the
    default IPAM parents for ``add_network``.
    """

    dns_group_ids: tuple[str, ...] = ()
    dhcp_group_ids: tuple[str, ...] = ()
    lease_server_ids: tuple[str, ...] = ()
    space_id: str | None = None
    block_id: str | None = None
    #: A scope id used when drafting an ``add_range`` (PoolCreate is scope-child).
    scope_id: str | None = None
    #: A zone id used when drafting DNS record mutations (RecordCreate/Update/Delete
    #: require the full path /dns/groups/{group_id}/zones/{zone_id}/records).
    #: When set, ``_record_parents`` embeds it in every DNS mutation draft body so
    #: the executor can reconstruct the URL without an extra zone-lookup round-trip.
    zone_id: str | None = None
    _extra: tuple[tuple[str, str], ...] = field(default=(), repr=False)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _SpatiumCapability(PluginCapability):
    """Shared base: holds the async client, device context, and addressing ids.

    :meth:`_run` bridges the async client to the synchronous capability
    interface; :meth:`_record_json` records each REST payload verbatim (ADR-0024
    §2 raw-first) before parsing into normalized models.
    """

    def __init__(
        self,
        client: SpatiumClient,
        device_id: UUID,
        context: SpatiumContext | None = None,
    ) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id
        self._ctx = context or SpatiumContext()

    def _run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        """Run *coro* on the shared :class:`SpatiumClient` private event loop.

        Loop ownership lives on the client (one pool → one loop) so multiple
        capability classes over the same client never bind httpx to two loops
        (H9). The production async-executor path calls the client directly.
        """
        return self._client.run_sync(coro)

    def close(self) -> None:
        """Close the shared client loop + httpx pool (idempotent).

        Safe to call from any capability over the same client; subsequent
        siblings see a closed client and should not issue further work.
        """
        self._client.close_sync()

    def _record_json(self, command: str, payload: Any) -> None:
        """Record a REST payload verbatim (canonical JSON) before parsing."""
        self._record_raw(command, json.dumps(payload, default=str, sort_keys=True))

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }


class SpatiumDiscoveryApi(_SpatiumCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: IPAM subnets + DNS zones + DHCP scopes -> objects.

    Read-only fan-out over the read endpoints (ADR-0024 §1 DISCOVERY_API): no
    single discovery endpoint exists server-side, so the pass composes spaces +
    blocks + subnets, group→zones, and group→scopes into
    :class:`NormalizedDiscoveredObject` records.
    """

    def discover(self) -> list[NormalizedDiscoveredObject]:
        return self._run(self._discover())

    async def _discover(self) -> list[NormalizedDiscoveredObject]:
        provenance = self._provenance()
        objects: list[NormalizedDiscoveredObject] = []

        subnets = await self._client.get_subnets()
        self._record_json("GET /ipam/subnets", subnets)
        for subnet in subnets:
            cidr = subnet.get("network")
            if not cidr:
                continue
            objects.append(
                NormalizedDiscoveredObject(
                    **provenance,
                    kind=DiscoveredObjectKind.NETWORK,
                    identifier=str(cidr),
                    display_name=subnet.get("name"),
                    object_ref=_opt_str(subnet.get("id")),
                    attributes=_attrs(subnet, ("space_id", "block_id", "status")),
                )
            )

        for group_id in await self._dns_group_ids():
            zones = await self._client.get_zones(group_id)
            self._record_json(f"GET /dns/groups/{group_id}/zones", zones)
            for zone in zones:
                name = zone.get("name")
                if not name:
                    continue
                objects.append(
                    NormalizedDiscoveredObject(
                        **provenance,
                        kind=DiscoveredObjectKind.DNS_ZONE,
                        identifier=str(name),
                        display_name=zone.get("comment"),
                        object_ref=_opt_str(zone.get("id")),
                        attributes=_attrs(zone, ("group_id", "zone_type", "kind")),
                    )
                )

        # DHCP scope fan-out (DDI_DHCP capability context, ADR-0024 §1).
        # Uses the same dhcp_group_ids already wired for SpatiumDdiDhcp so the
        # discovery pass surfaces DHCP scopes alongside subnets + DNS zones.
        # DHCP scopes map to DiscoveredObjectKind.OTHER (no DHCP_SCOPE member in
        # the shared enum); the raw payload is recorded verbatim before parsing.
        for dhcp_group_id in self._ctx.dhcp_group_ids:
            scopes = await self._client.get_dhcp_scopes(dhcp_group_id)
            self._record_json(f"GET /dhcp/server-groups/{dhcp_group_id}/scopes", scopes)
            for scope in scopes:
                scope_name = scope.get("name") or scope.get("network")
                scope_ref = _opt_str(scope.get("id"))
                if not scope_ref and not scope_name:
                    continue
                objects.append(
                    NormalizedDiscoveredObject(
                        **provenance,
                        kind=DiscoveredObjectKind.OTHER,
                        identifier=str(scope_ref or scope_name),
                        display_name=str(scope_name) if scope_name else None,
                        object_ref=scope_ref,
                        attributes=_attrs(scope, ("group_id", "network", "status")),
                    )
                )

        return objects

    async def _dns_group_ids(self) -> Sequence[str]:
        if self._ctx.dns_group_ids:
            return self._ctx.dns_group_ids
        groups = await self._client.get_dns_groups()
        self._record_json("GET /dns/groups", groups)
        return [str(g["id"]) for g in groups if g.get("id")]


class SpatiumDdiDns(_SpatiumCapability, DdiDnsCapability):
    """``DDI_DNS``: read zones/records; mutations produce ChangeRequestDrafts.

    Reads fan out across the configured DNS groups (group→zone→record). A DNS
    record's full key is the triple ``(group_id, zone_id, record_id)``; mutation
    drafts pin ``record_id`` as ``object_ref`` and carry ``group_id``/``zone_id``
    in the body so the executor can rebuild the path (ADR-0024 §1).
    """

    def get_zones(self) -> list[str]:
        return self._run(self._get_zones())

    async def _get_zones(self) -> list[str]:
        zones: list[str] = []
        for group_id in await self._dns_group_ids():
            payload = await self._client.get_zones(group_id)
            self._record_json(f"GET /dns/groups/{group_id}/zones", payload)
            for zone in payload:
                name = zone.get("name")
                if name:
                    zones.append(str(name))
        return zones

    def get_records(self, zone: str | None = None) -> list[NormalizedDnsRecord]:
        return self._run(self._get_records(zone))

    async def _get_records(self, zone: str | None) -> list[NormalizedDnsRecord]:
        provenance = self._provenance()
        records: list[NormalizedDnsRecord] = []
        for group_id in await self._dns_group_ids():
            zones = await self._client.get_zones(group_id)
            self._record_json(f"GET /dns/groups/{group_id}/zones", zones)
            for zone_obj in zones:
                zone_id = _opt_str(zone_obj.get("id"))
                zone_name = zone_obj.get("name")
                if zone_id is None:
                    continue
                if zone is not None and zone_name != zone:
                    continue
                payload = await self._client.get_records(group_id, zone_id)
                self._record_json(f"GET /dns/groups/{group_id}/zones/{zone_id}/records", payload)
                zone_label = str(zone_name) if zone_name else None
                for obj in payload:
                    record = _normalize_record(obj, zone_label, provenance)
                    if record is not None:
                        records.append(record)
        return records

    async def _dns_group_ids(self) -> Sequence[str]:
        if self._ctx.dns_group_ids:
            return self._ctx.dns_group_ids
        groups = await self._client.get_dns_groups()
        self._record_json("GET /dns/groups", groups)
        return [str(g["id"]) for g in groups if g.get("id")]

    def add_record(self, record: NormalizedDnsRecord) -> ChangeRequestDraft:
        group_id, zone_id = self._record_parents(record.zone)
        rtype = record.record_type.value.upper()
        body = _record_body(group_id, zone_id, record, rtype)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource=RESOURCE_DNS_RECORD,
            body=body,
            summary=f"add {rtype} record {record.name} in zone {record.zone or zone_id}",
            # Inverse of a create is a (soft) delete of the new record; the new id
            # is unknown until the write commits, so object_ref stays None and the
            # executor pins it post-create. A soft delete is itself restore-able.
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource=RESOURCE_DNS_RECORD,
                object_ref=None,
                body=_parent_body(group_id, zone_id),
                summary=f"soft-delete the newly-added {rtype} record {record.name}",
            ),
        )

    def modify_record(
        self,
        object_ref: str,
        changes: NormalizedDnsRecord,
        current: NormalizedDnsRecord | None = None,
    ) -> ChangeRequestDraft:
        group_id, zone_id = self._record_parents(changes.zone)
        rtype = changes.record_type.value.upper()
        body = _record_update_body(group_id, zone_id, changes)
        # The inverse can only restore prior values with the pre-image (record_type
        # is immutable server-side, so only the value/ttl fields roll back).
        if current is not None:
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.UPDATE,
                resource=RESOURCE_DNS_RECORD,
                object_ref=object_ref,
                body=_record_update_body(group_id, zone_id, current),
                summary=f"restore prior value of {current.record_type.value.upper()} "
                f"record {current.name}",
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
            resource=RESOURCE_DNS_RECORD,
            object_ref=object_ref,
            body=body,
            summary=summary,
            inverse=inverse,
        )

    def delete_record(
        self, object_ref: str, current: NormalizedDnsRecord | None = None
    ) -> ChangeRequestDraft:
        group_id, zone_id = self._record_parents(current.zone if current else None)
        # dns_record is a SOFT-delete type: the inverse is a RESTORE from trash by
        # (type, row_id) — NOT a re-create (ADR-0024 §3). The pre-image is not
        # required for the restore inverse (the trash holds the row), so the
        # rollback is always available.
        inverse = _restore_inverse(RESOURCE_DNS_RECORD, object_ref)
        if current is not None:
            summary = f"soft-delete {current.record_type.value.upper()} record {current.name}"
        else:
            summary = f"soft-delete DNS record {object_ref}"
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource=RESOURCE_DNS_RECORD,
            object_ref=object_ref,
            body=_parent_body(group_id, zone_id),
            summary=summary,
            inverse=inverse,
        )

    def _record_parents(self, zone: str | None) -> tuple[str, str]:
        """Return ``(group_id, zone_id)`` for embedding in a DNS mutation draft body.

        ``group_id`` is taken from the single configured DNS group when exactly one
        is present. ``zone_id`` comes from :attr:`SpatiumContext.zone_id` — the
        operator must supply it in the device connection config so the executor can
        construct the full REST path
        ``/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}`` (ADR-0024 §1).
        The ``zone`` argument (a zone name from :class:`NormalizedDnsRecord`) is
        kept for future zone-name→id caching; the id takes precedence when present.

        :raises PluginError: if either parent id is unresolved — emitting a draft
            with a missing ``group_id`` or ``zone_id`` would push a structurally
            invalid body into the CR approval/execution pipeline (ADR-0024 §1).
        """
        group_id = self._ctx.dns_group_ids[0] if len(self._ctx.dns_group_ids) == 1 else None
        zone_id = self._ctx.zone_id
        if group_id is None:
            raise PluginError(
                "spatiumddi: cannot build DNS mutation draft — dns_group_ids must contain "
                "exactly one group id in SpatiumContext (got "
                f"{len(self._ctx.dns_group_ids)}); set it in the device connection config"
            )
        if zone_id is None:
            raise PluginError(
                "spatiumddi: cannot build DNS mutation draft — SpatiumContext.zone_id is "
                f"unset (zone={zone!r}); set zone_id in the device connection config so "
                "the executor can construct /dns/groups/{group_id}/zones/{zone_id}/records"
            )
        return group_id, zone_id


class SpatiumDdiDhcp(_SpatiumCapability, DdiDhcpCapability):
    """``DDI_DHCP``: read pools (==ranges) + leases; mutations produce drafts.

    SpatiumDDI splits the Infoblox "range" into pools (dynamic, scope-child) and
    statics (reservations); ``get_ranges``/``add_range``/``delete_range`` map onto
    **pools** (ADR-0024 §1). Pools are HARD-deleted (no trash), so a delete
    inverse is a **re-create** — contrast the soft-delete restore used by the
    DNS/IPAM types.
    """

    def get_ranges(self) -> list[NormalizedDhcpRange]:
        return self._run(self._get_ranges())

    async def _get_ranges(self) -> list[NormalizedDhcpRange]:
        provenance = self._provenance()
        ranges: list[NormalizedDhcpRange] = []
        for scope_id in await self._scope_ids():
            payload = await self._client.get_pools(scope_id)
            self._record_json(f"GET /dhcp/scopes/{scope_id}/pools", payload)
            for obj in payload:
                start = obj.get("start_ip")
                end = obj.get("end_ip")
                if not start or not end:
                    continue
                ranges.append(
                    NormalizedDhcpRange(
                        **provenance,
                        start_address=ip_address(str(start)),
                        end_address=ip_address(str(end)),
                        name=obj.get("name"),
                        object_ref=_opt_str(obj.get("id")),
                    )
                )
        return ranges

    def get_leases(self) -> list[NormalizedDhcpLease]:
        return self._run(self._get_leases())

    async def _get_leases(self) -> list[NormalizedDhcpLease]:
        provenance = self._provenance()
        leases: list[NormalizedDhcpLease] = []
        for server_id in self._ctx.lease_server_ids:
            payload = await self._client.get_leases(server_id)
            self._record_json(f"GET /dhcp/servers/{server_id}/leases", payload)
            for obj in payload:
                address = obj.get("ip_address")
                if not address:
                    continue
                state = str(obj.get("state", "")).lower()
                leases.append(
                    NormalizedDhcpLease(
                        **provenance,
                        ip_address=ip_address(str(address)),
                        state=_LEASE_STATE_MAP.get(state, DhcpLeaseState.OTHER),
                        mac_address=obj.get("mac_address") or None,
                        hostname=obj.get("hostname") or None,
                        starts_at=_parse_dt(obj.get("starts_at")),
                        ends_at=_parse_dt(obj.get("ends_at") or obj.get("expires_at")),
                        object_ref=_opt_str(obj.get("id")),
                    )
                )
        return leases

    async def _scope_ids(self) -> list[str]:
        if self._ctx.scope_id is not None:
            return [self._ctx.scope_id]
        scope_ids: list[str] = []
        for group_id in self._ctx.dhcp_group_ids:
            scopes = await self._client.get_dhcp_scopes(group_id)
            self._record_json(f"GET /dhcp/server-groups/{group_id}/scopes", scopes)
            scope_ids.extend(str(s["id"]) for s in scopes if s.get("id"))
        return scope_ids

    def add_range(self, dhcp_range: NormalizedDhcpRange) -> ChangeRequestDraft:
        scope_id = self._ctx.scope_id
        body = _range_body(scope_id, dhcp_range)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource=RESOURCE_DHCP_POOL,
            body=body,
            summary=f"add DHCP pool {dhcp_range.start_address}-{dhcp_range.end_address}",
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource=RESOURCE_DHCP_POOL,
                object_ref=None,
                summary="hard-delete the newly-added DHCP pool",
            ),
        )

    def delete_range(
        self, object_ref: str, current: NormalizedDhcpRange | None = None
    ) -> ChangeRequestDraft:
        # dhcp_pool is a HARD-delete type (no trash row): the inverse is a
        # RE-CREATE from the full pre-image — NOT a restore (ADR-0024 §3). Without
        # the pre-image the delete is non-reversible and no misleading draft is set.
        if current is not None:
            inverse: ChangeRequestDraft | None = ChangeRequestDraft(
                verb=ChangeVerb.CREATE,
                resource=RESOURCE_DHCP_POOL,
                body=_range_body(self._ctx.scope_id, current),
                summary=f"re-create the deleted DHCP pool "
                f"{current.start_address}-{current.end_address}",
            )
            summary = f"delete DHCP pool {current.start_address}-{current.end_address}"
        else:
            inverse = None
            summary = (
                f"delete DHCP pool {object_ref} "
                "(non-reversible — no pre-image captured at draft time)"
            )
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource=RESOURCE_DHCP_POOL,
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


class SpatiumDdiIpam(_SpatiumCapability, DdiIpamCapability):
    """``DDI_IPAM``: read subnets (==networks); mutations produce drafts.

    ``get_next_available_ip`` uses the read-only server preview
    (``GET .../next-ip-preview``) — we never compute free space client-side
    (ADR-0024 §1, alternative 1). The committing allocator (``POST .../next``) is
    a separate write surfaced only through a draft. Subnets are SOFT-deleted, so a
    delete inverse is a **RESTORE** from trash.
    """

    def get_networks(self) -> list[NormalizedNetwork]:
        return self._run(self._get_networks())

    async def _get_networks(self) -> list[NormalizedNetwork]:
        provenance = self._provenance()
        networks: list[NormalizedNetwork] = []
        payload = await self._client.get_subnets()
        self._record_json("GET /ipam/subnets", payload)
        for obj in payload:
            cidr = obj.get("network")
            if not cidr:
                continue
            networks.append(
                NormalizedNetwork(
                    **provenance,
                    network=ip_network(str(cidr), strict=False),
                    comment=obj.get("name"),
                    utilization_percent=_utilization(obj.get("utilization_percent")),
                    object_ref=_opt_str(obj.get("id")),
                )
            )
        return networks

    def get_next_available_ip(self, network: str) -> str:
        return self._run(self._next_ip(network))

    async def _next_ip(self, network: str) -> str:
        # Resolve the subnet id by its CIDR, then call the read-only preview. No
        # client-side free-space computation (ADR-0024 alternative 1).
        subnet_id: str | None = None
        subnets = await self._client.get_subnets()
        self._record_json("GET /ipam/subnets", subnets)
        for obj in subnets:
            if str(obj.get("network")) == network and obj.get("id"):
                subnet_id = str(obj["id"])
                break
        if subnet_id is None:
            raise PluginError(f"spatiumddi: no such subnet {network!r} in IPAM")
        preview = await self._client.next_ip_preview(subnet_id)
        self._record_json(f"GET /ipam/subnets/{subnet_id}/next-ip-preview", preview)
        address = preview.get("address")
        if not address:
            raise PluginError(
                f"spatiumddi: next-ip-preview returned no free address for {network!r}"
            )
        return str(address)

    def add_network(self, network: NormalizedNetwork) -> ChangeRequestDraft:
        body = _subnet_body(self._ctx, network)
        return ChangeRequestDraft(
            verb=ChangeVerb.CREATE,
            resource=RESOURCE_SUBNET,
            body=body,
            summary=f"add subnet {network.network}",
            # Inverse of a create is a (soft) delete; the new id is unknown until
            # the write commits, so the executor pins object_ref post-create.
            inverse=ChangeRequestDraft(
                verb=ChangeVerb.DELETE,
                resource=RESOURCE_SUBNET,
                object_ref=None,
                summary=f"soft-delete the newly-added subnet {network.network}",
            ),
        )

    def delete_network(
        self, object_ref: str, current: NormalizedNetwork | None = None
    ) -> ChangeRequestDraft:
        # subnet is a SOFT-delete type: the inverse is a RESTORE from trash by
        # (type, row_id), NOT a re-create (ADR-0024 §3). The pre-image is not
        # required for the restore, so the rollback is always available.
        inverse = _restore_inverse(RESOURCE_SUBNET, object_ref)
        if current is not None:
            summary = f"soft-delete subnet {current.network}"
        else:
            summary = f"soft-delete subnet {object_ref}"
        return ChangeRequestDraft(
            verb=ChangeVerb.DELETE,
            resource=RESOURCE_SUBNET,
            object_ref=object_ref,
            summary=summary,
            inverse=inverse,
        )


# ---------------------------------------------------------------------------
# Parsing / draft-body helpers (no secrets ever flow through these)
# ---------------------------------------------------------------------------


def _restore_inverse(resource: str, object_ref: str) -> ChangeRequestDraft:
    """The delete-inverse of a SOFT-delete type: a RESTORE, not a re-create.

    ``resource`` is one of :data:`SOFT_DELETE_RESOURCE_TYPES`; the executor routes
    a ``POST /admin/trash/{resource}/{object_ref}/restore`` (ADR-0024 §3).

    **Executor routing convention.** Because :class:`~app.plugins.base.ChangeVerb`
    has no ``RESTORE`` value, this draft uses ``verb=CREATE`` together with a
    sentinel body entry ``("restore", "true")`` and a non-``None`` ``object_ref``.
    The :class:`~app.agents.automation.executors.DdiChangeExecutor` implementation
    MUST distinguish a restore from a plain create by checking for this sentinel
    **before** dispatching:

    .. code-block:: python

        body_dict = dict(draft.body)
        if draft.object_ref and body_dict.get("restore") == "true":
            # route to POST /admin/trash/{resource}/{object_ref}/restore
        else:
            # route to POST /{resource} (plain create)

    A plain create never has ``object_ref`` set (it is ``None`` until the write
    commits); a restore always targets an existing id.  Both conditions together
    uniquely identify a restore draft.
    """
    assert resource in SOFT_DELETE_RESOURCE_TYPES  # noqa: S101 — invariant guard
    return ChangeRequestDraft(
        verb=ChangeVerb.CREATE,
        resource=resource,
        object_ref=object_ref,
        body=(("restore", "true"),),
        summary=f"restore the soft-deleted {resource} {object_ref} from trash",
    )


def _normalize_record(
    obj: Mapping[str, Any], zone_name: str | None, provenance: Mapping[str, Any]
) -> NormalizedDnsRecord | None:
    name = obj.get("name")
    value = obj.get("value")
    if not name or not value:
        return None
    rtype = str(obj.get("record_type", "")).upper()
    return NormalizedDnsRecord(
        **provenance,
        name=str(name),
        record_type=_DNS_TYPE_MAP.get(rtype, DnsRecordType.OTHER),
        value=str(value),
        ttl=obj.get("ttl"),
        zone=zone_name or _opt_str(obj.get("zone_id")),
        object_ref=_opt_str(obj.get("id")),
    )


def _parent_body(group_id: str | None, zone_id: str | None) -> tuple[tuple[str, str], ...]:
    """Carry the (group_id, zone_id) path parents in the draft body, when known."""
    out: list[tuple[str, str]] = []
    if group_id is not None:
        out.append(("group_id", group_id))
    if zone_id is not None:
        out.append(("zone_id", zone_id))
    return tuple(out)


def _record_body(
    group_id: str | None,
    zone_id: str | None,
    record: NormalizedDnsRecord,
    rtype: str,
) -> tuple[tuple[str, str], ...]:
    """RecordCreate body. ``record_type`` is the verbatim SpatiumDDI type string."""
    body = [
        *_parent_body(group_id, zone_id),
        ("name", record.name),
        ("record_type", rtype),
        ("value", record.value),
    ]
    if record.ttl is not None:
        body.append(("ttl", str(record.ttl)))
    return tuple(body)


def _record_update_body(
    group_id: str | None, zone_id: str | None, record: NormalizedDnsRecord
) -> tuple[tuple[str, str], ...]:
    """RecordUpdate body (``record_type`` is immutable server-side; not sent)."""
    body = [*_parent_body(group_id, zone_id), ("value", record.value)]
    if record.ttl is not None:
        body.append(("ttl", str(record.ttl)))
    return tuple(body)


def _range_body(
    scope_id: str | None, dhcp_range: NormalizedDhcpRange
) -> tuple[tuple[str, str], ...]:
    """PoolCreate body (pool == Infoblox range; scope-child)."""
    body: list[tuple[str, str]] = []
    if scope_id is not None:
        body.append(("scope_id", scope_id))
    if dhcp_range.name:
        body.append(("name", dhcp_range.name))
    body.append(("start_ip", str(dhcp_range.start_address)))
    body.append(("end_ip", str(dhcp_range.end_address)))
    body.append(("pool_type", "dynamic"))
    return tuple(body)


def _subnet_body(ctx: SpatiumContext, network: NormalizedNetwork) -> tuple[tuple[str, str], ...]:
    """SubnetCreate body (space_id + block_id + network, ADR-0024 §1)."""
    body: list[tuple[str, str]] = []
    if ctx.space_id is not None:
        body.append(("space_id", ctx.space_id))
    if ctx.block_id is not None:
        body.append(("block_id", ctx.block_id))
    body.append(("network", str(network.network)))
    if network.comment:
        body.append(("name", network.comment))
    return tuple(body)


def _attrs(obj: Mapping[str, Any], keys: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Flatten selected fields into a secret-free (key, value) tuple list."""
    out: list[tuple[str, str]] = []
    for key in keys:
        value = obj.get(key)
        if value is None:
            continue
        out.append((key, str(value)))
    return tuple(out)


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _utilization(value: Any) -> float | None:
    """SpatiumDDI ``utilization_percent`` is already a 0–100 percentage."""
    if not isinstance(value, (int, float)):
        return None
    pct = round(float(value), 2)
    if pct < 0 or pct > 100:
        return None
    return pct


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp (SpatiumDDI lease times) to aware UTC."""
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


class SpatiumddiPlugin(VendorPlugin):
    """SpatiumDDI (``vendor_id="spatiumddi"``) — self-hostable DDI plugin (ADR-0024).

    Declares the four REST-backed capabilities: ``DISCOVERY_API`` plus
    ``DDI_DNS``/``DDI_DHCP``/``DDI_IPAM``. No SSH/SNMP/config-write capabilities —
    SpatiumDDI is a DDI backend, the partial-capability model ADR-0006 intends.
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "SpatiumDDI"
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
            Capability.DISCOVERY_API: SpatiumDiscoveryApi,
            Capability.DDI_DNS: SpatiumDdiDns,
            Capability.DDI_DHCP: SpatiumDdiDhcp,
            Capability.DDI_IPAM: SpatiumDdiIpam,
        }
