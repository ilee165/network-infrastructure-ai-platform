"""Unit tests for the spatiumddi plugin (ADR-0024 T4).

httpx is mocked with :class:`httpx.MockTransport` (no respx, no network — D16):
every read test wires the :class:`SpatiumClient` to a fixture-replaying
transport so each capability's read path, the verbatim raw-recording, and the
``source_vendor`` stamping are exercised without a running SpatiumDDI instance.

Mutation tests assert the vendor-neutral :class:`ChangeRequestDraft` shape and
— critically — the soft-vs-hard delete inverse selection (ADR-0024 §3): a
soft-delete type rolls back via RESTORE, a hard-delete pool via re-create. A
mutation must perform **no** HTTP I/O: the mutation tests build the capability
over a transport that fails on any request, proving the draft is data-only.

The only token anywhere in this module is the obviously-fake sentinel
``sddi_FAKE-token-zzz``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.core.errors import PluginError
from app.plugins.base import ChangeVerb
from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials
from app.plugins.vendors.spatiumddi.plugin import (
    RESOURCE_DHCP_POOL,
    RESOURCE_DNS_RECORD,
    RESOURCE_SUBNET,
    SOFT_DELETE_RESOURCE_TYPES,
    VENDOR_ID,
    SpatiumContext,
    SpatiumDdiDhcp,
    SpatiumDdiDns,
    SpatiumDdiIpam,
    SpatiumddiPlugin,
    SpatiumDiscoveryApi,
)
from app.schemas.normalized import (
    DhcpLeaseState,
    DiscoveredObjectKind,
    DnsRecordType,
    NormalizedDhcpRange,
    NormalizedDnsRecord,
    NormalizedNetwork,
)

FIXTURES = Path(__file__).parent / "fixtures" / "spatiumddi"

_GROUP = "11111111-1111-1111-1111-111111111111"
_ZONE = "22222222-2222-2222-2222-222222222222"
_RECORD = "33333333-3333-3333-3333-333333333333"
_SCOPE = "44444444-4444-4444-4444-444444444444"
_POOL = "55555555-5555-5555-5555-555555555555"
_SERVER = "66666666-6666-6666-6666-666666666666"
_SUBNET = "77777777-7777-7777-7777-777777777777"
_DHCP_GROUP = "88888888-8888-8888-8888-888888888888"
_SPACE = "99999999-9999-9999-9999-999999999999"
_BLOCK = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

_FAKE_TOKEN = "sddi_FAKE-token-zzz"  # noqa: S105 — obviously-fake test sentinel
_FAKE_CREDS = SpatiumCredentials(appliance_id="test", token=_FAKE_TOKEN)

_CONTEXT = SpatiumContext(
    dns_group_ids=(_GROUP,),
    dhcp_group_ids=(_DHCP_GROUP,),
    lease_server_ids=(_SERVER,),
    scope_id=_SCOPE,
    space_id=_SPACE,
    block_id=_BLOCK,
)


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _handle(request: httpx.Request) -> httpx.Response:
    path = request.url.path.split("/api/v1", 1)[1]
    if path == "/ipam/subnets":
        body: Any = _load("subnets.json")
    elif path == "/dns/groups":
        body = _load("groups.json")
    elif path.endswith("/records"):
        # Records belong to the example.com zone only; the reverse zone is empty.
        body = _load("records.json") if f"/zones/{_ZONE}/" in path else []
    elif path.endswith("/zones"):
        body = _load("zones.json")
    elif path.endswith("/pools"):
        body = _load("pools.json")
    elif path.endswith("/leases"):
        body = _load("leases.json")
    elif path.endswith("/next-ip-preview"):
        body = _load("next_ip_preview.json")
    else:
        body = []
    return httpx.Response(200, json=body)


def _client(
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
) -> SpatiumClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler or _handle))
    return SpatiumClient(
        base_url="https://sddi.example.com",
        credentials=_FAKE_CREDS,
        client=http,
    )


def _no_io_client() -> SpatiumClient:
    """A client whose transport raises if *any* request is issued.

    Used by mutation tests to prove a mutation method performs no HTTP I/O —
    it must return a draft built from its arguments alone.
    """

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"mutation performed inline I/O: {request.method} {request.url.path}")

    return _client(explode)


# ---------------------------------------------------------------------------
# DISCOVERY_API
# ---------------------------------------------------------------------------


class TestDiscoveryApi:
    def test_discover_returns_subnets_and_zones(self) -> None:
        cap = SpatiumDiscoveryApi(_client(), uuid4(), _CONTEXT)
        objects = cap.discover()
        kinds = {o.kind for o in objects}
        assert DiscoveredObjectKind.NETWORK in kinds
        assert DiscoveredObjectKind.DNS_ZONE in kinds
        net = next(o for o in objects if o.kind is DiscoveredObjectKind.NETWORK)
        assert net.identifier == "10.0.0.0/24"
        assert net.object_ref == _SUBNET
        assert all(o.source_vendor == VENDOR_ID for o in objects)

    def test_discover_records_raw_before_parsing(self) -> None:
        cap = SpatiumDiscoveryApi(_client(), uuid4(), _CONTEXT)
        cap.discover()
        commands = [raw.command for raw in cap.raw_outputs]
        assert "GET /ipam/subnets" in commands
        assert any(c.endswith("/zones") for c in commands)
        assert all(raw.output for raw in cap.raw_outputs)


# ---------------------------------------------------------------------------
# DDI_DNS
# ---------------------------------------------------------------------------


class TestDdiDns:
    def test_get_zones_lists_zone_names(self) -> None:
        cap = SpatiumDdiDns(_client(), uuid4(), _CONTEXT)
        assert "example.com" in cap.get_zones()

    def test_get_records_normalizes_known_and_other_types(self) -> None:
        cap = SpatiumDdiDns(_client(), uuid4(), _CONTEXT)
        records = cap.get_records()
        by_name = {r.name: r for r in records}
        assert by_name["www"].record_type is DnsRecordType.A
        assert by_name["www"].value == "10.0.0.10"
        assert by_name["alias"].record_type is DnsRecordType.CNAME
        # HTTPS is outside the lowest-common-denominator enum -> OTHER, but the
        # record is still surfaced (value preserved).
        assert by_name["_dns"].record_type is DnsRecordType.OTHER
        assert all(r.source_vendor == VENDOR_ID for r in records)
        assert all(r.zone == "example.com" for r in records)

    def test_get_records_scoped_to_zone(self) -> None:
        cap = SpatiumDdiDns(_client(), uuid4(), _CONTEXT)
        records = cap.get_records(zone="does-not-exist.example")
        assert records == []

    def test_add_record_is_create_draft_with_soft_delete_inverse(self) -> None:
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        record = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=_now(),
            source_vendor=VENDOR_ID,
            name="api",
            record_type=DnsRecordType.A,
            value="10.0.0.20",
            ttl=300,
            zone="example.com",
        )
        draft = cap.add_record(record)
        assert draft.verb is ChangeVerb.CREATE
        assert draft.resource == RESOURCE_DNS_RECORD
        body = dict(draft.body)
        assert body["name"] == "api"
        assert body["record_type"] == "A"
        assert body["value"] == "10.0.0.20"
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.DELETE
        assert draft.inverse.resource == RESOURCE_DNS_RECORD

    def test_add_record_embeds_zone_id_in_body_when_context_has_zone_id(self) -> None:
        """zone_id must be present in the draft body so the executor can build the URL."""
        ctx = SpatiumContext(
            dns_group_ids=(_GROUP,),
            zone_id=_ZONE,
        )
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), ctx)
        record = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=_now(),
            source_vendor=VENDOR_ID,
            name="api",
            record_type=DnsRecordType.A,
            value="10.0.0.20",
            zone="example.com",
        )
        draft = cap.add_record(record)
        body = dict(draft.body)
        assert body.get("zone_id") == _ZONE, (
            "zone_id must be embedded in the draft body for the executor to construct "
            "/dns/groups/{group_id}/zones/{zone_id}/records"
        )
        assert body.get("group_id") == _GROUP

    def test_modify_record_embeds_zone_id_in_body_when_context_has_zone_id(self) -> None:
        ctx = SpatiumContext(dns_group_ids=(_GROUP,), zone_id=_ZONE)
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), ctx)
        changes = _dns_record("www", DnsRecordType.A, "10.0.0.99")
        draft = cap.modify_record(_RECORD, changes)
        body = dict(draft.body)
        assert body.get("zone_id") == _ZONE

    def test_delete_record_embeds_zone_id_in_body_when_context_has_zone_id(self) -> None:
        ctx = SpatiumContext(dns_group_ids=(_GROUP,), zone_id=_ZONE)
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), ctx)
        draft = cap.delete_record(_RECORD)
        body = dict(draft.body)
        assert body.get("zone_id") == _ZONE

    def test_modify_record_inverse_restores_prior_value(self) -> None:
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        prior = _dns_record("www", DnsRecordType.A, "10.0.0.10")
        changes = _dns_record("www", DnsRecordType.A, "10.0.0.99")
        draft = cap.modify_record(_RECORD, changes, current=prior)
        assert draft.verb is ChangeVerb.UPDATE
        assert draft.object_ref == _RECORD
        assert dict(draft.body)["value"] == "10.0.0.99"
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.UPDATE
        assert dict(draft.inverse.body)["value"] == "10.0.0.10"

    def test_modify_record_without_preimage_has_no_inverse(self) -> None:
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        changes = _dns_record("www", DnsRecordType.A, "10.0.0.99")
        draft = cap.modify_record(_RECORD, changes)
        assert draft.inverse is None

    def test_delete_record_inverse_is_restore_not_recreate(self) -> None:
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.delete_record(_RECORD)
        assert draft.verb is ChangeVerb.DELETE
        assert draft.resource == RESOURCE_DNS_RECORD
        assert draft.object_ref == _RECORD
        # SOFT delete: the inverse is a RESTORE (verb CREATE, same object_ref +
        # the soft-delete resource type), NOT a re-create with a fresh body.
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.CREATE
        assert draft.inverse.resource in SOFT_DELETE_RESOURCE_TYPES
        assert draft.inverse.resource == RESOURCE_DNS_RECORD
        assert draft.inverse.object_ref == _RECORD
        assert "restore" in draft.inverse.summary.lower()

    def test_delete_record_restore_inverse_available_without_preimage(self) -> None:
        # Unlike Infoblox (hard delete needs a pre-image to re-create), a soft
        # delete is always reversible via the trash row.
        cap = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.delete_record(_RECORD)
        assert draft.inverse is not None


# ---------------------------------------------------------------------------
# DDI_DHCP
# ---------------------------------------------------------------------------


class TestDdiDhcp:
    def test_get_ranges_normalizes_pools(self) -> None:
        cap = SpatiumDdiDhcp(_client(), uuid4(), _CONTEXT)
        ranges = cap.get_ranges()
        assert len(ranges) == 1
        rng = ranges[0]
        assert rng.start_address == ip_address("10.0.0.100")
        assert rng.end_address == ip_address("10.0.0.200")
        assert rng.object_ref == _POOL
        assert rng.source_vendor == VENDOR_ID

    def test_get_leases_normalizes_state(self) -> None:
        cap = SpatiumDdiDhcp(_client(), uuid4(), _CONTEXT)
        leases = cap.get_leases()
        assert len(leases) == 1
        lease = leases[0]
        assert lease.ip_address == ip_address("10.0.0.120")
        assert lease.state is DhcpLeaseState.ACTIVE
        assert lease.ends_at is not None
        assert lease.source_vendor == VENDOR_ID

    def test_add_range_is_create_draft(self) -> None:
        cap = SpatiumDdiDhcp(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.add_range(_dhcp_range("10.0.0.100", "10.0.0.200"))
        assert draft.verb is ChangeVerb.CREATE
        assert draft.resource == RESOURCE_DHCP_POOL
        body = dict(draft.body)
        assert body["start_ip"] == "10.0.0.100"
        assert body["scope_id"] == _SCOPE
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.DELETE

    def test_delete_range_inverse_is_recreate_not_restore(self) -> None:
        cap = SpatiumDdiDhcp(_no_io_client(), uuid4(), _CONTEXT)
        current = _dhcp_range("10.0.0.100", "10.0.0.200")
        draft = cap.delete_range(_POOL, current=current)
        assert draft.verb is ChangeVerb.DELETE
        assert draft.resource == RESOURCE_DHCP_POOL
        # HARD delete: pool is NOT a soft-delete type -> inverse is a re-create
        # (verb CREATE with a fresh body, NOT a restore by object_ref).
        assert RESOURCE_DHCP_POOL not in SOFT_DELETE_RESOURCE_TYPES
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.CREATE
        assert draft.inverse.object_ref is None
        assert dict(draft.inverse.body)["start_ip"] == "10.0.0.100"

    def test_delete_range_without_preimage_is_non_reversible(self) -> None:
        cap = SpatiumDdiDhcp(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.delete_range(_POOL)
        assert draft.inverse is None


# ---------------------------------------------------------------------------
# DDI_IPAM
# ---------------------------------------------------------------------------


class TestDdiIpam:
    def test_get_networks_normalizes_subnets(self) -> None:
        cap = SpatiumDdiIpam(_client(), uuid4(), _CONTEXT)
        networks = cap.get_networks()
        assert len(networks) == 1
        net = networks[0]
        assert net.network == ip_network("10.0.0.0/24")
        assert net.utilization_percent == 42.5
        assert net.object_ref == _SUBNET
        assert net.source_vendor == VENDOR_ID

    def test_get_next_available_ip_uses_preview(self) -> None:
        cap = SpatiumDdiIpam(_client(), uuid4(), _CONTEXT)
        assert cap.get_next_available_ip("10.0.0.0/24") == "10.0.0.146"

    def test_get_next_available_ip_unknown_network_raises(self) -> None:
        cap = SpatiumDdiIpam(_client(), uuid4(), _CONTEXT)
        with pytest.raises(PluginError):
            cap.get_next_available_ip("192.0.2.0/24")

    def test_add_network_is_create_draft_with_space_and_block(self) -> None:
        cap = SpatiumDdiIpam(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.add_network(_network("10.1.0.0/24", "branch"))
        assert draft.verb is ChangeVerb.CREATE
        assert draft.resource == RESOURCE_SUBNET
        body = dict(draft.body)
        assert body["space_id"] == _SPACE
        assert body["block_id"] == _BLOCK
        assert body["network"] == "10.1.0.0/24"
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.DELETE

    def test_delete_network_inverse_is_restore_not_recreate(self) -> None:
        cap = SpatiumDdiIpam(_no_io_client(), uuid4(), _CONTEXT)
        draft = cap.delete_network(_SUBNET, current=_network("10.0.0.0/24", "lan"))
        assert draft.verb is ChangeVerb.DELETE
        assert draft.resource == RESOURCE_SUBNET
        assert draft.object_ref == _SUBNET
        # SOFT delete: inverse is a RESTORE, NOT a re-create.
        assert draft.inverse is not None
        assert draft.inverse.verb is ChangeVerb.CREATE
        assert draft.inverse.resource == RESOURCE_SUBNET
        assert draft.inverse.resource in SOFT_DELETE_RESOURCE_TYPES
        assert draft.inverse.object_ref == _SUBNET


# ---------------------------------------------------------------------------
# plugin wiring + secret hygiene
# ---------------------------------------------------------------------------


class TestPluginWiring:
    def test_plugin_declares_four_ddi_capabilities(self) -> None:
        plugin = SpatiumddiPlugin()
        from app.plugins.base import Capability

        assert plugin.capabilities == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.DDI_DNS,
                Capability.DDI_DHCP,
                Capability.DDI_IPAM,
            }
        )
        assert plugin.get_capability(Capability.DDI_DNS) is SpatiumDdiDns
        assert plugin.get_capability(Capability.DDI_DHCP) is SpatiumDdiDhcp
        assert plugin.get_capability(Capability.DDI_IPAM) is SpatiumDdiIpam
        assert plugin.get_capability(Capability.DISCOVERY_API) is SpatiumDiscoveryApi

    def test_no_token_leaks_into_drafts_or_records(self) -> None:
        cap = SpatiumDdiDns(_client(), uuid4(), _CONTEXT)
        records = cap.get_records()
        blob = json.dumps([r.model_dump(mode="json") for r in records])
        assert _FAKE_TOKEN not in blob
        mut = SpatiumDdiDns(_no_io_client(), uuid4(), _CONTEXT)
        draft = mut.delete_record(_RECORD)
        assert _FAKE_TOKEN not in draft.model_dump_json()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _now() -> Any:
    from datetime import UTC, datetime

    return datetime.now(UTC)


def _dns_record(name: str, rtype: DnsRecordType, value: str) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=uuid4(),
        collected_at=_now(),
        source_vendor=VENDOR_ID,
        name=name,
        record_type=rtype,
        value=value,
        ttl=3600,
        zone="example.com",
    )


def _dhcp_range(start: str, end: str) -> NormalizedDhcpRange:
    return NormalizedDhcpRange(
        device_id=uuid4(),
        collected_at=_now(),
        source_vendor=VENDOR_ID,
        start_address=ip_address(start),
        end_address=ip_address(end),
        name="lan-dynamic",
    )


def _network(cidr: str, name: str) -> NormalizedNetwork:
    return NormalizedNetwork(
        device_id=uuid4(),
        collected_at=_now(),
        source_vendor=VENDOR_ID,
        network=ip_network(cidr),
        comment=name,
    )
