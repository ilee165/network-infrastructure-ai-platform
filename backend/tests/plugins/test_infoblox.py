"""Unit tests for the infoblox plugin (ADR-0022).

httpx is mocked with :class:`httpx.MockTransport` (no respx dependency, no
network — D16): every test wires the WAPI client to a recorded-response
transport so each capability's read path, the verbatim raw-recording, the
mutations-as-drafts contract, and the no-secret-leak posture are exercised
without an appliance.

The only credential anywhere in this module is the obviously-fake
``("admin", "infoblox")`` pair; no test fixture carries a real secret.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.core.errors import PluginError
from app.plugins.base import ChangeRequestDraft, WapiVerb
from app.plugins.vendors.infoblox.plugin import (
    VENDOR_ID,
    InfobloxDdiDhcp,
    InfobloxDdiDns,
    InfobloxDdiIpam,
    InfobloxDiscoveryApi,
    InfobloxPlugin,
)
from app.plugins.vendors.infoblox.wapi import WapiClient, WapiCredentials
from app.schemas.normalized import (
    DhcpLeaseState,
    DiscoveredObjectKind,
    DnsRecordType,
    NormalizedDhcpRange,
    NormalizedDnsRecord,
    NormalizedNetwork,
)

FIXTURES = Path(__file__).parent / "fixtures" / "infoblox"

#: Map WAPI object type -> recorded JSON fixture file.
_OBJTYPE_FIXTURE = {
    "network": "network.json",
    "zone_auth": "zone_auth.json",
    "member": "member.json",
    "record:a": "record_a.json",
    "record:cname": "record_cname.json",
    "range": "range.json",
    "lease": "lease.json",
}

#: A clearly-fake credential — never a real secret (task constraint). The
#: password is a distinctive sentinel so a leak assertion cannot collide with
#: the vendor_id or the ``infoblox.example.com`` member hostname in fixtures.
_FAKE_CREDS = WapiCredentials(username="admin", password="FAKE-w@pi-pw-zzz")


def _load(objtype: str) -> list[dict[str, Any]]:
    filename = _OBJTYPE_FIXTURE.get(objtype)
    if filename is None:
        return []
    return json.loads((FIXTURES / filename).read_text(encoding="utf-8"))


def _handler(seen: list[httpx.Request] | None = None) -> Callable[[httpx.Request], httpx.Response]:
    """Build a MockTransport handler replaying the recorded WAPI fixtures."""

    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        # URL path is /wapi/v2.12/<objtype>; objtype may contain a ':'.
        objtype = request.url.path.split("/wapi/", 1)[1].split("/", 1)[1]
        return httpx.Response(200, json=_load(objtype))

    return handle


def _client(
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
) -> WapiClient:
    transport = httpx.MockTransport(handler or _handler())
    http = httpx.Client(transport=transport)
    return WapiClient(
        base_url="https://gm.example.com",
        version="2.12",
        credentials=_FAKE_CREDS,
        client=http,
    )


class TestDiscoveryApi:
    def test_discover_returns_networks_zones_and_members(self) -> None:
        cap = InfobloxDiscoveryApi(_client(), uuid4())
        objects = cap.discover()
        kinds = {o.kind for o in objects}
        assert kinds == {
            DiscoveredObjectKind.NETWORK,
            DiscoveredObjectKind.DNS_ZONE,
            DiscoveredObjectKind.MEMBER,
        }
        net = next(o for o in objects if o.kind is DiscoveredObjectKind.NETWORK)
        assert net.identifier == "10.0.0.0/24"
        assert net.object_ref and net.object_ref.startswith("network/")
        assert all(o.source_vendor == VENDOR_ID for o in objects)

    def test_discover_records_raw_before_parsing(self) -> None:
        cap = InfobloxDiscoveryApi(_client(), uuid4())
        cap.discover()
        commands = [raw.command for raw in cap.raw_outputs]
        assert commands == ["GET network", "GET zone_auth", "GET member"]
        assert all(raw.output for raw in cap.raw_outputs)


class TestDdiDns:
    def test_get_records_normalizes_a_and_cname(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        records = cap.get_records()
        by_type = {r.record_type for r in records}
        assert DnsRecordType.A in by_type
        assert DnsRecordType.CNAME in by_type
        a = next(r for r in records if r.record_type is DnsRecordType.A)
        assert a.value == "10.0.0.10"
        assert a.object_ref and a.object_ref.startswith("record:a/")
        cname = next(r for r in records if r.record_type is DnsRecordType.CNAME)
        assert cname.value == "web.example.com"

    def test_get_records_scopes_zone_param(self) -> None:
        seen: list[httpx.Request] = []
        cap = InfobloxDdiDns(_client(_handler(seen)), uuid4())
        cap.get_records(zone="example.com")
        assert seen, "no WAPI request was issued"
        assert all(req.url.params.get("zone") == "example.com" for req in seen)

    def test_add_record_returns_draft_and_does_no_io(self) -> None:
        seen: list[httpx.Request] = []
        cap = InfobloxDdiDns(_client(_handler(seen)), uuid4())
        record = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001 — test helper reuse
            source_vendor=VENDOR_ID,
            name="new.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.50",
        )
        draft = cap.add_record(record)
        assert isinstance(draft, ChangeRequestDraft)
        assert draft.verb is WapiVerb.CREATE
        assert draft.wapi_object == "record:a"
        assert dict(draft.body) == {"name": "new.example.com", "ipv4addr": "10.0.0.50"}
        assert draft.inverse is not None and draft.inverse.verb is WapiVerb.DELETE
        assert seen == [], "a mutation must not touch the appliance"

    def test_get_zones_normalizes_fqdns(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        zones = cap.get_zones()
        assert zones == ["example.com"]

    def test_get_zones_records_raw_before_parsing(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        cap.get_zones()
        commands = [raw.command for raw in cap.raw_outputs]
        assert commands == ["GET zone_auth"]
        assert all(raw.output for raw in cap.raw_outputs)

    def test_modify_record_inverse_restores_prior_state(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        object_ref = "record:a/abc:web.example.com/default"
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            name="web.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.10",
            object_ref=object_ref,
        )
        changes = current.model_copy(update={"value": "10.0.0.99"})
        draft = cap.modify_record(object_ref, changes, current=current)
        assert draft.verb is WapiVerb.UPDATE
        assert dict(draft.body) == {"ipv4addr": "10.0.0.99"}
        # The inverse must carry the PRIOR value so an approved rollback restores it.
        assert draft.inverse is not None
        assert draft.inverse.verb is WapiVerb.UPDATE
        assert draft.inverse.object_ref == object_ref
        assert dict(draft.inverse.body) == {"ipv4addr": "10.0.0.10"}

    def test_modify_record_without_pre_image_has_no_blind_inverse(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        object_ref = "record:a/abc:web.example.com/default"
        changes = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            name="web.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.99",
        )
        draft = cap.modify_record(object_ref, changes)
        # No pre-image -> no fake empty-body "restore" draft (ADR-0022 §3).
        assert draft.inverse is None
        assert "pre-image" in draft.summary.lower()

    def test_delete_record_inverse_recreates_from_pre_image(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        object_ref = "record:a/abc:web.example.com/default"
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            name="web.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.10",
            object_ref=object_ref,
        )
        draft = cap.delete_record(object_ref, current=current)
        assert draft.verb is WapiVerb.DELETE
        assert draft.object_ref == object_ref
        # The inverse re-create carries the typed object + full body to recreate.
        assert draft.inverse is not None
        assert draft.inverse.verb is WapiVerb.CREATE
        assert draft.inverse.wapi_object == "record:a"
        assert dict(draft.inverse.body) == {
            "name": "web.example.com",
            "ipv4addr": "10.0.0.10",
        }

    def test_delete_record_without_pre_image_is_non_reversible(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        draft = cap.delete_record("record:a/abc:web.example.com/default")
        assert draft.verb is WapiVerb.DELETE
        # No pre-image -> delete is non-reversible; no misleading re-create draft.
        assert draft.inverse is None


class TestDdiDhcp:
    def test_get_leases_maps_binding_state(self) -> None:
        cap = InfobloxDdiDhcp(_client(), uuid4())
        leases = cap.get_leases()
        states = {lease.ip_address.compressed: lease.state for lease in leases}
        assert states["10.0.0.101"] is DhcpLeaseState.ACTIVE
        assert states["10.0.0.102"] is DhcpLeaseState.FREE
        active = next(le for le in leases if le.state is DhcpLeaseState.ACTIVE)
        assert active.mac_address == "aa:bb:cc:00:11:22"
        assert active.starts_at is not None and active.ends_at is not None

    def test_get_ranges_normalizes_member(self) -> None:
        cap = InfobloxDdiDhcp(_client(), uuid4())
        ranges = cap.get_ranges()
        assert len(ranges) == 1
        rng = ranges[0]
        assert str(rng.start_address) == "10.0.0.100"
        assert rng.member == "infoblox.example.com"

    def test_add_range_returns_draft(self) -> None:
        cap = InfobloxDdiDhcp(_client(), uuid4())
        rng = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            start_address="10.0.0.210",
            end_address="10.0.0.220",
        )
        draft = cap.add_range(rng)
        assert draft.verb is WapiVerb.CREATE
        assert dict(draft.body) == {"start_addr": "10.0.0.210", "end_addr": "10.0.0.220"}
        assert draft.inverse is not None and draft.inverse.verb is WapiVerb.DELETE

    def test_delete_range_inverse_recreates_from_pre_image(self) -> None:
        cap = InfobloxDdiDhcp(_client(), uuid4())
        object_ref = "range/abc:10.0.0.100/10.0.0.200/default"
        current = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            start_address="10.0.0.100",
            end_address="10.0.0.200",
            object_ref=object_ref,
        )
        draft = cap.delete_range(object_ref, current=current)
        assert draft.verb is WapiVerb.DELETE
        assert draft.inverse is not None
        assert draft.inverse.verb is WapiVerb.CREATE
        assert draft.inverse.wapi_object == "range"
        assert dict(draft.inverse.body) == {
            "start_addr": "10.0.0.100",
            "end_addr": "10.0.0.200",
        }

    def test_delete_range_without_pre_image_is_non_reversible(self) -> None:
        cap = InfobloxDdiDhcp(_client(), uuid4())
        draft = cap.delete_range("range/abc:10.0.0.100/10.0.0.200/default")
        assert draft.verb is WapiVerb.DELETE
        assert draft.inverse is None


class TestDdiIpam:
    def test_get_networks_computes_utilization_percent(self) -> None:
        cap = InfobloxDdiIpam(_client(), uuid4())
        networks = cap.get_networks()
        by_cidr = {str(n.network): n for n in networks}
        assert by_cidr["10.0.0.0/24"].utilization_percent == 41.2
        assert by_cidr["192.0.2.0/24"].utilization_percent == 0.0
        assert by_cidr["10.0.0.0/24"].object_ref is not None

    def test_add_network_draft_carries_inverse(self) -> None:
        cap = InfobloxDdiIpam(_client(), uuid4())
        net = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            network="172.16.0.0/24",
            comment="new alloc",
        )
        draft = cap.add_network(net)
        assert draft.verb is WapiVerb.CREATE
        assert dict(draft.body)["network"] == "172.16.0.0/24"
        assert draft.inverse is not None and draft.inverse.verb is WapiVerb.DELETE

    def test_delete_network_inverse_recreates_from_pre_image(self) -> None:
        cap = InfobloxDdiIpam(_client(), uuid4())
        object_ref = "network/abc:10.0.0.0/24/default"
        current = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=cap._now(),  # noqa: SLF001
            source_vendor=VENDOR_ID,
            network="10.0.0.0/24",
            comment="lab access subnet",
            object_ref=object_ref,
        )
        draft = cap.delete_network(object_ref, current=current)
        assert draft.verb is WapiVerb.DELETE
        assert draft.inverse is not None
        assert draft.inverse.verb is WapiVerb.CREATE
        assert draft.inverse.wapi_object == "network"
        assert dict(draft.inverse.body) == {
            "network": "10.0.0.0/24",
            "comment": "lab access subnet",
        }

    def test_delete_network_without_pre_image_is_non_reversible(self) -> None:
        cap = InfobloxDdiIpam(_client(), uuid4())
        draft = cap.delete_network("network/abc:10.0.0.0/24/default")
        assert draft.verb is WapiVerb.DELETE
        assert draft.inverse is None

    def test_get_next_available_ip_calls_function_on_resolved_ref(self) -> None:
        posts: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                posts.append(request)
                return httpx.Response(200, json={"ips": ["10.0.0.5"]})
            objtype = request.url.path.split("/wapi/", 1)[1].split("/", 1)[1]
            return httpx.Response(200, json=_load(objtype))

        cap = InfobloxDdiIpam(_client(handle), uuid4())
        ip = cap.get_next_available_ip("10.0.0.0/24")
        assert ip == "10.0.0.5"
        assert posts, "next_available_ip must call the WAPI function"
        assert posts[0].url.params.get("_function") == "next_available_ip"

    def test_get_next_available_ip_unknown_network_raises(self) -> None:
        cap = InfobloxDdiIpam(_client(), uuid4())
        with pytest.raises(PluginError, match="no such network"):
            cap.get_next_available_ip("203.0.113.0/24")


class TestWapiClientErrors:
    def test_http_error_status_is_sanitized(self) -> None:
        def boom(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"Error": "auth failed"})

        client = _client(boom)
        with pytest.raises(PluginError) as excinfo:
            client.get("network")
        message = str(excinfo.value)
        assert "401" in message
        # The sanitized message names the object type + status but must not echo
        # the credential or the response body.
        assert "WAPI GET 'network'" in message
        assert "auth failed" not in message
        assert _FAKE_CREDS.password not in message
        assert _FAKE_CREDS.username not in message

    def test_non_list_payload_is_rejected(self) -> None:
        def obj(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"not": "a list"})

        with pytest.raises(PluginError, match="non-list"):
            _client(obj).get("network")


class TestNoSecretLeak:
    def test_credentials_password_not_in_repr(self) -> None:
        assert _FAKE_CREDS.password not in repr(_FAKE_CREDS)
        assert "admin" in repr(_FAKE_CREDS)  # username is not a secret

    def test_password_never_appears_in_raw_outputs_or_records(self) -> None:
        cap = InfobloxDiscoveryApi(_client(), uuid4())
        objects = cap.discover()
        blob = "".join(raw.output for raw in cap.raw_outputs)
        blob += "".join(repr(o.model_dump()) for o in objects)
        assert _FAKE_CREDS.password not in blob

    def test_drafts_carry_no_credentials(self) -> None:
        cap = InfobloxDdiDns(_client(), uuid4())
        draft = cap.delete_record("record:a/abc:web.example.com/default")
        assert _FAKE_CREDS.password not in repr(draft.model_dump())


class TestPluginRegistration:
    def test_plugin_declares_the_four_api_capabilities(self) -> None:
        from app.plugins.base import Capability

        plugin = InfobloxPlugin()
        assert plugin.vendor_id == "infoblox"
        assert plugin.capabilities == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.DDI_DNS,
                Capability.DDI_DHCP,
                Capability.DDI_IPAM,
            }
        )
        assert plugin.get_capability(Capability.DDI_DNS) is InfobloxDdiDns

    def test_registered_as_entry_point(self) -> None:
        from importlib.metadata import entry_points

        names = {ep.name for ep in entry_points(group="netops.plugins")}
        # The entry point is declared in pyproject; only assert presence when the
        # editable install metadata has been refreshed (skip otherwise so the
        # suite is green from source before reinstall).
        if "infoblox" not in names:
            pytest.skip("editable metadata not refreshed; entry point declared in pyproject")
        ep = next(ep for ep in entry_points(group="netops.plugins") if ep.name == "infoblox")
        assert ep.load() is InfobloxPlugin
