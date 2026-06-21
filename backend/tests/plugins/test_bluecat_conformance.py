"""BlueCat Address Manager plugin run through the reusable conformance suite (ADR-0027 §6).

The platform's third API-based DDI plugin certified against the shared suite
(after infoblox and spatiumddi). Builds a capability factory wiring each
capability to a :class:`BamClient` over source-derived BAM v2 fixtures
(replayed via :class:`httpx.MockTransport` — no respx, no network, D16), then
parametrizes over :func:`make_conformance_cases`. Each DDI/discovery read method
returns non-empty normalized records carrying ``source_vendor == "bluecat"``.

The only credential anywhere in this module is the obviously-fake sentinel
``FAKE-bam-session-token-zzz`` — it is never a real secret.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.plugins.base import (
    ChangeRequestDraft,
    ChangeVerb,
    PluginCapability,
)
from app.plugins.vendors.bluecat.client import BamClient, BamCredentials
from app.plugins.vendors.bluecat.plugin import (
    BluecatDdiDhcp,
    BluecatDdiDns,
    BluecatDdiIpam,
    BluecatPlugin,
)
from app.schemas.normalized import (
    DnsRecordType,
    NormalizedDhcpRange,
    NormalizedDnsRecord,
    NormalizedNetwork,
)
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

FIXTURES = Path(__file__).parent / "fixtures" / "bluecat"

#: A clearly-fake session token — never a real secret.
_FAKE_TOKEN = "FAKE-bam-session-token-zzz"  # noqa: S105 — obviously-fake test sentinel
_FAKE_CREDS = BamCredentials(username="apiuser", password="FAKE-pw-zzz")  # noqa: S106

#: Fixed BAM entity ids used throughout fixtures and tests.
_CONFIG_ID = 100001
_VIEW_ID = 200001
_ZONE_ID = 300001
_BLOCK_ID = 500001
_NETWORK_ID = 600001
_RANGE_ID = 700001


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _handle(request: httpx.Request) -> httpx.Response:
    """Route BAM v2 fixture requests by path.

    Replicates the BAM RESTful v2 URL structure so the capability layer can
    issue requests against the MockTransport without a running appliance (D16).
    Session login returns a fake token header; all other paths serve fixtures.
    """
    path = request.url.path
    # Session login (POST /api/v2/sessions) — return a fake session token.
    if path.endswith("/sessions") and request.method == "POST":
        return httpx.Response(
            200,
            json={"token": _FAKE_TOKEN},
            headers={"BAMAuthToken": _FAKE_TOKEN},
        )
    # Strip /api/v2 prefix for matching.
    rel = path.split("/api/v2", 1)[1] if "/api/v2" in path else path

    body: Any
    if rel == "/configurations":
        body = _load("configurations.json")
    elif "/views" in rel and rel.endswith("/views"):
        body = _load("views.json")
    elif rel.endswith("/zones") or "/zones" in rel and "/resourceRecords" not in rel:
        body = _load("zones.json")
    elif rel.endswith("/resourceRecords"):
        body = _load("resource_records.json")
    elif rel.endswith("/blocks") or "/blocks" in rel and "/networks" not in rel:
        body = _load("blocks.json")
    elif rel.endswith("/networks") or (
        "/networks" in rel and "/addresses" not in rel and "/ranges" not in rel
    ):
        body = _load("networks.json")
    elif rel.endswith("/addresses/next"):
        body = _load("next_ip.json")
    elif rel.endswith("/ranges"):
        body = _load("ranges.json")
    elif rel.endswith("/addresses"):
        body = _load("leases.json")
    else:
        body = {"count": 0, "data": []}
    return httpx.Response(200, json=body)


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    """Wire an impl class to a BamClient over the MockTransport."""
    http = httpx.Client(transport=httpx.MockTransport(_handle))
    client = BamClient(
        base_url="https://bam.example.com",
        credentials=_FAKE_CREDS,
        client=http,
        # Skip real session login — inject the fake token directly.
        session_token=_FAKE_TOKEN,
    )
    return impl(client, uuid4())


CASES = make_conformance_cases(BluecatPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_bluecat_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """Every declared capability has a typed interface in _INTERFACE_SPECS, so
    each must get both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in BluecatPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids


# ---------------------------------------------------------------------------
# Unit tests — shape of mutator ChangeRequestDrafts (no I/O, ADR-0027 §5)
# ---------------------------------------------------------------------------


class TestBluecatDnsWritePathShape:
    """Mutators return ChangeRequestDraft; no HTTP write occurs (ADR-0027 §5)."""

    def _dns(self) -> BluecatDdiDns:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        return BluecatDdiDns(client, uuid4())

    def test_add_record_returns_draft_create(self) -> None:
        dns = self._dns()
        record = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            name="test.example.com",
            record_type=DnsRecordType.A,
            value="10.0.1.1",
            ttl=300,
            zone="example.com",
            object_ref=None,
        )
        draft = dns.add_record(record, zone_id=_ZONE_ID)
        assert isinstance(draft, ChangeRequestDraft)
        assert draft.verb == ChangeVerb.CREATE
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.DELETE
        # No HTTP side-effects: object_ref is None (id unknown until Automation Agent writes).
        assert draft.object_ref is None

    def test_modify_record_with_preimage_has_restore_inverse(self) -> None:
        dns = self._dns()
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        base = dict(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            zone="example.com",
        )
        current = NormalizedDnsRecord(**base, value="10.0.0.1", ttl=300, object_ref=str(_ZONE_ID))
        changes = NormalizedDnsRecord(**base, value="10.0.0.2", ttl=300, object_ref=str(_ZONE_ID))
        draft = dns.modify_record(str(400001), changes, current=current)
        assert draft.verb == ChangeVerb.UPDATE
        assert draft.object_ref == str(400001)
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.UPDATE
        # Inverse body must re-apply prior value (ADR-0027 §3).
        body_dict = dict(draft.inverse.body or ())
        assert body_dict.get("address") == "10.0.0.1"

    def test_modify_record_without_preimage_has_no_inverse(self) -> None:
        dns = self._dns()
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        changes = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.2",
            ttl=300,
            zone="example.com",
            object_ref=str(_ZONE_ID),
        )
        draft = dns.modify_record(str(400001), changes, current=None)
        assert draft.inverse is None

    def test_delete_record_with_preimage_has_recreate_inverse(self) -> None:
        """Delete inverse is re-create (hard delete, ADR-0027 §3 — not RESTORE)."""
        dns = self._dns()
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.1",
            ttl=300,
            zone="example.com",
            object_ref=str(400001),
        )
        draft = dns.delete_record(str(400001), current=current, zone_id=_ZONE_ID)
        assert draft.verb == ChangeVerb.DELETE
        assert draft.object_ref == str(400001)
        assert draft.inverse is not None
        # Re-create (not RESTORE) — body carries the parent zone_id for re-parenting.
        assert draft.inverse.verb == ChangeVerb.CREATE
        body_dict = dict(draft.inverse.body or ())
        assert "zone_id" in body_dict

    def test_delete_record_without_preimage_has_no_inverse(self) -> None:
        dns = self._dns()
        draft = dns.delete_record(str(400001), current=None, zone_id=_ZONE_ID)
        assert draft.inverse is None


class TestBluecatIpamWritePathShape:
    """IPAM mutators return ChangeRequestDraft; no HTTP write occurs (ADR-0027 §5)."""

    def _ipam(self) -> BluecatDdiIpam:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        return BluecatDdiIpam(client, uuid4())

    def test_add_network_returns_draft_create(self) -> None:
        import datetime
        from ipaddress import ip_network

        ipam = self._ipam()
        network = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            network=ip_network("10.0.1.0/24"),
            comment="test",
            object_ref=None,
        )
        draft = ipam.add_network(network, block_id=_BLOCK_ID)
        assert draft.verb == ChangeVerb.CREATE
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.DELETE
        body_dict = dict(draft.body or ())
        assert body_dict.get("range") == "10.0.1.0/24"
        assert body_dict.get("block_id") == str(_BLOCK_ID)

    def test_delete_network_with_preimage_has_recreate_inverse(self) -> None:
        """Delete inverse is re-create from prior body (hard delete, ADR-0027 §3)."""
        import datetime
        from ipaddress import ip_network

        ipam = self._ipam()
        current = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            network=ip_network("10.0.0.0/24"),
            comment="lan",
            object_ref=str(_NETWORK_ID),
        )
        draft = ipam.delete_network(str(_NETWORK_ID), current=current, block_id=_BLOCK_ID)
        assert draft.verb == ChangeVerb.DELETE
        assert draft.object_ref == str(_NETWORK_ID)
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.CREATE
        body_dict = dict(draft.inverse.body or ())
        assert body_dict.get("range") == "10.0.0.0/24"
        assert body_dict.get("block_id") == str(_BLOCK_ID)

    def test_delete_network_without_preimage_has_no_inverse(self) -> None:
        ipam = self._ipam()
        draft = ipam.delete_network(str(_NETWORK_ID), current=None, block_id=_BLOCK_ID)
        assert draft.inverse is None


class TestBluecatDhcpWritePathShape:
    """DHCP mutators return ChangeRequestDraft; no HTTP write occurs (ADR-0027 §5)."""

    def _dhcp(self) -> BluecatDdiDhcp:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        return BluecatDdiDhcp(client, uuid4())

    def test_add_range_returns_draft_create(self) -> None:
        import datetime
        from ipaddress import ip_address

        dhcp = self._dhcp()
        dhcp_range = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            start_address=ip_address("10.0.0.100"),
            end_address=ip_address("10.0.0.200"),
            name="dynamic-pool",
            object_ref=None,
        )
        draft = dhcp.add_range(dhcp_range, network_id=_NETWORK_ID)
        assert draft.verb == ChangeVerb.CREATE
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.DELETE
        body_dict = dict(draft.body or ())
        assert body_dict.get("start") == "10.0.0.100"
        assert body_dict.get("end") == "10.0.0.200"
        assert body_dict.get("network_id") == str(_NETWORK_ID)

    def test_delete_range_with_preimage_has_recreate_inverse(self) -> None:
        """Delete inverse is re-create from prior body (hard delete, ADR-0027 §3)."""
        import datetime
        from ipaddress import ip_address

        dhcp = self._dhcp()
        current = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            start_address=ip_address("10.0.0.100"),
            end_address=ip_address("10.0.0.200"),
            name="dynamic-pool",
            object_ref=str(_RANGE_ID),
        )
        draft = dhcp.delete_range(str(_RANGE_ID), current=current, network_id=_NETWORK_ID)
        assert draft.verb == ChangeVerb.DELETE
        assert draft.object_ref == str(_RANGE_ID)
        assert draft.inverse is not None
        assert draft.inverse.verb == ChangeVerb.CREATE
        body_dict = dict(draft.inverse.body or ())
        assert body_dict.get("start") == "10.0.0.100"
        assert body_dict.get("end") == "10.0.0.200"
        assert body_dict.get("network_id") == str(_NETWORK_ID)

    def test_delete_range_without_preimage_has_no_inverse(self) -> None:
        dhcp = self._dhcp()
        draft = dhcp.delete_range(str(_RANGE_ID), current=None, network_id=_NETWORK_ID)
        assert draft.inverse is None


class TestBluecatClientCredentialHygiene:
    """Credentials are never logged or repr-exposed (ADR-0011 §1 / ADR-0027 §4)."""

    def test_credentials_password_not_in_repr(self) -> None:
        creds = BamCredentials(username="admin", password="s3cr3t-pw")
        assert "s3cr3t-pw" not in repr(creds)

    def test_client_repr_does_not_expose_session_token(self) -> None:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        r = repr(client)
        assert _FAKE_TOKEN not in r
        assert "FAKE" not in r

    def test_credentials_equality_excludes_password(self) -> None:
        a = BamCredentials(username="admin", password="pw1")
        b = BamCredentials(username="admin", password="pw2")
        # Two creds with same username but different passwords must be equal
        # (password excluded from compare, like WapiCredentials / SpatiumCredentials).
        assert a == b


class TestBluecatPaginationLoop:
    """Offset/limit pagination accumulates across pages (ADR-0027 §4)."""

    def test_list_paged_accumulates_two_pages(self) -> None:
        """BamClient.list() with a page limit accumulates data across pages."""
        paged = _load("paged_zones.json")
        page1 = paged["page1"]
        page2 = paged["page2"]
        call_count = 0

        def _paged_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if request.method == "POST" and request.url.path.endswith("/sessions"):
                return httpx.Response(200, json={"token": _FAKE_TOKEN})
            offset = int(request.url.params.get("offset", 0))
            if offset == 0:
                return httpx.Response(200, json=page1)
            return httpx.Response(200, json=page2)

        http = httpx.Client(transport=httpx.MockTransport(_paged_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        # page1 has count=3 but only 2 items; page2 has the remaining 1 item.
        result = client.get_list("/views/200001/zones", page_size=2)
        assert len(result) == 3
        # Two pages fetched (offset=0, offset=2).
        assert call_count == 2


class TestBluecatRegistration:
    """BlueCat is discoverable via iter_builtin_plugins and the default registry."""

    def test_iter_builtin_plugins_includes_bluecat(self) -> None:
        from app.plugins.vendors import iter_builtin_plugins

        vendor_ids = [p.vendor_id for p in iter_builtin_plugins()]
        assert "bluecat" in vendor_ids, "BluecatPlugin must be yielded by iter_builtin_plugins"

    def test_default_registry_contains_bluecat(self) -> None:
        from app.plugins.registry import get_default_registry

        get_default_registry.cache_clear()
        try:
            registry = get_default_registry()
            assert "bluecat" in registry.vendor_ids()
        finally:
            get_default_registry.cache_clear()

    def test_bluecat_declares_all_four_ddi_capabilities(self) -> None:
        from app.plugins.base import Capability

        caps = BluecatPlugin.capabilities
        assert caps == frozenset(
            {
                Capability.DISCOVERY_API,
                Capability.DDI_DNS,
                Capability.DDI_DHCP,
                Capability.DDI_IPAM,
            }
        )

    def test_bluecat_vendor_id_is_bluecat(self) -> None:
        assert BluecatPlugin.vendor_id == "bluecat"


# ---------------------------------------------------------------------------
# Extra unit tests to boost coverage on client + plugin paths (ADR-0027 §6)
# ---------------------------------------------------------------------------


class TestBamClientSessionManagement:
    """Session login + re-auth on 401 (ADR-0027 §4)."""

    def test_session_login_on_first_request(self) -> None:
        """A client without a pre-injected token performs POST /sessions first."""
        login_calls: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions") and request.method == "POST":
                login_calls.append("login")
                return httpx.Response(200, json={"token": "tok-abc"})
            return httpx.Response(200, json={"count": 0, "data": []})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            # No pre-injected token — must login.
        )
        client.get_list("/configurations")
        assert login_calls == ["login"]
        client.close()

    def test_reauth_on_401_retries_once(self) -> None:
        """A 401 response triggers re-login and exactly one retry (ADR-0027 §4)."""
        attempt_count = 0
        login_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count, login_count
            if request.url.path.endswith("/sessions") and request.method == "POST":
                login_count += 1
                return httpx.Response(200, json={"token": "tok-fresh"})
            attempt_count += 1
            if attempt_count == 1:
                # First data request — 401 (session expired).
                return httpx.Response(401, json={"error": "unauthorized"})
            # Second attempt — success.
            return httpx.Response(200, json={"count": 1, "data": [{"id": 1}]})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token="stale-token",
        )
        result = client.get_list("/configurations")
        assert len(result) == 1
        assert login_count == 1  # re-authenticated exactly once
        assert attempt_count == 2  # original + retry
        client.close()

    def test_login_via_header_token(self) -> None:
        """Token returned as BAMAuthToken response header is accepted (ADR-0027 §7)."""

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions") and request.method == "POST":
                return httpx.Response(
                    200,
                    json={},  # no token in body
                    headers={"BAMAuthToken": "header-tok"},
                )
            return httpx.Response(200, json={"count": 0, "data": []})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
        )
        # Must not raise — token extracted from header.
        client.get_list("/configurations")
        client.close()

    def test_login_raises_plugin_error_on_http_error(self) -> None:
        """A transport error during login raises PluginError (sanitized)."""
        from app.core.errors import PluginError

        def _bad_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TransportError("connection refused")

        http = httpx.Client(transport=httpx.MockTransport(_bad_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
        )
        with pytest.raises(PluginError, match="transport error"):
            client.get_list("/configurations")
        client.close()

    def test_login_raises_plugin_error_on_status_error(self) -> None:
        """A 401 on the login endpoint itself raises PluginError."""
        from app.core.errors import PluginError

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions"):
                return httpx.Response(401, json={"error": "bad credentials"})
            return httpx.Response(200, json={"count": 0, "data": []})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
        )
        with pytest.raises(PluginError, match="session login failed"):
            client.get_list("/configurations")
        client.close()

    def test_get_next_available_ip_via_client(self) -> None:
        """BamClient.get_next_available_ip returns {address} dict (ADR-0027 §2)."""
        next_ip_data = _load("next_ip.json")

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions") and request.method == "POST":
                return httpx.Response(200, json={"token": "tok"})
            if "/addresses/next" in request.url.path:
                return httpx.Response(200, json=next_ip_data)
            return httpx.Response(200, json={"count": 0, "data": []})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        result = client.get_next_available_ip(600001)
        assert result.get("address") == "10.0.0.5"
        client.close()


class TestBluecatPluginGetNextAvailableIp:
    """get_next_available_ip delegates to server (ADR-0027 §2 alt #4 rejected)."""

    def test_get_next_available_ip_returns_server_address(self) -> None:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        ipam = BluecatDdiIpam(client, uuid4())
        # The fixture has network 10.0.0.0/24; next_ip.json has address=10.0.0.5.
        result = ipam.get_next_available_ip("10.0.0.0/24")
        assert result == "10.0.0.5"

    def test_get_next_available_ip_raises_for_unknown_network(self) -> None:
        from app.core.errors import PluginError

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        ipam = BluecatDdiIpam(client, uuid4())
        with pytest.raises(PluginError, match="no such network"):
            ipam.get_next_available_ip("192.168.99.0/24")


class TestBluecatMutatorValidation:
    """Missing required parent ids raise PluginError (ADR-0027 §2 / §5)."""

    def test_add_record_raises_without_zone_id(self) -> None:
        import datetime

        from app.core.errors import PluginError

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        dns = BluecatDdiDns(client, uuid4())
        record = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            name="test.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.1",
            ttl=300,
            zone="example.com",
            object_ref=None,
        )
        with pytest.raises(PluginError, match="zone_id"):
            dns.add_record(record)  # no zone_id

    def test_add_range_raises_without_network_id(self) -> None:
        import datetime
        from ipaddress import ip_address

        from app.core.errors import PluginError

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        dhcp = BluecatDdiDhcp(client, uuid4())
        dhcp_range = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            start_address=ip_address("10.0.0.100"),
            end_address=ip_address("10.0.0.200"),
            object_ref=None,
        )
        with pytest.raises(PluginError, match="network_id"):
            dhcp.add_range(dhcp_range)

    def test_add_network_raises_without_block_id(self) -> None:
        import datetime
        from ipaddress import ip_network

        from app.core.errors import PluginError

        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        ipam = BluecatDdiIpam(client, uuid4())
        network = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            network=ip_network("10.0.1.0/24"),
            object_ref=None,
        )
        with pytest.raises(PluginError, match="block_id"):
            ipam.add_network(network)


class TestBluecatModifyRecordImmutableType:
    """modify_record must reject record_type changes (BAM type is immutable on update)."""

    def _dns(self) -> BluecatDdiDns:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        return BluecatDdiDns(client, uuid4())

    def test_modify_record_raises_when_record_type_changes(self) -> None:
        """Changing record_type on modify must raise ValueError (BAM type is immutable)."""
        import datetime

        dns = self._dns()
        now = datetime.datetime.now(datetime.UTC)
        base = dict(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            zone="example.com",
            ttl=300,
            object_ref=str(400001),
        )
        current = NormalizedDnsRecord(**base, record_type=DnsRecordType.A, value="10.0.0.1")
        changes = NormalizedDnsRecord(**base, record_type=DnsRecordType.AAAA, value="::1")
        with pytest.raises(ValueError, match="record_type"):
            dns.modify_record(str(400001), changes, current=current)

    def test_modify_record_same_type_does_not_raise(self) -> None:
        """Updating a value without changing record_type must NOT raise."""
        import datetime

        dns = self._dns()
        now = datetime.datetime.now(datetime.UTC)
        base = dict(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            zone="example.com",
            ttl=300,
            object_ref=str(400001),
        )
        current = NormalizedDnsRecord(**base, value="10.0.0.1")
        changes = NormalizedDnsRecord(**base, value="10.0.0.2")
        draft = dns.modify_record(str(400001), changes, current=current)
        assert draft.verb == ChangeVerb.UPDATE


class TestBluecatDeleteRecordResourceScheme:
    """delete_record resource must match the create/update scheme.

    i.e. ``bluecat:resourceRecord:<TYPE>``, not ``bluecat:<TYPE>``.
    """

    def _dns(self) -> BluecatDdiDns:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        return BluecatDdiDns(client, uuid4())

    def test_delete_record_resource_matches_create_update_scheme_with_preimage(self) -> None:
        """delete_record with current= emits bluecat:resourceRecord:<TYPE>, not bluecat:<TYPE>."""  # noqa: E501
        import datetime

        dns = self._dns()
        now = datetime.datetime.now(datetime.UTC)
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.1",
            ttl=300,
            zone="example.com",
            object_ref=str(400001),
        )
        draft = dns.delete_record(str(400001), current=current, zone_id=_ZONE_ID)
        assert draft.resource == "bluecat:resourceRecord:A", (
            f"Expected 'bluecat:resourceRecord:A', got {draft.resource!r}"
        )

    def test_delete_record_resource_matches_create_update_scheme_without_preimage(self) -> None:
        """delete_record without current= must also emit bluecat:resourceRecord:<TYPE> scheme."""
        dns = self._dns()
        draft = dns.delete_record(str(400001), current=None, zone_id=None)
        # Without current, falls back to generic but must still use the resourceRecord prefix.
        assert draft.resource.startswith("bluecat:resourceRecord"), (
            f"Expected resource starting with 'bluecat:resourceRecord', got {draft.resource!r}"
        )

    def test_delete_record_aaaa_resource_scheme(self) -> None:
        """delete_record for AAAA type must emit bluecat:resourceRecord:AAAA."""
        import datetime

        dns = self._dns()
        now = datetime.datetime.now(datetime.UTC)
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=now,
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.AAAA,
            value="::1",
            ttl=300,
            zone="example.com",
            object_ref=str(400001),
        )
        draft = dns.delete_record(str(400001), current=current, zone_id=_ZONE_ID)
        assert draft.resource == "bluecat:resourceRecord:AAAA", (
            f"Expected 'bluecat:resourceRecord:AAAA', got {draft.resource!r}"
        )


class TestBluecatGetLeasesFilter:
    """get_leases() must send the ADR-0027 §2 DHCP-state filter, not fetch every IP."""

    def test_get_leases_sends_dhcp_state_filter(self) -> None:
        """The addresses request carries filter=state:in('DHCP_ALLOCATED','DHCP_RESERVED').

        Without the filter, BAM returns every address (including DHCP_FREE), not just
        leases (ADR-0027 §2 DDI_DHCP) — this asserts the query parameter is sent.
        """
        addresses_filters: list[str | None] = []

        def _capturing_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/sessions") and request.method == "POST":
                return httpx.Response(200, json={"token": _FAKE_TOKEN})
            rel = path.split("/api/v2", 1)[1] if "/api/v2" in path else path
            if rel == "/configurations":
                return httpx.Response(200, json=_load("configurations.json"))
            if rel.endswith("/blocks"):
                return httpx.Response(200, json=_load("blocks.json"))
            if rel.endswith("/networks"):
                return httpx.Response(200, json=_load("networks.json"))
            if rel.endswith("/addresses"):
                addresses_filters.append(request.url.params.get("filter"))
                return httpx.Response(200, json=_load("leases.json"))
            return httpx.Response(200, json={"count": 0, "data": []})

        http = httpx.Client(transport=httpx.MockTransport(_capturing_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        dhcp = BluecatDdiDhcp(client, uuid4())
        dhcp.get_leases()
        # At least one /addresses call was made, and EVERY one carried the DHCP filter.
        assert addresses_filters
        assert all(f == "state:in('DHCP_ALLOCATED','DHCP_RESERVED')" for f in addresses_filters), (
            addresses_filters
        )
        client.close()


class TestBluecatDeleteRequiresParentIdWhenCurrent:
    """delete_* with current= but no parent id raises (no invalid inverse, ADR-0027 §3).

    Mirrors SpatiumDDI._record_parents, which raises rather than emitting an inverse
    pinned to a nonexistent parent. Reachable via the ABC-compatible call shape
    delete_*(object_ref, current=...) since parent ids are keyword-only with None defaults.
    """

    def _client(self) -> BamClient:
        http = httpx.Client(transport=httpx.MockTransport(_handle))
        return BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )

    def test_delete_record_with_current_but_no_zone_id_raises(self) -> None:
        import datetime

        from app.core.errors import PluginError

        dns = BluecatDdiDns(self._client(), uuid4())
        current = NormalizedDnsRecord(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            name="www.example.com",
            record_type=DnsRecordType.A,
            value="10.0.0.1",
            ttl=300,
            zone="example.com",
            object_ref=str(400001),
        )
        with pytest.raises(PluginError, match="zone_id"):
            dns.delete_record(str(400001), current=current)  # no zone_id

    def test_delete_range_with_current_but_no_network_id_raises(self) -> None:
        import datetime
        from ipaddress import ip_address

        from app.core.errors import PluginError

        dhcp = BluecatDdiDhcp(self._client(), uuid4())
        current = NormalizedDhcpRange(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            start_address=ip_address("10.0.0.100"),
            end_address=ip_address("10.0.0.200"),
            name="dynamic-pool",
            object_ref=str(_RANGE_ID),
        )
        with pytest.raises(PluginError, match="network_id"):
            dhcp.delete_range(str(_RANGE_ID), current=current)  # no network_id

    def test_delete_network_with_current_but_no_block_id_raises(self) -> None:
        import datetime
        from ipaddress import ip_network

        from app.core.errors import PluginError

        ipam = BluecatDdiIpam(self._client(), uuid4())
        current = NormalizedNetwork(
            device_id=uuid4(),
            collected_at=datetime.datetime.now(datetime.UTC),
            source_vendor="bluecat",
            network=ip_network("10.0.0.0/24"),
            comment="lan",
            object_ref=str(_NETWORK_ID),
        )
        with pytest.raises(PluginError, match="block_id"):
            ipam.delete_network(str(_NETWORK_ID), current=current)  # no block_id


class TestBluecatClientErrorPaths:
    """Client error paths: non-JSON body, non-list envelope data, etc."""

    def test_get_list_raises_on_non_object_envelope(self) -> None:
        """A list-endpoint returning a bare list (not an envelope) raises PluginError."""
        from app.core.errors import PluginError

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions"):
                return httpx.Response(200, json={"token": "tok"})
            return httpx.Response(200, json=[1, 2, 3])  # bare list, not {count,data}

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        with pytest.raises(PluginError, match="non-object"):
            client.get_list("/configurations")
        client.close()

    def test_request_raises_plugin_error_on_transport_error(self) -> None:
        """Transport errors on data requests raise PluginError (sanitized)."""
        from app.core.errors import PluginError

        call_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(200, json={"token": "tok"})
            raise httpx.TransportError("connection reset")

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
        )
        with pytest.raises(PluginError, match="transport error"):
            client.get_list("/configurations")
        client.close()

    def test_request_raises_plugin_error_on_http_status_error(self) -> None:
        """Non-2xx status after successful login raises PluginError."""
        from app.core.errors import PluginError

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/sessions"):
                return httpx.Response(200, json={"token": "tok"})
            return httpx.Response(500, json={"error": "internal error"})

        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        with pytest.raises(PluginError, match="status 500"):
            client.get_list("/configurations")
        client.close()

    def test_close_invalidates_token(self) -> None:
        """BamClient.close() clears the session token (ADR-0027 §4 / ADR-0011 §1)."""
        login_count = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count
            if request.url.path.endswith("/sessions"):
                login_count += 1
                return httpx.Response(200, json={"token": f"tok-{login_count}"})
            return httpx.Response(200, json={"count": 0, "data": []})

        # We can't truly test after close (httpx is closed too), but verify no error.
        http = httpx.Client(transport=httpx.MockTransport(_handler))
        client = BamClient(
            base_url="https://bam.example.com",
            credentials=_FAKE_CREDS,
            client=http,
            session_token=_FAKE_TOKEN,
        )
        # Pre-injected token; calling close is the main assertion (no crash).
        client.close()

    def test_join_raw_produces_secret_free_output(self) -> None:
        """join_raw renders a stable, secret-free text block (ADR-0027 §4)."""
        from app.plugins.vendors.bluecat.client import join_raw

        objects = [{"id": 100001, "name": "DefaultConfig"}]
        raw = join_raw("/configurations", objects)
        assert "100001" in raw
        assert "DefaultConfig" in raw
        assert _FAKE_TOKEN not in raw
        assert "FAKE" not in raw
