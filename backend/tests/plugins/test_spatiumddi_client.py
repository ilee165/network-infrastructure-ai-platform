"""Unit tests for the SpatiumDDI async httpx REST client (ADR-0024 §2).

httpx is mocked with :class:`httpx.MockTransport` (no respx dependency, no
network — parity with the Infoblox client tests): every test wires the
:class:`SpatiumClient` to an in-memory transport so the auth-header posture,
the two paginated endpoints (lease-history page/per_page, trash limit/offset),
the raw-first return shape, and the no-token-leak guarantee are exercised
without a running SpatiumDDI instance.

The only token anywhere in this module is the obviously-fake sentinel
``sddi_FAKE-token-zzz``; no test fixture carries a real secret.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import httpx
import pytest

from app.core.errors import PluginError
from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials

#: A clearly-fake bearer token — never a real secret. A distinctive sentinel so
#: a leak assertion cannot collide with any path segment or host in the mocks.
_FAKE_TOKEN = "sddi_FAKE-token-zzz"  # noqa: S105 — obviously-fake test sentinel
_FAKE_CREDS = SpatiumCredentials(token=_FAKE_TOKEN)

_GROUP = "11111111-1111-1111-1111-111111111111"
_ZONE = "22222222-2222-2222-2222-222222222222"
_RECORD = "33333333-3333-3333-3333-333333333333"
_SCOPE = "44444444-4444-4444-4444-444444444444"
_POOL = "55555555-5555-5555-5555-555555555555"
_SERVER = "66666666-6666-6666-6666-666666666666"
_SUBNET = "77777777-7777-7777-7777-777777777777"


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> SpatiumClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    return SpatiumClient(
        base_url="https://sddi.example.com",
        credentials=_FAKE_CREDS,
        client=http,
    )


def _record_handler(
    seen: list[httpx.Request] | None = None,
    *,
    status: int = 200,
    json_body: object = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Build a MockTransport handler capturing requests and replaying a body."""

    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=[] if json_body is None else json_body)

    return handle


class TestAuthHeader:
    async def test_every_request_carries_bearer_token(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_zones(_GROUP)
        assert seen, "no request was issued"
        assert seen[0].headers["Authorization"] == f"Bearer {_FAKE_TOKEN}"

    async def test_base_url_carries_api_v1_prefix(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_subnets()
        assert seen[0].url.path == "/api/v1/ipam/subnets"


class TestDnsEndpoints:
    async def test_get_zones_returns_raw_list(self) -> None:
        body = [{"id": _ZONE, "name": "example.com"}]
        client = _client(_record_handler(json_body=body))
        out = await client.get_zones(_GROUP)
        assert out == body

    async def test_get_zones_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_zones(_GROUP)
        assert seen[0].method == "GET"
        assert seen[0].url.path == f"/api/v1/dns/groups/{_GROUP}/zones"

    async def test_get_records_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_records(_GROUP, _ZONE)
        assert seen[0].url.path == f"/api/v1/dns/groups/{_GROUP}/zones/{_ZONE}/records"

    async def test_add_record_posts_body_and_returns_payload(self) -> None:
        seen: list[httpx.Request] = []
        created = {"id": _RECORD, "name": "web", "record_type": "A", "value": "10.0.0.5"}
        client = _client(_record_handler(seen, status=201, json_body=created))
        out = await client.add_record(
            _GROUP, _ZONE, {"name": "web", "record_type": "A", "value": "10.0.0.5"}
        )
        assert out == created
        assert seen[0].method == "POST"
        assert seen[0].url.path == f"/api/v1/dns/groups/{_GROUP}/zones/{_ZONE}/records"

    async def test_modify_record_puts_to_record_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, json_body={"id": _RECORD}))
        await client.modify_record(_GROUP, _ZONE, _RECORD, {"value": "10.0.0.9"})
        assert seen[0].method == "PUT"
        assert seen[0].url.path == (f"/api/v1/dns/groups/{_GROUP}/zones/{_ZONE}/records/{_RECORD}")

    async def test_delete_record_is_soft_by_default(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=204))
        await client.delete_record(_GROUP, _ZONE, _RECORD)
        assert seen[0].method == "DELETE"
        # SOFT-delete by default: permanent=false (ADR-0024 §1).
        assert seen[0].url.params.get("permanent") == "false"

    async def test_delete_record_permanent_flag(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=204))
        await client.delete_record(_GROUP, _ZONE, _RECORD, permanent=True)
        assert seen[0].url.params.get("permanent") == "true"


class TestDhcpEndpoints:
    async def test_get_pools_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_pools(_SCOPE)
        assert seen[0].url.path == f"/api/v1/dhcp/scopes/{_SCOPE}/pools"

    async def test_add_pool_posts_body(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=201, json_body={"id": _POOL}))
        out = await client.add_pool(_SCOPE, {"name": "dyn"})
        assert out == {"id": _POOL}
        assert seen[0].method == "POST"

    async def test_delete_pool_is_hard(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=204))
        await client.delete_pool(_POOL)
        assert seen[0].method == "DELETE"
        assert seen[0].url.path == f"/api/v1/dhcp/pools/{_POOL}"
        # Hard delete: no permanent query param (ADR-0024 §1).
        assert "permanent" not in seen[0].url.params

    async def test_get_leases_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen))
        await client.get_leases(_SERVER)
        assert seen[0].url.path == f"/api/v1/dhcp/servers/{_SERVER}/leases"


class TestLeaseHistoryPagination:
    async def test_follows_page_number_pagination(self) -> None:
        seen: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            page = int(request.url.params["page"])
            if page == 1:
                return httpx.Response(
                    200,
                    json={
                        "total": 3,
                        "page": 1,
                        "per_page": 2,
                        "items": [{"id": "a"}, {"id": "b"}],
                    },
                )
            return httpx.Response(
                200,
                json={"total": 3, "page": 2, "per_page": 2, "items": [{"id": "c"}]},
            )

        client = _client(handle)
        rows = await client.get_lease_history(_SERVER, per_page=2)
        # All pages walked, items concatenated in order.
        assert [r["id"] for r in rows] == ["a", "b", "c"]
        assert [int(r.url.params["page"]) for r in seen] == [1, 2]
        assert all(int(r.url.params["per_page"]) == 2 for r in seen)

    async def test_per_page_capped_at_500(self) -> None:
        with pytest.raises(PluginError, match="per_page"):
            client = _client(_record_handler())
            await client.get_lease_history(_SERVER, per_page=501)


class TestTrashPaginationAndRestore:
    async def test_list_trash_follows_limit_offset(self) -> None:
        seen: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            offset = int(request.url.params.get("offset", "0"))
            if offset == 0:
                return httpx.Response(200, json={"total": 3, "items": [{"id": "a"}, {"id": "b"}]})
            return httpx.Response(200, json={"total": 3, "items": [{"id": "c"}]})

        client = _client(handle)
        rows = await client.list_trash(limit=2)
        assert [r["id"] for r in rows] == ["a", "b", "c"]
        assert [int(r.url.params["offset"]) for r in seen] == [0, 2]

    async def test_limit_capped_at_1000(self) -> None:
        with pytest.raises(PluginError, match="limit"):
            client = _client(_record_handler())
            await client.list_trash(limit=1001)

    async def test_restore_posts_to_typed_path(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, json_body={"batch_id": "b1", "restored": 1}))
        out = await client.restore_trash("dns_record", _RECORD)
        assert out == {"batch_id": "b1", "restored": 1}
        assert seen[0].method == "POST"
        assert seen[0].url.path == f"/api/v1/admin/trash/dns_record/{_RECORD}/restore"


class TestIpamEndpoints:
    async def test_get_subnets_returns_raw_list(self) -> None:
        body = [{"id": _SUBNET, "network": "10.0.0.0/24"}]
        client = _client(_record_handler(json_body=body))
        assert await client.get_subnets() == body

    async def test_add_subnet_posts_body(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=201, json_body={"id": _SUBNET}))
        await client.add_subnet({"space_id": "s", "block_id": "b", "network": "10.0.0.0/24"})
        assert seen[0].method == "POST"
        assert seen[0].url.path == "/api/v1/ipam/subnets"

    async def test_delete_subnet_is_soft(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(_record_handler(seen, status=204))
        await client.delete_subnet(_SUBNET)
        assert seen[0].method == "DELETE"
        assert seen[0].url.path == f"/api/v1/ipam/subnets/{_SUBNET}"

    async def test_next_ip_preview_passes_strategy(self) -> None:
        seen: list[httpx.Request] = []
        client = _client(
            _record_handler(seen, json_body={"address": "10.0.0.7", "strategy": "sequential"})
        )
        out = await client.next_ip_preview(_SUBNET, strategy="sequential")
        assert out == {"address": "10.0.0.7", "strategy": "sequential"}
        assert seen[0].url.path == f"/api/v1/ipam/subnets/{_SUBNET}/next-ip-preview"
        assert seen[0].url.params.get("strategy") == "sequential"

    async def test_next_ip_preview_rejects_unknown_strategy(self) -> None:
        with pytest.raises(PluginError, match="strategy"):
            client = _client(_record_handler())
            await client.next_ip_preview(_SUBNET, strategy="bogus")


class TestErrorSanitization:
    async def test_non_2xx_raises_plugin_error_without_token(self) -> None:
        def boom(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"detail": "invalid token"})

        client = _client(boom)
        with pytest.raises(PluginError) as excinfo:
            await client.get_zones(_GROUP)
        message = str(excinfo.value)
        assert "401" in message
        # The sanitized message names the operation + status but never the token
        # nor the response body (which can echo request context).
        assert _FAKE_TOKEN not in message
        assert "invalid token" not in message

    async def test_transport_error_is_sanitized(self) -> None:
        def boom(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connect failed")

        client = _client(boom)
        with pytest.raises(PluginError) as excinfo:
            await client.get_subnets()
        assert _FAKE_TOKEN not in str(excinfo.value)

    async def test_non_list_payload_rejected_for_list_endpoint(self) -> None:
        client = _client(_record_handler(json_body={"not": "a list"}))
        with pytest.raises(PluginError, match="non-list"):
            await client.get_subnets()


class TestNoTokenLeak:
    def test_token_not_in_credentials_repr(self) -> None:
        assert _FAKE_TOKEN not in repr(_FAKE_CREDS)

    def test_token_not_in_client_repr(self) -> None:
        client = _client(_record_handler())
        assert _FAKE_TOKEN not in repr(client)

    async def test_token_never_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        seen: list[httpx.Request] = []
        with caplog.at_level(logging.DEBUG):
            client = _client(_record_handler(seen))
            await client.get_zones(_GROUP)
            with pytest.raises(PluginError):
                err = _client(lambda _r: httpx.Response(500, json={"detail": "boom"}))
                await err.get_zones(_GROUP)
        assert _FAKE_TOKEN not in caplog.text
