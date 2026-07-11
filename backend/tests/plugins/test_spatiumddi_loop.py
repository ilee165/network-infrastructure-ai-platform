"""Wave-2 regression: SpatiumDDI client owns one event loop for all capabilities (H9)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

import httpx

from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials
from app.plugins.vendors.spatiumddi.plugin import (
    SpatiumContext,
    SpatiumDdiDns,
    SpatiumDiscoveryApi,
)

_FAKE = SpatiumCredentials(appliance_id="test", token="sddi_FAKE-token-zzz")  # noqa: S105


def _client_with_handler(
    handler: Callable[[httpx.Request], httpx.Response],
) -> SpatiumClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return SpatiumClient(base_url="https://sddi.example.com", credentials=_FAKE, client=http)


def test_two_sequential_capability_calls_share_live_loop() -> None:
    """Two sequential _run invocations on one capability reuse the client loop."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=[])

    client = _client_with_handler(handler)
    cap = SpatiumDiscoveryApi(client, uuid4(), SpatiumContext())

    cap.discover()
    first_loop = client._loop
    cap.discover()
    assert calls["n"] >= 2
    assert client._loop is first_loop
    assert client._loop is not None and not client._loop.is_closed()
    cap.close()
    assert client._loop is None


def test_two_capability_classes_share_client_loop() -> None:
    """DNS + Discovery over one client must share the same loop (not per-cap)."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=[])

    client = _client_with_handler(handler)
    device_id = uuid4()
    ctx = SpatiumContext()
    discovery = SpatiumDiscoveryApi(client, device_id, ctx)
    dns = SpatiumDdiDns(client, device_id, ctx)

    discovery.discover()
    loop_after_discovery = client._loop
    # Empty group list → get_zones still enters _run and reuses the client loop.
    dns.get_zones()
    assert client._loop is loop_after_discovery
    assert calls["n"] >= 1
    client.close_sync()
    assert client._loop is None
