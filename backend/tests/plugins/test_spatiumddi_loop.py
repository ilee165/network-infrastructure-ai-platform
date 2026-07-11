"""Wave-2 regression: SpatiumDDI session reuses one event loop across capability calls (H9)."""
from __future__ import annotations

from uuid import uuid4

import httpx

from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials
from app.plugins.vendors.spatiumddi.plugin import SpatiumContext, SpatiumDiscoveryApi

_FAKE = SpatiumCredentials(appliance_id="test", token="sddi_FAKE-token-zzz")  # noqa: S105


def test_two_sequential_capability_calls_share_live_loop() -> None:
    """Two sequential _run invocations must not hit a dead-loop RuntimeError.

    Sync test (no outer pytest-asyncio loop) so the session loop is the only
    running loop — mirrors production discovery-runner / conformance callers.
    """
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=[])

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = SpatiumClient(base_url="https://sddi.example.com", credentials=_FAKE, client=http)
    cap = SpatiumDiscoveryApi(client, uuid4(), SpatiumContext())

    # Sync capability path: two sequential _run calls (fresh asyncio.run was the bug).
    cap.discover()
    first_loop = cap._loop
    cap.discover()
    assert calls["n"] >= 2
    # Same private loop reused across calls (not a new dead loop).
    assert cap._loop is first_loop
    assert cap._loop is not None and not cap._loop.is_closed()
    cap._loop.run_until_complete(client.aclose())
