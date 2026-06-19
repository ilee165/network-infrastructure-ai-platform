"""spatiumddi run through the reusable plugin conformance suite (ADR-0024 §5).

The platform's second API-based plugin certified against the shared suite
(after infoblox). Mirrors the infoblox conformance module: build a capability
factory wiring each capability to a :class:`SpatiumClient` over the bundled
source-derived fixtures (replayed via :class:`httpx.MockTransport` — no respx,
no network, D16), then parametrize over :func:`make_conformance_cases`. Each
DDI/discovery read method returns non-empty normalized records carrying
``source_vendor == "spatiumddi"``.

The only token anywhere in this module is the obviously-fake sentinel
``sddi_FAKE-token-zzz``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.plugins.base import PluginCapability
from app.plugins.vendors.spatiumddi.client import SpatiumClient, SpatiumCredentials
from app.plugins.vendors.spatiumddi.plugin import SpatiumContext, SpatiumddiPlugin
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

FIXTURES = Path(__file__).parent / "fixtures" / "spatiumddi"

_GROUP = "11111111-1111-1111-1111-111111111111"
_DHCP_GROUP = "88888888-8888-8888-8888-888888888888"
_SCOPE = "44444444-4444-4444-4444-444444444444"
_SERVER = "66666666-6666-6666-6666-666666666666"
_SPACE = "99999999-9999-9999-9999-999999999999"
_BLOCK = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

#: A clearly-fake bearer token — never a real secret.
_FAKE_TOKEN = "sddi_FAKE-token-zzz"  # noqa: S105 — obviously-fake test sentinel
_FAKE_CREDS = SpatiumCredentials(appliance_id="conformance", token=_FAKE_TOKEN)

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
    body: Any
    if path == "/ipam/subnets":
        body = _load("subnets.json")
    elif path == "/ipam/spaces":
        body = _load("spaces.json")
    elif path == "/ipam/blocks":
        body = _load("blocks.json")
    elif path == "/dns/groups":
        body = _load("groups.json")
    elif path.endswith("/records"):
        body = _load("records.json")
    elif path.endswith("/zones"):
        body = _load("zones.json")
    elif path.endswith("/pools"):
        body = _load("pools.json")
    elif path.endswith("/scopes"):
        body = _load("scopes.json")
    elif path.endswith("/leases"):
        body = _load("leases.json")
    elif path.endswith("/next-ip-preview"):
        body = _load("next_ip_preview.json")
    else:
        body = []
    return httpx.Response(200, json=body)


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    http = httpx.AsyncClient(transport=httpx.MockTransport(_handle))
    client = SpatiumClient(
        base_url="https://sddi.example.com",
        credentials=_FAKE_CREDS,
        client=http,
    )
    return impl(client, uuid4(), _CONTEXT)


CASES = make_conformance_cases(SpatiumddiPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_spatiumddi_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """Every declared capability has a typed interface in _INTERFACE_SPECS, so
    each must get both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in SpatiumddiPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
