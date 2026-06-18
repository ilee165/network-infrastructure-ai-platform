"""infoblox run through the reusable plugin conformance suite (ADR-0022 §4).

The first API-based plugin certified against the shared suite. Mirrors the
IOS/IOS-XE/EOS conformance modules: build a capability factory wiring each
capability to a :class:`WapiClient` over the bundled recorded WAPI fixtures
(replayed via :class:`httpx.MockTransport` — no respx, no network, D16), then
parametrize over :func:`make_conformance_cases`. Each DDI/discovery read method
returns non-empty normalized records carrying ``source_vendor == "infoblox"``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.plugins.base import PluginCapability
from app.plugins.vendors.infoblox.plugin import InfobloxPlugin
from app.plugins.vendors.infoblox.wapi import WapiClient, WapiCredentials
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

FIXTURES = Path(__file__).parent / "fixtures" / "infoblox"

_OBJTYPE_FIXTURE = {
    "network": "network.json",
    "zone_auth": "zone_auth.json",
    "member": "member.json",
    "record:a": "record_a.json",
    "record:cname": "record_cname.json",
    "range": "range.json",
    "lease": "lease.json",
}

#: Clearly-fake credential — never a real secret.
_FAKE_CREDS = WapiCredentials(username="admin", password="FAKE-w@pi-pw-zzz")


def _load(objtype: str) -> list[dict[str, Any]]:
    filename = _OBJTYPE_FIXTURE.get(objtype)
    if filename is None:
        return []
    return json.loads((FIXTURES / filename).read_text(encoding="utf-8"))


def _handle(request: httpx.Request) -> httpx.Response:
    objtype = request.url.path.split("/wapi/", 1)[1].split("/", 1)[1]
    return httpx.Response(200, json=_load(objtype))


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    http = httpx.Client(transport=httpx.MockTransport(_handle))
    client = WapiClient(
        base_url="https://gm.example.com",
        version="2.12",
        credentials=_FAKE_CREDS,
        client=http,
    )
    return impl(client, uuid4())


CASES = make_conformance_cases(InfobloxPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_infoblox_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """Every declared capability has a typed interface in _INTERFACE_SPECS, so
    each must get both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in InfobloxPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
