"""Integrations matrix endpoint (Path B / T2.1): ``GET /api/v1/integrations``.

Invariants:

- Admin-only (viewer/operator/engineer → 403; unauthenticated → 401).
- Response lists registered vendors with display names, sorted capabilities,
  and static category tags — never secrets or connection params.
- Empty-safe shape: always ``{"vendors": [...]}``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

INTEGRATIONS_URL = "/api/v1/integrations"

_SECRET_FIELD_HINTS = (
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "endpoint",
    "credential",
    "vault",
)


def _assert_no_secret_keys(payload: object) -> None:
    if isinstance(payload, dict):
        for field, value in payload.items():
            lowered = str(field).lower()
            assert not any(hint in lowered for hint in _SECRET_FIELD_HINTS), field
            _assert_no_secret_keys(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_no_secret_keys(item)


@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_integrations_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(INTEGRATIONS_URL, headers=auth_headers(role))
    assert resp.status_code == 403


async def test_integrations_unauthenticated_is_401(client, users) -> None:
    resp = await client.get(INTEGRATIONS_URL)
    assert resp.status_code == 401


async def test_integrations_admin_lists_registered_vendors(
    client, users, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.get(INTEGRATIONS_URL, headers=auth_headers("admin"))
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    assert "vendors" in body
    vendors = body["vendors"]
    assert isinstance(vendors, list)
    assert len(vendors) >= 1

    by_id = {row["vendor_id"]: row for row in vendors}
    # Built-in reference plugin always present via get_default_registry().
    assert "cisco_ios" in by_id
    ios = by_id["cisco_ios"]
    assert ios["display_name"]
    assert isinstance(ios["capabilities"], list)
    assert ios["capabilities"] == sorted(ios["capabilities"])
    assert ios["category"] in {"network", "ddi", "virt", "adc", "cloud", "other"}

    # Vendors are sorted by vendor_id (registry.vendor_ids()).
    ids = [row["vendor_id"] for row in vendors]
    assert ids == sorted(ids)
