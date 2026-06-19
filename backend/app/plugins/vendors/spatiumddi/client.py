"""SpatiumDDI REST client over async httpx (ADR-0024 §2, D7).

A thin, **async** client wrapping :mod:`httpx` against the SpatiumDDI REST API
(global prefix ``/api/v1``). It is used only inside the ``spatiumddi`` plugin
(ADR-0006 §6: vendor-private connectivity); engines and agents never see it.
Async by design — SpatiumDDI is an HTTP backend, so the capability layer awaits
these calls directly (contrast the netmiko/SNMP transports which are
synchronous and run inside Celery worker tasks, ADR-0007 §3).

Security posture (A9 / D11), parity with :class:`WapiClient`:

- The bearer token is a :class:`SpatiumCredentials` value materialized
  in-process from the vault (a ``credential_ref``, never a stored secret). It is
  held in a non-``repr`` field and pinned onto the httpx request ``Authorization``
  header only; it is **never** logged, never put into an exception message, never
  placed into a normalized record or a
  :class:`~app.plugins.base.ChangeRequestDraft`.
- TLS verification is **on by default**; ``verify`` is part of device connection
  config (the CA bundle path or ``True``/``False``).
- Read methods return the **raw decoded JSON payload verbatim** so the capability
  layer can record it via :meth:`PluginCapability._record_raw` *before* parsing
  into normalized models (ADR-0024 §2 raw-first).

Pagination (ADR-0024 §2): there is **no global cursor scheme**. Most list
endpoints return a bare ``list[...]`` and are single-shot. The only two paginated
endpoints are handled here: **lease-history** (page-number paging, ``per_page`` ≤
500) and **trash** (limit/offset paging, ``limit`` ≤ 1000); both are walked to
exhaustion and their ``items`` concatenated.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from app.core.errors import PluginError

__all__ = ["SpatiumClient", "SpatiumCredentials"]

#: SpatiumDDI mounts its v1 router under this global prefix (ADR-0024 §1).
_API_V1: Final = "/api/v1"

#: Hard server caps on the two paginated endpoints (ADR-0024 §2).
_MAX_PER_PAGE: Final = 500
_MAX_TRASH_LIMIT: Final = 1000

#: Accepted next-ip allocation strategies (ADR-0024 §1 ``next-ip-preview``).
_NEXT_IP_STRATEGIES: Final = frozenset({"sequential", "random", "eui64"})


@dataclass(frozen=True)
class SpatiumCredentials:
    """A SpatiumDDI bearer API token, materialized in-process from the vault (D11).

    The raw ``sddi_<token>`` is held in a non-``repr`` field so it never appears
    in a dataclass ``repr()``, a log line, a traceback frame dump, or a debugger
    display. Equality/hash deliberately exclude the secret too. SpatiumDDI mints
    user-scoped, resource-grantable tokens (``POST /api/v1/api-tokens``) and
    returns the raw value exactly once — we provision a least-privilege,
    resource-scoped token and pass only its ``credential_ref`` around; the raw
    token lives only here, inside the transport.
    """

    token: str = field(repr=False, compare=False)


class SpatiumClient:
    """Async SpatiumDDI REST client (one per device session).

    Parameters mirror the device connection config: the appliance ``base_url``
    (scheme + host[:port]; the ``/api/v1`` prefix is appended), the in-process
    :class:`SpatiumCredentials`, and the TLS ``verify`` setting. The bearer token
    is attached as a default ``Authorization`` header on the underlying client so
    it never appears in a per-call argument that might be logged.
    """

    def __init__(
        self,
        *,
        base_url: str,
        credentials: SpatiumCredentials,
        verify: bool | str = True,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._root = f"{base_url.rstrip('/')}{_API_V1}"
        # The token is pinned as a default header on the client only. Tests inject
        # an AsyncClient over a MockTransport; we still set the header on it so the
        # auth posture is identical to production.
        auth_header = {"Authorization": f"Bearer {credentials.token}"}
        if client is None:
            self._client = httpx.AsyncClient(headers=auth_header, verify=verify, timeout=timeout)
        else:
            self._client = client
            self._client.headers.update(auth_header)

    def __repr__(self) -> str:
        # Never echo the client (its default headers carry the token).
        return f"{type(self).__name__}(root={self._root!r})"

    # -- low-level verbs ----------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
        expect_json: bool = True,
    ) -> Any:
        """Issue one request and return the decoded JSON payload verbatim.

        On a non-2xx response or a transport error a typed :class:`PluginError`
        is raised whose message names only the verb + path + status — never the
        bearer token, the auth header, or the response body (which can echo
        request context). ``expect_json=False`` is used for ``204 No Content``
        deletes, which return ``None``.
        """
        op = f"{method} {path}"
        url = f"{self._root}{path}"
        try:
            response = await self._client.request(method, url, params=dict(params or {}), json=json)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"spatiumddi: {op} failed with status {exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            # Drop the original detail: an httpx error repr can carry the request
            # context. Re-raise with a sanitized, token-free message.
            raise PluginError(f"spatiumddi: {op} failed (transport error)") from None

        if not expect_json or response.status_code == httpx.codes.NO_CONTENT:
            return None
        return response.json()

    async def _get_list(self, path: str, *, params: Mapping[str, Any] | None = None) -> list[Any]:
        """GET a bare-list endpoint; reject a non-list payload (ADR-0024 §2)."""
        payload = await self._request("GET", path, params=params)
        if not isinstance(payload, list):
            raise PluginError(
                f"spatiumddi: GET {path} returned a non-list payload ({type(payload).__name__})"
            )
        return payload

    async def _request_obj(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
    ) -> dict[str, Any]:
        """Issue a request expecting a single JSON object; reject a non-object."""
        payload = await self._request(method, path, params=params, json=json)
        if not isinstance(payload, dict):
            raise PluginError(
                f"spatiumddi: {method} {path} returned a non-object payload "
                f"({type(payload).__name__})"
            )
        return payload

    # -- DNS (DDI_DNS) ------------------------------------------------------

    async def get_zones(self, group_id: str) -> list[dict[str, Any]]:
        """GET the authoritative zones of a DNS server group (bare list)."""
        return await self._get_list(f"/dns/groups/{group_id}/zones")

    async def get_records(self, group_id: str, zone_id: str) -> list[dict[str, Any]]:
        """GET the resource records of a zone (bare list)."""
        return await self._get_list(f"/dns/groups/{group_id}/zones/{zone_id}/records")

    async def add_record(
        self, group_id: str, zone_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        """POST a ``RecordCreate``; returns the created ``RecordResponse``."""
        return await self._request_obj(
            "POST", f"/dns/groups/{group_id}/zones/{zone_id}/records", json=dict(body)
        )

    async def modify_record(
        self, group_id: str, zone_id: str, record_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        """PUT a ``RecordUpdate`` (``record_type`` is immutable server-side)."""
        return await self._request_obj(
            "PUT",
            f"/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}",
            json=dict(body),
        )

    async def delete_record(
        self,
        group_id: str,
        zone_id: str,
        record_id: str,
        *,
        permanent: bool = False,
    ) -> None:
        """DELETE a record. SOFT by default (``permanent=false``, ADR-0024 §1)."""
        await self._request(
            "DELETE",
            f"/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}",
            params={"permanent": "true" if permanent else "false"},
            expect_json=False,
        )

    # -- DHCP (DDI_DHCP) ----------------------------------------------------

    async def get_pools(self, scope_id: str) -> list[dict[str, Any]]:
        """GET the dynamic pools (== Infoblox ranges) of a scope (bare list)."""
        return await self._get_list(f"/dhcp/scopes/{scope_id}/pools")

    async def add_pool(self, scope_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """POST a ``PoolCreate``; returns the created ``PoolResponse``."""
        return await self._request_obj("POST", f"/dhcp/scopes/{scope_id}/pools", json=dict(body))

    async def delete_pool(self, pool_id: str) -> None:
        """DELETE a pool — a HARD delete (no trash row; ADR-0024 §1/§3)."""
        await self._request("DELETE", f"/dhcp/pools/{pool_id}", expect_json=False)

    async def get_leases(self, server_id: str) -> list[dict[str, Any]]:
        """GET the live leases of a DHCP server (bare list)."""
        return await self._get_list(f"/dhcp/servers/{server_id}/leases")

    async def get_lease_history(
        self,
        server_id: str,
        *,
        per_page: int = _MAX_PER_PAGE,
        params: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Walk the page-numbered lease-history endpoint and concatenate items.

        Page-number paging (``page``/``per_page`` ≤ 500, ADR-0024 §2). All pages
        are fetched in order until the accumulated count reaches ``total``.
        """
        if not 1 <= per_page <= _MAX_PER_PAGE:
            raise PluginError(f"spatiumddi: per_page must be 1..{_MAX_PER_PAGE}")
        rows: list[dict[str, Any]] = []
        page = 1
        while True:
            query: dict[str, Any] = {**dict(params or {}), "page": page, "per_page": per_page}
            payload = await self._request(
                "GET", f"/dhcp/servers/{server_id}/lease-history", params=query
            )
            items = payload.get("items", []) if isinstance(payload, Mapping) else []
            rows.extend(items)
            total = payload.get("total", len(rows)) if isinstance(payload, Mapping) else len(rows)
            if not items or len(rows) >= total:
                break
            page += 1
        return rows

    # -- IPAM (DDI_IPAM) ----------------------------------------------------

    async def get_subnets(self, *, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """GET IPAM subnets (== networks), optionally filtered (bare list)."""
        return await self._get_list("/ipam/subnets", params=params)

    async def add_subnet(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """POST a ``SubnetCreate``; returns the created ``SubnetResponse``."""
        return await self._request_obj("POST", "/ipam/subnets", json=dict(body))

    async def delete_subnet(self, subnet_id: str) -> None:
        """DELETE a subnet — a SOFT delete (recoverable from trash, ADR-0024 §3)."""
        await self._request("DELETE", f"/ipam/subnets/{subnet_id}", expect_json=False)

    async def next_ip_preview(
        self,
        subnet_id: str,
        *,
        strategy: str = "sequential",
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        """GET the read-only next-IP preview (no allocation; ADR-0024 §1).

        ``strategy`` ∈ {sequential, random, eui64}; returns
        ``NextIPPreview{address|None, strategy}`` (``address=None`` ⇒ full /
        IPv6-unsupported). This is a peek — the committing allocator
        (``POST .../next``) is a separate write surfaced only as a draft.
        """
        if strategy not in _NEXT_IP_STRATEGIES:
            raise PluginError(f"spatiumddi: strategy must be one of {sorted(_NEXT_IP_STRATEGIES)}")
        params: dict[str, Any] = {"strategy": strategy}
        if mac_address is not None:
            params["mac_address"] = mac_address
        return await self._request_obj(
            "GET", f"/ipam/subnets/{subnet_id}/next-ip-preview", params=params
        )

    # -- admin / trash (soft-delete rollback inverse) -----------------------

    async def list_trash(
        self,
        *,
        type_: str | None = None,
        limit: int = _MAX_TRASH_LIMIT,
        params: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Walk the limit/offset-paged trash listing and concatenate items.

        Limit/offset paging (``limit`` ≤ 1000, ADR-0024 §2). Pages are fetched in
        order until the accumulated count reaches ``total``.
        """
        if not 1 <= limit <= _MAX_TRASH_LIMIT:
            raise PluginError(f"spatiumddi: limit must be 1..{_MAX_TRASH_LIMIT}")
        base: dict[str, Any] = dict(params or {})
        if type_ is not None:
            base["type"] = type_
        rows: list[dict[str, Any]] = []
        offset = 0
        while True:
            query = {**base, "limit": limit, "offset": offset}
            payload = await self._request("GET", "/admin/trash", params=query)
            items = payload.get("items", []) if isinstance(payload, Mapping) else []
            rows.extend(items)
            total = payload.get("total", len(rows)) if isinstance(payload, Mapping) else len(rows)
            if not items or len(rows) >= total:
                break
            offset += limit
        return rows

    async def restore_trash(self, type_: str, row_id: str) -> dict[str, Any]:
        """POST the RESTORE inverse of a soft-delete (atomic per batch, ADR-0024 §3).

        ``type_`` ∈ ``SOFT_DELETE_RESOURCE_TYPES``; returns
        ``RestoreResponse{batch_id, restored}``. A ``409`` (active-row clash) is
        surfaced as a sanitized :class:`PluginError`.
        """
        return await self._request_obj("POST", f"/admin/trash/{type_}/{row_id}/restore")

    # -- lifecycle ----------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying async httpx client."""
        await self._client.aclose()

    async def __aenter__(self) -> SpatiumClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
