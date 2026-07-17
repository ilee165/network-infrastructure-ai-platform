"""BlueCat Address Manager (BAM) HTTP client over httpx (ADR-0027 §4, D7).

A thin, synchronous client wrapping :mod:`httpx` against the BAM RESTful v2
API (global prefix ``/api/v2``). It is used only inside the ``bluecat``
plugin (ADR-0006 §6: vendor-private connectivity); engines and agents never see
it. Synchronous by design — capability methods run inside Celery worker tasks,
never on the FastAPI event loop (ADR-0007 §3).

Security posture (A9 / D11), parity with :class:`WapiClient` / :class:`SpatiumClient`:

- The BAM API-user **password** is materialized in-process from the vault
  (a ``credential_ref``, never a stored secret). The :class:`BamCredentials`
  dataclass holds it in a non-``repr`` field so it never appears in repr(),
  a log line, a traceback frame dump, or a debugger display.
- BAM v2 mints a **session token** via ``POST /api/v2/sessions``; the token is
  held only in process memory and is **never** logged, never put into an
  exception message, and never placed into a normalized record or a
  :class:`~app.plugins.base.ChangeRequestDraft`. :meth:`__repr__` deliberately
  omits the token (ADR-0027 §4).
- **Auth-token header form:** BAM v2 documentation describes the session token
  header but the exact encoding (RFC 7617 ``Authorization: Basic <base64(token:)>``
  vs. proprietary ``BAMAuthToken <token>``) is deferred-accepted pending live-
  appliance verification (ADR-0027 §7). This implementation uses the proprietary
  ``BAMAuthToken <token>`` header form and documents the open item in §7; the
  conformance suite injects the token directly (``session_token`` param) so
  fixture tests pass without a real appliance.
- **Session re-auth:** on a ``401`` response the client re-issues
  ``POST /api/v2/sessions`` exactly once (retry-once re-auth, ADR-0027 §4) and
  retries the original request.  The exact TTL and whether this is sufficient for
  multi-configuration discovery fan-outs is an open §7 item.
- TLS verification is **on by default**; ``verify`` is part of device connection
  config (the appliance CA bundle path or ``True``/``False``).
- Read methods return the **raw decoded JSON payload verbatim** so the capability
  layer can record it via ``PluginCapability._record_raw`` *before* parsing into
  normalized models (ADR-0027 §4 raw-first).

Pagination (ADR-0027 §4): BAM v2 list endpoints use ``offset``/``limit``
OData-style paging and return ``{count, data[...]}`` envelopes. :meth:`list`
accumulates pages until the total ``count`` is reached.
"""

from __future__ import annotations

import json as _json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.errors import PluginError

__all__ = ["BamClient", "BamCredentials"]

#: BAM RESTful v2 global prefix (ADR-0027 §2, §4).
_API_V2 = "/api/v2"

#: Default page size for list endpoints.  BAM's actual default is unspecified
#: pending live-appliance verification (ADR-0027 §7); 100 is a safe starting
#: point that keeps page counts low while avoiding oversized requests.
_DEFAULT_PAGE_SIZE = 100


@dataclass(frozen=True)
class BamCredentials:
    """BAM API-user username + password, materialized in-process from the vault (D11).

    The password is held in a non-``repr`` field so it never appears in a
    dataclass ``repr()``, a log line, a traceback frame dump, or a debugger
    display. Equality/hash deliberately exclude the secret too (parity with
    :class:`~app.plugins.vendors.infoblox.wapi.WapiCredentials`).
    """

    username: str
    password: str = field(repr=False, compare=False)


class BamClient:
    """Synchronous BAM RESTful v2 client (one per device session).

    Parameters mirror the device connection config: the appliance ``base_url``
    (scheme + host[:port]; ``/api/v2`` is appended), the in-process
    :class:`BamCredentials`, and the TLS ``verify`` setting. A ``session_token``
    may be injected directly (test path) to skip the login round-trip.

    The session token is obtained via ``POST /api/v2/sessions`` and presented
    as ``BAMAuthToken <token>`` on subsequent requests (ADR-0027 §4 open item;
    deferred-accepted pending live-appliance verification of the exact header
    form). The token is **never** logged or repr'd.
    """

    def __init__(
        self,
        *,
        base_url: str,
        credentials: BamCredentials,
        verify: bool | str = True,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        session_token: str | None = None,
    ) -> None:
        self._root = f"{base_url.rstrip('/')}{_API_V2}"
        self._credentials = credentials
        self._client = client or httpx.Client(verify=verify, timeout=timeout)
        # Hold the token in a name-mangled slot; repr() and public attrs never
        # expose it (ADR-0027 §4 / ADR-0011 §1).
        self.__token: str | None = session_token

    def __repr__(self) -> str:
        # Deliberately omit the session token — it is a bearer credential.
        return f"{type(self).__name__}(root={self._root!r})"

    # ------------------------------------------------------------------
    # Session management (ADR-0027 §4)
    # ------------------------------------------------------------------

    def _login(self) -> None:
        """Obtain a BAM session token via POST /api/v2/sessions.

        The username and password are passed as JSON; the response carries the
        token that subsequent requests present as ``BAMAuthToken <token>``.
        The token is **never** logged or placed into an exception message.
        """
        url = f"{self._root}/sessions"
        try:
            response = self._client.post(
                url,
                json={
                    "username": self._credentials.username,
                    "password": self._credentials.password,
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"bluecat: session login failed with status {exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            raise PluginError("bluecat: session login failed (transport error)") from None

        try:
            payload = response.json()
        except _json.JSONDecodeError:
            raise PluginError("bluecat: session login response was not JSON") from None

        # The token may arrive as a JSON field or as a response header
        # (exact form is an ADR-0027 §7 open item); try both.
        token: str | None = None
        if isinstance(payload, dict):
            token = payload.get("token") or payload.get("apiToken")
        if not token:
            token = response.headers.get("BAMAuthToken") or response.headers.get("Authorization")
        if not token:
            raise PluginError("bluecat: session login response did not contain a token") from None
        self.__token = token

    def _ensure_token(self) -> str:
        """Return the current session token, logging in if not yet obtained."""
        if self.__token is None:
            self._login()
        assert self.__token is not None  # noqa: S101 — _login sets it or raises
        return self.__token

    def _auth_headers(self) -> dict[str, str]:
        """Build the request auth header (ADR-0027 §4 open item — BAMAuthToken form)."""
        return {"BAMAuthToken": self._ensure_token()}

    # ------------------------------------------------------------------
    # Core HTTP verbs
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        expect_json: bool = True,
        _retry_auth: bool = True,
    ) -> Any:
        """Issue one request and return the decoded JSON payload verbatim.

        On a ``401`` response, re-issues ``POST /api/v2/sessions`` exactly once
        (retry-once re-auth, ADR-0027 §4) and retries the original request.
        On a non-2xx response or transport error a typed :class:`PluginError`
        is raised whose message names only the verb + path + status — never the
        session token, the auth header, or the response body.
        """
        op = f"{method} {path}"
        url = f"{self._root}{path}"
        try:
            response = self._client.request(
                method,
                url,
                params=dict(params or {}),
                json=dict(body) if body else None,
                headers=self._auth_headers(),
            )
        except httpx.HTTPError:
            raise PluginError(f"bluecat: {op} failed (transport error)") from None

        # Retry-once re-auth on 401 (ADR-0027 §4).
        if response.status_code == httpx.codes.UNAUTHORIZED and _retry_auth:
            self.__token = None  # force re-login
            return self._request(
                method, path, params=params, body=body, expect_json=expect_json, _retry_auth=False
            )

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"bluecat: {op} failed with status {exc.response.status_code}"
            ) from None

        if not expect_json or response.status_code == httpx.codes.NO_CONTENT:
            return None
        try:
            return response.json()
        except Exception:
            raise PluginError(
                f"bluecat: {op} returned a non-JSON body (status {response.status_code})"
            ) from None

    def _get_envelope(
        self, path: str, *, params: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """GET a paged envelope ``{count, data[...]}``. Validates the shape."""
        payload = self._request("GET", path, params=params)
        if not isinstance(payload, dict):
            raise PluginError(
                f"bluecat: GET {path} returned a non-object payload ({type(payload).__name__})"
            )
        return payload

    # ------------------------------------------------------------------
    # Pagination (ADR-0027 §4 offset/limit loop)
    # ------------------------------------------------------------------

    def get_list(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        page_size: int = _DEFAULT_PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """GET a BAM v2 list endpoint, accumulating all pages.

        BAM v2 list endpoints return ``{count, data[...]}`` envelopes with
        ``offset``/``limit`` OData paging (ADR-0027 §4). Pages are fetched
        until the accumulated count reaches ``total``.

        Returns the concatenated ``data`` list verbatim (raw-first; the caller
        records it before parsing, ADR-0027 §4).
        """
        base: dict[str, Any] = dict(params or {})
        rows: list[dict[str, Any]] = []
        offset = 0
        while True:
            query = {**base, "offset": offset, "limit": page_size}
            envelope = self._get_envelope(path, params=query)
            total = envelope.get("count", 0)
            data = envelope.get("data", [])
            if not isinstance(data, list):
                raise PluginError(
                    f"bluecat: GET {path} envelope 'data' is not a list ({type(data).__name__})"
                )
            rows.extend(data)
            if not data or len(rows) >= total:
                break
            offset += len(data)
        return rows

    # ------------------------------------------------------------------
    # DNS (DDI_DNS + DISCOVERY_API) — endpoint ↔ capability (ADR-0027 §2)
    # ------------------------------------------------------------------

    def get_zones(
        self, view_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET zones of a view (ADR-0027 §2 DDI_DNS.get_zones)."""
        return self.get_list(f"/views/{view_id}/zones", params=params)

    def get_records(
        self, zone_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET resource records of a zone (ADR-0027 §2 DDI_DNS.get_records)."""
        return self.get_list(f"/zones/{zone_id}/resourceRecords", params=params)

    # ------------------------------------------------------------------
    # IPAM (DDI_IPAM + DISCOVERY_API)
    # ------------------------------------------------------------------

    def get_blocks(
        self, config_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET IPv4 blocks under a configuration (ADR-0027 §2 DDI_IPAM)."""
        return self.get_list(f"/configurations/{config_id}/blocks", params=params)

    def get_networks(
        self, block_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET IPv4 networks under a block (ADR-0027 §2 DDI_IPAM.get_networks)."""
        return self.get_list(f"/blocks/{block_id}/networks", params=params)

    def get_next_available_ip(self, network_id: int) -> dict[str, Any]:
        """GET the next available IPv4 address for a network (server-side peek).

        Uses the BAM server-function ``getNextAvailableIP4Address`` — we do NOT
        compute free space client-side (ADR-0027 §2, alternative 4 rejected).
        Returns ``{address: str}`` (BAM-selected; actual allocation is a draft).
        """
        payload = self._request("GET", f"/networks/{network_id}/addresses/next")
        if not isinstance(payload, dict):
            raise PluginError(
                f"bluecat: GET /networks/{network_id}/addresses/next "
                f"returned a non-object payload ({type(payload).__name__})"
            )
        return payload

    def get_configurations(
        self, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET all configurations (ADR-0027 §1 DISCOVERY_API fan-out root)."""
        return self.get_list("/configurations", params=params)

    def get_views(
        self, config_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET DNS views under a configuration (ADR-0027 §1 DISCOVERY_API)."""
        return self.get_list(f"/configurations/{config_id}/views", params=params)

    # ------------------------------------------------------------------
    # DHCP (DDI_DHCP)
    # ------------------------------------------------------------------

    def get_ranges(
        self, network_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET DHCPv4 ranges under a network (ADR-0027 §2 DDI_DHCP.get_ranges)."""
        return self.get_list(f"/networks/{network_id}/ranges", params=params)

    def get_leases(
        self, network_id: int, *, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET DHCP-allocated/reserved addresses in a network (ADR-0027 §2)."""
        dhcp_filter = "state:in('DHCP_ALLOCATED','DHCP_RESERVED')"
        merged_params: dict[str, Any] = {"filter": dhcp_filter, **(params or {})}
        return self.get_list(f"/networks/{network_id}/addresses", params=merged_params)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying httpx client and invalidate the session token."""
        # Token is held in process memory only; clearing on close is belt-and-suspenders
        # (ADR-0027 §4 / ADR-0011 §1).
        self.__token = None
        self._client.close()

    def __enter__(self) -> BamClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def join_raw(path: str, objects: list[dict[str, Any]]) -> str:
    """Render BAM objects as a stable, secret-free text block for raw recording.

    Used by the capability layer to persist the verbatim BAM v2 response to
    ``raw_artifacts`` before parsing (ADR-0027 §4 / ADR-0006 §3 raw-first).
    ``path`` = the BAM v2 path fragment; deterministic for audit re-derivation.
    """
    header = f"# bluecat:{path} ({len(objects)} object(s))"
    return "\n".join([header, *(_json.dumps(obj, default=str, sort_keys=True) for obj in objects)])
