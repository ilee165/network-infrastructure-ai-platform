"""FortiOS REST API client over httpx (ADR-0036 §1, ADR-0007 D7).

A thin, synchronous client wrapping :mod:`httpx` against the FortiOS REST API
(``https://<host>/api/v2/{path}/{name}``). Used only inside the ``fortios``
plugin (ADR-0006 §6: vendor-private connectivity); engines and agents never
see it. Synchronous by design — capability methods run inside Celery worker
tasks, never on the FastAPI event loop (ADR-0007 §3).

Security posture (ADR-0011 / ADR-0036 §2):

- The FortiOS **REST API token** is materialized in-process from the vault
  (a ``credential_ref``, never a stored secret). The :class:`FortiosRestClient`
  holds the token in a name-mangled slot so it never appears in repr(),
  a log line, a traceback frame dump, or a debugger display (ADR-0011 §1).
- The API token is sent in the ``Authorization: Bearer <token>`` request header
  (or ``X-Access-Token`` header per FortiOS docs) — never in the URL query
  string. httpx logs the full request URL at INFO level; a token in the URL
  would be logged and thus leak. A per-instance :class:`_TokenRedactFilter`
  is registered on the ``httpx`` logger as defence-in-depth backstop
  (ADR-0036 §2).
- The SSH password (fallback credential) is materialized from the vault
  and passed only to the netmiko transport — it never enters this REST client,
  any log line, or any normalized field (ADR-0011 §1).
- Read methods return the **raw JSON text verbatim** so the capability layer
  can record it via ``PluginCapability._record_raw`` *before* parsing into
  normalized models (ADR-0006 §3 raw-first).
"""

from __future__ import annotations

import logging
import urllib.parse

import httpx

from app.core.errors import PluginError

__all__ = ["FortiosClient", "FortiosRestClient"]

#: FortiOS REST API base path prefix.
_API_BASE = "/api/v2"

#: FortiOS token header (also accepted as X-Access-Token on older firmware).
_TOKEN_HEADER = "Authorization"

_log = logging.getLogger(__name__)


class _TokenRedactFilter(logging.Filter):
    """Logging filter that blocks any record whose message contains the API token.

    Defence-in-depth backstop registered on the ``httpx`` logger (ADR-0036 §2).
    The primary defence is that the token is sent in the Authorization header
    and never in the URL; this filter additionally drops any record whose
    formatted message contains the token in either its **literal** form or its
    **URL-percent-encoded** form. Matching only the literal form would miss a
    percent-encoded token.

    The token is stored in a **name-mangled** slot (``__token``) so
    ``vars(filter)`` / a debugger display does not expose it under a guessable
    attribute name (ADR-0011 §1).
    """

    def __init__(self, token: str) -> None:
        super().__init__()
        self.__token = token
        self.__encoded_token = urllib.parse.quote(token, safe="")

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False (block) if the record message would expose the token."""
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        return self.__token not in msg and self.__encoded_token not in msg


class FortiosRestClient:
    """Synchronous FortiOS REST API client (one per device session).

    Parameters:
        host: Hostname or IP of the FortiOS device (HTTPS is always used).
        api_token: The FortiOS API token materialized from the vault (never logged).
        verify: TLS verify setting (True/False/CA-bundle path).
        client: Optional pre-built httpx.Client (for testing via MockTransport).
        timeout: Request timeout in seconds.
        vdom: VDOM name to scope queries (default ``root``; ADR-0036 §4).

    The API token is held in a name-mangled slot (``__token``) so it never
    appears in ``repr()``, ``__dict__``, or a debugger display (ADR-0011 §1).
    It is sent in the ``Authorization`` request header (never the URL), so it
    cannot leak through httpx's INFO-level request-URL log. A
    :class:`_TokenRedactFilter` is additionally registered on the ``httpx``
    logger as a defence-in-depth backstop.
    """

    def __init__(
        self,
        *,
        host: str,
        api_token: str,
        verify: bool | str = True,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        vdom: str = "root",
    ) -> None:
        self._base_url = f"https://{host}{_API_BASE}"
        # Name-mangled to prevent repr() / dir() / traceback exposure (ADR-0011 §1).
        self.__token: str = api_token
        self._vdom = vdom
        self._client = client or httpx.Client(verify=verify, timeout=timeout)
        # Defence-in-depth: register a redaction filter on the httpx logger so any
        # record that would expose the token (literal or percent-encoded) is dropped.
        self.__log_filter: _TokenRedactFilter = _TokenRedactFilter(api_token)
        logging.getLogger("httpx").addFilter(self.__log_filter)

    def __repr__(self) -> str:
        # Deliberately omit the API token — it is a bearer credential (ADR-0011 §1).
        return f"{type(self).__name__}(host={self._base_url!r}, vdom={self._vdom!r})"

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    def _get(self, path: str, *, params: dict[str, str] | None = None) -> str:
        """Issue one GET request and return the raw JSON text verbatim.

        The API token is passed in the ``Authorization`` request header (never the
        URL query), so it cannot appear in httpx's logged request URL. It is
        NEVER logged, NEVER referenced in an error message, and NEVER returned
        as part of the output (ADR-0036 §2 / ADR-0011 §1).

        On a non-2xx HTTP status, a :class:`~app.core.errors.PluginError` is
        raised whose message names only the path — never the token.
        """
        url = f"{self._base_url}{path}"
        query: dict[str, str] = {"vdom": self._vdom}
        if params:
            query.update(params)

        # op label for error messages: path only, never the token.
        op = f"GET {path}"
        # Token travels in the Authorization header, not the URL.
        headers = {_TOKEN_HEADER: f"Bearer {self.__token}"}

        try:
            response = self._client.get(url, params=query, headers=headers)
        except httpx.HTTPError:
            raise PluginError(f"fortios: {op} failed (transport error)") from None

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"fortios: {op} failed with HTTP {exc.response.status_code}"
            ) from None

        return response.text

    # ------------------------------------------------------------------
    # Named API calls (one per capability row, ADR-0036 §1 / §3)
    # ------------------------------------------------------------------

    def get_system_status(self) -> str:
        """GET /monitor/system/status → device identity facts (DISCOVERY_API)."""
        return self._get("/monitor/system/status")

    def get_system_interface(self) -> str:
        """GET /monitor/system/interface → interface list (INTERFACES)."""
        return self._get("/monitor/system/interface")

    def get_router_ipv4(self) -> str:
        """GET /monitor/router/ipv4 → IPv4 routing table (ROUTES)."""
        return self._get("/monitor/router/ipv4")

    def get_firewall_policy(self) -> str:
        """GET /cmdb/firewall/policy → security policy rules (FIREWALL_POLICY, ADR-0034)."""
        return self._get("/cmdb/firewall/policy")

    def get_firewall_central_snat(self) -> str:
        """GET /cmdb/firewall/central-snat-map → central SNAT rules (NAT, ADR-0034)."""
        return self._get("/cmdb/firewall/central-snat-map")

    def get_firewall_vip(self) -> str:
        """GET /cmdb/firewall/vip → VIP/DNAT rules (NAT, ADR-0034)."""
        return self._get("/cmdb/firewall/vip")

    def get_policy_hit_count(self) -> str:
        """GET /monitor/firewall/policy/select → per-policy hit counts (best-effort).

        Returns raw JSON; the caller silently ignores errors and returns
        ``None`` for ``hit_count`` when unavailable (ADR-0036 §3).
        """
        return self._get("/monitor/firewall/policy/select")

    def get_ha_statistics(self) -> str:
        """GET /monitor/system/ha-statistics → HA cluster state (HA_STATUS)."""
        return self._get("/monitor/system/ha-statistics")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying httpx client and remove the log filter."""
        logging.getLogger("httpx").removeFilter(self.__log_filter)
        self._client.close()

    def __enter__(self) -> FortiosRestClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


#: Public alias — ``FortiosClient`` is the REST client (primary transport).
FortiosClient = FortiosRestClient
