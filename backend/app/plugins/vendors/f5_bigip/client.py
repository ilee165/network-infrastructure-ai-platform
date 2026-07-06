"""F5 BIG-IP iControl REST client over httpx (ADR-0050 §1/§2, ADR-0007 D7).

A thin, synchronous client wrapping :mod:`httpx` against the iControl REST API
(``https://<host>/mgmt/``). Used only inside the ``f5_bigip`` plugin (ADR-0006
§6: vendor-private connectivity); engines and agents never see it. Synchronous
by design — capability methods run inside Celery worker tasks, never on the
FastAPI event loop (ADR-0007 §3).

Security posture (ADR-0011 / ADR-0050 §1/§2), parity with the four sibling API
plugins (``bluecat``/``infoblox``/``panos``/``fortios``):

- **Token-based auth is the only steady-state mode.** The vault-materialized
  username/password are POSTed once to ``/mgmt/shared/authn/login`` (with a
  configurable ``loginProviderName``) and exchanged for an ``X-F5-Auth-Token``
  session token. The login request/response bodies are **never** raw-recorded
  and never logged (the request carries the password, the response the token).
- **Secrets in headers, never URLs.** The token travels in the
  ``X-F5-Auth-Token`` request header; nothing secret ever appears in a URL in
  literal or percent-encoded form (httpx logs request URLs at INFO).
- **Name-mangled secret slots, no custom leaking repr.** Both the password and
  the live token are held in name-mangled attributes; :meth:`__repr__` omits
  both. A per-instance :class:`_SecretRedactFilter` on the ``httpx`` logger
  drops any record containing the password OR token in literal or
  percent-encoded form (ADR-0050 §1/§2 — the filter covers BOTH secrets, both
  forms).
- **Token lifecycle (ADR-0050 §2):** a 401 on a tokened request triggers a
  single re-auth + retry; the client does not pre-emptively raise the token
  timeout (least privilege — no long-lived tokens). On close it best-effort
  **revokes** the token (``DELETE /mgmt/shared/authz/tokens/<token>``);
  revocation failure is logged (without the token) and non-fatal.
- **Raw-first.** Read methods return the verbatim JSON response text so the
  capability layer records it via ``PluginCapability._record_raw`` *before*
  parsing (ADR-0006 §3). The UCS **binary** body is NOT a raw artifact — only
  the JSON control-plane exchanges are recorded (ADR-0050 §7.2).
- **Paged collection reads (ADR-0050 §1):** iControl collections are read with
  ``$top``/``$skip`` paging at a fixed page size, following the returned paging
  metadata until exhausted; every page's raw body is recorded by the caller.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from collections.abc import Iterator
from typing import Any

import httpx

from app.core.errors import PluginError

__all__ = ["F5Client"]

#: iControl REST management root.
_MGMT = "/mgmt"

#: Login / token endpoints (ADR-0050 §2).
_LOGIN_PATH = "/mgmt/shared/authn/login"
_TOKENS_PATH = "/mgmt/shared/authz/tokens"

#: iControl session-token request header.
_TOKEN_HEADER = "X-F5-Auth-Token"

#: Fixed collection page size for the ``$top``/``$skip`` loop (ADR-0050 §1).
_PAGE_SIZE = 100

_log = logging.getLogger(__name__)


class _SecretRedactFilter(logging.Filter):
    """Block any ``httpx`` log record containing the password OR the token.

    Defence-in-depth backstop (ADR-0050 §1/§2). The primary defence is that
    neither secret ever appears in a URL — the password rides the login POST
    body, the token the ``X-F5-Auth-Token`` header. This filter additionally
    drops any record whose formatted message contains **either** secret in its
    **literal** or **URL-percent-encoded** form (matching only the literal form
    would miss a percent-encoded token slipping into a query string).

    Secrets are stored in **name-mangled** slots so ``vars(filter)`` / a debugger
    display does not expose them under a guessable attribute name (ADR-0011 §1).
    The live token is registered lazily via :meth:`add_token` once login mints it.
    """

    def __init__(self, password: str) -> None:
        super().__init__()
        self.__needles: set[str] = set()
        self._add(password)

    def _add(self, secret: str) -> None:
        if not secret:
            return
        self.__needles.add(secret)
        self.__needles.add(urllib.parse.quote(secret, safe=""))

    def add_token(self, token: str) -> None:
        """Register the live session token (both literal + percent-encoded forms)."""
        self._add(token)

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False (block) if the record message would expose a secret."""
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — a broken record must never crash logging
            return True
        return not any(needle in msg for needle in self.__needles)


class F5Client:
    """Synchronous iControl REST client (one per device session).

    Parameters:
        host: Hostname or IP of the BIG-IP (HTTPS is always used).
        username: Vault-materialized login username.
        password: Vault-materialized login password (never logged/repr'd).
        login_provider: iControl ``loginProviderName`` (default ``tmos``;
            override for RADIUS/TACACS+/LDAP-backed service accounts, ADR-0050 §2).
        verify: TLS verify setting (True/False/CA-bundle path).
        client: Optional pre-built ``httpx.Client`` (test path via MockTransport).
        timeout: Request timeout in seconds.
        session_token: Optional pre-minted token (test path — skips login).

    The password and token are held in name-mangled slots so neither appears in
    ``repr()``, ``__dict__``, or a debugger display (ADR-0011 §1).
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        login_provider: str = "tmos",
        verify: bool | str = True,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        session_token: str | None = None,
    ) -> None:
        self._base_url = f"https://{host}{_MGMT}"
        self._host = host
        self._login_provider = login_provider
        # Name-mangled secret slots (ADR-0011 §1) — never rendered by repr().
        self.__username = username
        self.__password = password
        self.__token: str | None = session_token
        self._client = client or httpx.Client(verify=verify, timeout=timeout)
        # Register the redaction backstop on the httpx logger for BOTH secrets.
        self.__log_filter = _SecretRedactFilter(password)
        if session_token:
            self.__log_filter.add_token(session_token)
        logging.getLogger("httpx").addFilter(self.__log_filter)

    def __repr__(self) -> str:
        # Deliberately omit username/password/token — all bearer material.
        return f"{type(self).__name__}(host={self._host!r}, provider={self._login_provider!r})"

    # ------------------------------------------------------------------
    # Auth / token lifecycle (ADR-0050 §2)
    # ------------------------------------------------------------------

    def _login(self) -> None:
        """Exchange username/password for an ``X-F5-Auth-Token`` (never logged).

        The request body carries the password and the response the token; neither
        is raw-recorded and neither may appear in an error message (ADR-0050 §2).
        """
        url = f"{self._base_url}/shared/authn/login"
        try:
            response = self._client.post(
                url,
                json={
                    "username": self.__username,
                    "password": self.__password,
                    "loginProviderName": self._login_provider,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"f5_bigip: login failed with HTTP {exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            raise PluginError("f5_bigip: login failed (transport error)") from None
        except json.JSONDecodeError:
            raise PluginError("f5_bigip: login response was not JSON") from None

        token: str | None = None
        if isinstance(payload, dict):
            tok = payload.get("token")
            if isinstance(tok, dict):
                token = tok.get("token")
            elif isinstance(tok, str):
                token = tok
        if not token:
            raise PluginError("f5_bigip: login response did not contain a token")
        self.__token = token
        # The live token joins the redaction set the moment it is minted.
        self.__log_filter.add_token(token)

    def _ensure_token(self) -> str:
        if self.__token is None:
            self._login()
        assert self.__token is not None  # noqa: S101 — _login sets it or raises
        return self.__token

    def _auth_headers(self) -> dict[str, str]:
        return {_TOKEN_HEADER: self._ensure_token()}

    # ------------------------------------------------------------------
    # Core request
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        _retry_auth: bool = True,
    ) -> httpx.Response:
        """Issue one tokened request; single re-auth + retry on 401 (ADR-0050 §2).

        On a non-2xx (other than the handled 401) a typed :class:`PluginError` is
        raised whose message names only the verb + path + status — never the
        token, the password, or the response body.
        """
        op = f"{method} {path}"
        url = f"{self._base_url}{path}"
        try:
            response = self._client.request(
                method,
                url,
                params=params,
                json=body,
                headers=self._auth_headers(),
            )
        except httpx.HTTPError:
            raise PluginError(f"f5_bigip: {op} failed (transport error)") from None

        if response.status_code == httpx.codes.UNAUTHORIZED and _retry_auth:
            # Token expired/invalid — re-auth once and retry (ADR-0050 §2).
            self.__token = None
            return self._request(method, path, params=params, body=body, _retry_auth=False)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"f5_bigip: {op} failed with HTTP {exc.response.status_code}"
            ) from None
        return response

    def _get_text(self, path: str, *, params: dict[str, Any] | None = None) -> str:
        """GET *path* and return the verbatim JSON response text (raw-first)."""
        return self._request("GET", path, params=params).text

    # ------------------------------------------------------------------
    # Paged collection reads (ADR-0050 §1: $top/$skip)
    # ------------------------------------------------------------------

    def get_collection_pages(
        self, path: str, *, params: dict[str, Any] | None = None
    ) -> Iterator[str]:
        """Yield each collection page's verbatim JSON text via ``$top``/``$skip``.

        iControl collections page with ``$top``/``$skip`` and echo the paging
        state (``currentItemCount`` / ``totalItems`` / ``nextLink``). The loop
        follows that metadata until a page returns fewer than ``$top`` items or no
        ``nextLink`` remains. Every page body is yielded verbatim so the caller
        records each via ``_record_raw`` before parsing (ADR-0006 §3).
        """
        skip = 0
        while True:
            query: dict[str, Any] = {"$top": _PAGE_SIZE, "$skip": skip}
            if params:
                query.update(params)
            text = self._get_text(path, params=query)
            yield text
            try:
                page = json.loads(text)
            except json.JSONDecodeError:
                raise PluginError(f"f5_bigip: GET {path} returned a non-JSON page") from None
            items = page.get("items", []) if isinstance(page, dict) else []
            count = len(items)
            if count == 0 or count < _PAGE_SIZE:
                break
            if isinstance(page, dict) and not page.get("nextLink"):
                # No further page advertised even though this page was full — stop
                # rather than loop forever (termination guard, ADR-0050 §1).
                break
            skip += count

    # ------------------------------------------------------------------
    # Named read endpoints (one per capability row, ADR-0050 §3)
    # ------------------------------------------------------------------

    def get_version(self) -> str:
        """GET /mgmt/tm/sys/version → device version facts (DISCOVERY_API)."""
        return self._get_text("/tm/sys/version")

    def get_global_settings(self) -> str:
        """GET /mgmt/tm/sys/global-settings → hostname/identity (DISCOVERY_API)."""
        return self._get_text("/tm/sys/global-settings")

    def get_interfaces(self) -> str:
        """GET /mgmt/tm/net/interface → interface list (INTERFACES)."""
        return self._get_text("/tm/net/interface")

    def get_routes(self) -> str:
        """GET /mgmt/tm/net/route → static routes (ROUTES)."""
        return self._get_text("/tm/net/route")

    def get_selfips(self) -> str:
        """GET /mgmt/tm/net/self → self-IPs (connected routes, ROUTES)."""
        return self._get_text("/tm/net/self")

    def get_virtuals(self) -> Iterator[str]:
        """GET /mgmt/tm/ltm/virtual (paged) → virtual servers (ADC_SERVICES)."""
        return self.get_collection_pages("/tm/ltm/virtual")

    def get_pools(self) -> Iterator[str]:
        """GET /mgmt/tm/ltm/pool?expandSubcollections=true (paged) → pools (ADC_SERVICES)."""
        return self.get_collection_pages("/tm/ltm/pool", params={"expandSubcollections": "true"})

    def get_failover_status(self) -> str:
        """GET /mgmt/tm/cm/failover-status → DSC failover role (HA_STATUS)."""
        return self._get_text("/tm/cm/failover-status")

    def get_sync_status(self) -> str:
        """GET /mgmt/tm/cm/sync-status → ConfigSync state (HA_STATUS)."""
        return self._get_text("/tm/cm/sync-status")

    # ------------------------------------------------------------------
    # UCS control plane (ADR-0050 §7.2/§7.4). Passphrase never logged.
    # ------------------------------------------------------------------

    def save_ucs(self, name: str, passphrase: str) -> str:
        """POST /mgmt/tm/sys/ucs (command=save) — passphrase-encrypt on box.

        The request body carries the passphrase; that exchange is never
        raw-recorded and never logged (ADR-0050 §7.2). Returns the control-plane
        JSON text (safe to raw-record — it carries no passphrase).
        """
        return self._request(
            "POST",
            "/tm/sys/ucs",
            body={"command": "save", "name": name, "passphrase": passphrase},
        ).text

    def download_ucs(self, name: str) -> bytes:
        """GET the UCS binary via the file-transfer worker (ADR-0050 §7.2).

        The binary body is opaque secret material — NOT a raw artifact. Returns
        the raw bytes for the caller to encrypt/measure.
        """
        response = self._request("GET", f"/shared/file-transfer/ucs-downloads/{name}")
        return response.content

    def delete_ucs(self, name: str) -> str:
        """DELETE /mgmt/tm/sys/ucs/<name> — remove the on-box residue (ADR-0050 §7.2)."""
        return self._request("DELETE", f"/tm/sys/ucs/{name}").text

    def upload_ucs(self, name: str, content: bytes) -> str:
        """POST the UCS binary to the upload worker ahead of a load (ADR-0050 §7.4)."""
        op = f"POST /shared/file-transfer/ucs-uploads/{name}"
        url = f"{self._base_url}/shared/file-transfer/ucs-uploads/{name}"
        headers = {**self._auth_headers(), "Content-Type": "application/octet-stream"}
        try:
            response = self._client.post(url, content=content, headers=headers)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"f5_bigip: {op} failed with HTTP {exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            raise PluginError(f"f5_bigip: {op} failed (transport error)") from None
        return response.text

    def load_ucs(self, name: str, passphrase: str) -> str:
        """POST /mgmt/tm/sys/ucs (command=load) — restore from *name* (ADR-0050 §7.4).

        The passphrase rides the request body and is never raw-recorded/logged.
        """
        return self._request(
            "POST",
            "/tm/sys/ucs",
            body={"command": "load", "name": name, "passphrase": passphrase},
        ).text

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Best-effort revoke the token, remove the log filter, close httpx (ADR-0050 §2)."""
        token = self.__token
        if token is not None:
            try:
                self._client.request(
                    "DELETE",
                    f"{self._base_url}/shared/authz/tokens/{token}",
                    headers={_TOKEN_HEADER: token},
                )
            except httpx.HTTPError:
                # Revocation is best-effort; the 1200s expiry bounds exposure. The
                # token is NEVER named in the log line (ADR-0050 §2).
                _log.warning("f5_bigip: token revocation failed (non-fatal)")
        self.__token = None
        logging.getLogger("httpx").removeFilter(self.__log_filter)
        self._client.close()

    def __enter__(self) -> F5Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
