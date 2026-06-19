"""Infoblox WAPI HTTP client over httpx (ADR-0022 §1, D7).

A thin, synchronous client wrapping **httpx** against the Infoblox WAPI REST
endpoint (``/wapi/v2.x/<objtype>``). It is used only inside the ``infoblox``
plugin (ADR-0006 §6: vendor-private connectivity); engines and agents never see
it. Synchronous by design — capability methods run inside Celery worker tasks,
never on the FastAPI event loop (ADR-0007 §3).

Security posture (A9 / D11):

- Credentials are a :class:`WapiCredentials` value materialized in-process from
  the vault; they are passed to httpx basic-auth and **never** logged, never
  put in an exception message, and never placed into a normalized record or a
  :class:`~app.plugins.base.ChangeRequestDraft`. :class:`WapiCredentials`
  carries no ``__str__``/``__repr__`` that exposes the password.
- TLS verification is **on by default**; ``verify`` is part of device
  connection config (the appliance CA bundle path or ``True``/``False``).
- Read methods return the **raw decoded WAPI JSON list verbatim** so the
  capability layer can record it before parsing (ADR-0006 §3 raw-first).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.errors import PluginError

__all__ = ["WapiClient", "WapiCredentials"]


@dataclass(frozen=True)
class WapiCredentials:
    """WAPI username + password, materialized in-process from the vault (D11).

    The password is held in a non-``repr`` field so it never appears in a
    dataclass ``repr()``, a log line, a traceback frame dump, or a debugger
    display. Equality/hash deliberately exclude the secret too.
    """

    username: str
    password: str = field(repr=False, compare=False)


class WapiClient:
    """Synchronous Infoblox WAPI client (one per device session).

    Parameters mirror the device connection config: the appliance ``base_url``
    (scheme + host[:port]), the negotiated WAPI ``version`` (e.g. ``"2.12"``),
    the in-process :class:`WapiCredentials`, and the TLS ``verify`` setting.
    """

    def __init__(
        self,
        *,
        base_url: str,
        version: str,
        credentials: WapiCredentials,
        verify: bool | str = True,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._wapi_root = f"{base_url.rstrip('/')}/wapi/v{version.lstrip('v')}"
        self._username = credentials.username
        # The injected client (tests pass an httpx.Client over a MockTransport)
        # owns no auth; we attach basic-auth per request so the secret is never
        # stored on a long-lived object beyond httpx's own auth handler.
        self._auth = httpx.BasicAuth(credentials.username, credentials.password)
        self._client = client or httpx.Client(verify=verify, timeout=timeout)

    def get(self, objtype: str, params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        """GET ``/wapi/vX/<objtype>`` and return the decoded JSON list verbatim.

        WAPI returns a JSON array of objects (each with an ``_ref`` handle). On a
        non-2xx response or a transport error a typed :class:`PluginError` is
        raised whose message names only the object type and status — never the
        URL credentials, the auth header, or the response body (which can echo
        request context).
        """
        url = f"{self._wapi_root}/{objtype}"
        try:
            response = self._client.get(url, params=dict(params or {}), auth=self._auth)
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"infoblox: WAPI GET {objtype!r} failed with status {exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            # Deliberately drop the original exception detail: an httpx error repr
            # can contain the request URL (which, for some auth schemes, carries
            # credentials). Re-raise with a sanitized message.
            raise PluginError(f"infoblox: WAPI GET {objtype!r} failed (transport error)") from None

        if not isinstance(payload, list):
            raise PluginError(
                f"infoblox: WAPI GET {objtype!r} returned a non-list payload "
                f"({type(payload).__name__})"
            )
        return payload

    def get_function(
        self, ref: str, function: str, args: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call a WAPI function on an object ``_ref`` (e.g. ``next_available_ip``).

        WAPI function calls are POSTs of the form ``/<_ref>?_function=<name>``.
        Returns the decoded JSON object. Errors are sanitized exactly as
        :meth:`get`.
        """
        url = f"{self._wapi_root}/{ref}"
        try:
            response = self._client.post(
                url,
                params={"_function": function},
                json=dict(args or {}),
                auth=self._auth,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"infoblox: WAPI function {function!r} failed with status "
                f"{exc.response.status_code}"
            ) from None
        except httpx.HTTPError:
            raise PluginError(
                f"infoblox: WAPI function {function!r} failed (transport error)"
            ) from None
        if not isinstance(payload, dict):
            raise PluginError(
                f"infoblox: WAPI function {function!r} returned a non-object payload "
                f"({type(payload).__name__})"
            )
        return payload

    def close(self) -> None:
        """Close the underlying httpx client."""
        self._client.close()

    def __enter__(self) -> WapiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def join_raw(objtype: str, objects: Sequence[Mapping[str, Any]]) -> str:
    """Render WAPI objects as a stable, secret-free text block for raw recording.

    Used by the capability layer to persist the verbatim WAPI response to
    ``raw_artifacts`` before parsing (ADR-0006 §3). One ``repr`` per object,
    prefixed with the object type — deterministic for audit re-derivation.
    """
    header = f"# wapi:{objtype} ({len(objects)} object(s))"
    return "\n".join([header, *(repr(dict(obj)) for obj in objects)])
