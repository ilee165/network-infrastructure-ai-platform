"""Palo Alto PAN-OS XML API client over httpx (ADR-0035 §1, D7).

A thin, synchronous client wrapping :mod:`httpx` against the PAN-OS XML API
(``https://<host>/api/?type=...&key=...``). Used only inside the ``panos``
plugin (ADR-0006 §6: vendor-private connectivity); engines and agents never
see it. Synchronous by design — capability methods run inside Celery worker
tasks, never on the FastAPI event loop (ADR-0007 §3).

Security posture (A9 / D11):

- The PAN-OS **API key** is materialized in-process from the vault
  (a ``credential_ref``, never a stored secret). The :class:`PanosClient`
  holds the key in a name-mangled slot so it never appears in repr(),
  a log line, a traceback frame dump, or a debugger display (ADR-0011 §1).
- The API key is placed in the ``key=`` query parameter of every request.
  Since httpx logs the full URL (including query params) at INFO level via
  the ``httpx`` logger, a per-instance :class:`_ApiKeyRedactFilter` is
  registered on the ``httpx`` logger to suppress any record whose formatted
  message contains the key. This is the narrowest possible scope — only
  records that would leak this instance's key are dropped (ADR-0035 §2).
- The key is never placed in a normalized record, a raw artifact's ``command``
  field, or any exception message (ADR-0011 / ADR-0035 §2).
- TLS verification is **on by default**; ``verify`` is part of device
  connection config.
- Read methods return the **raw XML text verbatim** so the capability layer
  can record it via ``PluginCapability._record_raw`` *before* parsing into
  normalized models (ADR-0035 §1 raw-first, ADR-0006 §3).

A config export (``config show``) can carry secret material (pre-shared keys,
certificate private keys, SNMP communities in the running config). The stored
raw artifact inherits the same ``raw_artifacts`` storage, access-scoping, and
retention controls as every other raw payload (ADR-0006 §3 / ADR-0011) — it
is not a new, unprotected secret surface. The normalized ``FIREWALL_POLICY``
models stay secret-free (ADR-0034).
"""

from __future__ import annotations

import logging
from xml.etree import ElementTree as ET

import httpx

from app.core.errors import PluginError

__all__ = ["PanosClient"]

#: PAN-OS XML API path (fixed; parameters go in the query string).
_API_PATH = "/api/"

_log = logging.getLogger(__name__)


class _ApiKeyRedactFilter(logging.Filter):
    """Logging filter that blocks any record whose message contains the API key.

    Registered on the ``httpx`` logger so that httpx's INFO-level request
    URL log (which includes all query params including ``key=``) is suppressed
    for records that would expose the credential (ADR-0011 §1 / ADR-0035 §2).

    Only log records whose formatted message contains the literal key string
    are blocked — all other records pass through unchanged. This is the
    narrowest possible scope and avoids global logger mutation.
    """

    def __init__(self, api_key: str) -> None:
        super().__init__()
        # Store a reference to identify which records to drop; the key itself
        # is never stored in a loggable repr or serialised repr of this object.
        self._key = api_key

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False (block) if the record message would expose the key."""
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        return self._key not in msg


class PanosClient:
    """Synchronous PAN-OS XML API client (one per device session).

    Parameters:
        host: Hostname or IP of the PAN-OS device (HTTPS is always used).
        api_key: The PAN-OS API key materialized from the vault (never logged).
        verify: TLS verify setting (True/False/CA-bundle path).
        client: Optional pre-built httpx.Client (for testing via MockTransport).
        timeout: Request timeout in seconds.

    The API key is held in a name-mangled slot (``__key``) so it never
    appears in ``repr()``, ``__dict__``, or a debugger display (ADR-0011 §1).
    A :class:`_ApiKeyRedactFilter` is registered on the ``httpx`` logger to
    prevent the key from appearing in httpx's request/response URL log lines.
    """

    def __init__(
        self,
        *,
        host: str,
        api_key: str,
        verify: bool | str = True,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = f"https://{host}{_API_PATH}"
        # Name-mangled to prevent repr() / dir() / traceback exposure (ADR-0011 §1).
        self.__key: str = api_key
        self._client = client or httpx.Client(verify=verify, timeout=timeout)
        # Register the redaction filter on the httpx logger so URL log lines
        # containing the API key are never emitted (ADR-0011 §1 / ADR-0035 §2).
        self.__log_filter: _ApiKeyRedactFilter = _ApiKeyRedactFilter(api_key)
        logging.getLogger("httpx").addFilter(self.__log_filter)

    def __repr__(self) -> str:
        # Deliberately omit the API key — it is a bearer credential (ADR-0011 §1).
        return f"{type(self).__name__}(host={self._base_url!r})"

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    def request(
        self,
        req_type: str,
        *,
        cmd: str | None = None,
        xpath: str | None = None,
        action: str | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> str:
        """Issue one XML API request and return the raw XML text verbatim.

        The API key is passed as the ``key`` query parameter. It is NEVER
        logged, NEVER referenced in an error message, and NEVER returned
        as part of the output (ADR-0035 §2 / ADR-0011 §1).

        On a non-2xx HTTP status or a PAN-OS ``status="error"`` response,
        a :class:`~app.core.errors.PluginError` is raised whose message
        names only the request type and optional action — never the key.
        """
        params: dict[str, str] = {
            "type": req_type,
            "key": self.__key,  # credential in query param — filtered from logs
        }
        if cmd is not None:
            params["cmd"] = cmd
        if xpath is not None:
            params["xpath"] = xpath
        if action is not None:
            params["action"] = action
        if extra_params:
            params.update(extra_params)

        # op label for error messages: omits the key (ADR-0035 §2).
        op = f"type={req_type}" + (f" action={action}" if action else "")
        try:
            response = self._client.get(self._base_url, params=params)
        except httpx.HTTPError:
            # Transport error message omits the key and URL params (ADR-0035 §2).
            raise PluginError(f"panos: {op} failed (transport error)") from None

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PluginError(
                f"panos: {op} failed with HTTP status {exc.response.status_code}"
            ) from None

        xml_text = response.text
        self._check_status(op, xml_text)
        return xml_text

    def _check_status(self, op: str, xml_text: str) -> None:
        """Parse the response status and raise PluginError if not 'success'.

        The error message names the operation but never the API key or the
        raw server error body (which may contain config secrets, ADR-0035 §1).
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            raise PluginError(f"panos: {op} returned non-XML body") from None
        status = root.get("status", "")
        if status != "success":
            # Deliberately omit the response body from the error — the body
            # may contain config material (ADR-0035 §1).
            raise PluginError(f"panos: {op} returned status={status!r}") from None

    # ------------------------------------------------------------------
    # Named API calls (one per capability row, ADR-0035 §3)
    # ------------------------------------------------------------------

    def show_system_info(self) -> str:
        """``op`` show system info → device identity facts (DISCOVERY_API)."""
        return self.request("op", cmd="<show><system><info/></system></show>")

    def show_interface_all(self) -> str:
        """``op`` show interface all → hw interface list (INTERFACES)."""
        return self.request("op", cmd="<show><interface>all</interface></show>")

    def get_interface_config(self) -> str:
        """``config get`` interface config → IP addresses (INTERFACES)."""
        return self.request(
            "config",
            action="get",
            xpath="/config/devices/entry[@name='localhost.localdomain']/network/interface",
        )

    def show_routing_route(self) -> str:
        """``op`` show routing route → routing table (ROUTES)."""
        return self.request("op", cmd="<show><routing><route/></routing></show>")

    def get_security_rules(self) -> str:
        """``config get`` security policy rules (FIREWALL_POLICY, ADR-0034)."""
        return self.request(
            "config",
            action="get",
            xpath=(
                "/config/devices/entry[@name='localhost.localdomain']"
                "/vsys/entry[@name='vsys1']/rulebase/security/rules"
            ),
        )

    def get_nat_rules(self) -> str:
        """``config get`` NAT policy rules (FIREWALL_POLICY NAT side, ADR-0034)."""
        return self.request(
            "config",
            action="get",
            xpath=(
                "/config/devices/entry[@name='localhost.localdomain']"
                "/vsys/entry[@name='vsys1']/rulebase/nat/rules"
            ),
        )

    def show_rule_hit_count(self) -> str:
        """``op`` show rule-hit-count → per-rule hit counts (best-effort).

        Returns the raw XML text; the caller silently ignores parse errors
        and returns ``None`` for ``hit_count`` when unavailable (ADR-0035 §3).
        """
        cmd = (
            "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'>"
            "<rule-base><entry name='security'><rules><all/></rules></entry>"
            "</rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
        )
        return self.request("op", cmd=cmd)

    def show_config_running(self) -> str:
        """``config show`` running configuration (CONFIG_BACKUP, ADR-0035 §5).

        Returns the **running** (enforced) config, not the candidate config.
        The response may contain pre-shared keys, certificate material, and
        other secrets — the caller records this only into ``raw_artifacts``
        with appropriate access controls (ADR-0035 §1 / ADR-0006 §3).
        """
        return self.request("config", action="show")

    def show_ha_state(self) -> str:
        """``op`` show high-availability state → HA peer info (HA_STATUS)."""
        return self.request(
            "op", cmd="<show><high-availability><state/></high-availability></show>"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying httpx client and remove the log filter."""
        # Remove the redaction filter when done so it doesn't accumulate on the
        # httpx logger across many client instances (ADR-0011 §1).
        logging.getLogger("httpx").removeFilter(self.__log_filter)
        self._client.close()

    def __enter__(self) -> PanosClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def parse_xml(xml_text: str) -> ET.Element:
    """Parse XML text and return the root element.

    :raises PluginError: if the text is not valid XML.
    """
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise PluginError(f"panos: failed to parse XML response: {exc}") from None


def _text(element: ET.Element | None, default: str = "") -> str:
    """Return stripped element text or *default* if element or text is None."""
    if element is None:
        return default
    return (element.text or "").strip()


def _members(parent: ET.Element | None, tag: str = "member") -> tuple[str, ...]:
    """Return the text values of all ``<member>`` (or *tag*) children as a tuple."""
    if parent is None:
        return ()
    return tuple(m.strip() for el in parent.findall(tag) if (m := (el.text or "").strip()))
