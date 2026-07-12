"""Netmiko-backed SSH transport (ADR-0007: SSH/CLI protocol family).

:class:`SshTransport` is a context-managed netmiko session satisfying the
:class:`app.plugins.base.CommandTransport` protocol; capability
implementations execute CLI commands through it and receive device output
verbatim — no normalization at the transport layer.

Security invariants (D11):

- :class:`SshParams` redacts ``password``/``enable_secret`` in ``repr``/``str``.
- :class:`SshTransportError` messages identify the underlying netmiko failure
  by *class name only* — netmiko exception text is never embedded, so no
  credential material can leak into logs or API responses.

Blocking-I/O placement: netmiko is synchronous; transports run inside Celery
worker tasks or via :func:`asyncio.to_thread` (agent on-demand live reads) —
never directly on the FastAPI event loop (ADR-0007 §3, ADR-0008).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException, SSHException

from app.core.errors import PluginError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from netmiko import BaseConnection

__all__ = [
    "NETMIKO_DEVICE_TYPES",
    "SshParams",
    "SshTransport",
    "SshTransportError",
    "netmiko_device_type",
]

_REDACTED = "***REDACTED***"

#: Netmiko (and re-exported paramiko) failures wrapped into SshTransportError.
_NETMIKO_FAILURES: tuple[type[Exception], ...] = (NetmikoBaseException, SSHException)

#: Tclsh / IOS error markers in staged-file output — fail closed before
#: ``configure replace`` so a corrupt stage never becomes running config (C3).
#: Includes Tcl 8.3.x phrasing (IOS embedded tclsh is 8.3, not 8.6).
_TCL_ERROR_MARKERS: Final[tuple[str, ...]] = (
    "invalid command name",
    "syntax error",
    "can't read",
    "no such file",
    "couldn't open",
    "permission denied",
    "bad option",
    "wrong # args",
    "% invalid",
    "% error",
    "tclsh: ",
)

#: Staged candidate path for ``configure replace`` (Cisco-family).
_STAGED_CONFIG_PATH: Final[str] = "flash:netops-rollback.cfg"

#: Max chars per escaped Tcl double-quoted chunk (device CLI line limits).
_TCL_CHUNK_CHARS: Final[int] = 200

#: vendor_id -> netmiko ``device_type`` for vendors whose plugin id differs
#: from the netmiko driver name. Vendors absent here fall back to their
#: vendor_id (which matches the driver name for e.g. ``cisco_nxos``). One map
#: for every SSH session-open site (discovery, config backup, agent live
#: reads) — previously each worker carried its own copy.
NETMIKO_DEVICE_TYPES: Final[dict[str, str]] = {
    "cisco_ios": "cisco_ios",
    "cisco_iosxe": "cisco_xe",
    "eos": "arista_eos",
    "junos": "juniper_junos",
    "fortios": "fortinet",
}


def netmiko_device_type(vendor_id: str, params: Mapping[str, Any] | None = None) -> str:
    """Resolve the netmiko driver name for *vendor_id*.

    A per-credential ``device_type`` in *params* (non-secret protocol metadata
    on :class:`~app.models.DeviceCredential`) always wins; otherwise the shared
    :data:`NETMIKO_DEVICE_TYPES` map applies, falling back to the vendor_id
    itself. Mirrors the semantics both workers previously implemented locally.
    """
    override = (params or {}).get("device_type")
    if override:
        return str(override)
    return NETMIKO_DEVICE_TYPES.get(vendor_id, vendor_id)


class SshTransportError(PluginError):
    """An SSH transport operation failed (connect, enable, command, or state).

    Messages name the device by host/port/device_type and the underlying
    netmiko exception by class name only — never credential material.
    """

    title = "SSH Transport Failure"
    slug = "ssh-transport-failure"


@dataclass(frozen=True)
class SshParams:
    """Connection parameters for one SSH session (plain data, no DB coupling).

    ``device_type`` is the netmiko driver name (e.g. ``"cisco_ios"``).
    ``enable_secret`` triggers privileged-exec escalation when set.
    ``conn_timeout`` bounds session establishment; ``read_timeout`` bounds
    each command's output collection (seconds).
    ``commit_confirmed_minutes`` is consumed only by
    :class:`~app.plugins.transport.junos_ssh.JunosSshTransport` (JunOS
    ``commit confirmed <N>``); Cisco-family ignore it.

    Host-key policy (Wave 3 H7): ``ssh_strict`` / ``system_host_keys`` default
    true (secure by default). Optional ``host_key_fingerprint`` is a
    non-secret pin (``SHA256:…`` or hex MD5) verified after connect.
    """

    host: str
    device_type: str
    username: str
    password: str
    port: int = 22
    enable_secret: str | None = None
    conn_timeout: float = 10.0
    read_timeout: float = 30.0
    commit_confirmed_minutes: int = 2
    ssh_strict: bool = True
    system_host_keys: bool = True
    host_key_fingerprint: str | None = None

    def __repr__(self) -> str:
        enable_secret = _REDACTED if self.enable_secret is not None else None
        return (
            f"SshParams(host={self.host!r}, device_type={self.device_type!r}, "
            f"username={self.username!r}, password={_REDACTED!r}, port={self.port!r}, "
            f"enable_secret={enable_secret!r}, conn_timeout={self.conn_timeout!r}, "
            f"read_timeout={self.read_timeout!r}, "
            f"commit_confirmed_minutes={self.commit_confirmed_minutes!r}, "
            f"ssh_strict={self.ssh_strict!r}, system_host_keys={self.system_host_keys!r}, "
            f"host_key_fingerprint={self.host_key_fingerprint!r})"
        )


class SshTransport:
    """Context-managed netmiko SSH session executing CLI commands.

    Usage::

        with SshTransport(params) as transport:
            output = transport.run("show interfaces")

    Satisfies :class:`app.plugins.base.CommandTransport` (``send_command``)
    so capability implementations can consume it directly.
    """

    def __init__(self, params: SshParams) -> None:
        self._params = params
        self._connection: BaseConnection | None = None

    def __enter__(self) -> SshTransport:
        params = self._params
        if not params.ssh_strict:
            logger.warning(
                "SSH host-key verification DISABLED for %s:%s (device_type=%r); "
                "lab-only NETOPS_SSH_STRICT=false / SshParams.ssh_strict=False — "
                "do not use in production",
                params.host,
                params.port,
                params.device_type,
            )
        try:
            connection = ConnectHandler(
                host=params.host,
                device_type=params.device_type,
                username=params.username,
                password=params.password,
                port=params.port,
                secret=params.enable_secret or "",
                conn_timeout=params.conn_timeout,
                # Wave 3 H7: default strict + system known_hosts (not AutoAdd).
                ssh_strict=params.ssh_strict,
                system_host_keys=params.system_host_keys and params.ssh_strict,
            )
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._host_key_failure_message(exc)) from exc
        self._connection = connection
        try:
            self._verify_pinned_fingerprint(connection)
        except SshTransportError:
            self._close()
            raise
        if params.enable_secret is not None:
            try:
                connection.enable()
            except _NETMIKO_FAILURES as exc:
                self._close()
                raise SshTransportError(self._failure_message("enable", exc)) from exc
            except BaseException:
                self._close()
                raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._close()

    def run(self, command: str) -> str:
        """Execute *command* on the device and return its output verbatim."""
        connection = self._connection
        if connection is None:
            raise SshTransportError(
                f"SSH session to {self._params.host}:{self._params.port} is not open "
                "(use SshTransport as a context manager)"
            )
        try:
            output = connection.send_command(command, read_timeout=self._params.read_timeout)
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message(f"command {command!r}", exc)) from exc
        if not isinstance(output, str):  # pragma: no cover - structured output never requested
            raise SshTransportError(
                f"SSH command {command!r} for {self._params.host}:{self._params.port} "
                "returned non-text output"
            )
        return output

    def send_command(self, command: str) -> str:
        """:class:`~app.plugins.base.CommandTransport`-compatible alias of :meth:`run`."""
        return self.run(command)

    def send_config(self, lines: Sequence[str]) -> str:
        """Merge *lines* into the running config; return device output verbatim.

        The :class:`~app.plugins.base.ConfigWriteTransport` **merge** surface for
        the M5 config write path (ADR-0021 §4): netmiko's ``send_config_set``
        enters ``configure terminal``, sends the lines, and exits config mode. A
        merge adds/overrides lines but cannot *remove* a line absent from
        *lines* — the apply surface for an additive ``CONFIG_DEPLOY`` fragment.
        For an equal-to-baseline result (restore / rollback) use
        :meth:`replace_config`. Used only as the execution step of an approved
        ChangeRequest (the Automation Agent, Wave 4); the capability layer
        captures/verifies around it.

        Refuses ``juniper_junos`` — that platform must use
        :class:`~app.plugins.transport.junos_ssh.JunosSshTransport` via
        :func:`make_ssh_transport` (Wave 3 C2).
        """
        self._refuse_junos_write("send_config")
        connection = self._require_connection()
        try:
            output = connection.send_config_set(list(lines), read_timeout=self._params.read_timeout)
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message("config apply", exc)) from exc
        if not isinstance(output, str):  # pragma: no cover - structured output never requested
            raise SshTransportError(
                f"SSH config apply for {self._params.host}:{self._params.port} "
                "returned non-text output"
            )
        return output

    def replace_config(self, lines: Sequence[str]) -> str:
        """Replace the running config so it becomes exactly *lines* (configure replace).

        The :class:`~app.plugins.base.ConfigWriteTransport` **replace** surface
        (ADR-0021 §4 ``cisco_ios`` native rollback primitive). Unlike
        :meth:`send_config`, a replace removes any running line not present in
        *lines*, so a post-replace re-capture can normalize **equal** to the
        supplied target — the precondition for the symmetric equal-to-baseline
        predicate (§3) used by ``CONFIG_RESTORE`` apply and by rollback for both
        operations.

        Mechanism (Wave 3 C3): stage the candidate with Tcl ``puts`` of
        **escaped** lines (Tcl 8.3-safe — IOS embedded tclsh has no
        ``binary decode base64``). Every ``$``, ``"``, ``[``, ``]``, ``\\`` is
        escaped so Tcl cannot substitute or truncate the payload. Long lines are
        chunked under the device CLI limit. Staged length is verified before
        ``configure replace <file> force``. Any tclsh error output fails closed
        **before** replace is issued.

        Refuses ``juniper_junos`` — use :class:`~app.plugins.transport.junos_ssh.JunosSshTransport`.
        """
        self._refuse_junos_write("replace_config")
        connection = self._require_connection()
        line_list = list(lines)
        # puts writes a trailing newline per line — match that in expected length.
        expected_len = sum(len(line) + 1 for line in line_list)
        staged = _STAGED_CONFIG_PATH
        timeout = self._params.read_timeout
        output = ""
        try:
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged}", read_timeout=timeout)

            stage_cmds = ["do tclsh", f'set fd [open "{staged}" w+]']
            for line in line_list:
                stage_cmds.extend(self._tcl_puts_line_commands(line))
            stage_cmds.extend(["close $fd", "tclquit"])
            stage_out = connection.send_config_set(stage_cmds, read_timeout=timeout)
            if not isinstance(stage_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH config stage for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            self._raise_if_tcl_failed("stage config", stage_out)

            # Integrity: staged file length must match expected (line-oriented tclsh).
            size_cmds = [
                "do tclsh",
                f'set f [open "{staged}" r]',
                "set body [read $f]",
                "close $f",
                "puts [string length $body]",
                "tclquit",
            ]
            size_out = connection.send_config_set(size_cmds, read_timeout=timeout)
            if not isinstance(size_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH stage size check for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            self._raise_if_tcl_failed("stage size check", size_out)
            self._assert_staged_length(size_out, expected_len)

            replace_out = connection.send_command(
                f"configure replace {staged} force",
                read_timeout=timeout,
            )
            if not isinstance(replace_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH config replace for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            output = replace_out
        except SshTransportError:
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged}", read_timeout=timeout)
            raise
        except _NETMIKO_FAILURES as exc:
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged}", read_timeout=timeout)
            raise SshTransportError(self._failure_message("config replace", exc)) from exc
        with contextlib.suppress(*_NETMIKO_FAILURES):
            connection.send_command(f"delete /force {staged}", read_timeout=timeout)
        return output

    @staticmethod
    def _tcl_escape_double_quoted(text: str) -> str:
        """Escape *text* for inclusion inside a Tcl double-quoted string (Tcl 8.3)."""
        return (
            text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("$", "\\$")
            .replace("[", "\\[")
            .replace("]", "\\]")
        )

    def _tcl_puts_line_commands(self, line: str) -> list[str]:
        """Build chunked ``puts`` commands that write *line* plus a trailing newline.

        Chunks are cut from the already-escaped string but never end on a bare
        ``\\`` (that would escape the closing quote of the Tcl double-quoted
        argument).
        """
        escaped = self._tcl_escape_double_quoted(line)
        if len(escaped) <= _TCL_CHUNK_CHARS:
            return [f'puts $fd "{escaped}"']
        cmds: list[str] = []
        for chunk in self._tcl_chunk_escaped(escaped, _TCL_CHUNK_CHARS):
            cmds.append(f'puts -nonewline $fd "{chunk}"')
        # Final empty puts supplies the line terminator (matches single-puts path).
        cmds.append('puts $fd ""')
        return cmds

    @staticmethod
    def _tcl_chunk_escaped(escaped: str, max_chars: int) -> list[str]:
        """Split *escaped* into chunks of at most *max_chars* without trailing ``\\``."""
        chunks: list[str] = []
        i = 0
        n = len(escaped)
        while i < n:
            end = min(i + max_chars, n)
            # If we would end on a backslash, pull back so the escape pair stays whole.
            if end < n and escaped[end - 1] == "\\":
                end -= 1
            if end <= i:
                # Pathological: max_chars == 1 and char is "\\" — take two chars.
                end = min(i + 2, n)
            chunks.append(escaped[i:end])
            i = end
        return chunks

    def _raise_if_tcl_failed(self, action: str, output: str) -> None:
        """Fail closed on tclsh/IOS error text before configure replace."""
        lowered = output.lower()
        if any(marker in lowered for marker in _TCL_ERROR_MARKERS):
            snippet = output.strip().splitlines()[0][:200] if output.strip() else "(empty)"
            raise SshTransportError(
                f"SSH {action} failed for {self._params.host}:{self._params.port} "
                f"(device_type={self._params.device_type!r}): tclsh error "
                f"({snippet!r}); configure replace not attempted"
            )

    def _assert_staged_length(self, size_output: str, expected: int) -> None:
        """Parse staged-file length from tclsh output; raise on mismatch."""
        matches = re.findall(r"\b(\d+)\b", size_output)
        if not matches:
            raise SshTransportError(
                f"SSH stage size check failed for {self._params.host}:{self._params.port}: "
                "could not parse staged file length; configure replace not attempted"
            )
        actual = int(matches[-1])
        if actual != expected:
            raise SshTransportError(
                f"SSH stage integrity failed for {self._params.host}:{self._params.port}: "
                f"staged {actual} bytes, expected {expected}; configure replace not attempted"
            )

    def confirm_config(self) -> str:
        """No-op finalize for Cisco-family (apply is already permanent).

        Typed :class:`~app.plugins.base.ConfigWriteTransport` surface so a shared
        lifecycle can call confirm after verify-after without capability sniffing.
        JunOS overrides this on :class:`~app.plugins.transport.junos_ssh.JunosSshTransport`.
        """
        return ""

    def rollback_config(self, n: int = 1) -> str:
        """Cisco-family has no ``rollback N`` — use :meth:`replace_config` instead."""
        raise SshTransportError(
            f"SSH rollback_config is not supported for device_type="
            f"{self._params.device_type!r} on {self._params.host}:{self._params.port}; "
            "use replace_config with the captured baseline (ADR-0021 §4)"
        )

    def _refuse_junos_write(self, surface: str) -> None:
        """Belt-and-suspenders: base Cisco-shaped writes must not run on JunOS."""
        if self._params.device_type == "juniper_junos":
            raise SshTransportError(
                f"SSH {surface} refused for device_type='juniper_junos' on "
                f"{self._params.host}:{self._params.port}: use JunosSshTransport via "
                "make_ssh_transport (Wave 3 / ADR-0026 commit-confirmed flow)"
            )

    def _require_connection(self) -> BaseConnection:
        """Return the open netmiko connection or raise if used outside the context."""
        connection = self._connection
        if connection is None:
            raise SshTransportError(
                f"SSH session to {self._params.host}:{self._params.port} is not open "
                "(use SshTransport as a context manager)"
            )
        return connection

    def _close(self) -> None:
        """Best-effort disconnect; never raises (close failures don't mask errors)."""
        connection, self._connection = self._connection, None
        if connection is not None:
            with contextlib.suppress(Exception):
                connection.disconnect()

    def _failure_message(self, action: str, exc: Exception) -> str:
        """Credential-free failure description: coordinates + exception class name."""
        params = self._params
        return (
            f"SSH {action} failed for {params.host}:{params.port} "
            f"(device_type={params.device_type!r}): {type(exc).__name__}"
        )

    def _host_key_failure_message(self, exc: Exception) -> str:
        """Connect failure message; name host-key remediation when applicable."""
        base = self._failure_message("connect", exc)
        text = f"{type(exc).__name__} {exc}".lower()
        if any(
            token in text
            for token in (
                "host key",
                "hostkey",
                "known_hosts",
                "not found in known_hosts",
                "rejectpolicy",
            )
        ):
            return (
                f"{base}: host key verification failed. Remediation: add the "
                f"device host key to the platform known_hosts, or pin "
                f"host_key_fingerprints[{self._params.host!r}] on the SSH "
                f"credential params (SHA256:…), or set NETOPS_SSH_STRICT=false "
                f"only in an isolated lab"
            )
        return base

    def _verify_pinned_fingerprint(self, connection: BaseConnection) -> None:
        """If a pin is configured, compare against the presented host key."""
        expected = self._params.host_key_fingerprint
        if not expected:
            return
        presented = _connection_host_key_fingerprint(connection)
        if presented is None:
            raise SshTransportError(
                f"SSH host-key pin configured for {self._params.host}:{self._params.port} "
                f"but the session did not expose a remote host key; "
                f"cannot verify pin {expected!r}"
            )
        if not _fingerprints_match(expected, presented):
            raise SshTransportError(
                f"SSH host-key pin mismatch for {self._params.host}:{self._params.port}: "
                f"expected {expected!r}, presented {presented!r}. Remediation: update "
                f"credential params host_key_fingerprints[{self._params.host!r}] or "
                f"investigate host substitution / MITM"
            )


def _connection_host_key_fingerprint(connection: BaseConnection) -> str | None:
    """Return ``SHA256:…`` fingerprint of the remote host key, if available."""
    remote = getattr(connection, "remote_conn", None)
    if remote is None:
        return None
    get_transport = getattr(remote, "get_transport", None)
    transport_obj = (
        get_transport()
        if callable(get_transport)
        else getattr(remote, "transport", None)  # some netmiko drivers
    )
    if transport_obj is None:
        return None
    get_key = getattr(transport_obj, "get_remote_server_key", None)
    if not callable(get_key):
        return None
    key = get_key()
    if key is None:
        return None
    # Prefer OpenSSH-style SHA256 base64 fingerprint.
    raw = key.asbytes() if hasattr(key, "asbytes") else str(key).encode()
    asbytes = raw if isinstance(raw, (bytes, bytearray)) else bytes(raw)
    digest = hashlib.sha256(asbytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _fingerprints_match(expected: str, presented: str) -> bool:
    """Compare fingerprints case-insensitively; accept SHA256: with/without padding."""
    exp = expected.strip().replace(" ", "")
    pres = presented.strip().replace(" ", "")
    if exp.lower().startswith("sha256:") and pres.lower().startswith("sha256:"):
        return exp.split(":", 1)[1].rstrip("=").lower() == pres.split(":", 1)[1].rstrip("=").lower()
    # Hex MD5 (legacy OpenSSH) comparison.
    exp_hex = exp.lower().removeprefix("md5:")
    pres_hex = pres.lower().removeprefix("md5:")
    try:
        return binascii.unhexlify(exp_hex.replace(":", "")) == binascii.unhexlify(
            pres_hex.replace(":", "")
        )
    except binascii.Error:
        return exp.lower() == pres.lower()
