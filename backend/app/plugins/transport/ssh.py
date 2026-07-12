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
import contextlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException, SSHException

from app.core.errors import PluginError

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
_TCL_ERROR_MARKERS: Final[tuple[str, ...]] = (
    "invalid command name",
    "syntax error",
    "can't read",
    "no such file",
    "couldn't open",
    "permission denied",
    "% invalid",
    "% error",
    "tclsh: ",
)

#: Match ``puts`` / stage path used when writing the base64 blob to flash.
_STAGED_CONFIG_PATH: Final[str] = "flash:netops-rollback.cfg"
_STAGED_B64_PATH: Final[str] = "flash:netops-rollback.b64"

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

    def __repr__(self) -> str:
        enable_secret = _REDACTED if self.enable_secret is not None else None
        return (
            f"SshParams(host={self.host!r}, device_type={self.device_type!r}, "
            f"username={self.username!r}, password={_REDACTED!r}, port={self.port!r}, "
            f"enable_secret={enable_secret!r}, conn_timeout={self.conn_timeout!r}, "
            f"read_timeout={self.read_timeout!r}, "
            f"commit_confirmed_minutes={self.commit_confirmed_minutes!r})"
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
        try:
            connection = ConnectHandler(
                host=params.host,
                device_type=params.device_type,
                username=params.username,
                password=params.password,
                port=params.port,
                secret=params.enable_secret or "",
                conn_timeout=params.conn_timeout,
            )
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message("connect", exc)) from exc
        self._connection = connection
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

        Mechanism (Wave 3 C3): base64-encode the candidate, stage via Tcl
        *without* embedding raw config in a double-quoted string (avoids Tcl
        substitution of ``$``, ``"``, ``[``/``]``), decode on-box to a
        deterministic flash file, verify staged length, then
        ``configure replace <file> force``. Any tclsh error output fails closed
        **before** replace is issued.

        Refuses ``juniper_junos`` — use :class:`~app.plugins.transport.junos_ssh.JunosSshTransport`.
        """
        self._refuse_junos_write("replace_config")
        connection = self._require_connection()
        candidate = "\n".join(lines)
        if not candidate.endswith("\n"):
            candidate = candidate + "\n"
        staged = _STAGED_CONFIG_PATH
        staged_b64 = _STAGED_B64_PATH
        timeout = self._params.read_timeout
        payload_b64 = base64.b64encode(candidate.encode("utf-8")).decode("ascii")
        expected_len = len(candidate.encode("utf-8"))
        try:
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged}", read_timeout=timeout)
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged_b64}", read_timeout=timeout)

            # Stage base64 text with Tcl puts — payload is A-Za-z0-9+/= only, so
            # double-quoted Tcl is safe (no $, ", [, ] from config body).
            stage_cmds = [
                "do tclsh",
                f'puts [open "{staged_b64}" w+] "{payload_b64}"',
                "tclquit",
            ]
            stage_out = connection.send_config_set(stage_cmds, read_timeout=timeout)
            if not isinstance(stage_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH config stage for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            self._raise_if_tcl_failed("stage base64", stage_out)

            # Decode on-box: binary base64 -d is available on IOS-XE/NX-OS/EOS
            # flash tooling paths that already use configure replace; fall back
            # to Tcl base64 decode when the binary is missing (classic IOS).
            decode_out = connection.send_command(
                f"tclsh\n"
                f"set b64 [open {{{staged_b64}}} r]\n"
                f"set data [read $b64]\n"
                f"close $b64\n"
                f"set bin [binary decode base64 $data]\n"
                f'set out [open "{staged}" w+]\n'
                f"puts -nonewline $out $bin\n"
                f"close $out\n"
                f"tclquit",
                read_timeout=timeout,
            )
            if not isinstance(decode_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH config decode for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            self._raise_if_tcl_failed("decode base64 stage", decode_out)

            # Integrity: staged file size must match plaintext byte length.
            size_out = connection.send_command(
                f"tclsh\n"
                f'set f [open "{staged}" r]\n'
                f"set body [read $f]\n"
                f"close $f\n"
                f"puts [string bytelength $body]\n"
                f"tclquit",
                read_timeout=timeout,
            )
            if not isinstance(size_out, str):  # pragma: no cover
                raise SshTransportError(
                    f"SSH stage size check for {self._params.host}:{self._params.port} "
                    "returned non-text output"
                )
            self._raise_if_tcl_failed("stage size check", size_out)
            self._assert_staged_length(size_out, expected_len)

            output = connection.send_command(
                f"configure replace {staged} force",
                read_timeout=timeout,
            )
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged}", read_timeout=timeout)
            with contextlib.suppress(*_NETMIKO_FAILURES):
                connection.send_command(f"delete /force {staged_b64}", read_timeout=timeout)
        except SshTransportError:
            raise
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message("config replace", exc)) from exc
        if not isinstance(output, str):  # pragma: no cover - structured output never requested
            raise SshTransportError(
                f"SSH config replace for {self._params.host}:{self._params.port} "
                "returned non-text output"
            )
        return output

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
        """Parse staged-file byte length from tclsh output; raise on mismatch."""
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
