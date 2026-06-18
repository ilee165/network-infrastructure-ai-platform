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
worker tasks, never on the FastAPI event loop (ADR-0007 §3, ADR-0008).
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException, SSHException

from app.core.errors import PluginError

if TYPE_CHECKING:
    from netmiko import BaseConnection

__all__ = ["SshParams", "SshTransport", "SshTransportError"]

_REDACTED = "***REDACTED***"

#: Netmiko (and re-exported paramiko) failures wrapped into SshTransportError.
_NETMIKO_FAILURES: tuple[type[Exception], ...] = (NetmikoBaseException, SSHException)


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
    """

    host: str
    device_type: str
    username: str
    password: str
    port: int = 22
    enable_secret: str | None = None
    conn_timeout: float = 10.0
    read_timeout: float = 30.0

    def __repr__(self) -> str:
        enable_secret = _REDACTED if self.enable_secret is not None else None
        return (
            f"SshParams(host={self.host!r}, device_type={self.device_type!r}, "
            f"username={self.username!r}, password={_REDACTED!r}, port={self.port!r}, "
            f"enable_secret={enable_secret!r}, conn_timeout={self.conn_timeout!r}, "
            f"read_timeout={self.read_timeout!r})"
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
        """Apply *lines* in configuration mode; return device output verbatim.

        The :class:`~app.plugins.base.ConfigWriteTransport` write surface for the
        M5 config write path (ADR-0021): netmiko's ``send_config_set`` enters
        ``configure terminal``, sends the lines, and exits config mode. Used only
        as the execution step of an approved ChangeRequest (the Automation Agent,
        Wave 4); the capability layer captures/verifies around it.
        """
        connection = self._connection
        if connection is None:
            raise SshTransportError(
                f"SSH session to {self._params.host}:{self._params.port} is not open "
                "(use SshTransport as a context manager)"
            )
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
