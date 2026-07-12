"""JunOS SSH config-write transport (Wave 3 C2 / ADR-0026 Option A).

:class:`JunosSshTransport` subclasses :class:`~app.plugins.transport.ssh.SshTransport`
for session open/close and command reads, and overrides the write surfaces so
JunOS deploy/restore issue a real ``load`` → ``commit check`` →
``commit confirmed <N>`` sequence — **not** the Cisco ``send_config_set`` /
``configure replace`` path that left every JunOS write as a silent no-op.

Option A (ADR-faithful):

- :meth:`send_config` / :meth:`replace_config` end at ``commit confirmed <N>``
  (device state is tentatively active; dead-man timer armed).
- :meth:`confirm_config` issues the confirming ``commit`` **after** plugin
  verify-after success.
- On verify-after failure the plugin withholds confirm and runs structured
  rollback; the confirmed timer is the backstop if rollback cannot complete.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Literal

from netmiko.exceptions import NetmikoBaseException, SSHException

from app.plugins.transport.ssh import SshTransport, SshTransportError

__all__ = ["JunosSshTransport"]

_NETMIKO_FAILURES: tuple[type[Exception], ...] = (NetmikoBaseException, SSHException)

#: Substrings that indicate commit-check / commit failure in JunOS CLI output.
#: Kept narrow to avoid false-failing informational CLI text.
_FAILURE_MARKERS: Final[tuple[str, ...]] = (
    "error:",
    "syntax error",
    "missing mandatory",
)

#: End-of-file for ``load … terminal`` (JunOS expects Ctrl-D to finish the paste).
_LOAD_TERMINAL_EOF: Final[str] = "\x04"


class JunosSshTransport(SshTransport):
    """Netmiko session with JunOS candidate + commit-confirmed write surfaces."""

    def send_config(self, lines: Sequence[str]) -> str:
        """``load merge`` of *lines* (set-form) → ``commit check`` → ``commit confirmed <N>``.

        Does **not** issue the confirming ``commit`` — that is
        :meth:`confirm_config` after verify-after (Option A).
        """
        return self._confirmed_load(lines, mode="merge")

    def replace_config(self, lines: Sequence[str]) -> str:
        """``load override`` of *lines* → ``commit check`` → ``commit confirmed <N>``.

        Restore/rollback apply surface. Confirming ``commit`` is still
        :meth:`confirm_config` after verify-after.
        """
        return self._confirmed_load(lines, mode="override")

    def confirm_config(self) -> str:
        """Confirming ``commit`` — makes a pending confirmed commit permanent."""
        connection = self._require_connection()
        try:
            output = connection.send_command("commit", read_timeout=self._params.read_timeout)
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message("commit confirm", exc)) from exc
        if not isinstance(output, str):  # pragma: no cover
            raise SshTransportError(
                f"SSH commit confirm for {self._params.host}:{self._params.port} "
                "returned non-text output"
            )
        self._raise_if_cli_failed("commit confirm", output)
        return output

    def rollback_config(self, n: int = 1) -> str:
        """``rollback N`` + ``commit`` — commits the rolled-back baseline, not the bad change.

        Ordering is intentional: never a bare ``commit`` before ``rollback``.
        """
        if n < 0:
            raise SshTransportError(
                f"SSH rollback_config n must be >= 0 for {self._params.host}:{self._params.port}"
            )
        connection = self._require_connection()
        timeout = self._params.read_timeout
        parts: list[str] = []
        try:
            parts.append(str(connection.send_command("configure", read_timeout=timeout)))
            parts.append(str(connection.send_command(f"rollback {n}", read_timeout=timeout)))
            parts.append(str(connection.send_command("commit", read_timeout=timeout)))
            # Exit config mode best-effort (not part of the commit contract).
            exit_mode = getattr(connection, "exit_config_mode", None)
            if callable(exit_mode):
                try:
                    exit_mode()
                except _NETMIKO_FAILURES:
                    parts.append(str(connection.send_command("exit", read_timeout=timeout)))
            else:
                parts.append(str(connection.send_command("exit", read_timeout=timeout)))
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message("rollback", exc)) from exc
        joined = "\n".join(parts)
        self._raise_if_cli_failed("rollback", joined)
        return joined

    def _confirmed_load(self, lines: Sequence[str], *, mode: Literal["merge", "override"]) -> str:
        """Enter config, load candidate, commit check, commit confirmed — no final confirm."""
        connection = self._require_connection()
        timeout = self._params.read_timeout
        minutes = self._params.commit_confirmed_minutes
        if not 1 <= minutes <= 60:
            raise SshTransportError(
                f"SSH commit confirmed minutes must be 1..60 for "
                f"{self._params.host}:{self._params.port}, got {minutes}"
            )
        load_cmd = f"load {mode} terminal"
        parts: list[str] = []
        try:
            # Exact ordered sequence (unit tests pin these strings):
            # configure → load {merge|override} terminal → <set-form body> →
            # Ctrl-D (end terminal load) → commit check → commit confirmed <N>
            # Confirming ``commit`` is deliberately NOT issued here (Option A).
            parts.append(str(connection.send_command("configure", read_timeout=timeout)))
            parts.append(str(connection.send_command(load_cmd, read_timeout=timeout)))
            body = "\n".join(lines)
            if body:
                parts.append(str(connection.send_command(body, read_timeout=timeout)))
            # JunOS ``load … terminal`` waits for EOF (Ctrl-D) before accepting
            # further CLI; without this, commit check is swallowed as load input.
            parts.append(str(connection.send_command(_LOAD_TERMINAL_EOF, read_timeout=timeout)))
            check_out = str(connection.send_command("commit check", read_timeout=timeout))
            parts.append(check_out)
            self._raise_if_cli_failed("commit check", check_out)
            confirmed = str(
                connection.send_command(f"commit confirmed {minutes}", read_timeout=timeout)
            )
            parts.append(confirmed)
            self._raise_if_cli_failed("commit confirmed", confirmed)
        except SshTransportError:
            raise
        except _NETMIKO_FAILURES as exc:
            raise SshTransportError(self._failure_message(f"config {mode}", exc)) from exc
        return "\n".join(parts)

    def _raise_if_cli_failed(self, action: str, output: str) -> None:
        """Fail closed on known JunOS error markers in *output* (device text, not exceptions)."""
        lowered = output.lower()
        if any(marker in lowered for marker in _FAILURE_MARKERS):
            # Surface a short slice of device text for operators; never credentials
            # (config body is not embedded in transport errors here).
            snippet = output.strip().splitlines()[0][:200] if output.strip() else "(empty)"
            raise SshTransportError(
                f"SSH {action} failed for {self._params.host}:{self._params.port} "
                f"(device_type={self._params.device_type!r}): device rejected change "
                f"({snippet!r})"
            )
