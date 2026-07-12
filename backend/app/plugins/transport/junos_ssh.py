"""JunOS SSH config-write transport (Wave 3 C2 / ADR-0026 Option A).

:class:`JunosSshTransport` subclasses :class:`~app.plugins.transport.ssh.SshTransport`
for session open/close and command reads, and overrides the write surfaces so
JunOS deploy/restore issue a real ``load`` → ``commit check`` →
``commit confirmed <N>`` sequence — **not** the Cisco ``send_config_set`` /
``configure replace`` path that left every JunOS write as a silent no-op.

Option A (ADR-faithful):

- :meth:`send_config` / :meth:`replace_config` end at ``commit confirmed <N>``
  then **exit config mode** so verify-after operational commands work (B6).
- :meth:`confirm_config` re-enters config and issues confirming ``commit``.
- On verify-after failure the plugin withholds confirm and runs structured
  rollback; the confirmed timer is the backstop if rollback cannot complete.
- :meth:`rollback_config` fails closed if ``rollback N`` errors — never issues
  bare ``commit`` after a failed rollback (B1).
"""

from __future__ import annotations

import contextlib
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
        :meth:`confirm_config` after verify-after (Option A). Exits config mode
        after the confirmed commit so operational-mode capture works.
        """
        return self._confirmed_load(lines, mode="merge")

    def replace_config(self, lines: Sequence[str]) -> str:
        """``load override`` of *lines* → ``commit check`` → ``commit confirmed <N>``.

        Restore apply surface. Confirming ``commit`` is still
        :meth:`confirm_config` after verify-after.
        """
        return self._confirmed_load(lines, mode="override")

    def confirm_config(self) -> str:
        """Confirming ``commit`` — re-enter config, commit, exit (B6 mode discipline)."""
        connection = self._require_connection()
        timeout = self._params.read_timeout
        parts: list[str] = []
        try:
            parts.append(str(connection.send_command("configure", read_timeout=timeout)))
            commit_out = str(connection.send_command("commit", read_timeout=timeout))
            parts.append(commit_out)
            self._raise_if_cli_failed("commit confirm", commit_out)
            self._exit_config(connection, parts, timeout)
        except SshTransportError:
            self._best_effort_exit(connection, timeout)
            raise
        except _NETMIKO_FAILURES as exc:
            self._best_effort_exit(connection, timeout)
            raise SshTransportError(self._failure_message("commit confirm", exc)) from exc
        return "\n".join(parts)

    def rollback_config(self, n: int = 1) -> str:
        """``rollback N`` + ``commit`` — never bare commit if rollback failed (B1).

        Ordering is intentional: never a bare ``commit`` before ``rollback``.
        Each step is checked; a failed ``rollback N`` raises without sending
        ``commit`` (which would permanently confirm a pending bad change).
        """
        if n < 1:
            raise SshTransportError(
                f"SSH rollback_config n must be >= 1 for {self._params.host}:{self._params.port}"
            )
        connection = self._require_connection()
        timeout = self._params.read_timeout
        parts: list[str] = []
        try:
            parts.append(str(connection.send_command("configure", read_timeout=timeout)))
            rb_out = str(connection.send_command(f"rollback {n}", read_timeout=timeout))
            parts.append(rb_out)
            # B1: fail closed BEFORE commit — a bare commit after failed rollback
            # permanently confirms the bad tentative config.
            self._raise_if_cli_failed("rollback", rb_out)
            commit_out = str(connection.send_command("commit", read_timeout=timeout))
            parts.append(commit_out)
            self._raise_if_cli_failed("rollback commit", commit_out)
            self._exit_config(connection, parts, timeout)
        except SshTransportError:
            self._best_effort_exit(connection, timeout)
            raise
        except _NETMIKO_FAILURES as exc:
            self._best_effort_exit(connection, timeout)
            raise SshTransportError(self._failure_message("rollback", exc)) from exc
        return "\n".join(parts)

    def _confirmed_load(self, lines: Sequence[str], *, mode: Literal["merge", "override"]) -> str:
        """Enter config, load candidate, commit check, commit confirmed, exit config."""
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
            # Ctrl-D → commit check → commit confirmed <N> → exit
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
            # B6: leave config mode so plugin verify-after can run operational show.
            self._exit_config(connection, parts, timeout)
        except SshTransportError:
            # F4: discard dirty candidate on failure (best-effort).
            self._discard_candidate(connection, timeout)
            raise
        except _NETMIKO_FAILURES as exc:
            self._discard_candidate(connection, timeout)
            raise SshTransportError(self._failure_message(f"config {mode}", exc)) from exc
        return "\n".join(parts)

    def _exit_config(self, connection: object, parts: list[str], timeout: float) -> None:
        """Leave configuration mode (operational mode for show / verify-after)."""
        exit_mode = getattr(connection, "exit_config_mode", None)
        if callable(exit_mode):
            try:
                exit_mode()
                return
            except _NETMIKO_FAILURES:
                pass
        parts.append(str(connection.send_command("exit", read_timeout=timeout)))  # type: ignore[attr-defined]

    def _best_effort_exit(self, connection: object, timeout: float) -> None:
        with_context: list[str] = []
        try:
            self._exit_config(connection, with_context, timeout)
        except Exception:  # noqa: BLE001
            return

    def _discard_candidate(self, connection: object, timeout: float) -> None:
        """Best-effort rollback 0 + exit so a failed load does not poison the candidate."""
        with contextlib.suppress(Exception):
            connection.send_command("rollback 0", read_timeout=timeout)  # type: ignore[attr-defined]
        self._best_effort_exit(connection, timeout)

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
