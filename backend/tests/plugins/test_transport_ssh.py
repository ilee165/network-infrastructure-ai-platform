"""Unit tests for the netmiko-backed SSH transport (M1-08, ADR-0007).

No network and no real devices: ``ConnectHandler`` is monkeypatched with an
in-memory fake. Covered behaviors: verbatim command passthrough, netmiko
error wrapping (without credential leakage), params repr redaction, session
lifecycle (connect / enable / disconnect), and ``CommandTransport`` protocol
conformance.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

import pytest
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadException,
    SSHException,
)

from app.core.errors import PluginError
from app.plugins.base import CommandTransport
from app.plugins.transport import ssh as ssh_module
from app.plugins.transport.ssh import SshParams, SshTransport, SshTransportError

# Deliberately distinctive fake secrets so leak assertions cannot false-negative.
PASSWORD = "pw-hunter2-XYZZY"
ENABLE_SECRET = "enable-hunter2-PLUGH"


def make_params(**overrides: Any) -> SshParams:
    defaults: dict[str, Any] = {
        "host": "192.0.2.10",
        "device_type": "cisco_ios",
        "username": "netops",
        "password": PASSWORD,
        "enable_secret": ENABLE_SECRET,
    }
    defaults.update(overrides)
    return SshParams(**defaults)


class _FakeRemoteKey:
    def __init__(self, material: bytes = b"test-host-key-material") -> None:
        self._material = material

    def asbytes(self) -> bytes:
        return self._material


class _FakeParamikoTransport:
    def __init__(self, key: _FakeRemoteKey | None = None) -> None:
        self._key = key if key is not None else _FakeRemoteKey()

    def get_remote_server_key(self) -> _FakeRemoteKey:
        return self._key


class _FakeRemoteConn:
    def __init__(self, key: _FakeRemoteKey | None = None) -> None:
        self._transport = _FakeParamikoTransport(key)

    def get_transport(self) -> _FakeParamikoTransport:
        return self._transport


class FakeConnection:
    """In-memory stand-in for a connected netmiko ``BaseConnection``."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        send_error: Exception | None = None,
        disconnect_error: Exception | None = None,
        config_error: Exception | None = None,
        config_set_output: str = "configured",
        host_key: _FakeRemoteKey | None = None,
    ) -> None:
        self.outputs = outputs or {}
        self.send_error = send_error
        self.disconnect_error = disconnect_error
        self.config_error = config_error
        self.config_set_output = config_set_output
        self.commands: list[tuple[str, float]] = []
        self.config_sets: list[list[str]] = []
        self.enabled = False
        self.disconnected = False
        self.staged_plain_len: int | None = None
        self._force_size_output: str | None = None
        self.remote_conn = _FakeRemoteConn(host_key)

    def send_command(self, command: str, read_timeout: float = 10.0) -> str:
        if self.send_error is not None:
            raise self.send_error
        self.commands.append((command, read_timeout))
        return self.outputs.get(command, "")

    def send_config_set(self, config_commands: list[str], read_timeout: float = 10.0) -> str:
        if self.config_error is not None:
            raise self.config_error
        self.config_sets.append(list(config_commands))
        joined = "\n".join(config_commands)
        if any("set fd [open" in c for c in config_commands):

            def _unescape_tcl(s: str) -> str:
                out: list[str] = []
                i = 0
                while i < len(s):
                    if s[i] == "\\" and i + 1 < len(s):
                        out.append(s[i + 1])
                        i += 2
                    else:
                        out.append(s[i])
                        i += 1
                return "".join(out)

            total = 0
            for cmd in config_commands:
                m = re.search(r'puts(?: -nonewline)? \$fd "(.*)"\s*$', cmd)
                if not m:
                    continue
                total += len(_unescape_tcl(m.group(1)))
                if cmd.startswith("puts $fd "):
                    total += 1  # puts adds trailing newline
            self.staged_plain_len = total
            # Echo stage commands like interactive tclsh (F3 residual surface:
            # marker text inside puts payloads must not false-abort).
            if self.config_set_output != "configured":
                return self.config_set_output
            return "\n".join(config_commands)
        if "string length" in joined or "NETOPS-LEN=" in joined:
            if self._force_size_output is not None:
                # Preserve anchored-token shape when forcing a bad length.
                if self._force_size_output.isdigit():
                    return f"NETOPS-LEN={self._force_size_output}"
                return self._force_size_output
            if self.staged_plain_len is not None:
                return f"NETOPS-LEN={self.staged_plain_len}"
        return self.config_set_output

    def enable(self) -> str:
        self.enabled = True
        return ""

    def disconnect(self) -> None:
        self.disconnected = True
        if self.disconnect_error is not None:
            raise self.disconnect_error


class FakeConnectHandler:
    """Callable replacing ``netmiko.ConnectHandler``; records kwargs."""

    def __init__(
        self, connection: FakeConnection | None = None, error: Exception | None = None
    ) -> None:
        self.connection = connection if connection is not None else FakeConnection()
        self.error = error
        self.kwargs: dict[str, Any] | None = None

    def __call__(self, **kwargs: Any) -> FakeConnection:
        self.kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.connection


@pytest.fixture()
def fake_netmiko(monkeypatch: pytest.MonkeyPatch) -> FakeConnectHandler:
    handler = FakeConnectHandler()
    monkeypatch.setattr(ssh_module, "ConnectHandler", handler)
    return handler


class TestSshParams:
    def test_repr_redacts_password_and_enable_secret(self) -> None:
        params = make_params()
        for rendered in (repr(params), str(params)):
            assert PASSWORD not in rendered
            assert ENABLE_SECRET not in rendered
            assert "***" in rendered
            assert "192.0.2.10" in rendered
            assert "netops" in rendered
            assert "cisco_ios" in rendered

    def test_repr_shows_none_for_absent_enable_secret(self) -> None:
        rendered = repr(make_params(enable_secret=None))
        assert "enable_secret=None" in rendered

    def test_frozen(self) -> None:
        params = make_params()
        with pytest.raises(dataclasses.FrozenInstanceError):
            params.password = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        params = make_params()
        assert params.port == 22
        assert params.conn_timeout > 0
        assert params.read_timeout > 0


class TestSshTransportSession:
    def test_run_returns_verbatim_output(self, fake_netmiko: FakeConnectHandler) -> None:
        verbatim = "Cisco IOS Software\r\n  weird   spacing\t\n!\n"
        fake_netmiko.connection.outputs["show version"] = verbatim
        with SshTransport(make_params()) as transport:
            assert transport.run("show version") == verbatim

    def test_run_passes_command_and_read_timeout(self, fake_netmiko: FakeConnectHandler) -> None:
        params = make_params(read_timeout=42.5)
        with SshTransport(params) as transport:
            transport.run("show ip route")
        assert fake_netmiko.connection.commands == [("show ip route", 42.5)]

    def test_connect_kwargs_forwarded(self, fake_netmiko: FakeConnectHandler) -> None:
        params = make_params(port=2222, conn_timeout=7.0)
        with SshTransport(params):
            pass
        assert fake_netmiko.kwargs is not None
        assert fake_netmiko.kwargs["host"] == "192.0.2.10"
        assert fake_netmiko.kwargs["device_type"] == "cisco_ios"
        assert fake_netmiko.kwargs["username"] == "netops"
        assert fake_netmiko.kwargs["password"] == PASSWORD
        assert fake_netmiko.kwargs["port"] == 2222
        assert fake_netmiko.kwargs["secret"] == ENABLE_SECRET
        assert fake_netmiko.kwargs["conn_timeout"] == 7.0
        # Wave 3 H7: strict host keys by default.
        assert fake_netmiko.kwargs["ssh_strict"] is True
        assert fake_netmiko.kwargs["system_host_keys"] is True

    def test_ssh_strict_opt_out_disables_system_host_keys(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with SshTransport(make_params(ssh_strict=False, system_host_keys=True)):
            pass
        assert fake_netmiko.kwargs is not None
        assert fake_netmiko.kwargs["ssh_strict"] is False
        assert fake_netmiko.kwargs["system_host_keys"] is False

    def test_pinned_fingerprint_accepted(self, fake_netmiko: FakeConnectHandler) -> None:
        from app.plugins.transport.ssh import _connection_host_key_fingerprint

        presented = _connection_host_key_fingerprint(fake_netmiko.connection)
        assert presented is not None
        with SshTransport(make_params(host_key_fingerprint=presented)):
            pass

    def test_pin_policy_lock_serializes_monkey_patch_window(self) -> None:
        """Re-review item 2: pin policy install/restore holds the process lock."""
        from app.plugins.transport.ssh import _PIN_POLICY_LOCK, _pinned_host_key_policy

        # Without a fingerprint the lock is not taken (no-op path).
        with _pinned_host_key_policy(None):
            assert _PIN_POLICY_LOCK.acquire(blocking=False)
            _PIN_POLICY_LOCK.release()
        # With a fingerprint the lock is held for the connect window.
        with _pinned_host_key_policy("SHA256:deadbeef"):
            assert not _PIN_POLICY_LOCK.acquire(blocking=False)
        assert _PIN_POLICY_LOCK.acquire(blocking=False)
        _PIN_POLICY_LOCK.release()

    def test_pinned_fingerprint_mismatch_rejected(self, fake_netmiko: FakeConnectHandler) -> None:
        with (
            pytest.raises(SshTransportError, match="pin mismatch"),
            SshTransport(make_params(host_key_fingerprint="SHA256:not-the-real-key")),
        ):
            pass
        assert fake_netmiko.connection.disconnected is True

    def test_unknown_host_key_error_names_remediation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class HostKeyError(SSHException):
            pass

        handler = FakeConnectHandler(error=HostKeyError("Host key not found in known_hosts"))
        monkeypatch.setattr(ssh_module, "ConnectHandler", handler)
        with (
            pytest.raises(SshTransportError, match="known_hosts") as excinfo,
            SshTransport(make_params()),
        ):
            pass
        assert "host_key_fingerprints" in str(excinfo.value)
        assert "NETOPS_SSH_STRICT" in str(excinfo.value)

    def test_enable_called_when_enable_secret_present(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with SshTransport(make_params()):
            pass
        assert fake_netmiko.connection.enabled is True

    def test_enable_not_called_without_enable_secret(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with SshTransport(make_params(enable_secret=None)):
            pass
        assert fake_netmiko.connection.enabled is False

    def test_satisfies_command_transport_protocol(self, fake_netmiko: FakeConnectHandler) -> None:
        fake_netmiko.connection.outputs["show clock"] = "12:00:00 UTC"
        with SshTransport(make_params()) as transport:
            assert isinstance(transport, CommandTransport)
            assert transport.send_command("show clock") == "12:00:00 UTC"

    def test_disconnect_called_on_clean_exit(self, fake_netmiko: FakeConnectHandler) -> None:
        with SshTransport(make_params()):
            pass
        assert fake_netmiko.connection.disconnected is True

    def test_disconnect_called_when_body_raises(self, fake_netmiko: FakeConnectHandler) -> None:
        with pytest.raises(RuntimeError, match="boom"), SshTransport(make_params()):
            raise RuntimeError("boom")
        assert fake_netmiko.connection.disconnected is True

    def test_exit_swallows_disconnect_failure(self, fake_netmiko: FakeConnectHandler) -> None:
        fake_netmiko.connection.disconnect_error = OSError("socket already closed")
        with SshTransport(make_params()):
            pass  # must not raise on exit

    def test_run_before_open_raises(self) -> None:
        transport = SshTransport(make_params())
        with pytest.raises(SshTransportError, match="not open"):
            transport.run("show version")


class TestSshConfigWrite:
    """The ADR-0021 config-write surfaces: merge (send_config) + replace."""

    def test_send_config_merges_via_send_config_set(self, fake_netmiko: FakeConnectHandler) -> None:
        with SshTransport(make_params()) as transport:
            output = transport.send_config(["interface Loopback0", " description x"])
        assert output == "configured"
        assert fake_netmiko.connection.config_sets == [["interface Loopback0", " description x"]]

    def test_send_config_before_open_raises(self) -> None:
        transport = SshTransport(make_params())
        with pytest.raises(SshTransportError, match="not open"):
            transport.send_config(["hostname x"])

    def test_send_config_failure_wrapped_without_credentials(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        fake_netmiko.connection.config_error = ReadException(f"apply failed; pw={PASSWORD}")
        with SshTransport(make_params()) as transport, pytest.raises(SshTransportError) as excinfo:
            transport.send_config(["hostname x"])
        assert PASSWORD not in str(excinfo.value)
        assert "ReadException" in str(excinfo.value)

    def test_replace_config_runs_configure_replace(self, fake_netmiko: FakeConnectHandler) -> None:
        fake_netmiko.connection.outputs["configure replace flash:netops-rollback.cfg force"] = (
            "applied 3 lines"
        )
        with SshTransport(make_params()) as transport:
            output = transport.replace_config(["hostname core-rtr01", "!", "end"])
        assert output == "applied 3 lines"
        # Candidate staged via escaped puts (Wave 3 C3) before replace.
        assert len(fake_netmiko.connection.config_sets) >= 2  # stage + size check
        stage = fake_netmiko.connection.config_sets[0]
        assert stage[0] == "do tclsh"
        assert any("set fd [open" in c for c in stage)
        assert any("puts $fd" in c for c in stage)
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert "configure replace flash:netops-rollback.cfg force" in issued

    def test_replace_config_escapes_hostile_tcl_metacharacters(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        """Raw Tcl metacharacters must not appear unescaped in stage commands."""
        hostile = [
            'banner motd ^C$variable "quoted" [brackets]\\path^C',
            "as-path access-list 1 permit _100$",
            "-----BEGIN CERTIFICATE-----",
            "MIIBkTCB+wIJAKHBjQz$not[real]",
            "-----END CERTIFICATE-----",
        ]
        fake_netmiko.connection.outputs["configure replace flash:netops-rollback.cfg force"] = "ok"
        with SshTransport(make_params()) as transport:
            transport.replace_config(hostile)
        stage = "\n".join(fake_netmiko.connection.config_sets[0])
        assert re.search(r"(?<!\\)\$variable", stage) is None
        assert re.search(r"(?<!\\)\[brackets\]", stage) is None
        assert "\\$variable" in stage
        assert "\\[brackets\\]" in stage
        assert '\\"' in stage

    def test_replace_config_f3_banner_markers_do_not_false_abort(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        """F3: error-marker text inside staged config/puts echoes must not abort.

        FakeConnection echoes stage commands (including ``puts $fd "…"`` lines).
        Without the puts-line filter + nested NETOPS-LEN read, banners containing
        "permission denied" / "syntax error" would false-abort before replace.
        """
        banner_lines = [
            "banner motd ^CAccess denied: permission denied for guests^C",
            "banner login ^CInvalid login may cause syntax error messages^C",
            "hostname edge-01",
        ]
        fake_netmiko.connection.outputs["configure replace flash:netops-rollback.cfg force"] = (
            "applied"
        )
        with SshTransport(make_params()) as transport:
            output = transport.replace_config(banner_lines)
        assert output == "applied"
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert "configure replace flash:netops-rollback.cfg force" in issued
        # Size path must not ``set body [read $f]`` (would echo full config into scan).
        size = fake_netmiko.connection.config_sets[1]
        size_joined = "\n".join(size)
        assert "set body" not in size_joined
        assert "NETOPS-LEN=[string length [read $f]]" in size_joined

    def test_replace_config_tcl_error_fails_closed_before_apply(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        fake_netmiko.connection.config_set_output = 'invalid command name "puts"\n% Error in Tcl'
        with (
            SshTransport(make_params()) as transport,
            pytest.raises(SshTransportError, match="configure replace not attempted"),
        ):
            transport.replace_config(["hostname x"])
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert not any(c.startswith("configure replace") for c in issued)

    def test_replace_config_bad_option_fails_closed(self, fake_netmiko: FakeConnectHandler) -> None:
        fake_netmiko.connection.config_set_output = 'bad option "decode": must be format or scan'
        with (
            SshTransport(make_params()) as transport,
            pytest.raises(SshTransportError, match="configure replace not attempted"),
        ):
            transport.replace_config(["hostname x"])
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert not any(c.startswith("configure replace") for c in issued)

    def test_replace_config_size_mismatch_fails_closed(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        fake_netmiko.connection._force_size_output = "99999"
        with (
            SshTransport(make_params()) as transport,
            pytest.raises(SshTransportError, match="stage integrity"),
        ):
            transport.replace_config(["hostname x"])
        issued = [c for c, _ in fake_netmiko.connection.commands]
        assert not any(c.startswith("configure replace") for c in issued)

    def test_replace_config_chunks_long_lines(self, fake_netmiko: FakeConnectHandler) -> None:
        long_line = "x" * 500
        fake_netmiko.connection.outputs["configure replace flash:netops-rollback.cfg force"] = "ok"
        with SshTransport(make_params()) as transport:
            transport.replace_config([long_line])
        stage = fake_netmiko.connection.config_sets[0]
        assert any("puts -nonewline $fd" in c for c in stage)
        assert 'puts $fd ""' in stage

    def test_replace_config_chunk_boundary_does_not_split_escapes(self) -> None:
        """Chunk cuts must not leave a trailing bare backslash before the closing quote."""
        line = "a" * 198 + "$" + "b" * 50  # escaped: 198 a's + \$ + 50 b's
        chunks = SshTransport._tcl_chunk_escaped(SshTransport._tcl_escape_double_quoted(line), 200)
        for chunk in chunks:
            run = 0
            for ch in reversed(chunk):
                if ch == "\\":
                    run += 1
                else:
                    break
            assert run % 2 == 0, f"unpaired trailing backslash in {chunk!r}"
        assert "\\$" in "".join(chunks)

    def test_replace_config_chunk_boundary_does_not_split_backslash_pair(self) -> None:
        """B2: literal backslash near the boundary must not create a bare trailing ``\\``."""
        line = "a" * 198 + "\\" + "b" * 50  # escaped: 198 a's + \\\\ + 50 b's
        escaped = SshTransport._tcl_escape_double_quoted(line)
        chunks = SshTransport._tcl_chunk_escaped(escaped, 200)
        for chunk in chunks:
            run = 0
            for ch in reversed(chunk):
                if ch == "\\":
                    run += 1
                else:
                    break
            assert run % 2 == 0, f"unpaired trailing backslash in {chunk!r}"
        assert "".join(chunks) == escaped

    def test_replace_config_before_open_raises(self) -> None:
        transport = SshTransport(make_params())
        with pytest.raises(SshTransportError, match="not open"):
            transport.replace_config(["hostname x"])

    def test_replace_config_failure_wrapped_without_credentials(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        fake_netmiko.connection.config_error = ReadException(f"replace failed; pw={PASSWORD}")
        with SshTransport(make_params()) as transport, pytest.raises(SshTransportError) as excinfo:
            transport.replace_config(["hostname x"])
        assert PASSWORD not in str(excinfo.value)
        assert "ReadException" in str(excinfo.value)
        assert "config replace" in str(excinfo.value)

    def test_confirm_config_is_noop_for_cisco_family(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with SshTransport(make_params()) as transport:
            assert transport.confirm_config() == ""
        assert fake_netmiko.connection.commands == []

    def test_rollback_config_refused_for_cisco_family(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with (
            SshTransport(make_params()) as transport,
            pytest.raises(SshTransportError, match="not supported"),
        ):
            transport.rollback_config(1)

    def test_base_transport_refuses_junos_send_config(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with (
            SshTransport(make_params(device_type="juniper_junos")) as transport,
            pytest.raises(SshTransportError, match="JunosSshTransport"),
        ):
            transport.send_config(["set system host-name x"])

    def test_base_transport_refuses_junos_replace_config(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        with (
            SshTransport(make_params(device_type="juniper_junos")) as transport,
            pytest.raises(SshTransportError, match="JunosSshTransport"),
        ):
            transport.replace_config(["set system host-name x"])


class TestJunosSshTransport:
    """Wave 3 C2: JunOS commit-confirmed sequence (Option A)."""

    def test_send_config_sequence_ends_at_commit_confirmed_not_commit(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        from app.plugins.transport import JunosSshTransport, make_ssh_transport

        params = make_params(device_type="juniper_junos", commit_confirmed_minutes=2)
        assert isinstance(make_ssh_transport(params), JunosSshTransport)
        lines = ["set system host-name lab-mx"]
        with JunosSshTransport(params) as transport:
            transport.send_config(lines)
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert issued[0] == "configure"
        assert issued[1] == "load merge terminal"
        assert "set system host-name lab-mx" in issued
        assert "\x04" in issued  # Ctrl-D ends load … terminal
        assert "commit check" in issued
        assert "commit confirmed 2" in issued
        # Option A: no bare confirming commit inside apply
        assert "commit" not in issued
        conf_idx = issued.index("commit confirmed 2")
        check_idx = issued.index("commit check")
        eof_idx = issued.index("\x04")
        assert eof_idx < check_idx < conf_idx
        # B6: exit config mode for operational verify-after capture
        assert "exit" in issued
        assert issued.index("commit confirmed 2") < issued.index("exit")

    def test_replace_config_uses_load_override(self, fake_netmiko: FakeConnectHandler) -> None:
        from app.plugins.transport import JunosSshTransport

        params = make_params(device_type="juniper_junos", commit_confirmed_minutes=3)
        with JunosSshTransport(params) as transport:
            transport.replace_config(["set system host-name restored"])
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert "load override terminal" in issued
        assert "commit confirmed 3" in issued
        assert "commit" not in issued
        assert "exit" in issued

    def test_confirm_config_issues_commit(self, fake_netmiko: FakeConnectHandler) -> None:
        from app.plugins.transport import JunosSshTransport

        with JunosSshTransport(make_params(device_type="juniper_junos")) as transport:
            transport.confirm_config()
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert issued[0] == "configure"
        assert issued[1] == "commit"
        assert "exit" in issued

    def test_commit_check_failure_skips_commit_confirmed(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        from app.plugins.transport import JunosSshTransport

        fake_netmiko.connection.outputs["commit check"] = "error: missing mandatory statement"
        with (
            JunosSshTransport(make_params(device_type="juniper_junos")) as transport,
            pytest.raises(SshTransportError, match="commit check"),
        ):
            transport.send_config(["set system host-name bad"])
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert "commit check" in issued
        assert not any(c.startswith("commit confirmed") for c in issued)
        assert "commit" not in issued

    def test_rollback_config_orders_rollback_before_commit(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        from app.plugins.transport import JunosSshTransport

        with JunosSshTransport(make_params(device_type="juniper_junos")) as transport:
            transport.rollback_config(1)
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert issued[0] == "configure"
        assert issued[1] == "rollback 1"
        assert issued[2] == "commit"
        # Never bare commit before rollback
        assert issued.index("rollback 1") < issued.index("commit")

    def test_rollback_config_failed_rollback_does_not_commit(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        """B1: failed rollback N must not issue confirming bare commit."""
        from app.plugins.transport import JunosSshTransport

        fake_netmiko.connection.outputs["rollback 1"] = "error: cannot rollback"
        with (
            JunosSshTransport(make_params(device_type="juniper_junos")) as transport,
            pytest.raises(SshTransportError, match="rollback"),
        ):
            transport.rollback_config(1)
        issued = [command for command, _timeout in fake_netmiko.connection.commands]
        assert "rollback 1" in issued
        assert "commit" not in issued


class TestSshParamsFromHelper:
    def test_ssh_params_from_applies_strict_and_host_keyed_pin(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core.config import Settings
        from app.plugins.transport import ssh_params_from

        settings = Settings(
            env="dev",
            ssh_strict=True,
            junos_commit_confirmed_minutes=2,
        )
        params = ssh_params_from(
            host="10.0.0.1",
            device_type="cisco_ios",
            username="u",
            password="p",
            cred_params={"host_key_fingerprints": {"10.0.0.1": "SHA256:abc"}, "port": 2222},
            settings=settings,
        )
        assert params.ssh_strict is True
        assert params.host_key_fingerprint == "SHA256:abc"
        assert params.port == 2222


class TestSshErrorWrapping:
    def test_error_is_plugin_error(self) -> None:
        assert issubclass(SshTransportError, PluginError)

    def test_connect_timeout_wrapped_without_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = NetmikoTimeoutException(f"timed out; pw={PASSWORD} en={ENABLE_SECRET}")
        handler = FakeConnectHandler(error=original)
        monkeypatch.setattr(ssh_module, "ConnectHandler", handler)
        with pytest.raises(SshTransportError) as excinfo, SshTransport(make_params()):
            pass
        error = excinfo.value
        assert PASSWORD not in str(error)
        assert ENABLE_SECRET not in str(error)
        assert PASSWORD not in repr(error)
        assert "NetmikoTimeoutException" in str(error)
        assert "192.0.2.10" in str(error)
        assert error.__cause__ is original

    def test_auth_failure_wrapped_without_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = NetmikoAuthenticationException(f"auth failed with {PASSWORD}")
        handler = FakeConnectHandler(error=original)
        monkeypatch.setattr(ssh_module, "ConnectHandler", handler)
        with pytest.raises(SshTransportError) as excinfo, SshTransport(make_params()):
            pass
        assert PASSWORD not in str(excinfo.value)
        assert "NetmikoAuthenticationException" in str(excinfo.value)
        assert excinfo.value.__cause__ is original

    def test_run_failure_wrapped_without_credentials(
        self, fake_netmiko: FakeConnectHandler
    ) -> None:
        original = ReadException(f"read failed; pw={PASSWORD}")
        fake_netmiko.connection.send_error = original
        with SshTransport(make_params()) as transport, pytest.raises(SshTransportError) as excinfo:
            transport.run("show version")
        assert PASSWORD not in str(excinfo.value)
        assert "ReadException" in str(excinfo.value)
        assert "show version" in str(excinfo.value)
        assert excinfo.value.__cause__ is original

    def test_enable_failure_wrapped_and_disconnects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        connection = FakeConnection()

        def failing_enable() -> str:
            raise ReadException(f"enable failed; secret={ENABLE_SECRET}")

        connection.enable = failing_enable  # type: ignore[method-assign]
        handler = FakeConnectHandler(connection=connection)
        monkeypatch.setattr(ssh_module, "ConnectHandler", handler)
        with pytest.raises(SshTransportError) as excinfo, SshTransport(make_params()):
            pass
        assert ENABLE_SECRET not in str(excinfo.value)
        assert connection.disconnected is True
