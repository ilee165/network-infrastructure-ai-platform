"""Unit tests for the netmiko-backed SSH transport (M1-08, ADR-0007).

No network and no real devices: ``ConnectHandler`` is monkeypatched with an
in-memory fake. Covered behaviors: verbatim command passthrough, netmiko
error wrapping (without credential leakage), params repr redaction, session
lifecycle (connect / enable / disconnect), and ``CommandTransport`` protocol
conformance.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadException,
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


class FakeConnection:
    """In-memory stand-in for a connected netmiko ``BaseConnection``."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        send_error: Exception | None = None,
        disconnect_error: Exception | None = None,
    ) -> None:
        self.outputs = outputs or {}
        self.send_error = send_error
        self.disconnect_error = disconnect_error
        self.commands: list[tuple[str, float]] = []
        self.enabled = False
        self.disconnected = False

    def send_command(self, command: str, read_timeout: float = 10.0) -> str:
        if self.send_error is not None:
            raise self.send_error
        self.commands.append((command, read_timeout))
        return self.outputs.get(command, "")

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
