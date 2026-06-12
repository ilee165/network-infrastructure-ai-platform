"""Unit tests for the pysnmp-backed SNMP client (M1-08, ADR-0007).

No network: the pysnmp HLAPI surface used by :mod:`app.plugins.transport.snmp`
(``SnmpEngine``, ``UdpTransportTarget``, ``get_cmd``, ``walk_cmd``,
``CommunityData``, ``UsmUserData``) is monkeypatched with recording fakes.
Covered behaviors: params repr redaction, v2c vs v3 auth dispatch (including
protocol mapping), GET result assembly, walk pagination assembly across
batches, error mapping, and engine dispatcher cleanup.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from typing import Any

import pytest
from pysnmp.error import PySnmpError
from pysnmp.hlapi.v3arch.asyncio import (
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACSHAAuthProtocol,
)

from app.core.errors import PluginError
from app.plugins.transport import snmp as snmp_module
from app.plugins.transport.snmp import (
    SnmpAuthProtocol,
    SnmpClient,
    SnmpPrivProtocol,
    SnmpTransportError,
    SnmpV2cParams,
    SnmpV3Params,
)

# Deliberately distinctive fake secrets so leak assertions cannot false-negative.
COMMUNITY = "c0mmun1ty-XYZZY"
AUTH_KEY = "auth-key-PLUGH"
PRIV_KEY = "priv-key-FNORD"


def make_v2c_params(**overrides: Any) -> SnmpV2cParams:
    defaults: dict[str, Any] = {"host": "192.0.2.20", "community": COMMUNITY}
    defaults.update(overrides)
    return SnmpV2cParams(**defaults)


def make_v3_params(**overrides: Any) -> SnmpV3Params:
    defaults: dict[str, Any] = {
        "host": "192.0.2.30",
        "user": "snmp-operator",
        "auth_key": AUTH_KEY,
        "priv_key": PRIV_KEY,
    }
    defaults.update(overrides)
    return SnmpV3Params(**defaults)


class FakeOid:
    def __init__(self, oid: str) -> None:
        self._oid = oid

    def __str__(self) -> str:
        return self._oid


class FakeValue:
    def __init__(self, value: str) -> None:
        self._value = value

    def prettyPrint(self) -> str:  # noqa: N802 - pysnmp API name
        return self._value


class FakeErrorStatus:
    """Truthy stand-in for a non-zero pysnmp errorStatus Integer32."""

    def __init__(self, text: str) -> None:
        self._text = text

    def __bool__(self) -> bool:
        return True

    def prettyPrint(self) -> str:  # noqa: N802 - pysnmp API name
        return self._text


def varbind(oid: str, value: str) -> tuple[FakeOid, FakeValue]:
    return (FakeOid(oid), FakeValue(value))


@pytest.fixture()
def fake_pysnmp(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Patch the pysnmp surface in the snmp module with recording fakes."""
    rec = SimpleNamespace(
        engines=[],
        targets=[],
        get_calls=[],
        walk_calls=[],
        community_data=[],
        usm_user_data=[],
        get_result=(None, 0, 0, []),
        get_error=None,
        walk_batches=[],
    )

    class FakeEngine:
        def __init__(self) -> None:
            self.closed = False
            rec.engines.append(self)

        def close_dispatcher(self) -> None:
            self.closed = True

    class FakeTransportTarget:
        @classmethod
        async def create(cls, address: tuple[str, int], **kwargs: Any) -> FakeTransportTarget:
            target = cls()
            target.address = address
            target.kwargs = kwargs
            rec.targets.append(target)
            return target

    class FakeCommunityData:
        def __init__(self, community: str, mpModel: int | None = None) -> None:  # noqa: N803
            self.community = community
            self.mpModel = mpModel
            rec.community_data.append(self)

    class FakeUsmUserData:
        def __init__(self, user: str, **kwargs: Any) -> None:
            self.user = user
            self.kwargs = kwargs
            rec.usm_user_data.append(self)

    async def fake_get_cmd(
        engine: Any, auth: Any, target: Any, context: Any, *var_binds: Any, **options: Any
    ) -> Any:
        rec.get_calls.append(
            SimpleNamespace(
                engine=engine, auth=auth, target=target, var_binds=var_binds, options=options
            )
        )
        if rec.get_error is not None:
            raise rec.get_error
        return rec.get_result

    def fake_walk_cmd(
        engine: Any, auth: Any, target: Any, context: Any, var_bind: Any, **options: Any
    ) -> Any:
        rec.walk_calls.append(
            SimpleNamespace(
                engine=engine, auth=auth, target=target, var_bind=var_bind, options=options
            )
        )

        async def generate() -> Any:
            for batch in rec.walk_batches:
                if isinstance(batch, Exception):
                    raise batch
                yield batch

        return generate()

    monkeypatch.setattr(snmp_module, "SnmpEngine", FakeEngine)
    monkeypatch.setattr(snmp_module, "UdpTransportTarget", FakeTransportTarget)
    monkeypatch.setattr(snmp_module, "CommunityData", FakeCommunityData)
    monkeypatch.setattr(snmp_module, "UsmUserData", FakeUsmUserData)
    monkeypatch.setattr(snmp_module, "get_cmd", fake_get_cmd)
    monkeypatch.setattr(snmp_module, "walk_cmd", fake_walk_cmd)
    return rec


class TestSnmpParams:
    def test_v2c_repr_redacts_community(self) -> None:
        params = make_v2c_params()
        for rendered in (repr(params), str(params)):
            assert COMMUNITY not in rendered
            assert "***" in rendered
            assert "192.0.2.20" in rendered

    def test_v3_repr_redacts_keys(self) -> None:
        params = make_v3_params()
        for rendered in (repr(params), str(params)):
            assert AUTH_KEY not in rendered
            assert PRIV_KEY not in rendered
            assert "***" in rendered
            assert "snmp-operator" in rendered
            assert "192.0.2.30" in rendered

    def test_v2c_frozen(self) -> None:
        params = make_v2c_params()
        with pytest.raises(dataclasses.FrozenInstanceError):
            params.community = "other"  # type: ignore[misc]

    def test_v3_frozen(self) -> None:
        params = make_v3_params()
        with pytest.raises(dataclasses.FrozenInstanceError):
            params.auth_key = "other"  # type: ignore[misc]

    def test_v3_defaults_to_sha_aes_authpriv(self) -> None:
        params = make_v3_params()
        assert params.auth_protocol is SnmpAuthProtocol.SHA
        assert params.priv_protocol is SnmpPrivProtocol.AES128

    def test_default_port(self) -> None:
        assert make_v2c_params().port == 161
        assert make_v3_params().port == 161


class TestSnmpGet:
    def test_get_returns_oid_value_mapping(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.get_result = (
            None,
            0,
            0,
            [varbind("1.3.6.1.2.1.1.1.0", "Cisco IOS"), varbind("1.3.6.1.2.1.1.5.0", "r1")],
        )
        client = SnmpClient(make_v2c_params())
        result = client.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"])
        assert result == {"1.3.6.1.2.1.1.1.0": "Cisco IOS", "1.3.6.1.2.1.1.5.0": "r1"}
        assert len(fake_pysnmp.get_calls) == 1
        assert len(fake_pysnmp.get_calls[0].var_binds) == 2

    def test_get_targets_host_port_with_timeouts(self, fake_pysnmp: SimpleNamespace) -> None:
        client = SnmpClient(make_v2c_params(port=10161, timeout=9.0, retries=4))
        client.get(["1.3.6.1.2.1.1.1.0"])
        target = fake_pysnmp.targets[0]
        assert target.address == ("192.0.2.20", 10161)
        assert target.kwargs["timeout"] == 9.0
        assert target.kwargs["retries"] == 4

    def test_get_empty_oids_raises(self) -> None:
        # No fake_pysnmp fixture: the empty-OID guard fires before any pysnmp call.
        client = SnmpClient(make_v2c_params())
        with pytest.raises(ValueError, match="at least one OID"):
            client.get([])

    def test_get_closes_engine_dispatcher(self, fake_pysnmp: SimpleNamespace) -> None:
        SnmpClient(make_v2c_params()).get(["1.3.6.1.2.1.1.1.0"])
        assert len(fake_pysnmp.engines) == 1
        assert fake_pysnmp.engines[0].closed is True


class TestSnmpAuthDispatch:
    def test_v2c_uses_community_data(self, fake_pysnmp: SimpleNamespace) -> None:
        SnmpClient(make_v2c_params()).get(["1.3.6.1.2.1.1.1.0"])
        assert len(fake_pysnmp.community_data) == 1
        assert fake_pysnmp.usm_user_data == []
        auth = fake_pysnmp.get_calls[0].auth
        assert auth is fake_pysnmp.community_data[0]
        assert auth.community == COMMUNITY
        assert auth.mpModel == 1  # SNMPv2c, never v1

    def test_v3_uses_usm_user_data_with_default_protocols(
        self, fake_pysnmp: SimpleNamespace
    ) -> None:
        SnmpClient(make_v3_params()).get(["1.3.6.1.2.1.1.1.0"])
        assert fake_pysnmp.community_data == []
        assert len(fake_pysnmp.usm_user_data) == 1
        auth = fake_pysnmp.get_calls[0].auth
        assert auth is fake_pysnmp.usm_user_data[0]
        assert auth.user == "snmp-operator"
        assert auth.kwargs["authKey"] == AUTH_KEY
        assert auth.kwargs["privKey"] == PRIV_KEY
        assert auth.kwargs["authProtocol"] is usmHMACSHAAuthProtocol
        assert auth.kwargs["privProtocol"] is usmAesCfb128Protocol

    def test_v3_protocol_mapping_non_default(self, fake_pysnmp: SimpleNamespace) -> None:
        params = make_v3_params(
            auth_protocol=SnmpAuthProtocol.SHA256, priv_protocol=SnmpPrivProtocol.AES256
        )
        SnmpClient(params).get(["1.3.6.1.2.1.1.1.0"])
        auth = fake_pysnmp.usm_user_data[0]
        assert auth.kwargs["authProtocol"] is usmHMAC192SHA256AuthProtocol
        assert auth.kwargs["privProtocol"] is usmAesCfb256Protocol


class TestSnmpErrors:
    def test_error_is_plugin_error(self) -> None:
        assert issubclass(SnmpTransportError, PluginError)

    def test_get_error_indication_raises(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.get_result = ("No SNMP response received before timeout", 0, 0, [])
        with pytest.raises(SnmpTransportError) as excinfo:
            SnmpClient(make_v2c_params()).get(["1.3.6.1.2.1.1.1.0"])
        message = str(excinfo.value)
        assert "192.0.2.20" in message
        assert "No SNMP response received before timeout" in message
        assert COMMUNITY not in message

    def test_get_error_status_raises(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.get_result = (None, FakeErrorStatus("noSuchName"), 2, [])
        with pytest.raises(SnmpTransportError, match="noSuchName"):
            SnmpClient(make_v2c_params()).get(["1.3.6.1.2.1.1.1.0"])

    def test_get_wraps_pysnmp_error_without_secrets(self, fake_pysnmp: SimpleNamespace) -> None:
        original = PySnmpError(f"engine blew up; community={COMMUNITY}")
        fake_pysnmp.get_error = original
        with pytest.raises(SnmpTransportError) as excinfo:
            SnmpClient(make_v2c_params()).get(["1.3.6.1.2.1.1.1.0"])
        assert COMMUNITY not in str(excinfo.value)
        assert "PySnmpError" in str(excinfo.value)
        assert excinfo.value.__cause__ is original
        assert fake_pysnmp.engines[0].closed is True  # cleanup despite the failure

    def test_v3_error_messages_exclude_keys(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.get_result = ("wrongDigest", 0, 0, [])
        with pytest.raises(SnmpTransportError) as excinfo:
            SnmpClient(make_v3_params()).get(["1.3.6.1.2.1.1.1.0"])
        assert AUTH_KEY not in str(excinfo.value)
        assert PRIV_KEY not in str(excinfo.value)


class TestSnmpWalk:
    def test_walk_assembles_batches_in_order(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.walk_batches = [
            (None, 0, 0, [varbind("1.3.6.1.2.1.2.2.1.2.1", "Gi0/0")]),
            (
                None,
                0,
                0,
                [
                    varbind("1.3.6.1.2.1.2.2.1.2.2", "Gi0/1"),
                    varbind("1.3.6.1.2.1.2.2.1.2.3", "Gi0/2"),
                ],
            ),
            (None, 0, 0, [varbind("1.3.6.1.2.1.2.2.1.2.4", "Lo0")]),
        ]
        result = SnmpClient(make_v2c_params()).walk("1.3.6.1.2.1.2.2.1.2")
        assert result == [
            ("1.3.6.1.2.1.2.2.1.2.1", "Gi0/0"),
            ("1.3.6.1.2.1.2.2.1.2.2", "Gi0/1"),
            ("1.3.6.1.2.1.2.2.1.2.3", "Gi0/2"),
            ("1.3.6.1.2.1.2.2.1.2.4", "Lo0"),
        ]

    def test_walk_stays_within_subtree(self, fake_pysnmp: SimpleNamespace) -> None:
        SnmpClient(make_v2c_params()).walk("1.3.6.1.2.1.2.2.1.2")
        options = fake_pysnmp.walk_calls[0].options
        assert options["lexicographicMode"] is False

    def test_walk_error_indication_mid_stream(self, fake_pysnmp: SimpleNamespace) -> None:
        fake_pysnmp.walk_batches = [
            (None, 0, 0, [varbind("1.3.6.1.2.1.2.2.1.2.1", "Gi0/0")]),
            ("Request timed out", 0, 0, []),
        ]
        with pytest.raises(SnmpTransportError, match="Request timed out"):
            SnmpClient(make_v2c_params()).walk("1.3.6.1.2.1.2.2.1.2")
        assert fake_pysnmp.engines[0].closed is True

    def test_walk_wraps_pysnmp_error_without_secrets(self, fake_pysnmp: SimpleNamespace) -> None:
        original = PySnmpError(f"walk iterator blew up; community={COMMUNITY}")
        fake_pysnmp.walk_batches = [
            (None, 0, 0, [varbind("1.3.6.1.2.1.2.2.1.2.1", "Gi0/0")]),
            original,
        ]
        with pytest.raises(SnmpTransportError) as excinfo:
            SnmpClient(make_v2c_params()).walk("1.3.6.1.2.1.2.2.1.2")
        assert COMMUNITY not in str(excinfo.value)
        assert "PySnmpError" in str(excinfo.value)
        assert excinfo.value.__cause__ is original
        assert fake_pysnmp.engines[0].closed is True  # cleanup despite the failure

    def test_walk_closes_engine_dispatcher(self, fake_pysnmp: SimpleNamespace) -> None:
        SnmpClient(make_v2c_params()).walk("1.3.6.1.2.1.2.2.1.2")
        assert fake_pysnmp.engines[0].closed is True

    def test_walk_v3_dispatch(self, fake_pysnmp: SimpleNamespace) -> None:
        SnmpClient(make_v3_params()).walk("1.3.6.1.2.1.2.2.1.2")
        assert len(fake_pysnmp.usm_user_data) == 1
        assert fake_pysnmp.walk_calls[0].auth is fake_pysnmp.usm_user_data[0]
