"""pysnmp-backed SNMP v2c/v3 client (ADR-0007: SNMP protocol family).

:class:`SnmpClient` exposes synchronous ``get``/``walk`` facades over the
pysnmp 7 asyncio HLAPI (``pysnmp.hlapi.v3arch.asyncio``) by driving each
operation through :func:`asyncio.run`. Callers are Celery worker tasks
(blocking-in-worker, ADR-0007 §3); never call from a running event loop.

Scope per D7: SNMP v2c and v3 only — v1 is unsupported. The v3 defaults
follow the ADR's authPriv recommendation: HMAC-SHA authentication and
AES-128 privacy unless the caller selects stronger protocols.

Security invariants (D11): params objects redact community strings and
v3 keys in ``repr``/``str``; error messages carry device coordinates and
pysnmp error text/class names only — never credential material.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pysnmp.error import PySnmpError
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACSHAAuthProtocol,
    walk_cmd,
)

from app.core.errors import PluginError

__all__ = [
    "SnmpAuthProtocol",
    "SnmpClient",
    "SnmpPrivProtocol",
    "SnmpTransportError",
    "SnmpV2cParams",
    "SnmpV3Params",
]

_REDACTED = "***REDACTED***"


class SnmpTransportError(PluginError):
    """An SNMP operation failed (engine error, PDU error, or transport failure).

    Messages name the device by host/port and the failure by pysnmp error
    text or exception class name — never credential material.
    """

    title = "SNMP Transport Failure"
    slug = "snmp-transport-failure"


class SnmpAuthProtocol(StrEnum):
    """SNMPv3 USM authentication protocols (HMAC-SHA family; MD5 unsupported)."""

    SHA = "sha"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class SnmpPrivProtocol(StrEnum):
    """SNMPv3 USM privacy protocols (AES family; DES/3DES unsupported)."""

    AES128 = "aes128"
    AES192 = "aes192"
    AES256 = "aes256"


_AUTH_PROTOCOLS: dict[SnmpAuthProtocol, Any] = {
    SnmpAuthProtocol.SHA: usmHMACSHAAuthProtocol,
    SnmpAuthProtocol.SHA224: usmHMAC128SHA224AuthProtocol,
    SnmpAuthProtocol.SHA256: usmHMAC192SHA256AuthProtocol,
    SnmpAuthProtocol.SHA384: usmHMAC256SHA384AuthProtocol,
    SnmpAuthProtocol.SHA512: usmHMAC384SHA512AuthProtocol,
}

_PRIV_PROTOCOLS: dict[SnmpPrivProtocol, Any] = {
    SnmpPrivProtocol.AES128: usmAesCfb128Protocol,
    SnmpPrivProtocol.AES192: usmAesCfb192Protocol,
    SnmpPrivProtocol.AES256: usmAesCfb256Protocol,
}


@dataclass(frozen=True)
class SnmpV2cParams:
    """SNMP v2c parameters (plain data, no DB coupling). ``community`` is secret."""

    host: str
    community: str
    port: int = 161
    timeout: float = 5.0
    retries: int = 1

    def __repr__(self) -> str:
        return (
            f"SnmpV2cParams(host={self.host!r}, community={_REDACTED!r}, "
            f"port={self.port!r}, timeout={self.timeout!r}, retries={self.retries!r})"
        )


@dataclass(frozen=True)
class SnmpV3Params:
    """SNMP v3 USM parameters — authPriv by default (D7 recommendation).

    Both ``auth_key`` and ``priv_key`` are required: noAuthNoPriv/authNoPriv
    are deliberately unsupported. Protocol defaults are SHA/AES-128.
    """

    host: str
    user: str
    auth_key: str
    priv_key: str
    auth_protocol: SnmpAuthProtocol = SnmpAuthProtocol.SHA
    priv_protocol: SnmpPrivProtocol = SnmpPrivProtocol.AES128
    port: int = 161
    timeout: float = 5.0
    retries: int = 1

    def __repr__(self) -> str:
        return (
            f"SnmpV3Params(host={self.host!r}, user={self.user!r}, "
            f"auth_key={_REDACTED!r}, priv_key={_REDACTED!r}, "
            f"auth_protocol={self.auth_protocol!r}, priv_protocol={self.priv_protocol!r}, "
            f"port={self.port!r}, timeout={self.timeout!r}, retries={self.retries!r})"
        )


class SnmpClient:
    """Synchronous GET/WALK facade over the pysnmp 7 asyncio HLAPI.

    One UDP exchange per call: each ``get``/``walk`` spins up a fresh
    :class:`SnmpEngine` inside its own ``asyncio.run`` loop and closes the
    engine dispatcher on the way out. Values are returned pretty-printed
    (strings); OIDs are dotted-decimal strings.
    """

    def __init__(self, params: SnmpV2cParams | SnmpV3Params) -> None:
        self._params = params

    def get(self, oids: Sequence[str]) -> dict[str, str]:
        """SNMP GET for *oids*; returns ``{dotted_oid: pretty_value}``."""
        if not oids:
            raise ValueError("SnmpClient.get() requires at least one OID")
        return asyncio.run(self._get(tuple(oids)))

    def walk(self, base_oid: str) -> list[tuple[str, str]]:
        """SNMP WALK of the *base_oid* subtree; returns ordered (oid, value) pairs."""
        return asyncio.run(self._walk(base_oid))

    async def _get(self, oids: tuple[str, ...]) -> dict[str, str]:
        engine = SnmpEngine()
        try:
            try:
                error_indication, error_status, error_index, var_binds = await get_cmd(
                    engine,
                    self._auth_data(),
                    await self._transport_target(),
                    ContextData(),
                    *(ObjectType(ObjectIdentity(oid)) for oid in oids),
                )
            except PySnmpError as exc:
                raise SnmpTransportError(self._failure_message(exc)) from exc
            self._raise_on_error(error_indication, error_status, error_index)
            result: dict[str, str] = {}
            for name, value in var_binds:
                result[str(name)] = value.prettyPrint()
            return result
        finally:
            engine.close_dispatcher()

    async def _walk(self, base_oid: str) -> list[tuple[str, str]]:
        engine = SnmpEngine()
        results: list[tuple[str, str]] = []
        try:
            try:
                iterator = walk_cmd(
                    engine,
                    self._auth_data(),
                    await self._transport_target(),
                    ContextData(),
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,  # stay within the requested subtree
                )
                async for error_indication, error_status, error_index, var_binds in iterator:
                    self._raise_on_error(error_indication, error_status, error_index)
                    for name, value in var_binds:
                        results.append((str(name), value.prettyPrint()))
            except PySnmpError as exc:
                raise SnmpTransportError(self._failure_message(exc)) from exc
        finally:
            engine.close_dispatcher()
        return results

    def _auth_data(self) -> Any:
        """v2c vs v3 dispatch: CommunityData or UsmUserData from the params type."""
        params = self._params
        if isinstance(params, SnmpV2cParams):
            return CommunityData(params.community, mpModel=1)  # mpModel=1 → v2c, never v1
        return UsmUserData(
            params.user,
            authKey=params.auth_key,
            privKey=params.priv_key,
            authProtocol=_AUTH_PROTOCOLS[params.auth_protocol],
            privProtocol=_PRIV_PROTOCOLS[params.priv_protocol],
        )

    async def _transport_target(self) -> Any:
        params = self._params
        return await UdpTransportTarget.create(
            (params.host, params.port), timeout=params.timeout, retries=params.retries
        )

    def _raise_on_error(self, error_indication: Any, error_status: Any, error_index: Any) -> None:
        """Map pysnmp's (errorIndication, errorStatus) pair to typed errors."""
        params = self._params
        if error_indication:
            raise SnmpTransportError(
                f"SNMP engine failure for {params.host}:{params.port}: {error_indication}"
            )
        if error_status:
            raise SnmpTransportError(
                f"SNMP PDU error for {params.host}:{params.port}: "
                f"{error_status.prettyPrint()} at error-index {error_index}"
            )

    def _failure_message(self, exc: Exception) -> str:
        """Credential-free failure description: coordinates + exception class name."""
        params = self._params
        return f"SNMP transport failure for {params.host}:{params.port}: {type(exc).__name__}"
