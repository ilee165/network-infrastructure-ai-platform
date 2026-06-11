"""Vendor plugin contract: capabilities, typed interfaces, transports (D6/D7).

Defined here, exactly per brief §4 / ADR-0006:

- :class:`Capability` — the 19-member capability enum.
- :class:`VendorPlugin` — the per-vendor plugin ABC (``vendor_id``,
  ``display_name``, ``capabilities``, ``get_capability()``).
- Typed capability interfaces (one ABC per capability group) returning
  normalized Pydantic models from :mod:`app.schemas.normalized` — never raw
  strings or ad-hoc dicts.
- :class:`ConnectionParams` — connection coordinates carrying a vault
  *reference*, never raw secrets (D11).
- :class:`RawOutput` — verbatim command output preserved before any parsing
  (auditability, brief §4).
- :class:`CommandTransport` — the protocol capability implementations execute
  CLI commands through; the netmiko-backed transport lands in M1
  (``plugins/transport/ssh.py``, ADR-0007).

Capability interfaces not yet listed here (OSPF, ACL, FIREWALL_POLICY,
CONFIG_RESTORE/DEPLOY, DDI_*, PACKET_CAPTURE, HA_STATUS, DISCOVERY_API) are
added with the milestone that ships their first implementation (M1–M5);
adding one requires no change to existing plugins.

Concurrency note: capability methods are synchronous by design — blocking
transports (netmiko, pysnmp) run inside Celery worker tasks, never on the
FastAPI event loop (ADR-0007 §3, ADR-0008).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol, runtime_checkable

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.core.errors import PluginError
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NormalizedBgpPeer,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedRoute,
)

__all__ = [
    "BgpCapability",
    "Capability",
    "CommandTransport",
    "ConfigBackupCapability",
    "ConnectionParams",
    "DiscoverySnmpCapability",
    "DiscoverySshCapability",
    "InterfacesCapability",
    "NeighborsCapability",
    "PluginCapability",
    "RawOutput",
    "RoutesCapability",
    "SnmpReadTransport",
    "TransportKind",
    "VendorPlugin",
]

_VENDOR_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class Capability(StrEnum):
    """The 19 platform capabilities a vendor plugin may implement (brief §4).

    Partial coverage is the norm, not an error: a DDI appliance will never
    implement ``NEIGHBORS_CDP``, and a cloud account has no running-config.
    """

    DISCOVERY_SSH = "discovery_ssh"
    DISCOVERY_SNMP = "discovery_snmp"
    DISCOVERY_API = "discovery_api"
    INTERFACES = "interfaces"
    ROUTES = "routes"
    NEIGHBORS_LLDP = "neighbors_lldp"
    NEIGHBORS_CDP = "neighbors_cdp"
    BGP = "bgp"
    OSPF = "ospf"
    ACL = "acl"
    FIREWALL_POLICY = "firewall_policy"
    CONFIG_BACKUP = "config_backup"
    CONFIG_RESTORE = "config_restore"
    CONFIG_DEPLOY = "config_deploy"
    DDI_DNS = "ddi_dns"
    DDI_DHCP = "ddi_dhcp"
    DDI_IPAM = "ddi_ipam"
    PACKET_CAPTURE = "packet_capture"
    HA_STATUS = "ha_status"


class TransportKind(StrEnum):
    """Protocol family used to reach a device (ADR-0007)."""

    SSH = "ssh"
    SNMP = "snmp"
    HTTP = "http"
    HTTPS = "https"
    API = "api"  # cloud / virtualization SDKs (boto3, azure SDK, pyVmomi)


class ConnectionParams(BaseModel):
    """How to reach a device. Carries a credential *reference* — never secrets.

    ``credential_ref`` points into the encrypted vault
    (``device_credentials``, D11); the credentials service materializes the
    secret in-process only when a transport session is opened (M1).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(min_length=1, description="Hostname or IP address of the device.")
    port: int = Field(default=22, ge=1, le=65535)
    transport: TransportKind = TransportKind.SSH
    credential_ref: str = Field(
        min_length=1,
        description="Opaque reference to a vault entry (device_credentials.id) — never a secret.",
    )


def _utcnow() -> datetime:
    """Timezone-aware now (kept as a named function for monkeypatching)."""
    return datetime.now(UTC)


class RawOutput(BaseModel):
    """Verbatim output of one device command, preserved before parsing.

    Brief §4 / D11: all raw output is stored verbatim (``raw_artifacts``,
    M1 discovery runner) so every normalized row is re-derivable and parser
    bugs are recoverable. ``output`` must never be trimmed or rewritten.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    command: str = Field(min_length=1)
    output: str
    collected_at: AwareDatetime = Field(default_factory=_utcnow)


@runtime_checkable
class CommandTransport(Protocol):
    """A connected CLI session that can execute commands and return text.

    M1 ships the netmiko-backed implementation (``plugins/transport/ssh.py``,
    ADR-0007); tests use in-memory fakes. Implementations must return the
    device output verbatim — no normalization at the transport layer.
    """

    def send_command(self, command: str) -> str:
        """Execute *command* on the device and return its raw text output."""
        ...


@runtime_checkable
class SnmpReadTransport(Protocol):
    """A read-only SNMP session: GET over a set of OIDs.

    Satisfied by :class:`app.plugins.transport.snmp.SnmpClient` (M1-08);
    tests use in-memory fakes. Values are pretty-printed strings keyed by
    dotted-decimal OID — no normalization at the transport layer.
    """

    def get(self, oids: Sequence[str]) -> dict[str, str]:
        """SNMP GET for *oids*; returns ``{dotted_oid: pretty_value}``."""
        ...


class PluginCapability(ABC):
    """Base class for all capability implementations.

    Subclasses declare ``capabilities`` — the :class:`Capability` members the
    interface serves (usually one; ``NeighborsCapability`` serves both LLDP
    and CDP). Implementations record every executed command through
    :meth:`_record_raw` so the discovery runner (M1) can persist verbatim
    output to ``raw_artifacts`` *before* normalization.
    """

    capabilities: ClassVar[frozenset[Capability]]

    def __init__(self) -> None:
        self._raw_outputs: list[RawOutput] = []

    @property
    def raw_outputs(self) -> tuple[RawOutput, ...]:
        """Verbatim outputs of every command executed by this instance."""
        return tuple(self._raw_outputs)

    def _record_raw(self, command: str, output: str) -> str:
        """Record *output* verbatim for audit persistence; returns it unchanged."""
        self._raw_outputs.append(RawOutput(command=command, output=output))
        return output


class DiscoverySshCapability(PluginCapability):
    """``Capability.DISCOVERY_SSH`` — device identity facts over CLI (M1).

    Implementations collect the vendor's version/identity command through a
    :class:`CommandTransport` and return :class:`DeviceFacts`.
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DISCOVERY_SSH})

    @abstractmethod
    def get_device_facts(self) -> DeviceFacts:
        """Return the device identity facts observed over SSH/CLI."""


class DiscoverySnmpCapability(PluginCapability):
    """``Capability.DISCOVERY_SNMP`` — device identity facts via SNMP (M1).

    Implementations query the system MIB (sysName/sysDescr/sysObjectID)
    through an :class:`SnmpReadTransport` and map the values to
    :class:`DeviceFacts` — best-effort: only ``hostname``/``vendor_id`` are
    guaranteed.
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DISCOVERY_SNMP})

    @abstractmethod
    def get_device_facts(self) -> DeviceFacts:
        """Return the device identity facts observed over SNMP."""


class InterfacesCapability(PluginCapability):
    """``Capability.INTERFACES`` — interface inventory."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.INTERFACES})

    @abstractmethod
    def get_interfaces(self) -> list[NormalizedInterface]:
        """Return all interfaces of the device as normalized records."""


class RoutesCapability(PluginCapability):
    """``Capability.ROUTES`` — routing-table collection."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.ROUTES})

    @abstractmethod
    def get_routes(self) -> list[NormalizedRoute]:
        """Return the device routing table as normalized records."""


class NeighborsCapability(PluginCapability):
    """``Capability.NEIGHBORS_LLDP`` + ``Capability.NEIGHBORS_CDP``.

    One interface serves both discovery protocols; the plugin's declared
    ``VendorPlugin.capabilities`` set remains the source of truth for which
    of the two a vendor actually supports.
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.NEIGHBORS_LLDP, Capability.NEIGHBORS_CDP}
    )

    @abstractmethod
    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Return LLDP adjacencies as normalized records."""

    @abstractmethod
    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """Return CDP adjacencies as normalized records."""


class BgpCapability(PluginCapability):
    """``Capability.BGP`` — BGP peer/session state."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.BGP})

    @abstractmethod
    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Return BGP peering sessions as normalized records."""


class ConfigBackupCapability(PluginCapability):
    """``Capability.CONFIG_BACKUP`` — running-configuration retrieval."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CONFIG_BACKUP})

    @abstractmethod
    def fetch_running_config(self) -> str:
        """Return the device running configuration verbatim."""


class VendorPlugin(ABC):
    """A vendor plugin: identity plus its capability implementations (D6).

    Concrete subclasses set the three class attributes and map each declared
    capability to its implementation class via :meth:`_capability_classes`.
    Plugins are stateless descriptors — capability implementations are
    instantiated per device session by their consumer (the M1 discovery
    runner) with whatever transport the vendor requires.
    """

    vendor_id: ClassVar[str]
    display_name: ClassVar[str]
    capabilities: ClassVar[frozenset[Capability]]

    def __init__(self) -> None:
        for attr in ("vendor_id", "display_name", "capabilities"):
            if not hasattr(type(self), attr):
                raise PluginError(f"plugin class {type(self).__name__!r} does not define {attr!r}")
        if not _VENDOR_ID_RE.match(self.vendor_id):
            raise PluginError(
                f"plugin class {type(self).__name__!r} has invalid vendor_id "
                f"{self.vendor_id!r} (must be snake_case, REPO-STRUCTURE §4.1)"
            )

    @abstractmethod
    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        """Map every declared capability to its implementation class."""

    def supports(self, capability: Capability) -> bool:
        """Whether this plugin declares *capability*."""
        return capability in self.capabilities

    def get_capability(self, capability: Capability) -> type[PluginCapability]:
        """Return the implementation class for *capability*.

        Raises :class:`PluginError` when the capability is not declared (the
        typed fail-fast of ADR-0006: "FortiOS plugin does not implement OSPF
        analysis") or declared without an implementation (a plugin bug).
        """
        if capability not in self.capabilities:
            raise PluginError(
                f"vendor {self.vendor_id!r} does not implement capability {capability.value!r}"
            )
        impl = self._capability_classes().get(capability)
        if impl is None:
            raise PluginError(
                f"vendor {self.vendor_id!r} declares capability {capability.value!r} "
                "but provides no implementation class"
            )
        return impl
