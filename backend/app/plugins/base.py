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
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol, runtime_checkable

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.core.errors import PluginError
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedDhcpLease,
    NormalizedDhcpRange,
    NormalizedDiscoveredObject,
    NormalizedDnsRecord,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedNetwork,
    NormalizedOspfNeighbor,
    NormalizedRoute,
)

__all__ = [
    "AclCapability",
    "BgpCapability",
    "Capability",
    "ChangeOutcome",
    "ChangePlan",
    "ChangeRequestDraft",
    "ChangeResult",
    "CommandTransport",
    "ConfigBackupCapability",
    "ConfigDeployCapability",
    "ConfigRestoreCapability",
    "ConfigSnapshotRef",
    "ConfigWriteTransport",
    "ConnectionParams",
    "DdiDhcpCapability",
    "DdiDnsCapability",
    "DdiIpamCapability",
    "DiscoveryApiCapability",
    "DiscoverySnmpCapability",
    "DiscoverySshCapability",
    "InterfacesCapability",
    "NeighborsCapability",
    "OspfCapability",
    "PluginCapability",
    "RawOutput",
    "RollbackResult",
    "RoutesCapability",
    "SnmpReadTransport",
    "TransportKind",
    "VendorPlugin",
    "WapiVerb",
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


@runtime_checkable
class ConfigWriteTransport(CommandTransport, Protocol):
    """A CLI session that can both read (``send_command``) and **write** config.

    The write surface for ``CONFIG_RESTORE``/``CONFIG_DEPLOY`` (ADR-0021 §4):

    - :meth:`send_config` is the netmiko ``send_config_set`` family — it enters
      ``configure terminal``, sends the lines, and exits. This is a **MERGE**
      into the running config: it adds/overrides lines but cannot *remove* a
      line that is not mentioned. It is the apply surface for an additive
      ``CONFIG_DEPLOY`` fragment.
    - :meth:`replace_config` is the vendor-native config-**replace** primitive
      (``configure replace`` on IOS): it makes the running config become exactly
      the supplied lines, including removing device-only lines absent from the
      target. This is the apply surface for ``CONFIG_RESTORE`` and the rollback
      surface for both, because only a replace can re-establish *equality* with a
      captured baseline (ADR-0021 §4: "configure replace ... otherwise replay of
      the captured pre-change baseline as the inverse"). A merge cannot satisfy
      the symmetric equal-to-baseline predicate of §3.

    ``send_command`` (inherited) is used to capture/verify the running config
    around the write. Both are satisfied by
    :class:`app.plugins.transport.ssh.SshTransport`; tests use in-memory fakes.
    Implementations return device output verbatim.
    """

    def send_config(self, lines: Sequence[str]) -> str:
        """Merge *lines* into the running config (``configure terminal``); verbatim output."""
        ...

    def replace_config(self, lines: Sequence[str]) -> str:
        """Replace the running config so it becomes exactly *lines* (configure replace).

        The vendor-native config-replace primitive (ADR-0021 §4): unlike
        :meth:`send_config`, this removes any running line not present in *lines*,
        so a post-replace re-capture can normalize **equal** to the supplied
        target — the precondition for the symmetric rollback/restore equality
        predicate (§3). Returns the device output verbatim.
        """
        ...


@runtime_checkable
class ConfigSnapshotRef(Protocol):
    """Read-only view of a stored config snapshot a restore replays (ADR-0021 §1).

    The persisted ``app.models.ConfigSnapshot`` row structurally satisfies this
    protocol (it exposes ``content`` and ``content_hash``). Declaring the
    capability against the protocol — not the ORM model — keeps the plugin layer
    free of any ``app.models`` import (plugins are stateless transport-only
    descriptors); the executor (Wave 4) passes the real snapshot row.
    """

    @property
    def content(self) -> str:
        """The verbatim configuration text captured in the snapshot."""
        ...

    @property
    def content_hash(self) -> str:
        """The content-address (SHA-256) identifying the snapshot."""
        ...


class ChangeOutcome(StrEnum):
    """Terminal classification of one config write attempt (ADR-0021 §3).

    Maps onto the ChangeRequest lifecycle the executor drives: ``applied`` /
    ``no_op`` -> ``completed``; ``rolled_back`` -> ``failed -> rolled_back``;
    ``rollback_failed`` -> CR stays ``failed`` + operator alert (never silently
    closed, never reported ``rolled_back``).
    """

    APPLIED = "applied"
    NO_OP = "no_op"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class ChangePlan(BaseModel):
    """Execution context handed to a config-write capability (ADR-0021 §1/§2).

    Carries the originating ``change_request_id``, the attested CR lifecycle
    state, and the captured pre-change baseline reference / idempotency
    metadata. The capability **never self-authorizes**: it refuses to run unless
    ``cr_state`` attests ``executing`` (the state the Automation-Agent executor
    claims from ``approved`` before constructing the plan, ADR-0020 §1). The plan
    is data the executor builds *after* the four-eyes-approved CR is claimed; the
    plugin verifies the attestation but does not — and cannot — grant it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    change_request_id: uuid.UUID = Field(
        description="The approved ChangeRequest this write executes (ADR-0020 §2)."
    )
    cr_state: str = Field(
        description="Attested CR lifecycle state; must be 'executing' or the write is refused."
    )
    baseline_content_hash: str | None = Field(
        default=None,
        description="Content-address of the CR's rollback_plan baseline reference (audit only; "
        "the authoritative baseline is captured fresh at apply time, ADR-0021 §3).",
    )

    #: The single CR state in which a config write may execute (ADR-0021 §2).
    EXECUTING_STATE: ClassVar[str] = "executing"

    @property
    def is_executing(self) -> bool:
        """Whether the plan attests an ``executing`` CR (apply-time precondition)."""
        return self.cr_state == self.EXECUTING_STATE


class RollbackResult(BaseModel):
    """Outcome of the structured per-change rollback step (ADR-0021 §3).

    A first-class return value, not a side effect: ``succeeded`` is True only
    when the post-rollback re-capture normalizes **equal to the captured
    pre-change baseline** (the asserted equality criterion, symmetric with the
    restore exit criterion). A rollback that cannot reach the device or whose
    re-capture does not normalize equal to the baseline is ``succeeded=False`` —
    surfaced by the caller as ``ChangeOutcome.ROLLBACK_FAILED``, never
    ``rolled_back``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attempted: bool = Field(description="Whether a rollback was attempted (apply/verify failed).")
    succeeded: bool = Field(description="Whether the device was restored to the baseline.")
    verified: bool = Field(
        description="Whether the post-rollback re-capture normalized equal to the baseline."
    )
    detail: str | None = Field(
        default=None, description="Human-readable rollback note (never carries config secrets)."
    )


class ChangeResult(BaseModel):
    """Structured outcome of a ``CONFIG_RESTORE``/``CONFIG_DEPLOY`` execution.

    ADR-0021 §1: both capabilities return this — the applied diff summary, the
    verify-after outcome, and the structured rollback outcome when one ran. The
    executor maps ``outcome`` onto the CR lifecycle (ADR-0020). ``applied_diff``
    is a redaction-safe summary (line counts / changed-line markers), not raw
    config text, so a ``ChangeResult`` never carries config secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    change_request_id: uuid.UUID
    outcome: ChangeOutcome
    verified: bool = Field(
        description="Whether verify-after confirmed the intended end-state on the device."
    )
    applied_diff: tuple[str, ...] = Field(
        default=(),
        description="Redaction-safe summary of what the apply changed (empty for a no-op).",
    )
    rollback: RollbackResult | None = Field(
        default=None, description="Structured rollback outcome when apply/verify failed; else None."
    )


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


class OspfCapability(PluginCapability):
    """``Capability.OSPF`` — OSPF neighbor/adjacency state."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.OSPF})

    @abstractmethod
    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Return OSPF neighbor adjacencies as normalized records."""


class AclCapability(PluginCapability):
    """``Capability.ACL`` — access-control list entries."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.ACL})

    @abstractmethod
    def get_acls(self) -> list[NormalizedAclEntry]:
        """Return ACL entries as normalized records."""


class ConfigBackupCapability(PluginCapability):
    """``Capability.CONFIG_BACKUP`` — running-configuration retrieval."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CONFIG_BACKUP})

    @abstractmethod
    def fetch_running_config(self) -> str:
        """Return the device running configuration verbatim."""


class ConfigRestoreCapability(PluginCapability):
    """``Capability.CONFIG_RESTORE`` — replay a stored snapshot onto a device.

    The first device-write path (ADR-0021). Restores the device's running
    configuration to an existing M4 ``config_snapshot`` as the execution step of
    an ``executing`` ChangeRequest: capture a fresh pre-change baseline, compute
    the diff (empty => idempotent no-op), apply, verify-after (the re-captured
    config normalizes equal to the snapshot), and on failure replay the captured
    baseline and verify the rollback. The method **never self-authorizes** — it
    refuses unless the :class:`ChangePlan` attests an ``executing`` CR (§2).
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CONFIG_RESTORE})

    @abstractmethod
    def restore(self, snapshot: ConfigSnapshotRef, *, plan: ChangePlan) -> ChangeResult:
        """Restore the device to *snapshot* under the approved-CR *plan* (ADR-0021)."""


class ConfigDeployCapability(PluginCapability):
    """``Capability.CONFIG_DEPLOY`` — merge a supplied config fragment onto a device.

    The first device-write path (ADR-0021). Applies a config fragment as the
    execution step of an ``executing`` ChangeRequest with the same
    capture-before -> apply -> verify-after -> rollback-on-failure contract as
    restore: the deploy verify-after predicate (every fragment line present, no
    unintended residual diff) and the rollback-success criterion are symmetric
    with restore. The method **never self-authorizes** — it refuses unless the
    :class:`ChangePlan` attests an ``executing`` CR (§2).
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CONFIG_DEPLOY})

    @abstractmethod
    def deploy(self, config_fragment: str, *, plan: ChangePlan) -> ChangeResult:
        """Apply *config_fragment* under the approved-CR *plan* (ADR-0021)."""


# ---------------------------------------------------------------------------
# DDI + API-discovery capability interfaces (ADR-0022)
# ---------------------------------------------------------------------------


class WapiVerb(StrEnum):
    """The mutation verb a :class:`ChangeRequestDraft` would apply to a DDI object.

    Maps onto the REST methods an Infoblox-style WAPI exposes (ADR-0022 §3):
    ``create`` (POST a new object), ``update`` (PUT onto an existing ``_ref``),
    ``delete`` (DELETE an existing ``_ref``).
    """

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class ChangeRequestDraft(BaseModel):
    """A proposed DDI mutation — data only, never an executed write (ADR-0022 §3).

    A DDI capability's mutation method returns one of these instead of calling
    the appliance: it carries the target object handle (``object_ref`` — ``None``
    for a create), the exact WAPI verb + object type + body to apply, and an
    ``inverse`` draft that undoes the change (delete-the-added-record, or restore
    the prior object state). The DDI Agent hands the draft to the ChangeRequest
    service (ADR-0020); only the Automation Agent — for an ``approved`` CR — turns
    a draft into an actual write. Making mutations drafts means the capability
    layer *cannot* write, so there is no DDI write path that skips the CR spine
    (ADR-0022 §3 / alternative 2).

    The model is frozen and forbids extra fields. ``body`` carries DDI record
    fields (names, IPs, TTLs) — never credentials; the WAPI auth secret lives
    only inside the transport, never in a draft.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verb: WapiVerb = Field(description="The WAPI mutation to apply (create/update/delete).")
    wapi_object: str = Field(
        min_length=1,
        description="WAPI object type the verb targets (e.g. 'record:a', 'network').",
    )
    object_ref: str | None = Field(
        default=None,
        description="Opaque WAPI _ref of the existing target object; None for a create. "
        "Never a secret.",
    )
    body: tuple[tuple[str, str], ...] = Field(
        default=(),
        description="Object fields to send, as a flat secret-free (key, value) sequence.",
    )
    inverse: ChangeRequestDraft | None = Field(
        default=None,
        description="The draft that reverses this change (structured rollback spec, ADR-0022 §3).",
    )
    summary: str = Field(
        min_length=1,
        description="Human-readable, secret-free description of the intended change.",
    )


class DiscoveryApiCapability(PluginCapability):
    """``Capability.DISCOVERY_API`` — read-only API-based discovery (ADR-0022 §2).

    The first API-based discovery path: implementations query an appliance/cloud
    REST API (Infoblox WAPI) and return :class:`NormalizedDiscoveredObject`
    records (networks, DNS zones, members) for the discovery engine. Read-only —
    it never mutates the source.
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DISCOVERY_API})

    @abstractmethod
    def discover(self) -> list[NormalizedDiscoveredObject]:
        """Return the objects observed over the management API as normalized records."""


class DdiDnsCapability(PluginCapability):
    """``Capability.DDI_DNS`` — DNS read + draft-only mutations (ADR-0022 §2/§3).

    Reads return normalized records; mutations return a
    :class:`ChangeRequestDraft` and **never** write to the appliance (the write
    is the Automation Agent's job, only for an ``approved`` CR).
    """

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DDI_DNS})

    @abstractmethod
    def get_zones(self) -> list[str]:
        """Return the authoritative DNS zones (FQDNs) as normalized identifiers (ADR-0022 §2)."""

    @abstractmethod
    def get_records(self, zone: str | None = None) -> list[NormalizedDnsRecord]:
        """Return DNS resource records, optionally scoped to *zone*, as normalized records."""

    @abstractmethod
    def add_record(self, record: NormalizedDnsRecord) -> ChangeRequestDraft:
        """Draft the addition of *record* (no write performed)."""

    @abstractmethod
    def modify_record(
        self,
        object_ref: str,
        changes: NormalizedDnsRecord,
        current: NormalizedDnsRecord | None = None,
    ) -> ChangeRequestDraft:
        """Draft a modification of the object at *object_ref* (no write performed).

        *current* is the pre-image (prior record state); when supplied the draft's
        ``inverse`` carries the prior field values so an approved rollback restores
        them (ADR-0022 §3). When omitted, no blind empty-body restore is emitted.
        """

    @abstractmethod
    def delete_record(
        self, object_ref: str, current: NormalizedDnsRecord | None = None
    ) -> ChangeRequestDraft:
        """Draft the deletion of the object at *object_ref* (no write performed).

        *current* is the pre-image; when supplied the draft's ``inverse`` re-creates
        the deleted record from its full state (ADR-0022 §3). Without it the delete
        is non-reversible and no misleading re-create draft is emitted.
        """


class DdiDhcpCapability(PluginCapability):
    """``Capability.DDI_DHCP`` — DHCP read + draft-only mutations (ADR-0022 §2/§3)."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DDI_DHCP})

    @abstractmethod
    def get_ranges(self) -> list[NormalizedDhcpRange]:
        """Return the configured DHCP ranges as normalized records."""

    @abstractmethod
    def get_leases(self) -> list[NormalizedDhcpLease]:
        """Return the current DHCP leases as normalized records."""

    @abstractmethod
    def add_range(self, dhcp_range: NormalizedDhcpRange) -> ChangeRequestDraft:
        """Draft the addition of *dhcp_range* (no write performed)."""

    @abstractmethod
    def delete_range(
        self, object_ref: str, current: NormalizedDhcpRange | None = None
    ) -> ChangeRequestDraft:
        """Draft the deletion of the range at *object_ref* (no write performed).

        *current* is the pre-image; when supplied the draft's ``inverse`` re-creates
        the deleted range from its full state (ADR-0022 §3). Without it the delete
        is non-reversible and no misleading re-create draft is emitted.
        """


class DdiIpamCapability(PluginCapability):
    """``Capability.DDI_IPAM`` — IPAM read + draft-only mutations (ADR-0022 §2/§3)."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DDI_IPAM})

    @abstractmethod
    def get_networks(self) -> list[NormalizedNetwork]:
        """Return the IPAM networks/subnets as normalized records."""

    @abstractmethod
    def get_next_available_ip(self, network: str) -> str:
        """Return the next free IP address within *network* (ADR-0022 §2 read interface).

        Read-only: resolves the network's WAPI handle and calls the appliance's
        ``next_available_ip`` function. Never mutates the source.
        """

    @abstractmethod
    def add_network(self, network: NormalizedNetwork) -> ChangeRequestDraft:
        """Draft the allocation of *network* (no write performed)."""

    @abstractmethod
    def delete_network(
        self, object_ref: str, current: NormalizedNetwork | None = None
    ) -> ChangeRequestDraft:
        """Draft the deletion of the network at *object_ref* (no write performed).

        *current* is the pre-image; when supplied the draft's ``inverse`` re-creates
        the deleted network from its full state (ADR-0022 §3). Without it the delete
        is non-reversible and no misleading re-create draft is emitted.
        """


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
