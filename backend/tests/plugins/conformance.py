"""Reusable vendor-plugin conformance suite (M1-07, ADR-0006).

Every vendor plugin test package applies the same checks by parametrizing
over :func:`make_conformance_cases`::

    from tests.plugins.conformance import (
        ConformanceCase,
        FixtureReplayTransport,
        make_conformance_cases,
    )

    def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
        return impl(FixtureReplayTransport(_BUNDLED_FIXTURES), uuid4())

    CASES = make_conformance_cases(AcmePlugin(), capability_factory=_make_capability)

    @pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
    def test_acme_conformance(case: ConformanceCase) -> None:
        case.run()

Three case families are generated:

- ``metadata:*`` — plugin identity is well-formed: snake_case ``vendor_id``,
  non-blank ``display_name``, a non-empty ``capabilities`` frozenset of
  :class:`~app.plugins.base.Capability` members.
- ``implementation:<capability>`` — every declared capability resolves via
  ``get_capability()`` to a concrete class that declares the capability,
  subclasses the typed interface from :mod:`app.plugins.base`, and overrides
  each abstract method itself (never inherited-abstract).
- ``fixtures:<capability>`` — the capability, instantiated by the plugin's
  ``capability_factory`` over its bundled recorded fixtures, returns
  non-empty results that re-validate against the normalized Pydantic models
  and carry the plugin's ``vendor_id`` as ``source_vendor``.

Capabilities whose typed interface has not landed in ``plugins/base.py`` yet
(e.g. ``DISCOVERY_API`` before its milestone) get the implementation case
only — the interface/fixture contract attaches automatically once the
interface exists and is mapped in ``_INTERFACE_SPECS``.

Failure messages always name the vendor, the capability, the method, or the
model field at fault, so a failing plugin is fixable without reading this
module.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial

from pydantic import ValidationError

from app.core.errors import PluginError
from app.plugins.base import (
    AclCapability,
    AdcServicesCapability,
    BgpCapability,
    Capability,
    ChangeOutcome,
    ChangeResult,
    ConfigArchive,
    ConfigArchiveBackupCapability,
    ConfigArchiveRestoreCapability,
    ConfigBackupCapability,
    ConfigDeployCapability,
    ConfigRestoreCapability,
    DdiDhcpCapability,
    DdiDnsCapability,
    DdiIpamCapability,
    DiscoveryApiCapability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    FirewallPolicyCapability,
    HaStatusCapability,
    InterfacesCapability,
    NeighborsCapability,
    OspfCapability,
    PluginCapability,
    RoutesCapability,
    VendorPlugin,
    VirtualizationInventoryCapability,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NeighborProtocol,
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedComputeCluster,
    NormalizedDhcpLease,
    NormalizedDiscoveredObject,
    NormalizedDnsRecord,
    NormalizedFirewallRule,
    NormalizedHaStatus,
    NormalizedHypervisorHost,
    NormalizedInterface,
    NormalizedNatRule,
    NormalizedNeighbor,
    NormalizedNetwork,
    NormalizedOspfNeighbor,
    NormalizedPool,
    NormalizedPortGroup,
    NormalizedRecord,
    NormalizedRoute,
    NormalizedVirtualMachine,
    NormalizedVirtualServer,
)

__all__ = [
    "CapabilityFactory",
    "ChangeWriteInvoker",
    "ConformanceCase",
    "FixtureReplayTransport",
    "FixtureSnmpTransport",
    "assert_fixture_case_completeness",
    "make_conformance_cases",
]

CapabilityFactory = Callable[[type[PluginCapability]], PluginCapability]
"""Builds a ready-to-call capability instance wired to bundled fixtures."""

_VENDOR_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")


#: Invokes a change-write capability (CONFIG_RESTORE/DEPLOY) wired to fixtures
#: and returns its :class:`~app.plugins.base.ChangeResult`. The plugin's test
#: module supplies it via the capability factory because the call needs a
#: vendor-specific snapshot/fragment + an ``executing`` :class:`ChangePlan`.
ChangeWriteInvoker = Callable[[PluginCapability], ChangeResult]


@dataclass(frozen=True)
class _InterfaceSpec:
    """Conformance contract of one capability: typed interface + data shape.

    ``item_model`` is the normalized record type the data method must return
    a non-empty list of; ``None`` means the method returns a non-empty ``str``
    (``CONFIG_BACKUP``) — unless ``facts_model`` is set, in which case the
    method returns a single :class:`DeviceFacts` whose ``vendor_id`` must
    match the plugin (``DISCOVERY_SSH``/``DISCOVERY_SNMP``).
    ``neighbor_protocol`` pins the ``protocol`` field for the two neighbor
    capabilities served by the shared interface.
    ``change_write`` marks a device-write capability (CONFIG_RESTORE/DEPLOY,
    ADR-0021): its data method takes arguments and returns a
    :class:`~app.plugins.base.ChangeResult`, so the fixture case validates the
    structured result rather than a normalized-record list. The vendor-specific
    invocation is supplied per-plugin (see :func:`make_conformance_cases`).
    ``extra_records`` lists additional ``(method, model)`` pairs for a capability
    whose interface returns more than one normalized-record list (FIREWALL_POLICY:
    ``get_firewall_rules`` + ``get_nat_rules``, ADR-0034). Each extra method is
    invoked over the bundled fixtures and every returned record is re-validated
    against its model and checked for the plugin's ``source_vendor``; an empty
    list is permitted for an extra method (a firewall may legitimately have no NAT
    rules), while the primary ``method`` must be non-empty.
    """

    interface: type[PluginCapability]
    method: str
    item_model: type[NormalizedRecord] | None
    neighbor_protocol: NeighborProtocol | None = None
    facts_model: type[DeviceFacts] | None = None
    change_write: bool = False
    extra_records: tuple[tuple[str, type[NormalizedRecord]], ...] = ()
    #: Marks a binary-archive backup capability (CONFIG_BACKUP_ARCHIVE, ADR-0050
    #: §7.1): its data method returns a :class:`ConfigArchive` (secret-bearing
    #: :class:`~pydantic.SecretBytes` content), not a normalized-record list, so
    #: the fixture case asserts the archive metadata shape + that the content is
    #: masked in ``repr``/serialization rather than a record list.
    archive_backup: bool = False


#: Capability -> typed-interface contract from app.plugins.base. Extend this
#: mapping when a new capability interface lands (OSPF, ACL, …); existing
#: plugin conformance tests pick the new contract up automatically.
_INTERFACE_SPECS: dict[Capability, _InterfaceSpec] = {
    Capability.DISCOVERY_SSH: _InterfaceSpec(
        DiscoverySshCapability, "get_device_facts", None, facts_model=DeviceFacts
    ),
    Capability.DISCOVERY_SNMP: _InterfaceSpec(
        DiscoverySnmpCapability, "get_device_facts", None, facts_model=DeviceFacts
    ),
    Capability.INTERFACES: _InterfaceSpec(
        InterfacesCapability, "get_interfaces", NormalizedInterface
    ),
    Capability.ROUTES: _InterfaceSpec(RoutesCapability, "get_routes", NormalizedRoute),
    Capability.NEIGHBORS_LLDP: _InterfaceSpec(
        NeighborsCapability, "get_lldp_neighbors", NormalizedNeighbor, NeighborProtocol.LLDP
    ),
    Capability.NEIGHBORS_CDP: _InterfaceSpec(
        NeighborsCapability, "get_cdp_neighbors", NormalizedNeighbor, NeighborProtocol.CDP
    ),
    Capability.BGP: _InterfaceSpec(BgpCapability, "get_bgp_peers", NormalizedBgpPeer),
    Capability.OSPF: _InterfaceSpec(OspfCapability, "get_ospf_neighbors", NormalizedOspfNeighbor),
    Capability.ACL: _InterfaceSpec(AclCapability, "get_acls", NormalizedAclEntry),
    # Firewall policy (ADR-0034). Two normalized-record methods: firewall rules
    # (primary, must be non-empty) + NAT rules (extra, may be empty). First
    # implemented by panos/fortios (P2 W2), which the two-vendor rule validates
    # against this family before FIREWALL_POLICY is declared stable.
    Capability.FIREWALL_POLICY: _InterfaceSpec(
        FirewallPolicyCapability,
        "get_firewall_rules",
        NormalizedFirewallRule,
        extra_records=(("get_nat_rules", NormalizedNatRule),),
    ),
    Capability.CONFIG_BACKUP: _InterfaceSpec(ConfigBackupCapability, "fetch_running_config", None),
    Capability.CONFIG_RESTORE: _InterfaceSpec(
        ConfigRestoreCapability, "restore", None, change_write=True
    ),
    Capability.CONFIG_DEPLOY: _InterfaceSpec(
        ConfigDeployCapability, "deploy", None, change_write=True
    ),
    # DDI + API discovery (ADR-0022). The fixture case exercises each capability's
    # no-arg read method over recorded WAPI fixtures; mutation methods are
    # shape-tested in the plugin's own unit tests (a draft, no I/O).
    Capability.DISCOVERY_API: _InterfaceSpec(
        DiscoveryApiCapability, "discover", NormalizedDiscoveredObject
    ),
    Capability.DDI_DNS: _InterfaceSpec(DdiDnsCapability, "get_records", NormalizedDnsRecord),
    Capability.DDI_DHCP: _InterfaceSpec(DdiDhcpCapability, "get_leases", NormalizedDhcpLease),
    Capability.DDI_IPAM: _InterfaceSpec(DdiIpamCapability, "get_networks", NormalizedNetwork),
    # HA status (ADR-0025 §8). First implemented by cisco_nxos (vPC); reused by
    # PAN-OS/FortiOS/F5 in later waves.
    Capability.HA_STATUS: _InterfaceSpec(HaStatusCapability, "get_ha_status", NormalizedHaStatus),
    # ADC services (ADR-0050 §4). Two normalized-record methods: virtual servers
    # (primary, must be non-empty) + pools (extra, may be empty). First and only
    # implemented by f5_bigip; validated by the fixtures + the W2 derivation as
    # the second consumer (ADR-0050 §4.6).
    Capability.ADC_SERVICES: _InterfaceSpec(
        AdcServicesCapability,
        "get_virtual_servers",
        NormalizedVirtualServer,
        extra_records=(("get_pools", NormalizedPool),),
    ),
    # Binary config archive (UCS) backup + restore (ADR-0050 §7). Backup returns a
    # secret-bearing ConfigArchive; restore is CR-gated and returns a ChangeResult
    # (the change_write shape) invoked with a ConfigArchiveRef + executing plan.
    Capability.CONFIG_BACKUP_ARCHIVE: _InterfaceSpec(
        ConfigArchiveBackupCapability, "fetch_config_archive", None, archive_backup=True
    ),
    Capability.CONFIG_RESTORE_ARCHIVE: _InterfaceSpec(
        ConfigArchiveRestoreCapability, "restore_archive", None, change_write=True
    ),
    # Virtualization inventory (ADR-0051 §5.8). Four normalized-record methods:
    # virtual machines (primary, must be non-empty) + hosts/clusters/port groups
    # (extras, may be empty). First and only implemented by vmware; validated by
    # the recorded property-set fixtures + the W2 derivation as the second
    # consumer (ADR-0051 §5.7). Without this entry the fixtures case is silently
    # skipped (the three-file lesson, ADR-0025 §8).
    Capability.VIRTUALIZATION_INVENTORY: _InterfaceSpec(
        VirtualizationInventoryCapability,
        "get_virtual_machines",
        NormalizedVirtualMachine,
        extra_records=(
            ("get_hypervisor_hosts", NormalizedHypervisorHost),
            ("get_compute_clusters", NormalizedComputeCluster),
            ("get_port_groups", NormalizedPortGroup),
        ),
    ),
}


class FixtureReplayTransport:
    """:class:`CommandTransport` replaying bundled fixture text.

    No device, no network (D16): commands outside the bundled fixture map
    fail immediately, listing what the plugin's fixtures actually cover.
    """

    def __init__(self, responses: Mapping[str, str]) -> None:
        self._responses = dict(responses)
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if command not in self._responses:
            known = ", ".join(repr(known) for known in sorted(self._responses)) or "none"
            raise AssertionError(
                f"conformance: plugin sent unexpected command {command!r} "
                f"(bundled fixtures cover: {known})"
            )
        return self._responses[command]


class FixtureSnmpTransport:
    """:class:`SnmpReadTransport` replaying recorded SNMP values.

    No device, no network (D16): OIDs outside the bundled value map fail
    immediately, listing what the plugin's fixtures actually cover.
    """

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self.requests: list[list[str]] = []

    def get(self, oids: Sequence[str]) -> dict[str, str]:
        self.requests.append(list(oids))
        missing = [oid for oid in oids if oid not in self._values]
        if missing:
            known = ", ".join(repr(known) for known in sorted(self._values)) or "none"
            raise AssertionError(
                f"conformance: plugin requested unexpected OID(s) {missing!r} "
                f"(bundled fixtures cover: {known})"
            )
        return {oid: self._values[oid] for oid in oids}


@dataclass(frozen=True)
class ConformanceCase:
    """One named conformance check; :meth:`run` raises ``AssertionError`` on failure."""

    id: str
    check: Callable[[], None]

    def run(self) -> None:
        self.check()


def make_conformance_cases(
    plugin: VendorPlugin,
    *,
    capability_factory: CapabilityFactory,
    change_write_invokers: Mapping[Capability, ChangeWriteInvoker] | None = None,
) -> list[ConformanceCase]:
    """Build the full conformance case list for *plugin*.

    *capability_factory* receives each resolved implementation class and must
    return an instance wired to the plugin's bundled fixtures (typically via
    :class:`FixtureReplayTransport`); it is only invoked for capabilities
    with a typed interface in ``_INTERFACE_SPECS``.

    *change_write_invokers* supplies, per device-write capability
    (CONFIG_RESTORE/DEPLOY, ADR-0021), the vendor-specific call that invokes the
    factory-built capability with a fixture snapshot/fragment and an
    ``executing`` :class:`ChangePlan`, returning its
    :class:`~app.plugins.base.ChangeResult`. Required for any declared
    change-write capability; the fixture case asserts the structured result.
    """
    invokers = dict(change_write_invokers or {})
    cases = [
        ConformanceCase("metadata:vendor_id", partial(_check_vendor_id, plugin)),
        ConformanceCase("metadata:display_name", partial(_check_display_name, plugin)),
        ConformanceCase("metadata:capabilities", partial(_check_capability_set, plugin)),
    ]
    for capability in sorted(plugin.capabilities):
        cases.append(
            ConformanceCase(
                f"implementation:{capability.value}",
                partial(_check_capability_implementation, plugin, capability),
            )
        )
    for capability in sorted(plugin.capabilities):
        spec = _INTERFACE_SPECS.get(capability)
        if spec is None:
            continue
        if spec.change_write:
            cases.append(
                ConformanceCase(
                    f"fixtures:{capability.value}",
                    partial(
                        _check_change_write_outputs, plugin, capability, invokers.get(capability)
                    ),
                )
            )
        elif spec.archive_backup:
            cases.append(
                ConformanceCase(
                    f"fixtures:{capability.value}",
                    partial(_check_archive_backup_outputs, plugin, capability, capability_factory),
                )
            )
        else:
            cases.append(
                ConformanceCase(
                    f"fixtures:{capability.value}",
                    partial(_check_fixture_outputs, plugin, capability, capability_factory),
                )
            )
    return cases


def assert_fixture_case_completeness(
    plugin: VendorPlugin,
    cases: Sequence[ConformanceCase],
) -> None:
    """Assert every capability declared by *plugin* has a fixture case.

    This check is deliberately opt-in.  Generic case generation continues to
    permit capabilities whose typed fixture interface has not landed yet, while
    release-certified plugins can require complete fixture-family coverage and
    catch a missing ``_INTERFACE_SPECS`` entry instead of silently skipping it.
    """
    case_ids = {case.id for case in cases}
    missing = sorted(
        capability.value
        for capability in plugin.capabilities
        if f"fixtures:{capability.value}" not in case_ids
    )
    assert not missing, (
        f"{plugin.vendor_id}: declared capabilities missing fixtures:* "
        f"conformance families: {missing}"
    )


# ---------------------------------------------------------------------------
# metadata:* checks
# ---------------------------------------------------------------------------


def _check_vendor_id(plugin: VendorPlugin) -> None:
    vendor_id = getattr(type(plugin), "vendor_id", None)
    assert isinstance(vendor_id, str), (
        f"{type(plugin).__name__}: vendor_id must be a str ClassVar, got {type(vendor_id).__name__}"
    )
    assert _VENDOR_ID_RE.match(vendor_id), (
        f"{type(plugin).__name__}: vendor_id {vendor_id!r} is not snake_case "
        "(REPO-STRUCTURE §4.1: ^[a-z][a-z0-9_]*$)"
    )


def _check_display_name(plugin: VendorPlugin) -> None:
    display_name = getattr(type(plugin), "display_name", None)
    assert isinstance(display_name, str), (
        f"{plugin.vendor_id}: display_name must be a str ClassVar, "
        f"got {type(display_name).__name__}"
    )
    assert display_name.strip(), f"{plugin.vendor_id}: display_name must not be blank"


def _check_capability_set(plugin: VendorPlugin) -> None:
    capabilities = getattr(type(plugin), "capabilities", None)
    assert isinstance(capabilities, frozenset), (
        f"{plugin.vendor_id}: capabilities must be a frozenset ClassVar, "
        f"got {type(capabilities).__name__}"
    )
    assert capabilities, f"{plugin.vendor_id}: must declare at least one capability"
    rogue = sorted(str(item) for item in capabilities if not isinstance(item, Capability))
    assert not rogue, f"{plugin.vendor_id}: capabilities contains non-Capability members: {rogue}"


# ---------------------------------------------------------------------------
# implementation:<capability> checks
# ---------------------------------------------------------------------------


def _check_capability_implementation(plugin: VendorPlugin, capability: Capability) -> None:
    impl = _resolve(plugin, capability)
    ctx = f"{plugin.vendor_id}: capability {capability.value!r} -> {impl.__name__}"

    declared = getattr(impl, "capabilities", None)
    assert declared is not None, f"{ctx}: implementation class defines no `capabilities` ClassVar"
    assert capability in declared, (
        f"{ctx}: implementation class does not declare {capability.value!r} in its "
        f"`capabilities` ClassVar (declares: {sorted(c.value for c in declared)})"
    )

    spec = _INTERFACE_SPECS.get(capability)
    if spec is not None:
        assert issubclass(impl, spec.interface), (
            f"{ctx}: must subclass the typed interface {spec.interface.__name__} "
            f"from app.plugins.base"
        )
        for name in sorted(getattr(spec.interface, "__abstractmethods__", frozenset())):
            method = getattr(impl, name, None)
            assert method is not None, (
                f"{ctx}: missing method {name!r} required by {spec.interface.__name__}"
            )
            assert not getattr(method, "__isabstractmethod__", False), (
                f"{ctx}: inherits abstract {name!r} from {spec.interface.__name__} "
                "without a concrete override"
            )

    assert not inspect.isabstract(impl), (
        f"{ctx}: implementation class is abstract — unimplemented methods: "
        f"{sorted(impl.__abstractmethods__)}"
    )


def _resolve(plugin: VendorPlugin, capability: Capability) -> type[PluginCapability]:
    try:
        impl = plugin.get_capability(capability)
    except PluginError as exc:
        raise AssertionError(
            f"{plugin.vendor_id}: declared capability {capability.value!r} does not "
            f"resolve via get_capability(): {exc}"
        ) from exc
    assert isinstance(impl, type) and issubclass(impl, PluginCapability), (
        f"{plugin.vendor_id}: capability {capability.value!r} resolved to "
        f"{impl!r}, which is not a PluginCapability subclass"
    )
    return impl


# ---------------------------------------------------------------------------
# fixtures:<capability> checks
# ---------------------------------------------------------------------------


def _check_change_write_outputs(
    plugin: VendorPlugin,
    capability: Capability,
    invoker: ChangeWriteInvoker | None,
) -> None:
    """Certify a device-write capability over its bundled fixtures (ADR-0021).

    The capability is the first device-write path; it returns a structured
    :class:`ChangeResult`, not a normalized-record list, so the contract asserts
    the result shape and a successful end-state (``applied``/``no_op``) over a
    recorded :class:`ConfigWriteTransport` fixture — never a live device (D16).
    """
    spec = _INTERFACE_SPECS[capability]
    impl = _resolve(plugin, capability)
    ctx = f"{plugin.vendor_id}: capability {capability.value!r} ({impl.__name__}.{spec.method})"
    assert invoker is not None, (
        f"{ctx}: a change-write capability requires a 'change_write_invokers' entry "
        f"in make_conformance_cases() for {capability.value!r}"
    )

    result = invoker(impl)
    assert isinstance(result, ChangeResult), (
        f"{ctx}: must return ChangeResult, got {type(result).__name__}"
    )
    assert result.outcome in {ChangeOutcome.APPLIED, ChangeOutcome.NO_OP}, (
        f"{ctx}: over the bundled fixture the write must succeed "
        f"(applied/no_op), got {result.outcome.value!r}"
    )
    assert result.verified is True, (
        f"{ctx}: a successful write must report verify-after success (verified=True)"
    )
    assert result.rollback is None, f"{ctx}: a successful write must not carry a rollback result"


def _check_archive_backup_outputs(
    plugin: VendorPlugin, capability: Capability, capability_factory: CapabilityFactory
) -> None:
    """Certify a binary-archive backup capability over its bundled fixtures (ADR-0050 §7).

    The capability returns a secret-bearing :class:`ConfigArchive`, not a
    normalized-record list: the contract asserts the archive metadata shape
    (format / sha256 / size) AND that the archive bytes are masked in ``repr`` and
    serialization (the :class:`~pydantic.SecretBytes` no-leak posture) over a
    recorded control-plane fixture — never a live device (D16).
    """
    spec = _INTERFACE_SPECS[capability]
    impl = _resolve(plugin, capability)
    ctx = f"{plugin.vendor_id}: capability {capability.value!r} ({impl.__name__}.{spec.method})"

    instance = capability_factory(impl)
    result = getattr(instance, spec.method)()

    assert isinstance(result, ConfigArchive), (
        f"{ctx}: must return ConfigArchive, got {type(result).__name__}"
    )
    assert result.format.strip(), f"{ctx}: archive format must be non-empty"
    assert len(result.sha256) == 64, (
        f"{ctx}: archive sha256 must be a 64-char hex digest, got {len(result.sha256)} chars"
    )
    assert result.size_bytes > 0, f"{ctx}: archive size_bytes must be positive"
    assert result.passphrase_ref.strip(), (
        f"{ctx}: archive must carry a vault passphrase_ref (never the passphrase itself)"
    )
    # The archive bytes must NOT surface in repr or a JSON dump (SecretBytes mask).
    plaintext_bytes = result.content.get_secret_value()
    assert plaintext_bytes, f"{ctx}: archive content must be non-empty"
    rendered = repr(result)
    assert plaintext_bytes.hex() not in rendered and str(plaintext_bytes) not in rendered, (
        f"{ctx}: archive bytes must be masked in repr (SecretBytes), ADR-0050 §7.3"
    )
    dumped = str(result.model_dump())
    assert plaintext_bytes.hex() not in dumped and str(plaintext_bytes) not in dumped, (
        f"{ctx}: archive bytes must be masked in serialization (SecretBytes), ADR-0050 §7.3"
    )


def _check_fixture_outputs(
    plugin: VendorPlugin, capability: Capability, capability_factory: CapabilityFactory
) -> None:
    spec = _INTERFACE_SPECS[capability]
    impl = _resolve(plugin, capability)
    ctx = f"{plugin.vendor_id}: capability {capability.value!r} ({impl.__name__}.{spec.method})"

    instance = capability_factory(impl)
    result = getattr(instance, spec.method)()

    if spec.facts_model is not None:
        _check_facts(ctx, result, spec.facts_model, plugin.vendor_id)
        return

    if spec.item_model is None:
        assert isinstance(result, str), f"{ctx}: must return str, got {type(result).__name__}"
        assert result.strip(), f"{ctx}: returned empty output for the bundled fixture"
        return

    _check_record_list(
        ctx, result, spec.item_model, plugin.vendor_id, spec.neighbor_protocol, allow_empty=False
    )

    # Capabilities whose interface returns more than one normalized-record list
    # (FIREWALL_POLICY: firewall + NAT rules, ADR-0034). Each extra method is
    # exercised over the same fixtures and re-validated against its own model;
    # an extra list may be empty (e.g. a firewall with no NAT rules).
    for method_name, model in spec.extra_records:
        extra_ctx = (
            f"{plugin.vendor_id}: capability {capability.value!r} ({impl.__name__}.{method_name})"
        )
        extra_result = getattr(instance, method_name)()
        _check_record_list(extra_ctx, extra_result, model, plugin.vendor_id, None, allow_empty=True)


def _check_record_list(
    ctx: str,
    result: object,
    item_model: type[NormalizedRecord],
    vendor_id: str,
    neighbor_protocol: NeighborProtocol | None,
    *,
    allow_empty: bool,
) -> None:
    assert isinstance(result, list), f"{ctx}: must return a list, got {type(result).__name__}"
    if not allow_empty:
        assert result, f"{ctx}: returned no records for the bundled fixture — expected at least one"
    for index, item in enumerate(result):
        _check_record(ctx, index, item, item_model, vendor_id, neighbor_protocol)


def _check_facts(
    ctx: str,
    result: object,
    facts_model: type[DeviceFacts],
    vendor_id: str,
) -> None:
    assert isinstance(result, facts_model), (
        f"{ctx}: must return {facts_model.__name__}, got {type(result).__name__}"
    )
    try:
        facts_model.model_validate(result.model_dump(mode="python"))
    except ValidationError as exc:
        details = "; ".join(
            f"field {'.'.join(str(loc) for loc in error['loc'])!r}: {error['msg']}"
            for error in exc.errors()
        )
        raise AssertionError(f"{ctx} fails {facts_model.__name__} validation: {details}") from exc
    assert result.vendor_id == vendor_id, (
        f"{ctx}: field 'vendor_id' is {result.vendor_id!r}, "
        f"expected the plugin vendor_id {vendor_id!r}"
    )


def _check_record(
    ctx: str,
    index: int,
    item: object,
    item_model: type[NormalizedRecord],
    vendor_id: str,
    neighbor_protocol: NeighborProtocol | None,
) -> None:
    item_ctx = f"{ctx}: item[{index}]"
    assert isinstance(item, item_model), (
        f"{item_ctx} is {type(item).__name__}, expected {item_model.__name__}"
    )
    try:
        item_model.model_validate(item.model_dump(mode="python"))
    except ValidationError as exc:
        details = "; ".join(
            f"field {'.'.join(str(loc) for loc in error['loc'])!r}: {error['msg']}"
            for error in exc.errors()
        )
        raise AssertionError(
            f"{item_ctx} fails {item_model.__name__} validation: {details}"
        ) from exc
    assert item.source_vendor == vendor_id, (
        f"{item_ctx} field 'source_vendor' is {item.source_vendor!r}, "
        f"expected the plugin vendor_id {vendor_id!r}"
    )
    if neighbor_protocol is not None:
        assert isinstance(item, NormalizedNeighbor)  # implied by item_model
        assert item.protocol == neighbor_protocol, (
            f"{item_ctx} field 'protocol' is {item.protocol.value!r}, "
            f"expected {neighbor_protocol.value!r}"
        )
