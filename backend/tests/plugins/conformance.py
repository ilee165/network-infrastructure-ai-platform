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
    BgpCapability,
    Capability,
    ChangeOutcome,
    ChangeResult,
    ConfigBackupCapability,
    ConfigDeployCapability,
    ConfigRestoreCapability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    OspfCapability,
    PluginCapability,
    RoutesCapability,
    VendorPlugin,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NeighborProtocol,
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRecord,
    NormalizedRoute,
)

__all__ = [
    "CapabilityFactory",
    "ChangeWriteInvoker",
    "ConformanceCase",
    "FixtureReplayTransport",
    "FixtureSnmpTransport",
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
    """

    interface: type[PluginCapability]
    method: str
    item_model: type[NormalizedRecord] | None
    neighbor_protocol: NeighborProtocol | None = None
    facts_model: type[DeviceFacts] | None = None
    change_write: bool = False


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
    Capability.CONFIG_BACKUP: _InterfaceSpec(ConfigBackupCapability, "fetch_running_config", None),
    Capability.CONFIG_RESTORE: _InterfaceSpec(
        ConfigRestoreCapability, "restore", None, change_write=True
    ),
    Capability.CONFIG_DEPLOY: _InterfaceSpec(
        ConfigDeployCapability, "deploy", None, change_write=True
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
        else:
            cases.append(
                ConformanceCase(
                    f"fixtures:{capability.value}",
                    partial(_check_fixture_outputs, plugin, capability, capability_factory),
                )
            )
    return cases


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

    assert isinstance(result, list), f"{ctx}: must return a list, got {type(result).__name__}"
    assert result, f"{ctx}: returned no records for the bundled fixture — expected at least one"
    for index, item in enumerate(result):
        _check_record(ctx, index, item, spec, plugin.vendor_id)


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
    spec: _InterfaceSpec,
    vendor_id: str,
) -> None:
    assert spec.item_model is not None  # callers guarantee a record-list spec
    item_ctx = f"{ctx}: item[{index}]"
    assert isinstance(item, spec.item_model), (
        f"{item_ctx} is {type(item).__name__}, expected {spec.item_model.__name__}"
    )
    try:
        spec.item_model.model_validate(item.model_dump(mode="python"))
    except ValidationError as exc:
        details = "; ".join(
            f"field {'.'.join(str(loc) for loc in error['loc'])!r}: {error['msg']}"
            for error in exc.errors()
        )
        raise AssertionError(
            f"{item_ctx} fails {spec.item_model.__name__} validation: {details}"
        ) from exc
    assert item.source_vendor == vendor_id, (
        f"{item_ctx} field 'source_vendor' is {item.source_vendor!r}, "
        f"expected the plugin vendor_id {vendor_id!r}"
    )
    if spec.neighbor_protocol is not None:
        assert isinstance(item, NormalizedNeighbor)  # implied by item_model
        assert item.protocol == spec.neighbor_protocol, (
            f"{item_ctx} field 'protocol' is {item.protocol.value!r}, "
            f"expected {spec.neighbor_protocol.value!r}"
        )
