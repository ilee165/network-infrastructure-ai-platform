"""Application-dependency derivation — the three automated sources (ADR-0052 §2, P4 W2-T2).

ONE deterministic, **pure** derivation function
(:func:`derive_application_dependencies`) mirroring the ``derive_dns`` /
``derive_topology`` house pattern: no I/O inside, every input loaded (or
fetched) by the caller, output fully determined by input *content* and
insensitive to input ordering. It computes the desired state of the
``applications`` / ``application_dependencies`` tables for the automated
sources; persisting the plan (diff-replace per source, MERGE on
``origin_ref``, manual-wins dirty tracking) is the applier's job
(:mod:`app.engines.topology.app_derivation_store`). Derivation never
projects; projection never derives (ADR-0052 §5).

The three sources (ADR-0052 §2; source 4 — manual tagging — is user-written,
W2-T3):

1. **F5 VIP→pool→member** (W1 persisted ADC rows, ADR-0050 §4): one
   ``derived`` application per virtual server —
   ``origin_ref = f5:<device_pg_id>:<vs_full_path>`` — named by the
   partition-path leaf, with the VS-leaf-as-FQDN seed heuristic
   (:func:`_is_fqdn` binds it: at least two dot-separated RFC-952-shaped
   labels, non-numeric TLD). Edges go to each pool member's reconciled
   endpoint via the M5 :class:`~app.engines.topology.dns._AddressIndex`
   (interface-IP match → ``ip_address``, device-mgmt-IP match → ``device``);
   unreconcilable members emit **no** edge and are counted. Disabled/offline
   virtual servers and members still derive — impact analysis needs the
   configured dependency, not just live traffic (ADR-0050 §4.3/§4.4).
2. **VMware VM→host placement** (W1 persisted virtualization rows, ADR-0051
   §5.5) — a *chain extender*, creating no applications: every
   application-linked, non-template VM — linked by member-address ↔
   ``guest_ip_addresses``, member-``fqdn`` ↔ ``guest_hostname``
   (case-insensitive), or a manual tag on one of the VM's reconciled
   endpoints — emits app → the hypervisor host's inventory *device*, with the
   VM hop recorded in provenance. Hosts that are not inventory devices emit
   no edge (no phantom endpoints); the miss is counted.
3. **DNS dependencies (M5)** — the ``_AddressIndex`` reconciliation applied
   to **caller-fetched** DDI records (the ADR-0052 §2 input-side exception)
   for each application's ``fqdns`` — both rows that already exist and
   applications planned by source 1 in the same pass. CNAME hops are walked
   (bounded, loop-safe) and every record key (``name|type|value``) on the
   path lands in provenance. ``dns_records=None`` means the caller could not
   fetch (no DDI reachability): the pass is SKIPPED (``dns_pass_ran=False``)
   so persisted source-3 rows are preserved — an outage must never read as
   "no DNS evidence" and delete results that rebuild depends on.

Provenance steps reference rows by PG id or stable natural key only — never
row content, never secret material (ADR-0052 §3.1).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict

from app.engines.topology.dns import (
    _AddressIndex,  # noqa: PLC2701 - the ADR-0052 §2 named reconciliation machinery
    dns_record_key,
)
from app.knowledge.schema import LABEL_DEVICE, LABEL_IPADDRESS
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
    derived_attributes_clean,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord

__all__ = [
    "DerivationPlan",
    "DerivationStats",
    "PlannedApplication",
    "PlannedDependency",
    "ProvenanceStep",
    "derive_application_dependencies",
]

#: Projected label -> the rebuild-safe target kind it persists as (§2.3).
_TARGET_KIND_BY_LABEL: dict[str, str] = {
    LABEL_DEVICE: DependencyTargetKind.DEVICE.value,
    LABEL_IPADDRESS: DependencyTargetKind.IP_ADDRESS.value,
}

#: Terminal provenance step kind per target kind: an ``ip_address`` target is
#: an interface row (the M5 IPAddress node keys on the interface pg_id).
_TERMINAL_KIND: dict[str, str] = {
    DependencyTargetKind.DEVICE.value: "device",
    DependencyTargetKind.IP_ADDRESS.value: "interface",
}

_ADDRESS_RECORD_TYPES = frozenset({DnsRecordType.A, DnsRecordType.AAAA})

#: CNAME chains longer than this are abandoned (defensive; real chains are 1-2).
_MAX_CNAME_DEPTH = 8

_FQDN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Typed plan records (frozen — derivation output, not scratch space)
# ---------------------------------------------------------------------------


class ProvenanceStep(BaseModel):
    """One evidence-chain step: a row id or stable natural key, never content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str
    ref: str


class PlannedApplication(BaseModel):
    """Desired state of one source-1 derived application (ADR-0052 §2/§3.3.4).

    ``application_id`` is set when the pass resolved an EXISTING row (MERGE by
    ``origin_ref``, or the case-insensitive name-collision attach) and ``None``
    when the applier must create the row. ``record_origin_ref`` marks the
    first-attach case (derived-origin row lacking an ``origin_ref``);
    ``refresh_attributes`` is the §3.3.3 manual-wins verdict computed against
    the row snapshot — the applier re-checks it at write time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin_ref: str
    application_id: str | None = None
    name: str
    description: str | None = None
    fqdns: tuple[str, ...] = ()
    record_origin_ref: bool = False
    refresh_attributes: bool = False


class PlannedDependency(BaseModel):
    """Desired state of one (application, target, source) assertion.

    Exactly one of ``application_id`` (existing row) / ``app_origin_ref``
    (application planned by THIS pass, resolved after the applier upserts it)
    is set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: str | None = None
    app_origin_ref: str | None = None
    source: str
    target_kind: str
    target_ref: str
    provenance: tuple[ProvenanceStep, ...] = ()


class DerivationStats(BaseModel):
    """Per-source emitted/unreconciled counters (W2-T2 contract)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    f5_applications: int = 0
    f5_edges: int = 0
    f5_members_unreconciled: int = 0
    f5_pools_missing: int = 0
    vmware_edges: int = 0
    vmware_hosts_unmatched: int = 0
    dns_edges: int = 0
    dns_names_unreconciled: int = 0
    dns_skipped: bool = False


class DerivationPlan(BaseModel):
    """The complete desired automated-source state of one derivation pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    applications: tuple[PlannedApplication, ...] = ()
    dependencies: tuple[PlannedDependency, ...] = ()
    #: ``False`` when ``dns_records`` was ``None`` — the applier must then
    #: leave every ``source='dns'`` row untouched (results persist, §2.3).
    dns_pass_ran: bool = False
    stats: DerivationStats


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _canonical_ip(value: object) -> str | None:
    """Canonical host string of an IP literal, else ``None``."""
    if value is None:
        return None
    try:
        return str(ip_address(str(value).strip()))
    except ValueError:
        return None


def _leaf_name(full_path: str) -> str:
    """Human name of a partition-qualified F5 object (``/Common/x`` -> ``x``)."""
    leaf = full_path.rsplit("/", 1)[-1].strip()
    return leaf or full_path.strip()


def _is_fqdn(candidate: str) -> bool:
    """The W2-T2-bound VS-name-as-FQDN seed heuristic (ADR-0052 §1 ``fqdns``).

    True when *candidate* looks like a resolvable DNS name: <= 253 chars, at
    least two dot-separated labels each matching the hostname-label shape,
    and a non-numeric TLD (so an IPv4 literal never seeds).
    """
    name = candidate.strip().rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    labels = name.split(".")
    if len(labels) < 2 or any(not _FQDN_LABEL_RE.match(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def _dns_name_key(name: str) -> str:
    """Case-insensitive, root-dot-insensitive DNS name join key."""
    return name.strip().rstrip(".").lower()


class _AppKey:
    """Internal union key of a dependency's application (existing id XOR planned ref)."""

    __slots__ = ("application_id", "origin_ref")

    def __init__(self, *, application_id: str | None, origin_ref: str | None) -> None:
        self.application_id = application_id
        self.origin_ref = origin_ref

    def sort_key(self) -> tuple[str, str]:
        return (self.application_id or "", self.origin_ref or "")

    def identity(self) -> tuple[str | None, str | None]:
        return (self.application_id, self.origin_ref)


class _MemberEvidence:
    """One walked pool member, kept for the source-2 chain extension."""

    __slots__ = ("address", "app", "fqdn_key", "member_name", "prefix")

    def __init__(
        self,
        app: _AppKey,
        prefix: tuple[ProvenanceStep, ...],
        member_name: str,
        address: str | None,
        fqdn_key: str | None,
    ) -> None:
        self.app = app
        self.prefix = prefix
        self.member_name = member_name
        self.address = address
        self.fqdn_key = fqdn_key


def _dep(
    app: _AppKey,
    source: DependencySource,
    target_kind: str,
    target_ref: str,
    provenance: Sequence[ProvenanceStep],
) -> PlannedDependency:
    return PlannedDependency(
        application_id=app.application_id,
        app_origin_ref=app.origin_ref,
        source=source.value,
        target_kind=target_kind,
        target_ref=target_ref,
        provenance=tuple(provenance),
    )


# ---------------------------------------------------------------------------
# The one pure derivation function
# ---------------------------------------------------------------------------


def derive_application_dependencies(
    *,
    virtual_servers: Sequence[NormalizedVirtualServerRow],
    pools: Sequence[NormalizedPoolRow],
    virtual_machines: Sequence[NormalizedVirtualMachineRow],
    hypervisor_hosts: Sequence[NormalizedHypervisorHostRow],
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    applications: Sequence[Application],
    dependencies: Sequence[ApplicationDependency],
    dns_records: Sequence[NormalizedDnsRecord] | None,
) -> DerivationPlan:
    """Compute the desired automated-source rows from caller-loaded inputs (pure).

    Every argument is a plain in-memory row sequence — no session, no plugin,
    no DDI call happens here. *applications*/*dependencies* are the CURRENT
    table contents (collision attach, manual-tag linkage and per-app ``fqdns``
    need them); *dns_records* is the caller-fetched full DDI record set, or
    ``None`` when unfetchable (source 3 skipped). Output ordering and content
    are independent of every input sequence's ordering.
    """
    index = _AddressIndex(devices, interfaces)

    # -- shared existing-row lookups (deterministic on ties) ----------------
    apps_sorted = sorted(applications, key=lambda a: str(a.id))
    app_by_id = {str(a.id): a for a in apps_sorted}
    by_origin_ref: dict[str, Application] = {}
    by_lower_name: dict[str, Application] = {}
    for app in apps_sorted:
        if app.origin_ref is not None:
            by_origin_ref.setdefault(app.origin_ref, app)
        by_lower_name.setdefault(app.name.strip().lower(), app)

    # ======================================================================
    # Source 1 — F5 VIP -> pool -> member
    # ======================================================================
    pool_by_key = {
        (str(p.device_id), p.name): p
        for p in sorted(pools, key=lambda p: (str(p.device_id), p.name, str(p.id)))
    }

    planned: dict[str, PlannedApplication] = {}  # origin_ref -> planned app
    planned_ref_by_lower_name: dict[str, str] = {}  # in-pass collision registry
    f5_deps: dict[tuple[tuple[str | None, str | None], str, str], PlannedDependency] = {}
    member_evidence: list[_MemberEvidence] = []
    members_unreconciled = 0
    pools_missing = 0

    vs_sorted = sorted(virtual_servers, key=lambda vs: f"f5:{vs.device_id}:{vs.name}")
    for vs in vs_sorted:
        origin_ref = f"f5:{vs.device_id}:{vs.name}"
        name = _leaf_name(vs.name)
        fqdns: tuple[str, ...] = (name,) if _is_fqdn(name) else ()
        lower = name.strip().lower()

        existing = by_origin_ref.get(origin_ref)
        app_key: _AppKey
        if existing is not None:
            planned[origin_ref] = PlannedApplication(
                origin_ref=origin_ref,
                application_id=str(existing.id),
                name=name,
                description=vs.description,
                fqdns=fqdns,
                refresh_attributes=derived_attributes_clean(existing),
            )
            app_key = _AppKey(application_id=str(existing.id), origin_ref=None)
        elif lower in by_lower_name:
            # §3.3.4 name-collision attach: never a duplicate application.
            collided = by_lower_name[lower]
            is_derived = ApplicationOrigin(collided.origin) is ApplicationOrigin.DERIVED
            first_attach = is_derived and collided.origin_ref is None
            foreign_ref = is_derived and collided.origin_ref is not None
            planned[origin_ref] = PlannedApplication(
                origin_ref=origin_ref,
                application_id=str(collided.id),
                name=name,
                description=vs.description,
                fqdns=fqdns,
                record_origin_ref=first_attach,
                # A manual row keeps user-owned attributes by definition; a
                # derived row owned by ANOTHER origin_ref keeps its owner's.
                refresh_attributes=(
                    derived_attributes_clean(collided) if not foreign_ref else False
                ),
            )
            app_key = _AppKey(application_id=str(collided.id), origin_ref=None)
        elif lower in planned_ref_by_lower_name:
            # Within-pass duplicate leaf name: attach edges to the winner
            # (lexically-smallest origin_ref — vs_sorted order), plan no row.
            app_key = _AppKey(application_id=None, origin_ref=planned_ref_by_lower_name[lower])
        else:
            planned[origin_ref] = PlannedApplication(
                origin_ref=origin_ref,
                name=name,
                description=vs.description,
                fqdns=fqdns,
            )
            app_key = _AppKey(application_id=None, origin_ref=origin_ref)
        planned_ref_by_lower_name.setdefault(lower, origin_ref)

        if vs.pool_name is None:
            continue
        pool = pool_by_key.get((str(vs.device_id), vs.pool_name))
        if pool is None:
            pools_missing += 1
            continue

        vs_step = ProvenanceStep(kind="virtual_server", ref=str(vs.id))
        pool_step = ProvenanceStep(kind="pool", ref=str(pool.id))
        members: Iterable[object] = pool.members or []
        parsed: list[tuple[str, str | None, str | None]] = []
        for entry in members:
            if not isinstance(entry, Mapping):
                continue
            raw_name = str(entry.get("name") or "").strip()
            address = _canonical_ip(entry.get("address"))
            fqdn_raw = entry.get("fqdn")
            fqdn_key = _dns_name_key(str(fqdn_raw)) if fqdn_raw else None
            member_name = raw_name or (
                f"{address}:{entry.get('port')}" if address else fqdn_key or "<member>"
            )
            parsed.append((member_name, address, fqdn_key))

        # None-safe key: address/fqdn_key are ``str | None``, so a bare
        # ``sorted`` compares ``str`` vs ``None`` on the tie-break elements when
        # two members share a ``member_name`` (e.g. an address-bearing member
        # colliding with an fqdn-only one) and raises ``TypeError``, aborting the
        # whole pass (PR #119 review). Coerce ``None`` to ``""`` for ordering.
        for member_name, address, fqdn_key in sorted(
            parsed, key=lambda t: (t[0], t[1] or "", t[2] or "")
        ):
            member_step = ProvenanceStep(kind="member", ref=member_name)
            member_evidence.append(
                _MemberEvidence(app_key, (vs_step, member_step), member_name, address, fqdn_key)
            )
            target = index.resolve(address) if address is not None else None
            if target is None:
                members_unreconciled += 1
                continue
            label, key = target
            kind = _TARGET_KIND_BY_LABEL[label]
            f5_deps.setdefault(
                (app_key.identity(), kind, key),
                _dep(
                    app_key,
                    DependencySource.F5,
                    kind,
                    key,
                    (
                        vs_step,
                        pool_step,
                        member_step,
                        ProvenanceStep(kind=_TERMINAL_KIND[kind], ref=key),
                    ),
                ),
            )

    # ======================================================================
    # Source 2 — VMware VM -> host chain extender (no applications created)
    # ======================================================================
    devices_sorted = sorted(devices, key=lambda d: str(d.id))
    device_by_mgmt: dict[str, Device] = {}
    device_by_hostname: dict[str, list[Device]] = {}
    for device in devices_sorted:
        mgmt = _canonical_ip(device.mgmt_ip)
        if mgmt is not None:
            device_by_mgmt.setdefault(mgmt, device)
        device_by_hostname.setdefault(device.hostname.strip().lower(), []).append(device)

    def _host_inventory_device(host: NormalizedHypervisorHostRow) -> Device | None:
        mgmt = _canonical_ip(host.management_ip)
        if mgmt is not None and mgmt in device_by_mgmt:
            return device_by_mgmt[mgmt]
        name = _dns_name_key(host.name)
        full = device_by_hostname.get(name)
        if full:
            return full[0]
        leaf = device_by_hostname.get(name.split(".")[0])
        if leaf is not None and len(leaf) == 1:
            return leaf[0]  # unambiguous short-hostname match only
        return None

    hosts_sorted = sorted(hypervisor_hosts, key=lambda h: (str(h.device_id), h.moref, str(h.id)))
    host_index: dict[tuple[str, str], list[NormalizedHypervisorHostRow]] = {}
    for host in hosts_sorted:
        host_index.setdefault((str(host.device_id), _dns_name_key(host.name)), []).append(host)

    def _vm_host(vm: NormalizedVirtualMachineRow) -> NormalizedHypervisorHostRow | None:
        if not vm.host_name:
            return None
        candidates = host_index.get((str(vm.device_id), _dns_name_key(vm.host_name)), [])
        if vm.datacenter:
            # ADR-0051 §5.5: name joins are datacenter-scoped.
            candidates = [h for h in candidates if h.datacenter in (None, "", vm.datacenter)]
        return candidates[0] if candidates else None

    manual_rows = sorted(
        (
            row
            for row in dependencies
            if DependencySource(str(row.source)) is DependencySource.MANUAL
            and str(row.application_id) in app_by_id
        ),
        key=lambda row: str(row.id),
    )
    evidence_sorted = sorted(member_evidence, key=lambda e: (e.app.sort_key(), e.member_name))

    vmware_deps: dict[tuple[tuple[str | None, str | None], str, str], PlannedDependency] = {}
    hosts_unmatched = 0
    vms_sorted = sorted(virtual_machines, key=lambda vm: (str(vm.device_id), vm.moref, str(vm.id)))
    for vm in vms_sorted:
        if vm.is_template:
            continue  # never a traffic endpoint (ADR-0051 §5.3)
        guest_ips = {ip for ip in (_canonical_ip(raw) for raw in vm.guest_ip_addresses or []) if ip}
        guest_host_key = _dns_name_key(vm.guest_hostname) if vm.guest_hostname else None
        endpoints: set[tuple[str, str]] = set()
        for ip in guest_ips:
            resolved = index.resolve(ip)
            if resolved is not None:
                label, key = resolved
                endpoints.add((_TARGET_KIND_BY_LABEL[label], key))

        links: list[tuple[_AppKey, tuple[ProvenanceStep, ...]]] = []
        for evidence in evidence_sorted:
            ip_link = evidence.address is not None and evidence.address in guest_ips
            fqdn_link = (
                evidence.fqdn_key is not None
                and guest_host_key is not None
                and evidence.fqdn_key == guest_host_key
            )
            if ip_link or fqdn_link:
                links.append((evidence.app, evidence.prefix))
        for tag_row in manual_rows:
            if (str(tag_row.target_kind), tag_row.target_ref) in endpoints:
                links.append(
                    (
                        _AppKey(application_id=str(tag_row.application_id), origin_ref=None),
                        (ProvenanceStep(kind="dependency", ref=str(tag_row.id)),),
                    )
                )
        if not links:
            continue

        host_row = _vm_host(vm)
        target_device = _host_inventory_device(host_row) if host_row is not None else None
        if host_row is None or target_device is None:
            hosts_unmatched += 1  # linked VM, but no inventory host device: no edge
            continue

        vm_steps = (
            ProvenanceStep(kind="virtual_machine", ref=str(vm.id)),
            ProvenanceStep(kind="hypervisor_host", ref=str(host_row.id)),
            ProvenanceStep(kind="device", ref=str(target_device.id)),
        )
        for app_key, prefix in links:
            vmware_deps.setdefault(
                (
                    app_key.identity(),
                    DependencyTargetKind.DEVICE.value,
                    str(target_device.id),
                ),
                _dep(
                    app_key,
                    DependencySource.VMWARE,
                    DependencyTargetKind.DEVICE.value,
                    str(target_device.id),
                    prefix + vm_steps,
                ),
            )

    # ======================================================================
    # Source 3 — DNS linkage over caller-fetched records (skippable)
    # ======================================================================
    dns_deps: dict[tuple[tuple[str | None, str | None], str, str], PlannedDependency] = {}
    dns_unreconciled = 0
    dns_pass_ran = dns_records is not None
    if dns_records is not None:
        record_by_key: dict[str, NormalizedDnsRecord] = {}
        for record in dns_records:
            record_by_key.setdefault(
                dns_record_key(record.name, record.record_type, record.value), record
            )
        by_name: dict[str, list[tuple[str, NormalizedDnsRecord]]] = {}
        for key, record in sorted(record_by_key.items()):
            by_name.setdefault(_dns_name_key(record.name), []).append((key, record))

        consumed_ids = {
            pa.application_id for pa in planned.values() if pa.application_id is not None
        }
        planned_refs = set(planned)
        dns_apps: list[tuple[_AppKey, tuple[str, ...]]] = []
        for pa in sorted(planned.values(), key=lambda p: p.origin_ref):
            if pa.application_id is not None:
                merged_row = app_by_id.get(pa.application_id)
                # The row's stored fqdns win unless this pass refreshes them.
                stored: tuple[str, ...] = tuple(
                    (merged_row.fqdns or []) if merged_row is not None else ()
                )
                effective = pa.fqdns if pa.refresh_attributes else stored
                dns_apps.append(
                    (_AppKey(application_id=pa.application_id, origin_ref=None), effective)
                )
            else:
                dns_apps.append((_AppKey(application_id=None, origin_ref=pa.origin_ref), pa.fqdns))
        for app in apps_sorted:
            if str(app.id) in consumed_ids:
                continue
            if (
                ApplicationOrigin(app.origin) is ApplicationOrigin.DERIVED
                and app.origin_ref is not None
                and app.origin_ref.startswith("f5:")
                and app.origin_ref not in planned_refs
            ):
                continue  # the source object vanished — the applier deletes the row
            dns_apps.append(
                (
                    _AppKey(application_id=str(app.id), origin_ref=None),
                    tuple(app.fqdns or []),
                )
            )

        def _walk(
            name_key: str,
            chain: tuple[ProvenanceStep, ...],
            visited: frozenset[str],
        ) -> list[tuple[str, str, tuple[ProvenanceStep, ...]]]:
            """All reconciled (kind, key, provenance) endpoints below *name_key*."""
            results: list[tuple[str, str, tuple[ProvenanceStep, ...]]] = []
            for record_key, record in by_name.get(name_key, []):
                step = ProvenanceStep(kind="dns_record", ref=record_key)
                if record.record_type in _ADDRESS_RECORD_TYPES:
                    target = index.resolve(record.value)
                    if target is None:
                        continue
                    label, key = target
                    kind = _TARGET_KIND_BY_LABEL[label]
                    results.append(
                        (
                            kind,
                            key,
                            chain + (step, ProvenanceStep(kind=_TERMINAL_KIND[kind], ref=key)),
                        )
                    )
                elif record.record_type is DnsRecordType.CNAME:
                    next_key = _dns_name_key(record.value)
                    if next_key in visited or len(chain) >= _MAX_CNAME_DEPTH:
                        continue
                    results.extend(_walk(next_key, chain + (step,), visited | {next_key}))
            return results

        for app_key, fqdns in dns_apps:
            for fqdn in sorted({_dns_name_key(f) for f in fqdns if f and f.strip()}):
                resolved_any = False
                for kind, key, chain in _walk(fqdn, (), frozenset({fqdn})):
                    resolved_any = True
                    dns_deps.setdefault(
                        (app_key.identity(), kind, key),
                        _dep(app_key, DependencySource.DNS, kind, key, chain),
                    )
                if not resolved_any:
                    dns_unreconciled += 1

    # ======================================================================
    # Assemble (deterministic ordering; content already order-independent)
    # ======================================================================
    all_deps = sorted(
        (*f5_deps.values(), *vmware_deps.values(), *dns_deps.values()),
        key=lambda d: (
            d.source,
            d.application_id or "",
            d.app_origin_ref or "",
            d.target_kind,
            d.target_ref,
        ),
    )
    stats = DerivationStats(
        f5_applications=len(planned),
        f5_edges=len(f5_deps),
        f5_members_unreconciled=members_unreconciled,
        f5_pools_missing=pools_missing,
        vmware_edges=len(vmware_deps),
        vmware_hosts_unmatched=hosts_unmatched,
        dns_edges=len(dns_deps),
        dns_names_unreconciled=dns_unreconciled,
        dns_skipped=not dns_pass_ran,
    )
    return DerivationPlan(
        applications=tuple(sorted(planned.values(), key=lambda p: p.origin_ref)),
        dependencies=tuple(all_deps),
        dns_pass_ran=dns_pass_ran,
        stats=stats,
    )
