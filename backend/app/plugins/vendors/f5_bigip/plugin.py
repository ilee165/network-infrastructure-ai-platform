"""F5 BIG-IP plugin: iControl REST ADC + secret-bearing UCS archive (ADR-0050).

The platform's **first ADC vendor** (`f5_bigip`), declaring ``DISCOVERY_API``,
``INTERFACES``, ``ROUTES`` (static routes + self-IP connected routes, route
domains -> ``vrf``), the new ``ADC_SERVICES`` (virtual servers + pools with
nested members), ``HA_STATUS`` (DSC failover/sync), and the new binary
config-archive pair ``CONFIG_BACKUP_ARCHIVE`` / ``CONFIG_RESTORE_ARCHIVE``
(UCS). No text ``CONFIG_BACKUP``/``CONFIG_RESTORE`` and no ``FIREWALL_POLICY``
(AFM out of scope; F5 text drift is a named deferral, ADR-0050 §7.6).

Secret posture (ADR-0050 §1/§2/§7):

- Login password + session token live only inside :class:`F5Client`
  (name-mangled, redaction-filtered); no secret crosses into a normalized field,
  a raw artifact ``command``, an exception message, or a log line.
- Every JSON collection page is recorded verbatim via ``_record_raw`` *before*
  parsing (ADR-0006 §3). The login/token exchange and the UCS **binary** body
  are NEVER raw-recorded (ADR-0050 §7.2).
- The UCS archive is opaque secret material: passphrase-encrypted on-box before
  download, returned as :class:`~app.plugins.base.ConfigArchive` with
  :class:`~pydantic.SecretBytes` content and a vault ``passphrase_ref`` — never
  the passphrase itself. Restore is CR-gated, baseline-first, never-silent
  rollback (ADR-0021 / ADR-0050 §7.4).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface, ip_network
from typing import Any, ClassVar, Protocol, runtime_checkable

from pydantic import SecretBytes

from app.core.errors import PluginError
from app.plugins.base import (
    AdcServicesCapability,
    Capability,
    ChangeOutcome,
    ChangePlan,
    ChangeResult,
    ConfigArchive,
    ConfigArchiveBackupCapability,
    ConfigArchiveRef,
    ConfigArchiveRestoreCapability,
    DiscoveryApiCapability,
    HaStatusCapability,
    InterfacesCapability,
    PluginCapability,
    RollbackResult,
    RoutesCapability,
    VendorPlugin,
)
from app.plugins.vendors.f5_bigip.client import F5Client
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    AdcAdminState,
    AdcAvailability,
    AdcProtocol,
    DiscoveredObjectKind,
    HaPeerLinkState,
    HaPeerRole,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NormalizedDiscoveredObject,
    NormalizedHaStatus,
    NormalizedInterface,
    NormalizedPool,
    NormalizedPoolMember,
    NormalizedRoute,
    NormalizedVirtualServer,
    RouteProtocol,
)

__all__ = [
    "F5BigipPlugin",
    "F5ConfigArchiveBackup",
    "F5ConfigArchiveRestore",
    "F5DiscoveryApi",
    "F5HaStatus",
    "F5Interfaces",
    "F5Routes",
    "F5Services",
    "PassphraseVault",
    "_map_member_session",
    "_map_member_state",
    "_map_protocol",
    "_parse_virtual_destination",
    "_split_host_port",
    "_split_route_domain",
]

VENDOR_ID = "f5_bigip"

_ARCHIVE_FORMAT = "ucs"


# ---------------------------------------------------------------------------
# Passphrase vault seam (ADR-0050 §7.2/§7.3)
# ---------------------------------------------------------------------------


@runtime_checkable
class PassphraseVault(Protocol):
    """Per-backup passphrase issuer/materializer (ADR-0050 §7.2/§7.3).

    The plugin is transport-only and stateless: it never writes the vault
    itself. This seam lets the archive capabilities (a) mint + persist a fresh
    high-entropy per-backup passphrase and get back a vault **reference**
    (:meth:`issue_passphrase`), and (b) materialize an existing passphrase for a
    restore (:meth:`materialize_passphrase`). The real implementation is backed
    by the credential vault (AES-256-GCM under the ADR-0032 KMS-backed KEK);
    tests inject an in-memory double. The passphrase plaintext is transient — it
    is used for the on-box save/load only and never stored on the plugin, the
    :class:`~app.plugins.base.ConfigArchive`, or any log line.
    """

    def issue_passphrase(self) -> tuple[str, str]:
        """Generate + persist a fresh passphrase; return ``(passphrase_ref, passphrase)``."""
        ...

    def materialize_passphrase(self, passphrase_ref: str) -> str:
        """Return the passphrase for an existing ``passphrase_ref`` (restore path)."""
        ...


# ---------------------------------------------------------------------------
# Parsing helpers (route domains, destinations, availability) — module-level
# and independently unit-tested (ADR-0050 §5).
# ---------------------------------------------------------------------------

#: F5 ipProtocol -> normalized AdcProtocol.
_PROTOCOL_MAP: Mapping[str, AdcProtocol] = {
    "tcp": AdcProtocol.TCP,
    "udp": AdcProtocol.UDP,
    "sctp": AdcProtocol.SCTP,
    "any": AdcProtocol.ANY,
}

#: F5 member ``session`` -> normalized AdcAdminState.
_SESSION_MAP: Mapping[str, AdcAdminState] = {
    "user-enabled": AdcAdminState.ENABLED,
    "monitor-enabled": AdcAdminState.ENABLED,
    "user-disabled": AdcAdminState.DISABLED,
    "user-down": AdcAdminState.FORCED_OFFLINE,
}

#: F5 member ``state`` -> normalized AdcAvailability.
_STATE_MAP: Mapping[str, AdcAvailability] = {
    "up": AdcAvailability.AVAILABLE,
    "user-up": AdcAvailability.AVAILABLE,
    "down": AdcAvailability.OFFLINE,
    "user-down": AdcAvailability.OFFLINE,
    "unchecked": AdcAvailability.UNKNOWN,
}


def _split_route_domain(addr: str) -> tuple[str, str | None]:
    """Strip an F5 ``%<id>`` route-domain suffix; return ``(clean_addr, vrf)``.

    The route-domain id is the numeric run immediately after ``%``; anything
    after it (a ``/prefix`` on a network/self-IP, a ``:port``) is re-appended to
    the clean address so ``10.5.0.0%2/16`` -> ``("10.5.0.0/16", "2")`` and
    ``10.1.1.1%2`` -> ``("10.1.1.1", "2")``. The default route domain ``0`` (and
    an empty id) normalizes to ``vrf=None`` (ADR-0050 §5). Two identical
    addresses in different route domains are different endpoints, so the id is
    carried, never collapsed.
    """
    if "%" not in addr:
        return addr, None
    base, _, rest = addr.partition("%")
    end = 0
    while end < len(rest) and rest[end].isdigit():
        end += 1
    rd, suffix = rest[:end], rest[end:]
    vrf = rd if rd and rd != "0" else None
    return base + suffix, vrf


def _to_port(token: str) -> int | None:
    """Parse an F5 port token; ``any``/``0``/non-numeric -> ``None``."""
    if token in ("", "any", "*", "0"):
        return None
    try:
        return int(token)
    except ValueError:
        return None


def _split_host_port(leaf: str) -> tuple[str, int | None]:
    """Split an F5 address-leaf into ``(host, port)`` handling v4 ``:`` and v6 ``.``.

    F5 renders an IPv4 destination as ``addr:port`` and an IPv6 destination as
    ``addr.port`` (the colon is reserved for the v6 address). A leaf with a
    route-domain suffix keeps it on the host part for :func:`_split_route_domain`.
    """
    # IPv6-with-port: more than one colon and a trailing ``.port``.
    if leaf.count(":") > 1 and "." in leaf:
        host, _, port = leaf.rpartition(".")
        return host, _to_port(port)
    # IPv4-with-port: exactly one colon.
    if leaf.count(":") == 1:
        host, _, port = leaf.rpartition(":")
        return host, _to_port(port)
    return leaf, None


def _parse_virtual_destination(
    destination: str,
) -> tuple[IPv4Address | IPv6Address | None, int | None, str | None]:
    """Parse an F5 virtual ``destination`` into ``(address, port, vrf)`` (ADR-0050 §5).

    ``/Common/10.1.1.1%2:443`` -> ``(10.1.1.1, 443, "2")``;
    ``/Common/2001:db8::1.443`` -> ``(2001:db8::1, 443, None)``;
    ``/Common/vip_addr_list`` (a non-literal address list) -> ``(None, None, None)``.
    """
    leaf = destination.rsplit("/", 1)[-1]
    host, port = _split_host_port(leaf)
    clean, vrf = _split_route_domain(host)
    try:
        address = ip_address(clean)
    except ValueError:
        # Non-literal destination (address list / named object): no VIP address.
        return None, None, None
    return address, port, vrf


def _map_protocol(ip_protocol: str | None) -> AdcProtocol:
    """Map F5 ``ipProtocol`` to :class:`AdcProtocol`; unset -> ANY, unknown -> OTHER."""
    if not ip_protocol:
        return AdcProtocol.ANY
    return _PROTOCOL_MAP.get(ip_protocol.lower(), AdcProtocol.OTHER)


def _map_member_session(session: str | None) -> AdcAdminState:
    """Map F5 member ``session`` to :class:`AdcAdminState` (default ENABLED)."""
    if not session:
        return AdcAdminState.ENABLED
    return _SESSION_MAP.get(session.lower(), AdcAdminState.ENABLED)


def _map_member_state(state: str | None) -> AdcAvailability:
    """Map F5 member ``state`` to :class:`AdcAvailability` (default UNKNOWN)."""
    if not state:
        return AdcAvailability.UNKNOWN
    return _STATE_MAP.get(state.lower(), AdcAvailability.UNKNOWN)


def _nested_first_entries(payload: Any) -> dict[str, Any]:
    """Return the inner ``nestedStats.entries`` of the first ``entries`` node.

    iControl stats/status endpoints wrap values as
    ``{"entries": {"<url>": {"nestedStats": {"entries": {...}}}}}``. Returns ``{}``
    when the shape is absent so a standalone/empty response is empty-not-error.
    """
    if not isinstance(payload, dict):
        return {}
    entries = payload.get("entries")
    if not isinstance(entries, dict) or not entries:
        return {}
    first = next(iter(entries.values()))
    if not isinstance(first, dict):
        return {}
    nested = first.get("nestedStats", first)
    inner = nested.get("entries") if isinstance(nested, dict) else None
    return inner if isinstance(inner, dict) else {}


def _entry_description(entries: dict[str, Any], key: str) -> str | None:
    """Read ``entries[key].description`` (the iControl scalar-value shape)."""
    node = entries.get(key)
    if isinstance(node, dict):
        desc = node.get("description")
        if isinstance(desc, str):
            return desc
    return None


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Shared capability base
# ---------------------------------------------------------------------------


class _F5Capability(PluginCapability):
    """Shared base: holds the iControl client + device context (raw-first).

    The uniform 3-arg constructor (``passphrase_vault`` optional) lets a single
    capability factory build every F5 capability; the read capabilities ignore
    the vault, the archive capabilities require it.
    """

    def __init__(
        self,
        client: F5Client,
        device_id: uuid.UUID,
        passphrase_vault: PassphraseVault | None = None,
    ) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id
        self._vault = passphrase_vault

    def _fetch(self, label: str, method_name: str) -> Any:
        """Call a single-response client read, record raw, and return parsed JSON."""
        raw: str = getattr(self._client, method_name)()
        self._record_raw(f"f5_bigip:{label}", raw)
        return _parse_json(raw, label)

    def _fetch_pages(self, label: str, pages: Iterator[str]) -> list[dict[str, Any]]:
        """Record every collection page raw and return the concatenated ``items``."""
        items: list[dict[str, Any]] = []
        for index, raw in enumerate(pages):
            self._record_raw(f"f5_bigip:{label}[page={index}]", raw)
            page = _parse_json(raw, label)
            page_items = page.get("items", []) if isinstance(page, dict) else []
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
        return items

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }

    def _require_vault(self) -> PassphraseVault:
        if self._vault is None:
            raise PluginError(
                "f5_bigip: archive capability requires a passphrase vault (ADR-0050 §7.2)"
            )
        return self._vault


def _parse_json(raw: str, context: str) -> Any:
    """Parse JSON text; raises PluginError on failure (context only, not the body)."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise PluginError(f"f5_bigip: {context} returned a non-JSON body") from None


# ---------------------------------------------------------------------------
# DISCOVERY_API
# ---------------------------------------------------------------------------


class F5DiscoveryApi(_F5Capability, DiscoveryApiCapability):
    """``DISCOVERY_API``: sys/version + sys/global-settings -> device identity."""

    def discover(self) -> list[NormalizedDiscoveredObject]:
        facts = self._collect_facts()
        provenance = self._provenance()
        attributes: list[tuple[str, str]] = []
        if facts.model:
            attributes.append(("model", facts.model))
        if facts.os_version:
            attributes.append(("os_version", facts.os_version))
        if facts.serial:
            attributes.append(("serial", facts.serial))
        return [
            NormalizedDiscoveredObject(
                **provenance,
                kind=DiscoveredObjectKind.OTHER,
                identifier=facts.hostname,
                display_name=f"{facts.hostname} ({facts.model or 'BIG-IP'})",
                object_ref=facts.serial,
                attributes=tuple(attributes),
            )
        ]

    def get_device_facts(self) -> DeviceFacts:
        return self._collect_facts()

    def _collect_facts(self) -> DeviceFacts:
        version = self._fetch("sys_version", "get_version")
        settings = self._fetch("sys_global_settings", "get_global_settings")
        v_entries = _nested_first_entries(version)
        hostname = (settings.get("hostname") if isinstance(settings, dict) else None) or "unknown"
        return DeviceFacts(
            hostname=hostname,
            vendor_id=VENDOR_ID,
            model=_entry_description(v_entries, "Product") or "BIG-IP",
            os_version=_entry_description(v_entries, "Version"),
            serial=None,
        )


# ---------------------------------------------------------------------------
# INTERFACES
# ---------------------------------------------------------------------------


class F5Interfaces(_F5Capability, InterfacesCapability):
    """``INTERFACES``: net/interface -> interface inventory."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        data = self._fetch("net_interface", "get_interfaces")
        results = data.get("items", []) if isinstance(data, dict) else []
        provenance = self._provenance()
        interfaces: list[NormalizedInterface] = []
        for entry in results:
            name = entry.get("fullPath") or entry.get("name")
            if not name:
                continue
            enabled = entry.get("enabled", True) and not entry.get("disabled", False)
            admin = InterfaceAdminStatus.UP if enabled else InterfaceAdminStatus.DOWN
            status = str(entry.get("status", "")).lower()
            if status in ("up", "enabled"):
                oper = InterfaceOperStatus.UP
            elif status in ("down", "disabled", "missing"):
                oper = InterfaceOperStatus.DOWN
            else:
                oper = InterfaceOperStatus.UNKNOWN
            mac = entry.get("macAddress")
            if mac in ("none", "", "00:00:00:00:00:00"):
                mac = None
            mtu = entry.get("mtu")
            interfaces.append(
                NormalizedInterface(
                    **provenance,
                    name=name,
                    admin_status=admin,
                    oper_status=oper,
                    mac_address=mac,
                    mtu=int(mtu) if isinstance(mtu, int) and mtu >= 1 else None,
                )
            )
        return interfaces


# ---------------------------------------------------------------------------
# ROUTES (static routes + self-IP connected routes; route domains -> vrf)
# ---------------------------------------------------------------------------


class F5Routes(_F5Capability, RoutesCapability):
    """``ROUTES``: net/route (static) + net/self (connected); route domains -> ``vrf`` (§5)."""

    def get_routes(self) -> list[NormalizedRoute]:
        provenance = self._provenance()
        routes: list[NormalizedRoute] = []
        routes.extend(self._static_routes(provenance))
        routes.extend(self._connected_routes(provenance))
        return routes

    def _static_routes(self, provenance: dict[str, Any]) -> list[NormalizedRoute]:
        data = self._fetch("net_route", "get_routes")
        results = data.get("items", []) if isinstance(data, dict) else []
        routes: list[NormalizedRoute] = []
        for entry in results:
            network_raw = entry.get("network")
            if not network_raw:
                continue
            net_clean, vrf = _split_route_domain(str(network_raw))
            # F5 renders a default route as "default" / "default-inet6".
            if net_clean in ("default", "0.0.0.0/0"):
                net_clean = "0.0.0.0/0"
            elif net_clean in ("default-inet6", "::/0"):
                net_clean = "::/0"
            try:
                destination = ip_network(net_clean, strict=False)
            except ValueError:
                continue
            next_hop = None
            gw = entry.get("gw")
            if gw:
                gw_clean, _ = _split_route_domain(str(gw))
                with contextlib.suppress(ValueError):
                    next_hop = ip_address(gw_clean)
            routes.append(
                NormalizedRoute(
                    **provenance,
                    destination=destination,
                    protocol=RouteProtocol.STATIC,
                    next_hop=next_hop,
                    vrf=vrf,
                )
            )
        return routes

    def _connected_routes(self, provenance: dict[str, Any]) -> list[NormalizedRoute]:
        data = self._fetch("net_self", "get_selfips")
        results = data.get("items", []) if isinstance(data, dict) else []
        routes: list[NormalizedRoute] = []
        for entry in results:
            address_raw = entry.get("address")
            if not address_raw:
                continue
            addr_clean, vrf = _split_route_domain(str(address_raw))
            try:
                iface = ip_interface(addr_clean)
            except ValueError:
                continue
            routes.append(
                NormalizedRoute(
                    **provenance,
                    destination=iface.network,
                    protocol=RouteProtocol.CONNECTED,
                    interface=entry.get("vlan") or None,
                    vrf=vrf,
                )
            )
        return routes


# ---------------------------------------------------------------------------
# ADC_SERVICES (virtual servers + pools with nested members)
# ---------------------------------------------------------------------------


class F5Services(_F5Capability, AdcServicesCapability):
    """``ADC_SERVICES``: ltm/virtual + ltm/pool (expandSubcollections) -> VIPs/pools (§4)."""

    def get_virtual_servers(self) -> list[NormalizedVirtualServer]:
        items = self._fetch_pages("ltm_virtual", self._client.get_virtuals())
        provenance = self._provenance()
        virtuals: list[NormalizedVirtualServer] = []
        for entry in items:
            name = entry.get("fullPath") or entry.get("name")
            if not name:
                continue
            address, port, vrf = _parse_virtual_destination(str(entry.get("destination", "")))
            enabled = bool(entry.get("enabled", not entry.get("disabled", False)))
            availability = AdcAvailability.DISABLED if not enabled else AdcAvailability.UNKNOWN
            virtuals.append(
                NormalizedVirtualServer(
                    **provenance,
                    name=name,
                    vip_address=address,
                    port=port,
                    protocol=_map_protocol(entry.get("ipProtocol")),
                    vrf=vrf,
                    enabled=enabled,
                    availability=availability,
                    pool_name=entry.get("pool") or None,
                    description=entry.get("description") or None,
                )
            )
        return virtuals

    def get_pools(self) -> list[NormalizedPool]:
        items = self._fetch_pages("ltm_pool", self._client.get_pools())
        provenance = self._provenance()
        pools: list[NormalizedPool] = []
        for entry in items:
            name = entry.get("fullPath") or entry.get("name")
            if not name:
                continue
            members = _parse_members(entry)
            pools.append(
                NormalizedPool(
                    **provenance,
                    name=name,
                    monitors=_parse_monitors(entry.get("monitor")),
                    availability=_pool_availability(members),
                    members=members,
                    description=entry.get("description") or None,
                )
            )
        return pools


def _parse_monitors(monitor: str | None) -> tuple[str, ...]:
    """Parse the F5 pool ``monitor`` string (``/Common/http and /Common/tcp``)."""
    if not monitor:
        return ()
    parts = [p.strip() for p in monitor.replace(" and ", " ").split(" ")]
    return tuple(p for p in parts if p and p not in ("min", "of", "{", "}"))


def _pool_availability(members: tuple[NormalizedPoolMember, ...]) -> AdcAvailability:
    """Derive pool availability from member health (cmdb carries no pool /stats)."""
    if not members:
        return AdcAvailability.UNKNOWN
    if any(m.availability == AdcAvailability.AVAILABLE for m in members):
        return AdcAvailability.AVAILABLE
    if all(m.availability == AdcAvailability.OFFLINE for m in members):
        return AdcAvailability.OFFLINE
    return AdcAvailability.UNKNOWN


def _parse_members(pool: dict[str, Any]) -> tuple[NormalizedPoolMember, ...]:
    """Parse the expanded ``membersReference.items`` of a pool (ADR-0050 §4.5)."""
    ref = pool.get("membersReference")
    raw_members = ref.get("items", []) if isinstance(ref, dict) else []
    members: list[NormalizedPoolMember] = []
    for m in raw_members:
        if not isinstance(m, dict):
            continue
        name = m.get("fullPath") or m.get("name")
        if not name:
            continue
        # Port from the member name suffix (v4 ``:80`` / v6 ``.80``).
        _, port = _split_host_port(str(name))
        fqdn_obj = m.get("fqdn")
        fqdn = None
        if isinstance(fqdn_obj, dict):
            fqdn_name = fqdn_obj.get("tmName") or fqdn_obj.get("name")
            if fqdn_name and fqdn_name not in ("none", ""):
                fqdn = fqdn_name
        address = None
        vrf = None
        raw_addr = m.get("address")
        if raw_addr and raw_addr not in ("any", "any6", "::", "0.0.0.0"):
            addr_clean, vrf = _split_route_domain(str(raw_addr))
            with contextlib.suppress(ValueError):
                address = ip_address(addr_clean)
        members.append(
            NormalizedPoolMember(
                name=name,
                address=address,
                fqdn=fqdn,
                port=port if port is not None else 0,
                vrf=vrf,
                admin_state=_map_member_session(m.get("session")),
                availability=_map_member_state(m.get("state")),
            )
        )
    return tuple(members)


# ---------------------------------------------------------------------------
# HA_STATUS (DSC failover + sync)
# ---------------------------------------------------------------------------

_HA_ROLE_MAP: Mapping[str, HaPeerRole] = {
    "active": HaPeerRole.ACTIVE,
    "standby": HaPeerRole.STANDBY,
}


class F5HaStatus(_F5Capability, HaStatusCapability):
    """``HA_STATUS``: cm/failover-status + cm/sync-status -> DSC state (ADR-0050 §6)."""

    def get_ha_status(self) -> list[NormalizedHaStatus]:
        failover = self._fetch("cm_failover_status", "get_failover_status")
        sync = self._fetch("cm_sync_status", "get_sync_status")
        provenance = self._provenance()

        fo_entries = _nested_first_entries(failover)
        sync_entries = _nested_first_entries(sync)

        fo_status = (_entry_description(fo_entries, "status") or "").strip().lower()

        sync_status = (_entry_description(sync_entries, "status") or "").strip()
        sync_mode = (_entry_description(sync_entries, "mode") or "").strip().lower()
        standalone = sync_mode == "standalone" or sync_status.lower() == "standalone"

        # A standalone (non-DSC) BIG-IP has no peer: report UNKNOWN, empty-not-error
        # (ADR-0050 §6). Only a clustered device carries an ACTIVE/STANDBY role.
        peer_role = (
            HaPeerRole.UNKNOWN if standalone else _HA_ROLE_MAP.get(fo_status, HaPeerRole.UNKNOWN)
        )

        consistency: bool | None
        if standalone:
            consistency = None
        elif sync_status.lower() in ("in sync", "insync"):
            consistency = True
        else:
            consistency = False

        if standalone or peer_role is HaPeerRole.UNKNOWN:
            link = HaPeerLinkState.UNKNOWN
        else:
            link = HaPeerLinkState.UP

        ha_domain = _entry_description(sync_entries, "summary") if not standalone else None

        return [
            NormalizedHaStatus(
                **provenance,
                ha_domain=ha_domain,
                peer_role=peer_role,
                peer_link_state=link,
                keepalive_state=link,
                consistency_check_ok=consistency,
            )
        ]


# ---------------------------------------------------------------------------
# CONFIG_BACKUP_ARCHIVE (UCS) — read, secret-bearing (ADR-0050 §7.2/§7.5)
# ---------------------------------------------------------------------------


def _archive_name() -> str:
    return f"netops-{uuid.uuid4().hex}.ucs"


class F5ConfigArchiveBackup(_F5Capability, ConfigArchiveBackupCapability):
    """``CONFIG_BACKUP_ARCHIVE``: create + download a passphrase-encrypted UCS (ADR-0050 §7.2)."""

    def fetch_config_archive(self) -> ConfigArchive:
        vault = self._require_vault()
        passphrase_ref, passphrase = vault.issue_passphrase()
        name = _archive_name()
        # 1. Save on-box, passphrase-encrypted BEFORE it crosses the wire. The
        #    save exchange carries the passphrase in its body — record the JSON
        #    STATUS the client returns (it carries no passphrase), never the request.
        self._record_raw("f5_bigip:ucs_save", self._client.save_ucs(name, passphrase))
        # 2. Download the binary (NOT a raw artifact — opaque secret material).
        content = self._client.download_ucs(name)
        # 3. Best-effort delete the on-box residue (non-fatal, ADR-0050 §7.2).
        try:
            self._record_raw("f5_bigip:ucs_delete", self._client.delete_ucs(name))
        except PluginError:
            self._record_raw("f5_bigip:ucs_delete", '{"status":"delete_failed_nonfatal"}')
        sha256 = hashlib.sha256(content).hexdigest()
        return ConfigArchive(
            format=_ARCHIVE_FORMAT,
            content=SecretBytes(content),
            sha256=sha256,
            size_bytes=len(content),
            passphrase_ref=passphrase_ref,
        )


# ---------------------------------------------------------------------------
# CONFIG_RESTORE_ARCHIVE (UCS) — CR-gated, baseline-first, never-silent (§7.4)
# ---------------------------------------------------------------------------


class F5ConfigArchiveRestore(_F5Capability, ConfigArchiveRestoreCapability):
    """``CONFIG_RESTORE_ARCHIVE``: CR-gated UCS restore with baseline rollback (ADR-0050 §7.4).

    Refuses (typed :class:`PluginError`) unless the :class:`ChangePlan` attests an
    ``executing`` CR — **before any device call**. Sequence: capture a fresh
    pre-change baseline UCS (the rollback artifact) -> upload+load the target ->
    verify-after (reachability + HA-not-degraded) -> on failure load the baseline
    and verify; ``rollback_failed`` is surfaced, never reported as ``rolled_back``
    (ADR-0021 never-silent). The :class:`ChangeResult` carries metadata only —
    never archive contents (ADR-0050 §7.4).
    """

    def restore_archive(self, archive: ConfigArchiveRef, *, plan: ChangePlan) -> ChangeResult:
        # NEVER self-authorize: refuse before ANY device call (ADR-0050 §7.4).
        if not plan.is_executing:
            raise PluginError(
                "f5_bigip: archive restore refused — the ChangePlan does not attest an "
                f"executing ChangeRequest (cr_state={plan.cr_state!r}); a restore requires a "
                "four-eyes-approved CR (ADR-0021/ADR-0050 §7.4)"
            )
        vault = self._require_vault()

        # 1. Capture a fresh pre-change baseline UCS (the rollback artifact). Kept
        #    on-box under its own name so the rollback can load it.
        baseline_ref, baseline_pass = vault.issue_passphrase()
        baseline_name = _archive_name()
        self._record_raw(
            "f5_bigip:baseline_ucs_save", self._client.save_ucs(baseline_name, baseline_pass)
        )
        baseline_content = self._client.download_ucs(baseline_name)
        baseline_sha = hashlib.sha256(baseline_content).hexdigest()

        # 2. Upload + load the target archive under its vault-materialized passphrase.
        target_pass = vault.materialize_passphrase(archive.passphrase_ref)
        target_name = _archive_name()
        self._record_raw(
            "f5_bigip:target_ucs_upload",
            self._client.upload_ucs(target_name, archive.content.get_secret_value()),
        )
        self._record_raw(
            "f5_bigip:target_ucs_load", self._client.load_ucs(target_name, target_pass)
        )

        applied_diff = (
            "archive loaded",
            f"target_sha256={archive.sha256}",
            f"baseline_archive_id={baseline_ref}",
            f"baseline_sha256={baseline_sha}",
        )

        # 3. Verify-after (reachability + HA-not-degraded, ADR-0050 §7.4).
        if self._verify():
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.APPLIED,
                verified=True,
                applied_diff=applied_diff,
                rollback=None,
            )

        # 4. Verify failed -> load the baseline (rollback) and verify IT.
        with contextlib.suppress(PluginError):
            self._record_raw(
                "f5_bigip:baseline_ucs_load",
                self._client.load_ucs(baseline_name, baseline_pass),
            )
        rolled_back_ok = self._verify()
        rollback = RollbackResult(
            attempted=True,
            succeeded=rolled_back_ok,
            verified=rolled_back_ok,
            detail=(
                "baseline UCS reloaded; management reachable and HA not degraded"
                if rolled_back_ok
                else "baseline reload did not restore a reachable/healthy device"
            ),
        )
        outcome = ChangeOutcome.ROLLED_BACK if rolled_back_ok else ChangeOutcome.ROLLBACK_FAILED
        return ChangeResult(
            change_request_id=plan.change_request_id,
            outcome=outcome,
            verified=False,
            applied_diff=applied_diff,
            rollback=rollback,
        )

    def _verify(self) -> bool:
        """Reachability + HA-not-degraded verify predicate (ADR-0050 §7.4).

        Byte-equality verify-after is impossible for UCS (saves are not
        byte-stable), so the predicate is: the management API is reachable
        (``sys/version`` returns) AND DSC failover status is reachable and not a
        degraded/offline color. Identity-vs-archive-metadata is deferred to the
        live lab (the persisted ref carries only sha256/format, not hostname).
        """
        try:
            self._fetch("verify_version", "get_version")
            failover = self._fetch("verify_failover", "get_failover_status")
        except PluginError:
            return False
        entries = _nested_first_entries(failover)
        color = (_entry_description(entries, "color") or "").strip().lower()
        return color not in ("red", "black")


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


class F5BigipPlugin(VendorPlugin):
    """F5 BIG-IP (``vendor_id="f5_bigip"``) — iControl REST ADC plugin (ADR-0050).

    Declares seven capabilities: ``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``,
    the new ``ADC_SERVICES``, ``HA_STATUS``, and the new binary config-archive
    pair ``CONFIG_BACKUP_ARCHIVE`` / ``CONFIG_RESTORE_ARCHIVE``. The first ADC
    vendor in the platform (ADR-0050 §4.6); text drift and AFM are named
    deferrals (ADR-0050 §7.6).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "F5 BIG-IP"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_API,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.ADC_SERVICES,
            Capability.HA_STATUS,
            Capability.CONFIG_BACKUP_ARCHIVE,
            Capability.CONFIG_RESTORE_ARCHIVE,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_API: F5DiscoveryApi,
            Capability.INTERFACES: F5Interfaces,
            Capability.ROUTES: F5Routes,
            Capability.ADC_SERVICES: F5Services,
            Capability.HA_STATUS: F5HaStatus,
            Capability.CONFIG_BACKUP_ARCHIVE: F5ConfigArchiveBackup,
            Capability.CONFIG_RESTORE_ARCHIVE: F5ConfigArchiveRestore,
        }
