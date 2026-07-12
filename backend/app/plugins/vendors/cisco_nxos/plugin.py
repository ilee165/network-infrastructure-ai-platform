"""Cisco NX-OS plugin: capability implementations over a ``CommandTransport``.

Mirrors the ``cisco_ios`` reference plugin (ADR-0025), differing only in
NX-OS command text, NX-OS TextFSM templates (``cisco_nxos`` platform key),
VRF-scoped collection, feature-gate tolerance, the new ``HA_STATUS``
capability (vPC), and the ``show vpc | json`` per-command JSON escape hatch.

Command strings live in this module's ``SHOW_*`` constants — the single
source of command text for the plugin (REPO-STRUCTURE §6 step 7).

NX-OS-specific decisions (ADR-0025):
- ``device_type="cisco_nxos"`` (netmiko); SSH is the sole P1 transport.
- Feature-gated capabilities (BGP, OSPF, LLDP) return ``[]`` for disabled
  features — "feature not enabled" normalizes to empty, not error (§4).
- Route/BGP/OSPF use the ``vrf all`` form; each record carries its VRF (§3).
- ``show vpc`` is the one P1 command that applies ``| json`` (§3/§8); HA_STATUS
  is built from the decoded JSON document.
- Config write path reuses the ADR-0021 engine: ``configure replace`` baseline
  replay for rollback, the same tier as ``cisco_ios``. The transport exposes no
  NX-OS named-checkpoint primitive, so rollback is replace-based replay of the
  captured pre-change baseline, not ``rollback running-config checkpoint``.
- Each VDC is a separate inventory device; the plugin operates within the
  session's VDC only (§6).
- NX-API is deferred to P2 (§2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    AclCapability,
    BgpCapability,
    Capability,
    ChangePlan,
    ChangeResult,
    CommandTransport,
    ConfigBackupCapability,
    ConfigDeployCapability,
    ConfigRestoreCapability,
    ConfigSnapshotRef,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    HaStatusCapability,
    InterfacesCapability,
    NeighborsCapability,
    OspfCapability,
    PluginCapability,
    RoutesCapability,
    SnmpReadTransport,
    VendorPlugin,
)
from app.plugins.vendors.cisco_nxos import parsers
from app.plugins.vendors.cisco_nxos.parsers import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)
from app.plugins.vendors.cli_common import CliConfigWriteMixin
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedHaStatus,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRoute,
)

__all__ = [
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "CiscoNxosAcl",
    "CiscoNxosBgp",
    "CiscoNxosConfigBackup",
    "CiscoNxosConfigDeploy",
    "CiscoNxosConfigRestore",
    "CiscoNxosDiscoverySnmp",
    "CiscoNxosDiscoverySsh",
    "CiscoNxosHaStatus",
    "CiscoNxosInterfaces",
    "CiscoNxosNeighbors",
    "CiscoNxosOspf",
    "CiscoNxosPlugin",
    "CiscoNxosRoutes",
]

VENDOR_ID = "cisco_nxos"

# Command text — must match the ntc-templates index entries for cisco_nxos.
SHOW_VERSION = "show version"
SHOW_INTERFACE = "show interface"  # NX-OS uses "show interface" (no trailing 's')
SHOW_IP_ROUTE_VRF_ALL = "show ip route vrf all"
SHOW_CDP_NEIGHBORS_DETAIL = "show cdp neighbors detail"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"
SHOW_IP_BGP_SUMMARY_VRF_ALL = "show ip bgp summary vrf all"
SHOW_IP_OSPF_NEIGHBOR_VRF_ALL = "show ip ospf neighbor vrf all"
SHOW_IP_ACCESS_LISTS = "show ip access-lists"  # maps to ntc "show access-lists"
SHOW_VPC = "show vpc | json"  # §3/§8: the one P1 command that uses the | json hatch

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _CiscoNxosCommandCapability(PluginCapability):
    """Shared base: holds the transport/device context and runs commands.

    ``_run`` records every output verbatim (RawOutput) before any parsing —
    the audit hook the M1 discovery runner persists to ``raw_artifacts``.
    Mirrors ``_CiscoIosCommandCapability`` in cisco_ios/plugin.py.
    """

    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def _run(self, command: str) -> str:
        """Execute *command* and return its output, recorded verbatim."""
        output = self._transport.send_command(command)
        return self._record_raw(command, output)

    @staticmethod
    def _now() -> datetime:
        """Collection instant stamped onto normalized records."""
        return datetime.now(UTC)


class CiscoNxosDiscoverySsh(_CiscoNxosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`."""

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        return parsers.parse_device_facts(output)


class CiscoNxosDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Identical OIDs to ``cisco_ios`` — same :class:`~app.plugins.base.SnmpReadTransport`
    (ADR-0025 §1 table).
    """

    def __init__(self, snmp: SnmpReadTransport, device_id: UUID) -> None:
        super().__init__()
        self._snmp = snmp
        self._device_id = device_id

    def get_device_facts(self) -> DeviceFacts:
        """Query sysDescr/sysObjectID/sysName and map them to device facts."""
        values = self._snmp.get(list(_SNMP_DISCOVERY_OIDS))
        self._record_raw(
            f"SNMP GET {' '.join(_SNMP_DISCOVERY_OIDS)}",
            "\n".join(f"{oid} = {values.get(oid, '')}" for oid in _SNMP_DISCOVERY_OIDS),
        )
        return parsers.parse_snmp_device_facts(values)


class CiscoNxosInterfaces(_CiscoNxosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interface`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACE)
        return parsers.parse_interfaces(output, device_id=self._device_id, collected_at=self._now())


class CiscoNxosRoutes(_CiscoNxosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route vrf all`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize all VRFs' IPv4 routing tables (ADR-0025 §3)."""
        output = self._run(SHOW_IP_ROUTE_VRF_ALL)
        return parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())


class CiscoNxosNeighbors(_CiscoNxosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` + ``NEIGHBORS_CDP`` → :class:`NormalizedNeighbor`.

    LLDP requires ``feature lldp``; if disabled, returns ``[]`` (ADR-0025 §4).
    CDP is on by default on NX-OS.
    """

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies (feature-gate tolerant)."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        return parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize CDP adjacencies."""
        output = self._run(SHOW_CDP_NEIGHBORS_DETAIL)
        return parsers.parse_cdp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class CiscoNxosBgp(_CiscoNxosCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary vrf all`` → :class:`NormalizedBgpPeer`.

    Requires ``feature bgp``; if disabled, returns ``[]`` (ADR-0025 §4).
    Each record carries the VRF from the ``vrf all`` section headers (§3).
    """

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize BGP peering sessions across all VRFs."""
        output = self._run(SHOW_IP_BGP_SUMMARY_VRF_ALL)
        return parsers.parse_bgp_peers(output, device_id=self._device_id, collected_at=self._now())


class CiscoNxosOspf(_CiscoNxosCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor vrf all`` → :class:`NormalizedOspfNeighbor`.

    Requires ``feature ospf``; if disabled, returns ``[]`` (ADR-0025 §4).
    Each record carries the VRF from the section headers (§6).
    """

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize OSPF neighbor adjacencies across all VRFs."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR_VRF_ALL)
        return parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class CiscoNxosAcl(_CiscoNxosCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`.

    NX-OS ntc-templates platform key for this command is ``show access-lists``;
    the parser dispatches to that key internally.
    """

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        return parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())


class CiscoNxosConfigBackup(_CiscoNxosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim."""

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"cisco_nxos: {SHOW_RUNNING_CONFIG!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


class CiscoNxosHaStatus(_CiscoNxosCommandCapability, HaStatusCapability):
    """``HA_STATUS``: ``show vpc`` → :class:`NormalizedHaStatus` (ADR-0025 §8).

    Returns vPC domain role, peer-link state, keepalive state, and consistency
    status as a single :class:`NormalizedHaStatus` record. Returns ``[]`` when
    vPC is not configured or ``feature vpc`` is disabled (§4).
    """

    def get_ha_status(self) -> list[NormalizedHaStatus]:
        """Collect and normalize the vPC HA state."""
        output = self._run(SHOW_VPC)
        return parsers.parse_ha_status(output, device_id=self._device_id, collected_at=self._now())


# ---------------------------------------------------------------------------
# Config write path (ADR-0021 + ADR-0025 §5) — configure-replace baseline replay.
# ---------------------------------------------------------------------------


#: NX-OS ``show running-config`` preamble lines that are volatile display
#: artifacts and must be stripped before equality comparison and config replay.
#: NX-OS does not emit the IOS "Building configuration..." preamble, but
#: it does emit a !Command header and a !Running configuration timestamp.
_VOLATILE_PREAMBLE_RE = re.compile(
    r"^(?:!Command:\s+show\s+running-config|"
    r"!Running\s+configuration\s+last\s+done\s+at:|"
    r"!Time:).*$"
)


def _normalize_config(raw_config: str) -> str:
    """Byte-stable normalized form for equality comparison (ADR-0021 §1).

    Same contract as the ``cisco_ios`` normalizer: collapses ``\\r\\n``/``\\r``
    to ``\\n``, strips trailing per-line whitespace, drops the volatile NX-OS
    preamble (``!Command:`` / ``!Running configuration last done at:`` / ``!Time:``),
    and guarantees a single trailing newline.
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        line.rstrip()
        for line in unified.split("\n")
        if not _VOLATILE_PREAMBLE_RE.match(line.strip())
    ]
    body = "\n".join(lines).strip("\n")
    return f"{body}\n" if body else ""


#: vrf context management interface block header — the NX-OS management VRF.
_VRF_MGMT_RE = re.compile(r"^vrf\s+context\s+management\b", re.IGNORECASE)
#: Interface block header.
_INTERFACE_BLOCK_RE = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
#: Management-class NX-OS interface names (mgmt0 or Vlan/management SVIs).
_MGMT_INTERFACE_NAME_RE = re.compile(
    r"^(?:mgmt\d+|Vlan\d+|Management\d*)$",
    re.IGNORECASE,
)
#: Commands that, in any context, touch the session-carrying management path.
_MGMT_GLOBAL_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^ip\s+route\s+0\.0\.0\.0/0\b", re.IGNORECASE), "management default-route"),
)
#: Within a management-class interface block, commands that can drop reachability.
_MGMT_INTERFACE_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:no\s+)?shutdown\b", re.IGNORECASE), "mgmt interface admin state (shutdown)"),
    (re.compile(r"^ip\s+access-group\b", re.IGNORECASE), "mgmt interface ip access-group"),
    (re.compile(r"^(?:no\s+)?ip\s+address\b", re.IGNORECASE), "mgmt interface ip address"),
)


def _management_path_hits(baseline: str, end_state: str) -> tuple[str, ...]:
    """Reasons the change baseline -> end_state touches the NX-OS management path.

    Mirrors ``cisco_ios._management_path_hits`` with NX-OS specifics: the
    management VRF context block (``vrf context management``) and the mgmt0
    interface are the NX-OS management-path equivalents of the IOS
    ``line vty`` / mgmt interface pattern. Only lines in the delta are flagged.

    For removals the scan walks the **full baseline** (not just the removed
    lines) so that unchanged parent section headers (e.g. ``interface mgmt0``)
    still set the in_mgmt_interface / in_mgmt_vrf context before any removed
    child line is evaluated.  A line is flagged only when it is absent from
    end_state (i.e. it is actually removed); unchanged lines are skipped as
    context providers.
    """
    end_set = set(end_state.splitlines())
    end_lines = end_state.splitlines()
    baseline_lines = baseline.splitlines()

    hits: list[str] = []
    baseline_set = set(baseline_lines)
    # First pass: end_state lines — flag additions (lines not in baseline).
    # Second pass: full baseline lines — flag removals (lines not in end_state),
    # while still tracking section-header context from unchanged headers.
    for sequence, changed_against in ((end_lines, baseline_set), (baseline_lines, end_set)):
        in_mgmt_interface = False
        in_mgmt_vrf = False
        for raw in sequence:
            line = raw.strip()
            if not line:
                continue
            indented = raw[:1].isspace()
            interface_match = _INTERFACE_BLOCK_RE.match(line)
            if not indented:
                in_mgmt_vrf = bool(_VRF_MGMT_RE.match(line))
                in_mgmt_interface = bool(
                    interface_match and _MGMT_INTERFACE_NAME_RE.match(interface_match.group(1))
                )
            if raw in changed_against:
                continue  # unchanged line; context only
            for pattern, reason in _MGMT_GLOBAL_RES:
                if pattern.match(line):
                    hits.append(reason)
            if in_mgmt_interface or in_mgmt_vrf:
                for pattern, reason in _MGMT_INTERFACE_RES:
                    if pattern.match(line):
                        hits.append(reason)
    seen: dict[str, None] = {}
    for hit in hits:
        seen.setdefault(hit, None)
    return tuple(seen)


class _CiscoNxosConfigWriteCapability(CliConfigWriteMixin):
    """Capture-before -> apply -> verify-after -> rollback engine (ADR-0021/0025 §5).

    Wave 3 T4: inherits :class:`~app.plugins.vendors.cli_common.CliConfigWriteMixin`.
    NX-OS keeps management-path guardrail as defence-in-depth (ADR-0025 §5);
    rollback remains configure-replace of the captured baseline (no named
    checkpoint surface on ConfigWriteTransport).
    """

    vendor_label: ClassVar[str] = "cisco_nxos"
    _show_running_command: ClassVar[str] = SHOW_RUNNING_CONFIG

    def _normalize_captured(self, raw: str) -> str:
        return _normalize_config(raw)

    def _reject_management_path(self, operation: str, baseline: str, end_state: str) -> None:
        """Refuse a change that touches the NX-OS management path (ADR-0021 §4.2 / ADR-0025 §5).

        On NX-OS the ``configure replace ... commit-timeout`` dead-man timer
        is available, but the management-path guardrail is still implemented
        as defence-in-depth: a change touching the mgmt VRF / mgmt0 interface
        is rejected here because a connectivity-severing change can strand the
        worker mid-apply before the rollback fires (ADR-0025 §5).
        """
        offending = _management_path_hits(baseline, end_state)
        if offending:
            raise PluginError(
                f"cisco_nxos: {operation} refused — change touches the management path "
                f"({', '.join(offending)}). The management-path guardrail (ADR-0021 §4.2 / "
                "ADR-0025 §5) is defence-in-depth: even though NX-OS has a "
                "configure-replace commit-timeout, a mid-apply reachability loss can "
                "strand the worker before the rollback fires. Use a console/OOB-fallback "
                "path for management-plane changes."
            )


class CiscoNxosConfigRestore(_CiscoNxosConfigWriteCapability, ConfigRestoreCapability):
    """``CONFIG_RESTORE``: replay an existing config snapshot (ADR-0021 / ADR-0025 §5).

    Idempotent: when the live config already normalizes equal to the snapshot
    the pre-apply diff is empty and the device is never touched (``NO_OP``).
    Otherwise the snapshot text is replayed via ``configure replace`` and
    verify-after asserts the running config normalizes **equal** to the snapshot.
    """

    def restore(self, snapshot: ConfigSnapshotRef, *, plan: ChangePlan) -> ChangeResult:
        """Restore the device to *snapshot* as the execution step of *plan*."""
        target = _normalize_config(snapshot.content)

        return self._execute(
            plan=plan,
            operation="config restore",
            project=lambda _baseline: target,
            config_lines=target.splitlines(),
            apply=self._replace_config,
        )


class CiscoNxosConfigDeploy(_CiscoNxosConfigWriteCapability, ConfigDeployCapability):
    """``CONFIG_DEPLOY``: merge a supplied config fragment (ADR-0021 / ADR-0025 §5)."""

    def deploy(self, config_fragment: str, *, plan: ChangePlan) -> ChangeResult:
        """Apply *config_fragment* as the execution step of *plan*."""
        fragment_lines = [
            line for line in _normalize_config(config_fragment).splitlines() if line.strip()
        ]

        def project(baseline: str) -> str:
            present = set(baseline.splitlines())
            additions = [line for line in fragment_lines if line not in present]
            body = baseline.rstrip("\n")
            if additions:
                body = body + "\n" + "\n".join(additions)
            return f"{body}\n" if body else ""

        return self._execute(
            plan=plan,
            operation="config deploy",
            project=project,
            config_lines=fragment_lines,
            apply=self._send_config,
        )


class CiscoNxosPlugin(VendorPlugin):
    """Cisco NX-OS (``vendor_id="cisco_nxos"``) — P1 W1 plugin (ADR-0025).

    Declares the full Wave-0 capability set plus ``HA_STATUS`` (vPC),
    mirroring ``cisco_ios`` with NX-OS command text, NX-OS ntc-templates
    parsing, VRF-scoped collection, feature-gate tolerance, the
    ``show vpc | json`` escape hatch, and the configure-replace baseline-replay
    config write path (same tier as ``cisco_ios``; ADR-0025 §1).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Cisco NX-OS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
            Capability.NEIGHBORS_CDP,
            Capability.BGP,
            Capability.OSPF,
            Capability.ACL,
            Capability.CONFIG_BACKUP,
            Capability.CONFIG_RESTORE,
            Capability.CONFIG_DEPLOY,
            Capability.HA_STATUS,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: CiscoNxosDiscoverySsh,
            Capability.DISCOVERY_SNMP: CiscoNxosDiscoverySnmp,
            Capability.INTERFACES: CiscoNxosInterfaces,
            Capability.ROUTES: CiscoNxosRoutes,
            Capability.NEIGHBORS_LLDP: CiscoNxosNeighbors,
            Capability.NEIGHBORS_CDP: CiscoNxosNeighbors,
            Capability.BGP: CiscoNxosBgp,
            Capability.OSPF: CiscoNxosOspf,
            Capability.ACL: CiscoNxosAcl,
            Capability.CONFIG_BACKUP: CiscoNxosConfigBackup,
            Capability.CONFIG_RESTORE: CiscoNxosConfigRestore,
            Capability.CONFIG_DEPLOY: CiscoNxosConfigDeploy,
            Capability.HA_STATUS: CiscoNxosHaStatus,
        }
