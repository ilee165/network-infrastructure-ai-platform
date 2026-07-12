"""Juniper JunOS plugin: capability implementations over a ``CommandTransport`` (ADR-0026).

Structured-output strategy
---------------------------
JunOS CLI ships a first-class ``| display json`` modifier so every capability
reads structured JSON over the existing netmiko session — no PyEZ / ncclient /
lxml (ADR-0026 §2: "stay within ADR-0007's one-library-per-family rule, add no
new dependency").  Raw-first recording is preserved: each capability records the
verbatim ``| display json`` (or ``| display set``) response to ``raw_artifacts``
via :meth:`~app.plugins.base.PluginCapability._record_raw` **before** parsing.

Config write path (ADR-0026 §3 / ADR-0021)
--------------------------------------------
``CONFIG_RESTORE`` and ``CONFIG_DEPLOY`` bind to JunOS native candidate-config
transactions:

- **Capture-before**: ``show configuration | display set`` (verbatim snapshot).
- **Apply**: ``load override`` (restore) / ``load merge`` (deploy) into the
  **candidate** → ``commit confirmed <N>`` (dead-man auto-revert).
- **Verify-after**: re-capture ``| display set``, assert normalized equality.
- **Confirm**: on success → confirming ``commit``; on failure → ``rollback N``
  + re-capture equality assert (ADR-0021 §3 structured-rollback contract).

JunOS is the **strongest commit-confirm platform** in the matrix: ``commit confirmed``
fires the dead-man revert natively and unconditionally — no EEM scripting, no
management-path guardrail (ADR-0026 §3.1: "closes, by construction, the single
highest-blast-radius hole ADR-0021 had to special-case for classic IOS").  The
management-path guardrail (ADR-0021 §4.2) that ``cisco_ios`` and ``eos`` carry is
**not applied** here: the device auto-reverts at the ``commit confirmed`` timeout
even if the worker dies, so a mid-apply reachability loss cannot strand the device.

The ``CONFIG_RESTORE``/``CONFIG_DEPLOY`` capabilities model the JunOS transaction
over the :class:`~app.plugins.base.ConfigWriteTransport` protocol:

- ``send_config(lines)`` → ``load merge`` of the lines into the candidate, then
  ``commit confirmed <N>`` → confirm (deploy path: additive merge).
- ``replace_config(lines)`` → ``load override`` of the lines into the candidate,
  then ``commit confirmed <N>`` → confirm (restore + rollback path: full replace).
- ``send_command("show configuration | display set")`` → captures the current
  committed configuration in set-form for baseline / verify-after.

Command strings live in module-level ``SHOW_*``/``CMD_*`` constants — the single
source of command text for this plugin (REPO-STRUCTURE §6 step 7).
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
    InterfacesCapability,
    NeighborsCapability,
    OspfCapability,
    PluginCapability,
    RollbackResult,
    RoutesCapability,
    SnmpReadTransport,
    VendorPlugin,
)
from app.plugins.vendors.cli_common import CliConfigWriteMixin
from app.plugins.vendors.junos import parsers
from app.plugins.vendors.junos.parsers import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRoute,
)

__all__ = [
    "SHOW_BGP_NEIGHBOR",
    "SHOW_CONFIGURATION_FIREWALL",
    "SHOW_CONFIGURATION_SET",
    "SHOW_INTERFACES",
    "SHOW_LLDP_NEIGHBORS",
    "SHOW_OSPF_NEIGHBOR",
    "SHOW_ROUTE",
    "SHOW_VERSION",
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "JunosAcl",
    "JunosBgp",
    "JunosConfigBackup",
    "JunosConfigDeploy",
    "JunosConfigRestore",
    "JunosDiscoverySnmp",
    "JunosDiscoverySsh",
    "JunosInterfaces",
    "JunosNeighbors",
    "JunosOspf",
    "JunosPlugin",
    "JunosRoutes",
]

VENDOR_ID = "junos"

# ---------------------------------------------------------------------------
# Command strings — single source of truth for this plugin (REPO-STRUCTURE §6).
# ---------------------------------------------------------------------------

#: ``show version | display json`` — device identity (ADR-0026 §1 capability table).
SHOW_VERSION = "show version | display json"
#: ``show interfaces | display json`` — interface inventory.
SHOW_INTERFACES = "show interfaces | display json"
#: ``show route | display json`` — routing table.
SHOW_ROUTE = "show route | display json"
#: ``show lldp neighbors | display json`` — LLDP adjacencies (no CDP on JunOS).
SHOW_LLDP_NEIGHBORS = "show lldp neighbors | display json"
#: ``show bgp neighbor | display json`` — BGP peer sessions.
SHOW_BGP_NEIGHBOR = "show bgp neighbor | display json"
#: ``show ospf neighbor | display json`` — OSPF adjacencies.
SHOW_OSPF_NEIGHBOR = "show ospf neighbor | display json"
#: ``show configuration firewall | display json`` — firewall filter ACL.
SHOW_CONFIGURATION_FIREWALL = "show configuration firewall | display json"
#: ``show configuration | display set`` — config backup (set-form, re-loadable).
SHOW_CONFIGURATION_SET = "show configuration | display set"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


# ---------------------------------------------------------------------------
# Shared read-capability base
# ---------------------------------------------------------------------------


class _JunosCommandCapability(PluginCapability):
    """Shared base: holds the transport/device context and runs commands.

    ``_run`` records every output verbatim (RawOutput) before any parsing —
    the audit hook the M1 discovery runner persists to ``raw_artifacts``.
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


# ---------------------------------------------------------------------------
# Read capabilities
# ---------------------------------------------------------------------------


class JunosDiscoverySsh(_JunosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version | display json`` → :class:`DeviceFacts`."""

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        return parsers.parse_device_facts(output)


class JunosDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Takes an :class:`~app.plugins.base.SnmpReadTransport` (the M1-08
    ``SnmpClient`` in production, fakes in tests). The returned values are
    recorded verbatim as a :class:`~app.plugins.base.RawOutput` — one line
    per OID — before mapping.
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


class JunosInterfaces(_JunosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces | display json`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        return parsers.parse_interfaces(output, device_id=self._device_id, collected_at=self._now())


class JunosRoutes(_JunosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show route | display json`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the routing table."""
        output = self._run(SHOW_ROUTE)
        return parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())


class JunosNeighbors(_JunosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` — LLDP adjacencies only.

    JunOS does not implement CDP; ``get_cdp_neighbors`` satisfies the abstract
    method of :class:`~app.plugins.base.NeighborsCapability` but always returns
    an empty list. The plugin does **not** declare ``Capability.NEIGHBORS_CDP``
    (ADR-0026 §1: "CDP is absent — JunOS does not speak CDP").
    """

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS)
        return parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """JunOS does not support CDP; always returns an empty list."""
        return []


class JunosBgp(_JunosCommandCapability, BgpCapability):
    """``BGP``: ``show bgp neighbor | display json`` → :class:`NormalizedBgpPeer`."""

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize BGP peering sessions."""
        output = self._run(SHOW_BGP_NEIGHBOR)
        return parsers.parse_bgp_peers(output, device_id=self._device_id, collected_at=self._now())


class JunosOspf(_JunosCommandCapability, OspfCapability):
    """``OSPF``: ``show ospf neighbor | display json`` → :class:`NormalizedOspfNeighbor`."""

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize OSPF neighbor adjacencies."""
        output = self._run(SHOW_OSPF_NEIGHBOR)
        return parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class JunosAcl(_JunosCommandCapability, AclCapability):
    """``ACL``: ``show configuration firewall | display json`` → :class:`NormalizedAclEntry`.

    JunOS ACLs are **firewall filters** composed of ordered **terms** (ADR-0026 §1):
    each term is normalized to one ``NormalizedAclEntry`` row. Terms with
    non-permit/deny actions (``count``, ``policer``, etc.) receive ``action=DENY``
    as the lowest-common-denominator approximation; the verbatim raw artifact is the
    authoritative source.
    """

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize firewall filter entries."""
        output = self._run(SHOW_CONFIGURATION_FIREWALL)
        return parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())


class JunosConfigBackup(_JunosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show configuration | display set`` returned verbatim.

    The ``| display set`` form is line-oriented, idempotent to re-apply, and is
    what the restore/deploy path loads (ADR-0026 §1: "CONFIG_BACKUP uses
    ``| display set``"). Hierarchical and JSON forms are display projections;
    the set form is the settable one.
    """

    def fetch_running_config(self) -> str:
        """Return the configuration in set-form exactly as the device emitted it."""
        output = self._run(SHOW_CONFIGURATION_SET)
        if not output.strip():
            raise PluginError(
                f"junos: {SHOW_CONFIGURATION_SET!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


# ---------------------------------------------------------------------------
# Config write path (ADR-0026 §3 / ADR-0021)
# ---------------------------------------------------------------------------

#: Volatile / non-settable JunOS ``show configuration | display set`` header lines.
#: Examples: ``## Last commit: 2026-06-20 12:34:56 UTC by admin``
#:           ``## version 23.1R1.8;``
#: These change between captures (commit timestamp, version) and must be stripped
#: before equality comparison — the JunOS analogue of the IOS ``Current configuration
#: : NNN bytes`` preamble (ADR-0026 §3.2 / ADR-0021 §5).
_VOLATILE_HEADER_RE = re.compile(r"^(?:##\s*Last commit:|##\s*version\s+)")


def _normalize_config(raw_config: str) -> str:
    """Byte-stable normalized form for equality comparison (ADR-0026 §3.2 / ADR-0017 §1).

    Collapses ``\\r\\n``/``\\r`` to ``\\n``, strips trailing per-line whitespace,
    drops volatile/non-settable JunOS ``| display set`` header lines
    (``## Last commit:`` / ``## version ...`` — display artifacts that change on
    every capture and are not valid set commands), and guarantees a single trailing
    newline — so a verify-after / rollback equality reflects a real config difference,
    not display noise. Stripping the headers is also what lets the normalized form be
    re-loaded as configuration (ADR-0026 §3.2 parity with ADR-0017 §1 IOS baseline).
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        line.rstrip() for line in unified.split("\n") if not _VOLATILE_HEADER_RE.match(line.strip())
    ]
    body = "\n".join(lines).strip("\n")
    return f"{body}\n" if body else ""


class _JunosConfigWriteCapability(CliConfigWriteMixin):
    """Shared capture-before -> apply -> verify-after -> rollback engine (ADR-0021 §3).

    Wave 3 T4: inherits :class:`~app.plugins.vendors.cli_common.CliConfigWriteMixin`
    with JunOS Option A overrides:

    - capture via ``show configuration | display set``
    - apply audit labels: load merge / load override + commit confirmed
    - no management-path guardrail (native dead-man)
    - apply-fail: re-assert baseline **without** permanent ``rollback 1``
    - verify-fail: permanent ``rollback_config(1)`` (not another commit confirmed)

    **Tracked gap** (ADR-0026 §3.2.1): unconfirmed window spans apply + verify-after.
    """

    vendor_label: ClassVar[str] = "junos"
    _show_running_command: ClassVar[str] = SHOW_CONFIGURATION_SET

    def _normalize_captured(self, raw: str) -> str:
        return _normalize_config(raw)

    def _capture_config(self) -> str:
        """Alias used by JunOS-specific call sites; same as mixin capture."""
        return self._capture_running()

    def _send_config(self, lines: list[str]) -> None:
        """Merge *lines* into the candidate and commit confirmed (deploy apply surface)."""
        output = self._transport.send_config(lines)
        self._record_raw("load merge + commit confirmed\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Override the candidate with exactly *lines* and commit confirmed."""
        output = self._transport.replace_config(lines)
        self._record_raw("load override + commit confirmed\n" + "\n".join(lines), output)

    def _after_verified(self) -> None:
        """Option A confirming commit (mixin default); keep explicit for clarity."""
        self._transport.confirm_config()

    def _recover_apply_failure(self, baseline_normalized: str) -> RollbackResult:
        """Apply failed before commit confirmed — do not permanent rollback 1."""
        try:
            after = self._normalize_captured(self._capture_running())
        except Exception as exc:  # noqa: BLE001
            return RollbackResult(
                attempted=True,
                succeeded=False,
                verified=False,
                detail=f"post-apply-failure re-capture failed ({type(exc).__name__})",
            )
        equal = after == baseline_normalized
        return RollbackResult(
            attempted=True,
            succeeded=equal,
            verified=equal,
            detail=(
                None
                if equal
                else (
                    "apply failed before commit confirmed but running config no longer "
                    "matches the pre-change baseline"
                )
            ),
        )

    def _rollback_to_baseline(self, baseline_normalized: str) -> RollbackResult:
        """Verify-fail path: permanent ``rollback N`` + ``commit`` (not commit confirmed)."""
        try:
            self._transport.rollback_config(1)
            after = self._normalize_captured(self._capture_running())
        except Exception as exc:  # noqa: BLE001
            return RollbackResult(
                attempted=True,
                succeeded=False,
                verified=False,
                detail=f"rollback N + commit failed ({type(exc).__name__})",
            )
        equal = after == baseline_normalized
        return RollbackResult(
            attempted=True,
            succeeded=equal,
            verified=equal,
            detail=(
                None
                if equal
                else "re-captured config did not normalize equal to the baseline after rollback N"
            ),
        )


class JunosConfigRestore(_JunosConfigWriteCapability, ConfigRestoreCapability):
    """``CONFIG_RESTORE``: replay an existing snapshot via ``load override`` + ``commit confirmed``.

    Apply is a **config override** (``replace_config`` → JunOS ``load override``)
    to the normalized snapshot — the only surface that can re-establish equality with
    the snapshot (a merge cannot remove device-only lines, ADR-0026 §3.2). Idempotent:
    empty diff yields ``NO_OP`` without touching the candidate.

    JunOS volatile ``| display set`` headers (``## Last commit:`` / ``## version ...``)
    are stripped by :func:`_normalize_config` so a changed commit-timestamp header does
    not defeat the equality predicate (ADR-0026 §3.2 / ADR-0021 §5 parity).
    """

    def restore(self, snapshot: ConfigSnapshotRef, *, plan: ChangePlan) -> ChangeResult:
        """Restore the device to *snapshot* as the execution step of *plan*.

        The pre-apply ``commit check`` (ADR-0026 §3.2: "JunOS validates the candidate's
        syntactic/semantic integrity server-side") is modelled by the transport's
        ``replace_config`` preconditions; a hard failure before any committed state is
        surfaced as a :class:`PluginError`. Verify-after asserts re-captured config
        normalizes **equal** to the snapshot (ADR-0021 §3 restore exit criterion).
        """
        target = _normalize_config(snapshot.content)
        return self._execute(
            plan=plan,
            operation="config restore",
            project=lambda _baseline: target,
            config_lines=target.splitlines(),
            apply=self._replace_config,
        )


class JunosConfigDeploy(_JunosConfigWriteCapability, ConfigDeployCapability):
    """``CONFIG_DEPLOY``: merge a config fragment via ``load merge`` + ``commit confirmed``.

    Apply is a **merge** (``send_config`` → JunOS ``load merge``) — additive.
    The deploy verify-after predicate is the strengthened residual-diff check
    (ADR-0021 §3): re-captured config must equal baseline + fragment additions exactly
    — every fragment line present AND no line outside the fragment's scope changed
    unexpectedly. On failure the captured baseline is restored via ``replace_config``
    (JunOS ``rollback N``); rollback success is the asserted baseline equality.

    Best-effort idempotent: re-applying an already-present fragment yields an empty
    pre-apply diff and a ``NO_OP``.
    """

    def deploy(self, config_fragment: str, *, plan: ChangePlan) -> ChangeResult:
        """Apply *config_fragment* as the execution step of *plan*."""
        fragment_lines = [
            line for line in _normalize_config(config_fragment).splitlines() if line.strip()
        ]

        def project(baseline: str) -> str:
            # Intended end-state AND verify-after target: baseline merged with the
            # fragment lines not already present (a merge never removes lines). The
            # deploy post-condition is the re-captured config equals this projection
            # exactly — fragment present AND no unintended residual diff outside the
            # fragment scope (ADR-0021 §3), not mere set-membership.
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


class JunosPlugin(VendorPlugin):
    """Juniper JunOS (``vendor_id="junos"``) — ADR-0026 / P1 Wave-1 plugin.

    Declares the Wave-1 capability set (``PRODUCTION.md`` §2.2): SSH/SNMP discovery,
    interface inventory, route collection, LLDP neighbors, BGP, OSPF, ACL (firewall
    filters → ``NormalizedAclEntry``), config backup, and config restore/deploy.
    CDP is intentionally absent — JunOS does not speak CDP (ADR-0026 §1).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Juniper JunOS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
            Capability.BGP,
            Capability.OSPF,
            Capability.ACL,
            Capability.CONFIG_BACKUP,
            Capability.CONFIG_RESTORE,
            Capability.CONFIG_DEPLOY,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: JunosDiscoverySsh,
            Capability.DISCOVERY_SNMP: JunosDiscoverySnmp,
            Capability.INTERFACES: JunosInterfaces,
            Capability.ROUTES: JunosRoutes,
            Capability.NEIGHBORS_LLDP: JunosNeighbors,
            Capability.BGP: JunosBgp,
            Capability.OSPF: JunosOspf,
            Capability.ACL: JunosAcl,
            Capability.CONFIG_BACKUP: JunosConfigBackup,
            Capability.CONFIG_RESTORE: JunosConfigRestore,
            Capability.CONFIG_DEPLOY: JunosConfigDeploy,
        }
