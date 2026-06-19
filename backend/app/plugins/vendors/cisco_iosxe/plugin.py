"""Cisco IOS-XE plugin: capability implementations over a ``CommandTransport``.

IOS-XE (Cat9k, CSR1000v, ISR4000, etc.) shares the same CLI show-command
syntax and ntc-templates parsing as classic IOS (ADR-0007: both use the
``cisco_ios`` platform key).  Rather than duplicating parsers, this module
imports the shared cisco_ios parser functions directly and wraps them in
IOS-XE-specific capability classes whose ``source_vendor`` is ``cisco_iosxe``.

The netmiko ``device_type`` for IOS-XE is ``cisco_xe``.

Command strings are the same as cisco_ios; they are redeclared here as the
single source of command text for this plugin (REPO-STRUCTURE §6 step 7).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    AclCapability,
    BgpCapability,
    Capability,
    ChangeOutcome,
    ChangePlan,
    ChangeResult,
    CommandTransport,
    ConfigBackupCapability,
    ConfigDeployCapability,
    ConfigRestoreCapability,
    ConfigSnapshotRef,
    ConfigWriteTransport,
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

# Re-use cisco_ios parsers: IOS-XE show output is parsed with the same
# ntc-templates platform key ("cisco_ios").  Only source_vendor changes.
from app.plugins.vendors.cisco_ios import parsers as _ios_parsers
from app.plugins.vendors.cisco_ios.parsers import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)

# Re-use the cisco_ios management-path detector (the regex machinery is the
# single source of truth, ADR-0021 §4.2). IOS-XE shares the IOS config syntax,
# so the same delta-scoped scan applies unchanged.
from app.plugins.vendors.cisco_ios.plugin import _management_path_hits
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
    "SHOW_IP_ACCESS_LISTS",
    "SHOW_IP_BGP_SUMMARY",
    "SHOW_IP_OSPF_NEIGHBOR",
    "SHOW_RUNNING_CONFIG",
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "CiscoIosXeAcl",
    "CiscoIosXeBgp",
    "CiscoIosXeConfigBackup",
    "CiscoIosXeConfigDeploy",
    "CiscoIosXeConfigRestore",
    "CiscoIosXeDiscoverySnmp",
    "CiscoIosXeDiscoverySsh",
    "CiscoIosXeInterfaces",
    "CiscoIosXeNeighbors",
    "CiscoIosXeOspf",
    "CiscoIosXePlugin",
    "CiscoIosXeRoutes",
]

VENDOR_ID = "cisco_iosxe"

# Command text — ntc-templates index entries for cisco_ios cover IOS-XE output.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_CDP_NEIGHBORS_DETAIL = "show cdp neighbors detail"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"
SHOW_IP_BGP_SUMMARY = "show ip bgp summary"
SHOW_IP_OSPF_NEIGHBOR = "show ip ospf neighbor"
SHOW_IP_ACCESS_LISTS = "show ip access-lists"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _CiscoIosXeCommandCapability(PluginCapability):
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


class CiscoIosXeDiscoverySsh(_CiscoIosXeCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`.

    Delegates parsing to the shared cisco_ios parser (same template),
    then overwrites ``vendor_id`` to ``cisco_iosxe``.
    """

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        facts = _ios_parsers.parse_device_facts(output)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class CiscoIosXeDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Delegates to the shared cisco_ios SNMP parser then stamps
    ``vendor_id = cisco_iosxe``.
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
        facts = _ios_parsers.parse_snmp_device_facts(values)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class CiscoIosXeInterfaces(_CiscoIosXeCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        records = _ios_parsers.parse_interfaces(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeRoutes(_CiscoIosXeCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        records = _ios_parsers.parse_routes(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeNeighbors(_CiscoIosXeCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` + ``NEIGHBORS_CDP`` → :class:`NormalizedNeighbor`."""

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        records = _ios_parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize CDP adjacencies."""
        output = self._run(SHOW_CDP_NEIGHBORS_DETAIL)
        records = _ios_parsers.parse_cdp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeConfigBackup(_CiscoIosXeCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim."""

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"cisco_iosxe: {SHOW_RUNNING_CONFIG!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


# ---------------------------------------------------------------------------
# Config write path (ADR-0021) — IOS-XE transactional config replace
# ---------------------------------------------------------------------------

#: Volatile / non-settable IOS-XE ``show running-config`` preamble lines.
#: Identical format to classic IOS; stripped before equality comparison and
#: before replaying as configuration (ADR-0021 §4/§5).
_VOLATILE_PREAMBLE_RE = re.compile(
    r"^(?:Building configuration\.\.\.|Current configuration\s*:.*)$"
)


def _normalize_config(raw_config: str) -> str:
    """Byte-stable normalized form for equality comparison (ADR-0021 §4/§5).

    Collapses ``\\r\\n``/``\\r`` to ``\\n``, strips trailing per-line whitespace,
    drops the volatile IOS-XE preamble (``Building configuration...`` /
    ``Current configuration : NNN bytes``), and guarantees a single trailing
    newline — so verify-after equality reflects a real config difference, not
    transport noise or a volatile header byte count.
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        line.rstrip()
        for line in unified.split("\n")
        if not _VOLATILE_PREAMBLE_RE.match(line.strip())
    ]
    body = "\n".join(lines).strip("\n")
    return f"{body}\n" if body else ""


class _CiscoIosXeConfigWriteCapability(PluginCapability):
    """Shared capture-before -> apply -> verify-after -> rollback engine (ADR-0021 §3).

    Mirrors :class:`~app.plugins.vendors.cisco_ios.plugin._CiscoIosConfigWriteCapability`
    with IOS-XE differences:

    - **Rollback primitive**: rollback is a ``configure replace`` of the captured
      pre-change baseline. IOS-XE *can* support ``configure replace ... commit-confirm
      <timer>`` (dead-man auto-revert), but the production ``replace_config`` transport
      does NOT arm one — it issues a plain ``configure replace <file> force``. Because
      no dead-man primitive is actually armed, the management-path guardrail
      (ADR-0021 §4.2) **IS applied here** (a change touching the management path is
      refused before any write); relaxing it would require a real commit-confirm
      apply surface that does not yet exist.
    - **Same verify-after and rollback contract**: the re-captured config must normalize
      equal to the intended end-state (apply) or to the captured baseline (rollback);
      ``rollback_failed`` is surfaced when the equality predicate does not hold
      (never silently closed, ADR-0021 §3).
    - **Same apply surfaces**: RESTORE and rollback use ``replace_config``; DEPLOY
      uses ``send_config`` (merge).

    The capability **never self-authorizes**: every entry point first asserts the
    :class:`~app.plugins.base.ChangePlan` attests an ``executing`` CR (ADR-0021 §2).
    """

    def __init__(self, transport: ConfigWriteTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def _capture_running(self) -> str:
        """Capture the live running config verbatim (recorded for audit)."""
        return self._record_raw(
            SHOW_RUNNING_CONFIG, self._transport.send_command(SHOW_RUNNING_CONFIG)
        )

    def _send_config(self, lines: list[str]) -> None:
        """Merge *lines* in config mode (send_config_set); record verbatim output."""
        output = self._transport.send_config(lines)
        self._record_raw("configure terminal\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Replace the running config with exactly *lines* (configure replace).

        IOS-XE native config-replace primitive (ADR-0021 §4): the apply surface
        for ``CONFIG_RESTORE`` and the rollback surface for both operations. The
        production ``SshTransport.replace_config`` issues a plain ``configure
        replace <file> force`` — it does NOT arm a ``commit-confirm`` /
        rollback-timer dead-man revert, so this path provides no device-side
        auto-revert (see :meth:`_reject_management_path`). Records the verbatim
        device output for audit.
        """
        output = self._transport.replace_config(lines)
        self._record_raw("configure replace\n" + "\n".join(lines), output)

    def _reject_management_path(self, operation: str, baseline: str, end_state: str) -> None:
        """Refuse a change that touches the management path (ADR-0021 §4.2).

        ADR-0021 §4 sanctions relaxing this guardrail on IOS-XE ONLY when the
        executor arms a device-side dead-man auto-revert (``configure replace ...
        commit <timer>``) so a connectivity-severing change reverts even if the
        worker loses the session. No production transport implements that
        primitive — :meth:`app.plugins.transport.ssh.SshTransport.replace_config`
        issues a plain ``configure replace <file> force`` with no commit timer —
        so the compensating control does not exist. Until it does, IOS-XE is an
        image *without* a dead-man primitive (§4 sub-bullet 2): a change touching
        the management path is **rejected**, with a typed :class:`PluginError` and
        before any device write, rather than silently stranding the device with no
        replay path. The change is the delta baseline -> end_state.
        """
        offending = _management_path_hits(baseline, end_state)
        if offending:
            raise PluginError(
                f"cisco_iosxe: {operation} refused — change touches the management path "
                f"({', '.join(offending)}) and no armed dead-man auto-revert "
                "(commit-confirm timer) is implemented by the transport; a mid-apply "
                "reachability loss would strand the device with no replay path "
                "(ADR-0021 §4.2: management-path guardrail). Out of M5 scope until a "
                "commit-confirm apply surface exists — use a console/OOB-fallback path."
            )

    @staticmethod
    def _require_executing(plan: ChangePlan, operation: str) -> None:
        """Refuse the write unless the plan attests an ``executing`` CR (§2)."""
        if not plan.is_executing:
            raise PluginError(
                f"cisco_iosxe: {operation} refused — change request "
                f"'{plan.change_request_id}' is '{plan.cr_state}', not 'executing' "
                "(ADR-0021 §2: a config write executes only as the execution step of "
                "an approved, claimed ChangeRequest)"
            )

    @staticmethod
    def _diff_summary(before: str, after: str) -> tuple[str, ...]:
        """Redaction-safe summary of a config change (line counts only)."""
        before_lines = before.splitlines()
        after_lines = after.splitlines()
        before_set = set(before_lines)
        after_set = set(after_lines)
        added = sum(1 for line in after_lines if line not in before_set)
        removed = sum(1 for line in before_lines if line not in after_set)
        summary: list[str] = []
        if added:
            summary.append(f"+{added} line(s)")
        if removed:
            summary.append(f"-{removed} line(s)")
        return tuple(summary)

    def _execute(
        self,
        *,
        plan: ChangePlan,
        operation: str,
        project: Callable[[str], str],
        config_lines: list[str],
        apply: Callable[[list[str]], None],
    ) -> ChangeResult:
        """Run the ADR-0021 §3 contract and return a structured :class:`ChangeResult`.

        ``project`` maps the captured baseline to the intended normalized end-state.
        ``apply`` is the write surface (DEPLOY merges via ``send_config``; RESTORE
        replaces via ``replace_config``).

        IOS-XE note: the management-path guardrail (ADR-0021 §4.2) IS applied here.
        ADR-0021 §4 would permit relaxing it only if the executor armed a device-side
        ``commit-confirm`` dead-man auto-revert, but no transport implements that
        primitive (``SshTransport.replace_config`` issues a plain ``configure replace
        ... force``), so IOS-XE is an image without a dead-man primitive and a
        management-path change must be refused before any write.
        """
        self._require_executing(plan, operation)

        baseline = _normalize_config(self._capture_running())
        end_state = project(baseline)

        # Management-path guardrail BEFORE any device write (ADR-0021 §4.2): scoped
        # to the *delta* vs the captured baseline so replaying a snapshot whose mgmt
        # lines already match is not spuriously refused.
        self._reject_management_path(operation, baseline, end_state)

        if baseline == end_state:
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.NO_OP,
                verified=True,
                applied_diff=(),
                rollback=None,
            )

        applied_diff = self._diff_summary(baseline, end_state)

        apply_failed = False
        try:
            apply(config_lines)
        except Exception:  # noqa: BLE001
            apply_failed = True

        verified = False
        if not apply_failed:
            after = _normalize_config(self._capture_running())
            verified = after == end_state

        if verified:
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.APPLIED,
                verified=True,
                applied_diff=applied_diff,
                rollback=None,
            )

        rollback = self._rollback_to_baseline(baseline)
        outcome = ChangeOutcome.ROLLED_BACK if rollback.succeeded else ChangeOutcome.ROLLBACK_FAILED
        return ChangeResult(
            change_request_id=plan.change_request_id,
            outcome=outcome,
            verified=False,
            applied_diff=applied_diff,
            rollback=rollback,
        )

    def _rollback_to_baseline(self, baseline_normalized: str) -> RollbackResult:
        """Replace the device with the captured baseline and verify equality (§4).

        IOS-XE rollback uses ``configure replace`` of the captured pre-change
        baseline (the production transport issues a plain ``configure replace ...
        force`` — no ``commit-confirm`` timer is armed). A replace that cannot reach
        the device or cannot re-establish equality surfaces ``rollback_failed``
        (never silently closed, ADR-0021 §3).
        """
        try:
            self._replace_config(baseline_normalized.splitlines())
            after = _normalize_config(self._capture_running())
        except Exception as exc:  # noqa: BLE001
            return RollbackResult(
                attempted=True,
                succeeded=False,
                verified=False,
                detail=f"baseline replace failed ({type(exc).__name__})",
            )
        equal = after == baseline_normalized
        return RollbackResult(
            attempted=True,
            succeeded=equal,
            verified=equal,
            detail=None if equal else "re-captured config did not normalize equal to the baseline",
        )


class CiscoIosXeConfigRestore(_CiscoIosXeConfigWriteCapability, ConfigRestoreCapability):
    """``CONFIG_RESTORE``: replay an existing M4 ``config_snapshot`` (ADR-0021).

    Apply is a **config replace** (``replace_config`` / ``configure replace``) to
    the normalized snapshot — the only surface that can re-establish equality with
    the snapshot (a merge cannot remove device-only lines). IOS-XE supports
    ``commit-confirm`` for dead-man auto-revert; the management-path guardrail of
    classic IOS (ADR-0021 §4.2) does not apply. Idempotent: empty diff yields
    ``NO_OP`` without touching the device.
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


class CiscoIosXeConfigDeploy(_CiscoIosXeConfigWriteCapability, ConfigDeployCapability):
    """``CONFIG_DEPLOY``: merge a supplied config fragment (ADR-0021).

    Apply is a **merge** (``send_config`` / ``send_config_set``) — additive. The
    verify-after predicate is the strengthened residual-diff check (ADR-0021 §3):
    re-captured config must equal baseline + fragment additions exactly. On failure
    the captured baseline is replayed via ``replace_config``; rollback success is
    the asserted baseline equality. IOS-XE ``commit-confirm`` provides dead-man
    auto-revert; no management-path pre-write guardrail.
    """

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


class CiscoIosXeBgp(_CiscoIosXeCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary`` → :class:`NormalizedBgpPeer`.

    Delegates parsing to the shared cisco_ios parser (same ntc-templates
    platform key); stamps ``source_vendor = cisco_iosxe`` on every record.
    """

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize the IPv4-unicast BGP peering sessions."""
        output = self._run(SHOW_IP_BGP_SUMMARY)
        records = _ios_parsers.parse_bgp_peers(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeOspf(_CiscoIosXeCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor`` → :class:`NormalizedOspfNeighbor`.

    Delegates parsing to the shared cisco_ios parser (same ntc-templates
    platform key); stamps ``source_vendor = cisco_iosxe`` on every record.
    """

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize the OSPF neighbor adjacencies."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR)
        records = _ios_parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeAcl(_CiscoIosXeCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`.

    Delegates parsing to the shared cisco_ios parser (same ntc-templates
    platform key); stamps ``source_vendor = cisco_iosxe`` on every record.
    """

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        records = _ios_parsers.parse_acls(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXePlugin(VendorPlugin):
    """Cisco IOS-XE (``vendor_id="cisco_iosxe"``) — Cat9k/CSR/ISR plugin.

    Declares the full M1 capability set plus the M3 troubleshooting trio
    (BGP/OSPF/ACL): SSH/SNMP discovery, interface inventory, route
    collection, LLDP/CDP neighbors, config backup, BGP peers, OSPF
    neighbors, and IP access-lists.  Parsing is delegated to the
    ``cisco_ios`` parser module because IOS-XE ``show`` output is handled
    by the same ntc-templates templates (platform key ``cisco_ios``; ADR-0007).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Cisco IOS-XE"
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
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: CiscoIosXeDiscoverySsh,
            Capability.DISCOVERY_SNMP: CiscoIosXeDiscoverySnmp,
            Capability.INTERFACES: CiscoIosXeInterfaces,
            Capability.ROUTES: CiscoIosXeRoutes,
            Capability.NEIGHBORS_LLDP: CiscoIosXeNeighbors,
            Capability.NEIGHBORS_CDP: CiscoIosXeNeighbors,
            Capability.BGP: CiscoIosXeBgp,
            Capability.OSPF: CiscoIosXeOspf,
            Capability.ACL: CiscoIosXeAcl,
            Capability.CONFIG_BACKUP: CiscoIosXeConfigBackup,
            Capability.CONFIG_RESTORE: CiscoIosXeConfigRestore,
            Capability.CONFIG_DEPLOY: CiscoIosXeConfigDeploy,
        }
