"""Arista EOS plugin: capability implementations over a ``CommandTransport``.

EOS-specific notes
------------------
- netmiko ``device_type``: ``arista_eos``
- ntc-templates platform key: ``arista_eos``
- No CDP support on EOS — ``NEIGHBORS_CDP`` is intentionally absent from the
  declared capability set (EOS uses LLDP exclusively for L2 neighbor discovery).
- ``show version`` on EOS does **not** emit ``hostname``; :meth:`EosDiscoverySsh`
  returns a placeholder hostname (serial > sys_mac > model) from the CLI path.
  SNMP discovery (``sysName``) provides the authoritative hostname.
- ``show ip route`` PROTOCOL is multi-token for eBGP/iBGP (``"B E"`` / ``"B I"``).

Command strings live in module-level ``SHOW_*`` constants — the single
source of command text for this plugin (REPO-STRUCTURE §6 step 7).
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
from app.plugins.vendors.eos import parsers
from app.plugins.vendors.eos.parsers import (
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
    "SHOW_RUNNING_CONFIG",
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "EosAcl",
    "EosBgp",
    "EosConfigBackup",
    "EosConfigDeploy",
    "EosConfigRestore",
    "EosDiscoverySnmp",
    "EosDiscoverySsh",
    "EosInterfaces",
    "EosNeighbors",
    "EosOspf",
    "EosPlugin",
    "EosRoutes",
]

VENDOR_ID = "eos"

# Command text — must match the ntc-templates index entries for arista_eos.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"
SHOW_IP_BGP_SUMMARY = "show ip bgp summary"
SHOW_IP_OSPF_NEIGHBOR = "show ip ospf neighbor"
SHOW_IP_ACCESS_LISTS = "show ip access-lists"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _EosCommandCapability(PluginCapability):
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


class EosDiscoverySsh(_EosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`.

    EOS ``show version`` does not include the device hostname; the returned
    :class:`DeviceFacts` carries a non-empty placeholder hostname (serial >
    sys_mac > model) when using the SSH path.  Use SNMP discovery
    (``sysName``) for authoritative hostname resolution.
    The parser stamps ``vendor_id="arista_eos"`` (ntc-templates platform key);
    we overwrite it with the plugin vendor_id ``"eos"`` on return.
    """

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        facts = parsers.parse_device_facts(output)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class EosDiscoverySnmp(DiscoverySnmpCapability):
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
        facts = parsers.parse_snmp_device_facts(values)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class EosInterfaces(_EosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        records = parsers.parse_interfaces(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosRoutes(_EosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        records = parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosNeighbors(_EosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` — LLDP adjacencies only.

    EOS does not implement CDP; ``get_cdp_neighbors`` satisfies the abstract
    method of :class:`~app.plugins.base.NeighborsCapability` but always
    returns an empty list.  The plugin does **not** declare
    ``Capability.NEIGHBORS_CDP`` in its capability set, so the conformance
    suite never calls ``get_cdp_neighbors`` through the fixture path.
    """

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        records = parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """EOS does not support CDP; always returns an empty list."""
        return []


class EosBgp(_EosCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary`` → :class:`NormalizedBgpPeer`.

    EOS uses separate ``state`` and ``state_pfxrcd`` columns in the TextFSM
    template (unlike IOS which overloads a single column).
    """

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize the IPv4-unicast BGP peering sessions."""
        output = self._run(SHOW_IP_BGP_SUMMARY)
        records = parsers.parse_bgp_peers(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosOspf(_EosCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor`` → :class:`NormalizedOspfNeighbor`.

    EOS emits plain uppercase state tokens (``FULL``, ``2WAY``, …) without
    the ``/DR``-role suffix seen in IOS output.
    """

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize the OSPF neighbor adjacencies."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR)
        records = parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosAcl(_EosCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`.

    EOS uses CIDR notation for network prefixes and the ``modifier`` field for
    destination port matches; host entries use the ``host <ip>`` form.
    """

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        records = parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosConfigBackup(_EosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim.

    EOS ``show running-config`` emits the full running configuration as plain
    text over SSH (``arista_eos`` netmiko device_type).  The output is
    returned unchanged — no trimming, no redaction — per ADR-0017 verbatim
    storage requirement.  Redaction happens only at the LLM boundary
    (``llm/redaction.py``, ADR-0017 §5).
    """

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"eos: {SHOW_RUNNING_CONFIG!r} returned empty output for device {self._device_id}"
            )
        return output


# ---------------------------------------------------------------------------
# Config write path (ADR-0021) — EOS config-session rollback
# ---------------------------------------------------------------------------

#: EOS ``show running-config`` comment headers — volatile / non-settable lines
#: that appear at the top of EOS output but are not configuration commands.
#: Examples:
#:   ``! Command: show running-config``
#:   ``! device: leaf01 (DCS-7050TX-64, EOS-4.28.3M)``
#:   ``! boot system flash:/EOS.swi``
#: These differ across captures (device description/version changes) and must
#: be stripped before equality comparison (ADR-0021 §4/§5 parity).
_EOS_COMMENT_LINE_RE = re.compile(r"^!")


def _normalize_config(raw_config: str) -> str:
    """Byte-stable normalized form for equality comparison (ADR-0021 §4/§5).

    Collapses ``\\r\\n``/``\\r`` to ``\\n``, strips trailing per-line whitespace,
    drops EOS ``!``-prefixed comment/header lines (``! Command: show running-config``,
    ``! device: ...``, ``! boot system ...`` — volatile lines that vary between
    captures), and guarantees a single trailing newline.

    EOS does not emit the IOS ``Building configuration...`` / ``Current
    configuration : NNN bytes`` preamble; instead it has ``!``-comment headers.
    Stripping all ``!``-prefixed lines (which are also not settable as config
    commands) keeps the form replay-safe.
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        line.rstrip()
        for line in unified.split("\n")
        if not _EOS_COMMENT_LINE_RE.match(line.strip())
    ]
    body = "\n".join(lines).strip("\n")
    return f"{body}\n" if body else ""


class _EosConfigWriteCapability(PluginCapability):
    """Shared capture-before -> apply -> verify-after -> rollback engine (ADR-0021 §3).

    **EOS config-session rollback**: Arista EOS supports transactional config
    sessions (``configure session <name>`` / ``commit`` / ``abort``). The apply
    is sent as a config session that is committed on success or aborted on failure.
    On verify-after failure the captured pre-change baseline is replayed via
    ``replace_config`` (which models an abort-and-reapply of the baseline session).
    The symmetric equality predicate (re-captured config == baseline after rollback)
    is still asserted — a session abort that does not restore equality surfaces
    ``rollback_failed`` (never silently closed, ADR-0021 §3).

    No management-path guardrail: EOS config sessions are transactional (abort
    reverts atomically), so there is no stranded-device risk and no pre-write
    refusal for management-path changes.

    The capability **never self-authorizes**: every entry point asserts
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
        """Commit a config-session with *lines* (additive); record verbatim output.

        Models an EOS ``configure session <name>`` / commit — an additive merge
        that enters the lines and exits, equivalent to ``send_config_set`` for the
        deploy apply surface.
        """
        output = self._transport.send_config(lines)
        self._record_raw("configure session\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Replace the running config with exactly *lines* (configure replace / session rollback).

        Models an EOS ``configure replace`` or baseline-session-commit — the only
        surface that can re-establish equality with a captured baseline (a merge
        cannot remove device-only lines). Used for CONFIG_RESTORE apply and for
        rollback of both operations. Records the verbatim device output for audit.
        """
        output = self._transport.replace_config(lines)
        self._record_raw("configure replace\n" + "\n".join(lines), output)

    @staticmethod
    def _require_executing(plan: ChangePlan, operation: str) -> None:
        """Refuse the write unless the plan attests an ``executing`` CR (§2)."""
        if not plan.is_executing:
            raise PluginError(
                f"eos: {operation} refused — change request "
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
        ``apply`` is the write surface (DEPLOY commits a session; RESTORE replaces).

        EOS note: the management-path guardrail (ADR-0021 §4.2) is NOT applied here
        because EOS config sessions are transactional (abort reverts atomically).
        """
        self._require_executing(plan, operation)

        baseline = _normalize_config(self._capture_running())
        end_state = project(baseline)

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
        """Restore the device to the captured baseline (§4).

        EOS rollback uses a ``configure replace`` of the captured pre-change
        baseline (modelled by ``replace_config``). In practice on a real device
        this maps to either a ``configure replace`` command or a baseline-session
        commit that restores the pre-change state. The rollback success criterion
        is symmetric: the re-captured config must normalize equal to the baseline
        (never assumed, always asserted). A replace that cannot reach the device
        or whose re-capture does not normalize equal is ``succeeded=False`` ->
        the caller surfaces ``rollback_failed``, never ``rolled_back`` (§3).
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


class EosConfigRestore(_EosConfigWriteCapability, ConfigRestoreCapability):
    """``CONFIG_RESTORE``: replay an existing M4 ``config_snapshot`` (ADR-0021).

    Apply is a **config replace** (``replace_config`` / EOS ``configure replace``)
    to the normalized snapshot — the only surface that can re-establish equality
    with the snapshot. EOS config sessions are transactional (abort on failure);
    the management-path guardrail (ADR-0021 §4.2) does not apply. Idempotent:
    empty diff yields ``NO_OP`` without touching the device.

    EOS comment headers (``! Command: ...`` / ``! device: ...``) are stripped by
    :func:`_normalize_config` before equality comparison, so a changed device
    version string does not defeat the equality predicate.
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


class EosConfigDeploy(_EosConfigWriteCapability, ConfigDeployCapability):
    """``CONFIG_DEPLOY``: merge a supplied config fragment (ADR-0021).

    Apply is a **merge** (``send_config`` / EOS config-session commit of an
    additive fragment) — additive. The verify-after predicate is the strengthened
    residual-diff check (ADR-0021 §3): re-captured config must equal
    baseline + fragment additions exactly. On failure the captured baseline is
    replayed via ``replace_config``; rollback success is the asserted baseline
    equality. EOS config sessions are transactional; no management-path guardrail.
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


class EosPlugin(VendorPlugin):
    """Arista EOS (``vendor_id="eos"``) — leaf/spine switching plugin.

    Declares: SSH/SNMP discovery, interface inventory, route collection,
    LLDP neighbors, and the M3 troubleshooting trio (BGP/OSPF/ACL).
    CDP is intentionally absent — EOS does not implement it.
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Arista EOS"
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
            Capability.DISCOVERY_SSH: EosDiscoverySsh,
            Capability.DISCOVERY_SNMP: EosDiscoverySnmp,
            Capability.INTERFACES: EosInterfaces,
            Capability.ROUTES: EosRoutes,
            Capability.NEIGHBORS_LLDP: EosNeighbors,
            Capability.BGP: EosBgp,
            Capability.OSPF: EosOspf,
            Capability.ACL: EosAcl,
            Capability.CONFIG_BACKUP: EosConfigBackup,
            Capability.CONFIG_RESTORE: EosConfigRestore,
            Capability.CONFIG_DEPLOY: EosConfigDeploy,
        }
