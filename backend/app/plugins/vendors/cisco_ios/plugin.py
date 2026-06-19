"""Cisco IOS plugin: capability implementations over a ``CommandTransport``.

Reference implementation of the D6/ADR-0006 plugin contract. Capability
classes are instantiated per device session with a connected
:class:`~app.plugins.base.CommandTransport` (netmiko-backed in M1) plus the
inventory ``device_id``; every executed command is recorded verbatim via
``PluginCapability._record_raw`` before parsing (brief §4, D11).

Command strings live in this module's ``SHOW_*`` constants — the single
source of command text for the plugin (REPO-STRUCTURE §6 step 7; the
``commands.py``/``capabilities/`` split of the full reference layout is an
M1 refactor once more capabilities land).
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
from app.plugins.vendors.cisco_ios import parsers
from app.plugins.vendors.cisco_ios.parsers import (
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
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "CiscoIosAcl",
    "CiscoIosBgp",
    "CiscoIosConfigBackup",
    "CiscoIosConfigDeploy",
    "CiscoIosConfigRestore",
    "CiscoIosDiscoverySnmp",
    "CiscoIosDiscoverySsh",
    "CiscoIosInterfaces",
    "CiscoIosNeighbors",
    "CiscoIosOspf",
    "CiscoIosPlugin",
    "CiscoIosRoutes",
]

VENDOR_ID = "cisco_ios"

# Command text — must match the ntc-templates index entries for cisco_ios.
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


class _CiscoIosCommandCapability(PluginCapability):
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


class CiscoIosDiscoverySsh(_CiscoIosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`."""

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        return parsers.parse_device_facts(output)


class CiscoIosDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Takes an :class:`~app.plugins.base.SnmpReadTransport` (the M1-08
    ``SnmpClient`` in production, fakes in tests). The returned values are
    recorded verbatim as a :class:`~app.plugins.base.RawOutput` — one line
    per OID — before mapping, mirroring the CLI capabilities' audit trail.
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


class CiscoIosInterfaces(_CiscoIosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        return parsers.parse_interfaces(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosRoutes(_CiscoIosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        return parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosNeighbors(_CiscoIosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` + ``NEIGHBORS_CDP`` → :class:`NormalizedNeighbor`."""

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
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


class CiscoIosBgp(_CiscoIosCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary`` → :class:`NormalizedBgpPeer`."""

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize the IPv4-unicast BGP peering sessions."""
        output = self._run(SHOW_IP_BGP_SUMMARY)
        return parsers.parse_bgp_peers(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosOspf(_CiscoIosCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor`` → :class:`NormalizedOspfNeighbor`."""

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize the OSPF neighbor adjacencies."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR)
        return parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class CiscoIosAcl(_CiscoIosCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`."""

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        return parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosConfigBackup(_CiscoIosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim."""

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"cisco_ios: {SHOW_RUNNING_CONFIG!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


# ---------------------------------------------------------------------------
# Config write path (ADR-0021) — the first operations that mutate a device.
# ---------------------------------------------------------------------------


#: Volatile / non-settable IOS ``show running-config`` preamble lines. A real
#: device emits ``Building configuration...`` and ``Current configuration : NNN
#: bytes`` (the byte count changes with config size on every capture) — display
#: artifacts the device rejects as config commands and which would otherwise make
#: a byte-for-byte equality spuriously fail (ADR-0021 §4/§5). They are stripped
#: before equality comparison and before any line is replayed as configuration.
_VOLATILE_PREAMBLE_RE = re.compile(
    r"^(?:Building configuration\.\.\.|Current configuration\s*:.*)$"
)


def _normalize_config(raw_config: str) -> str:
    """Byte-stable normalized form for equality comparison (ADR-0017 §1 parity).

    Collapses ``\\r\\n``/``\\r`` to ``\\n``, strips trailing per-line whitespace,
    drops the volatile/non-settable IOS preamble (``Building configuration...`` /
    ``Current configuration : NNN bytes`` — see :data:`_VOLATILE_PREAMBLE_RE`),
    and guarantees a single trailing newline — so a verify-after / rollback
    equality reflects a *real* config difference, not transport CR/LF noise or a
    volatile header byte count that changes on every capture. Stripping the
    preamble is also what lets the normalized form be replayed as configuration:
    the display artifacts are not settable commands. The CR/LF + trailing-newline
    transform stays identical to M4's ``normalize_config`` so a snapshot stored by
    M4 still compares equal to a fresh capture here.
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    lines = [
        line.rstrip()
        for line in unified.split("\n")
        if not _VOLATILE_PREAMBLE_RE.match(line.strip())
    ]
    body = "\n".join(lines).strip("\n")
    return f"{body}\n" if body else ""


#: ``line con|vty|aux`` block header — the lines that carry the operator's
#: session itself; any change inside one can sever reachability.
_LINE_BLOCK_RE = re.compile(r"^line\s+(?:con|console|vty|aux)\b", re.IGNORECASE)
#: An interface block header.
_INTERFACE_BLOCK_RE = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
#: Management-class interface names (the mgmt interface / uplink / mgmt SVI). A
#: change to admin state / addressing / ACL binding on one of these can strand the
#: device; ordinary data/loopback interfaces are deliberately NOT matched, so a
#: benign interface deploy is not refused.
_MGMT_INTERFACE_NAME_RE = re.compile(
    r"^(?:Vlan\d+|(?:Mgmt|Management|FastEthernet0/0|GigabitEthernet0/0)\S*)$",
    re.IGNORECASE,
)
#: Commands that, in any context, touch the session-carrying management path
#: (ADR-0021 §4.2): vty/line ACLs (``access-class``), the session transport
#: (``transport input/output``), and the management default-gateway.
_MGMT_GLOBAL_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^access-class\b", re.IGNORECASE), "line access-class (mgmt ACL)"),
    (re.compile(r"^transport\s+(?:input|output)\b", re.IGNORECASE), "line transport (session)"),
    (re.compile(r"^ip\s+default-gateway\b", re.IGNORECASE), "management default-gateway"),
)
#: Within a *management-class* interface block, commands that can drop
#: reachability: admin state, the mgmt-interface ACL binding, and addressing.
_MGMT_INTERFACE_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:no\s+)?shutdown\b", re.IGNORECASE), "mgmt interface admin state (shutdown)"),
    (re.compile(r"^ip\s+access-group\b", re.IGNORECASE), "mgmt interface ip access-group"),
    (re.compile(r"^(?:no\s+)?ip\s+address\b", re.IGNORECASE), "mgmt interface ip address"),
)


def _management_path_hits(baseline: str, end_state: str) -> tuple[str, ...]:
    """Reasons the change baseline -> end_state touches the management path, or ``()``.

    The unit the guardrail validates (ADR-0021 §4.2) is the *change* — the lines
    a deploy/restore actually adds or removes — not the whole target. To keep
    interface-block context correct even when only an indented child line changes
    (its ``interface`` header may be unchanged), the scan walks the full ordered
    config (end-state, then baseline-only lines for removals) for context but
    flags a line only when it is part of the delta.

    A line is a management-path hit when it is a ``line con|vty|aux`` block, an
    ``access-class``/``transport input`` line, a management default-gateway, or —
    inside a *management-class* ``interface`` block (a VLAN SVI or a
    Mgmt/Management/0/0 uplink, see :data:`_MGMT_INTERFACE_NAME_RE`) — an
    admin-state (``shutdown``), an ``ip access-group`` binding, or an ``ip
    address`` change. Ordinary data/loopback interfaces are deliberately not
    flagged, so a benign interface deploy is not refused. Detection is
    conservative within the management scope (over-reject rather than strand a
    device); empty for a non-management change.
    """
    baseline_set = set(baseline.splitlines())
    end_set = set(end_state.splitlines())
    # Scan end-state for context + additions, then baseline-only lines (removals).
    end_lines = end_state.splitlines()
    removed_lines = [line for line in baseline.splitlines() if line not in end_set]

    hits: list[str] = []
    for sequence, changed_against in ((end_lines, baseline_set), (removed_lines, end_set)):
        in_mgmt_interface = False
        for raw in sequence:
            line = raw.strip()
            if not line:
                continue
            indented = raw[:1].isspace()
            interface_match = _INTERFACE_BLOCK_RE.match(line)
            if not indented:
                in_mgmt_interface = bool(
                    interface_match and _MGMT_INTERFACE_NAME_RE.match(interface_match.group(1))
                )
            # Only a line that is part of the delta (not present on the other
            # side) is a candidate hit; unchanged lines provide context only.
            if raw in changed_against:
                continue
            if not indented and _LINE_BLOCK_RE.match(line):
                hits.append("line con/vty/aux block (session transport)")
            for pattern, reason in _MGMT_GLOBAL_RES:
                if pattern.match(line):
                    hits.append(reason)
            if in_mgmt_interface:
                for pattern, reason in _MGMT_INTERFACE_RES:
                    if pattern.match(line):
                        hits.append(reason)
    # De-duplicate while preserving first-seen order.
    seen: dict[str, None] = {}
    for hit in hits:
        seen.setdefault(hit, None)
    return tuple(seen)


class _CiscoIosConfigWriteCapability(PluginCapability):
    """Shared capture-before -> apply -> verify-after -> rollback engine (ADR-0021 §3).

    Subclasses (restore/deploy) supply only what differs: how to compute the
    pre-apply diff, the config lines to send, and the verify-after predicate
    against the re-captured running config. The structured rollback is a
    first-class return (:class:`RollbackResult`), not a side effect: on apply
    error or verify-after failure the captured pre-change baseline is replayed
    and the rollback is itself verified (re-capture must normalize **equal** to
    the captured baseline) before any ``rolled_back`` is reported — otherwise
    ``rollback_failed`` is surfaced (never silently closed, §3).

    The capability **never self-authorizes**: every entry point first asserts
    the :class:`ChangePlan` attests an ``executing`` CR.
    """

    def __init__(self, transport: ConfigWriteTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    # -- transport helpers (each recorded verbatim for audit) ----------------

    def _capture_running(self) -> str:
        """Capture the live running config verbatim (recorded for audit)."""
        return self._record_raw(
            SHOW_RUNNING_CONFIG, self._transport.send_command(SHOW_RUNNING_CONFIG)
        )

    def _send_config(self, lines: list[str]) -> None:
        """Merge *lines* in config mode; record the verbatim device output.

        A ``send_config_set`` merge (additive) — the deploy apply surface. It
        cannot remove lines, so it is never used for an equal-to-baseline result.
        """
        output = self._transport.send_config(lines)
        self._record_raw("configure terminal\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Replace the running config with exactly *lines* (configure replace).

        The vendor-native config-replace primitive (ADR-0021 §4): the apply
        surface for ``CONFIG_RESTORE`` and the rollback surface for both
        operations, because only a replace can re-establish equality with a
        captured baseline (a merge cannot remove device-only lines). Records the
        verbatim device output for audit.
        """
        output = self._transport.replace_config(lines)
        self._record_raw("configure replace\n" + "\n".join(lines), output)

    @staticmethod
    def _require_executing(plan: ChangePlan, operation: str) -> None:
        """Refuse the write unless the plan attests an ``executing`` CR (§2).

        The plugin is the execution body of an approved CR claimed by the
        Automation Agent (Wave 4); it does not — and cannot — grant authorization
        itself. A plan in any other state is a typed :class:`PluginError`.
        """
        if not plan.is_executing:
            raise PluginError(
                f"cisco_ios: {operation} refused — change request "
                f"'{plan.change_request_id}' is '{plan.cr_state}', not 'executing' "
                "(ADR-0021 §2: a config write executes only as the execution step of "
                "an approved, claimed ChangeRequest)"
            )

    @staticmethod
    def _diff_summary(before: str, after: str) -> tuple[str, ...]:
        """Redaction-safe summary of a config change (never raw config text).

        Reports only the count of added/removed normalized lines, so a
        :class:`ChangeResult` carries no config secrets while still recording
        that (and how much) changed.
        """
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

    def _reject_management_path(self, operation: str, baseline: str, end_state: str) -> None:
        """Refuse a change that touches the management path (ADR-0021 §4.2).

        Classic ``cisco_ios`` implements neither a ``configure replace ... commit
        timer`` nor an EEM/kron dead-man auto-revert, so a change that severs the
        management path mid-apply strands the device: the worker can no longer
        reach it to replay the baseline (§4.1). On images without a dead-man
        primitive, ADR-0021 §4.2 places the guardrail in the deploy/restore
        fragment validation: it **rejects**, with a typed :class:`PluginError`
        and before any device write, any change touching the management path
        (mgmt-interface ACLs, the mgmt interface/uplink admin state, the mgmt
        VLAN/IP, or the line/transport carrying the session). The change is the
        delta baseline -> end_state. Such changes are out of M5 scope for classic
        IOS and need a console/OOB-fallback path.
        """
        offending = _management_path_hits(baseline, end_state)
        if offending:
            raise PluginError(
                f"cisco_ios: {operation} refused — change touches the management path "
                f"({', '.join(offending)}) and classic cisco_ios has no dead-man "
                "auto-revert primitive; a mid-apply reachability loss would strand the "
                "device with no replay path (ADR-0021 §4.2: management-path guardrail). "
                "This is out of M5 scope for classic IOS — use a console/OOB-fallback path."
            )

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

        ``project`` maps the captured baseline to the intended normalized
        end-state (restore: the snapshot; deploy: baseline + fragment additions).
        That projection is BOTH the redaction-safe diff target AND the
        verify-after target: verify-after asserts the re-captured config equals
        the projection **exactly** — symmetric in rigor between restore (equal to
        the snapshot) and deploy (equal to baseline + fragment, i.e. fragment
        present AND no unintended residual diff outside the fragment scope,
        ADR-0021 §3). ``apply`` is the write surface (deploy merges via
        ``send_config``; restore replaces via ``replace_config``).
        """
        self._require_executing(plan, operation)

        # Capture the FRESH pre-change baseline — the authoritative rollback
        # target (preferred over a possibly-stale CR rollback_plan reference, §3).
        baseline = _normalize_config(self._capture_running())
        end_state = project(baseline)

        # Management-path guardrail BEFORE any device write (ADR-0021 §4.2): on
        # classic IOS (no dead-man revert) a change touching the mgmt path is
        # refused. Scoped to the *delta* vs the captured baseline — the lines this
        # operation actually adds or removes — so restoring/replaying a snapshot
        # whose mgmt lines already match the live config is not spuriously refused;
        # only a change that would alter the management path is rejected.
        self._reject_management_path(operation, baseline, end_state)

        # Idempotency: if the device already satisfies the intended end-state,
        # complete without touching it (restore no-op; deploy fragment present).
        if baseline == end_state:
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.NO_OP,
                verified=True,
                applied_diff=(),
                rollback=None,
            )

        applied_diff = self._diff_summary(baseline, end_state)

        # Apply, then verify-after by re-capturing the running config and
        # asserting it equals the intended end-state exactly (residual-diff check).
        apply_failed = False
        try:
            apply(config_lines)
        except Exception:  # noqa: BLE001 — any apply failure triggers rollback (§3)
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

        # Apply errored or verify-after failed -> structured rollback to baseline.
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

        Classic IOS has no transactional commit, so rollback is a **config
        replace** of the captured pre-change baseline (ADR-0021 §4: the native
        rollback primitive is ``configure replace`` / replay of the baseline as
        the inverse). A replace — not a merge — is required: a merge cannot
        remove lines the failed apply added, so the re-capture could never
        normalize equal to the baseline. Success is an **asserted equality** (the
        re-captured config normalizes equal to the baseline), symmetric with the
        restore exit criterion — not an assumption. A replace that cannot reach
        the device (the transport raises) or whose re-capture does not normalize
        equal is ``succeeded=False`` -> the caller surfaces ``rollback_failed``,
        never ``rolled_back`` (§3).
        """
        try:
            self._replace_config(baseline_normalized.splitlines())
            after = _normalize_config(self._capture_running())
        except Exception as exc:  # noqa: BLE001 — unreachable device = rollback-failed
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


class CiscoIosConfigRestore(_CiscoIosConfigWriteCapability, ConfigRestoreCapability):
    """``CONFIG_RESTORE``: replay an existing M4 ``config_snapshot`` (ADR-0021).

    Idempotent: when the live config already normalizes equal to the snapshot the
    pre-apply diff is empty and the device is never touched (``NO_OP``). Otherwise
    the snapshot text is replayed (the captured baseline being the safety net,
    §4) and verify-after asserts the running config normalizes **equal** to the
    snapshot — the restore exit criterion.
    """

    def restore(self, snapshot: ConfigSnapshotRef, *, plan: ChangePlan) -> ChangeResult:
        """Restore the device to *snapshot* as the execution step of *plan*.

        Apply is a **config replace** (``replace_config``) to the normalized
        snapshot — the only surface that can re-establish equality with the
        snapshot, since the live config may be a superset of it (a merge could
        not remove the device-only lines, leaving verify-after unachievable,
        ADR-0021 §4). The volatile IOS preamble is stripped by
        :func:`_normalize_config`, so a benign byte-count header change does not
        defeat the equality predicate (§5).
        """
        target = _normalize_config(snapshot.content)

        return self._execute(
            plan=plan,
            operation="config restore",
            project=lambda _baseline: target,
            config_lines=target.splitlines(),
            apply=self._replace_config,
        )


class CiscoIosConfigDeploy(_CiscoIosConfigWriteCapability, ConfigDeployCapability):
    """``CONFIG_DEPLOY``: merge a supplied config fragment (ADR-0021).

    Best-effort idempotent: re-applying an already-present fragment yields an
    empty pre-apply diff and a ``NO_OP``. The deploy verify-after predicate is
    symmetric in rigor with restore: every normalized fragment line must be
    present in the re-captured running config **and** nothing outside the
    fragment's scope changed unexpectedly (no unintended residual diff). On
    failure the captured baseline is replayed; because a baseline replay of an
    order-sensitive fragment may not reproduce the exact baseline, rollback
    success is the asserted baseline equality (§3) — if it does not hold,
    ``rollback_failed`` is surfaced, never ``rolled_back``.
    """

    def deploy(self, config_fragment: str, *, plan: ChangePlan) -> ChangeResult:
        """Apply *config_fragment* as the execution step of *plan*.

        Apply is a **merge** (``send_config`` / ``send_config_set``) — the IOS
        apply primitive for an additive fragment (ADR-0021 §4). Verify-after is
        the *strengthened* predicate ADR-0021 §3 mandates: the re-captured,
        normalized running config must equal the projected end-state
        (baseline + the fragment's additions) **exactly** — every fragment line
        present AND no line outside the fragment's scope changed unexpectedly (no
        unintended residual diff), symmetric in rigor with the restore predicate,
        not merely set-membership of the fragment lines.
        """
        fragment_lines = [
            line for line in _normalize_config(config_fragment).splitlines() if line.strip()
        ]

        def project(baseline: str) -> str:
            # Intended end-state AND verify-after target: baseline merged with the
            # fragment lines not already present (a merge never removes lines). The
            # deploy post-condition is the re-captured config equals this
            # projection exactly — fragment present AND no unintended residual diff
            # outside the fragment scope (ADR-0021 §3), not mere set-membership.
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


class CiscoIosPlugin(VendorPlugin):
    """Cisco IOS (``vendor_id="cisco_ios"``) — M0/M1 reference plugin.

    Declares only what is implemented (REPO-STRUCTURE §6 step 4): the full
    M1 capability set — SSH/SNMP discovery, interface inventory, route
    collection, LLDP/CDP neighbors — plus config backup, the M3 troubleshooting
    trio (BGP/OSPF/ACL), and the M5 write path (CONFIG_RESTORE/CONFIG_DEPLOY,
    ADR-0021 — the first, certified-first device-write capabilities).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Cisco IOS"
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
            Capability.DISCOVERY_SSH: CiscoIosDiscoverySsh,
            Capability.DISCOVERY_SNMP: CiscoIosDiscoverySnmp,
            Capability.INTERFACES: CiscoIosInterfaces,
            Capability.ROUTES: CiscoIosRoutes,
            Capability.NEIGHBORS_LLDP: CiscoIosNeighbors,
            Capability.NEIGHBORS_CDP: CiscoIosNeighbors,
            Capability.BGP: CiscoIosBgp,
            Capability.OSPF: CiscoIosOspf,
            Capability.ACL: CiscoIosAcl,
            Capability.CONFIG_BACKUP: CiscoIosConfigBackup,
            Capability.CONFIG_RESTORE: CiscoIosConfigRestore,
            Capability.CONFIG_DEPLOY: CiscoIosConfigDeploy,
        }
