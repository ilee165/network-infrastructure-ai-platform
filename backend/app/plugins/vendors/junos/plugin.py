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


class _JunosConfigWriteCapability(PluginCapability):
    """Shared capture-before -> apply -> verify-after -> rollback engine (ADR-0021 §3).

    **JunOS rollback (ADR-0026 §3.1)**: The config-write surfaces model the JunOS
    candidate-config + ``commit confirmed`` transaction:

    - ``send_config(lines)`` → ``load merge`` into the candidate + ``commit confirmed``;
      on verify-after success → confirming ``commit``. Deploy apply surface.
    - ``replace_config(lines)`` → ``load override`` into the candidate +
      ``commit confirmed``; on verify-after success → confirming ``commit``; on
      verify-after failure → ``rollback N``. Restore apply + rollback surface.

    **No management-path guardrail** (ADR-0026 §3.1): JunOS provides
    ``commit confirmed`` natively — the device auto-reverts at the timeout even if
    the worker loses the session. The ADR-0021 §4.2 guardrail that ``cisco_ios``
    and ``eos`` carry is therefore **not applied** here; this is not an oversight
    but the explicit consequence of JunOS supplying a native dead-man revert
    (ADR-0026 §3 "closes, by construction, the highest-blast-radius hole
    ADR-0021 had to special-case for classic IOS").

    **Tracked gap — worker crash during ``commit confirmed`` window** (ADR-0026 §3.2.1):
    if the Celery worker dies after ``commit confirmed`` but before the confirming
    ``commit`` or ``rollback N``, the device correctly auto-reverts at the timeout
    but the CR remains stuck in ``executing``. This is deferred to a future ADR;
    see ADR-0026 §3.2.1 for the three reaper paths under consideration.

    The capability **never self-authorizes**: every entry point first asserts
    the :class:`ChangePlan` attests an ``executing`` CR (ADR-0021 §2).
    """

    def __init__(self, transport: ConfigWriteTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def _capture_config(self) -> str:
        """Capture the live committed configuration verbatim (recorded for audit)."""
        return self._record_raw(
            SHOW_CONFIGURATION_SET,
            self._transport.send_command(SHOW_CONFIGURATION_SET),
        )

    def _send_config(self, lines: list[str]) -> None:
        """Merge *lines* into the candidate and commit confirmed (deploy apply surface).

        Models: ``load merge`` of fragment lines → ``commit confirmed <N>``.
        The transport's ``send_config`` method drives this sequence; the plugin
        records the verbatim device output for audit.
        """
        output = self._transport.send_config(lines)
        self._record_raw("load merge + commit confirmed\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Override the candidate with exactly *lines* and commit confirmed.

        Models: ``load override`` of the full config set-form → ``commit confirmed <N>``.
        Used for ``CONFIG_RESTORE`` apply and for ``rollback N`` / re-baseline on
        both operations (ADR-0026 §3.1: the only surface that can re-establish equality
        with a captured baseline, since a merge cannot remove device-only lines).
        Records the verbatim device output for audit.
        """
        output = self._transport.replace_config(lines)
        self._record_raw("load override + commit confirmed\n" + "\n".join(lines), output)

    @staticmethod
    def _require_executing(plan: ChangePlan, operation: str) -> None:
        """Refuse the write unless the plan attests an ``executing`` CR (ADR-0021 §2).

        JunOS candidate-config writes are gated by the same CR-state check as all
        other vendors: the plugin cannot self-authorize; it verifies the attestation
        supplied by the Automation-Agent executor (ADR-0020 four-eyes spine,
        ADR-0026 §3.2: "``_require_executing(plan)`` is unchanged").
        """
        if not plan.is_executing:
            raise PluginError(
                f"junos: {operation} refused — change request "
                f"'{plan.change_request_id}' is '{plan.cr_state}', not 'executing' "
                "(ADR-0021 §2: a config write executes only as the execution step of "
                "an approved, claimed ChangeRequest)"
            )

    @staticmethod
    def _diff_summary(before: str, after: str) -> tuple[str, ...]:
        """Redaction-safe summary of a config change (line counts only).

        Reports only the count of added/removed normalized lines, so a
        :class:`ChangeResult` carries no config secrets while still recording
        that (and how much) changed (ADR-0021 §3 / ADR-0026 §4).
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

        JunOS note: no management-path guardrail is applied here (ADR-0026 §3.1:
        ``commit confirmed`` provides the native dead-man revert unconditionally, so
        a connectivity-severing change auto-reverts at the timeout even if the worker
        dies — the ADR-0021 §4.2 guardrail is not needed). See class docstring for
        the tracked gap when the worker crashes during the ``commit confirmed`` window.
        """
        self._require_executing(plan, operation)

        # Capture the FRESH pre-change baseline — the authoritative rollback target.
        baseline = _normalize_config(self._capture_config())
        end_state = project(baseline)

        # Idempotency: if the device already satisfies the intended end-state,
        # complete without touching it.
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
        except Exception:  # noqa: BLE001 — any apply failure triggers rollback
            apply_failed = True

        verified = False
        if not apply_failed:
            after = _normalize_config(self._capture_config())
            verified = after == end_state

        if verified:
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.APPLIED,
                verified=True,
                applied_diff=applied_diff,
                rollback=None,
            )

        # Apply errored or verify-after failed → structured rollback to baseline.
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
        """Roll back to the captured baseline via ``rollback N`` / ``load override``.

        See ADR-0026 §3.1 for the full vendor mapping.

        JunOS rollback is a ``replace_config`` of the captured pre-change baseline,
        modelling the JunOS ``rollback N`` primitive (addressable to the exact prior
        committed configuration point — a single atomic device-side operation,
        ADR-0026 §3.1: "the cleanest possible mapping ... a single addressable inverse,
        not a re-create or a line replay"). The rollback success criterion is the
        symmetric asserted equality: re-captured config must normalize equal to the
        baseline (ADR-0021 §3: "rollback success is an asserted equality, never an
        assumption"). A rollback that cannot reach the device or whose re-capture does
        not normalize equal is ``succeeded=False`` → caller surfaces ``rollback_failed``,
        never ``rolled_back`` (ADR-0021 §3).
        """
        try:
            self._replace_config(baseline_normalized.splitlines())
            after = _normalize_config(self._capture_config())
        except Exception as exc:  # noqa: BLE001 — unreachable device = rollback-failed
            return RollbackResult(
                attempted=True,
                succeeded=False,
                verified=False,
                detail=f"rollback N / load override failed ({type(exc).__name__})",
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
