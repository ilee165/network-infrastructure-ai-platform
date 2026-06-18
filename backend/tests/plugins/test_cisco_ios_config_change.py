"""cisco_ios CONFIG_RESTORE / CONFIG_DEPLOY + structured rollback (M5 task #5).

The first device-write path in the project (ADR-0021). These tests drive the
capture-before -> apply -> verify-after -> rollback-on-failure contract over an
in-memory :class:`ConfigWriteTransport` fake — no device, no network (D16). The
capability bodies execute *only* as the execution step of an ``executing``
ChangeRequest: a :class:`ChangePlan` not attesting ``executing`` is a typed
``PluginError`` (the plugin never self-authorizes; ADR-0021 §2).

Fixtures: the cisco_ios running-config (``show_running_config.txt``) is the
restore source and the rollback baseline; deploy fragments are small line sets.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    ChangeOutcome,
    ChangePlan,
    ChangeResult,
    ConfigDeployCapability,
    ConfigRestoreCapability,
)
from app.plugins.vendors.cisco_ios.plugin import (
    SHOW_RUNNING_CONFIG,
    CiscoIosConfigDeploy,
    CiscoIosConfigRestore,
    CiscoIosPlugin,
)

FIXTURES = Path(__file__).parent / "fixtures"
_BASELINE = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")


def _executing_plan(*, baseline_hash: str = "sha-baseline") -> ChangePlan:
    """A ChangePlan attesting the originating CR is in ``executing`` state."""
    return ChangePlan(
        change_request_id=uuid4(),
        cr_state="executing",
        baseline_content_hash=baseline_hash,
    )


class _SnapshotStub:
    """Structurally satisfies ``ConfigSnapshotRef`` (content + content_hash).

    The real ORM ``ConfigSnapshot`` is passed in production; the plugin layer
    only reads ``content``/``content_hash`` and never imports the model.
    """

    def __init__(self, content: str, content_hash: str = "sha-snapshot") -> None:
        self.content = content
        self.content_hash = content_hash


_FRAGMENT = (
    "interface Loopback0\n description M5 test loopback\n ip address 10.255.0.1 255.255.255.255\n"
)


class ConfigWriteFakeTransport:
    """In-memory ``ConfigWriteTransport`` modelling the REAL IOS write surfaces.

    ``send_command('show running-config')`` returns the current config text.

    - ``send_config(lines)`` models netmiko ``send_config_set`` — a **MERGE**:
      lines not already present are appended (in order); nothing is removed. This
      is the deploy apply surface. It cannot reproduce a baseline that is a strict
      superset of the merged lines (matching real IOS), so it is never used by the
      plugin for an equal-to-baseline result.
    - ``replace_config(lines)`` models ``configure replace`` — a **REPLACE**: the
      running config becomes exactly the applied lines (device-only lines are
      removed). This is the restore apply surface and the rollback surface, the
      only surface that can re-establish equality with a captured baseline.

    Failure injection flags (apply = the FIRST write call):

    - ``corrupt_apply``: the first write records the lines but leaves the running
      config unchanged (verify-after fails); the later rollback ``replace_config``
      still applies, so rollback succeeds. Models "the apply did not land."
    - ``raise_on_apply``: the first write raises (apply error); the rollback
      ``replace_config`` still applies, so the device returns to the baseline.
    """

    def __init__(self, running: str) -> None:
        self._running = running
        self.config_batches: list[list[str]] = []
        self.replace_batches: list[list[str]] = []
        self.commands: list[str] = []
        self.corrupt_apply: bool = False
        self.raise_on_apply: bool = False
        self._writes = 0

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if command == SHOW_RUNNING_CONFIG:
            return self._running
        raise AssertionError(f"unexpected command sent to device: {command!r}")

    def _begin_write(self) -> bool:
        """Advance the write counter; return whether this is the apply (first) write."""
        self._writes += 1
        is_apply = self._writes == 1
        if is_apply and self.raise_on_apply:
            raise RuntimeError("config session dropped")
        return is_apply

    def send_config(self, lines: list[str]) -> str:
        # MERGE: union into the running config, no deletion, additions appended in
        # order (deterministic model of send_config_set).
        self.config_batches.append(list(lines))
        is_apply = self._begin_write()
        if is_apply and self.corrupt_apply:
            return ""  # apply did not land
        present = self._running.splitlines()
        present_set = set(present)
        merged = present + [line for line in lines if line not in present_set]
        self._running = "\n".join(merged) + "\n"
        return ""

    def replace_config(self, lines: list[str]) -> str:
        # REPLACE: running config becomes exactly the applied lines.
        self.replace_batches.append(list(lines))
        is_apply = self._begin_write()
        if is_apply and self.corrupt_apply:
            return ""  # apply did not land
        self._running = "\n".join(lines) + "\n"
        return ""


@pytest.fixture()
def device_id() -> UUID:
    return uuid4()


# ---------------------------------------------------------------------------
# Plugin declaration
# ---------------------------------------------------------------------------


class TestPluginDeclaration:
    def test_declares_both_write_capabilities(self) -> None:
        caps = CiscoIosPlugin.capabilities
        assert Capability.CONFIG_RESTORE in caps
        assert Capability.CONFIG_DEPLOY in caps

    def test_restore_and_deploy_resolve_to_distinct_classes(self) -> None:
        plugin = CiscoIosPlugin()
        assert plugin.get_capability(Capability.CONFIG_RESTORE) is CiscoIosConfigRestore
        assert plugin.get_capability(Capability.CONFIG_DEPLOY) is CiscoIosConfigDeploy
        assert CiscoIosConfigRestore is not CiscoIosConfigDeploy

    def test_classes_implement_typed_interfaces(self) -> None:
        assert issubclass(CiscoIosConfigRestore, ConfigRestoreCapability)
        assert issubclass(CiscoIosConfigDeploy, ConfigDeployCapability)


# ---------------------------------------------------------------------------
# Authorization: never self-authorize (ADR-0021 §2)
# ---------------------------------------------------------------------------


class TestNeverSelfAuthorizes:
    def test_restore_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigRestore(transport, device_id)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="approved", baseline_content_hash="x")
        with pytest.raises(PluginError):
            cap.restore(_SnapshotStub(_BASELINE), plan=plan)
        # Refused before any device write.
        assert transport.config_batches == []

    def test_deploy_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)
        plan = ChangePlan(
            change_request_id=uuid4(), cr_state="pending_approval", baseline_content_hash="x"
        )
        with pytest.raises(PluginError):
            cap.deploy("interface Loopback0\n description test\n", plan=plan)
        assert transport.config_batches == []


# ---------------------------------------------------------------------------
# CONFIG_RESTORE
# ---------------------------------------------------------------------------


class TestRestore:
    def test_restore_applies_and_verifies(self, device_id: UUID) -> None:
        # Device currently has a *different* config than the snapshot.
        current = _BASELINE.replace("hostname core-rtr01", "hostname WRONG")
        transport = ConfigWriteFakeTransport(current)
        cap = CiscoIosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert result.applied_diff  # non-empty diff was applied
        # A fresh pre-change baseline was captured AND verify-after re-captured.
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2
        # Raw device output recorded verbatim for audit.
        assert cap.raw_outputs

    def test_restore_empty_diff_is_noop(self, device_id: UUID) -> None:
        # Device already matches the snapshot => idempotent no-op, no write.
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert result.verified is True
        assert result.rollback is None
        assert transport.config_batches == []  # device never touched

    def test_restore_verify_failure_rolls_back(self, device_id: UUID) -> None:
        current = _BASELINE.replace("hostname core-rtr01", "hostname WRONG")
        transport = ConfigWriteFakeTransport(current)
        # Apply "succeeds" at the transport but does not land the snapshot text
        # (verify-after fails); baseline replay then restores the captured state.
        transport.corrupt_apply = True
        cap = CiscoIosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        # Rollback re-captured and confirmed equality with the captured baseline.
        assert result.rollback.verified is True


# ---------------------------------------------------------------------------
# CONFIG_DEPLOY
# ---------------------------------------------------------------------------


class TestDeploy:
    def test_deploy_applies_and_verifies(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        # Every fragment line present in the re-captured config (deploy predicate).
        assert transport.config_batches  # fragment was sent in config mode
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2

    def test_deploy_empty_diff_is_noop(self, device_id: UUID) -> None:
        # Fragment already present in the running config => no-op.
        already = _BASELINE.rstrip("\n") + "\n" + _FRAGMENT
        transport = ConfigWriteFakeTransport(already)
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert transport.config_batches == []

    def test_deploy_verify_failure_rolls_back(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True  # apply does not land the fragment
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True

    def test_deploy_apply_error_rolls_back(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        transport.raise_on_apply = True
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        # Apply errored; the baseline replay restores the captured baseline.
        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# Rollback-failed: never reported rolled_back (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestRollbackFailedNeverSilent:
    def test_deploy_rollback_failure_surfaces_failed(self, device_id: UUID) -> None:
        # The apply does not land (verify-after fails), and the baseline REPLACE
        # also fails to reproduce the captured baseline (a partially-applied,
        # order-sensitive fragment per ADR-0021 §3) -> rollback-failed.
        class _PartialRollbackTransport(ConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                # The apply (first write): record it but do not land it.
                self.config_batches.append(list(lines))
                self._begin_write()
                return ""  # verify-after will fail

            def replace_config(self, lines: list[str]) -> str:
                # The rollback replace leaves residual mangling -> != baseline.
                self.replace_batches.append(list(lines))
                self._begin_write()
                self._running = "hostname BROKEN-AFTER-ROLLBACK\n!\nend\n"
                return ""

        transport = _PartialRollbackTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLBACK_FAILED
        assert result.outcome is not ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is False
        assert result.rollback.verified is False


# ---------------------------------------------------------------------------
# Deploy verify-after: residual-diff check, not mere line-membership (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestDeployResidualDiff:
    def test_deploy_fragment_present_but_residual_diff_fails_verify(self, device_id: UUID) -> None:
        # The apply lands the fragment lines BUT also drops an unrelated baseline
        # line (a device-mangled / connectivity-affecting apply). Mere
        # set-membership of the fragment lines would pass; the strengthened
        # predicate (re-captured config == baseline + additions exactly) must FAIL
        # and trigger rollback (ADR-0021 §3, line 33).
        class _ResidualDiffTransport(ConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                is_apply = self._begin_write()
                if is_apply:
                    # Land the fragment, but DROP an unrelated baseline line.
                    merged = self._running.replace("ip route 0.0.0.0 0.0.0.0 192.0.2.9\n", "")
                    present = merged.splitlines()
                    present_set = set(present)
                    merged_lines = present + [ln for ln in lines if ln not in present_set]
                    self._running = "\n".join(merged_lines) + "\n"
                    return ""
                # rollback replace restores the exact baseline
                self._running = "\n".join(lines) + "\n"
                return ""

            def replace_config(self, lines: list[str]) -> str:
                self.replace_batches.append(list(lines))
                self._begin_write()
                self._running = "\n".join(lines) + "\n"
                return ""

        transport = _ResidualDiffTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        # Fragment present, but an unrelated line changed -> NOT applied.
        assert result.outcome is not ChangeOutcome.APPLIED
        assert result.verified is False
        # The captured baseline replace restored the device -> rolled_back.
        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# Restore verify-after tolerates the volatile IOS preamble (ADR-0021 §4/§5)
# ---------------------------------------------------------------------------


class TestRestoreVolatilePreamble:
    def test_restore_succeeds_despite_changed_byte_count_header(self, device_id: UUID) -> None:
        # A real `show running-config` re-capture carries `Building
        # configuration...` and a `Current configuration : NNN bytes` header whose
        # byte count changes with config size. The snapshot was taken at a
        # different size, so the headers differ. A correct restore must still
        # report APPLIED/verified — the volatile preamble is stripped before the
        # equality comparison (ADR-0021 §5); it must not trigger a spurious
        # rollback.
        snapshot_text = (
            "Building configuration...\n\nCurrent configuration : 1840 bytes\n" + _BASELINE
        )

        class _VolatileHeaderTransport(ConfigWriteFakeTransport):
            def send_command(self, command: str) -> str:
                self.commands.append(command)
                if command == SHOW_RUNNING_CONFIG:
                    # Re-capture carries a DIFFERENT byte-count header than the
                    # snapshot, plus the volatile build banner.
                    return (
                        "Building configuration...\n\n"
                        "Current configuration : 9999 bytes\n" + self._running
                    )
                raise AssertionError(f"unexpected command sent to device: {command!r}")

        # Device drifted on a non-mgmt line so the restore actually applies.
        current = _BASELINE.replace("hostname core-rtr01", "hostname WRONG")
        transport = _VolatileHeaderTransport(current)
        cap = CiscoIosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(snapshot_text), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None


# ---------------------------------------------------------------------------
# Management-path guardrail: refuse mgmt-path changes on classic IOS (ADR-0021 §4.2)
# ---------------------------------------------------------------------------


class TestManagementPathGuardrail:
    def test_deploy_rejects_vty_transport_change_before_any_write(self, device_id: UUID) -> None:
        # A fragment touching the session-carrying vty/transport must be refused
        # with a typed PluginError BEFORE any device write — classic cisco_ios has
        # no dead-man auto-revert (ADR-0021 §4.2).
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        fragment = "line vty 0 4\n transport input telnet ssh\n"
        with pytest.raises(PluginError, match="management path"):
            cap.deploy(fragment, plan=_executing_plan())

        # Refused before any write surface was touched.
        assert transport.config_batches == []
        assert transport.replace_batches == []

    def test_deploy_rejects_vty_access_class_change(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        fragment = "line vty 0 4\n access-class MGMT-ACL in\n"
        with pytest.raises(PluginError, match="management path"):
            cap.deploy(fragment, plan=_executing_plan())
        assert transport.config_batches == []

    def test_deploy_rejects_mgmt_svi_ip_change(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        fragment = "interface Vlan10\n ip address 10.0.0.9 255.255.255.0\n"
        with pytest.raises(PluginError, match="management path"):
            cap.deploy(fragment, plan=_executing_plan())
        assert transport.config_batches == []

    def test_deploy_allows_benign_non_mgmt_fragment(self, device_id: UUID) -> None:
        # A loopback/data interface fragment (the existing _FRAGMENT) is NOT a
        # mgmt-path change and must be allowed through to apply.
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.APPLIED
        assert transport.config_batches  # the write surface WAS used

    def test_restore_rejects_when_delta_touches_mgmt_path(self, device_id: UUID) -> None:
        # The device drifted by ADDING a vty access-class; restoring the snapshot
        # would REMOVE it — a management-path change — so restore is refused before
        # any write (ADR-0021 §4.2: the guardrail validates the change delta).
        drifted = _BASELINE.replace(
            "line vty 0 4\n login local\n",
            "line vty 0 4\n access-class TIGHTENED in\n login local\n",
        )
        assert drifted != _BASELINE  # guard against a no-op fixture edit
        transport = ConfigWriteFakeTransport(drifted)
        cap = CiscoIosConfigRestore(transport, device_id)

        with pytest.raises(PluginError, match="management path"):
            cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())
        assert transport.config_batches == []
        assert transport.replace_batches == []
