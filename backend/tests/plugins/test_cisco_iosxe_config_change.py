"""cisco_iosxe CONFIG_RESTORE / CONFIG_DEPLOY + structured rollback (M5 task #6).

Mirrors the cisco_ios test contract (test_cisco_ios_config_change.py) with
IOS-XE-specific differences:

- apply surface for RESTORE and rollback is ``replace_config`` (configure replace),
  same as classic IOS — the transactional ``commit-confirm`` timer acts as the
  dead-man auto-revert, so the management-path guardrail is relaxed (no pre-write
  refusal for mgmt-path changes, ADR-0021 §4.2 note).
- DEPLOY apply is ``send_config`` (merge, same as classic IOS).
- Normalization strips the same volatile IOS-XE preamble (Building configuration...
  / Current configuration : NNN bytes) before equality comparison.
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
from app.plugins.vendors.cisco_iosxe.plugin import (
    SHOW_RUNNING_CONFIG,
    CiscoIosXeConfigDeploy,
    CiscoIosXeConfigRestore,
    CiscoIosXePlugin,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_iosxe"
_BASELINE = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")


def _executing_plan(*, baseline_hash: str = "sha-baseline") -> ChangePlan:
    """A ChangePlan attesting the originating CR is in ``executing`` state."""
    return ChangePlan(
        change_request_id=uuid4(),
        cr_state="executing",
        baseline_content_hash=baseline_hash,
    )


class _SnapshotStub:
    """Structurally satisfies ``ConfigSnapshotRef`` (content + content_hash)."""

    def __init__(self, content: str, content_hash: str = "sha-snapshot") -> None:
        self.content = content
        self.content_hash = content_hash


_FRAGMENT = (
    "interface Loopback0\n description M5 iosxe test\n ip address 10.255.0.2 255.255.255.255\n"
)


class ConfigWriteFakeTransport:
    """In-memory ``ConfigWriteTransport`` modelling the REAL IOS-XE write surfaces.

    ``send_command('show running-config')`` returns the current config text.

    - ``send_config(lines)`` — MERGE: lines not already present are appended.
    - ``replace_config(lines)`` — REPLACE: running config becomes exactly the
      applied lines (configure replace / commit-confirm semantics on IOS-XE).

    Failure injection flags:

    - ``corrupt_apply``: the first write records the lines but leaves the running
      config unchanged (verify-after fails); the later rollback still applies.
    - ``raise_on_apply``: the first write raises (apply error); rollback still runs.
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
            raise RuntimeError("configure replace session dropped")
        return is_apply

    def send_config(self, lines: list[str]) -> str:
        self.config_batches.append(list(lines))
        is_apply = self._begin_write()
        if is_apply and self.corrupt_apply:
            return ""
        present = self._running.splitlines()
        present_set = set(present)
        merged = present + [line for line in lines if line not in present_set]
        self._running = "\n".join(merged) + "\n"
        return ""

    def replace_config(self, lines: list[str]) -> str:
        self.replace_batches.append(list(lines))
        is_apply = self._begin_write()
        if is_apply and self.corrupt_apply:
            return ""
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
        caps = CiscoIosXePlugin.capabilities
        assert Capability.CONFIG_RESTORE in caps
        assert Capability.CONFIG_DEPLOY in caps

    def test_restore_and_deploy_resolve_to_distinct_classes(self) -> None:
        plugin = CiscoIosXePlugin()
        assert plugin.get_capability(Capability.CONFIG_RESTORE) is CiscoIosXeConfigRestore
        assert plugin.get_capability(Capability.CONFIG_DEPLOY) is CiscoIosXeConfigDeploy
        assert CiscoIosXeConfigRestore is not CiscoIosXeConfigDeploy

    def test_classes_implement_typed_interfaces(self) -> None:
        assert issubclass(CiscoIosXeConfigRestore, ConfigRestoreCapability)
        assert issubclass(CiscoIosXeConfigDeploy, ConfigDeployCapability)


# ---------------------------------------------------------------------------
# Authorization: never self-authorize (ADR-0021 §2)
# ---------------------------------------------------------------------------


class TestNeverSelfAuthorizes:
    def test_restore_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigRestore(transport, device_id)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="approved", baseline_content_hash="x")
        with pytest.raises(PluginError):
            cap.restore(_SnapshotStub(_BASELINE), plan=plan)
        assert transport.replace_batches == []

    def test_deploy_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)
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
        current = _BASELINE.replace("hostname core-sw01", "hostname WRONG")
        transport = ConfigWriteFakeTransport(current)
        cap = CiscoIosXeConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert result.applied_diff
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2
        assert cap.raw_outputs

    def test_restore_uses_replace_config(self, device_id: UUID) -> None:
        """Restore apply surface must be replace_config (configure replace), not merge."""
        current = _BASELINE.replace("hostname core-sw01", "hostname WRONG")
        transport = ConfigWriteFakeTransport(current)
        cap = CiscoIosXeConfigRestore(transport, device_id)

        cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        # replace_config was called for the apply; send_config was NOT.
        assert transport.replace_batches  # at least one replace call (the apply)
        assert transport.config_batches == []  # no merge calls

    def test_restore_empty_diff_is_noop(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert result.verified is True
        assert result.rollback is None
        assert transport.replace_batches == []

    def test_restore_verify_failure_rolls_back(self, device_id: UUID) -> None:
        current = _BASELINE.replace("hostname core-sw01", "hostname WRONG")
        transport = ConfigWriteFakeTransport(current)
        transport.corrupt_apply = True
        cap = CiscoIosXeConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True

    def test_restore_volatile_preamble_tolerated(self, device_id: UUID) -> None:
        """Volatile IOS-XE preamble (byte-count header) does not defeat equality."""
        snapshot_text = (
            "Building configuration...\n\nCurrent configuration : 4231 bytes\n" + _BASELINE
        )

        class _VolatileHeaderTransport(ConfigWriteFakeTransport):
            def send_command(self, command: str) -> str:
                self.commands.append(command)
                if command == SHOW_RUNNING_CONFIG:
                    return (
                        "Building configuration...\n\n"
                        "Current configuration : 9999 bytes\n" + self._running
                    )
                raise AssertionError(f"unexpected command: {command!r}")

        current = _BASELINE.replace("hostname core-sw01", "hostname WRONG")
        transport = _VolatileHeaderTransport(current)
        cap = CiscoIosXeConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(snapshot_text), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None


# ---------------------------------------------------------------------------
# CONFIG_DEPLOY
# ---------------------------------------------------------------------------


class TestDeploy:
    def test_deploy_applies_and_verifies(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert transport.config_batches
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2

    def test_deploy_uses_send_config_merge(self, device_id: UUID) -> None:
        """Deploy apply surface must be send_config (merge), not replace."""
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert transport.config_batches  # merge was used for apply
        # replace_config is only used if rollback is triggered; in success path: not called.
        assert transport.replace_batches == []

    def test_deploy_empty_diff_is_noop(self, device_id: UUID) -> None:
        already = _BASELINE.rstrip("\n") + "\n" + _FRAGMENT
        transport = ConfigWriteFakeTransport(already)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert transport.config_batches == []

    def test_deploy_verify_failure_rolls_back(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True

    def test_deploy_rollback_uses_replace_config(self, device_id: UUID) -> None:
        """Rollback must use replace_config (not merge) to restore baseline equality."""
        transport = ConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        # Apply used send_config (merge), rollback used replace_config.
        assert transport.config_batches  # merge apply
        assert transport.replace_batches  # replace rollback

    def test_deploy_apply_error_rolls_back(self, device_id: UUID) -> None:
        transport = ConfigWriteFakeTransport(_BASELINE)
        transport.raise_on_apply = True
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# Rollback-failed: never reported rolled_back (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestRollbackFailedNeverSilent:
    def test_deploy_rollback_failure_surfaces_failed(self, device_id: UUID) -> None:
        class _BrokenRollbackTransport(ConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                self._begin_write()
                return ""  # apply does not land

            def replace_config(self, lines: list[str]) -> str:
                self.replace_batches.append(list(lines))
                self._begin_write()
                self._running = "hostname BROKEN-AFTER-ROLLBACK\n!\nend\n"
                return ""

        transport = _BrokenRollbackTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLBACK_FAILED
        assert result.outcome is not ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is False
        assert result.rollback.verified is False


# ---------------------------------------------------------------------------
# Deploy residual-diff check (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestDeployResidualDiff:
    def test_deploy_fragment_present_but_residual_diff_fails_verify(self, device_id: UUID) -> None:
        class _ResidualDiffTransport(ConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                is_apply = self._begin_write()
                if is_apply:
                    merged = self._running.replace("ip route 0.0.0.0 0.0.0.0 10.0.0.2\n", "")
                    present = merged.splitlines()
                    present_set = set(present)
                    merged_lines = present + [ln for ln in lines if ln not in present_set]
                    self._running = "\n".join(merged_lines) + "\n"
                    return ""
                self._running = "\n".join(lines) + "\n"
                return ""

            def replace_config(self, lines: list[str]) -> str:
                self.replace_batches.append(list(lines))
                self._begin_write()
                self._running = "\n".join(lines) + "\n"
                return ""

        transport = _ResidualDiffTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is not ChangeOutcome.APPLIED
        assert result.verified is False
        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# IOS-XE: management-path changes are NOT pre-refused (commit-confirm timer)
# ---------------------------------------------------------------------------


class TestManagementPathNotRefusedOnIosXe:
    """IOS-XE has a dead-man auto-revert (commit-confirm timer), so ADR-0021
    §4.2's pre-write management-path guardrail (which applies to classic IOS
    only) does NOT apply to IOS-XE. A vty/mgmt-path fragment must be allowed
    through and not refused before the write.
    """

    def test_deploy_allows_vty_fragment_iosxe(self, device_id: UUID) -> None:
        """A vty transport fragment must reach the apply stage on IOS-XE."""
        transport = ConfigWriteFakeTransport(_BASELINE)
        cap = CiscoIosXeConfigDeploy(transport, device_id)

        # This would be refused on classic cisco_ios but must NOT be refused here.
        fragment = "line vty 0 4\n transport input ssh\n"
        # Must not raise PluginError; apply may succeed or rollback — just not pre-refused.
        result = cap.deploy(fragment, plan=_executing_plan())

        # The write surface was reached (no pre-write PluginError raised).
        assert result.outcome in {
            ChangeOutcome.APPLIED,
            ChangeOutcome.NO_OP,
            ChangeOutcome.ROLLED_BACK,
        }
        # send_config was invoked — the apply stage was reached.
        assert transport.config_batches or result.outcome is ChangeOutcome.NO_OP
