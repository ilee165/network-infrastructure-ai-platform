"""Juniper JunOS CONFIG_RESTORE / CONFIG_DEPLOY + structured rollback (ADR-0026 §3).

Mirrors the eos / cisco_ios test contract with JunOS-specific differences:

- JunOS rollback: ``rollback N`` / ``load override`` of the captured baseline (not
  a line-by-line replay; single atomic inverse — ADR-0026 §3.1 "cleanest possible
  mapping").
- **No management-path guardrail**: ``commit confirmed`` provides native dead-man
  auto-revert so a connectivity-severing change auto-reverts even if the worker
  dies (ADR-0026 §3.1: guardrail not needed — the explicit consequence of JunOS
  supplying a native dead-man revert).
- ``show configuration | display set`` (not ``show running-config``) is the capture
  command; volatile ``## Last commit:`` / ``## version`` headers are stripped by
  ``_normalize_config``.
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
from app.plugins.vendors.junos.plugin import (
    SHOW_CONFIGURATION_SET,
    JunosConfigDeploy,
    JunosConfigRestore,
    JunosPlugin,
)

FIXTURES = Path(__file__).parent / "fixtures" / "junos"
_BASELINE = (FIXTURES / "show_configuration_display_set.txt").read_text(encoding="utf-8")

_FRAGMENT = "set interfaces lo0 unit 0 family inet address 10.255.0.1/32\n"


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


class JunosConfigWriteFakeTransport:
    """In-memory ``ConfigWriteTransport`` modelling JunOS candidate-config write surfaces.

    ``send_command("show configuration | display set")`` returns the current config
    (the committed state — after confirm or after rollback, not the candidate).

    - ``send_config(lines)`` — MERGE: models ``load merge`` + ``commit confirmed`` →
      confirming ``commit`` (deploy path, additive).
    - ``replace_config(lines)`` — REPLACE: models ``load override`` + ``commit confirmed``
      → confirming ``commit`` (restore + rollback path, full replace).

    Failure injection flags:
    - ``corrupt_apply``: the first write does NOT change the running state (verify-after
      fails); rollback replace still applies.
    - ``raise_on_apply``: the first write raises (apply error); rollback still runs.
    """

    def __init__(self, running: str) -> None:
        self._running = running
        self.config_batches: list[list[str]] = []
        self.replace_batches: list[list[str]] = []
        self.commands: list[str] = []
        self.confirm_calls: int = 0
        self.rollback_calls: list[int] = []
        self.corrupt_apply: bool = False
        self.raise_on_apply: bool = False
        self.raise_on_confirm: bool = False
        self._writes = 0
        self._pre_apply: str | None = None

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if command == SHOW_CONFIGURATION_SET:
            return self._running
        raise AssertionError(f"unexpected command sent to device: {command!r}")

    def _begin_write(self) -> bool:
        """Advance the write counter; return whether this is the apply (first) write."""
        self._writes += 1
        is_apply = self._writes == 1
        if is_apply:
            self._pre_apply = self._running
        if is_apply and self.raise_on_apply:
            raise RuntimeError("JunOS commit confirmed failed")
        return is_apply

    def send_config(self, lines: list[str]) -> str:
        """Apply-only (commit confirmed) — confirming commit is :meth:`confirm_config`."""
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
        """Apply-only override — confirming commit is :meth:`confirm_config`."""
        self.replace_batches.append(list(lines))
        is_apply = self._begin_write()
        if is_apply and self.corrupt_apply:
            return ""
        self._running = "\n".join(lines) + "\n"
        return ""

    def confirm_config(self) -> str:
        """Option A: confirming commit after verify-after success."""
        self.confirm_calls += 1
        if self.raise_on_confirm:
            raise RuntimeError("JunOS confirming commit failed")
        return ""

    def rollback_config(self, n: int = 1) -> str:
        """Permanent inverse: restore pre-apply committed config (models rollback N + commit)."""
        self.rollback_calls.append(n)
        if self._pre_apply is not None:
            self._running = self._pre_apply
        return ""


@pytest.fixture()
def device_id() -> UUID:
    return uuid4()


# ---------------------------------------------------------------------------
# Plugin declaration
# ---------------------------------------------------------------------------


class TestPluginDeclaration:
    def test_declares_both_write_capabilities(self) -> None:
        caps = JunosPlugin.capabilities
        assert Capability.CONFIG_RESTORE in caps
        assert Capability.CONFIG_DEPLOY in caps

    def test_restore_and_deploy_resolve_to_distinct_classes(self) -> None:
        plugin = JunosPlugin()
        assert plugin.get_capability(Capability.CONFIG_RESTORE) is JunosConfigRestore
        assert plugin.get_capability(Capability.CONFIG_DEPLOY) is JunosConfigDeploy
        assert JunosConfigRestore is not JunosConfigDeploy

    def test_classes_implement_typed_interfaces(self) -> None:
        assert issubclass(JunosConfigRestore, ConfigRestoreCapability)
        assert issubclass(JunosConfigDeploy, ConfigDeployCapability)

    def test_cdp_not_accidentally_added(self) -> None:
        """Adding config-write must not accidentally add CDP (JunOS doesn't support it)."""
        assert Capability.NEIGHBORS_CDP not in JunosPlugin.capabilities


# ---------------------------------------------------------------------------
# Authorization: never self-authorize (ADR-0021 §2)
# ---------------------------------------------------------------------------


class TestNeverSelfAuthorizes:
    def test_restore_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigRestore(transport, device_id)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="approved", baseline_content_hash="x")
        with pytest.raises(PluginError, match="not 'executing'"):
            cap.restore(_SnapshotStub(_BASELINE), plan=plan)
        assert transport.replace_batches == []

    def test_deploy_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigDeploy(transport, device_id)
        plan = ChangePlan(
            change_request_id=uuid4(), cr_state="pending_approval", baseline_content_hash="x"
        )
        with pytest.raises(PluginError, match="not 'executing'"):
            cap.deploy(_FRAGMENT, plan=plan)
        assert transport.config_batches == []


# ---------------------------------------------------------------------------
# CONFIG_RESTORE
# ---------------------------------------------------------------------------


_DRIFTED = _BASELINE.replace("set system host-name juniper-mx01", "set system host-name WRONG")


class TestRestore:
    def test_restore_applies_and_verifies(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_DRIFTED)
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert result.applied_diff
        assert transport.commands.count(SHOW_CONFIGURATION_SET) >= 2
        assert transport.confirm_calls == 1  # Option A: confirm after verify
        assert cap.raw_outputs

    def test_restore_uses_replace_config(self, device_id: UUID) -> None:
        """JunOS restore apply surface must be replace_config (load override)."""
        transport = JunosConfigWriteFakeTransport(_DRIFTED)
        cap = JunosConfigRestore(transport, device_id)

        cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert transport.replace_batches  # replace called for apply
        assert transport.config_batches == []  # no merge calls

    def test_restore_empty_diff_is_noop(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert result.verified is True
        assert result.rollback is None
        assert transport.replace_batches == []

    def test_restore_verify_failure_rolls_back(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_DRIFTED)
        transport.corrupt_apply = True
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True
        assert transport.confirm_calls == 0  # Option A: never confirm bad change
        assert transport.rollback_calls == [1]  # permanent rollback N + commit

    def test_restore_apply_error_rolls_back(self, device_id: UUID) -> None:
        """Spec §5(d): a pre-apply transport failure on the restore path leaves no committed
        state and surfaces as ROLLED_BACK (commit-check / apply failure aborts cleanly)."""
        transport = JunosConfigWriteFakeTransport(_DRIFTED)
        transport.raise_on_apply = True
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True
        # Apply failed before commit confirmed — must NOT permanent rollback 1
        assert transport.rollback_calls == []

    def test_restore_apply_error_diverged_device_surfaces_rollback_failed(
        self, device_id: UUID
    ) -> None:
        """If apply fails before commit confirmed but running config already drifted,
        recovery cannot claim rolled_back without a permanent inverse (ADR-0021 §3)."""

        class _DivergedOnApplyFailTransport(JunosConfigWriteFakeTransport):
            def replace_config(self, lines: list[str]) -> str:
                self.replace_batches.append(list(lines))
                self._begin_write()
                # Mutate then raise — models a partial failure before confirmed commit.
                self._running = "set system host-name BROKEN-MID-APPLY\n"
                raise RuntimeError("JunOS commit check failed")

        transport = _DivergedOnApplyFailTransport(_DRIFTED)
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLBACK_FAILED
        assert result.outcome is not ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is False
        assert transport.rollback_calls == []  # no permanent rollback 1 on apply-fail

    def test_restore_junos_volatile_header_tolerated(self, device_id: UUID) -> None:
        """JunOS ``## Last commit:`` header does not defeat normalize equality."""
        snapshot_with_header = (
            "## Last commit: 2026-06-20 10:00:00 UTC by admin\n## version 23.1R1.8;\n"
        ) + _BASELINE

        class _HeaderTransport(JunosConfigWriteFakeTransport):
            def send_command(self, command: str) -> str:
                self.commands.append(command)
                if command == SHOW_CONFIGURATION_SET:
                    # Re-capture carries a different commit timestamp.
                    return (
                        "## Last commit: 2026-06-20 11:00:00 UTC by operator\n"
                        "## version 23.1R1.8;\n"
                    ) + self._running
                raise AssertionError(f"unexpected command: {command!r}")

        transport = _HeaderTransport(_DRIFTED)
        cap = JunosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(snapshot_with_header), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None


# ---------------------------------------------------------------------------
# CONFIG_DEPLOY
# ---------------------------------------------------------------------------


class TestDeploy:
    def test_deploy_applies_and_verifies(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert transport.config_batches
        assert transport.commands.count(SHOW_CONFIGURATION_SET) >= 2
        assert transport.confirm_calls == 1

    def test_deploy_uses_send_config_merge(self, device_id: UUID) -> None:
        """JunOS deploy apply surface must be send_config (load merge + commit confirmed)."""
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert transport.config_batches
        assert transport.replace_batches == []  # no replace in success path

    def test_deploy_empty_diff_is_noop(self, device_id: UUID) -> None:
        already = _BASELINE.rstrip("\n") + "\n" + _FRAGMENT
        transport = JunosConfigWriteFakeTransport(already)
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert transport.config_batches == []

    def test_deploy_verify_failure_rolls_back(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True
        assert transport.confirm_calls == 0
        assert transport.rollback_calls == [1]

    def test_deploy_rollback_uses_rollback_config(self, device_id: UUID) -> None:
        """JunOS failure path uses permanent rollback_config (not commit confirmed)."""
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = JunosConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert transport.config_batches  # merge apply
        assert transport.rollback_calls == [1]
        assert transport.replace_batches == []  # no second commit confirmed
        assert transport.confirm_calls == 0  # never confirm before structured rollback

    def test_deploy_apply_error_rolls_back(self, device_id: UUID) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        transport.raise_on_apply = True
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert transport.rollback_calls == []  # apply-fail: no permanent rollback 1


# ---------------------------------------------------------------------------
# Rollback-failed: never reported rolled_back (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestRollbackFailedNeverSilent:
    def test_deploy_rollback_failure_surfaces_rollback_failed(self, device_id: UUID) -> None:
        """Verify-fail path: permanent rollback_config lands wrong config → ROLLBACK_FAILED."""

        class _BrokenRollbackTransport(JunosConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                self._begin_write()
                # Apply "lands" a wrong end-state so verify-after fails (commit confirmed armed).
                present = self._running.splitlines()
                present_set = set(present)
                merged = present + [line for line in lines if line not in present_set]
                self._running = "\n".join(merged) + "\nset system host-name CORRUPT\n"
                return ""

            def rollback_config(self, n: int = 1) -> str:
                self.rollback_calls.append(n)
                self._running = "set system host-name BROKEN-AFTER-ROLLBACK\n"
                return ""

        transport = _BrokenRollbackTransport(_BASELINE)
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLBACK_FAILED
        assert result.outcome is not ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is False
        assert result.rollback.verified is False
        assert transport.rollback_calls == [1]

    def test_confirm_failure_after_verify_surfaces_structured_failure(
        self, device_id: UUID
    ) -> None:
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        transport.raise_on_confirm = True
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLBACK_FAILED
        assert result.verified is True  # end-state was correct
        assert result.rollback is not None
        assert result.rollback.attempted is False
        assert "confirm after verify failed" in (result.rollback.detail or "")
        assert transport.confirm_calls == 2  # initial + one retry


# ---------------------------------------------------------------------------
# Deploy residual-diff check (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestDeployResidualDiff:
    def test_residual_diff_fails_verify(self, device_id: UUID) -> None:
        class _ResidualDiffTransport(JunosConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                is_apply = self._begin_write()
                if is_apply:
                    # Drop an unrelated baseline line while landing the fragment.
                    merged = self._running.replace(
                        "set routing-options static route 0.0.0.0/0 next-hop 10.0.0.2\n", ""
                    )
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
        cap = JunosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is not ChangeOutcome.APPLIED
        assert result.verified is False
        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert transport.rollback_calls == [1]


# ---------------------------------------------------------------------------
# JunOS-specific: NO management-path guardrail (ADR-0026 §3.1)
# ---------------------------------------------------------------------------


class TestNoManagementPathGuardrail:
    """JunOS does NOT refuse management-path changes (ADR-0026 §3.1).

    Unlike ``cisco_ios`` and ``eos``, JunOS provides ``commit confirmed`` natively
    — the device auto-reverts at the timeout even if the worker loses the session
    (no EEM scripting, no OOB requirement). ADR-0026 §3.1 explicitly removes the
    ADR-0021 §4.2 management-path guardrail for JunOS. A vty / management-interface
    fragment must NOT be refused — it reaches the apply stage.
    """

    def test_deploy_allows_management_path_fragment(self, device_id: UUID) -> None:
        """A management-interface fragment is NOT refused by junos (unlike cisco_ios/eos)."""
        transport = JunosConfigWriteFakeTransport(_BASELINE)
        cap = JunosConfigDeploy(transport, device_id)

        # This fragment would be refused on cisco_ios/eos but NOT on JunOS.
        mgmt_fragment = "set interfaces fxp0 unit 0 family inet address 10.99.0.1/24\n"
        # No PluginError should be raised; the write reaches the apply stage.
        result = cap.deploy(mgmt_fragment, plan=_executing_plan())

        assert result.outcome in {
            ChangeOutcome.APPLIED,
            ChangeOutcome.NO_OP,
            ChangeOutcome.ROLLED_BACK,
        }
        # The key assertion: no management-path refusal; the write attempt happened.
        assert transport.config_batches or result.outcome is ChangeOutcome.NO_OP
