"""Arista EOS CONFIG_RESTORE / CONFIG_DEPLOY + structured rollback (M5 task #6).

Mirrors the cisco_ios test contract (test_cisco_ios_config_change.py) with
EOS-specific differences:

- Config-session rollback: apply is done in a transient session
  (``configure session <name>``); on verify-after failure the session is
  ``abort``ed and the running config rolls back atomically. The structured
  rollback result still asserts equality with the captured baseline (the
  session abort should restore exactly the baseline).
- EOS ``show running-config`` does NOT emit the "Building configuration..."
  or "Current configuration : NNN bytes" preamble; instead it has a
  ``! Command: show running-config`` comment header. Normalization strips
  these EOS comment headers before equality comparison.
- No management-path guardrail pre-write: EOS config sessions are transactional
  (abort on failure), so there is no stranded-device risk on mid-apply failure.
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
from app.plugins.vendors.eos.plugin import (
    SHOW_RUNNING_CONFIG,
    EosConfigDeploy,
    EosConfigRestore,
    EosPlugin,
)

FIXTURES = Path(__file__).parent / "fixtures" / "eos"
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


_FRAGMENT = "interface Loopback0\n   description M5 eos test\n   ip address 10.255.0.3/32\n"


class EosConfigWriteFakeTransport:
    """In-memory ``ConfigWriteTransport`` modelling EOS config-session write surfaces.

    ``send_command('show running-config')`` returns the current config text.

    - ``send_config(lines)`` — MERGE: lines not already present are appended.
      Models an EOS configure-session commit (additive for deploy).
    - ``replace_config(lines)`` — REPLACE: the running config becomes exactly the
      applied lines. Models an EOS configure-session with the full baseline (restore
      apply + rollback path). On rollback the session is aborted and the running
      config is restored to the captured baseline.

    Failure injection flags:

    - ``corrupt_apply``: the first write records the lines but leaves the running
      config unchanged (verify-after fails); the rollback replace still applies.
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
            raise RuntimeError("EOS configure session commit failed")
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
        caps = EosPlugin.capabilities
        assert Capability.CONFIG_RESTORE in caps
        assert Capability.CONFIG_DEPLOY in caps

    def test_restore_and_deploy_resolve_to_distinct_classes(self) -> None:
        plugin = EosPlugin()
        assert plugin.get_capability(Capability.CONFIG_RESTORE) is EosConfigRestore
        assert plugin.get_capability(Capability.CONFIG_DEPLOY) is EosConfigDeploy
        assert EosConfigRestore is not EosConfigDeploy

    def test_classes_implement_typed_interfaces(self) -> None:
        assert issubclass(EosConfigRestore, ConfigRestoreCapability)
        assert issubclass(EosConfigDeploy, ConfigDeployCapability)

    def test_cdp_still_not_declared(self) -> None:
        """Adding config-write must not accidentally re-add CDP (EOS doesn't support it)."""
        assert Capability.NEIGHBORS_CDP not in EosPlugin.capabilities


# ---------------------------------------------------------------------------
# Authorization: never self-authorize (ADR-0021 §2)
# ---------------------------------------------------------------------------


class TestNeverSelfAuthorizes:
    def test_restore_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigRestore(transport, device_id)
        plan = ChangePlan(change_request_id=uuid4(), cr_state="approved", baseline_content_hash="x")
        with pytest.raises(PluginError):
            cap.restore(_SnapshotStub(_BASELINE), plan=plan)
        assert transport.replace_batches == []

    def test_deploy_refuses_non_executing_cr(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)
        plan = ChangePlan(
            change_request_id=uuid4(), cr_state="pending_approval", baseline_content_hash="x"
        )
        with pytest.raises(PluginError):
            cap.deploy("interface Loopback0\n   description test\n", plan=plan)
        assert transport.config_batches == []


# ---------------------------------------------------------------------------
# CONFIG_RESTORE
# ---------------------------------------------------------------------------


class TestRestore:
    def test_restore_applies_and_verifies(self, device_id: UUID) -> None:
        current = _BASELINE.replace("hostname leaf01", "hostname WRONG")
        transport = EosConfigWriteFakeTransport(current)
        cap = EosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert result.applied_diff
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2
        assert cap.raw_outputs

    def test_restore_uses_replace_config(self, device_id: UUID) -> None:
        """EOS restore apply surface must be replace_config (config session replace)."""
        current = _BASELINE.replace("hostname leaf01", "hostname WRONG")
        transport = EosConfigWriteFakeTransport(current)
        cap = EosConfigRestore(transport, device_id)

        cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert transport.replace_batches  # replace called for apply
        assert transport.config_batches == []  # no merge calls

    def test_restore_empty_diff_is_noop(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert result.verified is True
        assert result.rollback is None
        assert transport.replace_batches == []

    def test_restore_verify_failure_rolls_back(self, device_id: UUID) -> None:
        current = _BASELINE.replace("hostname leaf01", "hostname WRONG")
        transport = EosConfigWriteFakeTransport(current)
        transport.corrupt_apply = True
        cap = EosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True

    def test_restore_eos_comment_header_tolerated(self, device_id: UUID) -> None:
        """EOS ``! Command: show running-config`` comment header does not defeat equality."""
        # Snapshot has the comment header; re-capture also has it (possibly different date).
        snapshot_text = (
            "! Command: show running-config\n"
            "! device: leaf01 (DCS-7050TX-64, EOS-4.28.3M)\n!\n"
            "! boot system flash:/EOS-4.28.3M.swi\n!\n"
        ) + _BASELINE

        class _CommentHeaderTransport(EosConfigWriteFakeTransport):
            def send_command(self, command: str) -> str:
                self.commands.append(command)
                if command == SHOW_RUNNING_CONFIG:
                    # Re-capture carries a different device comment header.
                    return (
                        "! Command: show running-config\n"
                        "! device: leaf01 (DCS-7050TX-64, EOS-NEWER)\n!\n"
                    ) + self._running
                raise AssertionError(f"unexpected command: {command!r}")

        current = _BASELINE.replace("hostname leaf01", "hostname WRONG")
        transport = _CommentHeaderTransport(current)
        cap = EosConfigRestore(transport, device_id)

        result = cap.restore(_SnapshotStub(snapshot_text), plan=_executing_plan())

        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None


# ---------------------------------------------------------------------------
# CONFIG_DEPLOY
# ---------------------------------------------------------------------------


class TestDeploy:
    def test_deploy_applies_and_verifies(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert isinstance(result, ChangeResult)
        assert result.outcome is ChangeOutcome.APPLIED
        assert result.verified is True
        assert result.rollback is None
        assert transport.config_batches
        assert transport.commands.count(SHOW_RUNNING_CONFIG) >= 2

    def test_deploy_uses_send_config_merge(self, device_id: UUID) -> None:
        """EOS deploy apply surface must be send_config (session commit / merge)."""
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert transport.config_batches
        assert transport.replace_batches == []  # no replace in success path

    def test_deploy_empty_diff_is_noop(self, device_id: UUID) -> None:
        already = _BASELINE.rstrip("\n") + "\n" + _FRAGMENT
        transport = EosConfigWriteFakeTransport(already)
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.NO_OP
        assert transport.config_batches == []

    def test_deploy_verify_failure_rolls_back(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.verified is False
        assert result.rollback is not None
        assert result.rollback.succeeded is True
        assert result.rollback.verified is True

    def test_deploy_rollback_uses_replace_config(self, device_id: UUID) -> None:
        """EOS rollback (session abort/restore) must use replace_config for baseline equality."""
        transport = EosConfigWriteFakeTransport(_BASELINE)
        transport.corrupt_apply = True
        cap = EosConfigDeploy(transport, device_id)

        cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert transport.config_batches  # merge apply
        assert transport.replace_batches  # replace rollback

    def test_deploy_apply_error_rolls_back(self, device_id: UUID) -> None:
        transport = EosConfigWriteFakeTransport(_BASELINE)
        transport.raise_on_apply = True
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# Rollback-failed: never reported rolled_back (ADR-0021 §3)
# ---------------------------------------------------------------------------


class TestRollbackFailedNeverSilent:
    def test_deploy_rollback_failure_surfaces_failed(self, device_id: UUID) -> None:
        class _BrokenRollbackTransport(EosConfigWriteFakeTransport):
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
        cap = EosConfigDeploy(transport, device_id)

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
        class _ResidualDiffTransport(EosConfigWriteFakeTransport):
            def send_config(self, lines: list[str]) -> str:
                self.config_batches.append(list(lines))
                is_apply = self._begin_write()
                if is_apply:
                    # Drop an unrelated baseline line while landing the fragment.
                    merged = self._running.replace("ip route 0.0.0.0/0 10.0.0.2\n", "")
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
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome is not ChangeOutcome.APPLIED
        assert result.verified is False
        assert result.outcome is ChangeOutcome.ROLLED_BACK
        assert result.rollback is not None
        assert result.rollback.succeeded is True


# ---------------------------------------------------------------------------
# EOS: management-path changes ARE pre-refused (no armed dead-man revert)
# ---------------------------------------------------------------------------


class TestManagementPathRefusedOnEos:
    """The ADR-0021 §4.2 management-path guardrail applies to EOS.

    §4 sanctions relaxing the guardrail ONLY when the executor arms a device-side
    dead-man auto-revert (an EOS ``configure session`` + commit-timer) so a
    connectivity-severing change reverts even if the worker loses the session. No
    production transport implements that primitive (``SshTransport.replace_config``
    issues a plain ``configure replace <file> force`` with neither a config session
    nor a commit timer), so the compensating control does not exist. Until it does,
    a management-path change must be REFUSED before any device write — never
    silently strand the device.
    """

    def test_deploy_refuses_vty_fragment_eos(self, device_id: UUID) -> None:
        """A vty/transport fragment must be refused BEFORE any device write."""
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)

        fragment = "line vty 0 4\n   transport input ssh\n"
        with pytest.raises(PluginError, match="management path"):
            cap.deploy(fragment, plan=_executing_plan())

        # The guardrail fires BEFORE any write: no config/replace surface touched.
        assert transport.config_batches == []
        assert transport.replace_batches == []

    def test_deploy_refuses_mgmt_svi_ip_change_eos(self, device_id: UUID) -> None:
        """Adding/altering a management-SVI IP must be refused before any write."""
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)

        fragment = "interface Vlan99\n   ip address 10.9.9.9/24\n"
        with pytest.raises(PluginError, match="management path"):
            cap.deploy(fragment, plan=_executing_plan())

        assert transport.config_batches == []
        assert transport.replace_batches == []

    def test_deploy_allows_non_mgmt_fragment_eos(self, device_id: UUID) -> None:
        """A benign (non-mgmt) fragment is NOT refused — it reaches the apply stage."""
        transport = EosConfigWriteFakeTransport(_BASELINE)
        cap = EosConfigDeploy(transport, device_id)

        result = cap.deploy(_FRAGMENT, plan=_executing_plan())

        assert result.outcome in {
            ChangeOutcome.APPLIED,
            ChangeOutcome.NO_OP,
            ChangeOutcome.ROLLED_BACK,
        }
        assert transport.config_batches or result.outcome is ChangeOutcome.NO_OP
