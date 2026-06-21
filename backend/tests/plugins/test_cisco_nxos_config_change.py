"""cisco_nxos CONFIG_RESTORE / CONFIG_DEPLOY rollback mechanism (ADR-0025 §5).

These tests pin the *mechanism* of the NX-OS config-write path, closing the
finding that nothing verified what rollback actually issues. ADR-0025 §5's
binding decision is realized here as a ``configure replace`` baseline replay
(the same tier as ``cisco_ios``): the :class:`ConfigWriteTransport` exposes no
NX-OS named-checkpoint primitive, so the path never issues ``checkpoint`` or
``rollback running-config checkpoint``. The tests assert exactly that — the
write surfaces used are ``send_command`` / ``send_config`` / ``replace_config``
and no checkpoint CLI is ever sent — and that rollback returns a structured,
verified :class:`RollbackResult`.

No device, no network (D16): an in-memory transport models the write surfaces.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.plugins.base import (
    ChangeOutcome,
    ChangePlan,
    ConfigWriteTransport,
)
from app.plugins.vendors.cisco_nxos.plugin import (
    SHOW_RUNNING_CONFIG,
    CiscoNxosConfigDeploy,
    CiscoNxosConfigRestore,
    _management_path_hits,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_nxos"
_BASELINE = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")

_FRAGMENT = "interface loopback0\n description nxos config-change test\n"

#: CLI verbs that would indicate the rejected NX-OS named-checkpoint mechanism.
_CHECKPOINT_TOKENS = ("checkpoint", "rollback running-config")


class _ConfigWriteFakeTransport:
    """In-memory ``ConfigWriteTransport`` recording every command/surface used.

    ``send_command`` returns the running config; ``send_config`` MERGES;
    ``replace_config`` REPLACES. ``corrupt_apply`` makes the first write not
    land (verify-after fails) so the rollback (configure replace) fires.
    """

    def __init__(self, running: str) -> None:
        self._running = running
        self.commands: list[str] = []
        self.config_batches: list[list[str]] = []
        self.replace_batches: list[list[str]] = []
        self.corrupt_apply = False
        self._writes = 0

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if command == SHOW_RUNNING_CONFIG:
            return self._running
        raise AssertionError(f"unexpected command sent to device: {command!r}")

    def _is_apply(self) -> bool:
        self._writes += 1
        return self._writes == 1

    def send_config(self, lines: list[str]) -> str:
        self.config_batches.append(list(lines))
        if self._is_apply() and self.corrupt_apply:
            return ""
        present = self._running.splitlines()
        present_set = set(present)
        merged = present + [line for line in lines if line not in present_set]
        self._running = "\n".join(merged) + "\n"
        return ""

    def replace_config(self, lines: list[str]) -> str:
        self.replace_batches.append(list(lines))
        if self._is_apply() and self.corrupt_apply:
            return ""
        self._running = "\n".join(lines) + "\n"
        return ""


@pytest.fixture()
def device_id() -> UUID:
    return uuid4()


def _executing_plan() -> ChangePlan:
    return ChangePlan(
        change_request_id=uuid4(), cr_state="executing", baseline_content_hash="sha-baseline"
    )


class _SnapshotStub:
    def __init__(self, content: str) -> None:
        self.content = content
        self.content_hash = "sha-snapshot"


def _no_checkpoint_command_issued(transport: _ConfigWriteFakeTransport) -> bool:
    """No ``checkpoint`` / ``rollback running-config checkpoint`` CLI was sent."""
    every_token = [
        token
        for command in transport.commands
        for token in (command.lower(),)
        if any(verb in command.lower() for verb in _CHECKPOINT_TOKENS)
    ]
    return not every_token


def test_transport_exposes_no_checkpoint_primitive() -> None:
    """The write transport protocol has no checkpoint/rollback-checkpoint surface.

    The named-checkpoint mechanism ADR-0025 §5 narrates cannot be issued because
    the transport contract does not expose it — rollback is configure-replace.
    """
    surfaces = set(dir(ConfigWriteTransport))
    assert "checkpoint" not in surfaces
    assert "rollback" not in surfaces
    assert "send_config" in surfaces
    assert "replace_config" in surfaces


def test_deploy_rollback_uses_configure_replace_not_checkpoint(device_id: UUID) -> None:
    transport = _ConfigWriteFakeTransport(_BASELINE)
    transport.corrupt_apply = True  # apply does not land -> rollback fires
    cap = CiscoNxosConfigDeploy(transport, device_id)

    result = cap.deploy(_FRAGMENT, plan=_executing_plan())

    assert result.outcome is ChangeOutcome.ROLLED_BACK
    assert result.rollback is not None
    assert result.rollback.succeeded is True
    assert result.rollback.verified is True
    # Rollback fired via the configure-replace surface (baseline replay)...
    assert transport.replace_batches, "rollback must issue a configure replace"
    # ...and never via a named-checkpoint CLI command.
    assert _no_checkpoint_command_issued(transport)


def test_restore_rollback_uses_configure_replace_not_checkpoint(device_id: UUID) -> None:
    # Device drifted on a non-management line so the restore applies; the apply
    # is corrupted so verify-after fails and the baseline replay rolls back.
    drifted = _BASELINE.replace("hostname nxos-spine01", "hostname DRIFTED")
    transport = _ConfigWriteFakeTransport(drifted)
    transport.corrupt_apply = True
    cap = CiscoNxosConfigRestore(transport, device_id)

    result = cap.restore(_SnapshotStub(_BASELINE), plan=_executing_plan())

    assert result.outcome is ChangeOutcome.ROLLED_BACK
    assert result.rollback is not None
    assert result.rollback.succeeded is True
    assert transport.replace_batches, "rollback must issue a configure replace"
    assert _no_checkpoint_command_issued(transport)


# ---------------------------------------------------------------------------
# Regression tests: management-path guardrail — removed child under unchanged
# section header must still be detected (ADR-0021 §4.2).
# ---------------------------------------------------------------------------


def test_mgmt_path_hits_detects_removed_ip_address_under_unchanged_interface_header() -> None:
    """Removing 'ip address' under an unchanged 'interface mgmt0' header must be detected.

    Regression test for the guardrail bug where removed_lines did not include
    the unchanged parent section header, so in_mgmt_interface context was never
    set and the child ip-address removal bypassed rejection.
    """
    baseline = (
        "hostname nxos-spine01\ninterface mgmt0\n  ip address 192.168.1.1/24\n  no shutdown\n"
    )
    # Remove the ip address line, leave the interface mgmt0 header unchanged.
    end_state = "hostname nxos-spine01\ninterface mgmt0\n  no shutdown\n"
    hits = _management_path_hits(baseline, end_state)
    assert hits, "removing 'ip address' under 'interface mgmt0' must be a management-path hit"
    assert any("ip address" in h for h in hits), (
        f"expected an 'ip address' reason in hits, got: {hits!r}"
    )


def test_mgmt_path_hits_unchanged_child_not_flagged() -> None:
    """A child line present in both baseline and end_state is not flagged.

    Sanity-check: an interface mgmt0 block that is entirely unchanged produces
    no management-path hits (the delta is empty).
    """
    config = "hostname nxos-spine01\ninterface mgmt0\n  ip address 192.168.1.1/24\n  no shutdown\n"
    hits = _management_path_hits(config, config)
    assert hits == (), f"identical baseline and end_state must yield no hits, got: {hits!r}"


def test_mgmt_path_hits_vrf_management_removal_detected() -> None:
    """Removing a route inside 'vrf context management' is a management-path hit."""
    baseline = "vrf context management\n  ip route 0.0.0.0/0 192.168.1.254\n"
    end_state = "vrf context management\n"
    hits = _management_path_hits(baseline, end_state)
    assert hits, (
        "removing a child line under 'vrf context management' must be a management-path hit"
    )
