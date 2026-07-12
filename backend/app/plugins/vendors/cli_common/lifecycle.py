"""Shared ADR-0021 config-write lifecycle for CLI vendors (Wave 3 T4).

:class:`CliConfigWriteMixin` hosts the capture → apply → verify-after →
confirm → rollback engine that was duplicated across Cisco-family plugins.
Vendor classes supply:

- ``vendor_label`` — error prefix (e.g. ``cisco_ios``)
- ``_show_running_command`` — capture command string
- optional ``_reject_management_path`` (classic IOS)
- optional ``_after_verified`` (JunOS confirming commit; default calls
  ``confirm_config``)
- optional ``_recover_apply_failure`` / ``_rollback_to_baseline`` overrides

Cisco-family: apply is permanent, so ``confirm_config`` is a no-op on the
transport. JunOS (Option A): apply ends at ``commit confirmed``; confirm runs
after verify-after success.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    ChangeOutcome,
    ChangePlan,
    ChangeResult,
    ConfigWriteTransport,
    PluginCapability,
    RollbackResult,
)

__all__ = ["CliConfigWriteMixin"]


class CliConfigWriteMixin(PluginCapability):
    """ADR-0021 §3 write lifecycle shared by CLI vendor config capabilities."""

    #: Prefix for typed PluginError messages (``cisco_ios``, ``eos``, …).
    vendor_label: ClassVar[str] = "cli"

    #: Device command used to capture the running/committed config.
    _show_running_command: ClassVar[str] = "show running-config"

    def __init__(self, transport: ConfigWriteTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def _capture_running(self) -> str:
        """Capture the live config verbatim (recorded for audit)."""
        cmd = self._show_running_command
        return self._record_raw(cmd, self._transport.send_command(cmd))

    def _send_config(self, lines: list[str]) -> None:
        """Merge *lines* (deploy apply surface); record verbatim device output."""
        output = self._transport.send_config(lines)
        self._record_raw("configure terminal\n" + "\n".join(lines), output)

    def _replace_config(self, lines: list[str]) -> None:
        """Replace running config with *lines* (restore/rollback surface)."""
        output = self._transport.replace_config(lines)
        self._record_raw("configure replace\n" + "\n".join(lines), output)

    def _require_executing(self, plan: ChangePlan, operation: str) -> None:
        """Refuse the write unless the plan attests an ``executing`` CR."""
        if not plan.is_executing:
            raise PluginError(
                f"{self.vendor_label}: {operation} refused — change request "
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

    def _reject_management_path(self, operation: str, baseline: str, end_state: str) -> None:
        """Optional guardrail; classic IOS overrides. Default: no-op."""

    def _normalize_captured(self, raw: str) -> str:
        """Normalize a captured config for equality. Subclasses must implement."""
        raise NotImplementedError(f"{type(self).__name__} must implement _normalize_captured")

    def _after_verified(self) -> None:
        """Hook after verify-after success — default: transport ``confirm_config``."""
        self._transport.confirm_config()

    def _execute(
        self,
        *,
        plan: ChangePlan,
        operation: str,
        project: Callable[[str], str],
        config_lines: list[str],
        apply: Callable[[list[str]], None],
    ) -> ChangeResult:
        """Run the ADR-0021 §3 contract and return a structured :class:`ChangeResult`."""
        self._require_executing(plan, operation)

        baseline = self._normalize_captured(self._capture_running())
        end_state = project(baseline)

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
        except Exception:  # noqa: BLE001 — any apply failure triggers recovery
            apply_failed = True

        verified = False
        if not apply_failed:
            after = self._normalize_captured(self._capture_running())
            verified = after == end_state

        if verified:
            try:
                self._after_verified()
            except Exception:  # noqa: BLE001 — one retry then structured failure
                try:
                    self._after_verified()
                except Exception as exc:  # noqa: BLE001
                    return ChangeResult(
                        change_request_id=plan.change_request_id,
                        outcome=ChangeOutcome.ROLLBACK_FAILED,
                        verified=True,
                        applied_diff=applied_diff,
                        rollback=RollbackResult(
                            attempted=False,
                            succeeded=False,
                            verified=False,
                            detail=(
                                f"confirm after verify failed ({type(exc).__name__}); "
                                "device may remain in an unconfirmed state"
                            ),
                        ),
                    )
            return ChangeResult(
                change_request_id=plan.change_request_id,
                outcome=ChangeOutcome.APPLIED,
                verified=True,
                applied_diff=applied_diff,
                rollback=None,
            )

        if apply_failed:
            rollback = self._recover_apply_failure(baseline)
        else:
            rollback = self._rollback_to_baseline(baseline)
        outcome = ChangeOutcome.ROLLED_BACK if rollback.succeeded else ChangeOutcome.ROLLBACK_FAILED
        return ChangeResult(
            change_request_id=plan.change_request_id,
            outcome=outcome,
            verified=False,
            applied_diff=applied_diff,
            rollback=rollback,
        )

    def _recover_apply_failure(self, baseline_normalized: str) -> RollbackResult:
        """Default apply-fail recovery for permanent-apply vendors (Cisco-family).

        Replays the baseline via :meth:`_rollback_to_baseline` (configure replace).
        JunOS Option A overrides this to re-assert baseline **without** permanent
        ``rollback 1`` when ``commit confirmed`` never landed.
        """
        return self._rollback_to_baseline(baseline_normalized)

    def _rollback_to_baseline(self, baseline_normalized: str) -> RollbackResult:
        """Replace the device with the captured baseline and verify equality."""
        try:
            self._replace_config(baseline_normalized.splitlines())
            after = self._normalize_captured(self._capture_running())
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
