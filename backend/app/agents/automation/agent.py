"""Automation Agent — sole executor of approved ChangeRequests (M5 task #9).

CLAUDE.md Core Agent #10 / M5-PLAN row #9. This is the single, most
security-critical executor in the project (M5-PLAN risk #1): the only component
that turns an *approved* :class:`~app.models.change_requests.ChangeRequest` into a
real device or DDI write. It is **not** a free-reasoning ReAct agent — letting a
model decide *whether* to apply a change would reintroduce the very write path the
ChangeRequest spine eliminates. Instead the write path is a deterministic,
server-gated method, :meth:`AutomationAgent.execute`, and the
:class:`~app.agents.framework.base.BaseSpecialistAgent` surface it exposes to the
supervisor carries only READ_ONLY narration tools (so a "change X" request routes
to *draft-a-CR*, never to direct execution — M5-PLAN risk #4).

Authority: ADR-0020 (CR state machine + four-eyes), ADR-0021 (config
deploy/restore + structured rollback), ADR-0022 (Infoblox DDI). The mandated
contract :meth:`execute` enforces:

* **Executes ONLY ``approved`` CRs.** Any other state — ``draft``,
  ``pending_approval``, a rejected CR (back in ``draft``), ``executing``,
  ``completed``, ``failed``, ``rolled_back`` — is refused with an audited
  :data:`~app.services.audit.service.AUTOMATION_EXECUTION_REFUSED`, no device/DDI
  write, and the CR state left untouched.
* **Drives the lifecycle through the CR service, never around it.** It claims
  ``approved -> executing`` via :meth:`ChangeRequestService.mark_executing` (which
  re-checks the state server-side and requires the verified
  :data:`~app.services.change_requests.AUTOMATION_PRINCIPAL`), then maps the
  executor's structured outcome onto ``completed`` / ``failed -> rolled_back``.
* **Never self-approves / never bypasses four-eyes.** It holds no path to
  :meth:`ChangeRequestService.approve`; the only route to ``approved`` is the
  service's primary four-eyes guard (approver != requester), enforced upstream.
* **Structured rollback per change.** On an apply/verify failure it marks the CR
  ``failed`` and, when the capability's structured rollback restored the baseline,
  ``rolled_back``; a rollback that could not reach the baseline leaves the CR
  ``failed`` and raises an operator-alert audit — never silently closed, never
  reported ``rolled_back`` (ADR-0021 §3).
* **A9 redaction at the LLM boundary.** Any config/DNS content surfaced to a model
  passes :func:`~app.llm.redaction.redact_prompt` (the narration tools); audit
  ``detail`` carries only redaction-safe summaries (applied-diff line counts,
  rollback notes), never the secret-bearing CR ``payload``.

The actual transport/plugin work is injected as executor ports
(:mod:`app.agents.automation.executors`); this agent opens no device session, no
WAPI client, and no plugin registry itself, mirroring the engine/agent separation
the rest of the platform keeps (REPO-STRUCTURE §3.2).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import structlog

from app.agents.automation.executors import (
    ConfigChangeExecutor,
    DdiChangeExecutor,
    DdiChangeResult,
)
from app.agents.automation.tools import AUTOMATION_TOOLS
from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool
from app.agents.framework.traces import (
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.core.errors import NetOpsError
from app.models.change_requests import (
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.plugins.base import (
    ChangeOutcome,
    ChangePlan,
    ChangeRequestDraft,
    ChangeResult,
)
from app.services.audit import service as audit
from app.services.change_requests import (
    AUTOMATION_PRINCIPAL,
    AutomationPrincipal,
    ChangeRequestService,
)

logger = structlog.get_logger(__name__)

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
AUTOMATION_NAME = "automation"

#: Terminal outcomes that complete the CR successfully (ADR-0021 §3).
_SUCCESS_OUTCOMES = frozenset({ChangeOutcome.APPLIED, ChangeOutcome.NO_OP})

#: Signature every CR-kind executor shares: ``(cr, trace) -> terminal state``.
_KindExecutor = Callable[["ChangeRequest", "ReasoningTrace"], Awaitable["ChangeRequestState"]]


class ChangeExecutionRefused(NetOpsError):
    """The Automation Agent refused to execute a CR it may not run.

    Two refusal reasons: the CR is not ``approved``, or its ``kind`` has no
    executor wired (e.g. ``security_remediation`` before its executor ships).

    Raised before any device/DDI write and before any lifecycle transition, so a
    refused CR's state is never touched (an unsupported-kind CR stays ``approved``
    and runs unchanged once an executor exists). The refusal is audited
    (:data:`~app.services.audit.service.AUTOMATION_EXECUTION_REFUSED`) before this
    is raised. ``409`` — the CR is in a state/kind from which execution is not legal.
    """

    status_code = 409
    title = "Change Execution Refused"
    slug = "change-execution-refused"


class ChangeExecutionResult:
    """The outcome of one :meth:`AutomationAgent.execute` call.

    Carries the CR's terminal lifecycle ``state`` (``completed`` / ``rolled_back``
    / ``failed``) and the reasoning-trace produced by the run, so the caller (the
    API/worker, Wave 5) can surface "I executed change request X" with a link to
    its explainable trace. Secret-free by construction.
    """

    __slots__ = ("state", "trace")

    def __init__(self, *, state: ChangeRequestState, trace: ReasoningTrace) -> None:
        self.state = state
        self.trace = trace


class AutomationAgent(BaseSpecialistAgent):
    """Sole executor of approved ChangeRequests (CLAUDE.md Core Agent #10).

    Construct with the :class:`ChangeRequestService` (the lifecycle owner) and the
    injected executor ports for the write paths it must drive — a
    :class:`ConfigChangeExecutor` for ``config`` CRs and/or a
    :class:`DdiChangeExecutor` for ``ddi_record`` CRs (each optional; a CR whose
    kind has no wired executor is failed rather than half-run). An optional
    :class:`TraceRecorder` captures the run's explainable trace and an optional
    :class:`AutomationPrincipal` (defaults to the verified
    :data:`AUTOMATION_PRINCIPAL`) is presented to the service's execution
    handoffs — a foreign principal cannot drive the lifecycle (ADR-0020 §2).
    """

    def __init__(
        self,
        *,
        change_request_service: ChangeRequestService | None = None,
        config_executor: ConfigChangeExecutor | None = None,
        ddi_executor: DdiChangeExecutor | None = None,
        trace_recorder: TraceRecorder | None = None,
        principal: AutomationPrincipal = AUTOMATION_PRINCIPAL,
    ) -> None:
        # ``change_request_service`` is REQUIRED to execute (the write path), but
        # OPTIONAL for the routing surface. The composition root
        # (:func:`app.agents.build_default_registry`) builds a routing-only agent
        # — its name/description/system_prompt/read-only tools — with no service
        # and no DB, exactly as the deterministic test suite does. ``execute``
        # guards a missing service so a routing-only agent can never write.
        self._service = change_request_service
        self._config_executor = config_executor
        self._ddi_executor = ddi_executor
        self._trace_recorder: TraceRecorder = (
            trace_recorder if trace_recorder is not None else InMemoryTraceRecorder()
        )
        self._principal = principal

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return AUTOMATION_NAME

    @property
    def description(self) -> str:
        return (
            "Executes already-approved change requests against the network: it is the "
            "sole executor that applies an approved config restore/deploy or DDI record "
            "change, verifies the result, and rolls back on failure. Route here ONLY to "
            "report on or trigger execution of a change request that a different user has "
            "already approved — never to author, modify, or approve a change. It does NOT "
            "draft change requests (the Configuration and DDI agents do that), does NOT "
            "approve them (that is the human four-eyes gate), and does NOT troubleshoot. A "
            "request to 'change' or 'fix' the network is NOT for this agent unless it names "
            "an approved change request to execute."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Automation Agent for an AI Network Operations Platform.\n\n"
            "You are the sole executor of approved change requests. You apply ONLY change "
            "requests that are already in the 'approved' state — never a draft, a "
            "pending-approval, a rejected, or an in-flight/finished change. You never "
            "approve a change yourself: approval is a separate human, four-eyes decision.\n\n"
            "Execution is deterministic and gated by the server: you claim an approved "
            "change request (approved -> executing), apply its reviewed payload verbatim, "
            "verify the result, and on any failure perform the structured rollback to the "
            "captured baseline (failed -> rolled_back). A rollback that cannot restore the "
            "baseline leaves the change failed and raises an operator alert — never report "
            "it as rolled back.\n\n"
            "Any config or DNS content you narrate is already redacted: secret values "
            "appear only as <<REDACTED:...>> tokens. Never ask for, infer, or reconstruct "
            "a redacted secret value.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """Read-only narration tools only — the write path is :meth:`execute`."""
        return AUTOMATION_TOOLS

    @property
    def trace_recorder(self) -> TraceRecorder:
        """The recorder a run's explainable trace is written to."""
        return self._trace_recorder

    # ------------------------------------------------------------------
    # The deterministic, server-gated execution path (NOT a model tool)
    # ------------------------------------------------------------------

    async def execute(self, cr_id: uuid.UUID) -> ChangeExecutionResult:
        """Execute the approved ChangeRequest *cr_id*, driving its full lifecycle.

        Refuses (audited, raising :class:`ChangeExecutionRefused`) any CR not in
        ``approved``. Otherwise: ``approved -> executing`` (via the service, which
        re-checks the state and the principal), apply the change via the matching
        executor port, then map its structured outcome onto ``completed`` or
        ``failed -> rolled_back`` (or ``failed`` + operator alert on
        rollback-failure). Returns the terminal state and the run's reasoning trace.

        Raises :class:`ChangeExecutionRefused` if this agent was built without a
        :class:`ChangeRequestService` (a routing-only instance from the
        composition root) — such an instance has no write path and refuses
        before touching any state.
        """
        if self._service is None:
            raise ChangeExecutionRefused(
                "this Automation Agent has no ChangeRequestService and cannot execute "
                "(it was built for routing only); construct it with a service to execute"
            )
        cr = await self._service.get(cr_id)
        trace = await self._trace_recorder.start(self.name)
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary=(
                    f"received change request {cr_id} (kind={cr.kind.value}, "
                    f"state={cr.state.value}) for execution"
                ),
            ),
        )

        if cr.state is not ChangeRequestState.APPROVED:
            await self._refuse(cr, trace)
            completed = await self._trace_recorder.complete(trace.trace_id)
            raise ChangeExecutionRefused(
                f"change request '{cr_id}' is '{cr.state.value}'; the Automation Agent "
                "executes only 'approved' change requests"
            )

        # Refuse a kind with no executor BEFORE claiming it (approved -> executing),
        # so an approved-but-unsupported CR never churns through executing -> failed.
        # It stays 'approved' and runs unchanged once its executor ships. The same
        # _executor_for map drives both this gate and _apply_and_finalize, so the
        # set of executable kinds has a single source of truth.
        if self._executor_for(cr.kind) is None:
            await self._refuse_unsupported_kind(cr, trace)
            await self._trace_recorder.complete(trace.trace_id)
            raise ChangeExecutionRefused(
                f"change request '{cr_id}' has kind '{cr.kind.value}', which has no "
                "executor wired; the Automation Agent cannot execute it"
            )

        # Claim the CR: approved -> executing. The service re-validates the state
        # AND the principal, so this is the second, server-side guard — a foreign
        # principal or a non-approved CR is rejected here too (ADR-0020 §2).
        await self._service.mark_executing(cr_id, principal=self._principal)
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary=f"claimed change request {cr_id}: approved -> executing",
            ),
        )

        # From here the CR is 'executing'; an escaping exception would strand it
        # there forever (execute() refuses non-'approved' CRs, and no reaper
        # exists), so any unexpected raise is converted into an audited
        # executing -> failed transition before propagating.
        try:
            final_state = await self._apply_and_finalize(cr, trace)
        except Exception as exc:
            await self._fail_unexpected(cr, trace, exc)
            raise
        completed = await self._trace_recorder.complete(trace.trace_id)
        return ChangeExecutionResult(state=final_state, trace=completed)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @property
    def _svc(self) -> ChangeRequestService:
        """Narrow ``self._service`` to non-None for internal call sites.

        All internal helpers are only reachable from :meth:`execute`, which
        raises :class:`ChangeExecutionRefused` before the internal helpers are
        ever called when ``self._service is None``.  This property exists so
        mypy can see the narrowing without scattering ``assert`` statements
        across every helper.
        """
        assert self._service is not None, (  # noqa: S101
            "_svc accessed with no ChangeRequestService wired; this is a bug — "
            "execute() should have raised ChangeExecutionRefused first"
        )
        return self._service

    async def _refuse(self, cr: ChangeRequest, trace: ReasoningTrace) -> None:
        """Audit the refusal of a non-``approved`` CR; performs no write."""
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=audit.AUTOMATION_EXECUTION_REFUSED,
                target_type="change_request",
                target_id=str(cr.id),
                detail={
                    "refused_state": cr.state.value,
                    "reason": "executor runs only 'approved' change requests",
                    "target_refs": cr.target_refs,
                },
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=(
                    f"refused change request {cr.id}: state '{cr.state.value}' is not "
                    "'approved'; no change was applied"
                ),
            ),
        )

    async def _refuse_unsupported_kind(self, cr: ChangeRequest, trace: ReasoningTrace) -> None:
        """Audit the refusal of an approved CR whose kind has no executor wired.

        Mirrors :meth:`_refuse` (same ``AUTOMATION_EXECUTION_REFUSED`` action) but
        for the kind-level gap rather than a non-approved state. Performs no write
        and no lifecycle transition — the CR is left ``approved``. The audit detail
        names the kind so an operator can see why an approved CR is not running.
        """
        reason = f"no executor wired for CR kind '{cr.kind.value}'"
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=audit.AUTOMATION_EXECUTION_REFUSED,
                target_type="change_request",
                target_id=str(cr.id),
                detail={"reason": reason, "kind": cr.kind.value, "target_refs": cr.target_refs},
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=(
                    f"refused change request {cr.id}: kind '{cr.kind.value}' has no executor "
                    "wired; no change was applied and the request stays 'approved'"
                ),
            ),
        )

    def _executor_for(self, kind: ChangeRequestKind) -> _KindExecutor | None:
        """The executor for *kind*, or ``None`` if the kind has no executor wired.

        Single source of truth for "which CR kinds are executable": both the
        :meth:`execute` pre-flight gate and :meth:`_apply_and_finalize` dispatch
        consult this map, so kind support cannot drift between the two (cubic
        PR #70). A kind absent here (e.g. ``security_remediation`` — drafted by the
        Security Agent in P2 W3, executor in a later wave) is refused before
        ``approved -> executing`` and never reaches a half-run.
        """
        return {
            ChangeRequestKind.CONFIG: self._execute_config,
            ChangeRequestKind.DDI_RECORD: self._execute_ddi,
        }.get(kind)

    async def _apply_and_finalize(
        self, cr: ChangeRequest, trace: ReasoningTrace
    ) -> ChangeRequestState:
        """Run the matching executor port and map its outcome onto the lifecycle."""
        executor = self._executor_for(cr.kind)
        if executor is None:
            # Defense-in-depth backstop: execute() already refuses a kind with no
            # executor BEFORE mark_executing, so this is unreachable via execute();
            # it stays the fail-closed guard for any other entry path — never a
            # half-run.
            return await self._fail_no_executor(
                cr, trace, reason=f"no executor wired for CR kind '{cr.kind.value}'"
            )
        return await executor(cr, trace)

    # -- config (CONFIG_RESTORE / CONFIG_DEPLOY) -----------------------------

    async def _execute_config(self, cr: ChangeRequest, trace: ReasoningTrace) -> ChangeRequestState:
        if self._config_executor is None:
            return await self._fail_no_executor(
                cr, trace, reason="no config executor wired for this run"
            )
        plan = ChangePlan(
            change_request_id=cr.id,
            cr_state=ChangePlan.EXECUTING_STATE,
            baseline_content_hash=_baseline_hash(cr.rollback_plan),
        )
        result = await self._config_executor.apply(cr, plan)
        await self._audit_applied_config(cr, result)
        return await self._finalize_from_outcome(
            cr,
            trace,
            outcome=result.outcome,
            after_state=_config_after_state(result),
            rollback_succeeded=(result.rollback.succeeded if result.rollback else False),
        )

    # -- DDI (Infoblox WAPI write) ------------------------------------------

    async def _execute_ddi(self, cr: ChangeRequest, trace: ReasoningTrace) -> ChangeRequestState:
        if self._ddi_executor is None:
            return await self._fail_no_executor(
                cr, trace, reason="no DDI executor wired for this run"
            )
        draft = _draft_from_payload(cr.payload)
        if draft is None:
            return await self._fail_no_executor(
                cr, trace, reason="CR payload is not a well-formed DDI change draft"
            )
        result = await self._ddi_executor.apply(cr, draft)
        await self._audit_applied_ddi(cr, result)
        outcome = _ddi_outcome(result)
        return await self._finalize_from_outcome(
            cr,
            trace,
            outcome=outcome,
            after_state=_ddi_after_state(result),
            rollback_succeeded=(result.rolled_back and result.rollback_verified),
        )

    # -- shared finalize -----------------------------------------------------

    async def _finalize_from_outcome(
        self,
        cr: ChangeRequest,
        trace: ReasoningTrace,
        *,
        outcome: ChangeOutcome,
        after_state: dict[str, Any],
        rollback_succeeded: bool,
    ) -> ChangeRequestState:
        """Map a structured :class:`ChangeOutcome` onto the CR lifecycle (ADR-0021 §3)."""
        if outcome in _SUCCESS_OUTCOMES:
            await self._svc.mark_completed(
                cr.id, principal=self._principal, after_state=after_state
            )
            await self._trace_recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.CONCLUSION,
                    summary=(
                        f"applied change request {cr.id}: executing -> completed ({outcome.value})"
                    ),
                ),
            )
            return ChangeRequestState.COMPLETED

        # Apply/verify failed: executing -> failed, then structured rollback.
        await self._svc.mark_failed(cr.id, principal=self._principal, after_state=after_state)
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.OBSERVATION,
                summary=f"apply failed for change request {cr.id} ({outcome.value}); rolling back",
            ),
        )

        if outcome is ChangeOutcome.ROLLED_BACK and rollback_succeeded:
            await self._audit_rollback(cr, succeeded=True)
            await self._svc.mark_rolled_back(cr.id, principal=self._principal)
            await self._trace_recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.CONCLUSION,
                    summary=f"rolled back change request {cr.id}: failed -> rolled_back",
                ),
            )
            return ChangeRequestState.ROLLED_BACK

        # Rollback could not reach the baseline (or was not attempted): the CR
        # stays 'failed' and an operator alert is raised — never silently closed,
        # never reported 'rolled_back' (ADR-0021 §3).
        await self._audit_rollback(cr, succeeded=False)
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=(
                    f"change request {cr.id} stays 'failed': rollback did not restore the "
                    "baseline — operator alert raised, NOT reported as rolled_back"
                ),
            ),
        )
        return ChangeRequestState.FAILED

    async def _fail_unexpected(
        self, cr: ChangeRequest, trace: ReasoningTrace, exc: Exception
    ) -> None:
        """Best-effort executing -> failed salvage when the executor raised unexpectedly.

        Mirrors :meth:`_fail_no_executor`'s fail-closed shape (mark failed +
        operator-alert audit + trace conclusion), but every salvage step is
        individually guarded: the original exception must propagate even when
        the DB itself is what failed, so a salvage error is logged and swallowed
        rather than allowed to mask the cause.
        """
        reason = f"unexpected {type(exc).__name__} during execution: {exc}"
        try:
            await self._svc.mark_failed(cr.id, principal=self._principal)
        except Exception:
            logger.exception(
                "failed to mark change request failed after unexpected executor error",
                change_request_id=str(cr.id),
            )
        try:
            async with self._svc.sessionmaker() as session:
                await audit.record(
                    session,
                    actor=self._principal.actor,
                    action=audit.AUTOMATION_ROLLBACK_FAILED,
                    target_type="change_request",
                    target_id=str(cr.id),
                    detail={"reason": reason, "target_refs": cr.target_refs},
                    reasoning_trace_id=cr.reasoning_trace_id,
                )
                await session.commit()
        except Exception:
            logger.exception(
                "failed to audit unexpected executor error",
                change_request_id=str(cr.id),
            )
        try:
            await self._trace_recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.CONCLUSION,
                    summary=f"change request {cr.id} marked 'failed': {reason}",
                ),
            )
            await self._trace_recorder.complete(trace.trace_id)
        except Exception:
            logger.exception(
                "failed to record trace for unexpected executor error",
                change_request_id=str(cr.id),
            )

    async def _fail_no_executor(
        self, cr: ChangeRequest, trace: ReasoningTrace, *, reason: str
    ) -> ChangeRequestState:
        """Mark an executing CR failed when no executor could apply it (fail closed)."""
        await self._svc.mark_failed(cr.id, principal=self._principal)
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=audit.AUTOMATION_ROLLBACK_FAILED,
                target_type="change_request",
                target_id=str(cr.id),
                detail={"reason": reason, "target_refs": cr.target_refs},
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()
        await self._trace_recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=f"change request {cr.id} stays 'failed': {reason}",
            ),
        )
        return ChangeRequestState.FAILED

    # -- audit helpers (redaction-safe details only) -------------------------

    async def _audit_applied_config(self, cr: ChangeRequest, result: ChangeResult) -> None:
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=audit.AUTOMATION_CHANGE_APPLIED,
                target_type="change_request",
                target_id=str(cr.id),
                detail={
                    "kind": cr.kind.value,
                    "outcome": result.outcome.value,
                    "verified": result.verified,
                    # applied_diff is a redaction-safe summary (line counts/markers),
                    # never raw config text (ADR-0021 §1 ChangeResult contract).
                    "applied_diff": list(result.applied_diff),
                    "target_refs": cr.target_refs,
                },
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()

    async def _audit_applied_ddi(self, cr: ChangeRequest, result: DdiChangeResult) -> None:
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=audit.AUTOMATION_CHANGE_APPLIED,
                target_type="change_request",
                target_id=str(cr.id),
                detail={
                    "kind": cr.kind.value,
                    "verified": result.verified,
                    "object_ref": result.object_ref,
                    "target_refs": cr.target_refs,
                },
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()

    async def _audit_rollback(self, cr: ChangeRequest, *, succeeded: bool) -> None:
        action = audit.AUTOMATION_ROLLBACK if succeeded else audit.AUTOMATION_ROLLBACK_FAILED
        async with self._svc.sessionmaker() as session:
            await audit.record(
                session,
                actor=self._principal.actor,
                action=action,
                target_type="change_request",
                target_id=str(cr.id),
                detail={
                    "kind": cr.kind.value,
                    "rollback_succeeded": succeeded,
                    "target_refs": cr.target_refs,
                },
                reasoning_trace_id=cr.reasoning_trace_id,
            )
            await session.commit()


# ---------------------------------------------------------------------------
# pure helpers (no I/O, secret-free)
# ---------------------------------------------------------------------------


def _baseline_hash(rollback_plan: dict[str, Any] | None) -> str | None:
    """Extract the audit-only baseline content hash from a CR rollback plan."""
    if not isinstance(rollback_plan, dict):
        return None
    value = rollback_plan.get("baseline_content_hash")
    return value if isinstance(value, str) else None


def _config_after_state(result: ChangeResult) -> dict[str, Any]:
    """Redaction-safe ``after_state`` for a config apply (ADR-0020 §4)."""
    return {
        "outcome": result.outcome.value,
        "verified": result.verified,
        "applied_diff": list(result.applied_diff),
    }


def _ddi_after_state(result: DdiChangeResult) -> dict[str, Any]:
    """Redaction-safe ``after_state`` for a DDI apply (ADR-0020 §4)."""
    return {
        "verified": result.verified,
        "object_ref": result.object_ref,
        "rolled_back": result.rolled_back,
    }


def _ddi_outcome(result: DdiChangeResult) -> ChangeOutcome:
    """Map a :class:`DdiChangeResult` onto the shared :class:`ChangeOutcome`."""
    if result.verified and not result.rolled_back:
        return ChangeOutcome.APPLIED
    if result.rolled_back and result.rollback_verified:
        return ChangeOutcome.ROLLED_BACK
    return ChangeOutcome.ROLLBACK_FAILED


def _draft_from_payload(payload: dict[str, Any] | None) -> ChangeRequestDraft | None:
    """Reconstruct the approved :class:`ChangeRequestDraft` from a CR payload.

    The CR ``payload`` is the draft an approver reviewed, frozen at submit
    (ADR-0020 §2). ``body``/``inverse.body`` ride as JSON lists of ``[key, value]``
    pairs; coerce them back to the tuple-of-tuples the model requires. Returns
    ``None`` for a payload that is not a well-formed draft (failed closed by the
    caller) rather than raising.
    """
    if not isinstance(payload, dict):
        return None
    try:
        return ChangeRequestDraft.model_validate(_coerce_draft(payload))
    except (ValueError, TypeError):
        return None


def _coerce_draft(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a JSON draft payload's ``body`` lists into tuple pairs, recursively.

    Also accepts legacy pre-D-SP1 payloads that used ``wapi_object`` instead of
    ``resource`` (the field was renamed when the model became vendor-neutral).
    ``wapi_object`` is silently aliased to ``resource`` so persisted CRs from
    before the rename remain executable.  Any other unrecognised keys are left in
    place; ``ChangeRequestDraft.model_validate`` (``extra="forbid"``) will reject
    them with a ``ValueError``, which ``_draft_from_payload`` catches and converts
    to a ``None`` (fail-closed).
    """
    coerced = dict(payload)
    # Backward-compat alias: pre-D-SP1 payloads stored the resource type under
    # ``wapi_object`` (the Infoblox WAPI terminology).  Prefer the current key;
    # only fall back to the legacy one when the current key is absent.  Always
    # drop ``wapi_object`` from the coerced dict: ChangeRequestDraft uses
    # ``extra="forbid"``, so any unrecognised key causes model_validate to raise.
    if "wapi_object" in coerced:
        if "resource" not in coerced:
            coerced["resource"] = coerced["wapi_object"]
        del coerced["wapi_object"]
    body = coerced.get("body")
    if isinstance(body, list):
        coerced["body"] = tuple(tuple(pair) for pair in body)
    inverse = coerced.get("inverse")
    if isinstance(inverse, dict):
        coerced["inverse"] = _coerce_draft(inverse)
    return coerced
