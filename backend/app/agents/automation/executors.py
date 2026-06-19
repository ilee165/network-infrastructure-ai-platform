"""Executor ports for the Automation Agent (M5 task #9; ADR-0020 §1, ADR-0021/0022).

The Automation Agent is the *sole executor* of an ``approved`` ChangeRequest, but
it must not couple to a transport, a netmiko/WAPI session, or the plugin registry
directly — those live behind the engine/plugin layer and are wired by the worker
/ API composition root (M5 Wave 5). Mirroring how the Configuration Agent receives
its server-computed drift/compliance inputs injected, the Automation Agent
receives two **executor ports** as constructor dependencies:

* :class:`ConfigChangeExecutor` — turns an ``executing`` config CR into a real
  ``CONFIG_RESTORE``/``CONFIG_DEPLOY`` apply via the vendor plugin capability,
  returning the plugin's structured :class:`~app.plugins.base.ChangeResult`
  (applied diff, verify-after, structured rollback outcome). The port builds the
  :class:`~app.plugins.base.ChangePlan` that attests the ``executing`` state — the
  capability refuses to run otherwise (ADR-0021 §2), so the executor never
  self-authorizes.
* :class:`DdiChangeExecutor` — turns an ``executing`` DDI CR's
  :class:`~app.plugins.base.ChangeRequestDraft` into a real ``WapiClient`` write,
  re-reads the object to verify, and on failure applies the draft's ``inverse``
  as the structured rollback (ADR-0022 §3). It returns a :class:`DdiChangeResult`.

Both ports are :class:`Protocol`\\ s: the production implementations (which open
the device session / WAPI client and resolve the plugin from the registry) are
wired in Wave 5; the unit tests inject scripted fakes. The Automation Agent maps
each port's structured outcome onto the ChangeRequest lifecycle (ADR-0020 §1) and
performs no transport I/O itself.

Security: neither a result type nor this module ever carries a secret. A
:class:`~app.plugins.base.ChangeResult` already exposes only a redaction-safe
applied-diff summary (line counts/markers); :class:`DdiChangeResult` carries the
verified object ``_ref`` (never a credential) and the rollback flag only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.models.change_requests import ChangeRequest
from app.plugins.base import ChangePlan, ChangeRequestDraft, ChangeResult


class DdiChangeResult(BaseModel):
    """Structured outcome of one DDI (Infoblox WAPI) write attempt (ADR-0022 §3).

    The DDI analogue of :class:`~app.plugins.base.ChangeResult`: it records whether
    the post-write re-read verified the intended end-state, the (non-secret) object
    ``_ref`` the write produced/targeted, and — when the apply/verify failed and
    the draft's ``inverse`` was applied — whether the structured rollback restored
    the prior state. Frozen and secret-free: ``object_ref`` is an opaque WAPI
    handle, never a credential.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verified: bool = Field(
        description="Whether the post-write re-read confirmed the intended end-state."
    )
    object_ref: str | None = Field(
        default=None,
        description="Opaque WAPI _ref of the written/targeted object; never a secret.",
    )
    rolled_back: bool = Field(
        default=False,
        description="True when apply/verify failed and the inverse draft restored the prior state.",
    )
    rollback_attempted: bool = Field(
        default=False,
        description="Whether a structured rollback (inverse draft) was attempted.",
    )
    rollback_verified: bool = Field(
        default=False,
        description="Whether the post-rollback re-read confirmed the restored prior state.",
    )
    detail: str | None = Field(
        default=None,
        description="Human-readable note; never carries DDI record secrets or credentials.",
    )

    @property
    def succeeded(self) -> bool:
        """Whether the write verified its intended end-state (no rollback needed)."""
        return self.verified and not self.rolled_back


@runtime_checkable
class ConfigChangeExecutor(Protocol):
    """Applies a config CR to a device via a ``CONFIG_RESTORE``/``CONFIG_DEPLOY`` capability.

    The implementation (Wave 5) resolves the vendor plugin from the registry,
    opens the device session, captures the fresh pre-change baseline, applies the
    change, verifies, and on failure runs the vendor-native structured rollback —
    returning the plugin's :class:`~app.plugins.base.ChangeResult`. It is handed
    the persisted :class:`ChangeRequest` (for ``payload``/``target_refs``) and the
    :class:`~app.plugins.base.ChangePlan` the Automation Agent built attesting the
    ``executing`` state, which the capability requires (ADR-0021 §2).
    """

    async def apply(self, cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
        """Apply the config change described by *cr* under *plan*; return its result."""
        ...


@runtime_checkable
class DdiChangeExecutor(Protocol):
    """Applies a DDI CR to the appliance via a ``WapiClient`` write (ADR-0022 §3).

    The implementation (Wave 5) materializes the WAPI credentials in-process,
    applies the draft's ``verb``/``body`` against the target ``_ref``, re-reads to
    verify, and on failure applies the draft's ``inverse`` as the structured
    rollback. It is handed the persisted :class:`ChangeRequest` and the
    :class:`~app.plugins.base.ChangeRequestDraft` reconstructed from the CR's
    approved ``payload`` (frozen at submit), returning a :class:`DdiChangeResult`.
    """

    async def apply(self, cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
        """Apply the DDI change described by *draft*; return its result."""
        ...


__all__ = [
    "ConfigChangeExecutor",
    "DdiChangeExecutor",
    "DdiChangeResult",
]
