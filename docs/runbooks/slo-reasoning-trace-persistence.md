# Reasoning-trace persistence

Alert source: `NetopsReasoningTracePersistenceBurn`. Rerun the read-only scan
after confirming PostgreSQL is healthy. Inspect the three aggregate classes:
terminal sessions without traces, traces without sessions, and steps without
trace parents. A committed row is settled immediately: the recorder awaits each
trace transaction, and the session service awaits its terminal commit only after
the supervisor and recorder return.

Preserve trace and audit evidence. Do not delete an orphan to silence the alert;
capture affected identifiers in access-controlled incident evidence and
escalate to the agent-persistence owner.

# Settlement boundary

The settled grace is zero elapsed time. `PostgresTraceRecorder.start`,
`record_step`, and `complete` each await their PostgreSQL commit; then
`AgentSessionService.run` awaits the terminal session commit after the supervisor
returns. No background trace-persistence retry or deferred task remains after
that boundary. The daily reconciliation schedule determines how soon corruption
is detected, while the separate first-token SLO measures model responsiveness
and does not bound persistence settlement.
