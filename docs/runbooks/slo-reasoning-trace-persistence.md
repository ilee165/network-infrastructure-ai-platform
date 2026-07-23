# Reasoning-trace persistence

Alert source: `NetopsReasoningTracePersistenceBurn`. Rerun the read-only scan
after confirming PostgreSQL is healthy. Inspect the three aggregate classes:
settled terminal sessions without traces, traces without sessions, and steps
without trace parents. The five-minute settled grace derives from the existing
first-token SLO and covers the separate short commits used for trace start,
step append, trace completion, and session completion.

Preserve trace and audit evidence. Do not delete an orphan to silence the alert;
capture affected identifiers in access-controlled incident evidence and
escalate to the agent-persistence owner.
