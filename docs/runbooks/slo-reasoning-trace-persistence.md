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
# Settlement boundary

The five-minute settled grace is the persistence lifecycle bound: trace header,
step appends, trace completion, and session completion commit independently.
It is grounded in the platform's five-minute first-token objective and prevents
reconciliation from observing those normal transaction seams. Exactly five
minutes old is settled; any younger row remains excluded.
