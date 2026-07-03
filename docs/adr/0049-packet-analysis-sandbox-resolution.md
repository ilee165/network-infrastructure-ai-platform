# ADR-0049: Packet-Analysis Sandbox Resolution — Executor-Split, Not a Weaker Worker

**Status:** Proposed | **Date:** 2026-07-03 | **Milestone:** Production audit 2026-07-01, Wave 3 (ARCH_DEBT #1)

> **Decision document only.** This ADR resolves the *design contradiction* the
> 2026-07-01 audit flagged (ARCH_DEBT #1). The implementation is deliberately
> out-of-wave — it lands in a dedicated follow-on wave after this ADR is
> Accepted (see **Owner & sequencing**). Nothing in audit Wave 3 changes the
> running packet-analysis behaviour; the service stays opt-in (default OFF)
> until the executor-split ships.

## Context

ADR-0031 (Accepted, P1 W3) gave the packet-capture path OS-level isolation: a
strict seccomp profile, `cap_drop: [ALL]`, non-root, read-only rootfs, no
egress, on a dedicated node pool. The driving threat is unchanged — **pcaps are
untrusted, remote-attacker-controlled input and tshark's C dissectors carry
memory-corruption CVEs** — so the sandbox exists to contain a *popped tshark
process*, not merely a hostile filename.

The contradiction ARCH_DEBT #1 names: that strict profile is **incompatible with
the Celery worker runtime it was applied to**. The packet worker is a Celery
consumer; it must hold a long-lived broker (Redis) connection and the socket /
`epoll` / futex syscalls that connection and Celery's prefork pool need. The
ADR-0031 seccomp allowlist — scoped to what a short-lived `tshark` invocation
needs — denies them. PR #86 patched the incidental blockers (tempdir,
`sem_open`, a batch of mount/`link` syscalls for runc ≥1.2) but explicitly
deferred the fundamental problem: **a process cannot be both a full Celery
consumer and a minimally-sandboxed capture executor.** The pragmatic triage was
to gate the whole service OFF (`profiles: ["packet"]` in compose, component-gated
in the Helm values, README marks it non-functional) so the quickstart boots.

That triage is correct but leaves two things wrong as a steady state:

1. A headline capability CLAUDE.md *requires* (tcpdump / tshark / Wireshark
   support) ships dark.
2. The platform's "secure by default" principle is inverted for this one
   component: the secure profile and the functional service are mutually
   exclusive, so operators who turn the service on do so by removing the
   sandbox, which is exactly backwards.

The audit offered two coherent resolutions:

- **(a) Executor-split** — a thin, *unsandboxed-but-privilege-light* dispatcher
  process stays the Celery consumer; each capture/dissection job is run in a
  short-lived **fully-seccomp'd child** (closest to ADR-0031's intent).
- **(b) Superseding ADR** — accept a *broader* seccomp allowlist for the worker
  process itself, with compensating controls (the dedicated node pool +
  NetworkPolicy already exist), and re-enable the service by default.

## Decision

**Adopt (a), the executor-split.** The sandbox boundary is drawn around the
untrusted work (parsing attacker-controlled pcap bytes in tshark's C
dissectors), **not** around the Celery machinery, which handles no untrusted
input:

- **Dispatcher (Celery consumer).** Stays a normal-ish worker process: it holds
  the broker connection, pulls `packet`-queue jobs, and owns the capture/analysis
  credential split and the process-launch controls already shipped in M5
  (argv-not-shell, filter whitelist, `-n`, hard timeout). It runs on the
  dedicated packet node pool with `cap_drop: [ALL]`, non-root, and the
  egress-deny NetworkPolicy — but with the *broader* syscall set Celery needs.
  It never itself parses pcap bytes.
- **Capture/dissection executor (short-lived child).** For each job the
  dispatcher spawns a fresh child that runs `tcpdump`/`tshark` under the strict
  ADR-0031 seccomp profile, `cap_drop: [ALL]` (or only `CAP_NET_RAW` for a live
  capture leg, dropped for offline pcap analysis), read-only rootfs, no egress,
  and a hard rlimit/timeout. The child is the blast-radius container: if a
  dissector is popped, the attacker lands in a process that is non-root, holds no
  capabilities, has no writable filesystem, has no network route out, and dies in
  seconds. The dispatcher reaps it and records the result.

This keeps ADR-0031's threat model intact (the strict profile still wraps the
tshark process) while removing the false choice between "secure" and
"functional." Option (b) is **rejected**: broadening the worker's own seccomp
allowlist widens exactly the surface ADR-0031 was written to narrow, and the
compensating controls it leans on (node pool, NetworkPolicy) are *lateral-movement*
controls, not a substitute for syscall confinement of the process that touches
untrusted bytes.

**End state:** once the executor-split ships and is test-pinned, the service is
re-enabled by default (secure by default restored). Until then it remains opt-in;
the opt-in default is the *interim* posture, not the accepted end state.

## Consequences

**Positive**

- Restores "secure by default" for packet analysis without weakening ADR-0031.
- The untrusted-input boundary is the short-lived child — the tightest possible
  sandbox scope, re-armed per job.
- Live-capture (`CAP_NET_RAW`) privilege is confined to the capture leg and
  dropped for offline analysis, further shrinking the standing privilege set.

**Negative / costs**

- Added complexity: a spawn/reap executor protocol, result marshalling between
  child and dispatcher, and a second (child) seccomp/pod profile to maintain.
- Two profiles to keep in lockstep with the existing compose/Helm seccomp
  lockstep CI gate; the child profile is the strict one, the dispatcher a
  documented broader one.
- Per-job process spawn has a latency/throughput cost vs. in-process dissection
  (acceptable: packet analysis is not a hot path).

**Neutral**

- No change to the process-launch controls or credential split already shipped.
- No migration; no API change. The change is runtime/topology + deploy manifests.

## Owner & sequencing

- **Owner:** a dedicated **"Packet-Analysis Executor-Split"** follow-on wave,
  scheduled after this ADR is Accepted (tracked in the audit
  `IMPLEMENTATION_WAVES.md` "Deliberately out-of-wave" table as
  "Packet-analysis implementation (post-ADR-0049)").
- **Roles (per repo build policy):** `wf-infra` for the child pod + seccomp
  profiles, the dispatcher pod spec, and the NetworkPolicy/node-pool wiring;
  `wf-implementer` for the dispatcher↔executor spawn/reap runtime and result
  marshalling. Both escalate to the strong model — this is a security-surface
  task touching the sandbox boundary (repo standing discipline).
- **Acceptance gate:** a security review (dual-strong, per repo policy) of this
  design before the wave is scheduled; the implementation wave then re-enables the
  service by default only once the child sandbox is test-pinned (unit + a live
  bite-proof that a denied syscall inside the child is actually killed).

## Alternatives considered

- **(b) Broader worker seccomp allowlist + compensating controls** — rejected
  (see Decision): widens the confinement of the process that parses untrusted
  input; node-pool/NetworkPolicy are lateral-movement controls, not syscall
  confinement.
- **Status quo (permanent opt-in, service dark)** — rejected: leaves a required
  capability unshipped and "secure by default" inverted with no path back.
- **Drop OS-level isolation, rely on process-launch controls only** — rejected:
  process-launch controls cannot contain a memory-corruption exploit *inside*
  tshark, which is the whole ADR-0031/ADR-0023 threat.

## References

- [ADR-0031](0031-packet-sandbox-os-isolation.md) — Packet Capture Sandbox
  OS-Level Isolation (the profile this ADR keeps intact).
- [ADR-0023] — packet-analysis containment split (process-launch vs OS-level).
- [ADR-0041](0041-collector-network-segmentation.md) — collector node
  pool + egress-deny NetworkPolicy (a compensating control, reused by the
  dispatcher tier).
- `docs/production-audit-2026-07-01/ARCHITECTURE_DEBT.md` §1 — the finding.
- PR #86 — the interim opt-in gate + seccomp/tempdir patches.
