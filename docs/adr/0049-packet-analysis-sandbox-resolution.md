# ADR-0049: Packet-Analysis Sandbox Resolution — Executor-Split, Not a Weaker Worker

**Status:** Accepted | **Date:** 2026-07-03 | **Accepted:** 2026-07-03 (dual-strong design review — see **Design review outcome**) | **Milestone:** Production audit 2026-07-01, Wave 3 (ARCH_DEBT #1)

> **Accepted; implementation in progress.** This ADR resolved the *design
> contradiction* the 2026-07-01 audit flagged (ARCH_DEBT #1). The dual-strong
> design-review acceptance gate passed on 2026-07-03 (both reviewers: *approach
> sound*), so the follow-on implementation wave is now scheduled and building on
> branch `feat/packet-executor-split`. The running packet-analysis service stays
> opt-in (default OFF) until the executor-split is **test-pinned by the Linux
> bite-proof** (see **Acceptance**); re-enable-by-default lands in the same PR
> the bite-proof is green at HEAD.

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
- **Dissection executor (short-lived child).** For each *analysis* job the
  dispatcher spawns a fresh `python -m app.engines.packet.executor` child that
  runs `tshark` under the strict ADR-0031 seccomp profile, `cap_drop: [ALL]`
  (**no** `CAP_NET_RAW` — the strict profile denies `socket()`, so a raw-capture
  leg cannot and must not run here; live capture stays in the separate
  `packet_capture` workload — see **Design review outcome** §6), read-only
  rootfs, no egress, and a hard rlimit/timeout. The child both dissects the pcap
  **and** normalizes the result (the `json.loads` of tshark's output +
  `summarize_packets` runs *inside* the sandbox), so the dispatcher only ever
  handles small, schema-shaped `PacketFindings` — never raw pcap-derived bytes.
  The child is the blast-radius process: if a dissector is popped, the attacker
  lands non-root, holds no capabilities, has no writable filesystem, holds no
  inherited socket or secret env, has no network route out, and dies in seconds.
  The dispatcher reaps it — killing the whole process group on timeout so no
  tshark grandchild outlives the bound — and records the validated result.

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

## Design review outcome (2026-07-03, dual-strong)

Per the acceptance gate below, two independent strong-model security reviewers
reviewed this design *before* the implementation wave was scheduled. Both
returned **approach sound** and converged on the confinement mechanism; the wave
proceeds with their blockers folded into the task specs. This section is the
build contract.

**Mechanism (agreed): a `pyseccomp` self-confining child.** The dispatcher spawns
`python -m app.engines.packet.executor`, which sets rlimits, `PR_SET_NO_NEW_PRIVS`,
and a libseccomp filter **parsed from the committed ADR-0031 JSON profile** (single
source of truth), self-verifies confinement, then runs `tshark` and normalizes
in-process. Rejected alternatives: `preexec_fn` (fork/thread-unsafe in the billiard
prefork worker — post-fork malloc deadlock); `nsjail`/`bwrap` (require namespace
creation that `cap_drop:[ALL]` + the container seccomp deliberately block); a per-job
K8s Job (fails the compose single-container constraint and needs an API token the pod
does not mount). This is the same "nested confinement (a)" path ADR-0031 §3's deferred
note already named as the preferred target.

**Blockers folded into the build (all must hold before re-enable-by-default):**

1. **Fail closed (CRITICAL).** The sandboxed-executor-vs-in-process choice is keyed
   ONLY on `packet_sandbox_posture_enforced` (default `True`), never on runtime
   detection. With enforcement on, any confinement-setup failure (pyseccomp import,
   rlimit, `PR_SET_NO_NEW_PRIVS`, filter load) aborts with `SandboxError` **before any
   pcap byte is opened**; the executor self-verifies `/proc/self/status` shows
   `Seccomp:\t2` and `NoNewPrivs:\t1` before spawning tshark, else refuses.
2. **Child env/fd hygiene (CRITICAL).** The child is spawned with `close_fds` (the live
   Redis/PG sockets must not cross into the blast radius) and an explicit minimal env
   allowlist (`PATH`, `TMPDIR`, `LANG`/`LC_*`) — no `NETOPS_*` secret material. Pinned
   by a test asserting the child sees only fds 0/1/2 and no `NETOPS_*` env.
3. **Single source of truth (MAJOR).** The executor programs its filter by parsing the
   committed strict JSON (packaged into the image via `importlib.resources`); the
   byte-lockstep CI gate is extended to every copy (compose, Helm, in-package) and to
   the new dispatcher-profile pair.
4. **Process-group timeout kill (MAJOR).** The dispatcher spawns with
   `start_new_session=True` and `os.killpg`s the group on timeout; the executor sets
   `PR_SET_PDEATHSIG=SIGKILL` on the tshark child plus an `RLIMIT_CPU` backstop — so a
   wedged/popped tshark grandchild cannot outlive the hard timeout (ADR-0023 §1).
5. **Dispatcher profile (MAJOR).** The analysis container's seccomp is swapped to an
   authored **deny-by-default dispatcher profile** (client sockets + `seccomp()`/
   `prctl()` allowed so the child can self-confine; `AF_PACKET`/`AF_NETLINK`-raw, `bpf`,
   `ptrace`, `mount`, `unshare`, `setns`, `keyctl` still denied) — never RuntimeDefault,
   never profile removal. conftest/OPA + lockstep gates are re-pointed to the new
   invariant, not deleted. Every other ADR-0031 control on the container is unchanged.
6. **Scope = analysis only (MAJOR).** This split covers the **analysis** workload
   (`packet_analysis` queue) only. The strict child profile denies `socket()`, so
   `tcpdump` cannot run under it and the child/container carry `CAP_NET_RAW` nowhere;
   live capture stays in the separate `packet_capture` workload/queue. This supersedes
   any earlier "CAP_NET_RAW live-capture leg" wording.
7. **Packaging (MAJOR).** `tshark` + `libseccomp`/`pyseccomp` (Linux-only marker,
   lockfile-pinned) are added to the **packet-analysis image/stage**, not the shared
   api/worker image (installing tshark's CVE-bearing C dissectors into the API image
   would widen *its* surface). A build-time `executor --self-check` fails the build on a
   missing wheel/library.
8. **Deny action (MINOR).** The child default action is `SCMP_ACT_KILL_PROCESS` if the
   live green-path passes (a denied syscall kills with `SIGSYS`); otherwise
   `SCMP_ACT_ERRNO` parity, with the gate re-worded to assert `EPERM` + nonzero exit.
   Pinned by the live test.

## Acceptance

A **Linux CI bite-proof**, three legs, green at HEAD before re-enable-by-default:
(1) **GREEN** — a real pcap through the fully confined executor returns schema-valid
`PacketFindings`; (2) **RED** — a `socket()`/`ptrace()` probe under identical
confinement is denied (SIGSYS-killed or EPERM+nonzero) **with a negative control**
(the same probe unconfined succeeds, proving the gate bites); (3) **TIMEOUT** — a
wedged child is killed with its whole process group (no orphan survives). The
Windows/SQLite unit suite cannot run seccomp, so this job runs on a Linux runner
alongside the existing PG-integration job and is required-when-run.

## Consequences

**Positive**

- Restores "secure by default" for packet analysis without weakening ADR-0031.
- The untrusted-input boundary is the short-lived child — the tightest possible
  sandbox scope, re-armed per job — and normalization runs inside it, so the
  dispatcher never parses attacker-derived bytes.
- No `CAP_NET_RAW` anywhere in the analysis tier: the child parses a *file*, never
  a socket. Live-capture privilege stays isolated in the separate `packet_capture`
  workload (ADR-0031 §1's physical split), so the analysis tier's standing
  privilege set is zero capabilities.

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
- **Residual — the synchronous API analyzer.** The `GET /captures/{id}/analysis`
  endpoint (the `get_pcap_analyzer` seam in `app/api/v1/agents.py`) parses the
  pcap **in-process in the API pod** — a pod that holds DB/JWT/KEK credentials
  plus egress and carries none of the strict controls above. It is therefore
  **fail-closed** when `packet_sandbox_posture_enforced` is on (the secure
  default): the endpoint raises an explicit typed 409 ("synchronous in-pod
  packet analysis is disabled; analysis runs only in the executor-confined
  `packet_analysis` worker") instead of invoking tshark. The shared api/worker
  image also ships **no tshark** (a guard test pins the Dockerfile stage
  split), closing the "just install tshark on the api pod" trap. Routing the
  endpoint through the analysis tier (enqueue → executor → stored findings) so
  it works AND stays confined is a scoped follow-up; until then synchronous
  in-pod analysis is disabled by design.

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
  design before the wave is scheduled — **passed 2026-07-03** (both reviewers
  *approach sound*; outcome + folded blockers recorded under **Design review
  outcome**). The implementation wave then re-enables the service by default only
  once the child sandbox is test-pinned (unit + the three-leg Linux **Acceptance**
  bite-proof, green at HEAD in the re-enable PR).

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
