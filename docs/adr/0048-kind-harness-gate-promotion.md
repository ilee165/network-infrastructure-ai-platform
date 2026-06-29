# ADR-0048: kind-harness Gate Promotion — mTLS-Handshake + Collector-Egress-Deny Live Assertions → Blocking in `all-gates`

**Status:** Proposed | **Date:** 2026-06-29 | **Milestone:** P3 W0

## Context

P2-Security shipped two security controls whose **live enforcement** is validated
on the ephemeral in-CI kind cluster (`docs/runbooks/kind-harness.md`, ADR-0039 §6,
ADR-0041 §2/§3):

1. **mTLS api/worker↔postgres** — a valid-cert client handshakes; a plaintext or
   wrong-CA client is **refused** (ADR-0039 §3/§6).
2. **Collector default-deny egress NetworkPolicy** — an allowed egress (mgmt subnet
   / named service) succeeds; an arbitrary external egress is **blocked** on an
   enforcing-CNI cluster (ADR-0041 §3).

At P2-Security exit these two **live** assertions were recorded **PARTIAL /
deferred-accepted** (`P2-RELEASE-READINESS.md` §2 G-SEC, §3, §5 item 5;
`PRODUCTION.md` §1 P2-exit marker + §11 G-SEC): their **render / static /
harness-invariant** layers bite and are blocking (the `infra` job's render-twice L4
guard, the `kind-harness` job's static `validate-harness.sh` + assertion-library
self-tests + `extract_secret.py` tests), but the **live** `kind-harness.sh`
enforcement run is `continue-on-error: true` (`.github/workflows/ci.yml` step
`harness`, ~ln 782) and the `kind-harness` job is **deliberately absent** from the
`all-gates` required aggregator's `needs` list (`.github/workflows/ci.yml` job
`all-gates`, `needs:` ~ln 1135; the DELIBERATE OMISSION comment ~ln 1122). So a
**live**-enforcement regression — async plaintext silently admitted, NetworkPolicy
removed — does **not** currently turn any required check red.

The reason it was not promoted at P2 is **P1-W4-LESSONS L1**: a new gating CI tool
must be validated **locally** before it is made required, and the kind/CNI live path
could not run on the P2 authoring host (Windows, no Docker/Linux kind). The W5-T3
release auditor reviewed this and **re-deferred** promotion to P3-Platform
(`P2-RELEASE-READINESS.md` §5 item 5; `docs/runbooks/kind-harness.md` "Gate status").
`PRODUCTION.md` §1 records "promotion of the kind-harness live-enforcement run to a
blocking gate" as explicit **P3-Platform inheritance**, and P3-PLATFORM-PLAN §1
(Gate promotion row) / §5 (W4 "Gate promotion") make it a P3 deliverable (build =
**W4-T2**, on the **W4-T1** HA kind topology).

This ADR is the **design gate** that ratifies *that* promotion: which CI steps move,
the prerequisites that must hold first, and the prove-it-bites requirement. It does
**not** implement the change (build = W4-T2) and adds **no new security claim** — it
only flips two already-built, already-rendered controls from signal-only to biting.

Bounded by ADR-0039 (mTLS api/worker↔pg), ADR-0041 (collector egress NetworkPolicy),
ADR-0016 (D16 testing & CI/CD — the `all-gates` aggregator model), ADR-0047 + W4-T1
(the reliable enforcing-CNI HA kind topology this gate runs on).

## Decision

**Promote the P2 kind-harness *live-enforcement* run to a blocking member of
`all-gates`: the mTLS handshake + plaintext-refused assertion and the collector
default-deny egress assertion become biting gates. Promotion is gated on two
prerequisites — a reliable enforcing-CNI kind topology (W4-T1) and a demonstrated
prove-it-bites on a planted regression — and on updating `docs/runbooks/kind-harness.md`
to record the new blocking status. Promote the two named P2 sub-items only; no new
security claim is introduced.**

### 1. Promote, don't widen — exactly the two P2 sub-items

Only the two controls already recorded PARTIAL at P2-Security exit move to blocking:

- **mTLS api/worker↔postgres** — handshake OK + plaintext/wrong-CA refused
  (ADR-0039 §3/§6; `P2-RELEASE-READINESS.md` §2 G-SEC mTLS line).
- **Collector default-deny egress** — allowed egress succeeds, arbitrary external
  egress blocked, on an enforcing CNI (ADR-0041 §3; `P2-RELEASE-READINESS.md` §2
  G-SEC collector line).

No other live assertion, no new claim, no scope widening. The assertions are the
ones already plugged into the runner via `ci/kind/assertions/checks/` (W4-T4
`mtls-*.sh`, W4-T5 `collector-egress*.sh` — `docs/runbooks/kind-harness.md`).

### 2. The exact CI change W4-T2 makes (named, two edits)

The promotion is the two edits the runbook already names ("Gate status — how to
promote it"):

1. **Drop `continue-on-error: true`** from the "Run kind harness" step
   (`id: harness`, `.github/workflows/ci.yml` ~ln 782), so a failed live run fails
   the `kind-harness` job instead of being swallowed.
2. **Add `kind-harness` to the `all-gates` `needs:` list**
   (`.github/workflows/ci.yml` job `all-gates`, ~ln 1018), so the required
   aggregator fails unless the `kind-harness` job is `success` — making a
   live-enforcement regression block merge atomically (the §1.1
   `P2-RELEASE-READINESS.md` "no orphan advisory gate" property).

The static layers already blocking within the `kind-harness` job
(`validate-harness.sh`, the assertion-library self-tests, the `extract_secret.py`
tests) **stay** blocking — promotion adds the live run on top, it does not relax
them. The DELIBERATE-OMISSION comment block (~ln 1005) and the job-name
"— non-blocking" suffix (~ln 729) are updated to reflect the new status.

### 3. Prerequisite A — a reliable enforcing-CNI kind topology (W4-T1)

NetworkPolicy is **not enforced by kind's default CNI** (ADR-0041 §2,
`docs/runbooks/kind-harness.md` Facts/step 2): the harness brings up the cluster
with `disableDefaultCNI: true` and installs an **enforcing CNI** (Calico), gated by
the **CNI self-test bite** (a harness-applied default-deny must block a known egress
before any downstream assertion runs). Promotion to `all-gates` REQUIRES this
bring-up to be **reliable enough to block every merge** — no flakiness that turns
the required aggregator red on a CNI-install/shell-quoting quirk rather than a real
regression. That reliable HA topology is **W4-T1** (P3-PLATFORM-PLAN §1/§5,
ADR-0047); this gate may not be promoted before W4-T1 lands and the bring-up is
green. Apply P1-W4-LESSONS **L1** (run the gating path before requiring it),
**L5** (`set -o pipefail` + `test -s` on the apply/assert pipeline — already in the
harness), and **L3** (no unsubstituted `$(VAR)` in any exec argv the harness/Jobs
use).

### 4. Prerequisite B — prove-it-bites before joining `all-gates` (non-negotiable)

Per P1-W4-LESSONS ("a gate green-at-setup masks the findings it would produce") and
the explicit P2 carry that the live run **does NOT yet bite**
(`P2-RELEASE-READINESS.md` §3), the live assertions must be shown to turn the gate
**red on a planted regression** before `continue-on-error` is dropped:

- **mTLS:** plant a regression that **allows an async plaintext / wrong-CA
  connection** (e.g. a `pg_hba`/sslmode weakening) and confirm
  `assert_handshake_refused` fails → `kind-harness` job red → `all-gates` red; then
  revert and confirm green.
- **Collector egress:** **remove the default-deny NetworkPolicy** (or broaden it to
  admit an arbitrary external destination) and confirm `assert_egress_blocked`
  fails → red; then restore and confirm green.

A promoted gate that does not bite is a **false-green blocking gate — worse than
`continue-on-error`** (the Risks below). The bite proof is recorded in the W4-T2
commit / the readiness doc. This mirrors the W4 drills' negative-control discipline
(P3-PLATFORM-PLAN §0a) and the `pg-integration` "proven to bite via `dd366bd`"
precedent (`P2-RELEASE-READINESS.md` §1.1).

### 5. Prerequisite C — runbook records the promotion

`docs/runbooks/kind-harness.md` "Gate status" section is updated by W4-T2 to record
that the live run is **now blocking** (no longer `continue-on-error`, now in
`all-gates needs`), closing the P2 "promotion path" note (re-deferred from W5-T3).
This keeps the runbook the single source of truth for the gate's status (no silent
drift — `PRODUCTION.md` gate G-MNT).

### 6. Scope boundary

**Out of this ADR:** building the kind topology (W4-T1, ADR-0047); the actual
promotion commit and its CI edits (W4-T2); the HA/scale-out and DR drills
themselves (G-REL/G-SCA, ADR-0047 — those are reliability drills, not this G-SEC
promotion); any *new* security control or new live assertion. This ADR ratifies a
**gate-policy** change for two already-built controls only. The reduced-scale +
named-certified-ceiling posture (P3-PLATFORM-PLAN §0) is inherited unchanged: this
gate proves the *enforcement mechanism* bites on kind, not a certified scale point.

## Consequences

**Positive**

- Closes the single named P2 G-SEC gap (`P2-RELEASE-READINESS.md` §5 item 5,
  `PRODUCTION.md` §1 inheritance): the mTLS handshake-refusal and collector
  egress-deny **live** enforcement become biting, blocking gates — a live
  regression now blocks merge instead of passing silently.
- Cheap, deterministic G-SEC bite on kind without HA/scale hardware (extends the
  ADR-0039/0041 "kind-validatable" design intent to an enforced gate).
- No new attack surface or claim — only two already-rendered, already-asserted
  controls flip from signal-only to blocking.

**Negative**

- A promoted gate that is **flaky** blocks every merge — mitigated by Prerequisite A
  (the W4-T1 reliable enforcing-CNI topology; promotion forbidden before it is
  green) and L1/L5.
- A promoted gate that does **not bite** is a false-green blocking gate, worse than
  the prior `continue-on-error` — mitigated by Prerequisite B (the mandatory planted
  regression).
- Adds a kind cluster bring-up (~3–6 min) to the critical merge path — accepted: it
  is the only hardware-free place these two controls can be enforced.

## Alternatives considered

1. **Leave the live run `continue-on-error` (status quo).** Rejected: it leaves the
   two P2 G-SEC sub-items permanently non-biting — a live mTLS-refusal or
   collector-deny regression would ship green. `PRODUCTION.md` §1 and the readiness
   doc explicitly schedule promotion as P3 inheritance; not promoting would silently
   drop it (ADR-0033 §1 discipline).
2. **Promote without the bite proof.** Rejected (Prerequisite B): a non-biting
   required gate is a false-green — the exact P1-W4 failure mode. The planted
   regression is non-negotiable.
3. **Promote on the existing (non-HA, P2) harness before W4-T1.** Rejected
   (Prerequisite A): the P2 harness was never run green on a real enforcing-CNI host
   (L1); requiring it then would let a CI-only CNI/bring-up quirk mask the whole
   suite. Promotion waits on the reliable W4-T1 topology.
4. **Widen the promotion to other live assertions (e.g. neo4j/redis mTLS, ingress
   TLS).** Rejected: those links are ADR-0039 §2 named-deferred and not built; this
   ADR promotes only the two controls already shipped and recorded PARTIAL at P2.
   Widening would introduce a new claim, out of scope.
5. **Gate via a manifest/static check only (no live cluster).** Rejected: the static
   render / harness-invariant layers already bite and are already blocking; they
   cannot prove the CNI *actually enforces* or that Postgres *actually refuses*
   plaintext — only the live assertion on an enforcing-CNI cluster does (ADR-0041 §2
   false-green warning). The live bite is the point of the promotion.
