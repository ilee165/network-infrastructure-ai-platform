# ADR-0060: Scale Certification Methodology

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

ADR-0047 proved reliability mechanisms at reduced scale and named the missing
certified-scale environment. P5 must produce reproducible certification without
claiming that this authoring host met loads it cannot sustain. Consultant Q1 is
still unanswered, so current G-SCA numbers remain proposed reference targets.

## Decision

Certification is a versioned scenario manifest plus immutable evidence. The
harness is parameterized from reduced scale through the current full targets:

| Dimension | Full target |
|---|---:|
| Discovery estate | 500 devices |
| API load | 100 concurrent users |
| Topology projection | 5,000 devices / 100,000 interfaces |
| Queue isolation | 10× baseline burst per queue |
| Database budget | PgBouncer/client connections remain within configured pool and reserved-admin budget |

The harness contains a deterministic seeded-estate generator, k6 read/write
profiles using approved synthetic identities, a cloud/hybrid-aware projection
fixture, queue-specific burst producers, and collectors for HPA/KEDA, latency,
errors, queue lag, pool use, and topology usability. Seeds, image digests,
commit SHA, configuration, start/end times, target and achieved scale, and raw
metric artifact digests are recorded. Secrets and bearer tokens are excluded.

Certification write traffic runs only against a dedicated, non-production,
disposable environment. Synthetic identities are restricted to the seeded
fixture namespace and minimum test permissions. Preflight verifies target
identity, fixture scope, isolation, and explicit operator authorization; a run
is blocked and invalid unless every isolation assertion passes before write
traffic begins.

Each scenario first runs a negative control (disabled autoscaling, removed
queue isolation, constrained connection budget, or corrupted projection
expectation as appropriate) and must fail its assertion. The control is then
removed and the same assertion must pass. A run is invalid if the gate did not
bite, if telemetry is incomplete, or if the environment changed mid-run.

On constrained hosts, binary-search upward through declared scale points until
the next point violates a resource guard or SLO. Record both the highest passing
point and first failing/not-attempted point with reason. This is a mechanism
PASS at the achieved point, never certification of the full target. The harness
must still render and validate the full-target manifests ready for an external
cluster.

At W4-T3 the Consultant Q1 re-check either replaces the target table with the
owner's numbers or explicitly re-confirms the proposed values. Re-basing
changes scenario parameters and evidence expectations, not implementation
semantics. Full certification promotes only when an environment runs every
target concurrently at release HEAD, all positive assertions pass, every
negative control bites, and evidence is reviewed. Until then the delta is named
deferred-accepted to GA.

The authoring-host posture—no certified-scale cluster, maximum feasible
reduced-scale execution, and no invented full-scale claim—is ratified as the P5
W0 working contract. A later owner answer supersedes target values only.

## Consequences

Scale evidence becomes comparable and reproducible while clearly separating a
working mechanism from certified capacity. Full runs may be expensive, but no
new architecture decision is required when suitable infrastructure appears.
