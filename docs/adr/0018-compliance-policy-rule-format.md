# ADR-0018: Compliance Policy Rule Format

**Status:** Accepted | **Date:** 2026-06-14 | **Milestone:** M4 (new capability — `REPO-STRUCTURE.md` §6)

## Context

CLAUDE.md "Config Management → Compliance checks" requires evaluating device configurations against policy (MVP M4). The `compliance_policies` table is declared in ADR-0004 §2; MVP.md §6 PROPOSES "declarative YAML rules with regex and parsed-model assertions, severity levels, scoped by vendor/role/site." This ADR fixes the rule format and the evaluation model so the engine and the seeded policy pack share one contract.

Requirements:
- Policies must be authored by operators (not code) and version-controlled → declarative, text-based.
- Two assertion kinds are needed: raw-text pattern checks (e.g. "no `transport input telnet`") and assertions over already-parsed/normalized data (e.g. "every interface in VRF X has an ACL bound").
- Findings must carry device, rule, severity, and concrete evidence (the matching line / the asserted fact) to satisfy the M4 exit criterion and "Explain all AI decisions".
- Scope: a rule may apply only to some vendors/roles/sites.

## Decision

**Compliance policies are declarative YAML documents validated by a Pydantic schema; the engine evaluates each rule's typed assertions against a device's raw config and its normalized models, emitting structured findings.**

1. **Policy document shape** (loaded into `compliance_policies`, one row per policy version):
   ```yaml
   id: baseline-hardening
   version: 1
   scope: { vendors: [cisco_ios, cisco_iosxe, eos], roles: [core, edge], sites: ["*"] }
   rules:
     - id: ssh-v2-only
       severity: violation        # info | warn | violation
       description: "Device must run SSH v2 only."
       assert:
         type: regex_present       # see assertion types below
         pattern: '^ip ssh version 2$'
     - id: no-any-any-permit
       severity: violation
       description: "No 'permit ip any any' in ACLs."
       assert:
         type: regex_absent
         pattern: 'permit ip any any'
     - id: ntp-configured
       severity: warn
       assert: { type: model_assert, model: ntp_servers, predicate: non_empty }
   ```

2. **Assertion types** (each a discriminated Pydantic model; the set is closed and extended only by ADR amendment):
   - `regex_present` / `regex_absent` — match against the **raw** snapshot text (multiline). Evidence = the matching line(s) or, for `absent`, a clean result.
   - `model_assert` — a predicate (`non_empty`, `equals`, `contains`, `count_*`) over a named **normalized** model already collected (e.g. `acl_entries`, `bgp_peers`, `interfaces`). Evidence = the offending rows.
   These are the only two M4 families; both are evaluated server-side over verbatim/normalized data — never via an LLM (the Configuration Agent *explains* findings; it does not *produce* them).

3. **Severity** is `info | warn | violation`; a device's compliance posture is the worst severity present plus the per-rule findings list.

4. **Scope resolution.** A policy applies to a device iff the device's vendor ∈ scope.vendors, role ∈ scope.roles (or `*`), and site ∈ scope.sites (or `*`). Non-matching policies are skipped (not "passed").

5. **Findings** (returned by the engine, persisted/audited): `{ device_id, policy_id, policy_version, rule_id, severity, status: pass|violation|skipped, evidence }`. A compliant device reports every applicable rule `pass`.

6. **Seeded policy pack.** Ship `baseline-hardening` with at least: SSHv2-only, no `permit ip any any`, NTP servers configured (the MVP.md §6 examples), as fixtures + a loadable default.

## Consequences

**Positive**
- Operators author/version policies as data; new rules need no code (within the two assertion families).
- Deterministic, LLM-free evaluation → reproducible, testable against fixtures (M4 exit criterion: seeded violation detected, compliant device clean).
- Structured evidence makes findings explainable and lets the Configuration Agent narrate them after A9 redaction (ADR-0017).

**Negative**
- The closed assertion set limits expressiveness; genuinely novel checks require an ADR amendment + a new assertion type (deliberate — prevents an unbounded mini-language).
- `model_assert` rules depend on the relevant normalized model being collected; a rule referencing an uncollected model resolves to `skipped` with a reason, not a false pass.

## Alternatives considered

1. **A general expression language (CEL / JSONLogic / Rego/OPA).** Rejected for M4: heavier dependency and authoring burden than the two assertion families need; revisit if policy complexity outgrows regex + model assertions.
2. **Python-coded policies.** Rejected: not operator-authorable, not data-versioned, and turns every new check into a deploy.
3. **LLM-judged compliance.** Rejected: non-deterministic and unfixturable; compliance must be exact and reproducible. The LLM's role is explanation only (ADR-0017 §3).
