# W6-T5 — SBOM (syft) + cosign Image Signing + Admission Verify + Trivy Gate Raise

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-infra` (CI supply-chain + admission policy) |
| **Review tier** | sonnet spec + **strong** quality (image supply-chain + admission = security-semantic) |
| **Depends on** | W6-T4 (extends the same `ci.yml` docker job); W4 (admission policy controller in the chart) |
| **ADRs** | ADR-0016 (Trivy gate, CI), ADR-0029 (K8s hardening / admission), ADR-0013 (deploy) |
| **PRODUCTION.md** | §5 ("SBOM generation (syft), image signing + admission verification — cosign + policy controller; Trivy gate raised to zero critical *and* high CVEs at release"), §9, §11 G-SEC |
| **Status** | Proposed |

## Objective

Complete the image supply-chain: generate an **SBOM (syft)** per built image, **sign images with
cosign**, add **admission verification** of signatures at deploy, and raise the **Trivy gate to zero
critical *and* high** CVEs at release. Builds on the W6-T4 scanning jobs in the same `ci.yml` docker
stage.

## Scope

**In**
- **SBOM (syft)** generation for the backend and frontend images in the `ci.yml` `docker` job
  (which already builds both images + runs Trivy); SBOM attached as a build artifact and (PROPOSED)
  as a cosign attestation.
- **cosign signing** of both images on push to registry (main/tags — matching the existing
  `push to registry on main/tags` gate in ADR-0016); keyless (OIDC) or key-ref signing, key material
  referenced never inlined.
- **Admission verification** (PROPOSED: cosign policy-controller / Sigstore policy, or Kyverno
  verifyImages) in the Helm chart so the cluster **only admits signed images** — secure-by-default
  opt-out (CLAUDE.md, PRODUCTION.md §9), coordinated with the W4 admission-policy slot.
- **Trivy gate raise**: from the MVP "fail on CRITICAL" to **CRITICAL + HIGH at release**
  (ADR-0016 §, PRODUCTION.md §5 / G-SEC), with the reviewed `.trivyignore` carrying any accepted
  finding (justification/expiry).

**Out**
- Dependency/secret scanning (W6-T4).
- The base K8s admission/PSS/NetworkPolicy posture (W3/W4) — this task adds **image-signature**
  verification to the existing admission controller, not the controller itself.
- Runtime KMS / rate-limit (other W6 tasks).

## Requirements (grounded in PRODUCTION.md §5, ADR-0016, ADR-0029)

1. **SBOM per image** (PRODUCTION.md §5): syft over each built image; artifact retained; PROPOSED
   cosign-attested so provenance travels with the image.
2. **Sign on publish** (ADR-0016 "push to registry on main/tags"): images signed at the same gate
   they are pushed; signing identity/key referenced indirectly (keyless OIDC or external key ref),
   never inlined.
3. **Admission only admits signed images** (PRODUCTION.md §5 "admission verification"): the chart's
   admission policy verifies the cosign signature; **on by default = opt-out** (secure-by-default).
   An unsigned/forged-signature image is **rejected** at admission.
4. **Trivy gate raised to zero critical + high at release** (PRODUCTION.md §5 / ADR-0016): the
   release-time threshold is `HIGH,CRITICAL`; accepted findings only via the reviewed `.trivyignore`.
5. **Pinned + deterministic** (ADR-0016): pin syft/cosign/policy-controller versions/SHAs.

## Contracts / artifacts

- `.github/workflows/ci.yml` `docker` job — syft SBOM steps + cosign sign steps (gated on
  main/tags); Trivy `severity: CRITICAL,HIGH` at the release gate.
- `deploy/kubernetes/<chart>/templates/admission/*` — image-signature verification policy
  (cosign policy-controller / Kyverno verifyImages), behind `security.imageVerification.enabled`
  (default true), public key / keyless issuer referenced via values/external-secret.
- `docs/security/image-supply-chain.md` — SBOM/signing/admission/Trivy policy + verification
  procedure (and how to verify a released image's signature).

## Test & gate plan (CI + infra policy-as-test)

- `ci.yml`: syft produces an SBOM artifact for each image; cosign sign step runs on the main/tags
  path (dry-run/verify on PRs); Trivy at `HIGH,CRITICAL` green (or justified `.trivyignore`).
- Admission policy: `helm lint` / `kubeconform` / `conftest` render clean with verification **on by
  default**; a `conftest`/OPA test asserts the verify-images policy is present and not disabled; an
  unsigned-image manifest is rejected by the policy in a policy-test harness.
- cosign `verify` of a signed image succeeds; a tampered/unsigned image fails — proving the chain.
- Versions/SHAs pinned; YAML lints.

## Exit criteria

- [ ] syft SBOM generated + retained (PROPOSED attested) for backend + frontend images (G-SEC).
- [ ] Images cosign-signed on publish; signing key/identity referenced, never inlined.
- [ ] Admission policy admits **only signed images**, on by default; unsigned image rejected (proven).
- [ ] Trivy gate raised to zero **critical + high** at release; accepted findings only via reviewed
      `.trivyignore`.
- [ ] cosign `verify` proves the signature chain; infra + CI gates green; supply-chain documented.

## Workflow (P1-PLAN.md §3)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (strong —
escalated: admission + signing is security-semantic)** in parallel → `wf-fixer` if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- Admission verification on-by-default can block deploys if signing/verify is mis-wired — the policy
  test (signed admits / unsigned rejects) plus a documented break-glass for the bootstrap window
  guard against a self-inflicted outage, without making it opt-in.
- Raising Trivy to HIGH may surface base-image OS CVEs (cf. the existing
  `docs/security/2026-06-14-trivy-baseimage-cves.md` note) — triage via reviewed `.trivyignore`,
  not by lowering the gate.
