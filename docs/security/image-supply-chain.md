# Image supply-chain — SBOM, cosign signing, admission verification, Trivy gate

**Task:** P1 W6-T5 · **Pipeline:** `.github/workflows/ci.yml` (`docker` job) ·
**Chart:** `deploy/kubernetes/netops` (admission policy)
**Posture refs:** PRODUCTION.md §5 (SBOM + signing + admission verify + Trivy raise),
§9, §11 G-SEC; ADR-0016 §5 (pinned, deterministic CI; push-to-registry on
main/tags); ADR-0029 §5/§6 (admission, secrets-by-reference); ADR-0011 §6
(no-secret posture).

This note documents the four image supply-chain controls and **how to verify a
released image's signature**. The sibling **W6-T4** note
(`supply-chain-scanning.md`) covers dependency + secret scanning of the *repo*;
this one covers the *built images*.

## Controls at a glance

| Control | Where | What it does | Fail/Default |
|---------|-------|--------------|--------------|
| **SBOM (syft)** | `docker` job · "SBOM (syft)" | SPDX-JSON SBOM per image, retained as `image-sboms` artifact; cosign-attested on publish | runs every build; artifact required |
| **cosign sign + attest** | `docker` job · "cosign sign + attest" | keyless (OIDC→Fulcio→Rekor) signature + SBOM attestation on each pushed image | publish gate only (main/tags), after Trivy |
| **Trivy image scan** | `docker` job · "Trivy scan" | image-CVE gate raised to **CRITICAL + HIGH** | RED gate; suppress only via reviewed `.trivyignore-image` |
| **Admission verify** | chart · `verify-image-signatures` Kyverno rule | cluster admits ONLY cosign-signed images | **ON by default** (`security.imageVerification.enabled: true`) |

## 1. SBOM (syft)

`syft scan docker:<image> -o spdx-json` produces an SPDX-JSON SBOM for the
backend and frontend images on **every** CI build (PR + publish), uploaded as the
`image-sboms` artifact. On the publish gate the SBOM is additionally attached to
the image as a cosign **attestation** (`cosign attest --type spdxjson`) so
provenance travels with the image and can be retrieved + verified later.

- Pinned: `syft v1.18.1` via `anchore/sbom-action/download-syft@v0.17.9`
  (ADR-0016 §5 — the SBOM generator is not itself a supply-chain risk).

Retrieve + verify a published image's SBOM attestation:

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/ci.yml@refs/.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/<owner>/netops-backend:<sha> \
  | jq -r '.payload | @base64d | fromjson | .predicate' > backend.sbom.spdx.json
```

## 2. cosign signing (keyless)

Images are signed **only on the publish gate** (`push` to `main` or a tag —
matching ADR-0016 "push to registry on main/tags") and **only after Trivy
passes**, so a CVE-failing image is never signed. Signing is **keyless**:

- GitHub mints a short-lived OIDC token for the workflow (`id-token: write`).
- cosign exchanges it at **Fulcio** for an ephemeral signing certificate bound to
  the workflow identity (`…/ci.yml@refs/…`).
- The signature is recorded in the **Rekor** transparency log.

There is **no long-lived private signing key** anywhere in the repo, values, CI
logs, or rendered manifests (ADR-0011 §6 / ADR-0029 §6). The signing identity
*is* the workflow's OIDC identity. Pinned: `cosign v2.4.1` via
`sigstore/cosign-installer@v3.7.0`.

### How to verify a released image's signature

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/ci.yml@refs/.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/<owner>/netops-backend:<sha>
```

A signed image prints the verified certificate + Rekor entry; a **tampered or
unsigned** image **fails** with `no matching signatures` — the same identity the
admission policy enforces, so "verifies in cosign" ⇔ "admits in-cluster".

## 3. Admission verification (secure-by-default)

The cluster **admits only signed images**. This is enforced by the existing W4
Kyverno `verify-image-signatures` rule
(`deploy/kubernetes/netops/templates/policy/kyverno-clusterpolicy.yaml`) — W6-T5
**wires the real verifier and flips it ON by default**. It does **not** add a
second admission controller; it drives the W4 slot.

Controlled by `security.imageVerification` in `values.yaml`:

```yaml
security:
  imageVerification:
    enabled: true            # SECURE-BY-DEFAULT, opt-out
    keyless:
      enabled: true
      issuer: "https://token.actions.githubusercontent.com"
      subjectRegExp: "^https://github\\.com/.+/\\.github/workflows/ci\\.yml@refs/.+$"
      rekorUrl: "https://rekor.sigstore.dev"
    imageReferences: [netops-backend, netops-frontend]
```

When `enabled: true` (default) the rule renders `failureAction: Enforce`,
`required: true`, `verifyDigest: true` over **both** image refs, with the keyless
attestor above. An **unsigned or forged-signature** image is **rejected** at
admission; a tag-swap to an unsigned digest is rejected by `verifyDigest`.

Operators who prefer a long-lived cosign key-pair set
`security.imageVerification.publicKeyPEM` (the **public** `cosign.pub` only) and
`admission.signedImages.publicKeyConfigMap` — the chart renders
`templates/admission/image-verification-key.yaml` (a ConfigMap holding the public
verifier; **never** a private key) and the rule reads `publicKeys` from it.

### Policy-as-test (signed admits / unsigned rejects)

`deploy/kubernetes/policy/rego/hardening.rego` (run by `conftest` in the `infra`
CI job) asserts on the **default-rendered** chart that the rule:

1. is present (`verify-image-signatures`);
2. **Enforces** (not Audit) and is `required: true` — a verification it cannot
   perform must reject, not skip;
3. `verifyDigest: true`;
4. carries a **real attestor** (keyless issuer+subject OR a key-ref), not the old
   empty-string placeholder that admitted everything;
5. **covers both** `netops-backend` and `netops-frontend`.

These guards **bite**: rendering with `security.imageVerification.enabled=false`,
an empty issuer, or a dropped image ref fails `conftest` (verified locally). The
gate therefore catches any silent downgrade to Audit-only / no-op verification.

## 4. Trivy gate raised to CRITICAL + HIGH

The image-CVE gate fails on **CRITICAL and HIGH** (`severity: CRITICAL,HIGH`)
with `ignore-unfixed` (un-patchable base-OS CVEs with no upstream fix are out of
our control — `2026-06-14-trivy-baseimage-cves.md`). The gate is **not lowered**:
accepted findings flow **only** through the reviewed
`deploy/docker/.trivyignore-image`, each line a specific CVE ID with a
justification **and** an expiry/re-review date (mirrors the `.pip-audit` /
`.trivyignore` conventions). The file is currently **empty of accepted findings**
— the raise is clean on the current images.

> Image-CVE suppression (`deploy/docker/.trivyignore-image`) is kept **separate**
> from IaC-misconfig suppression (`deploy/kubernetes/.trivyignore`) so a misconfig
> exception can never silence a real CVE, and vice-versa.

## Break-glass — bootstrap window

Admission verification on-by-default can block deploys if signing/verify is
mis-wired (e.g. the very first cluster bring-up before any signed image exists, or
a Rekor/Fulcio outage). **Break-glass, time-boxed, documented:**

1. **Preferred — scope, don't disable.** Pre-load known-good signed digests or
   widen `security.imageVerification.imageReferences` only for the bootstrap
   image, leaving enforcement on for everything else.
2. **Full opt-out (last resort).** Set `security.imageVerification.enabled=false`
   for the install, deploy, then **re-enable immediately**:

   ```bash
   helm upgrade netops deploy/kubernetes/netops \
     --set security.imageVerification.enabled=false   # BOOTSTRAP ONLY
   # …bring the platform up, confirm signing pipeline is healthy…
   helm upgrade netops deploy/kubernetes/netops \
     --set security.imageVerification.enabled=true    # RESTORE the gate
   ```

   This renders the rule `Audit`-only (non-blocking) — it does **not** remove it,
   so violations are still logged. Leaving it off in production defeats the
   supply-chain gate; the `conftest` policy-as-test gates the **default** (on)
   render, so an accidental committed opt-out is caught in CI.

## Pinned versions

| Tool | Version | Pinned via |
|------|---------|-----------|
| syft | v1.18.1 | `anchore/sbom-action/download-syft@v0.17.9` |
| cosign | v2.4.1 | `sigstore/cosign-installer@v3.7.0` |
| Trivy | trivy-action v0.36.0 | action ref |
| Kyverno | (cluster) verify-images rule, `kyverno.io/v1` | chart `admission.engine: kyverno` |

## Local verification performed (this task)

`syft` / `cosign` / `trivy` are **not installed on the authoring host**, so the
signing/SBOM/image-CVE steps were validated by the rendered CI-equivalent (pinned
action refs, `actionlint` clean) rather than executed locally. The chart +
policy half was validated locally end-to-end: `helm lint` clean, `helm template |
kubeconform -strict` (0 invalid), `kube-linter` clean, and `conftest` —
**9222 tests pass** on the secure-by-default render, and the new
signed-admits/unsigned-rejects guards **fail as expected** on planted negatives
(opt-out, empty attestor, dropped image ref). `actionlint v1.7.7` lints `ci.yml`
clean.
