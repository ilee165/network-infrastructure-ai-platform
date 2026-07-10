# Cross-wave lessons learned

Living log of concrete, repo-specific traps that already cost a CI red or a
review round. Wave-scoped retros also live alongside plans (e.g.
`P1-W4-LESSONS.md`); **new standing rules that apply to every phase land here
and in `CLAUDE.md`**.

Each lesson: **what bit us → why → the rule for next time → who it hits next.**

---

## Frontend / SPA

### L-FE-1 — Partial `vi.mock` of an API module must list every export the tree imports

**Bit us:** Settings hub Path A (PR #125) added `getRotationStatus` on
`frontend/src/api/credentials.ts` and wired it into `SettingsCredentialsSection`.
`SettingsPage.test.tsx` was updated; **`SettingsRoute.test.tsx` was not**. CI
frontend job failed with:

```text
[vitest] No "getRotationStatus" export is defined on the "../api/credentials" mock.
Did you forget to return it from "vi.mock"?
```

Same class of risk for `getOidcStatus` on the auth mock when Access mounts.

**Why:** Vitest replaces the whole module with the mock factory return value.
Any new named import from a partially mocked module is missing unless the
factory exports it — and the failure only appears when a test *mounts* a
component that imports the new symbol (page tests can pass while route-gate
tests go red).

**Rule:**

1. When adding a public export to `frontend/src/api/*`, **grep** for
   `vi.mock("../api/<module>"` / `vi.mock('../../api/<module>'` and update
   **every** mock factory.
2. Prefer the same default-resolved shape the real client returns so
   `useQuery` does not hang on pending forever.
3. Run the sibling suites before push: page + route + layout tests that
   import the same section components.

**Hits next:** Any Settings / inventory / topology PR that grows an API client
used under nested routes or shell queries.

**Evidence:** PR #125 CI run (frontend fail); fix commit
`cf54ac5` (`SettingsRoute.test.tsx` mocks).

---

## Images / supply chain

### L-IMG-1 — Fixable Alpine CVE + GHA layer cache: bump `apk upgrade` cache-bust, do not ignore

**Bit us:** Same PR #125 docker job: Trivy image scan on `netops-frontend:ci`
failed **HIGH** on `c-ares` **CVE-2026-33630** (`1.34.6-r0` → fixed in
`1.34.8-r0`). The Dockerfile already runs `apk upgrade --no-cache`, but CI
`cache-from/to type=gha` reused the **stale** upgrade layer dated
`2026-07-08`, so the patched package never entered the image.

**Why:** `apk upgrade` is only as fresh as the last uncached layer. A date
comment is the intentional cache-bust (documented in
`deploy/docker/frontend.Dockerfile`). Ignoring a *fixable* CVE in
`.trivyignore-image` would green the gate without shipping the patch.

**Rule:**

1. On Trivy RED for a **fixed** Alpine (or similar) package in the frontend
   (or any) image: **bump the cache-bust date/comment** on the
   `apk upgrade` (or equivalent) `RUN` so the layer rebuilds.
2. Prefer upgrade over pin-and-ignore. Use `.trivyignore-image` only for
   reviewed **unfixed** or accepted residual findings with expiry (see
   `docs/security/image-supply-chain.md` §4).
3. After the bump, confirm the docker job’s Trivy step is green — that is
   the “gate RUN and BITE” proof that the new packages landed.

**Hits next:** Every PR that builds `deploy/docker/frontend.Dockerfile` (and
any future image stage that relies on periodic `apk`/`apt` upgrade + GHA
layer cache).

**Evidence:** PR #125 docker fail (c-ares 1.34.6-r0); fix commit `cf54ac5`
(cache-bust `2026-07-10`).

---

## Related

| Doc | Scope |
|---|---|
| `CLAUDE.md` § Orchestrated builds / Build & runtime | Standing agent rules (includes L-FE-1 / L-IMG-1 one-liners) |
| `P1-W4-LESSONS.md` | Helm/K8s GA chart wave (L1–L8) |
| `docs/security/image-supply-chain.md` | Trivy / SBOM / cosign / admission controls |
| `deploy/docker/frontend.Dockerfile` | `apk upgrade` cache-bust comment mechanism |
