# UI / UX Review

Production readiness audit, 2026-07-09. Frontend: React 19 + TypeScript + Vite + Tailwind + zustand + @tanstack/react-query. Local evidence: **461** vitest tests green; eslint 0 errors / 2 warnings; production build green.

**What improved since 2026-07-01:** App-level + layout `ErrorBoundary`; shared `StatusPill` / `ErrorBanner` / `FormField` / `Skeleton` / `Pagination` / `Toaster`; mobile drawer layout; `eslint-plugin-jsx-a11y` + axe-core page suite; Applications optimistic concurrency UX; ADC/Virtualization pages follow inventory patterns.

---

## 1. Audit page overclaims platform-wide audit log

- **Severity:** High (product honesty / operator trust)
- **Location:** `frontend/src/pages/AuditPage.tsx:133–136` (PageHeader description); file header comments `:1–14` correctly document session tool-call scope
- **Root cause:** UI title/description say “Append-only audit log: every actor, action, and AI decision…” but the page only loads one agent session by ID and lists `tool_call` steps. No filterable `/audit` browser over `audit_log` exists yet (comments acknowledge later milestone).
- **User impact:** Operators believe the platform audit trail is browsable here; security/compliance reviews will flag the gap.
- **Proposed fix:** (a) ship filterable audit-log browser, or (b) rename page/copy to “Agent tool audit”, point at session IDs from Chat, keep full audit for P4 W3 / dedicated API.
- **Effort:** S for copy; M–L for real browser | **Risk:** Medium for (a)

---

## 2. Devices inventory silent truncation

- **Severity:** Medium
- **Location:** `frontend/src/pages/DevicesPage.tsx` (`listDevices({ limit: 100 })`, total badge without Pagination)
- **Root cause:** API supports offset/limit; UI does not page. Large inventories hide devices past first page.
- **Proposed fix:** Reuse `Pagination` (Applications/ADC pattern).
- **Effort:** S | **Risk:** Low

---

## 3. Changes queue first-page only

- **Severity:** Medium
- **Location:** `frontend/src/pages/ChangesPage.tsx` (`limit: 50`, no page controls)
- **Root cause:** Same class as #2.
- **Proposed fix:** `offset` + `Pagination`.
- **Effort:** S | **Risk:** Low

---

## 4. Modal a11y incomplete on Applications (and siblings)

- **Severity:** Medium
- **Location:** `ApplicationsPage.tsx` ConfirmDialog / form modal (`role="dialog"` without focus trap, initial focus, Escape, labelled title)
- **Root cause:** Dialog markup without shared Modal primitive.
- **Proposed fix:** Shared `Modal` with focus trap, Esc, restore focus, `aria-labelledby`; adopt on Applications + other modals.
- **Effort:** M | **Risk:** Low

---

## 5. ErrorBoundary fallback lacks recovery actions

- **Severity:** Low
- **Location:** `frontend/src/components/ErrorBoundary.tsx`
- **Root cause:** Copy says navigate/reload; no buttons. Outer App boundary unmounts nav.
- **Proposed fix:** “Reload” + “Dashboard” controls on fallback.
- **Effort:** S | **Risk:** Low

---

## 6. Topology detail pane not responsive

- **Severity:** Low–Medium
- **Location:** `TopologyPage.tsx` fixed `grid-cols-[1fr_18rem]`
- **Root cause:** Detail column crowds narrow viewports despite Layout drawer fix.
- **Proposed fix:** Stack below `lg:`.
- **Effort:** S | **Risk:** Low

---

## 7. EmptyState component under-adopted

- **Severity:** Low
- **Location:** `components/EmptyState.tsx` still milestone-oriented; pages inline empties
- **Proposed fix:** Optional milestone/CTA slots; migrate key pages.
- **Effort:** S–M | **Risk:** Low

---

## Closed since 2026-07-01 (do not re-open)

| Prior item | Status |
|---|---|
| No ErrorBoundary | **CLOSED** — App + Layout |
| Desktop-only layout (no drawer) | **CLOSED** — hamburger + overlay |
| Thin shared component layer | **MOSTLY CLOSED** — StatusPill/ErrorBanner/Skeleton/Pagination/Toaster |
| Text-only loading | **IMPROVED** — SkeletonRows on inventory-class pages |
| No a11y lint / axe | **CLOSED** floor — jsx-a11y + axe suite (color-contrast still disabled in jsdom) |
| No toast channel | **CLOSED** — Toaster + ui store |

---

## Strengths

- Applications page is the quality bar: pagination, origin badges, If-Match stale UX, role-gated writes, keyboard expand.
- RFC 7807 errors surface via shared `ErrorBanner` on most data pages.
- Nested ErrorBoundary keeps shell usable when a page throws.
- TypeScript: no `any` / `@ts-ignore` in product source.
- Auth routes + FormField label wiring improved vs July baseline.
