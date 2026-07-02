# UI / UX Review

Production readiness audit, 2026-07-01. Frontend: React 18 + TypeScript + Vite + Tailwind + zustand + @tanstack/react-query — 67 files, ~14.2k LOC (16 pages, 5 shared components, 4 stores, 11 typed API modules, 27 test files).

**What is already good:** every page sampled uses the react-query `isPending` / `error` / empty triple with explicit copy ("Loading interfaces…", "No interfaces recorded."); the RFC 7807 error contract surfaces real backend messages instead of generic failures; routing enforces auth + role gates as defense-in-depth over backend RBAC; theme system (light/dark/system) is persisted and test-covered; the access token is memory-only by design. The gaps below are concentrated in resilience, responsiveness, and reuse — not in state handling.

---

## 1. No ErrorBoundary — a render error blanks the entire app

- **Severity:** High
- **Location:** `frontend/src/App.tsx`, `frontend/src/main.tsx` (no boundary anywhere; zero matches for `ErrorBoundary`/`componentDidCatch` in `src/`)
- **Root cause:** Error handling was built for *data* errors (react-query) but not *render* errors. Any exception thrown during render — a malformed API payload reaching JSX, a null deref in a formatter, a bug in the topology canvas — unmounts the whole tree: white screen, no message, no recovery, for an operator potentially mid-incident.
- **Proposed fix:** App-level boundary (inside the router, wrapping `Layout`'s outlet) with a "something went wrong — reload / go to dashboard" panel that reports the error to the console/structured log; optionally per-route boundaries so one broken page doesn't take down navigation. `react-error-boundary` is the standard tiny dependency, or ~40 lines hand-rolled.
- **Effort:** S–M (including tests)
- **Risk:** Low.

## 2. Desktop-only layout — no responsive behavior

- **Severity:** Medium
- **Location:** Entire page layer: 1 responsive Tailwind prefix (`sm:`/`md:`/`lg:`) in `frontend/src/components/Layout.tsx`, 1 across all 16 pages combined.
- **Root cause:** Layout is a fixed sidebar + wide data tables designed against a desktop viewport; responsive variants were never applied. On a tablet or phone (on-call engineer checking an incident), the sidebar consumes the viewport and 6–8-column tables overflow with no scroll affordance.
- **Proposed fix:** (a) collapsible sidebar below `lg:` (hamburger + overlay drawer); (b) wrap wide tables in `overflow-x-auto` containers as the cheap universal fix; (c) for the highest-traffic pages (Dashboard, Devices, Chat) consider stacked card layouts below `md:`. Full mobile optimization is not required for an enterprise NOC tool — graceful degradation is.
- **Effort:** M for (a)+(b); L if (c) is included
- **Risk:** Low — additive classes.

## 3. Thin shared-component layer — per-page duplication

- **Severity:** Medium
- **Location:** `frontend/src/components/` holds only 5 components (Layout, PageHeader, EmptyState, ProtectedRoute, RoleRoute) against 16 pages / 5,339 LOC.
- **Root cause:** Pages grew self-contained: status pills (`PILL_BASE` + per-status class maps in `DevicesPage.tsx:31–53`, with siblings in ChangesPage, ConfigPage, PacketPage…), data tables with the same `border-carbon-700` header idiom, inline error banners, form field + label stacks, and modal/confirm patterns are each re-implemented per page. This is the main reason pages average 300–560 LOC, and it lets visual drift creep in (pill paddings and tones already differ subtly between pages).
- **Proposed fix:** Extract the four highest-frequency primitives — `StatusPill` (variant-mapped), `DataTable` (header/row slot API), `ErrorBanner` (ApiError-aware), `FormField` — and adopt them opportunistically per page touched (no big-bang rewrite). This also becomes the natural home for a11y fixes (#5).
- **Effort:** M initial extraction; amortized adoption
- **Risk:** Low–Medium — visual regression risk mitigated by per-page adoption + existing page tests.

## 4. Loading UX is text-only; zero motion design

- **Severity:** Low
- **Location:** All pages: loading states are plain text ("Loading…"); zero `animate-spin`/`animate-pulse`/skeleton usage; zero transition classes on route changes, row expansion (DevicesPage `Fragment` expansion), modals, or theme switches.
- **Root cause:** States were implemented for correctness, not perceived performance; no motion vocabulary was ever established.
- **Proposed fix:** Small, systematic pass: skeleton rows for tables (`animate-pulse` blocks matching column layout), a single spinner component for in-flight mutations, `transition-colors` on theme switch, and 150 ms expand/collapse transitions on row expansion. Respect `prefers-reduced-motion`. This is the highest polish-per-effort item in the report.
- **Effort:** S–M
- **Risk:** None.

## 5. Accessibility coverage is thin and unenforced

- **Severity:** Medium
- **Location:** 55 `aria-*` attributes / 57 `role=` across the app, unevenly distributed (UsersPage 9, LoginPage 0, ChangePasswordPage 0); `frontend/eslint.config.js` has no jsx-a11y ruleset; no axe pass in CI.
- **Root cause:** A11y attributes were added where a component obviously needed them, but there is no enforcement layer, so critical flows (login and forced password change — the two pages every user must pass through) have none. Interactive table-row expansion (DevicesPage) and the topology canvas are keyboard-opaque. Status communicated by pill color alone (ok/warn/error tones) fails color-independence for the exact red/green distinctions a NOC tool lives on.
- **Proposed fix:** (a) add `eslint-plugin-jsx-a11y` (recommended config) to make the floor enforceable; (b) run an axe audit on the five core pages and fix findings — label associations on Login/ChangePassword forms, `aria-expanded`/keyboard handler on expandable rows, text/icon alongside color on status pills; (c) put the fixes into the shared components from #3 so they propagate.
- **Effort:** M
- **Risk:** Low.

## 6. No global notification/toast channel

- **Severity:** Low
- **Location:** Cross-cutting; each page renders errors and mutation outcomes inline in its own idiom (error-string counts per page range from 5 to 26).
- **Root cause:** No shared feedback primitive exists, so long-running async outcomes (discovery run finished, config deploy failed, CR approved) are only visible if the user is still on the originating page watching its poll loop.
- **Proposed fix:** Minimal toast store (the existing zustand `ui.ts` store is the natural host) + portal renderer in `Layout`; route mutation successes/failures and WS session terminal events through it. Keep inline errors for form validation.
- **Effort:** M
- **Risk:** Low.

## 7. Design-system consistency: tokens exist, usage is ad hoc

- **Severity:** Low
- **Location:** `frontend/tailwind.config.ts` defines a real token palette (`carbon-*`, `status-ok/warn/error`, `accent`) — good foundation; pages hand-compose them with one-off opacity/border permutations (`border-status-warn/40 bg-status-warn/10` vs neighboring pages using different opacity steps).
- **Root cause:** Tokens without composed variants; every page re-derives "what does a warning pill look like".
- **Proposed fix:** Encode the sanctioned compositions once (in `StatusPill`/`ErrorBanner` from #3, or as Tailwind component classes) and treat raw `status-*` utility composition in pages as a review smell.
- **Effort:** Folded into #3
- **Risk:** None.
