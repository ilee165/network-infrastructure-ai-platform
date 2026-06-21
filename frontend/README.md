# NetOps Console — frontend

React 19 + TypeScript (strict) + Vite SPA for the AI Network Operations Platform
(ADR-0012, M0 scaffold). Dark, dense operations-console aesthetic built with
Tailwind CSS — no component library.

## Prerequisites

- Node.js >= 20 (see `engines` in `package.json`)
- npm

## Quickstart (dev)

```bash
npm install
npm run dev
```

The Vite dev server starts on `http://localhost:5173` and proxies `/api/*` to
the FastAPI backend on `http://localhost:8000` (see `vite.config.ts`), so the
SPA is same-origin in development. In production the same is done by nginx in
the `frontend` container (ADR-0012 decision 2).

## Scripts

These five script names are canonical — CI invokes them exactly as written:

| Script | Command | Purpose |
| --- | --- | --- |
| `npm run dev` | `vite` | Dev server with `/api` proxy |
| `npm run build` | `vite build` | Production build to `dist/` |
| `npm test` | `vitest run` | Unit/component tests (jsdom, no backend needed) |
| `npm run lint` | `eslint .` | Flat-config ESLint; `no-explicit-any` is an error |
| `npm run typecheck` | `tsc --noEmit` | TypeScript strict + `noUncheckedIndexedAccess` |

## State management conventions (ADR-0012)

- **Server state → TanStack Query, exclusively.** Anything that comes from the
  FastAPI backend (health, devices, topology, changes, audit) lives in the
  Query cache and is never copied into a client store.
- **UI-local state → Zustand** (`src/stores/ui.ts`): sidebar collapse, theme,
  and later: selected panels, topology filters, chat composer drafts.

Duplicating server data into Zustand is the failure mode — flag it in review.

## Project structure

```
src/
├── api/          # Typed fetch wrapper (RFC 7807 errors) + per-router API modules
├── components/   # Shared presentational components (Layout, PageHeader, EmptyState)
├── pages/        # Route-level views, one per sidebar entry
├── stores/       # Zustand stores (UI-local state only)
├── test/         # Vitest setup (jest-dom matchers + cleanup)
└── __tests__/    # Component tests (vitest + @testing-library/react)
```

## Pages and milestones

Pages ship with honest empty states naming the roadmap milestone
(`docs/roadmap/MVP.md`) that populates them — never fake data.

| Route | Page | Status |
| --- | --- | --- |
| `/` | Dashboard | **Live in M0** — polls `GET /api/v1/health/ready`, per-dependency status cards |
| `/devices` | Devices | Populated in M1 (inventory + discovery engine) |
| `/topology` | Topology | Populated in M2 (Neo4j projection + Cytoscape.js) |
| `/chat` | Chat | Populated in M3 (agent framework + reasoning traces) |
| `/changes` | Changes | Populated in M5 (ChangeRequest approval workflow) |
| `/audit` | Audit | Populated in M3 (read-only audit browser) |

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_LLM_PROFILE` | `local` | Display-only header badge mirroring the backend's `NETOPS_LLM_PROFILE`; the backend is the source of truth |

## Testing

```bash
npm test
```

Vitest runs in jsdom with the shared setup file `src/test/setup.ts`
(configured in `vite.config.ts`). Tests mock `fetch` — they require no
backend, Postgres, Neo4j, or Redis. Test files live in `src/__tests__/` as
`<Component>.test.tsx`.
