# ADR-0012: Frontend Stack

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D12

## Context

CLAUDE.md mandates **React** and **TypeScript** in the architecture stack. The brief's container table (section 1) defines the `frontend` container's responsibilities: **chat console** (agent interaction with streaming), **topology visualization** (L2/L3/DNS/application-dependency graphs from Neo4j — potentially thousands of nodes), **inventory**, **change approvals** (the human gate from D11), and **audit views** including reasoning traces ("Explain all AI decisions"). The brief (D12) fixes the stack: React 18, TypeScript strict, Vite, TanStack Query, Zustand, Tailwind CSS, and Cytoscape.js for topology rendering; the container is built with Vite and served by nginx. MVP milestones M2 (topology visualization) and M3 (chat UI with reasoning traces) are the first major frontend deliverables.

## Decision

1. **React 18 + TypeScript strict.** `tsconfig.json` ships with `"strict": true` plus `noUncheckedIndexedAccess` (**PROPOSED** — the brief says "TypeScript strict"; the extra flag is a conservative tightening). No `any` in committed code (lint-enforced, D16).

2. **Vite** for dev server and production build; output static assets served by **nginx** in the `frontend` container (one image per container, D13). API and WebSocket traffic is reverse-proxied by nginx to the `api` container so the SPA is same-origin (no CORS surface in production — secure by default).

3. **Server state: TanStack Query, exclusively.** All data from the FastAPI backend (devices, topology, change requests, audit entries) lives in TanStack Query's cache — never copied into a client store. API types are **generated from the FastAPI OpenAPI schema** so backend Pydantic schemas and frontend types cannot drift; **PROPOSED:** `openapi-typescript` + typed `fetch` wrapper as the generator (the brief mandates the stack but not a codegen tool).

4. **Client state: Zustand**, strictly for UI-local state: selected device/panel, topology layout and filter settings, chat composer drafts, in-flight approval dialog state. The rule "server data only in Query, UI state only in Zustand" is a reviewable convention documented in `frontend/README`.

5. **Styling: Tailwind CSS** utility-first; design tokens (colors, spacing, status palettes for device/CR states) defined in the Tailwind config. **PROPOSED:** Headless, accessible primitives (dialogs, menus, comboboxes) from Radix UI rather than a styled component library, keeping Tailwind in control of all visuals.

6. **Topology: Cytoscape.js** rendering the Neo4j projection (node labels `Device`, `Interface`, `Subnet`, …; edges `CONNECTED_TO`, `L3_ADJACENT`, `DEPENDS_ON`, … per brief section 6) delivered by the topology API as a normalized JSON graph — the frontend never talks to Neo4j directly. Layouts: **PROPOSED** `fcose` for organic L2/L3 views and `dagre` for dependency trees. Compound nodes group interfaces under devices and devices under `Site`.

7. **Chat console:** WebSocket connection to the `api` container streaming agent tokens, tool-call events, and reasoning-trace step updates; authenticated with the JWT access token (ADR-0010). The reasoning-trace panel renders the persisted trace (ADR-0011) next to the conversation so every answer is inspectable.

8. **Routing: PROPOSED** React Router (v6) — the brief does not name a router; React Router is the conservative default for an nginx-served SPA.

9. **Quality gates** (detailed in ADR-0016): vitest + @testing-library/react, eslint, `tsc --noEmit` in CI.

## Consequences

**Positive**
- TanStack Query gives caching, refetching, optimistic updates, and request dedup for free — most "global state" disappears, and Zustand stays tiny.
- Generated API types make the FastAPI contract compile-time-checked in the UI; a backend schema change breaks the frontend build instead of production.
- Cytoscape.js is purpose-built for network-style graphs: compound nodes, rich selectors for styling by device role/status, and canvas rendering that survives graphs far larger than SVG-based libraries tolerate.
- Static Vite output behind nginx means the frontend container has no runtime, minimal CVE surface, and trivially satisfies self-hosted/air-gapped deployment.

**Negative**
- Two state systems (Query + Zustand) require discipline; the failure mode is duplicating server data into Zustand and desyncing — mitigated only by convention and review.
- Cytoscape.js's imperative API sits awkwardly inside React's declarative model; a wrapper component owning the Cytoscape instance lifecycle is required, and that boundary is a recurring source of subtle bugs (stale handlers, double-mounts under StrictMode).
- Tailwind's utility classes make markup verbose and put real weight on design-token discipline to avoid visual drift.
- Type generation adds a build step that must run whenever the backend schema changes (wired into CI to fail on drift).

## Alternatives considered

1. **Next.js instead of Vite SPA.** Rejected: SSR/RSC adds a Node runtime to the production footprint for zero benefit — this is an authenticated internal tool with no SEO or first-paint-anonymous requirements, and a static SPA behind nginx is simpler to self-host, scan, and air-gap. The brief also explicitly names Vite.
2. **Redux Toolkit (+ RTK Query) for all state.** Rejected: with TanStack Query owning server state there is too little client state left to justify Redux's ceremony; Zustand covers the remainder in a few dozen lines. RTK Query is credible but TanStack Query is mandated by D12 and has the stronger ecosystem for this pattern.
3. **React Flow (xyflow) for topology.** Rejected: excellent for editable node-graph *editors*, but weaker for large read-mostly network graphs — no built-in graph-theory model, fewer automatic layouts suited to mesh topologies, and SVG/DOM rendering degrades well before Cytoscape's canvas does at the multi-thousand-node scale enterprise L2 topologies reach. D3-force alone was also rejected: it is a layout primitive, not a graph component, and would mean hand-building selection, styling, and compound-node semantics.
4. **A styled component library (MUI / Ant Design / Chakra) instead of Tailwind + headless primitives.** Rejected: heavyweight theming systems fight the dense, data-grid-and-graph NOC aesthetic this product needs, lock visual language to the library's design system, and the brief mandates Tailwind.
