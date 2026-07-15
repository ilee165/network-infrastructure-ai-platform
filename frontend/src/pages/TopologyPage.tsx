/**
 * Topology: interactive L2/L3 network graph rendered with Cytoscape.js.
 *
 * The topology engine (M2) projects the Postgres inventory into Neo4j
 * (CONNECTED_TO, L3_ADJACENT, HAS_INTERFACE, IN_SUBNET, ROUTES_TO …); the
 * M2-10 ``GET /topology/graph`` endpoint returns that projection and the
 * M2-12 client (``api/topology.ts``) types it. This page maps those nodes and
 * edges into Cytoscape elements (``topology-graph.ts``), styles them per
 * label, offers an L2/L3 layer toggle (re-fetches with the ``layer`` query
 * param), and shows a detail side panel for the selected node. ``projected_at``
 * surfaces the projection pass the view is "as of" (ADR-0005).
 *
 * Loading is scoped by default (audit Wave 5, G-SCA): the page fetches one
 * site's subgraph (first site auto-selected) or a device neighborhood at
 * depth N (``/topology/graph/neighborhood``); the full-graph fetch is an
 * explicit action and the server refuses it with a 413 problem over the
 * ``NETOPS_TOPOLOGY_MAX_NODES`` cap, which this page surfaces with guidance
 * back to the scoped modes.
 */

import cytoscape from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../api/client";
import {
  MAX_NEIGHBORHOOD_DEPTH,
  type TopologyDiff,
  type TopologyEdge,
  type TopologyGraph,
  type TopologyGraphParams,
  type TopologyNode,
} from "../api/topology";
import { useTopologyInventory } from "../hooks/useDeviceQueries";
import { useDiscoveryRuns } from "../hooks/useDiscoveryQueries";
import { useScopedTopology, useTopologyDiff } from "../hooks/useTopologyQueries";
import { PageHeader } from "../components/PageHeader";
import { ErrorBanner } from "../components/ErrorBanner";
import {
  DEFAULT_NODE_COLOR,
  DIFF_ADDED_CLASS,
  DIFF_REMOVED_CLASS,
  LABEL_COLOR,
  applyDiffClasses,
  detailFields,
  diffChangeCount,
  diffListItems,
  toCytoscapeElements,
  type CytoscapeElement,
} from "./topology-graph";

// ── Diff palette ──────────────────────────────────────────────────────────────

/** Green for added, red for removed — shared by the canvas overlay and panel. */
const DIFF_ADDED_COLOR = "#22c55e";
const DIFF_REMOVED_COLOR = "#ef4444";

// ── Constants ─────────────────────────────────────────────────────────────────

type Layer = NonNullable<TopologyGraphParams["layer"]>;

const LAYERS: { value: Layer; label: string; title: string }[] = [
  { value: "all", label: "All", title: "All relationship types" },
  { value: "l2", label: "L2", title: "LLDP/CDP neighbor links only" },
  { value: "l3", label: "L3", title: "Subnet adjacency and routing links only" },
  { value: "dns", label: "DNS", title: "DNS zone/record dependency layer (DnsZone, DnsRecord, RESOLVES_TO)" },
  { value: "app", label: "App", title: "Application-dependency layer (Application nodes, DEPENDS_ON edges with per-source provenance)" },
];

/** Tailwind tone per dependency source, so a DEPENDS_ON edge's provenance reads at a glance. */
const APP_SOURCE_TONE: Record<string, string> = {
  manual: "bg-accent/15 text-accent",
  f5: "bg-sky-500/15 text-sky-300",
  vmware: "bg-emerald-500/15 text-emerald-300",
  dns: "bg-amber-500/15 text-amber-300",
};

/** The sources asserting one DEPENDS_ON edge (empty when the property is absent). */
function edgeSources(edge: TopologyEdge): string[] {
  const raw = edge.properties.sources;
  return Array.isArray(raw) ? raw.map((s) => String(s)) : [];
}

/**
 * The application-dependency panel (P4 W2-T4): the DEPENDS_ON edges of the
 * current ``app``-layer graph, each with per-source provenance badges, plus the
 * projection watermark these answers are "as of" and an honest empty state.
 * Complements the cytoscape canvas (which cannot render DOM badges) so an
 * operator can read each dependency's provenance at a glance.
 */
function AppDependencyPanel({ graph }: { graph: TopologyGraph }) {
  const dependsOn = graph.edges.filter((edge) => edge.type === "DEPENDS_ON");
  return (
    <section
      data-testid="app-dependency-panel"
      aria-label="Application dependencies"
      className="panel flex flex-col gap-3 p-4"
    >
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Application dependencies
        </h3>
        {graph.projected_at ? (
          <span data-testid="app-impact-watermark" className="badge">
            as of {new Date(graph.projected_at).toLocaleString()}
          </span>
        ) : null}
      </div>
      {dependsOn.length === 0 ? (
        <p data-testid="app-impact-empty" className="text-xs leading-relaxed text-zinc-500">
          No application dependencies in this scope. Derived edges (F5 / VMware / DNS) appear
          after a derivation pass; manual edges after tagging on the Applications page.
        </p>
      ) : (
        <ul className="flex flex-col">
          {dependsOn.map((edge, index) => (
            <li
              key={`${edge.source}->${edge.target}-${index}`}
              data-testid={`app-dependency-edge-${index}`}
              className="flex items-center justify-between gap-3 border-b border-carbon-800 py-1.5 text-xs last:border-0"
            >
              <span className="font-mono text-zinc-300">
                <span className="text-zinc-100">{String(edge.source)}</span>
                <span className="text-zinc-600"> → </span>
                <span className="text-zinc-100">{String(edge.target)}</span>
              </span>
              <span className="flex flex-wrap gap-1">
                {edgeSources(edge).map((source) => (
                  <span
                    key={source}
                    data-testid={`app-edge-${index}-source-${source}`}
                    className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                      APP_SOURCE_TONE[source] ?? "bg-carbon-700 text-zinc-300"
                    }`}
                  >
                    {source}
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * Scoped-by-default topology loading (audit Wave 5, G-SCA): the page fetches a
 * site subgraph or a device neighborhood; the full-graph fetch is an explicit
 * action and is refused server-side (413) over the configured node cap.
 */
type ScopeMode = "site" | "device" | "full";

const SCOPE_MODES: { value: ScopeMode; label: string; title: string }[] = [
  { value: "site", label: "Site", title: "Devices assigned to one site (scoped query)" },
  {
    value: "device",
    label: "Device",
    title: "Everything within N hops of one device (scoped query)",
  },
  {
    value: "full",
    label: "Full graph",
    title: "Explicit full-graph fetch — refused over the server node cap (413)",
  },
];

const DEPTHS = Array.from({ length: MAX_NEIGHBORHOOD_DEPTH }, (_, i) => i + 1);

/** The device list API caps ``limit`` at 500; pages are accumulated up to the
 * G-SCA design scale so sites/devices past the first page stay selectable.
 * Beyond that, a distinct-sites endpoint + searchable combobox are the right
 * tools (deferred to the P5 scale work). */
const INVENTORY_PAGE = 500;
const INVENTORY_MAX = 5000;

// ── Stylesheet ──────────────────────────────────────────────────────────────

/** Stylesheet: one color rule per label plus shared node/edge defaults. */
function buildStylesheet(): cytoscape.StylesheetStyle[] {
  const labelRules: cytoscape.StylesheetStyle[] = Object.entries(LABEL_COLOR).map(
    ([label, color]) => ({
      selector: `node.${label}`,
      style: { "background-color": color, "border-color": color },
    }),
  );
  return [
    {
      selector: "node",
      style: {
        "background-color": DEFAULT_NODE_COLOR,
        "border-width": 1,
        "border-color": DEFAULT_NODE_COLOR,
        label: "data(display)",
        color: "#e4e4e7",
        "font-size": 9,
        "text-valign": "bottom",
        "text-margin-y": 4,
        width: 18,
        height: 18,
      },
    },
    ...labelRules,
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": "#3f3f46",
        "target-arrow-color": "#3f3f46",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "font-size": 7,
        color: "#71717a",
      },
    },
    {
      selector: "node:selected",
      style: { "border-width": 3, "border-color": "#fafafa" },
    },
    // Diff overlay: added (green) / removed (red) for both nodes and edges.
    {
      selector: `node.${DIFF_ADDED_CLASS}`,
      style: { "border-width": 3, "border-color": DIFF_ADDED_COLOR },
    },
    {
      selector: `node.${DIFF_REMOVED_CLASS}`,
      style: { "border-width": 3, "border-color": DIFF_REMOVED_COLOR },
    },
    {
      selector: `edge.${DIFF_ADDED_CLASS}`,
      style: {
        width: 3,
        "line-color": DIFF_ADDED_COLOR,
        "target-arrow-color": DIFF_ADDED_COLOR,
      },
    },
    {
      selector: `edge.${DIFF_REMOVED_CLASS}`,
      style: {
        width: 3,
        "line-color": DIFF_REMOVED_COLOR,
        "target-arrow-color": DIFF_REMOVED_COLOR,
        "line-style": "dashed",
      },
    },
  ];
}

// ── Detail side panel ───────────────────────────────────────────────────────

/** One labeled field row in the detail panel. */
function Field({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[10px] uppercase tracking-wider text-zinc-600">{label}</dt>
      <dd className="font-mono text-xs text-zinc-200">{value ?? "—"}</dd>
    </div>
  );
}

/** Label-specific field list for the selected node. */
function NodeDetail({ node }: { node: TopologyNode }) {
  const fields = detailFields(node);
  return (
    <div data-testid="topology-detail-panel" className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span
          className="h-2.5 w-2.5 rounded-full"
          style={{ backgroundColor: LABEL_COLOR[node.label] ?? DEFAULT_NODE_COLOR }}
        />
        <span className="font-mono text-xs uppercase tracking-wider text-zinc-400">
          {node.label}
        </span>
      </div>
      <dl className="flex flex-col gap-2">
        {fields.map((f) => (
          <Field key={f.label} label={f.label} value={f.value} />
        ))}
      </dl>
    </div>
  );
}

// ── Canvas ────────────────────────────────────────────────────────────────────

/**
 * Structural identity of a cytoscape element set (ids + edge endpoints).
 * Used to decide whether a re-layout is required after a refetch (Wave 5).
 */
function structuralSignature(elements: CytoscapeElement[]): string {
  return elements
    .map((el) => {
      // CytoscapeElement has no `group` field — edges carry source/target.
      const isEdge =
        el.data.source !== undefined && el.data.target !== undefined;
      if (!isEdge) {
        return `n:${el.data.id}`;
      }
      return `e:${el.data.id}:${el.data.source ?? ""}>${el.data.target ?? ""}`;
    })
    .sort()
    .join("|");
}

/**
 * Renders the topology graph into a persistent Cytoscape instance and reports
 * node selection up via ``onSelect``. Wave 5 / perf #16: the cy instance is
 * created once, element diffs are applied in place, and layout only re-runs
 * when the structural signature changes — viewport is preserved across
 * refetch / diff-overlay toggles that do not add/remove nodes or edges.
 */
function TopologyCanvas({
  elements,
  onSelect,
}: {
  elements: CytoscapeElement[];
  onSelect: (key: string | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const onSelectRef = useRef(onSelect);
  const signatureRef = useRef<string>("");
  onSelectRef.current = onSelect;

  // Create once; destroy on unmount only.
  useEffect(() => {
    const container = containerRef.current;
    if (!container || cyRef.current) {
      return;
    }
    const cy = cytoscape({
      container,
      elements: [],
      style: buildStylesheet(),
      layout: { name: "preset" },
    });
    cy.on("tap", "node", (evt) => onSelectRef.current(evt.target.id()));
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        onSelectRef.current(null);
      }
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
      signatureRef.current = "";
    };
  }, []);

  // Diff elements into the persistent instance.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }
    const nextSig = structuralSignature(elements);
    const needsLayout = nextSig !== signatureRef.current;
    // Preserve pan/zoom and node positions across non-structural updates
    // (class-only diffs / refetch of the same graph).
    const pan = cy.pan();
    const zoom = cy.zoom();
    const positions = new Map<string, { x: number; y: number }>();
    if (!needsLayout) {
      cy.nodes().forEach((node) => {
        positions.set(node.id(), { ...node.position() });
      });
    }
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
      if (!needsLayout) {
        for (const [id, pos] of positions) {
          const node = cy.getElementById(id);
          if (node.nonempty()) {
            node.position(pos);
          }
        }
      }
    });
    if (needsLayout) {
      cy.layout({ name: "cose", animate: false }).run();
      signatureRef.current = nextSig;
    } else {
      cy.viewport({ pan, zoom });
    }
  }, [elements]);

  return (
    <div
      ref={containerRef}
      data-testid="topology-canvas"
      className="panel h-full w-full"
      aria-label="Topology graph canvas"
    />
  );
}

// ── Run-to-run diff (M2-14) ─────────────────────────────────────────────────

/**
 * Run-pair selector: reuses the discovery runs listing (``listRuns``) to offer
 * a "from" and "to" run, and on Compare fetches the M2-12 diff client. The
 * resulting diff is lifted to the page so it can both drive the canvas overlay
 * and render the change list.
 */
function DiffControls({
  onDiff,
  active,
  onClear,
}: {
  onDiff: (diff: TopologyDiff) => void;
  active: boolean;
  onClear: () => void;
}) {
  const [fromRun, setFromRun] = useState("");
  const [toRun, setToRun] = useState("");

  const { data: runsData } = useDiscoveryRuns("topology-diff", { limit: 50 });
  const diffQuery = useTopologyDiff(fromRun, toRun, false);
  const runs = runsData?.items ?? [];

  async function handleCompare() {
    if (!fromRun || !toRun) return;
    const result = await diffQuery.refetch();
    if (result.isSuccess && result.data) onDiff(result.data.diff);
  }

  const runOption = (run: (typeof runs)[number]) => (
    <option key={run.id} value={run.id}>
      {run.id.slice(0, 8)}… · {run.status} · {new Date(run.created_at).toLocaleString()}
    </option>
  );

  return (
    <section
      aria-label="Run-to-run diff"
      className="flex flex-wrap items-end gap-3"
    >
      <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">Diff</span>
      <div className="flex flex-col gap-1">
        <label htmlFor="diff-from-run" className="text-[10px] text-zinc-500">
          From run (baseline)
        </label>
        <select
          id="diff-from-run"
          data-testid="diff-from-run"
          value={fromRun}
          onChange={(e) => setFromRun(e.target.value)}
          className="input w-56"
        >
          <option value="">Select a run…</option>
          {runs.map(runOption)}
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor="diff-to-run" className="text-[10px] text-zinc-500">
          To run (compared)
        </label>
        <select
          id="diff-to-run"
          data-testid="diff-to-run"
          value={toRun}
          onChange={(e) => setToRun(e.target.value)}
          className="input w-56"
        >
          <option value="">Select a run…</option>
          {runs.map(runOption)}
        </select>
      </div>
      <button
        type="button"
        data-testid="diff-compare-btn"
        onClick={() => { void handleCompare(); }}
        disabled={diffQuery.isFetching || !fromRun || !toRun}
        className="btn"
      >
        {diffQuery.isFetching ? "Comparing…" : "Compare"}
      </button>
      {active ? (
        <button
          type="button"
          data-testid="diff-clear-btn"
          onClick={onClear}
          className="btn"
        >
          Clear diff
        </button>
      ) : null}
      {diffQuery.error ? (
        <p data-testid="diff-error" role="alert" className="w-full text-xs text-status-error">
          Diff failed: {diffQuery.error.message}
        </p>
      ) : null}
    </section>
  );
}

/** The added/removed change list for the active diff. */
function DiffPanel({ diff }: { diff: TopologyDiff }) {
  const items = diffListItems(diff);
  const count = diffChangeCount(diff);

  return (
    <aside
      data-testid="topology-diff-panel"
      aria-label="Topology diff"
      className="panel min-h-0 overflow-y-auto p-4"
    >
      <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-zinc-500">
        Changes ({count})
      </h3>
      {count === 0 ? (
        <p data-testid="diff-no-changes" className="text-xs text-zinc-500">
          No topology changes between the two runs.
        </p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {items.map((item) => (
            <li
              key={`${item.change}-${item.kind}-${item.category}-${item.label}`}
              data-testid={`diff-item-${item.change}`}
              className="flex items-start gap-2 text-xs"
            >
              <span
                className="mt-0.5 font-mono text-sm leading-none"
                style={{
                  color: item.change === "added" ? DIFF_ADDED_COLOR : DIFF_REMOVED_COLOR,
                }}
                aria-label={item.change}
              >
                {item.change === "added" ? "+" : "−"}
              </span>
              <span className="flex flex-col">
                <span className="font-mono uppercase tracking-wider text-[10px] text-zinc-500">
                  {item.kind} · {item.category}
                </span>
                <span className="font-mono text-zinc-300 break-all">{item.label}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function TopologyPage() {
  const [layer, setLayer] = useState<Layer>("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [diff, setDiff] = useState<TopologyDiff | null>(null);
  const [scopeMode, setScopeMode] = useState<ScopeMode>("site");
  const [selectedSite, setSelectedSite] = useState<string | null>(null);
  const [selectedDevice, setSelectedDevice] = useState("");
  const [depth, setDepth] = useState(2);

  // The inventory powers both scope pickers (distinct sites + device list).
  const { data: devicesData, error: devicesError } = useTopologyInventory(INVENTORY_PAGE, INVENTORY_MAX);
  const inventory = useMemo(() => devicesData?.items ?? [], [devicesData]);
  const sites = useMemo(
    () =>
      Array.from(
        new Set(inventory.map((d) => d.site).filter((s): s is string => s !== null && s !== "")),
      ).sort(),
    [inventory],
  );
  // Default scoped view: the first site, until the operator picks one.
  const activeSite = selectedSite ?? sites[0] ?? null;

  const scopeReady =
    scopeMode === "full" ||
    (scopeMode === "site" ? activeSite !== null : selectedDevice !== "");

  const topologyScope = scopeMode === "device"
    ? { mode: "device" as const, device: selectedDevice, depth, layer }
    : scopeMode === "site"
      ? { mode: "site" as const, site: activeSite, layer }
      : { mode: "full" as const, layer };
  const { data, error, isLoading } = useScopedTopology(topologyScope, scopeReady);

  const capError = error instanceof ApiError && error.status === 413 ? error : null;

  const elements = useMemo(() => {
    if (!data) return [];
    const base = toCytoscapeElements(data);
    // When a diff is active, overlay added (green) / removed (red) classes onto
    // any element present in the current graph (M2-14).
    return diff ? applyDiffClasses(base, diff) : base;
  }, [data, diff]);

  const selectedNode = useMemo(
    () => data?.nodes.find((n) => n.key === selectedKey) ?? null,
    [data, selectedKey],
  );

  const hasNodes = (data?.nodes.length ?? 0) > 0;

  return (
    <div className="flex h-full flex-col gap-6">
      <PageHeader
        title="Topology"
        description="L2/L3 network graph projected from Postgres into Neo4j, rendered with Cytoscape.js."
        actions={
          data?.projected_at ? (
            <span data-testid="topology-as-of" className="badge">
              as of {new Date(data.projected_at).toLocaleString()}
            </span>
          ) : null
        }
      />

      {/* Scope selector: scoped (site / device neighborhood) by default; the
          full-graph fetch is explicit and server-capped (audit Wave 5). */}
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Topology scope">
        <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
          Scope
        </span>
        {SCOPE_MODES.map((opt) => (
          <button
            key={opt.value}
            type="button"
            data-testid={`topology-scope-${opt.value}`}
            title={opt.title}
            aria-pressed={scopeMode === opt.value}
            onClick={() => setScopeMode(opt.value)}
            className={`btn ${
              scopeMode === opt.value ? "border-accent bg-accent/10 text-accent" : ""
            }`}
          >
            {opt.label}
          </button>
        ))}
        {scopeMode === "site" && sites.length > 0 ? (
          <select
            data-testid="topology-site-select"
            aria-label="Site"
            value={activeSite ?? ""}
            onChange={(e) => setSelectedSite(e.target.value)}
            className="input w-48"
          >
            {sites.map((site) => (
              <option key={site} value={site}>
                {site}
              </option>
            ))}
          </select>
        ) : null}
        {scopeMode === "device" ? (
          <>
            <select
              data-testid="topology-device-select"
              aria-label="Center device"
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="input w-56"
            >
              <option value="">Select a device…</option>
              {inventory.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.hostname}
                </option>
              ))}
            </select>
            <select
              data-testid="topology-depth-select"
              aria-label="Neighborhood depth"
              title="Hop radius around the selected device"
              value={depth}
              onChange={(e) => setDepth(Number(e.target.value))}
              className="input w-28"
            >
              {DEPTHS.map((d) => (
                <option key={d} value={d}>
                  {d} hop{d > 1 ? "s" : ""}
                </option>
              ))}
            </select>
          </>
        ) : null}
      </div>

      {/* Layer toggle */}
      <div className="flex items-center gap-2" role="group" aria-label="Topology layer">
        <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
          Layer
        </span>
        {LAYERS.map((opt) => (
          <button
            key={opt.value}
            type="button"
            data-testid={`topology-layer-${opt.value}`}
            title={opt.title}
            aria-pressed={layer === opt.value}
            onClick={() => setLayer(opt.value)}
            className={`btn ${
              layer === opt.value ? "border-accent bg-accent/10 text-accent" : ""
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {/* Application-dependency panel: the DEPENDS_ON edges + per-source badges
          for the current app-layer graph (P4 W2-T4). */}
      {layer === "app" && data ? <AppDependencyPanel graph={data} /> : null}

      {/* Run-to-run diff selector */}
      <DiffControls
        onDiff={setDiff}
        active={diff !== null}
        onClear={() => setDiff(null)}
      />

      {/* Scope hints: nothing is fetched until the scope is actionable. */}
      {devicesError ? (
        <ErrorBanner error={new Error(`Device inventory failed to load: ${devicesError.message}. Site and device scoping are unavailable — you can still explicitly load the full graph.`)} data-testid="topology-inventory-error" />
      ) : null}
      {scopeMode === "site" && devicesData && sites.length === 0 ? (
        <div
          data-testid="topology-scope-empty"
          className="flex flex-col items-start gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-4 py-3"
        >
          <p className="text-xs text-zinc-400">
            No sites in the inventory to scope by. Pick a device neighborhood, or explicitly
            load the full graph (server-capped).
          </p>
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={() => setScopeMode("device")}>
              Device neighborhood
            </button>
            <button type="button" className="btn" onClick={() => setScopeMode("full")}>
              Load full graph
            </button>
          </div>
        </div>
      ) : null}
      {scopeMode === "device" && selectedDevice === "" ? (
        <p data-testid="topology-scope-hint" className="text-xs text-zinc-500">
          Select a device to load its neighborhood.
        </p>
      ) : null}

      {/* States */}
      {isLoading ? (
        <p role="status" className="text-xs text-zinc-500">
          Loading topology…
        </p>
      ) : null}
      {capError ? (
        <div
          data-testid="topology-cap-alert"
          role="alert"
          className="panel border-status-error/40 px-4 py-3 text-xs text-zinc-300"
        >
          <p className="mb-1 font-medium text-status-error">Graph too large to load</p>
          <p>{capError.problem.detail}</p>
          <p className="mt-1 text-zinc-500">
            Switch to a site or device-neighborhood scope above to keep the view usable.
          </p>
        </div>
      ) : null}
      {error && !capError ? (
        <ErrorBanner error={new Error(`Topology load failed: ${error.message}`)} />
      ) : null}
      {scopeReady && !isLoading && !error && data && !hasNodes ? (
        <div
          data-testid="topology-empty-state"
          className="flex flex-1 flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">No topology to render</p>
          <p className="max-w-md text-xs leading-relaxed text-zinc-500">
            The topology engine projects discovered devices, interfaces, neighbors, routes,
            and subnets into Neo4j. Run discovery and a projection pass to populate this view.
          </p>
        </div>
      ) : null}

      {/* Graph + detail (selection panel, or the diff change list when diffing) */}
      {hasNodes ? (
        <div className="grid min-h-0 flex-1 grid-cols-[1fr_18rem] gap-4">
          <TopologyCanvas elements={elements} onSelect={setSelectedKey} />
          {diff ? (
            <DiffPanel diff={diff} />
          ) : (
            <aside aria-label="Node detail" className="panel min-h-0 overflow-y-auto p-4">
              <h3 className="mb-3 font-mono text-xs uppercase tracking-widest text-zinc-500">
                Selection
              </h3>
              {selectedNode ? (
                <NodeDetail node={selectedNode} />
              ) : (
                <p data-testid="topology-detail-empty" className="text-xs text-zinc-500">
                  Click a node to inspect its properties.
                </p>
              )}
            </aside>
          )}
        </div>
      ) : null}
    </div>
  );
}
