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
 */

import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { listRuns } from "../api/discovery";
import {
  getTopologyDiff,
  getTopologyGraph,
  type TopologyDiff,
  type TopologyGraphParams,
  type TopologyNode,
} from "../api/topology";
import { PageHeader } from "../components/PageHeader";
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
];

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
 * Renders the topology graph into a Cytoscape instance and reports node
 * selection up via ``onSelect``. The instance is rebuilt whenever the element
 * set changes and destroyed on unmount (no canvas leaks across re-renders).
 */
function TopologyCanvas({
  elements,
  onSelect,
}: {
  elements: CytoscapeElement[];
  onSelect: (key: string | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return;
    }
    const cy = cytoscape({
      container,
      elements,
      style: buildStylesheet(),
      layout: { name: "cose", animate: false },
    });
    cy.on("tap", "node", (evt) => onSelect(evt.target.id()));
    cy.on("tap", (evt) => {
      // Tap on empty background clears the selection.
      if (evt.target === cy) {
        onSelect(null);
      }
    });
    return () => {
      cy.destroy();
    };
  }, [elements, onSelect]);

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
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: runsData } = useQuery({
    queryKey: ["discovery-runs", "topology-diff"],
    queryFn: () => listRuns({ limit: 50 }),
  });
  const runs = runsData?.items ?? [];

  async function handleCompare() {
    if (!fromRun || !toRun) return;
    setPending(true);
    setError(null);
    try {
      const response = await getTopologyDiff(fromRun, toRun);
      onDiff(response.diff);
    } catch (err) {
      setError(err instanceof Error ? err.message : "diff failed");
    } finally {
      setPending(false);
    }
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
        onClick={() => void handleCompare()}
        disabled={pending || !fromRun || !toRun}
        className="btn"
      >
        {pending ? "Comparing…" : "Compare"}
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
      {error ? (
        <p data-testid="diff-error" role="alert" className="w-full text-xs text-status-error">
          Diff failed: {error}
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

  const { data, error, isPending } = useQuery({
    queryKey: ["topology-graph", layer],
    queryFn: () => getTopologyGraph({ layer }),
  });

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

      {/* Run-to-run diff selector */}
      <DiffControls
        onDiff={setDiff}
        active={diff !== null}
        onClear={() => setDiff(null)}
      />

      {/* States */}
      {isPending ? (
        <p role="status" className="text-xs text-zinc-500">
          Loading topology…
        </p>
      ) : null}
      {error ? (
        <div
          role="alert"
          className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
        >
          Topology load failed: {error.message}
        </div>
      ) : null}
      {!isPending && !error && !hasNodes ? (
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
