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
import {
  getTopologyGraph,
  type TopologyGraphParams,
  type TopologyNode,
} from "../api/topology";
import { PageHeader } from "../components/PageHeader";
import {
  DEFAULT_NODE_COLOR,
  LABEL_COLOR,
  detailFields,
  toCytoscapeElements,
  type CytoscapeElement,
} from "./topology-graph";

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

// ── Page ──────────────────────────────────────────────────────────────────────

export function TopologyPage() {
  const [layer, setLayer] = useState<Layer>("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const { data, error, isPending } = useQuery({
    queryKey: ["topology-graph", layer],
    queryFn: () => getTopologyGraph({ layer }),
  });

  const elements = useMemo(() => (data ? toCytoscapeElements(data) : []), [data]);

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

      {/* Graph + detail */}
      {hasNodes ? (
        <div className="grid min-h-0 flex-1 grid-cols-[1fr_18rem] gap-4">
          <TopologyCanvas elements={elements} onSelect={setSelectedKey} />
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
        </div>
      ) : null}
    </div>
  );
}
