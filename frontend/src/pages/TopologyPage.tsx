/**
 * Topology: interactive L2/L3 network graph.
 *
 * Populated in M2: the topology engine projects Postgres inventory into
 * Neo4j (CONNECTED_TO, L3_ADJACENT, IN_SUBNET, …) and this page renders the
 * projection with Cytoscape.js (ADR-0012 decision 6).
 */

import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function TopologyPage() {
  return (
    <div className="flex h-full flex-col gap-6">
      <PageHeader
        title="Topology"
        description="L2/L3 network graph projected from Postgres into Neo4j, rendered with Cytoscape.js."
      />
      <div className="flex flex-1 flex-col justify-center">
        <EmptyState
          title="No topology to render"
          description="The topology engine builds CONNECTED_TO and L3-adjacency edges from discovered neighbors, routes, and subnets; this canvas renders that Neo4j projection."
          milestone="M2"
        />
      </div>
    </div>
  );
}
