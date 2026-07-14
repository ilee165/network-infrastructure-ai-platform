import type { ListVirtualServersParams, ListPoolsParams } from "../api/adc";
import type { ListDevicesParams } from "../api/devices";
import type { TopologyGraphParams, TopologyNeighborhoodParams } from "../api/topology";

export type TopologyScope =
  | { mode: "site"; site: string | null; layer: TopologyGraphParams["layer"] }
  | { mode: "device"; device: string; depth: number; layer: TopologyGraphParams["layer"] }
  | { mode: "full"; layer: TopologyGraphParams["layer"] };

export const queryKeys = {
  adc: {
    all: ["adc"] as const,
    virtualServers: (params: ListVirtualServersParams) => ["adc", "virtual-servers", params] as const,
    pools: (params: ListPoolsParams) => ["adc", "pools", params] as const,
  },
  devices: {
    all: ["devices"] as const,
    list: (params: ListDevicesParams) => ["devices", "list", params] as const,
    interfaces: (id: string) => ["devices", id, "interfaces"] as const,
    neighbors: (id: string) => ["devices", id, "neighbors"] as const,
  },
  discovery: {
    runs: (scope: string) => ["discovery", "runs", scope] as const,
  },
  topology: {
    all: ["topology"] as const,
    graph: (params: TopologyGraphParams) => ["topology", "graph", params] as const,
    scoped: (scope: TopologyScope) => ["topology", "graph", scope] as const,
    neighborhood: (params: TopologyNeighborhoodParams) => ["topology", "neighborhood", params] as const,
    diff: (from: string, to: string) => ["topology", "diff", from, to] as const,
  },
  chat: {
    all: ["chat"] as const,
    sessions: ["chat", "sessions"] as const,
    session: (id: string) => ["chat", "sessions", id] as const,
    history: (id: string) => ["chat", "sessions", id, "history"] as const,
    trace: (id: string) => ["chat", "sessions", id, "trace"] as const,
  },
  packet: { all: ["packet"] as const, captures: ["packet", "captures"] as const },
  auth: { me: ["auth", "me"] as const },
} as const;
