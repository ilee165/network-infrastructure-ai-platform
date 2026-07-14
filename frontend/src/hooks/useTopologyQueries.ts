import { useQuery } from "@tanstack/react-query";
import { getTopologyDiff, getTopologyGraph, getTopologyNeighborhood, type TopologyGraphParams, type TopologyNeighborhoodParams } from "../api/topology";
import { queryKeys, type TopologyScope } from "./queryKeys";

export function useTopologyGraph(params: TopologyGraphParams, enabled = true) {
  return useQuery({ queryKey: queryKeys.topology.graph(params), queryFn: ({ signal }) => getTopologyGraph(params, signal), enabled });
}
export function useTopologyNeighborhood(params: TopologyNeighborhoodParams, enabled = true) {
  return useQuery({ queryKey: queryKeys.topology.neighborhood(params), queryFn: ({ signal }) => getTopologyNeighborhood(params, signal), enabled });
}
export function useTopologyDiff(from: string, to: string, enabled = true) {
  return useQuery({ queryKey: queryKeys.topology.diff(from, to), queryFn: ({ signal }) => getTopologyDiff(from, to, signal), enabled });
}
export type { TopologyScope } from "./queryKeys";

export function useScopedTopology(scope: TopologyScope, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.topology.scoped(scope),
    enabled,
    retry: false,
    queryFn: ({ signal }) => {
      if (scope.mode === "device") return getTopologyNeighborhood(scope, signal);
      if (scope.mode === "site" && scope.site !== null) return getTopologyGraph({ layer: scope.layer, site: scope.site }, signal);
      return getTopologyGraph({ layer: scope.layer }, signal);
    },
  });
}
