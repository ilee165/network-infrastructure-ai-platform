import { useQuery } from "@tanstack/react-query";
import { listRuns } from "../api/discovery";
import { queryKeys } from "./queryKeys";

export function useDiscoveryRuns(scope: string, params: { limit?: number; offset?: number }, pollMs?: number) {
  return useQuery({
    queryKey: [...queryKeys.discovery.runs(scope), params],
    queryFn: ({ signal }) => listRuns(params, signal),
    refetchInterval: pollMs ? (query) => query.state.data?.items.some((run) => run.status === "pending" || run.status === "running") ? pollMs : false : false,
  });
}
