import { useQuery } from "@tanstack/react-query";
import { listPools, listVirtualServers, type ListPoolsParams, type ListVirtualServersParams } from "../api/adc";
import { queryKeys } from "./queryKeys";

export function useVirtualServers(params: ListVirtualServersParams) {
  return useQuery({ queryKey: queryKeys.adc.virtualServers(params), queryFn: ({ signal }) => listVirtualServers(params, signal) });
}
export function usePools(params: ListPoolsParams) {
  return useQuery({ queryKey: queryKeys.adc.pools(params), queryFn: ({ signal }) => listPools(params, signal) });
}
