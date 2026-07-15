import { useQuery } from "@tanstack/react-query";
import { listDeviceInterfaces, listDeviceNeighbors, listDevices, type ListDevicesParams } from "../api/devices";
import { queryKeys } from "./queryKeys";

export function useDevices(params: ListDevicesParams) {
  return useQuery({ queryKey: queryKeys.devices.list(params), queryFn: ({ signal }) => listDevices(params, signal) });
}
export function useTopologyInventory(pageSize: number, max: number) {
  return useQuery({
    queryKey: queryKeys.devices.topologyInventory(pageSize, max),
    queryFn: async ({ signal }) => {
      const first = await listDevices({ limit: pageSize }, signal);
      const items = [...first.items];
      while (items.length < first.total && items.length < max) {
        const page = await listDevices({ limit: pageSize, offset: items.length }, signal);
        if (page.items.length === 0) break;
        items.push(...page.items);
      }
      return { ...first, items };
    },
  });
}
export function useDeviceInterfaces(id: string) {
  return useQuery({ queryKey: queryKeys.devices.interfaces(id), queryFn: ({ signal }) => listDeviceInterfaces(id, signal) });
}
export function useDeviceNeighbors(id: string) {
  return useQuery({ queryKey: queryKeys.devices.neighbors(id), queryFn: ({ signal }) => listDeviceNeighbors(id, signal) });
}
