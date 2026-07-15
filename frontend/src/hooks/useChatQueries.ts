import { useQuery } from "@tanstack/react-query";
import { getSession } from "../api/agents";
import { queryKeys } from "./queryKeys";

export function useAgentSession(id: string, enabled = true) {
  return useQuery({ queryKey: queryKeys.chat.session(id), queryFn: ({ signal }) => getSession(id, signal), enabled });
}
