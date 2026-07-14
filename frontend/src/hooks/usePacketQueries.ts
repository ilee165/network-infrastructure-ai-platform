import { useMutation, useQueryClient } from "@tanstack/react-query";
import { launchCapture } from "../api/packet";
import { queryKeys } from "./queryKeys";

export function useCaptureLaunch() {
  const client = useQueryClient();
  return useMutation({ mutationFn: launchCapture, onSuccess: () => client.invalidateQueries({ queryKey: queryKeys.packet.captures }) });
}
