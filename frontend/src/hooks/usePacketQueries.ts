import { useMutation } from "@tanstack/react-query";
import { launchCapture } from "../api/packet";

export function useCaptureLaunch() {
  return useMutation({ mutationFn: launchCapture });
}
