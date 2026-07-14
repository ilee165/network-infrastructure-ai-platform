import { waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { listDevices } from "../api/devices";
import { queryKeys } from "../hooks/queryKeys";
import { useCaptureLaunch } from "../hooks/usePacketQueries";
import { renderHookWithQueryClient } from "../test/test-utils";

afterEach(() => vi.unstubAllGlobals());

describe("central query layer", () => {
  it("builds hierarchical keys for targeted invalidation", () => {
    expect(queryKeys.devices.list({ limit: 25, offset: 0 })).toEqual([
      "devices",
      "list",
      { limit: 25, offset: 0 },
    ]);
    expect(queryKeys.devices.topologyInventory(100, 1_000)).toEqual([
      "devices",
      "topology-inventory",
      { pageSize: 100, max: 1_000 },
    ]);
    expect(queryKeys.devices.topologyInventory(100, 1_000)).not.toEqual(
      queryKeys.devices.topologyInventory(100, 5_000),
    );
    expect(queryKeys.chat.session("session-1")).toEqual(["chat", "sessions", "session-1"]);
    expect(queryKeys.topology.all).toEqual(["topology"]);
    expect(queryKeys.topology.scoped({ mode: "full", layer: "l3" })).toEqual([
      "topology",
      "graph",
      { mode: "full", layer: "l3" },
    ]);
  });

  it("threads a caller AbortSignal through a cacheable API read", async () => {
    const controller = new AbortController();
    let passedSignal: AbortSignal | undefined;
    const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
      passedSignal = init?.signal as AbortSignal | undefined;
      return new Promise<Response>((_resolve, reject) => {
        passedSignal?.addEventListener("abort", () => reject(passedSignal?.reason), {
          once: true,
        });
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const request = listDevices({ limit: 25 }, controller.signal);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    const cancellation = new Error("cancelled by query owner");
    controller.abort(cancellation);

    expect(fetchMock.mock.calls[0]?.[0]).toContain("/devices?limit=25");
    expect(passedSignal?.aborted).toBe(true);
    await expect(request).rejects.toBe(cancellation);
  });

  it("models capture launch as a server mutation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ capture_id: "capture-1", status: "queued", interface: "eth0", device_id: null }),
          { status: 202, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const { result, queryClient } = renderHookWithQueryClient(() => useCaptureLaunch());
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");

    result.current.mutate({ interface: "eth0" });

    await waitFor(() => expect(result.current.data?.capture_id).toBe("capture-1"));
    expect(invalidate).not.toHaveBeenCalled();
  });
});
