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
    expect(queryKeys.chat.session("session-1")).toEqual(["chat", "sessions", "session-1"]);
    expect(queryKeys.topology.all).toEqual(["topology"]);
    expect(queryKeys.topology.scoped({ mode: "full", layer: "l3" })).toEqual([
      "topology",
      "graph",
      { mode: "full", layer: "l3" },
    ]);
  });

  it("threads a caller AbortSignal through a cacheable API read", async () => {
    const signal = new AbortController().signal;
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, limit: 25, offset: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await listDevices({ limit: 25 }, signal);

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/devices?limit=25"),
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
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
    const { result } = renderHookWithQueryClient(() => useCaptureLaunch());

    result.current.mutate({ interface: "eth0" });

    await waitFor(() => expect(result.current.data?.capture_id).toBe("capture-1"));
  });
});
