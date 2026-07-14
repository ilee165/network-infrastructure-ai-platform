/**
 * AdcPage tests: virtual-server table, pool table + nested-member expansion,
 * empty states, error banners — mocked global fetch, no backend required.
 */

import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { PoolListResponse, VirtualServerListResponse } from "../api/adc";
import { AdcPage } from "../pages/AdcPage";

const VIRTUAL_SERVERS: VirtualServerListResponse = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "/Common/vs_web",
      vip_address: "203.0.113.10",
      port: 443,
      protocol: "tcp",
      vrf: null,
      enabled: true,
      availability: "available",
      pool_name: "/Common/pool_web",
      description: null,
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "f5_bigip",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_VIRTUAL_SERVERS: VirtualServerListResponse = {
  items: [],
  total: 0,
  limit: 100,
  offset: 0,
};

const POOLS: PoolListResponse = {
  items: [
    {
      id: "22222222-2222-2222-2222-222222222222",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "/Common/pool_web",
      monitors: ["/Common/http"],
      availability: "available",
      members: [
        {
          name: "/Common/web01:80",
          address: "10.0.0.11",
          fqdn: null,
          port: 80,
          vrf: null,
          admin_state: "enabled",
          availability: "available",
        },
      ],
      description: null,
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "f5_bigip",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_POOL: PoolListResponse = {
  items: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "/Common/pool_empty",
      monitors: [],
      availability: "unknown",
      members: [],
      description: null,
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "f5_bigip",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_POOLS: PoolListResponse = { items: [], total: 0, limit: 100, offset: 0 };

function fetchRouted(vsBody: unknown, poolBody: unknown) {
  return vi.fn((url: string): Promise<Response> => {
    const body = String(url).includes("/adc/pools") ? poolBody : vsBody;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
renderWithQueryClient(
      <AdcPage />
    );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AdcPage — virtual servers", () => {
  it("renders one row per virtual server with VIP, protocol, pool, availability", async () => {
    vi.stubGlobal("fetch", fetchRouted(VIRTUAL_SERVERS, EMPTY_POOLS));
    renderPage();

    expect(await screen.findByText("/Common/vs_web")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.10:443")).toBeInTheDocument();
    expect(screen.getByText("/Common/pool_web")).toBeInTheDocument();
    expect(screen.getByText("available")).toBeInTheDocument();
  });

  it("shows the empty state when no virtual servers exist", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_VIRTUAL_SERVERS, EMPTY_POOLS));
    renderPage();

    expect(await screen.findByTestId("virtual-servers-empty-state")).toBeInTheDocument();
  });

  it("shows an error alert when the virtual-servers API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    expect(await screen.findAllByRole("alert")).not.toHaveLength(0);
  });

  it("keeps enabled and availability as separate columns (not collapsed)", async () => {
    const disabled: VirtualServerListResponse = {
      ...VIRTUAL_SERVERS,
      items: [{ ...VIRTUAL_SERVERS.items[0]!, enabled: false, availability: "offline" }],
    };
    vi.stubGlobal("fetch", fetchRouted(disabled, EMPTY_POOLS));
    renderPage();

    await screen.findByText("/Common/vs_web");
    expect(screen.getByText("No")).toBeInTheDocument();
    expect(screen.getByText("offline")).toBeInTheDocument();
  });
});

describe("AdcPage — pools", () => {
  it("shows the empty state when no pools exist", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_VIRTUAL_SERVERS, EMPTY_POOLS));
    renderPage();

    expect(await screen.findByTestId("pools-empty-state")).toBeInTheDocument();
  });

  it("renders an empty pool (no members) as data, not an error", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_VIRTUAL_SERVERS, EMPTY_POOL));
    renderPage();

    expect(await screen.findByText("/Common/pool_empty")).toBeInTheDocument();
    // The member count column shows 0, not an error state.
    const row = screen.getByTestId(`pool-row-${EMPTY_POOL.items[0]!.id}`);
    expect(row).toHaveTextContent("0");
  });

  it("expands a pool row to reveal its nested members table", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_VIRTUAL_SERVERS, POOLS));
    renderPage();

    const row = await screen.findByTestId(`pool-row-${POOLS.items[0]!.id}`);
    expect(row).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");
    const detail = await screen.findByTestId(`pool-detail-${POOLS.items[0]!.id}`);
    expect(detail).toHaveTextContent("/Common/web01:80");
    expect(detail).toHaveTextContent("enabled");
  });

  it("expanding an empty pool shows 'No members' text, not an error", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_VIRTUAL_SERVERS, EMPTY_POOL));
    renderPage();

    const row = await screen.findByTestId(`pool-row-${EMPTY_POOL.items[0]!.id}`);
    fireEvent.click(row);
    const detail = await screen.findByTestId(`pool-detail-${EMPTY_POOL.items[0]!.id}`);
    expect(detail).toHaveTextContent("No members in this pool.");
  });
});

describe("AdcPage — pagination", () => {
  function fetchByOffset(page0: unknown, page1: unknown) {
    return vi.fn((url: string): Promise<Response> => {
      const offset = new URL(String(url), "http://t").searchParams.get("offset") ?? "0";
      const body = String(url).includes("/adc/pools")
        ? EMPTY_POOLS
        : offset === "100"
          ? page1
          : page0;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
  }

  it("surfaces the true total and pages beyond the first 100 (no silent truncation)", async () => {
    const page0: VirtualServerListResponse = { ...VIRTUAL_SERVERS, total: 150, offset: 0 };
    const page1: VirtualServerListResponse = {
      ...VIRTUAL_SERVERS,
      items: [
        {
          ...VIRTUAL_SERVERS.items[0]!,
          id: "99999999-9999-9999-9999-999999999999",
          name: "/Common/vs_page2",
        },
      ],
      total: 150,
      offset: 100,
    };
    vi.stubGlobal("fetch", fetchByOffset(page0, page1));
    renderPage();

    // The pager shows the real total — items beyond the first page are reachable.
    expect(await screen.findByTestId("virtual-servers-pagination-range")).toHaveTextContent(
      "Showing 1–100 of 150",
    );
    fireEvent.click(screen.getByTestId("virtual-servers-pagination-next"));
    expect(await screen.findByText("/Common/vs_page2")).toBeInTheDocument();
    expect(screen.getByTestId("virtual-servers-pagination-range")).toHaveTextContent(
      "Showing 101–150 of 150",
    );
  });

  it("renders no pager when the whole result fits on one page", async () => {
    vi.stubGlobal("fetch", fetchRouted(VIRTUAL_SERVERS, EMPTY_POOLS));
    renderPage();

    await screen.findByText("/Common/vs_web");
    expect(screen.queryByTestId("virtual-servers-pagination")).not.toBeInTheDocument();
  });
});
