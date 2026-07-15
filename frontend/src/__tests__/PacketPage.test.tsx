/**
 * PacketPage tests: capture-launch form posts through the API, analysis view
 * renders fixture findings, error states — mocked global fetch, no backend.
 *
 * Mirrors the DocumentsPage / ConfigPage test pattern.
 */

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { CaptureLaunchResponse, PacketFindings } from "../api/packet";
import { PacketPage } from "../pages/PacketPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const CAPTURE_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";

const LAUNCH_RESPONSE: CaptureLaunchResponse = {
  capture_id: CAPTURE_ID,
  status: "queued",
  interface: "eth0",
  device_id: null,
};

const FINDINGS: PacketFindings = {
  packet_count: 1500,
  top_talkers: [
    { src: "10.0.0.1", dst: "10.0.0.2", packets: 800, bytes: 640000 },
    { src: "10.0.0.3", dst: "10.0.0.4", packets: 700, bytes: 560000 },
  ],
  protocol_hierarchy: [
    { protocol: "TCP", packets: 1200 },
    { protocol: "UDP", packets: 300 },
  ],
  tcp_resets: 5,
  tcp_retransmissions: 12,
};

const EMPTY_FINDINGS: PacketFindings = {
  packet_count: 0,
  top_talkers: [],
  protocol_hierarchy: [],
  tcp_resets: 0,
  tcp_retransmissions: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFetch(opts: {
  launchBody?: unknown;
  launchStatus?: number;
  analysisBody?: unknown;
  analysisStatus?: number;
}) {
  return vi.fn((url: string, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    const method = (init?.method ?? "GET").toUpperCase();

    // POST /agents/captures → capture launch
    if (method === "POST" && u.includes("/agents/captures")) {
      const status = opts.launchStatus ?? 202;
      const body = opts.launchBody ?? LAUNCH_RESPONSE;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }

    // GET /agents/captures/{id}/analysis
    if (u.includes("/analysis")) {
      const status = opts.analysisStatus ?? 200;
      const body = opts.analysisBody ?? FINDINGS;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }

    // GET /agents/captures/{id} (status poll — not directly tested here)
    return Promise.resolve(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
renderWithQueryClient(
      <PacketPage />
    );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Page structure ────────────────────────────────────────────────────────────

describe("PacketPage — structure", () => {
  it("renders the page header", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    expect(screen.getByText("Packet Analysis")).toBeInTheDocument();
  });

  it("shows the Launch and Analysis tabs", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    expect(screen.getByTestId("packet-tab-launch")).toBeInTheDocument();
    expect(screen.getByTestId("packet-tab-analysis")).toBeInTheDocument();
  });

  it("shows the Launch panel by default", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    expect(screen.getByTestId("capture-launch-form")).toBeInTheDocument();
  });

  it("switches to Analysis panel on tab click", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    fireEvent.click(screen.getByTestId("packet-tab-analysis"));
    expect(screen.getByTestId("capture-analysis-form")).toBeInTheDocument();
  });
});

// ── Capture launch ────────────────────────────────────────────────────────────

describe("PacketPage — capture launch", () => {
  it("launch button is disabled when interface is empty", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    const btn = screen.getByTestId("capture-launch-btn");
    expect(btn).toBeDisabled();
  });

  it("launch button is enabled when interface is filled", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    expect(screen.getByTestId("capture-launch-btn")).not.toBeDisabled();
  });

  it("posts to /agents/captures with interface on submit", async () => {
    const fetchMock = makeFetch({});
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    fireEvent.click(screen.getByTestId("capture-launch-btn"));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/agents/captures"),
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("includes BPF filter in the request body when provided", async () => {
    const fetchMock = makeFetch({});
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    fireEvent.change(screen.getByTestId("capture-filter"), {
      target: { value: "host 10.0.0.1" },
    });
    fireEvent.click(screen.getByTestId("capture-launch-btn"));

    await waitFor(() => {
      const calls = fetchMock.mock.calls;
      const postCall = calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === "POST",
      );
      expect(postCall).toBeDefined();
      const body = JSON.parse(String((postCall?.[1] as RequestInit)?.body ?? "{}")) as Record<
        string,
        unknown
      >;
      expect(body.capture_filter).toBe("host 10.0.0.1");
    });
  });

  it("shows the capture id after a successful launch", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();

    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    fireEvent.click(screen.getByTestId("capture-launch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("capture-launch-result")).toBeInTheDocument();
    });
    expect(screen.getByTestId("capture-id")).toHaveTextContent(CAPTURE_ID);
  });

  it("shows error alert when the API returns an error", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetch({
        launchBody: {
          type: "urn:netops:error:unprocessable",
          title: "Unprocessable Entity",
          status: 422,
          detail: "BPF filter invalid",
        },
        launchStatus: 422,
      }),
    );
    renderPage();

    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    fireEvent.click(screen.getByTestId("capture-launch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("capture-launch-error")).toBeInTheDocument();
    });
    expect(screen.getByTestId("capture-launch-error")).toHaveTextContent(
      "Launch failed: Unprocessable Entity: BPF filter invalid",
    );
  });

  it("shows a fallback alert when capture launch rejects a non-Error value", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue("transport closed"));
    renderPage();

    fireEvent.change(screen.getByTestId("capture-interface"), {
      target: { value: "eth0" },
    });
    fireEvent.click(screen.getByTestId("capture-launch-btn"));

    expect(await screen.findByTestId("capture-launch-error")).toHaveTextContent(
      "Launch failed",
    );
  });
});

// ── Capture analysis ──────────────────────────────────────────────────────────

describe("PacketPage — analysis view", () => {
  function goToAnalysis() {
    fireEvent.click(screen.getByTestId("packet-tab-analysis"));
  }

  it("fetch button is disabled when capture id is empty", () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    goToAnalysis();
    expect(screen.getByTestId("analysis-fetch-btn")).toBeDisabled();
  });

  it("renders top talkers table from fixture findings", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("top-talkers-table")).toBeInTheDocument();
    });
    expect(screen.getByTestId("talker-row-0")).toHaveTextContent("10.0.0.1");
    expect(screen.getByTestId("talker-row-1")).toHaveTextContent("10.0.0.3");
  });

  it("renders protocol hierarchy table from fixture findings", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("protocol-table")).toBeInTheDocument();
    });
    expect(screen.getByTestId("proto-row-0")).toHaveTextContent("TCP");
    expect(screen.getByTestId("proto-row-1")).toHaveTextContent("UDP");
  });

  it("renders packet count, TCP resets and retransmissions", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("findings-packet-count")).toBeInTheDocument();
    });
    expect(screen.getByTestId("findings-packet-count")).toHaveTextContent("1,500");
    expect(screen.getByTestId("findings-tcp-resets")).toHaveTextContent("5");
    expect(screen.getByTestId("findings-tcp-retx")).toHaveTextContent("12");
  });

  it("shows the empty-findings state when no conversations are returned", async () => {
    vi.stubGlobal("fetch", makeFetch({ analysisBody: EMPTY_FINDINGS }));
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("findings-empty")).toBeInTheDocument();
    });
  });

  it("shows error alert when analysis API fails", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetch({
        analysisBody: {
          type: "urn:netops:error:not-found",
          title: "Not Found",
          status: 404,
          detail: "capture not found",
        },
        analysisStatus: 404,
      }),
    );
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("analysis-error")).toBeInTheDocument();
    });
  });

  it("sends display_filter query param when provided", async () => {
    const fetchMock = makeFetch({});
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    goToAnalysis();

    fireEvent.change(screen.getByTestId("analysis-capture-id"), {
      target: { value: CAPTURE_ID },
    });
    fireEvent.change(screen.getByTestId("analysis-display-filter"), {
      target: { value: "tcp.port == 443" },
    });
    fireEvent.click(screen.getByTestId("analysis-fetch-btn"));

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([url]) => String(url));
      const analysisUrl = urls.find((u) => u.includes("/analysis"));
      expect(analysisUrl).toBeDefined();
      expect(analysisUrl).toContain("display_filter=tcp.port");
    });
  });
});
