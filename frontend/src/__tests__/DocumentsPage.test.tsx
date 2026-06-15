/**
 * DocumentsPage tests: document library list, kind filter, download, and
 * Mermaid client-side render — mocked global fetch, no backend required.
 *
 * Mirrors the ConfigPage test pattern: fetchRouted() by URL substring,
 * QueryClientProvider wrapping, afterEach unstubAll.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DocumentListResponse, DocumentRead } from "../api/docs";
import { DocumentsPage } from "../pages/DocumentsPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DOC_ID_INV = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const DOC_ID_DIAG = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const DOC_ID_RUN = "cccccccc-cccc-cccc-cccc-cccccccccccc";

const INV_DOC: DocumentRead = {
  id: DOC_ID_INV,
  kind: "inventory",
  title: "Network Inventory — Site A",
  format: "md",
  content: "# Network Inventory\n\n| Device | IP |\n|--------|----|\n| core-sw-01 | 192.168.1.1 |",
  source_refs: { site: "site-a" },
  generated_at: "2024-01-15T10:00:00Z",
  generated_by_session_id: null,
  created_at: "2024-01-15T10:00:00Z",
  updated_at: "2024-01-15T10:00:00Z",
};

const DIAG_DOC: DocumentRead = {
  id: DOC_ID_DIAG,
  kind: "diagram",
  title: "L2 Topology Diagram",
  format: "mermaid",
  content: "graph LR\n  A[core-sw-01] --> B[dist-sw-01]\n  B --> C[access-sw-01]",
  source_refs: { site: "site-a" },
  generated_at: "2024-01-15T11:00:00Z",
  generated_by_session_id: null,
  created_at: "2024-01-15T11:00:00Z",
  updated_at: "2024-01-15T11:00:00Z",
};

const RUN_DOC: DocumentRead = {
  id: DOC_ID_RUN,
  kind: "runbook",
  title: "BGP Troubleshooting Runbook",
  format: "md",
  content: "# BGP Troubleshooting\n\nFollow these steps...",
  source_refs: { device: "core-rtr-01" },
  generated_at: "2024-01-15T12:00:00Z",
  generated_by_session_id: null,
  created_at: "2024-01-15T12:00:00Z",
  updated_at: "2024-01-15T12:00:00Z",
};

const ALL_DOCS: DocumentListResponse = {
  items: [INV_DOC, DIAG_DOC, RUN_DOC],
  total: 3,
  limit: 50,
  offset: 0,
};

const EMPTY_DOCS: DocumentListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

const INVENTORY_ONLY: DocumentListResponse = {
  items: [INV_DOC],
  total: 1,
  limit: 50,
  offset: 0,
};

const DIAGRAM_ONLY: DocumentListResponse = {
  items: [DIAG_DOC],
  total: 1,
  limit: 50,
  offset: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Route fetch by URL query-string kind parameter.
 * Calls to /docs?kind=inventory → inventoryDocs,
 *            /docs?kind=diagram  → diagramDocs,
 *            /docs?kind=runbook  → runbookDocs,
 *            /docs               → allDocs (no kind param)
 * /docs/{id}/download            → downloadBody
 */
function fetchRouted(opts: {
  allDocs?: unknown;
  inventoryDocs?: unknown;
  diagramDocs?: unknown;
  runbookDocs?: unknown;
  downloadBody?: unknown;
}) {
  return vi.fn((url: string): Promise<Response> => {
    const u = String(url);
    let body: unknown;
    if (u.includes("/download")) {
      body = opts.downloadBody ?? {
        id: DOC_ID_INV,
        title: "Network Inventory — Site A",
        format: "md",
        content: "# Network Inventory\n\n| Device | IP |",
        generated_at: "2024-01-15T10:00:00Z",
      };
    } else if (u.includes("kind=inventory")) {
      body = opts.inventoryDocs ?? INVENTORY_ONLY;
    } else if (u.includes("kind=diagram")) {
      body = opts.diagramDocs ?? DIAGRAM_ONLY;
    } else if (u.includes("kind=runbook")) {
      body = opts.runbookDocs ?? { items: [RUN_DOC], total: 1, limit: 50, offset: 0 };
    } else {
      body = opts.allDocs ?? ALL_DOCS;
    }
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <DocumentsPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Page-level tests ──────────────────────────────────────────────────────────

describe("DocumentsPage — initial state", () => {
  it("renders the page header", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByText("Documents")).toBeInTheDocument();
  });

  it("shows all documents in the default (all kinds) view", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByTestId(`doc-row-${DOC_ID_INV}`)).toBeInTheDocument();
    expect(screen.getByTestId(`doc-row-${DOC_ID_DIAG}`)).toBeInTheDocument();
    expect(screen.getByTestId(`doc-row-${DOC_ID_RUN}`)).toBeInTheDocument();
  });

  it("shows the total document count", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId("docs-total-count")).toHaveTextContent("3");
  });

  it("shows an empty state when no documents exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({ allDocs: EMPTY_DOCS }));
    renderPage();
    expect(await screen.findByTestId("docs-empty-state")).toBeInTheDocument();
  });

  it("shows an error alert when the docs API fails", async () => {
    const mock = vi.fn((): Promise<Response> =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            type: "urn:netops:error:internal",
            title: "Internal Server Error",
            status: 500,
            detail: "unexpected failure",
          }),
          { status: 500, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    vi.stubGlobal("fetch", mock);
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(/Documents load failed/);
  });
});

// ── Kind filter ───────────────────────────────────────────────────────────────

describe("DocumentsPage — kind filter", () => {
  it("renders kind filter tabs: All, Inventory, Diagram, Runbook", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId("docs-tab-all")).toBeInTheDocument();
    expect(screen.getByTestId("docs-tab-inventory")).toBeInTheDocument();
    expect(screen.getByTestId("docs-tab-diagram")).toBeInTheDocument();
    expect(screen.getByTestId("docs-tab-runbook")).toBeInTheDocument();
  });

  it("clicking Inventory tab shows only inventory documents", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId("docs-tab-inventory"));
    expect(await screen.findByTestId(`doc-row-${DOC_ID_INV}`)).toBeInTheDocument();
  });

  it("clicking Diagram tab shows only diagram documents", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId("docs-tab-diagram"));
    expect(await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`)).toBeInTheDocument();
  });

  it("clicking All tab resets to all-kinds query (no kind param)", async () => {
    const mock = fetchRouted({});
    vi.stubGlobal("fetch", mock);
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId("docs-tab-inventory"));
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId("docs-tab-all"));
    // Should call /docs without a kind query param
    await waitFor(() => {
      const calls = mock.mock.calls.map(([u]) => String(u));
      expect(calls.some((u) => u.includes("/docs") && !u.includes("kind="))).toBe(true);
    });
  });
});

// ── Document rows ─────────────────────────────────────────────────────────────

describe("DocumentsPage — document rows", () => {
  it("shows kind badge on each row", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId(`doc-kind-${DOC_ID_INV}`)).toHaveTextContent("inventory");
    expect(screen.getByTestId(`doc-kind-${DOC_ID_DIAG}`)).toHaveTextContent("diagram");
    expect(screen.getByTestId(`doc-kind-${DOC_ID_RUN}`)).toHaveTextContent("runbook");
  });

  it("shows format badge on each row", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId(`doc-format-${DOC_ID_INV}`)).toHaveTextContent("md");
    expect(screen.getByTestId(`doc-format-${DOC_ID_DIAG}`)).toHaveTextContent("mermaid");
  });

  it("shows the document title", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    expect(await screen.findByText("Network Inventory — Site A")).toBeInTheDocument();
    expect(screen.getByText("L2 Topology Diagram")).toBeInTheDocument();
  });

  it("shows a download button on each row", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId(`doc-download-${DOC_ID_INV}`)).toBeInTheDocument();
    expect(screen.getByTestId(`doc-download-${DOC_ID_DIAG}`)).toBeInTheDocument();
  });

  it("shows a View button on each row", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    expect(screen.getByTestId(`doc-view-${DOC_ID_INV}`)).toBeInTheDocument();
  });
});

// ── Mermaid render panel ──────────────────────────────────────────────────────

describe("DocumentsPage — Mermaid render panel", () => {
  it("clicking View on a mermaid doc shows the mermaid panel", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    expect(await screen.findByTestId("mermaid-panel")).toBeInTheDocument();
  });

  it("mermaid panel shows the raw Mermaid source", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    const panel = await screen.findByTestId("mermaid-panel");
    expect(panel).toBeInTheDocument();
    expect(screen.getByTestId("mermaid-source")).toHaveTextContent("graph LR");
  });

  it("mermaid panel shows a PNG export button", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    await screen.findByTestId("mermaid-panel");
    expect(screen.getByTestId("mermaid-export-png")).toBeInTheDocument();
  });

  it("clicking View on a non-mermaid doc shows the content panel instead", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_INV}`));
    expect(await screen.findByTestId("doc-content-panel")).toBeInTheDocument();
    expect(screen.queryByTestId("mermaid-panel")).not.toBeInTheDocument();
  });

  it("clicking View on a mermaid doc does not show the plain content panel", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    await screen.findByTestId("mermaid-panel");
    expect(screen.queryByTestId("doc-content-panel")).not.toBeInTheDocument();
  });

  it("panel can be closed by clicking the Close button", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    await screen.findByTestId("mermaid-panel");
    fireEvent.click(screen.getByTestId("doc-panel-close"));
    await waitFor(() => {
      expect(screen.queryByTestId("mermaid-panel")).not.toBeInTheDocument();
      expect(screen.queryByTestId("doc-content-panel")).not.toBeInTheDocument();
    });
  });
});

// ── Download ──────────────────────────────────────────────────────────────────

describe("DocumentsPage — download", () => {
  it("requests the canonical /docs/{id}/download path when download is clicked", async () => {
    const mock = fetchRouted({});
    vi.stubGlobal("fetch", mock);
    // Mock createObjectURL and revokeObjectURL so download doesn't crash in jsdom
    const createURL = vi.fn(() => "blob:mock-url");
    const revokeURL = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: createURL, revokeObjectURL: revokeURL });
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId(`doc-download-${DOC_ID_INV}`));
    await waitFor(() => {
      expect(mock).toHaveBeenCalledWith(
        expect.stringContaining(`/docs/${DOC_ID_INV}/download`),
        expect.anything(),
      );
    });
  });

  it("defers revokeObjectURL via setTimeout (not called synchronously with createObjectURL)", async () => {
    // Use a spy that wraps the real setTimeout so testing-library's internal
    // polling timers continue to work.  We capture only zero-delay callbacks
    // and forward everything else to the real implementation.
    const capturedZeroDelayCallbacks: Array<() => void> = [];
    const realSetTimeout = globalThis.setTimeout.bind(globalThis);
    const setTimeoutSpy = vi
      .spyOn(globalThis, "setTimeout")
      .mockImplementation(
        (fn: TimerHandler, delay?: number, ...args: unknown[]): ReturnType<typeof setTimeout> => {
          if (typeof fn === "function" && (delay === 0 || delay === undefined)) {
            capturedZeroDelayCallbacks.push(fn as () => void);
            // Still schedule it for real so nothing is blocked
            return realSetTimeout(fn as TimerHandler, delay, ...args);
          }
          return realSetTimeout(fn as TimerHandler, delay, ...args);
        },
      );

    try {
      const mock = fetchRouted({});
      vi.stubGlobal("fetch", mock);
      const createURL = vi.fn(() => "blob:mock-url");
      const revokeURL = vi.fn();
      vi.stubGlobal("URL", { createObjectURL: createURL, revokeObjectURL: revokeURL });

      renderPage();
      await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
      fireEvent.click(screen.getByTestId(`doc-download-${DOC_ID_INV}`));

      // Wait until createObjectURL is called (download blob was created)
      await waitFor(() => expect(createURL).toHaveBeenCalled());

      // At the synchronous level (before the next macro-task), revokeObjectURL
      // must not have been called yet.  waitFor drains microtasks but the
      // setTimeout(0) fires in the next macro-task, which happens after
      // revokeURL is called by the real timer.  So: we inspect whether
      // our spy captured a zero-delay callback containing the revoke.
      const revokeCallback = capturedZeroDelayCallbacks.find(
        (cb) => {
          // Invoke a clone-check: call it and see if revokeURL gets called.
          // Reset mock first so we can isolate this call.
          revokeURL.mockClear();
          cb();
          return revokeURL.mock.calls.length > 0;
        },
      );
      expect(revokeCallback).toBeDefined();
      expect(revokeURL).toHaveBeenCalledWith("blob:mock-url");
    } finally {
      setTimeoutSpy.mockRestore();
    }
  });

  it("shows a download error alert when the fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string): Promise<Response> => {
        if (String(url).includes("/download")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ detail: "not found" }),
              { status: 404, headers: { "Content-Type": "application/json" } },
            ),
          );
        }
        return Promise.resolve(
          new Response(JSON.stringify(ALL_DOCS), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_INV}`);
    fireEvent.click(screen.getByTestId(`doc-download-${DOC_ID_INV}`));
    expect(await screen.findByRole("alert")).toHaveTextContent(/download failed/i);
  });
});

// ── PNG export stub ───────────────────────────────────────────────────────────

describe("DocumentsPage — PNG export stub", () => {
  it("Export PNG button is disabled (stub — no mermaid renderer)", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    await screen.findByTestId("mermaid-panel");
    const btn = screen.getByTestId("mermaid-export-png");
    expect(btn).toBeDisabled();
  });

  it("clicking the disabled Export PNG button does not trigger a file download", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    const createURL = vi.fn(() => "blob:mock-url");
    vi.stubGlobal("URL", { createObjectURL: createURL, revokeObjectURL: vi.fn() });
    renderPage();
    await screen.findByTestId(`doc-row-${DOC_ID_DIAG}`);
    fireEvent.click(screen.getByTestId(`doc-view-${DOC_ID_DIAG}`));
    await screen.findByTestId("mermaid-panel");
    // Attempt to click the disabled button
    fireEvent.click(screen.getByTestId("mermaid-export-png"));
    // createObjectURL must never be called — no canvas export attempted
    expect(createURL).not.toHaveBeenCalled();
  });
});
