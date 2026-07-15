/**
 * IncidentReportsPage tests: list, view inline, download — mocked global fetch.
 *
 * Incident reports are Document rows with kind="incident_report" served by the
 * existing /docs endpoint (M4 T14 / M5 T12). Mirrors DocumentsPage test pattern.
 */

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { DocumentListResponse, DocumentRead } from "../api/docs";
import { IncidentReportsPage } from "../pages/IncidentReportsPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DOC_ID_1 = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const DOC_ID_2 = "ffffffff-ffff-ffff-ffff-ffffffffffff";

const INCIDENT_1: DocumentRead = {
  id: DOC_ID_1,
  kind: "incident_report",
  title: "Incident 2026-06-18 — BGP flap core-rtr-01",
  format: "md",
  content:
    "# Incident Report\n\n## Executive Summary\n\nBGP session flapped.\n\n## Timeline\n\n- 10:00 Session down\n- 10:15 Session restored",
  source_refs: { session_id: "sess-abc" },
  generated_at: "2026-06-18T10:20:00Z",
  generated_by_session_id: "sess-abc",
  created_at: "2026-06-18T10:20:00Z",
  updated_at: "2026-06-18T10:20:00Z",
};

const INCIDENT_2: DocumentRead = {
  id: DOC_ID_2,
  kind: "incident_report",
  title: "Incident 2026-06-17 — DNS resolution failure",
  format: "md",
  content: "# Incident Report\n\nDNS failure on zone corp.example.com",
  source_refs: { session_id: "sess-def" },
  generated_at: "2026-06-17T08:00:00Z",
  generated_by_session_id: "sess-def",
  created_at: "2026-06-17T08:00:00Z",
  updated_at: "2026-06-17T08:00:00Z",
};

const ALL_INCIDENTS: DocumentListResponse = {
  items: [INCIDENT_1, INCIDENT_2],
  total: 2,
  limit: 50,
  offset: 0,
};

const EMPTY_INCIDENTS: DocumentListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFetch(opts: {
  listBody?: unknown;
  listStatus?: number;
  downloadBody?: unknown;
  downloadStatus?: number;
}) {
  return vi.fn((url: string): Promise<Response> => {
    const u = String(url);

    if (u.includes("/download")) {
      const status = opts.downloadStatus ?? 200;
      const body = opts.downloadBody ?? {
        id: DOC_ID_1,
        title: INCIDENT_1.title,
        format: "md",
        content: INCIDENT_1.content,
        generated_at: INCIDENT_1.generated_at,
      };
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }

    // List endpoint (kind=incident_report)
    const status = opts.listStatus ?? 200;
    const body = opts.listBody ?? ALL_INCIDENTS;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
renderWithQueryClient(
      <IncidentReportsPage />
    );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Page-level tests ──────────────────────────────────────────────────────────

describe("IncidentReportsPage — initial state", () => {
  it("renders the page header", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    expect(await screen.findByText("Incident Reports")).toBeInTheDocument();
  });

  it("shows all incident reports in the list", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    expect(
      await screen.findByTestId(`incident-row-${DOC_ID_1}`),
    ).toBeInTheDocument();
    expect(screen.getByTestId(`incident-row-${DOC_ID_2}`)).toBeInTheDocument();
  });

  it("shows the total report count", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);
    expect(screen.getByTestId("incident-total-count")).toHaveTextContent("2");
  });

  it("shows empty state when no incident reports exist", async () => {
    vi.stubGlobal("fetch", makeFetch({ listBody: EMPTY_INCIDENTS }));
    renderPage();
    expect(await screen.findByTestId("incident-empty-state")).toBeInTheDocument();
  });

  it("shows error alert when the docs API fails", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetch({
        listBody: {
          type: "urn:netops:error:internal",
          title: "Internal Server Error",
          status: 500,
          detail: "database error",
        },
        listStatus: 500,
      }),
    );
    renderPage();
    await waitFor(() => {
      expect(screen.getByRole("alert")).toBeInTheDocument();
    });
  });
});

// ── View inline ───────────────────────────────────────────────────────────────

describe("IncidentReportsPage — inline view", () => {
  it("opens the report panel when View is clicked", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);

    fireEvent.click(screen.getByTestId(`incident-view-${DOC_ID_1}`));
    expect(screen.getByTestId("incident-report-panel")).toBeInTheDocument();
  });

  it("renders report content in the panel", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);

    fireEvent.click(screen.getByTestId(`incident-view-${DOC_ID_1}`));
    expect(screen.getByTestId("incident-report-content")).toHaveTextContent(
      "BGP session flapped",
    );
  });

  it("closes the report panel when Close is clicked", async () => {
    vi.stubGlobal("fetch", makeFetch({}));
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);

    fireEvent.click(screen.getByTestId(`incident-view-${DOC_ID_1}`));
    expect(screen.getByTestId("incident-report-panel")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("incident-panel-close"));
    expect(screen.queryByTestId("incident-report-panel")).not.toBeInTheDocument();
  });
});

// ── Download ──────────────────────────────────────────────────────────────────

describe("IncidentReportsPage — download", () => {
  // Stub URL.createObjectURL / revokeObjectURL for the entire describe block so
  // the setTimeout(() => URL.revokeObjectURL(url), 0) in the page never fires
  // against jsdom's unimplemented URL methods — even when a download fails
  // mid-flight and the setTimeout from a prior test runs during teardown.
  beforeEach(() => {
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn(() => "blob:mock"),
      revokeObjectURL: vi.fn(),
    });
  });

  it("triggers a download when Download is clicked", async () => {
    const fetchMock = makeFetch({});
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);

    // Stub anchor click to avoid jsdom navigation
    const clickSpy = vi.fn();
    const origCreate = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      const el = origCreate(tag);
      if (tag === "a") {
        Object.defineProperty(el, "click", { value: clickSpy });
      }
      return el;
    });

    fireEvent.click(screen.getByTestId(`incident-download-${DOC_ID_1}`));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining(`/docs/${DOC_ID_1}/download`),
        expect.anything(),
      );
    });

    vi.restoreAllMocks();
  });

  it("shows download-error alert when the API fails", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetch({
        downloadBody: {
          type: "urn:netops:error:not-found",
          title: "Not Found",
          status: 404,
          detail: "document not found",
        },
        downloadStatus: 404,
      }),
    );
    renderPage();
    await screen.findByTestId(`incident-row-${DOC_ID_1}`);

    fireEvent.click(screen.getByTestId(`incident-download-${DOC_ID_1}`));

    await waitFor(() => {
      expect(screen.getByTestId("incident-download-error")).toBeInTheDocument();
    });
  });
});
