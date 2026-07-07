/**
 * ApplicationsPage tests: the manual application-tagging surface (P4 W2-T3).
 *
 * Read surface (rider P2): the application list with per-origin badges and the
 * per-application dependency detail with per-source badges. Write flows + role
 * gating (rider P3) are added to this same file in P3. Mocked global fetch,
 * react-query provider, no backend required — the AdcPage test style.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  ApplicationDependencyRead,
  ApplicationListResponse,
  ApplicationRead,
} from "../api/applications";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { useAuthStore, type UserMe } from "../stores/auth";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const MANUAL_APP: ApplicationRead = {
  id: "11111111-1111-1111-1111-111111111111",
  name: "billing-web",
  description: "customer billing frontend",
  fqdns: ["billing.example.com"],
  origin: "manual",
  origin_ref: null,
  owner: "payments-team",
  created_by: "44444444-4444-4444-4444-444444444444",
  created_at: "2026-07-01T10:00:00Z",
  updated_at: "2026-07-01T10:00:00Z",
};

const DERIVED_APP: ApplicationRead = {
  id: "22222222-2222-2222-2222-222222222222",
  name: "vs-billing-app",
  description: null,
  fqdns: [],
  origin: "derived",
  origin_ref: "f5:aaaa:/Common/vs_billing",
  owner: null,
  created_by: null,
  created_at: "2026-07-01T10:00:00Z",
  updated_at: "2026-07-01T10:00:00Z",
};

const LIST: ApplicationListResponse = {
  items: [MANUAL_APP, DERIVED_APP],
  total: 2,
  limit: 100,
  offset: 0,
};

const EMPTY_LIST: ApplicationListResponse = { items: [], total: 0, limit: 100, offset: 0 };

const MANUAL_DEP: ApplicationDependencyRead = {
  id: "33333333-3333-3333-3333-333333333333",
  application_id: MANUAL_APP.id,
  target_kind: "device",
  target_ref: "dddddddd-dddd-dddd-dddd-dddddddddddd",
  source: "manual",
  provenance: [{ kind: "user", ref: "44444444-4444-4444-4444-444444444444" }],
  derived_at: "2026-07-01T10:00:00Z",
  created_by: "44444444-4444-4444-4444-444444444444",
  created_at: "2026-07-01T10:00:00Z",
};

const F5_DEP: ApplicationDependencyRead = {
  ...MANUAL_DEP,
  id: "55555555-5555-5555-5555-555555555555",
  target_kind: "ip_address",
  target_ref: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
  source: "f5",
  provenance: [{ kind: "adc_pool_member", ref: "pool:/Common/pool_billing" }],
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Route mocked fetch: dependency reads first (most specific), then the list. */
function fetchRouted(list: unknown, deps: Record<string, unknown[]>) {
  return vi.fn((url: string): Promise<Response> => {
    const path = String(url);
    let body: unknown = list;
    const depMatch = path.match(/\/applications\/([^/?]+)\/dependencies/);
    if (depMatch) {
      body = deps[depMatch[1]!] ?? [];
    }
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function makeUser(role: string): UserMe {
  return {
    id: "44444444-4444-4444-4444-444444444444",
    username: "u",
    email: null,
    display_name: null,
    role,
    is_active: true,
    must_change_password: false,
  };
}

function renderPage(role = "viewer"): void {
  useAuthStore.setState({ user: makeUser(role), status: "authed", accessToken: "t" });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ApplicationsPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  useAuthStore.setState({ user: null, status: "anon", accessToken: null });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── applications_page_lists_manual_and_derived_applications ────────────────────

describe("applications_page_lists_manual_and_derived_applications", () => {
  it("renders one row per application across both origins", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, {}));
    renderPage();

    expect(await screen.findByText("billing-web")).toBeInTheDocument();
    expect(screen.getByText("vs-billing-app")).toBeInTheDocument();
    expect(screen.getByTestId(`application-row-${MANUAL_APP.id}`)).toBeInTheDocument();
    expect(screen.getByTestId(`application-row-${DERIVED_APP.id}`)).toBeInTheDocument();
  });

  it("shows the empty state when no applications exist", async () => {
    vi.stubGlobal("fetch", fetchRouted(EMPTY_LIST, {}));
    renderPage();

    expect(await screen.findByTestId("applications-empty-state")).toBeInTheDocument();
  });

  it("shows an error alert when the applications API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    expect(await screen.findAllByRole("alert")).not.toHaveLength(0);
  });
});

// ── application_detail_shows_dependency_rows_with_source ────────────────────────

describe("application_detail_shows_dependency_rows_with_source", () => {
  it("expands an application to reveal its dependency rows with per-source badges", async () => {
    vi.stubGlobal(
      "fetch",
      fetchRouted(LIST, { [MANUAL_APP.id]: [MANUAL_DEP, F5_DEP] }),
    );
    renderPage();

    const row = await screen.findByTestId(`application-row-${MANUAL_APP.id}`);
    expect(row).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-expanded", "true");

    // Wait for the async dependency query to resolve into rows.
    expect(await screen.findByTestId(`dependency-source-${MANUAL_DEP.id}`)).toHaveTextContent(
      "manual",
    );
    const detail = screen.getByTestId(`application-detail-${MANUAL_APP.id}`);
    // Both dependency rows show their target and their source.
    expect(detail).toHaveTextContent("device");
    expect(detail).toHaveTextContent("ip_address");
    expect(detail).toHaveTextContent("manual");
    expect(detail).toHaveTextContent("f5");
    expect(screen.getByTestId(`dependency-source-${F5_DEP.id}`)).toHaveTextContent("f5");
  });

  it("expanding an application with no dependencies shows an honest empty detail", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, { [DERIVED_APP.id]: [] }));
    renderPage();

    const row = await screen.findByTestId(`application-row-${DERIVED_APP.id}`);
    fireEvent.click(row);
    // Wait for the empty dependency query to resolve into the honest empty state.
    expect(await screen.findByText(/no dependencies/i)).toBeInTheDocument();
  });
});

// ── derived_application_shows_origin_badge_and_no_delete_control ────────────────

describe("derived_application_shows_origin_badge_and_no_delete_control", () => {
  it("shows a 'derived' origin badge on the derived row and 'manual' on the manual row", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, {}));
    renderPage("engineer");

    await screen.findByText("vs-billing-app");
    expect(screen.getByTestId(`application-origin-${DERIVED_APP.id}`)).toHaveTextContent("derived");
    expect(screen.getByTestId(`application-origin-${MANUAL_APP.id}`)).toHaveTextContent("manual");
  });

  it("never offers a delete control for a derived application, even to an engineer", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, {}));
    renderPage("engineer");

    await screen.findByText("vs-billing-app");
    // Derivation owns the lifecycle of derived rows — the UI must not offer to
    // delete one (the backend refuses it with a 409 regardless).
    expect(screen.queryByTestId(`application-delete-${DERIVED_APP.id}`)).not.toBeInTheDocument();
  });
});
