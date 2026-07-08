/**
 * ApplicationsPage tests: the manual application-tagging surface (P4 W2-T3).
 *
 * Read surface (rider P2): the application list with per-origin badges and the
 * per-application dependency detail with per-source badges. Write flows + role
 * gating (rider P3) are added to this same file in P3. Mocked global fetch,
 * react-query provider, no backend required — the AdcPage test style.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

// ── Write-flow helpers (rider P3) ──────────────────────────────────────────────

interface RecordedCall {
  method: string;
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

/**
 * A fetch mock that records every request and answers reads with the fixtures
 * and writes with a synthetic success — so a test can both drive the UI and
 * assert the exact mutation the client issued.
 */
function fetchWriting(
  list: unknown,
  deps: Record<string, unknown[]>,
): { mock: ReturnType<typeof vi.fn>; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const mock = vi.fn((url: string, init?: RequestInit): Promise<Response> => {
    const method = (init?.method ?? "GET").toUpperCase();
    const path = String(url);
    calls.push({
      method,
      url: path,
      body: init?.body !== undefined && init?.body !== null ? JSON.parse(String(init.body)) : undefined,
      headers: (init?.headers as Record<string, string> | undefined) ?? {},
    });
    if (method === "DELETE") {
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (method === "POST" || method === "PATCH") {
      return Promise.resolve(
        new Response(JSON.stringify({ ...MANUAL_APP, ...MANUAL_DEP }), {
          status: method === "POST" ? 201 : 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
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
  return { mock, calls };
}

function writeCalls(calls: RecordedCall[]): RecordedCall[] {
  return calls.filter((c) => c.method !== "GET");
}

// ── engineer_can_create_edit_delete_manual_application ─────────────────────────

describe("engineer_can_create_edit_delete_manual_application", () => {
  it("creates a manual application via the create modal (POST /applications)", async () => {
    const { mock, calls } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId("application-create-button"));
    fireEvent.change(screen.getByTestId("application-form-name"), {
      target: { value: "new-app" },
    });
    fireEvent.click(screen.getByTestId("application-form-submit"));

    await waitFor(() => {
      const post = writeCalls(calls).find((c) => c.method === "POST");
      expect(post).toBeDefined();
      expect(post!.url).toContain("/api/v1/applications");
      expect(post!.body).toMatchObject({ name: "new-app" });
    });
  });

  it("edits a manual application via the edit modal (PATCH /applications/{id})", async () => {
    const { mock, calls } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-edit-${MANUAL_APP.id}`));
    fireEvent.change(screen.getByTestId("application-form-owner"), {
      target: { value: "new-owner" },
    });
    fireEvent.click(screen.getByTestId("application-form-submit"));

    await waitFor(() => {
      const patch = writeCalls(calls).find((c) => c.method === "PATCH");
      expect(patch).toBeDefined();
      expect(patch!.url).toContain(`/api/v1/applications/${MANUAL_APP.id}`);
      expect(patch!.body).toMatchObject({ owner: "new-owner" });
    });
  });

  it("deletes a manual application after confirmation (DELETE /applications/{id})", async () => {
    const { mock, calls } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-delete-${MANUAL_APP.id}`));
    fireEvent.click(await screen.findByTestId("confirm-action"));

    await waitFor(() => {
      const del = writeCalls(calls).find((c) => c.method === "DELETE");
      expect(del).toBeDefined();
      expect(del!.url).toContain(`/api/v1/applications/${MANUAL_APP.id}`);
    });
  });
});

// ── engineer_can_add_and_remove_manual_dependency_row ──────────────────────────

describe("engineer_can_add_and_remove_manual_dependency_row", () => {
  it("adds a manual dependency via the tag form (POST /{id}/dependencies)", async () => {
    const { mock, calls } = fetchWriting(LIST, { [MANUAL_APP.id]: [] });
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-row-${MANUAL_APP.id}`));
    fireEvent.click(await screen.findByTestId(`dependency-add-${MANUAL_APP.id}`));
    fireEvent.change(screen.getByTestId("dependency-form-ref"), {
      target: { value: "dddddddd-dddd-dddd-dddd-dddddddddddd" },
    });
    fireEvent.click(screen.getByTestId("dependency-form-submit"));

    await waitFor(() => {
      const post = writeCalls(calls).find((c) => c.method === "POST");
      expect(post).toBeDefined();
      expect(post!.url).toContain(`/api/v1/applications/${MANUAL_APP.id}/dependencies`);
      expect(post!.body).toMatchObject({
        target_kind: "device",
        target_ref: "dddddddd-dddd-dddd-dddd-dddddddddddd",
      });
    });
  });

  it("removes a manual dependency row but never a derivation-owned one", async () => {
    const { mock, calls } = fetchWriting(LIST, { [MANUAL_APP.id]: [MANUAL_DEP, F5_DEP] });
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-row-${MANUAL_APP.id}`));
    // The manual row has a remove control; the f5 (derivation-owned) row does not.
    const removeManual = await screen.findByTestId(`dependency-remove-${MANUAL_DEP.id}`);
    expect(screen.queryByTestId(`dependency-remove-${F5_DEP.id}`)).not.toBeInTheDocument();

    fireEvent.click(removeManual);
    fireEvent.click(await screen.findByTestId("confirm-action"));

    await waitFor(() => {
      const del = writeCalls(calls).find((c) => c.method === "DELETE");
      expect(del).toBeDefined();
      expect(del!.url).toContain(
        `/api/v1/applications/${MANUAL_APP.id}/dependencies/${MANUAL_DEP.id}`,
      );
    });
  });
});

// ── viewer_sees_read_only_tagging_surface_without_write_controls ───────────────

describe("viewer_sees_read_only_tagging_surface_without_write_controls", () => {
  it("shows no create/edit/delete controls to a viewer", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, {}));
    renderPage("viewer");

    await screen.findByText("billing-web");
    expect(screen.queryByTestId("application-create-button")).not.toBeInTheDocument();
    expect(screen.queryByTestId(`application-edit-${MANUAL_APP.id}`)).not.toBeInTheDocument();
    expect(screen.queryByTestId(`application-delete-${MANUAL_APP.id}`)).not.toBeInTheDocument();
  });

  it("shows no add/remove dependency controls to a viewer in the expanded detail", async () => {
    vi.stubGlobal("fetch", fetchRouted(LIST, { [MANUAL_APP.id]: [MANUAL_DEP] }));
    renderPage("viewer");

    fireEvent.click(await screen.findByTestId(`application-row-${MANUAL_APP.id}`));
    await screen.findByTestId(`dependency-source-${MANUAL_DEP.id}`);
    expect(screen.queryByTestId(`dependency-add-${MANUAL_APP.id}`)).not.toBeInTheDocument();
    expect(screen.queryByTestId(`dependency-remove-${MANUAL_DEP.id}`)).not.toBeInTheDocument();
  });
});

// ── application_edit_uses_optimistic_concurrency_if_match (N1) ──────────────────

const STALE_PROBLEM = {
  type: "urn:netops:error:stale-precondition",
  title: "Conflict",
  status: 409,
  detail: "application was modified by another writer since you last read it; reload and retry",
  instance: `/api/v1/applications/${MANUAL_APP.id}`,
};

const NAME_CONFLICT_PROBLEM = {
  type: "urn:netops:error:conflict",
  title: "Conflict",
  status: 409,
  detail: "an application named 'taken' already exists (names are case-insensitive)",
  instance: `/api/v1/applications/${MANUAL_APP.id}`,
};

/** Answer reads with the list and the edit PATCH with a fixed status/problem. */
function fetchEditReturns(list: unknown, status: number, problem?: unknown) {
  return vi.fn((_url: string, init?: RequestInit): Promise<Response> => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "PATCH") {
      return Promise.resolve(
        new Response(problem !== undefined ? JSON.stringify(problem) : null, {
          status,
          headers: { "Content-Type": "application/problem+json" },
        }),
      );
    }
    return Promise.resolve(
      new Response(JSON.stringify(list), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

/** Answer reads with the list and the delete DELETE with a fixed status/problem. */
function fetchDeleteReturns(list: unknown, status: number, problem?: unknown) {
  return vi.fn((_url: string, init?: RequestInit): Promise<Response> => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "DELETE") {
      return Promise.resolve(
        new Response(problem !== undefined ? JSON.stringify(problem) : null, {
          status,
          headers: { "Content-Type": "application/problem+json" },
        }),
      );
    }
    return Promise.resolve(
      new Response(JSON.stringify(list), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

async function openEditAndSubmit(): Promise<void> {
  fireEvent.click(await screen.findByTestId(`application-edit-${MANUAL_APP.id}`));
  fireEvent.change(screen.getByTestId("application-form-owner"), {
    target: { value: "new-owner" },
  });
  fireEvent.click(screen.getByTestId("application-form-submit"));
}

describe("application_edit_uses_optimistic_concurrency_if_match", () => {
  it("(a) sends the row's updated_at as the If-Match precondition on edit", async () => {
    const { mock, calls } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");
    await openEditAndSubmit();

    await waitFor(() => {
      const patch = writeCalls(calls).find((c) => c.method === "PATCH");
      expect(patch).toBeDefined();
      expect(patch!.headers["If-Match"]).toBe(`"${MANUAL_APP.updated_at}"`);
    });
  });

  it("(b) a stale-precondition 409 shows the reload message and does not close the modal", async () => {
    vi.stubGlobal("fetch", fetchEditReturns(LIST, 409, STALE_PROBLEM));
    renderPage("engineer");
    await openEditAndSubmit();

    expect(await screen.findByText(/changed by someone else/i)).toBeInTheDocument();
    expect(screen.getByTestId("application-reload-button")).toBeInTheDocument();
    // The modal stays open — the success path (toast + close) never ran.
    expect(screen.getByLabelText("Edit application")).toBeInTheDocument();
  });

  it("(c) a name-collision 409 shows the plain detail, not the reload UX", async () => {
    vi.stubGlobal("fetch", fetchEditReturns(LIST, 409, NAME_CONFLICT_PROBLEM));
    renderPage("engineer");
    await openEditAndSubmit();

    expect(await screen.findByText(/already exists/i)).toBeInTheDocument();
    expect(screen.queryByTestId("application-reload-button")).not.toBeInTheDocument();
    expect(screen.queryByText(/changed by someone else/i)).not.toBeInTheDocument();
  });

  it("(d) a successful edit closes the modal (invalidating the list as before)", async () => {
    const { mock } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");
    await openEditAndSubmit();

    await waitFor(() => {
      expect(screen.queryByLabelText("Edit application")).not.toBeInTheDocument();
    });
  });

  it("(e) sends the row's updated_at as the If-Match precondition on delete", async () => {
    const { mock, calls } = fetchWriting(LIST, {});
    vi.stubGlobal("fetch", mock);
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-delete-${MANUAL_APP.id}`));
    fireEvent.click(await screen.findByTestId("confirm-action"));

    await waitFor(() => {
      const del = writeCalls(calls).find((c) => c.method === "DELETE");
      expect(del).toBeDefined();
      expect(del!.headers["If-Match"]).toBe(`"${MANUAL_APP.updated_at}"`);
    });
  });

  it("(f) a stale-precondition 409 on delete shows the reload message and keeps the confirm dialog open", async () => {
    vi.stubGlobal("fetch", fetchDeleteReturns(LIST, 409, STALE_PROBLEM));
    renderPage("engineer");

    fireEvent.click(await screen.findByTestId(`application-delete-${MANUAL_APP.id}`));
    fireEvent.click(await screen.findByTestId("confirm-action"));

    expect(await screen.findByText(/changed by someone else/i)).toBeInTheDocument();
    expect(screen.getByTestId("confirm-action")).toBeInTheDocument();
  });
});
