/**
 * Unit tests for the applications tagging API client (P4 W2-T3, rider P1).
 *
 * Mirrors the topology/devices test style: global fetch is stubbed with
 * ``vi.stubGlobal``; the RFC 7807 error path exercises ``ApiError``; no
 * backend, Postgres, or Neo4j required.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type {
  ApplicationDependencyRead,
  ApplicationListResponse,
  ApplicationRead,
} from "../api/applications";
import {
  createApplication,
  createApplicationDependency,
  deleteApplication,
  deleteApplicationDependency,
  getApplication,
  listApplicationDependencies,
  listApplications,
  updateApplication,
} from "../api/applications";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const APP_ID = "11111111-1111-1111-1111-111111111111";
const DEP_ID = "22222222-2222-2222-2222-222222222222";
const TARGET_ID = "33333333-3333-3333-3333-333333333333";

const MANUAL_APP: ApplicationRead = {
  id: APP_ID,
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
  ...MANUAL_APP,
  id: "55555555-5555-5555-5555-555555555555",
  name: "vip-derived-app",
  origin: "derived",
  origin_ref: "f5:aaa:/Common/vs_billing",
  created_by: null,
};

const LIST_RESPONSE: ApplicationListResponse = {
  items: [MANUAL_APP, DERIVED_APP],
  total: 2,
  limit: 50,
  offset: 0,
};

const DEP_ROW: ApplicationDependencyRead = {
  id: DEP_ID,
  application_id: APP_ID,
  target_kind: "device",
  target_ref: TARGET_ID,
  source: "manual",
  provenance: [{ kind: "user", ref: "44444444-4444-4444-4444-444444444444" }],
  derived_at: "2026-07-01T10:00:00Z",
  created_by: "44444444-4444-4444-4444-444444444444",
  created_at: "2026-07-01T10:00:00Z",
};

const PROBLEM_409 = {
  type: "urn:netops:error:conflict",
  title: "Conflict",
  status: 409,
  detail: "an application named 'billing-web' already exists (names are case-insensitive)",
  instance: "/api/v1/applications",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function okFetch(body: unknown, status = 200) {
  return vi.fn((): Promise<Response> =>
    Promise.resolve(
      new Response(status === 204 ? null : JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

function errorFetch(problem: unknown, status: number) {
  return vi.fn((): Promise<Response> =>
    Promise.resolve(
      new Response(JSON.stringify(problem), {
        status,
        headers: { "Content-Type": "application/problem+json" },
      }),
    ),
  );
}

function calledUrl(mock: ReturnType<typeof okFetch>): string {
  return String((mock.mock.calls[0] as unknown as [string])[0]);
}

function calledInit(mock: ReturnType<typeof okFetch>): RequestInit {
  return (mock.mock.calls[0] as unknown as [string, RequestInit])[1];
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── applications_client_calls_list_get_and_dependency_endpoints ────────────────

describe("applications_client_calls_list_get_and_dependency_endpoints", () => {
  it("listApplications hits /api/v1/applications and returns the paginated body", async () => {
    const mock = okFetch(LIST_RESPONSE);
    vi.stubGlobal("fetch", mock);
    const result = await listApplications();
    expect(result).toEqual(LIST_RESPONSE);
    expect(calledUrl(mock)).toContain("/api/v1/applications");
  });

  it("listApplications serializes origin, q, limit, and offset filters", async () => {
    const mock = okFetch(LIST_RESPONSE);
    vi.stubGlobal("fetch", mock);
    await listApplications({ origin: "derived", q: "bill", limit: 10, offset: 20 });
    const url = calledUrl(mock);
    expect(url).toContain("origin=derived");
    expect(url).toContain("q=bill");
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=20");
  });

  it("getApplication hits /api/v1/applications/{id}", async () => {
    const mock = okFetch(MANUAL_APP);
    vi.stubGlobal("fetch", mock);
    const result = await getApplication(APP_ID);
    expect(result).toEqual(MANUAL_APP);
    expect(calledUrl(mock)).toContain(`/api/v1/applications/${APP_ID}`);
  });

  it("listApplicationDependencies hits /{id}/dependencies and returns the rows", async () => {
    const mock = okFetch([DEP_ROW]);
    vi.stubGlobal("fetch", mock);
    const result = await listApplicationDependencies(APP_ID);
    expect(result).toEqual([DEP_ROW]);
    expect(calledUrl(mock)).toContain(`/api/v1/applications/${APP_ID}/dependencies`);
  });

  it("deleteApplication issues DELETE and resolves for a 204", async () => {
    const mock = okFetch(undefined, 204);
    vi.stubGlobal("fetch", mock);
    await expect(deleteApplication(APP_ID)).resolves.toBeUndefined();
    expect(calledInit(mock).method).toBe("DELETE");
    expect(calledUrl(mock)).toContain(`/api/v1/applications/${APP_ID}`);
  });

  it("deleteApplicationDependency issues DELETE against the nested row path", async () => {
    const mock = okFetch(undefined, 204);
    vi.stubGlobal("fetch", mock);
    await deleteApplicationDependency(APP_ID, DEP_ID);
    expect(calledInit(mock).method).toBe("DELETE");
    expect(calledUrl(mock)).toContain(`/api/v1/applications/${APP_ID}/dependencies/${DEP_ID}`);
  });
});

// ── applications_client_create_sends_manual_origin_payload ─────────────────────

describe("applications_client_create_sends_manual_origin_payload", () => {
  it("createApplication POSTs name/description/owner/fqdns with no caller-set origin", async () => {
    const mock = okFetch(MANUAL_APP, 201);
    vi.stubGlobal("fetch", mock);
    await createApplication({
      name: "billing-web",
      description: "customer billing frontend",
      owner: "payments-team",
      fqdns: ["billing.example.com"],
    });
    const init = calledInit(mock);
    expect(init.method).toBe("POST");
    const sent = JSON.parse(String(init.body));
    expect(sent).toEqual({
      name: "billing-web",
      description: "customer billing frontend",
      owner: "payments-team",
      fqdns: ["billing.example.com"],
    });
    // origin is server-assigned (manual): the client must never send it.
    expect(sent).not.toHaveProperty("origin");
    expect(sent).not.toHaveProperty("origin_ref");
  });

  it("createApplicationDependency POSTs only target_kind and target_ref (source server-assigned)", async () => {
    const mock = okFetch(DEP_ROW, 201);
    vi.stubGlobal("fetch", mock);
    await createApplicationDependency(APP_ID, { target_kind: "device", target_ref: TARGET_ID });
    const init = calledInit(mock);
    expect(init.method).toBe("POST");
    const sent = JSON.parse(String(init.body));
    expect(sent).toEqual({ target_kind: "device", target_ref: TARGET_ID });
    expect(sent).not.toHaveProperty("source");
    expect(calledUrl(mock)).toContain(`/api/v1/applications/${APP_ID}/dependencies`);
  });

  it("updateApplication PATCHes only the supplied fields", async () => {
    const mock = okFetch(MANUAL_APP);
    vi.stubGlobal("fetch", mock);
    await updateApplication(APP_ID, { owner: "new-team" });
    const init = calledInit(mock);
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toEqual({ owner: "new-team" });
  });
});

// ── applications_client_surfaces_api_error_detail ──────────────────────────────

describe("applications_client_surfaces_api_error_detail", () => {
  it("createApplication rejects with ApiError carrying the problem detail on 409", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_409, 409));
    await expect(createApplication({ name: "billing-web", fqdns: [] })).rejects.toBeInstanceOf(
      ApiError,
    );
  });

  it("ApiError.status and problem.detail are preserved for the caller", async () => {
    vi.stubGlobal("fetch", errorFetch(PROBLEM_409, 409));
    try {
      await createApplication({ name: "billing-web", fqdns: [] });
      throw new Error("expected ApiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(409);
      expect((err as ApiError).problem.detail).toContain("already exists");
    }
  });
});
