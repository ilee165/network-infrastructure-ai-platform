/**
 * AuditPage tests: agent tool-audit view.
 *
 * The audit view surfaces the agent's tool actions for a session — the
 * `tool_call` reasoning steps recorded for the run (every AI tool invocation is
 * a traced, auditable action; brief §6 "audit everything"). Sourced from
 * `GET /api/v1/agents/{id}`; global `fetch` is mocked, no backend required.
 */

import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import type { StartSessionResponse } from "../api/agents";
import { AuditPage } from "../pages/AuditPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const SESSION_ID = "55555555-5555-5555-5555-555555555555";

const SESSION_WITH_TOOL_EVENTS: StartSessionResponse = {
  session: {
    id: SESSION_ID,
    user_id: "99999999-9999-9999-9999-999999999999",
    invoking_role: "engineer",
    intent: "Why is BGP peer 10.0.0.2 down on core-sw-01?",
    status: "succeeded",
    started_at: "2024-01-15T12:00:00Z",
    completed_at: "2024-01-15T12:00:05Z",
  },
  answer: "The interface is admin-down.",
  traces: [
    {
      trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      agent_name: "troubleshooting",
      started_at: "2024-01-15T12:00:00Z",
      completed_at: "2024-01-15T12:00:05Z",
      steps: [
        {
          kind: "plan",
          summary: "Plan the analysis.",
          detail: null,
          tool_name: null,
          evidence: [],
          occurred_at: "2024-01-15T12:00:01Z",
        },
        {
          kind: "tool_call",
          summary: "Inspect BGP peer state.",
          detail: "analyze_bgp(device=core-sw-01)",
          tool_name: "analyze_bgp",
          evidence: [
            { kind: "device", reference: "core-sw-01:bgp", description: "BGP summary" },
          ],
          occurred_at: "2024-01-15T12:00:02Z",
        },
        {
          kind: "tool_call",
          summary: "Check interface status.",
          detail: "list_interfaces(device=core-sw-01)",
          tool_name: "list_interfaces",
          evidence: [],
          occurred_at: "2024-01-15T12:00:03Z",
        },
      ],
    },
  ],
};

const SESSION_NO_TOOL_EVENTS: StartSessionResponse = {
  ...SESSION_WITH_TOOL_EVENTS,
  traces: [
    {
      ...SESSION_WITH_TOOL_EVENTS.traces[0]!,
      steps: [SESSION_WITH_TOOL_EVENTS.traces[0]!.steps[0]!],
    },
  ],
};

// ── Harness ───────────────────────────────────────────────────────────────────

function mockSessionFetch(response: StartSessionResponse) {
  return vi.fn(() =>
    Promise.resolve(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

function renderPage(): void {
renderWithQueryClient(
      <AuditPage />
    );
}

function loadSession(id = SESSION_ID): void {
  fireEvent.change(screen.getByLabelText(/session id/i), { target: { value: id } });
  fireEvent.click(screen.getByRole("button", { name: /load/i }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("AuditPage — agent tool-audit view", () => {
  it("labels itself as agent tool audit, not the platform audit_log browser", () => {
    renderPage();
    expect(
      screen.getByRole("heading", { name: /agent tool audit/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/not the platform-wide audit_log browser/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/every actor, action, and AI decision/i),
    ).not.toBeInTheDocument();
  });

  it("lists one audit row per agent tool_call step", async () => {
    vi.stubGlobal("fetch", mockSessionFetch(SESSION_WITH_TOOL_EVENTS));
    renderPage();
    loadSession();

    const rows = await screen.findAllByTestId("tool-audit-event");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("analyze_bgp");
    expect(rows[1]).toHaveTextContent("list_interfaces");
  });

  it("requests the canonical session path", async () => {
    const fetchMock = mockSessionFetch(SESSION_WITH_TOOL_EVENTS);
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    loadSession();

    await screen.findAllByTestId("tool-audit-event");
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/api/v1/agents/${SESSION_ID}`),
      expect.anything(),
    );
  });

  it("excludes non-tool steps (plan/observation/conclusion) from the audit view", async () => {
    vi.stubGlobal("fetch", mockSessionFetch(SESSION_NO_TOOL_EVENTS));
    renderPage();
    loadSession();

    expect(await screen.findByTestId("audit-empty-state")).toBeInTheDocument();
    expect(screen.queryAllByTestId("tool-audit-event")).toHaveLength(0);
  });

  it("shows an error alert when the session lookup fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              type: "urn:netops:error:not-found",
              title: "Not Found",
              status: 404,
              detail: "agent session does not exist",
            }),
            { status: 404, headers: { "Content-Type": "application/problem+json" } },
          ),
        ),
      ),
    );
    renderPage();
    loadSession("00000000-0000-0000-0000-000000000000");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Session load failed: Not Found: agent session does not exist",
    );
  });
});
