/**
 * Layout shell tests: every page in the route table is reachable from the
 * sidebar, the routed page renders through the outlet, the header badges
 * are present, and the user menu (Auth & Account UI, F2) shows the current
 * user + role, a working logout, and an admin-only Users link.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Layout } from "../components/Layout";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

const { logoutMock } = vi.hoisted(() => ({ logoutMock: vi.fn() }));
vi.mock("../api/auth", () => ({ logout: logoutMock }));

/** Must stay in sync with NAV_ITEMS in components/Layout.tsx and App.tsx. */
const NAV_LABELS = ["Dashboard", "Devices", "Topology", "Chat", "Changes", "Audit"] as const;

function userWithRole(role: string, display_name: string | null = null): UserMe {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    username: "alice",
    email: null,
    display_name,
    role,
    is_active: true,
    must_change_password: false,
  };
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(() => {
  resetStore();
  logoutMock.mockReset();
  logoutMock.mockResolvedValue({ revoked: true });
});
afterEach(resetStore);

function renderLayout(role = "viewer", display_name: string | null = null) {
  useAuthStore.setState({
    status: "authed",
    accessToken: "tok",
    user: userWithRole(role, display_name),
  });
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div data-testid="outlet-page" />} />
        </Route>
        <Route path="/login" element={<div data-testid="login-page" />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Layout", () => {
  it("renders a navigation link for every page", () => {
    renderLayout();
    for (const label of NAV_LABELS) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("renders the routed page through the outlet", () => {
    renderLayout();
    expect(screen.getByTestId("outlet-page")).toBeInTheDocument();
  });

  it("shows environment and LLM-profile badges in the header", () => {
    renderLayout();
    expect(screen.getByTestId("env-badge")).toBeInTheDocument();
    expect(screen.getByTestId("llm-profile-badge")).toHaveTextContent("llm: local");
  });

  it("includes Profile and Settings nav links", () => {
    renderLayout();
    expect(screen.getByRole("link", { name: "Profile" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();
  });
});

describe("Layout — user menu", () => {
  it("shows the display name (falling back to username) and the role", () => {
    renderLayout("engineer", "Alice Smith");
    const menu = screen.getByTestId("user-menu");
    expect(menu).toHaveTextContent("Alice Smith");
    expect(menu).toHaveTextContent("engineer");
  });

  it("falls back to the username when display_name is null", () => {
    renderLayout("viewer", null);
    expect(screen.getByTestId("user-menu")).toHaveTextContent("alice");
  });

  it("hides the Users link for a non-admin", () => {
    renderLayout("engineer");
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });

  it("shows the Users link for an admin", () => {
    renderLayout("admin");
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
  });

  it("logs out, marks the store anon, and redirects to /login", async () => {
    renderLayout("admin");
    fireEvent.click(screen.getByRole("button", { name: /log ?out/i }));
    await waitFor(() => expect(logoutMock).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(useAuthStore.getState().status).toBe("anon"));
    expect(await screen.findByTestId("login-page")).toBeInTheDocument();
  });
});
