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
          {/* Catch-all so clicking a nav link (e.g. "Devices") keeps Layout
              mounted, mirroring the real route table, instead of falling
              through to "no routes matched". */}
          <Route path="*" element={<div data-testid="outlet-page" />} />
        </Route>
        <Route path="/login" element={<div data-testid="login-page" />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Layout", () => {
  it("renders a navigation link for every page", () => {
    // Render at engineer so the engineer+ gated "Changes" link is visible
    // alongside the always-on links (Users remains admin-only and is excluded).
    renderLayout("engineer");
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

describe("Layout — per-route error boundary", () => {
  function Boom(): never {
    throw new Error("page exploded");
  }

  it("keeps the shell (sidebar nav) mounted when the routed page crashes", () => {
    useAuthStore.setState({
      status: "authed",
      accessToken: "tok",
      user: userWithRole("engineer"),
    });
    // Silence React's expected error logging for the intentional throw.
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      render(
        <MemoryRouter initialEntries={["/"]}>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<Boom />} />
            </Route>
          </Routes>
        </MemoryRouter>,
      );
    } finally {
      errorSpy.mockRestore();
    }
    // Fallback shown in the outlet area…
    expect(screen.getByTestId("error-boundary-fallback")).toBeInTheDocument();
    // …while the app shell survives: nav links stay clickable for recovery.
    for (const label of NAV_LABELS) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });
});

describe("Layout — responsive drawer sidebar", () => {
  function hamburger() {
    return screen.getByRole("button", { name: /open navigation|close navigation/i });
  }

  it("renders the hamburger toggle collapsed with aria-expanded=false and an aria-controls link to the sidebar", () => {
    renderLayout("engineer");
    const toggle = hamburger();
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    const controls = toggle.getAttribute("aria-controls");
    expect(controls).toBeTruthy();
    expect(document.getElementById(controls as string)).toBeInTheDocument();
  });

  it("opens the drawer (aria-expanded=true, backdrop present) when the hamburger is clicked", () => {
    renderLayout("engineer");
    fireEvent.click(hamburger());
    expect(hamburger()).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByTestId("drawer-backdrop")).toBeInTheDocument();
  });

  it("closes the drawer when the backdrop is clicked", () => {
    renderLayout("engineer");
    fireEvent.click(hamburger());
    fireEvent.click(screen.getByTestId("drawer-backdrop"));
    expect(hamburger()).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByTestId("drawer-backdrop")).not.toBeInTheDocument();
  });

  it("closes the drawer on Escape", () => {
    renderLayout("engineer");
    fireEvent.click(hamburger());
    expect(hamburger()).toHaveAttribute("aria-expanded", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(hamburger()).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByTestId("drawer-backdrop")).not.toBeInTheDocument();
  });

  it("closes the drawer on nav-link navigation", () => {
    renderLayout("engineer");
    fireEvent.click(hamburger());
    expect(hamburger()).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("link", { name: "Devices" }));
    expect(hamburger()).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByTestId("drawer-backdrop")).not.toBeInTheDocument();
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

  it("hides the Changes link for a sub-engineer (operator/viewer)", () => {
    renderLayout("operator");
    expect(screen.queryByRole("link", { name: "Changes" })).not.toBeInTheDocument();
  });

  it("shows the Changes link for an engineer", () => {
    renderLayout("engineer");
    expect(screen.getByRole("link", { name: "Changes" })).toBeInTheDocument();
  });

  it("logs out, marks the store anon, and redirects to /login", async () => {
    renderLayout("admin");
    fireEvent.click(screen.getByRole("button", { name: /log ?out/i }));
    await waitFor(() => expect(logoutMock).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(useAuthStore.getState().status).toBe("anon"));
    expect(await screen.findByTestId("login-page")).toBeInTheDocument();
  });
});
