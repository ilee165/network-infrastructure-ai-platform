/**
 * Settings route gate tests (Auth & Account UI, F2 review fix).
 *
 * Spec F2 item 3 requires "/users AND the LLM section of /settings under
 * RoleRoute(\"admin\")". The Appearance section of /settings is reachable by any
 * authenticated user; the LLM profile + role map section is admin-only and must
 * sit behind a nested RoleRoute("admin") — defense-in-depth over the backend
 * require_role, which remains the source of truth.
 *
 * These mount the same /settings route subtree the App wires up (SettingsPage as
 * the layout, the admin LLM section behind RoleRoute("admin")), mirroring the
 * isolated-subtree style of ProtectedRoute / RoleRoute tests.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
import { SettingsLlmSection } from "../pages/SettingsPage";
import { SettingsPage } from "../pages/SettingsPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

function userWithRole(role: string): UserMe {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    username: "u",
    email: null,
    display_name: null,
    role,
    is_active: true,
    must_change_password: false,
  };
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(resetStore);
afterEach(resetStore);

/** Mount the /settings subtree exactly as App wires it. */
function renderSettings(path: string, role: string) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user: userWithRole(role) });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/settings" element={<SettingsPage />}>
          <Route element={<RoleRoute minimum="admin" />}>
            <Route path="llm" element={<SettingsLlmSection />} />
          </Route>
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("/settings LLM section — admin gate", () => {
  it("renders the LLM section for an admin", () => {
    renderSettings("/settings/llm", "admin");
    expect(screen.getByTestId("settings-llm")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("blocks a viewer from the LLM section with a forbidden view", () => {
    renderSettings("/settings/llm", "viewer");
    expect(screen.queryByTestId("settings-llm")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("blocks an engineer (one rank below admin) from the LLM section", () => {
    renderSettings("/settings/llm", "engineer");
    expect(screen.queryByTestId("settings-llm")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("keeps the appearance settings reachable by a non-admin", () => {
    renderSettings("/settings", "viewer");
    expect(screen.getByTestId("settings-page")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });
});
