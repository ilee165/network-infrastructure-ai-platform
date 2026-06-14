/**
 * RoleRoute tests (Auth & Account UI, F2): minimum-role defense-in-depth gate.
 *
 * Rank order viewer < operator < engineer < admin. A user at or above the
 * minimum sees the nested <Outlet/>; below it they get a forbidden view.
 * The backend require_role remains the source of truth — this is UI hardening.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
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

function renderAdminGate(role: string) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user: userWithRole(role) });
  return render(
    <MemoryRouter initialEntries={["/users"]}>
      <Routes>
        <Route element={<RoleRoute minimum="admin" />}>
          <Route path="/users" element={<div data-testid="admin-only" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("RoleRoute — admin minimum", () => {
  it("renders the gated outlet for an admin", () => {
    renderAdminGate("admin");
    expect(screen.getByTestId("admin-only")).toBeInTheDocument();
  });

  it("blocks a viewer with a forbidden view", () => {
    renderAdminGate("viewer");
    expect(screen.queryByTestId("admin-only")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("blocks an engineer (one rank below admin)", () => {
    renderAdminGate("engineer");
    expect(screen.queryByTestId("admin-only")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("blocks an unknown role (ranks below everything)", () => {
    renderAdminGate("wizard");
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });
});
