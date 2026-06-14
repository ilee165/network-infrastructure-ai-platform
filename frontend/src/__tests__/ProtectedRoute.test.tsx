/**
 * ProtectedRoute tests (Auth & Account UI, F2): the app-wide auth gate.
 *
 * Contract:
 *  - status "loading"  → render a loader (never the protected tree, never a redirect).
 *  - status "anon"     → redirect to /login, preserving the intended path.
 *  - status "authed" + user.must_change_password → force /change-password
 *    (unless already on /change-password).
 *  - otherwise          → render the nested <Outlet/>.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ProtectedRoute } from "../components/ProtectedRoute";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

const ADMIN: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "admin",
  is_active: true,
  must_change_password: false,
};

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(resetStore);
afterEach(resetStore);

/** Render the gate at *initial* with a protected child + sentinel public pages. */
function renderGate(initial: string) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/login" element={<div data-testid="login-page" />} />
        <Route path="/change-password" element={<div data-testid="change-password-page" />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<div data-testid="protected-home" />} />
          <Route path="/devices" element={<div data-testid="protected-devices" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute — loading", () => {
  it("renders a loader and neither the protected tree nor a redirect", () => {
    useAuthStore.setState({ status: "loading" });
    renderGate("/");
    expect(screen.getByTestId("auth-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-home")).not.toBeInTheDocument();
    expect(screen.queryByTestId("login-page")).not.toBeInTheDocument();
  });
});

describe("ProtectedRoute — anonymous", () => {
  it("redirects an unauthenticated user to /login", () => {
    useAuthStore.setState({ status: "anon" });
    renderGate("/devices");
    expect(screen.getByTestId("login-page")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-devices")).not.toBeInTheDocument();
  });
});

describe("ProtectedRoute — authed", () => {
  it("renders the protected outlet for an authenticated user", () => {
    useAuthStore.setState({ status: "authed", user: ADMIN, accessToken: "tok" });
    renderGate("/");
    expect(screen.getByTestId("protected-home")).toBeInTheDocument();
  });

  it("forces /change-password when must_change_password is set", () => {
    useAuthStore.setState({
      status: "authed",
      accessToken: "tok",
      user: { ...ADMIN, must_change_password: true },
    });
    renderGate("/devices");
    expect(screen.getByTestId("change-password-page")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-devices")).not.toBeInTheDocument();
  });
});
