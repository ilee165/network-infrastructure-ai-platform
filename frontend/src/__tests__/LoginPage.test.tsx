/**
 * LoginPage tests (Auth & Account UI, F3): public credential entry.
 *
 * Contract:
 *  - success → call ``login()`` then ``getMe()``, populate the auth store
 *    (status "authed" + user), and navigate to the intended path (redirect
 *    ``location.state.from``) or "/".
 *  - failure → render the backend ``ApiError`` detail (generic invalid creds);
 *    the store stays anon and the user is NOT navigated away.
 *  - the submit button is disabled while the request is in flight, and shows
 *    the shared Spinner (audit UI_UX #4).
 *  - an already-authed visitor is redirected away from /login.
 *  - both inputs are real label-associated FormFields (audit UI_UX #5 — this
 *    page previously had zero aria attributes).
 *
 * ``../api/auth`` is mocked so no network is touched; ``getMe`` resolves the
 * user the store should cache. Navigation is asserted with a location probe.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { LoginPage } from "../pages/LoginPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

vi.mock("../api/auth", async () => (await import("../test/test-utils")).mockAuthApi(() => ({
  login: vi.fn(),
  getMe: vi.fn(),
}))());

import { getMe, login } from "../api/auth";

const USER: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "engineer",
  is_active: true,
  must_change_password: false,
};

function badCredentials(): ApiError {
  return new ApiError({
    type: "urn:netops:error:unauthorized",
    title: "Unauthorized",
    status: 401,
    detail: "Invalid username or password",
  });
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "anon" });
}

beforeEach(() => {
  resetStore();
  vi.mocked(login).mockReset();
  vi.mocked(getMe).mockReset();
});
afterEach(() => {
  resetStore();
  vi.restoreAllMocks();
});

/** Probe that records the current path so navigation can be asserted. */
function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname}</div>;
}

/**
 * Render LoginPage at /login. ``from`` seeds a protected origin into the
 * router's location state, mimicking ProtectedRoute's redirect.
 */
function renderLogin(from?: string) {
  const initial = from
    ? [{ pathname: "/login", state: { from: { pathname: from } } }]
    : ["/login"];
  return render(
    <MemoryRouter initialEntries={initial}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div data-testid="home" />} />
        <Route path="/devices" element={<div data-testid="devices" />} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );
}

describe("LoginPage — successful sign-in", () => {
  it("populates the store and navigates to / when there is no intended path", async () => {
    vi.mocked(login).mockResolvedValue({ access_token: "tok-123", token_type: "bearer" });
    vi.mocked(getMe).mockResolvedValue(USER);

    renderLogin();
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "s3cret-pass" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent("/");
    });
    expect(login).toHaveBeenCalledWith("alice", "s3cret-pass");
    const state = useAuthStore.getState();
    expect(state.status).toBe("authed");
    expect(state.accessToken).toBe("tok-123");
    expect(state.user).toEqual(USER);
  });

  it("navigates to the intended path preserved in location state", async () => {
    vi.mocked(login).mockResolvedValue({ access_token: "tok-123", token_type: "bearer" });
    vi.mocked(getMe).mockResolvedValue(USER);

    renderLogin("/devices");
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "s3cret-pass" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent("/devices");
    });
  });
});

describe("LoginPage — failed sign-in", () => {
  it("renders the backend error detail and leaves the store anonymous", async () => {
    vi.mocked(login).mockRejectedValue(badCredentials());

    renderLogin();
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "wrong-pass" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(getMe).not.toHaveBeenCalled();
    expect(useAuthStore.getState().status).toBe("anon");
    expect(screen.getByTestId("location")).toHaveTextContent("/login");
  });
});

describe("LoginPage — pending state", () => {
  it("disables the submit button and shows a spinner while the request is in flight", async () => {
    let resolveLogin!: (value: { access_token: string; token_type: string }) => void;
    vi.mocked(login).mockReturnValue(
      new Promise((resolve) => {
        resolveLogin = resolve;
      }),
    );
    vi.mocked(getMe).mockResolvedValue(USER);

    renderLogin();
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "s3cret-pass" } });
    const submit = screen.getByRole("button", { name: /sign in/i });
    fireEvent.click(submit);

    await waitFor(() => expect(submit).toBeDisabled());
    expect(within(submit).getByRole("status")).toBeInTheDocument();

    resolveLogin({ access_token: "tok", token_type: "bearer" });
    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent("/");
    });
  });
});

describe("LoginPage — accessible form labels", () => {
  it("associates the username and password inputs with real <label> elements", () => {
    renderLogin();
    const username = screen.getByLabelText(/username/i);
    const password = screen.getByLabelText(/password/i);
    expect(username).toHaveAttribute("id");
    expect(password).toHaveAttribute("id");
    expect(username.tagName).toBe("INPUT");
    expect(password.tagName).toBe("INPUT");
  });
});

describe("LoginPage — already authenticated", () => {
  it("redirects an authed visitor away from /login", async () => {
    useAuthStore.setState({ status: "authed", accessToken: "tok", user: USER });
    renderLogin();
    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent("/");
    });
    expect(login).not.toHaveBeenCalled();
  });
});
