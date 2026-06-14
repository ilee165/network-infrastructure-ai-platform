/**
 * ChangePasswordPage tests (Auth & Account UI, F3): change-own-password flow.
 *
 * Serves BOTH the voluntary change and the forced first-login gate target.
 *
 * Contract:
 *  - success → call ``changePassword(current, new)``, refetch ``getMe()`` so the
 *    cached user's ``must_change_password`` flips false, then navigate to "/".
 *  - client-side validation → new password < 8 chars, or confirm != new, is
 *    rejected BEFORE any API call and surfaces a message.
 *  - backend errors (e.g. wrong current password) render via the ``ApiError``
 *    detail and the user is NOT navigated away.
 *
 * ``../api/auth`` is mocked; navigation is asserted with a location probe.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { ChangePasswordPage } from "../pages/ChangePasswordPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

vi.mock("../api/auth", () => ({
  changePassword: vi.fn(),
  getMe: vi.fn(),
}));

import { changePassword, getMe } from "../api/auth";

const FLAGGED_USER: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "engineer",
  is_active: true,
  must_change_password: true,
};

function wrongCurrentPassword(): ApiError {
  return new ApiError({
    type: "urn:netops:error:bad-request",
    title: "Bad Request",
    status: 400,
    detail: "Current password is incorrect",
  });
}

function resetStore(): void {
  useAuthStore.setState({
    accessToken: "tok",
    user: FLAGGED_USER,
    status: "authed",
  });
}

beforeEach(() => {
  resetStore();
  vi.mocked(changePassword).mockReset();
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

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/change-password"]}>
      <Routes>
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="/" element={<div data-testid="home" />} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );
}

describe("ChangePasswordPage — successful change", () => {
  it("calls changePassword, refetches /me, clears the forced flag, and navigates to /", async () => {
    vi.mocked(changePassword).mockResolvedValue({ changed: true });
    vi.mocked(getMe).mockResolvedValue({ ...FLAGGED_USER, must_change_password: false });

    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), {
      target: { value: "old-pass-1" },
    });
    fireEvent.change(screen.getByLabelText(/^new password/i), {
      target: { value: "new-pass-12" },
    });
    fireEvent.change(screen.getByLabelText(/confirm/i), { target: { value: "new-pass-12" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent("/");
    });
    expect(changePassword).toHaveBeenCalledWith("old-pass-1", "new-pass-12");
    expect(getMe).toHaveBeenCalled();
    expect(useAuthStore.getState().user?.must_change_password).toBe(false);
  });
});

describe("ChangePasswordPage — client-side validation", () => {
  it("rejects a new password shorter than 8 characters without calling the API", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), {
      target: { value: "old-pass-1" },
    });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "short" } });
    fireEvent.change(screen.getByLabelText(/confirm/i), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/at least 8/i);
    expect(changePassword).not.toHaveBeenCalled();
    expect(screen.getByTestId("location")).toHaveTextContent("/change-password");
  });

  it("rejects a confirmation that does not match the new password", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), {
      target: { value: "old-pass-1" },
    });
    fireEvent.change(screen.getByLabelText(/^new password/i), {
      target: { value: "new-pass-12" },
    });
    fireEvent.change(screen.getByLabelText(/confirm/i), { target: { value: "different-12" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/match/i);
    expect(changePassword).not.toHaveBeenCalled();
  });
});

describe("ChangePasswordPage — backend error", () => {
  it("renders the backend error detail and does not navigate away", async () => {
    vi.mocked(changePassword).mockRejectedValue(wrongCurrentPassword());

    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), {
      target: { value: "wrong-current" },
    });
    fireEvent.change(screen.getByLabelText(/^new password/i), {
      target: { value: "new-pass-12" },
    });
    fireEvent.change(screen.getByLabelText(/confirm/i), { target: { value: "new-pass-12" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Current password is incorrect");
    expect(getMe).not.toHaveBeenCalled();
    expect(screen.getByTestId("location")).toHaveTextContent("/change-password");
  });
});
