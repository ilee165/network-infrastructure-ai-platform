/**
 * ProfilePage tests (Auth & Account UI, F4): self-service profile view.
 *
 * Covers:
 *  - profile info display (username, email, display_name, role)
 *  - profile edit: PATCH /me submitted on form submit
 *  - sessions list: renders session rows; current session marked; revoke calls API
 *  - revoke-all calls POST /auth/sessions/revoke-all
 *  - no own-audit section (no filterable actor audit endpoint on this backend)
 *
 * ``../api/auth`` is mocked; no network is touched.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { ProfilePage } from "../pages/ProfilePage";
import type { SessionInfo } from "../api/auth";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/auth", () => ({
  getMe: vi.fn(),
  updateMe: vi.fn(),
  changePassword: vi.fn(),
  listSessions: vi.fn(),
  revokeSession: vi.fn(),
  revokeAllSessions: vi.fn(),
}));

import { changePassword, getMe, updateMe, listSessions, revokeSession, revokeAllSessions } from "../api/auth";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const BASE_USER: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice Smith",
  role: "engineer",
  is_active: true,
  must_change_password: false,
};

const SESSION_CURRENT: SessionInfo = {
  sid: "aaaa-1111",
  created_at: "2026-06-01T10:00:00Z",
  last_used_at: "2026-06-14T02:00:00Z",
  user_agent: "Mozilla/5.0",
  ip: "192.168.1.10",
  revoked_at: null,
  is_current: true,
};

const SESSION_OTHER: SessionInfo = {
  sid: "bbbb-2222",
  created_at: "2026-06-10T08:00:00Z",
  last_used_at: "2026-06-13T20:00:00Z",
  user_agent: "curl/7.68",
  ip: "10.0.0.5",
  revoked_at: null,
  is_current: false,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: "tok", user: BASE_USER, status: "authed" });
}

function renderPage() {
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ProfilePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  resetStore();
  vi.mocked(getMe).mockReset();
  vi.mocked(updateMe).mockReset();
  vi.mocked(changePassword).mockReset();
  vi.mocked(listSessions).mockReset();
  vi.mocked(revokeSession).mockReset();
  vi.mocked(revokeAllSessions).mockReset();

  // Default: sessions returns two rows
  vi.mocked(listSessions).mockResolvedValue([SESSION_CURRENT, SESSION_OTHER]);
});

afterEach(() => {
  resetStore();
  vi.restoreAllMocks();
});

// ── Profile display ────────────────────────────────────────────────────────────

describe("ProfilePage — profile display", () => {
  it("shows the current user's username, email, display name, and role", async () => {
    renderPage();
    // Username appears in both the badge and the dl row; use findAllByText
    const aliceEls = await screen.findAllByText("alice");
    expect(aliceEls.length).toBeGreaterThanOrEqual(1);
    // Email and display_name are pre-populated into controlled inputs
    expect(screen.getByDisplayValue("alice@example.com")).toBeInTheDocument();
    expect(screen.getByDisplayValue("Alice Smith")).toBeInTheDocument();
    // Role is shown in the read-only dl
    expect(screen.getByText("engineer")).toBeInTheDocument();
  });
});

// ── Profile edit ───────────────────────────────────────────────────────────────

describe("ProfilePage — profile edit", () => {
  it("submits PATCH /me with the new email and display_name and updates the store", async () => {
    const updated: UserMe = {
      ...BASE_USER,
      email: "alice.new@example.com",
      display_name: "Alice Updated",
    };
    vi.mocked(updateMe).mockResolvedValue(updated);

    renderPage();

    // Wait for the form to appear
    const emailInput = await screen.findByLabelText(/email/i);
    const nameInput = screen.getByLabelText(/display name/i);

    fireEvent.change(emailInput, { target: { value: "alice.new@example.com" } });
    fireEvent.change(nameInput, { target: { value: "Alice Updated" } });
    fireEvent.click(screen.getByRole("button", { name: /save profile/i }));

    await waitFor(() => {
      expect(updateMe).toHaveBeenCalledWith({
        email: "alice.new@example.com",
        display_name: "Alice Updated",
      });
    });
    // Auth store user is updated
    expect(useAuthStore.getState().user?.email).toBe("alice.new@example.com");
    expect(useAuthStore.getState().user?.display_name).toBe("Alice Updated");
  });

  it("shows a backend error when PATCH /me fails", async () => {
    vi.mocked(updateMe).mockRejectedValue(
      new ApiError({
        type: "urn:netops:error:conflict",
        title: "Conflict",
        status: 409,
        detail: "That email is already in use",
      }),
    );

    renderPage();
    const emailInput = await screen.findByLabelText(/email/i);
    fireEvent.change(emailInput, { target: { value: "taken@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: /save profile/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("That email is already in use");
  });
});

// ── Sessions list ─────────────────────────────────────────────────────────────

describe("ProfilePage — sessions list", () => {
  it("renders a row for each session returned by GET /sessions", async () => {
    renderPage();
    // Current session row
    expect(await screen.findByText(/192\.168\.1\.10/)).toBeInTheDocument();
    // Other session row
    expect(screen.getByText(/10\.0\.0\.5/)).toBeInTheDocument();
  });

  it("marks the current session distinctly", async () => {
    renderPage();
    expect(await screen.findByTestId("session-current")).toBeInTheDocument();
  });

  it("calls DELETE /auth/sessions/{sid} when revoke is clicked for a non-current session", async () => {
    vi.mocked(revokeSession).mockResolvedValue({ revoked: true });
    vi.mocked(listSessions).mockResolvedValue([SESSION_OTHER]);

    renderPage();
    // Use exact match to avoid matching "Revoke all"
    const revokeBtn = await screen.findByRole("button", { name: /^revoke$/i });
    fireEvent.click(revokeBtn);

    await waitFor(() => {
      expect(revokeSession).toHaveBeenCalledWith("bbbb-2222");
    });
  });

  it("calls POST /auth/sessions/revoke-all when revoke-all is clicked", async () => {
    vi.mocked(revokeAllSessions).mockResolvedValue({ revoked: 2 });

    renderPage();
    await screen.findByText(/192\.168\.1\.10/);
    const revokeAllBtn = screen.getByRole("button", { name: /revoke all/i });
    fireEvent.click(revokeAllBtn);

    await waitFor(() => {
      expect(revokeAllSessions).toHaveBeenCalled();
    });
  });
});

// ── Change-password section ───────────────────────────────────────────────────

describe("ProfilePage — ChangePasswordSection", () => {
  it("calls changePassword with current/next and then refreshes the store via getMe on success", async () => {
    vi.mocked(changePassword).mockResolvedValue({ changed: true });
    const updatedUser: UserMe = { ...BASE_USER, must_change_password: false };
    vi.mocked(getMe).mockResolvedValue(updatedUser);

    renderPage();

    const currentInput = await screen.findByLabelText(/current password/i);
    const newInput = screen.getByLabelText(/^new password$/i);
    const confirmInput = screen.getByLabelText(/confirm new password/i);

    fireEvent.change(currentInput, { target: { value: "oldpass1" } });
    fireEvent.change(newInput, { target: { value: "newpass123" } });
    fireEvent.change(confirmInput, { target: { value: "newpass123" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    await waitFor(() => {
      expect(changePassword).toHaveBeenCalledWith("oldpass1", "newpass123");
    });
    await waitFor(() => {
      expect(getMe).toHaveBeenCalled();
    });
    expect(useAuthStore.getState().user).toEqual(updatedUser);
  });

  it("shows a validation error and does not call changePassword when new password is too short", async () => {
    renderPage();

    const currentInput = await screen.findByLabelText(/current password/i);
    const newInput = screen.getByLabelText(/^new password$/i);
    const confirmInput = screen.getByLabelText(/confirm new password/i);

    fireEvent.change(currentInput, { target: { value: "oldpass1" } });
    fireEvent.change(newInput, { target: { value: "short" } });
    fireEvent.change(confirmInput, { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/at least 8 characters/i);
    expect(changePassword).not.toHaveBeenCalled();
  });

  it("shows a validation error and does not call changePassword when new and confirm do not match", async () => {
    renderPage();

    const currentInput = await screen.findByLabelText(/current password/i);
    const newInput = screen.getByLabelText(/^new password$/i);
    const confirmInput = screen.getByLabelText(/confirm new password/i);

    fireEvent.change(currentInput, { target: { value: "oldpass1" } });
    fireEvent.change(newInput, { target: { value: "newpass123" } });
    fireEvent.change(confirmInput, { target: { value: "differentpass" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/do not match/i);
    expect(changePassword).not.toHaveBeenCalled();
  });
});

// ── Current session revoke guard ──────────────────────────────────────────────

describe("ProfilePage — current session revoke guard", () => {
  it("does not render a Revoke button for the current session row", async () => {
    vi.mocked(listSessions).mockResolvedValue([SESSION_CURRENT]);

    renderPage();

    // Wait for the session row to appear
    expect(await screen.findByTestId("session-current")).toBeInTheDocument();

    // No revoke button should be present for the current session
    expect(screen.queryByRole("button", { name: /^revoke$/i })).not.toBeInTheDocument();

    // The "Current session" label should appear in its place
    expect(screen.getByText(/current session/i)).toBeInTheDocument();
  });

  it("renders a Revoke button for a non-current non-revoked session", async () => {
    vi.mocked(listSessions).mockResolvedValue([SESSION_OTHER]);

    renderPage();

    expect(await screen.findByRole("button", { name: /^revoke$/i })).toBeInTheDocument();
  });
});

// ── No own-audit section ──────────────────────────────────────────────────────

describe("ProfilePage — own-audit section omitted", () => {
  it("does not render an audit/recent-activity section (no filterable actor endpoint)", async () => {
    renderPage();
    // Wait for page to settle using a more specific query
    await screen.findAllByText("alice");
    expect(screen.queryByTestId("profile-audit")).not.toBeInTheDocument();
  });
});
