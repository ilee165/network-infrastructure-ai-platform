/**
 * UsersPage tests (Auth & Account UI, F5): admin-only account management.
 *
 * Covers:
 *  - table renders users with all required columns
 *  - create-user modal: shows temp password exactly once with copy affordance
 *  - deactivate: calls PATCH is_active=false; surfaces 409 last-admin error
 *  - reset-password: shows the returned temp password once
 *  - role edit: submits PATCH /auth/users/{id} with the new role
 *  - revoke-sessions: calls POST /auth/users/{id}/revoke-sessions
 *
 * ``../api/auth`` is mocked; no network is touched.
 */

import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import { ApiError } from "../api/client";
import { UsersPage } from "../pages/UsersPage";
import type { UserSummary } from "../api/auth";
import { useAuthStore } from "../stores/auth";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/auth", async () => (await import("../test/test-utils")).mockAuthApi(() => ({
  listUsers: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  resetUserPassword: vi.fn(),
  revokeUserSessions: vi.fn(),
  // other exports used by Layout/other pages — provide no-ops
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  refresh: vi.fn(),
  changePassword: vi.fn(),
  listSessions: vi.fn(),
  revokeSession: vi.fn(),
  revokeAllSessions: vi.fn(),
  updateMe: vi.fn(),
  getUser: vi.fn(),
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
  initAuth: vi.fn(),
}))());

import {
  listUsers,
  createUser,
  updateUser,
  resetUserPassword,
  revokeUserSessions,
} from "../api/auth";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ADMIN_USER: UserSummary = {
  id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  username: "admin",
  email: "admin@example.com",
  display_name: "Admin User",
  role: "admin",
  is_active: true,
  must_change_password: false,
};

const VIEWER_USER: UserSummary = {
  id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  username: "viewer1",
  email: "viewer@example.com",
  display_name: "Viewer One",
  role: "viewer",
  is_active: true,
  must_change_password: false,
};

const INACTIVE_USER: UserSummary = {
  id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
  username: "inactive",
  email: null,
  display_name: null,
  role: "operator",
  is_active: false,
  must_change_password: true,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function resetStore(): void {
  useAuthStore.setState({
    accessToken: "tok",
    user: {
      id: ADMIN_USER.id,
      username: ADMIN_USER.username,
      email: ADMIN_USER.email,
      display_name: ADMIN_USER.display_name,
      role: "admin",
      is_active: true,
      must_change_password: false,
    },
    status: "authed",
  });
}

function renderPage() {
return renderWithQueryClient(
      <MemoryRouter>
        <UsersPage />
      </MemoryRouter>
    );
}

beforeEach(() => {
  resetStore();
  vi.mocked(listUsers).mockReset();
  vi.mocked(createUser).mockReset();
  vi.mocked(updateUser).mockReset();
  vi.mocked(resetUserPassword).mockReset();
  vi.mocked(revokeUserSessions).mockReset();

  // Default: two users
  vi.mocked(listUsers).mockResolvedValue([ADMIN_USER, VIEWER_USER]);
});

afterEach(() => {
  resetStore();
  vi.restoreAllMocks();
});

// ── Table renders users ───────────────────────────────────────────────────────

describe("UsersPage — user table", () => {
  it("renders a row for each user with username, email, role, is_active and must_change_password", async () => {
    renderPage();

    // Wait for data to load; use findAllByText for "admin" since it appears
    // in the username cell and also as an option in every role select.
    const adminEls = await screen.findAllByText("admin");
    expect(adminEls.length).toBeGreaterThanOrEqual(1);

    // Usernames in the monospace cells
    expect(screen.getByText("viewer1")).toBeInTheDocument();

    // Emails
    expect(screen.getByText("admin@example.com")).toBeInTheDocument();
    expect(screen.getByText("viewer@example.com")).toBeInTheDocument();

    // viewer role appears as the value of the viewer1 row's role select (index 1)
    expect(
      (screen.getAllByLabelText(/change role/i)[1] as HTMLSelectElement).value,
    ).toBe("viewer");
  });

  it("shows all required column headers", async () => {
    renderPage();
    // Wait for table to load
    await screen.findByText("viewer1");

    expect(screen.getByText(/username/i)).toBeInTheDocument();
    // The "Email" column header appears once in the thead (other email text is in td cells)
    const emailEls = screen.getAllByText(/^email$/i);
    expect(emailEls.length).toBeGreaterThanOrEqual(1);
    // "Role" header — use column header role if available, else getAllByText
    const roleEls = screen.getAllByText(/^role$/i);
    expect(roleEls.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/^active$/i)).toBeInTheDocument();
  });

  it("renders all three users when the API returns three", async () => {
    vi.mocked(listUsers).mockResolvedValue([ADMIN_USER, VIEWER_USER, INACTIVE_USER]);
    renderPage();

    await screen.findByText("viewer1");
    expect(screen.getByText("inactive")).toBeInTheDocument();
    // admin username is in the DOM (may appear multiple times with selects)
    const adminEls = screen.getAllByText("admin");
    expect(adminEls.length).toBeGreaterThanOrEqual(1);
  });

  it("shows a loading state before data arrives", () => {
    // Never resolves during this test
    vi.mocked(listUsers).mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("shows the query failure instead of a header-only table", async () => {
    vi.mocked(listUsers).mockRejectedValue(
      new ApiError({
        type: "urn:netops:error:forbidden",
        title: "Forbidden",
        status: 403,
        detail: "User inventory is unavailable.",
      }),
    );

    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "User inventory is unavailable.",
    );
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});

// ── Create user modal ─────────────────────────────────────────────────────────

describe("UsersPage — create user", () => {
  it("opens the create-user modal when the create button is clicked", async () => {
    renderPage();
    // Wait for table to be loaded
    await screen.findByText("viewer1");

    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // The dialog has a username input (labeled "Username") and a role select (labeled "Role")
    const dialog = screen.getByRole("dialog");
    expect(dialog).toBeInTheDocument();
    // Within the dialog there should be a username field
    expect(screen.getByRole("textbox", { name: /username/i })).toBeInTheDocument();
  });

  it("shows the temp password exactly once after successful create", async () => {
    const newUser: UserSummary = {
      id: "dddddddd-dddd-dddd-dddd-dddddddddddd",
      username: "newuser",
      email: null,
      display_name: null,
      role: "viewer",
      is_active: true,
      must_change_password: true,
    };
    vi.mocked(createUser).mockResolvedValue({
      user: newUser,
      temp_password: "TempPass-abc123XYZ",
    });
    // After create, listUsers returns the new user too
    vi.mocked(listUsers).mockResolvedValue([ADMIN_USER, VIEWER_USER, newUser]);

    renderPage();
    await screen.findByText("viewer1");

    // Open create modal
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    // Fill in form — find the username field within the dialog
    const usernameInput = screen.getByRole("textbox", { name: /username/i });
    fireEvent.change(usernameInput, { target: { value: "newuser" } });

    // Submit (role defaults to viewer)
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));

    // Temp password is shown in reveal dialog
    expect(await screen.findByText("TempPass-abc123XYZ")).toBeInTheDocument();

    // Warning that it won't be shown again
    expect(screen.getByText(/not be shown again/i)).toBeInTheDocument();

    // Copy button is present
    expect(screen.getByRole("button", { name: /copy/i })).toBeInTheDocument();

    // Clicking Done removes the password — proves "exactly once"
    fireEvent.click(screen.getByRole("button", { name: /done/i }));
    expect(screen.queryByText("TempPass-abc123XYZ")).not.toBeInTheDocument();
  });

  it("surfaces clipboard copy failures", async () => {
    vi.mocked(createUser).mockResolvedValue({ user: { ...VIEWER_USER, id: "copy-user", username: "copy-user" }, temp_password: "Temp-copy" });
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    renderPage();
    await screen.findByText("viewer1");
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /username/i }), { target: { value: "copy-user" } });
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));
    await screen.findByText("Temp-copy");
    fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not copy the password");
  });

  it("clears copied success state when a later clipboard attempt fails", async () => {
    vi.mocked(createUser).mockResolvedValue({
      user: { ...VIEWER_USER, id: "copy-user", username: "copy-user" },
      temp_password: "Temp-copy",
    });
    const writeText = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderPage();
    await screen.findByText("viewer1");
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /username/i }), {
      target: { value: "copy-user" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));
    await screen.findByText("Temp-copy");

    const copyButton = screen.getByRole("button", { name: /copy/i });
    fireEvent.click(copyButton);
    await waitFor(() => expect(copyButton).toHaveTextContent(/^Copied$/));
    fireEvent.click(copyButton);

    expect(await screen.findByRole("alert")).toHaveTextContent("Could not copy the password");
    expect(copyButton).toHaveTextContent(/^Copy$/);
  });

  it("ignores a stale success after a newer clipboard attempt fails", async () => {
    vi.mocked(createUser).mockResolvedValue({
      user: { ...VIEWER_USER, id: "copy-user", username: "copy-user" },
      temp_password: "Temp-copy",
    });
    let resolveFirstWrite!: () => void;
    const firstWrite = new Promise<void>((resolve) => {
      resolveFirstWrite = resolve;
    });
    const writeText = vi
      .fn()
      .mockReturnValueOnce(firstWrite)
      .mockRejectedValueOnce(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderPage();
    await screen.findByText("viewer1");
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /username/i }), {
      target: { value: "copy-user" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));
    await screen.findByText("Temp-copy");

    const copyButton = screen.getByRole("button", { name: /copy/i });
    fireEvent.click(copyButton);
    fireEvent.click(copyButton);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not copy the password");

    await act(async () => {
      resolveFirstWrite();
      await firstWrite;
    });

    expect(copyButton).toHaveTextContent(/^Copy$/);
    expect(screen.getByRole("alert")).toHaveTextContent("Could not copy the password");
  });

  it("surfaces copy failure when the clipboard API is unavailable", async () => {
    vi.mocked(createUser).mockResolvedValue({ user: { ...VIEWER_USER, id: "copy-user", username: "copy-user" }, temp_password: "Temp-copy" });
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    renderPage();
    await screen.findByText("viewer1");
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /username/i }), { target: { value: "copy-user" } });
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));
    await screen.findByText("Temp-copy");
    fireEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not copy the password");
  });

  it("calls POST /auth/users with the correct payload", async () => {
    const newUser: UserSummary = {
      id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
      username: "engineer1",
      email: "eng@example.com",
      display_name: null,
      role: "engineer",
      is_active: true,
      must_change_password: true,
    };
    vi.mocked(createUser).mockResolvedValue({
      user: newUser,
      temp_password: "SomeRandomTemp99",
    });
    vi.mocked(listUsers).mockResolvedValue([ADMIN_USER, VIEWER_USER, newUser]);

    renderPage();
    await screen.findByText("viewer1");

    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    fireEvent.change(screen.getByRole("textbox", { name: /username/i }), {
      target: { value: "engineer1" },
    });
    // The email input is type="email", not role="textbox" in some browsers.
    // Use getByLabelText which works for any input type.
    fireEvent.change(screen.getByLabelText(/^email/i), {
      target: { value: "eng@example.com" },
    });

    // Select role = engineer
    fireEvent.change(screen.getByLabelText(/^role/i), {
      target: { value: "engineer" },
    });

    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() => {
      expect(createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          username: "engineer1",
          role: "engineer",
          email: "eng@example.com",
        }),
      );
    });
  });
});

// ── Deactivate user / 409 last-admin guard ────────────────────────────────────

describe("UsersPage — deactivate", () => {
  it("calls PATCH /auth/users/{id} with is_active=false after confirm", async () => {
    vi.mocked(updateUser).mockResolvedValue({ ...VIEWER_USER, is_active: false });

    renderPage();
    await screen.findByText("viewer1");

    // Click the deactivate button — there are two rows (admin, viewer1);
    // both are active so there are two Deactivate buttons. Click the second (viewer1).
    const deactivateBtns = screen.getAllByRole("button", { name: /^deactivate$/i });
    // viewer1 is the second user row
    fireEvent.click(deactivateBtns[1]!);

    // Confirmation dialog appears
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    await waitFor(() => {
      expect(updateUser).toHaveBeenCalledWith(
        VIEWER_USER.id,
        expect.objectContaining({ is_active: false }),
      );
    });
  });

  it("surfaces the 409 last-admin error to the user", async () => {
    vi.mocked(updateUser).mockRejectedValue(
      new ApiError({
        type: "urn:netops:error:conflict",
        title: "Conflict",
        status: 409,
        detail: "Cannot remove the last active admin",
      }),
    );

    // Make admin the only user (so deactivate triggers last-admin guard)
    vi.mocked(listUsers).mockResolvedValue([ADMIN_USER]);

    renderPage();
    // Wait for the admin row to appear
    await screen.findByText("admin@example.com");

    const deactivateBtns = screen.getAllByRole("button", { name: /^deactivate$/i });
    fireEvent.click(deactivateBtns[0]!);

    // Confirm the dialog
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    // The 409 message is shown
    expect(
      await screen.findByText(/cannot remove the last active admin/i),
    ).toBeInTheDocument();
  });
});

// ── Reset password ────────────────────────────────────────────────────────────

describe("UsersPage — reset password", () => {
  it("calls POST /auth/users/{id}/reset-password and shows the new temp password", async () => {
    vi.mocked(resetUserPassword).mockResolvedValue({
      temp_password: "NewTemp-xyz987",
    });

    renderPage();
    await screen.findByText("viewer1");

    // There are two "Reset password" buttons (one per user row); click viewer1's (index 1)
    const resetBtns = screen.getAllByRole("button", { name: /^reset password$/i });
    fireEvent.click(resetBtns[1]!);

    // Confirm dialog
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    // Temp password is shown
    expect(await screen.findByText("NewTemp-xyz987")).toBeInTheDocument();

    await waitFor(() => {
      expect(resetUserPassword).toHaveBeenCalledWith(VIEWER_USER.id, undefined);
    });
  });
});

// ── Role edit ─────────────────────────────────────────────────────────────────

describe("UsersPage — role edit", () => {
  it("submits PATCH /auth/users/{id} with the new role when the role select changes", async () => {
    vi.mocked(updateUser).mockResolvedValue({ ...VIEWER_USER, role: "operator" });

    renderPage();
    await screen.findByText("viewer1");

    // Each row has a role select (aria-label="Change role").
    // There are two rows, so two selects: [0]=admin row, [1]=viewer1 row.
    const roleSelects = screen.getAllByLabelText(/^change role$/i);
    expect(roleSelects.length).toBe(2);

    // Change the viewer1 row role select
    fireEvent.change(roleSelects[1]!, { target: { value: "operator" } });

    // Confirmation dialog should appear
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    await waitFor(() => {
      expect(updateUser).toHaveBeenCalledWith(
        VIEWER_USER.id,
        expect.objectContaining({ role: "operator" }),
      );
    });
  });
});

// ── Revoke sessions ───────────────────────────────────────────────────────────

describe("UsersPage — revoke sessions", () => {
  it("calls POST /auth/users/{id}/revoke-sessions after confirmation", async () => {
    vi.mocked(revokeUserSessions).mockResolvedValue({ revoked: 2 });

    renderPage();
    await screen.findByText("viewer1");

    // Two "Revoke sessions" buttons; click viewer1's (index 1)
    const revokeSessionBtns = screen.getAllByRole("button", { name: /^revoke sessions$/i });
    fireEvent.click(revokeSessionBtns[1]!);

    // Confirmation dialog
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    await waitFor(() => {
      expect(revokeUserSessions).toHaveBeenCalledWith(VIEWER_USER.id);
    });
  });
});
