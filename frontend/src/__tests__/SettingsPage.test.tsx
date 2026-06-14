/**
 * SettingsPage tests (Auth & Account UI, F4): appearance + LLM admin settings.
 *
 * Covers:
 *  - Theme selector: clicking light/dark/system updates the theme store
 *  - LLM section hidden for a non-admin (SettingsRoute test already covers
 *    the RoleRoute gate; here we test the section's own submit behavior)
 *  - LLM section: GET /auth/settings renders current profile; PATCH /auth/settings
 *    submitted on form save (admin only)
 *
 * ``../api/auth`` is mocked; no network is touched.
 * ``../stores/theme`` is imported directly to assert store updates.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
import { SettingsLlmSection, SettingsPage } from "../pages/SettingsPage";
import type { SystemSettings } from "../api/auth";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";
import { useThemeStore } from "../stores/theme";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/auth", () => ({
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
}));

import { getSettings, updateSettings } from "../api/auth";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ADMIN_USER: UserMe = {
  id: "aaaa-1111",
  username: "admin",
  email: "admin@example.com",
  display_name: "Admin User",
  role: "admin",
  is_active: true,
  must_change_password: false,
};

const VIEWER_USER: UserMe = {
  id: "bbbb-2222",
  username: "viewer",
  email: "viewer@example.com",
  display_name: null,
  role: "viewer",
  is_active: true,
  must_change_password: false,
};

const CURRENT_SETTINGS: SystemSettings = {
  llm_profile: "local",
  llm_role_reasoning: null,
  llm_role_fast: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

/** Render /settings with the nested /settings/llm route, mirroring App.tsx wiring. */
function renderSettings(path: string, user: UserMe) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user });
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/settings" element={<SettingsPage />}>
            <Route element={<RoleRoute minimum="admin" />}>
              <Route path="llm" element={<SettingsLlmSection />} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(() => {
  resetStore();
  vi.mocked(getSettings).mockReset();
  vi.mocked(updateSettings).mockReset();
});

afterEach(() => {
  resetStore();
  vi.restoreAllMocks();
});

// ── Theme selector ─────────────────────────────────────────────────────────────

describe("SettingsPage — theme selector", () => {
  it("renders theme options (light, dark, system)", () => {
    useAuthStore.setState({ status: "authed", accessToken: "tok", user: VIEWER_USER });
    const qc = makeQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/settings"]}>
          <Routes>
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByRole("button", { name: /light/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /dark/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /system/i })).toBeInTheDocument();
  });

  it("clicking 'light' sets the theme store to light", () => {
    useAuthStore.setState({ status: "authed", accessToken: "tok", user: VIEWER_USER });
    const qc = makeQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/settings"]}>
          <Routes>
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /light/i }));
    expect(useThemeStore.getState().theme).toBe("light");
  });

  it("clicking 'dark' sets the theme store to dark", () => {
    useAuthStore.setState({ status: "authed", accessToken: "tok", user: VIEWER_USER });
    const qc = makeQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/settings"]}>
          <Routes>
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /dark/i }));
    expect(useThemeStore.getState().theme).toBe("dark");
  });

  it("clicking 'system' sets the theme store to system", () => {
    useAuthStore.setState({ status: "authed", accessToken: "tok", user: VIEWER_USER });
    const qc = makeQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/settings"]}>
          <Routes>
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /system/i }));
    expect(useThemeStore.getState().theme).toBe("system");
  });
});

// ── LLM section — visibility gate ─────────────────────────────────────────────

describe("SettingsPage — LLM section visibility", () => {
  it("is hidden for a non-admin (viewer) at /settings/llm", () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    renderSettings("/settings/llm", VIEWER_USER);
    expect(screen.queryByTestId("settings-llm")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("is visible for an admin at /settings/llm", async () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    renderSettings("/settings/llm", ADMIN_USER);
    expect(await screen.findByTestId("settings-llm")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });
});

// ── LLM section — GET/PATCH ────────────────────────────────────────────────────

describe("SettingsPage — LLM section content (admin)", () => {
  it("renders the current llm_profile from GET /auth/settings", async () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    renderSettings("/settings/llm", ADMIN_USER);
    await screen.findByTestId("settings-llm");
    // The profile selector should show 'local'
    expect(screen.getByDisplayValue("local")).toBeInTheDocument();
  });

  it("submits PATCH /auth/settings with the selected profile on save", async () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    vi.mocked(updateSettings).mockResolvedValue({
      llm_profile: "anthropic",
      llm_role_reasoning: null,
      llm_role_fast: null,
    });

    renderSettings("/settings/llm", ADMIN_USER);
    await screen.findByTestId("settings-llm");

    // Change the profile select
    const select = screen.getByDisplayValue("local");
    fireEvent.change(select, { target: { value: "anthropic" } });

    fireEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(updateSettings).toHaveBeenCalledWith(
        expect.objectContaining({ llm_profile: "anthropic" }),
      );
    });
  });

  it("does not display or accept API keys", async () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    renderSettings("/settings/llm", ADMIN_USER);
    await screen.findByTestId("settings-llm");

    // No input with type=password and no label mentioning "key"
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    expect(passwordInputs.length).toBe(0);

    const allLabels = document.querySelectorAll("label");
    const keyLabel = Array.from(allLabels).find((l) =>
      /key/i.test(l.textContent ?? ""),
    );
    expect(keyLabel).toBeUndefined();
  });
});
