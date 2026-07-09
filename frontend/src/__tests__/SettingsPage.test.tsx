/**
 * SettingsPage tests: hub shell, appearance, agents help, LLM admin settings.
 *
 * ``../api/auth`` is mocked; no network is touched.
 * ``../stores/theme`` is imported directly to assert store updates.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
import {
  SettingsAccessSection,
  SettingsAccountSection,
  SettingsAgentsSection,
  SettingsAppearanceSection,
  SettingsCredentialsSection,
  SettingsLlmSection,
  SettingsPage,
} from "../pages/SettingsPage";
import type { SystemSettings } from "../api/auth";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";
import { useThemeStore } from "../stores/theme";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/auth", () => ({
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
  getLlmProfile: vi.fn().mockResolvedValue({ llm_profile: "local" }),
}));

vi.mock("../api/credentials", () => ({
  listCredentials: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
    limit: 100,
    offset: 0,
  }),
  createCredential: vi.fn(),
  rotateCredential: vi.fn(),
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

const ENGINEER_USER: UserMe = {
  id: "cccc-3333",
  username: "engineer",
  email: null,
  display_name: null,
  role: "engineer",
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

/** Render the settings hub as App.tsx wires it. */
function renderSettings(path: string, user: UserMe) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user });
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/settings" element={<SettingsPage />}>
            <Route index element={<SettingsAppearanceSection />} />
            <Route path="agents" element={<SettingsAgentsSection />} />
            <Route path="account" element={<SettingsAccountSection />} />
            <Route element={<RoleRoute minimum="engineer" />}>
              <Route path="credentials" element={<SettingsCredentialsSection />} />
            </Route>
            <Route element={<RoleRoute minimum="admin" />}>
              <Route path="llm" element={<SettingsLlmSection />} />
              <Route path="access" element={<SettingsAccessSection />} />
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
    renderSettings("/settings", VIEWER_USER);
    expect(screen.getByRole("button", { name: /light/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /dark/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /system/i })).toBeInTheDocument();
  });

  it("clicking 'light' sets the theme store to light", () => {
    renderSettings("/settings", VIEWER_USER);
    fireEvent.click(screen.getByRole("button", { name: /light/i }));
    expect(useThemeStore.getState().theme).toBe("light");
  });

  it("clicking 'dark' sets the theme store to dark", () => {
    renderSettings("/settings", VIEWER_USER);
    fireEvent.click(screen.getByRole("button", { name: /dark/i }));
    expect(useThemeStore.getState().theme).toBe("dark");
  });

  it("clicking 'system' sets the theme store to system", () => {
    renderSettings("/settings", VIEWER_USER);
    fireEvent.click(screen.getByRole("button", { name: /system/i }));
    expect(useThemeStore.getState().theme).toBe("system");
  });
});

// ── Hub navigation ────────────────────────────────────────────────────────────

describe("SettingsPage — section nav", () => {
  it("shows Appearance and Agents for any user", () => {
    renderSettings("/settings", VIEWER_USER);
    expect(screen.getByTestId("settings-section-nav")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /appearance/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /agents & chat/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /ai \/ llm/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /credentials/i })).not.toBeInTheDocument();
  });

  it("shows Credentials for engineer+", () => {
    renderSettings("/settings", ENGINEER_USER);
    expect(screen.getByRole("link", { name: /credentials/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /ai \/ llm/i })).not.toBeInTheDocument();
  });

  it("shows AI / LLM and Users & access for admin", () => {
    renderSettings("/settings", ADMIN_USER);
    expect(screen.getByRole("link", { name: /ai \/ llm/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /users & access/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /credentials/i })).toBeInTheDocument();
  });

  it("renders agents setup content", () => {
    renderSettings("/settings/agents", VIEWER_USER);
    expect(screen.getByTestId("settings-agents")).toBeInTheDocument();
    expect(screen.getByText(/Prerequisites checklist/i)).toBeInTheDocument();
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
    expect(await screen.findByDisplayValue("local")).toBeInTheDocument();
  });

  it("shows egress warning when an external profile is selected", async () => {
    vi.mocked(getSettings).mockResolvedValue({
      llm_profile: "anthropic",
      llm_role_reasoning: null,
      llm_role_fast: null,
    });
    renderSettings("/settings/llm", ADMIN_USER);
    await screen.findByTestId("settings-llm");
    expect(await screen.findByTestId("llm-egress-warning")).toBeInTheDocument();
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

    const select = await screen.findByDisplayValue("local");
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

    // LLM form must not ask for provider API keys (credential vault uses password
    // inputs on a different route).
    const allLabels = document.querySelectorAll("label");
    const keyLabel = Array.from(allLabels).find((l) =>
      /api\s*key|provider\s*key/i.test(l.textContent ?? ""),
    );
    expect(keyLabel).toBeUndefined();
  });
});
