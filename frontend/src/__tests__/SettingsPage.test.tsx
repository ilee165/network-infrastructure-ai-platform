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
  getLlmReadiness: vi.fn().mockResolvedValue({
    active_profile: "local",
    local_model: "llama3.1:8b",
    profiles: [
      {
        profile: "local",
        configured: true,
        status: "ready",
        model: "llama3.1:8b",
        egress: false,
        models: [],
        detail: null,
        latency_ms: null,
      },
      {
        profile: "anthropic",
        configured: false,
        status: "not_configured",
        model: "claude-sonnet-4-5",
        egress: true,
        models: [],
        detail: "credentials not set in server environment",
        latency_ms: null,
      },
      {
        profile: "openai",
        configured: false,
        status: "not_configured",
        model: "gpt-4o",
        egress: true,
        models: [],
        detail: null,
        latency_ms: null,
      },
      {
        profile: "azure",
        configured: false,
        status: "not_configured",
        model: "gpt-4o",
        egress: true,
        models: [],
        detail: null,
        latency_ms: null,
      },
    ],
  }),
  testLlmConnection: vi.fn(),
  getOidcStatus: vi.fn().mockResolvedValue({
    enabled: false,
    issuer_configured: false,
    client_id_configured: false,
    client_ref_configured: false,
    redirect_uri: "https://localhost/api/v1/auth/oidc/callback",
    break_glass_local_admin_only: false,
    allow_admin_via_oidc: false,
  }),
}));

vi.mock("../api/credentials", () => ({
  listCredentials: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
    limit: 50,
    offset: 0,
  }),
  createCredential: vi.fn(),
  rotateCredential: vi.fn(),
  getRotationStatus: vi.fn().mockResolvedValue({
    from_version: null,
    to_version: "test-v1",
    rows_pending: 0,
  }),
}));

import { getOidcStatus, getSettings, testLlmConnection, updateSettings } from "../api/auth";
import {
  createCredential,
  getRotationStatus,
  listCredentials,
  rotateCredential,
} from "../api/credentials";

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
  vi.mocked(listCredentials).mockReset();
  vi.mocked(createCredential).mockReset();
  vi.mocked(rotateCredential).mockReset();
  vi.mocked(listCredentials).mockResolvedValue({
    items: [],
    total: 0,
    limit: 50,
    offset: 0,
  });
});

afterEach(() => {
  resetStore();
  vi.clearAllMocks();
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
    const llm = await screen.findByTestId("settings-llm");

    // Scope to the LLM section only — credential vault password fields live on
    // /settings/credentials and must not false-positive this ADR-0009 guard.
    const passwordInputs = llm.querySelectorAll('input[type="password"]');
    expect(passwordInputs.length).toBe(0);

    const secretLabel = Array.from(llm.querySelectorAll("label")).find((l) =>
      /api\s*key|provider\s*key|client\s*secret|access\s*token|secret\s*key|bearer/i.test(
        l.textContent ?? "",
      ),
    );
    expect(secretLabel).toBeUndefined();
  });

  it("shows provider readiness and runs a connection test", async () => {
    vi.mocked(getSettings).mockResolvedValue(CURRENT_SETTINGS);
    vi.mocked(testLlmConnection).mockResolvedValue({
      profile: "local",
      configured: true,
      status: "ready",
      model: "llama3.1:8b",
      egress: false,
      models: ["llama3.1:8b"],
      detail: null,
      latency_ms: 12.5,
    });
    renderSettings("/settings/llm", ADMIN_USER);
    expect(await screen.findByTestId("llm-readiness-panel")).toBeInTheDocument();
    expect(await screen.findByTestId("llm-readiness-list")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("llm-test-local"));
    await waitFor(() => {
      expect(testLlmConnection).toHaveBeenCalledWith("local");
    });
    expect(await screen.findByTestId("llm-probe-result")).toHaveTextContent(/ready/i);
    expect(screen.getByTestId("llm-probe-result")).toHaveTextContent("llama3.1:8b");
  });
});

// ── Credentials vault (engineer+) ─────────────────────────────────────────────

const SAMPLE_CREDENTIAL = {
  id: "cred-1111-2222-3333-444444444444",
  name: "prod-ssh",
  kind: "ssh" as const,
  username: "netops",
  params: null,
  scope_site: null,
  scope_role: null,
  scope_device_group: null,
  kek_version: "v1",
  created_at: "2026-07-01T00:00:00Z",
  updated_at: "2026-07-01T00:00:00Z",
};

describe("SettingsPage — credentials vault (engineer)", () => {
  it("lists credentials with the first page offset", async () => {
    vi.mocked(listCredentials).mockResolvedValue({
      items: [SAMPLE_CREDENTIAL],
      total: 1,
      limit: 50,
      offset: 0,
    });
    renderSettings("/settings/credentials", ENGINEER_USER);
    expect(await screen.findByText("prod-ssh")).toBeInTheDocument();
    await waitFor(() => {
      expect(listCredentials).toHaveBeenCalledWith({ limit: 50, offset: 0 });
    });
  });

  it("requires name and secret on create", async () => {
    renderSettings("/settings/credentials", ENGINEER_USER);
    await screen.findByTestId("credential-create-form");
    fireEvent.click(screen.getByRole("button", { name: /create credential/i }));
    expect(await screen.findByText(/name and secret are required/i)).toBeInTheDocument();
    expect(createCredential).not.toHaveBeenCalled();
  });

  it("creates a credential and clears the form", async () => {
    vi.mocked(createCredential).mockResolvedValue(SAMPLE_CREDENTIAL);
    renderSettings("/settings/credentials", ENGINEER_USER);
    await screen.findByTestId("credential-create-form");

    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "prod-ssh" } });
    fireEvent.change(screen.getByLabelText(/^secret/i), { target: { value: "s3cret" } });
    fireEvent.click(screen.getByRole("button", { name: /create credential/i }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "prod-ssh",
          kind: "ssh",
          secret: "s3cret",
        }),
      );
    });
    expect(
      await screen.findByText(/credential “prod-ssh” created/i),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^name/i)).toHaveValue("");
    expect(screen.getByLabelText(/^secret/i)).toHaveValue("");
  });

  it("requires a new secret on rotate", async () => {
    vi.mocked(listCredentials).mockResolvedValue({
      items: [SAMPLE_CREDENTIAL],
      total: 1,
      limit: 50,
      offset: 0,
    });
    renderSettings("/settings/credentials", ENGINEER_USER);
    expect(await screen.findByText("prod-ssh")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^rotate$/i }));
    await screen.findByTestId("credential-rotate-form");
    fireEvent.click(screen.getByRole("button", { name: /confirm rotate/i }));
    expect(await screen.findByText(/new secret is required/i)).toBeInTheDocument();
    expect(rotateCredential).not.toHaveBeenCalled();
  });

  it("rotates a credential secret", async () => {
    vi.mocked(listCredentials).mockResolvedValue({
      items: [SAMPLE_CREDENTIAL],
      total: 1,
      limit: 50,
      offset: 0,
    });
    vi.mocked(rotateCredential).mockResolvedValue({
      ...SAMPLE_CREDENTIAL,
      updated_at: "2026-07-09T00:00:00Z",
    });
    renderSettings("/settings/credentials", ENGINEER_USER);
    expect(await screen.findByText("prod-ssh")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^rotate$/i }));
    await screen.findByTestId("credential-rotate-form");
    fireEvent.change(screen.getByLabelText(/new secret/i), {
      target: { value: "new-s3cret" },
    });
    fireEvent.click(screen.getByRole("button", { name: /confirm rotate/i }));

    await waitFor(() => {
      expect(rotateCredential).toHaveBeenCalledWith(SAMPLE_CREDENTIAL.id, {
        secret: "new-s3cret",
      });
    });
    expect(await screen.findByText(/rotated “prod-ssh”/i)).toBeInTheDocument();
  });

  it("shows KEK rotation status (fully wrapped when nothing pending)", async () => {
    vi.mocked(getRotationStatus).mockResolvedValue({
      from_version: null,
      to_version: "test-v1",
      rows_pending: 0,
    });
    renderSettings("/settings/credentials", ENGINEER_USER);
    expect(await screen.findByTestId("credentials-kek-rotation")).toBeInTheDocument();
    expect(await screen.findByTestId("kek-rows-pending-pill")).toHaveTextContent(
      /fully wrapped/i,
    );
    expect(screen.getByText("test-v1")).toBeInTheDocument();
    expect(getRotationStatus).toHaveBeenCalled();
  });

  it("warns when KEK rewrap rows are pending", async () => {
    vi.mocked(getRotationStatus).mockResolvedValue({
      from_version: "netops-kek:v1",
      to_version: "netops-kek:v2",
      rows_pending: 3,
    });
    renderSettings("/settings/credentials", ENGINEER_USER);
    expect(await screen.findByTestId("kek-rows-pending-pill")).toHaveTextContent(
      /3 pending/i,
    );
    expect(screen.getByText("netops-kek:v1")).toBeInTheDocument();
  });
});

// ── Access / OIDC status (admin) ──────────────────────────────────────────────

describe("SettingsPage — access OIDC status (admin)", () => {
  it("shows SSO disabled pill when OIDC is off", async () => {
    vi.mocked(getOidcStatus).mockResolvedValue({
      enabled: false,
      issuer_configured: false,
      client_id_configured: false,
      client_ref_configured: false,
      redirect_uri: "https://localhost/api/v1/auth/oidc/callback",
      break_glass_local_admin_only: false,
      allow_admin_via_oidc: false,
    });
    renderSettings("/settings/access", ADMIN_USER);
    expect(await screen.findByTestId("settings-oidc-status")).toBeInTheDocument();
    expect(await screen.findByTestId("oidc-enabled-pill")).toHaveTextContent(
      /sso disabled/i,
    );
    expect(screen.queryByTestId("oidc-break-glass-pill")).not.toBeInTheDocument();
  });

  it("shows SSO enabled and break-glass when OIDC is on", async () => {
    vi.mocked(getOidcStatus).mockResolvedValue({
      enabled: true,
      issuer_configured: true,
      client_id_configured: true,
      client_ref_configured: true,
      redirect_uri: "https://app.example/api/v1/auth/oidc/callback",
      break_glass_local_admin_only: true,
      allow_admin_via_oidc: false,
    });
    renderSettings("/settings/access", ADMIN_USER);
    expect(await screen.findByTestId("oidc-enabled-pill")).toHaveTextContent(
      /sso enabled/i,
    );
    expect(await screen.findByTestId("oidc-break-glass-pill")).toHaveTextContent(
      /break-glass admin only/i,
    );
    expect(screen.getByText(/admin via sso capped/i)).toBeInTheDocument();
    // Never render vault ref strings or secret field labels in this panel.
    expect(screen.queryByText(/vault\//i)).not.toBeInTheDocument();
  });
});
