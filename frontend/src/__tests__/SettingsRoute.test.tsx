/**
 * Settings route gate tests.
 *
 * Appearance / agents / account: any authenticated user.
 * Credentials: RoleRoute("engineer").
 * LLM + access: RoleRoute("admin").
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RoleRoute } from "../components/RoleRoute";
import {
  SettingsAccessSection,
  SettingsAccountSection,
  SettingsAgentsSection,
  SettingsAppearanceSection,
  SettingsCredentialsSection,
  SettingsIntegrationsSection,
  SettingsLlmSection,
  SettingsPage,
  SettingsPlatformSection,
} from "../pages/SettingsPage";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

vi.mock("../api/auth", () => ({
  getSettings: vi.fn().mockResolvedValue({
    llm_profile: "local",
    llm_role_reasoning: null,
    llm_role_fast: null,
  }),
  updateSettings: vi.fn(),
  getLlmProfile: vi.fn().mockResolvedValue({ llm_profile: "local" }),
  getLlmReadiness: vi.fn().mockResolvedValue({
    active_profile: "local",
    local_model: "llama3.1:8b",
    profiles: [],
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
  getPlatformHealth: vi.fn().mockResolvedValue({
    status: "ok",
    dependencies: {
      postgres: { status: "ok", latency_ms: 1, error: null },
    },
  }),
  getPlatformConfig: vi.fn().mockResolvedValue({
    pcap_retention_days: 30,
    pcap_retention_hour: 3,
    pcap_retention_minute: 0,
    raw_artifact_retention_days: 90,
    raw_artifact_retention_hour: 4,
    raw_artifact_retention_minute: 0,
    audit_export_format: null,
    audit_export_configured: false,
  }),
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
  disableCredential: vi.fn(),
  getRotationStatus: vi.fn().mockResolvedValue({
    from_version: null,
    to_version: "test-v1",
    rows_pending: 0,
  }),
}));

vi.mock("../api/integrations", () => ({
  listIntegrations: vi.fn().mockResolvedValue({ vendors: [] }),
}));

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

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

/** Mount the /settings subtree exactly as App wires it. */
function renderSettings(path: string, role: string) {
  useAuthStore.setState({ status: "authed", accessToken: "tok", user: userWithRole(role) });
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
              <Route path="integrations" element={<SettingsIntegrationsSection />} />
              <Route path="platform" element={<SettingsPlatformSection />} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
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
    expect(screen.getByTestId("settings-appearance")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });
});

describe("/settings credentials — engineer gate", () => {
  it("renders credentials for an engineer", async () => {
    renderSettings("/settings/credentials", "engineer");
    expect(await screen.findByTestId("settings-credentials")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("blocks a viewer from credentials", () => {
    renderSettings("/settings/credentials", "viewer");
    expect(screen.queryByTestId("settings-credentials")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("allows admin (above engineer) on credentials", async () => {
    renderSettings("/settings/credentials", "admin");
    expect(await screen.findByTestId("settings-credentials")).toBeInTheDocument();
  });
});

describe("/settings integrations + platform — admin gate", () => {
  it("renders integrations for an admin", async () => {
    renderSettings("/settings/integrations", "admin");
    expect(await screen.findByTestId("settings-integrations")).toBeInTheDocument();
    expect(screen.queryByTestId("forbidden")).not.toBeInTheDocument();
  });

  it("blocks a viewer from integrations", () => {
    renderSettings("/settings/integrations", "viewer");
    expect(screen.queryByTestId("settings-integrations")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });

  it("renders platform for an admin", async () => {
    renderSettings("/settings/platform", "admin");
    expect(await screen.findByTestId("settings-platform")).toBeInTheDocument();
  });

  it("blocks an engineer from platform", () => {
    renderSettings("/settings/platform", "engineer");
    expect(screen.queryByTestId("settings-platform")).not.toBeInTheDocument();
    expect(screen.getByTestId("forbidden")).toBeInTheDocument();
  });
});
