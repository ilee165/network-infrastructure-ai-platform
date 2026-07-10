/**
 * Settings hub: appearance, account links, agents onboarding, credentials
 * vault (engineer+), LLM profile (admin), users/access, integrations matrix,
 * and platform health/retention (admin).
 *
 * Nested routes (App.tsx):
 *  - index              Appearance
 *  - /agents            Agents & Chat setup
 *  - /account           My account deep-links
 *  - /credentials       Device credential vault (RoleRoute engineer+)
 *  - /llm               LLM profile + role map (RoleRoute admin)
 *  - /access            Users & access help (RoleRoute admin)
 *  - /integrations      Vendor plugin matrix (RoleRoute admin)
 *  - /platform          Health + retention effective config (RoleRoute admin)
 *
 * Provider API keys are NEVER shown, entered, or stored here (ADR-0009).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import {
  getLlmReadiness,
  getOidcStatus,
  getPlatformConfig,
  getPlatformHealth,
  getSettings,
  testLlmConnection,
  updateSettings,
  type LlmProbeResult,
} from "../api/auth";
import {
  createCredential,
  getRotationStatus,
  listCredentials,
  rotateCredential,
  type CredentialKind,
  type CredentialRead,
} from "../api/credentials";
import { listIntegrations } from "../api/integrations";
import { ApiError } from "../api/client";
import { FormField } from "../components/FormField";
import { PageHeader } from "../components/PageHeader";
import { Pagination } from "../components/Pagination";
import { Spinner } from "../components/Skeleton";
import { StatusPill } from "../components/StatusPill";
import { useAuthStore } from "../stores/auth";
import { hasMinimumRole, type Role } from "../stores/roles";
import { useThemeStore } from "../stores/theme";
import type { Theme } from "../stores/theme";

// ── Known LLM profiles (must match KNOWN_PROFILES in the backend registry) ──

const KNOWN_PROFILES = ["local", "anthropic", "openai", "azure"] as const;
type LlmProfile = (typeof KNOWN_PROFILES)[number];

/** Page size for the credential vault table (server-side offset/limit). */
const CREDENTIALS_PAGE_SIZE = 50;

const CREDENTIAL_KINDS: { value: CredentialKind; label: string }[] = [
  { value: "ssh", label: "SSH" },
  { value: "snmp_v2c", label: "SNMP v2c" },
  { value: "snmp_v3", label: "SNMP v3" },
  { value: "oidc", label: "OIDC client secret" },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

const GENERIC_ERROR = "Something went wrong. Please try again.";

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.problem.detail;
  }
  return GENERIC_ERROR;
}

// ── Section navigation ────────────────────────────────────────────────────────

interface SectionLink {
  to: string;
  label: string;
  end?: boolean;
  /** Shown only when the user meets this minimum role. */
  minRole?: Role;
}

const SECTION_LINKS: SectionLink[] = [
  { to: "/settings", label: "Appearance", end: true },
  { to: "/settings/agents", label: "Agents & Chat" },
  { to: "/settings/account", label: "My account" },
  { to: "/settings/credentials", label: "Credentials", minRole: "engineer" },
  { to: "/settings/llm", label: "AI / LLM", minRole: "admin" },
  { to: "/settings/access", label: "Users & access", minRole: "admin" },
  { to: "/settings/integrations", label: "Integrations", minRole: "admin" },
  { to: "/settings/platform", label: "Platform", minRole: "admin" },
];

function SettingsSectionNav() {
  const role = useAuthStore((s) => s.user?.role);
  const links = SECTION_LINKS.filter(
    (link) => !link.minRole || hasMinimumRole(role, link.minRole),
  );

  return (
    <nav
      aria-label="Settings sections"
      data-testid="settings-section-nav"
      className="flex flex-wrap gap-2 border-b border-carbon-800 pb-3"
    >
      {links.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          end={link.end}
          className={({ isActive }) =>
            [
              "rounded border px-3 py-1.5 text-xs font-medium transition-colors",
              isActive
                ? "border-accent bg-accent/10 text-accent"
                : "border-carbon-700 text-zinc-400 hover:border-carbon-600 hover:text-zinc-200",
            ].join(" ")
          }
        >
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}

// ── Appearance section ────────────────────────────────────────────────────────

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

export function SettingsAppearanceSection() {
  const theme = useThemeStore((state) => state.theme);
  const setTheme = useThemeStore((state) => state.setTheme);

  return (
    <section
      aria-label="Appearance"
      data-testid="settings-appearance"
      className="panel p-4 flex flex-col gap-4"
    >
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Appearance
      </h3>
      <div className="flex flex-col gap-2">
        <p className="text-xs text-zinc-400">Theme</p>
        <div className="flex gap-2">
          {THEME_OPTIONS.map(({ value, label }) => (
            <button
              key={value}
              type="button"
              onClick={() => setTheme(value)}
              className={[
                "rounded border px-3 py-1.5 text-xs font-medium transition-colors",
                theme === value
                  ? "border-accent bg-accent/10 text-accent"
                  : "border-carbon-700 text-zinc-400 hover:border-carbon-600 hover:text-zinc-200",
              ].join(" ")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Agents & Chat help ────────────────────────────────────────────────────────

const CORE_AGENTS: { name: string; summary: string }[] = [
  { name: "Master Architect", summary: "Plans multi-step work and routes to specialists." },
  { name: "Consultant", summary: "Clarifies requirements when intent is ambiguous." },
  { name: "Discovery", summary: "Inventory, neighbors, routes via SSH/SNMP/API plugins." },
  { name: "Troubleshooting", summary: "BGP, OSPF, ACL, firewall, path analysis." },
  { name: "Packet Analysis", summary: "tcpdump/tshark capture and findings (engineer+)." },
  { name: "Configuration", summary: "Backup, restore, drift, compliance — changes need approval." },
  { name: "DDI", summary: "DNS/DHCP/IPAM via Infoblox, BlueCat, Route53." },
  { name: "Documentation", summary: "Runbooks, incident reports, inventories, diagrams." },
  { name: "Security", summary: "Policy and exposure analysis (firewall wave)." },
  { name: "Automation", summary: "Executes approved Change Requests only." },
];

const EXAMPLE_PROMPTS = [
  "Why is BGP down between core-a and core-b?",
  "Show the L2 path from host-web-01 to the firewall.",
  "Draft a ChangeRequest to open TCP 443 from DMZ to app-tier.",
  "Summarize discovery findings for site DFW1.",
];

export function SettingsAgentsSection() {
  return (
    <section
      aria-label="Agents and Chat setup"
      data-testid="settings-agents"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Agents & Chat setup
        </h3>
        <p className="text-sm text-zinc-300">
          Chat is the AI Network Engineer console. The supervisor routes your
          question to specialist agents, streams a reasoning trace, and keeps
          write operations behind human approval.
        </p>
        <Link to="/chat" className="btn self-start text-xs">
          Open Chat
        </Link>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Prerequisites checklist
        </h3>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-zinc-300">
          <li>
            <strong className="text-zinc-100">LLM ready</strong> — admins set the
            active profile under{" "}
            <Link to="/settings/llm" className="text-accent hover:underline">
              AI / LLM
            </Link>
            . Local uses Ollama; subscription providers need env API keys on the
            server (never pasted in the browser).
          </li>
          <li>
            <strong className="text-zinc-100">Device credentials</strong> —
            engineer+ create vault entries under{" "}
            <Link to="/settings/credentials" className="text-accent hover:underline">
              Credentials
            </Link>
            , then reference those names when launching discovery.
          </li>
          <li>
            <strong className="text-zinc-100">Inventory & topology</strong> — run
            discovery on{" "}
            <Link to="/devices" className="text-accent hover:underline">
              Devices
            </Link>
            , then open{" "}
            <Link to="/topology" className="text-accent hover:underline">
              Topology
            </Link>
            .
          </li>
          <li>
            <strong className="text-zinc-100">Change approval</strong> —
            engineer+ reviews drafts on{" "}
            <Link to="/changes" className="text-accent hover:underline">
              Changes
            </Link>
            . Agents do not push device changes without four-eyes approval.
          </li>
        </ol>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Core agents
        </h3>
        <ul className="grid gap-2 sm:grid-cols-2">
          {CORE_AGENTS.map((agent) => (
            <li
              key={agent.name}
              className="rounded border border-carbon-800 bg-carbon-950/50 px-3 py-2"
            >
              <p className="text-xs font-medium text-zinc-100">{agent.name}</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">{agent.summary}</p>
            </li>
          ))}
        </ul>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Example prompts
        </h3>
        <ul className="space-y-1.5 text-sm text-zinc-300">
          {EXAMPLE_PROMPTS.map((prompt) => (
            <li key={prompt} className="font-mono text-xs text-zinc-400">
              “{prompt}”
            </li>
          ))}
        </ul>
      </div>

      <div className="panel p-4 flex flex-col gap-2">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Safety & trust
        </h3>
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-zinc-300">
          <li>Vault secrets never enter LLM prompts; CLI output is redacted.</li>
          <li>
            External LLM profiles (Anthropic / OpenAI / Azure) imply data may leave
            the deployment — selection is audited.
          </li>
          <li>
            Every answer shows a reasoning trace (plan → tool calls → observations
            → conclusion). Expand it under each Chat reply.
          </li>
          <li>
            Roles: viewers can chat and read; engineers run captures and approve
            changes; admins manage users and LLM profile.
          </li>
        </ul>
      </div>
    </section>
  );
}

// ── My account ────────────────────────────────────────────────────────────────

export function SettingsAccountSection() {
  return (
    <section
      aria-label="My account"
      data-testid="settings-account"
      className="panel p-4 flex flex-col gap-3"
    >
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        My account
      </h3>
      <p className="text-sm text-zinc-300">
        Profile editing, password change, and session management live on the
        Profile page so day-to-day account work stays one click away from the
        user menu.
      </p>
      <ul className="list-disc space-y-1 pl-5 text-sm text-zinc-400">
        <li>Display name and email</li>
        <li>Change password</li>
        <li>Active sessions (revoke one or all)</li>
      </ul>
      <Link to="/profile" className="btn self-start text-xs">
        Open Profile
      </Link>
    </section>
  );
}

// ── Users & access (admin) ────────────────────────────────────────────────────

export function SettingsAccessSection() {
  const {
    data: oidc,
    isPending: oidcPending,
    error: oidcError,
  } = useQuery({
    queryKey: ["oidc-status"],
    queryFn: getOidcStatus,
  });

  return (
    <section
      aria-label="Users and access"
      data-testid="settings-access"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Users & access
        </h3>
        <p className="text-sm text-zinc-300">
          Admins create accounts with a one-time temporary password (no
          self-signup, no SMTP invite). Full user administration is on the Users
          page.
        </p>
        <Link to="/users" className="btn self-start text-xs">
          Open user management
        </Link>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          RBAC ranks
        </h3>
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          {(
            [
              ["viewer", "Read inventory, topology, chat, audit views."],
              ["operator", "Viewer + limited operational actions."],
              ["engineer", "Discovery, credentials, packet, change approval."],
              ["admin", "Users, LLM profile, platform settings."],
            ] as const
          ).map(([role, desc]) => (
            <div key={role} className="rounded border border-carbon-800 px-3 py-2">
              <dt className="font-mono text-xs uppercase tracking-wider text-accent">
                {role}
              </dt>
              <dd className="mt-0.5 text-xs text-zinc-400">{desc}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div
        className="panel p-4 flex flex-col gap-2"
        data-testid="settings-oidc-status"
      >
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          SSO / break-glass
        </h3>
        {oidcPending && (
          <p role="status" className="text-xs text-zinc-500">
            Loading SSO status…
          </p>
        )}
        {oidcError && (
          <p role="alert" className="text-xs text-status-error">
            {errorMessage(oidcError)}
          </p>
        )}
        {oidc && (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill
                variant={oidc.enabled ? "ok" : "neutral"}
                data-testid="oidc-enabled-pill"
              >
                {oidc.enabled ? "SSO enabled" : "SSO disabled"}
              </StatusPill>
              {oidc.enabled && oidc.break_glass_local_admin_only && (
                <StatusPill variant="warn" data-testid="oidc-break-glass-pill">
                  break-glass admin only
                </StatusPill>
              )}
              {oidc.enabled && (
                <StatusPill
                  variant={oidc.allow_admin_via_oidc ? "info" : "neutral"}
                  data-testid="oidc-admin-via-sso-pill"
                >
                  {oidc.allow_admin_via_oidc
                    ? "admin via SSO allowed"
                    : "admin via SSO capped"}
                </StatusPill>
              )}
            </div>
            <ul className="list-disc space-y-1 pl-5 text-xs text-zinc-400">
              <li>
                Issuer: {oidc.issuer_configured ? "configured" : "not set"}
              </li>
              <li>
                Client id: {oidc.client_id_configured ? "configured" : "not set"}
              </li>
              <li>
                Client secret ref:{" "}
                {oidc.client_ref_configured ? "configured" : "not set"}
              </li>
              <li>
                Redirect URI:{" "}
                <code className="font-mono text-[11px] text-zinc-300">
                  {oidc.redirect_uri}
                </code>
              </li>
            </ul>
          </div>
        )}
        <p className="text-sm text-zinc-300">
          OIDC/SSO is configured at deploy time (issuer, client id, secret ref,
          group→role map) — not via this form. When OIDC is enabled, local
          password login is fenced to break-glass admin only. Keep at least one
          local admin active; the platform refuses to demote or deactivate the
          last admin.
        </p>
      </div>
    </section>
  );
}

// ── Credentials vault (engineer+) ─────────────────────────────────────────────

export function SettingsCredentialsSection() {
  const queryClient = useQueryClient();
  const canWrite = hasMinimumRole(useAuthStore((s) => s.user?.role), "engineer");

  const [offset, setOffset] = useState(0);
  const { data, isPending, error: loadError } = useQuery({
    queryKey: ["credentials", offset],
    queryFn: () => listCredentials({ limit: CREDENTIALS_PAGE_SIZE, offset }),
  });

  const {
    data: rotation,
    isPending: rotationPending,
    error: rotationError,
  } = useQuery({
    queryKey: ["credentials-rotation-status"],
    queryFn: getRotationStatus,
    // engineer+ only: viewers never mount this section (RoleRoute).
    enabled: canWrite,
  });

  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("ssh");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [scopeSite, setScopeSite] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const [rotateId, setRotateId] = useState<string | null>(null);
  const [rotateSecret, setRotateSecret] = useState("");
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [rotateSuccess, setRotateSuccess] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () =>
      createCredential({
        name: name.trim(),
        kind,
        username: username.trim() || null,
        secret,
        scope_site: scopeSite.trim() || null,
      }),
    onSuccess: (created) => {
      setFormSuccess(`Credential “${created.name}” created. The secret is not shown again.`);
      setFormError(null);
      setName("");
      setUsername("");
      setSecret("");
      setScopeSite("");
      setOffset(0);
      void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    },
    onError: (err) => {
      setFormError(errorMessage(err));
      setFormSuccess(null);
    },
  });

  const rotateMutation = useMutation({
    mutationFn: () => {
      if (!rotateId) {
        throw new Error("missing credential id");
      }
      return rotateCredential(rotateId, { secret: rotateSecret });
    },
    onSuccess: (updated) => {
      setRotateSuccess(`Rotated “${updated.name}”. The new secret is not shown again.`);
      setRotateError(null);
      setRotateId(null);
      setRotateSecret("");
      void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    },
    onError: (err) => {
      setRotateError(errorMessage(err));
      setRotateSuccess(null);
    },
  });

  function handleCreate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    if (!name.trim() || !secret) {
      setFormError("Name and secret are required.");
      return;
    }
    createMutation.mutate();
  }

  function handleRotate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setRotateError(null);
    setRotateSuccess(null);
    if (!rotateSecret) {
      setRotateError("New secret is required.");
      return;
    }
    rotateMutation.mutate();
  }

  return (
    <section
      aria-label="Device credentials"
      data-testid="settings-credentials"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-2">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Device credentials
        </h3>
        <p className="text-sm text-zinc-300">
          Vault entries used by discovery, config backup, and agent tools. Secrets
          are write-only: stored under envelope encryption and never returned by
          the API. Use the credential <em>name</em> when launching discovery on
          Devices.
        </p>
      </div>

      {canWrite && (
        <div
          className="panel p-4 flex flex-col gap-2"
          data-testid="credentials-kek-rotation"
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            KEK rotation status
          </h3>
          <p className="text-xs text-zinc-400">
            Envelope-key rewrap progress (versions and pending row count only —
            no key material).
          </p>
          {rotationPending && (
            <p role="status" className="text-xs text-zinc-500">
              Loading rotation status…
            </p>
          )}
          {rotationError && (
            <p role="alert" className="text-xs text-status-error">
              {errorMessage(rotationError)}
            </p>
          )}
          {rotation && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-300">
              <StatusPill
                variant={rotation.rows_pending > 0 ? "warn" : "ok"}
                data-testid="kek-rows-pending-pill"
              >
                {rotation.rows_pending > 0
                  ? `${rotation.rows_pending} pending`
                  : "fully wrapped"}
              </StatusPill>
              <span>
                Active KEK:{" "}
                <code className="font-mono text-zinc-200">{rotation.to_version}</code>
              </span>
              {rotation.from_version != null && (
                <span>
                  Migrating from:{" "}
                  <code className="font-mono text-zinc-200">
                    {rotation.from_version}
                  </code>
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {isPending && (
        <p role="status" className="flex items-center gap-2 text-xs text-zinc-500">
          <Spinner /> Loading credentials…
        </p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">
          {errorMessage(loadError)}
        </p>
      )}

      {data && (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[32rem] text-left text-xs">
            <thead className="border-b border-carbon-800 font-mono text-[10px] uppercase tracking-widest text-zinc-500">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Username</th>
                <th className="px-3 py-2">Scope</th>
                <th className="px-3 py-2">Updated</th>
                {canWrite && <th className="px-3 py-2">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr>
                  <td
                    colSpan={canWrite ? 6 : 5}
                    className="px-3 py-6 text-center text-zinc-500"
                  >
                    No credentials yet. Create one below for discovery to use.
                  </td>
                </tr>
              ) : (
                data.items.map((row: CredentialRead) => (
                  <tr key={row.id} className="border-b border-carbon-900/80">
                    <td className="px-3 py-2 font-mono text-zinc-100">{row.name}</td>
                    <td className="px-3 py-2 text-zinc-400">{row.kind}</td>
                    <td className="px-3 py-2 text-zinc-400">{row.username ?? "—"}</td>
                    <td className="px-3 py-2 text-zinc-500">
                      {row.scope_site || row.scope_role || row.scope_device_group
                        ? [row.scope_site, row.scope_role, row.scope_device_group]
                            .filter(Boolean)
                            .join(" / ")
                        : "unscoped"}
                    </td>
                    <td className="px-3 py-2 font-mono text-[10px] text-zinc-500">
                      {new Date(row.updated_at).toLocaleString()}
                    </td>
                    {canWrite && (
                      <td className="px-3 py-2">
                        <button
                          type="button"
                          className="text-accent hover:underline"
                          onClick={() => {
                            setRotateId(row.id);
                            setRotateSecret("");
                            setRotateError(null);
                            setRotateSuccess(null);
                          }}
                        >
                          Rotate
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <p className="border-t border-carbon-800 px-3 py-2 text-[11px] text-zinc-600">
            {data.total} total
          </p>
          <Pagination
            offset={offset}
            limit={CREDENTIALS_PAGE_SIZE}
            total={data.total}
            onChange={setOffset}
            label="credentials"
          />
        </div>
      )}

      {canWrite && rotateId && (
        <form
          onSubmit={handleRotate}
          className="panel p-4 flex flex-col gap-3"
          data-testid="credential-rotate-form"
          noValidate
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Rotate secret
          </h3>
          <FormField label="New secret" required>
            {(cp) => (
              <input
                {...cp}
                type="password"
                autoComplete="new-password"
                className="input"
                value={rotateSecret}
                onChange={(e) => setRotateSecret(e.target.value)}
              />
            )}
          </FormField>
          {rotateError && (
            <p role="alert" className="text-xs text-status-error">
              {rotateError}
            </p>
          )}
          <div className="flex gap-2">
            <button type="submit" className="btn" disabled={rotateMutation.isPending}>
              {rotateMutation.isPending ? "Rotating…" : "Confirm rotate"}
            </button>
            <button
              type="button"
              className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400"
              onClick={() => setRotateId(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {rotateSuccess && (
        <p className="text-xs text-status-ok" role="status">
          {rotateSuccess}
        </p>
      )}

      {canWrite && (
        <form
          onSubmit={handleCreate}
          className="panel p-4 flex flex-col gap-3"
          data-testid="credential-create-form"
          noValidate
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Create credential
          </h3>
          <FormField label="Name" required>
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="prod-ssh"
                autoComplete="off"
              />
            )}
          </FormField>
          <FormField label="Kind" required>
            {(cp) => (
              <select
                {...cp}
                className="input"
                value={kind}
                onChange={(e) => setKind(e.target.value as CredentialKind)}
              >
                {CREDENTIAL_KINDS.map((k) => (
                  <option key={k.value} value={k.value}>
                    {k.label}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          <FormField label="Username">
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            )}
          </FormField>
          <FormField label="Secret" required>
            {(cp) => (
              <input
                {...cp}
                type="password"
                className="input"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoComplete="new-password"
              />
            )}
          </FormField>
          <FormField label="Scope site (optional)">
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={scopeSite}
                onChange={(e) => setScopeSite(e.target.value)}
                placeholder="Leave empty for unscoped"
              />
            )}
          </FormField>
          {formError && (
            <p role="alert" className="text-xs text-status-error">
              {formError}
            </p>
          )}
          {formSuccess && (
            <p className="text-xs text-status-ok" role="status">
              {formSuccess}
            </p>
          )}
          <button type="submit" className="btn self-start" disabled={createMutation.isPending}>
            {createMutation.isPending ? "Creating…" : "Create credential"}
          </button>
        </form>
      )}
    </section>
  );
}

// ── LLM settings section (admin only, mounted at /settings/llm) ───────────────

function readinessTone(status: string, configured: boolean): string {
  if (status === "ready" && configured) {
    return "text-status-ok";
  }
  if (status === "not_configured") {
    return "text-zinc-500";
  }
  return "text-status-error";
}

/**
 * Admin-only LLM profile + role map section.
 *
 * Loads the current settings from GET /auth/settings, lets the admin choose a
 * profile and optional reasoning/fast role overrides, then PATCHes on save.
 * Provider API keys are never shown, entered, or stored here — the backend has
 * no body field for them and this component has no such input.
 *
 * Readiness + connection test: GET /auth/settings/llm-readiness (static) and
 * POST /auth/settings/llm-test (live probe).
 */
export function SettingsLlmSection() {
  const queryClient = useQueryClient();

  const { data: settings, isPending, error: loadError } = useQuery({
    queryKey: ["auth-settings"],
    queryFn: getSettings,
  });

  const {
    data: readiness,
    isPending: readinessPending,
    error: readinessError,
  } = useQuery({
    queryKey: ["llm-readiness"],
    queryFn: getLlmReadiness,
  });

  const [profile, setProfile] = useState<LlmProfile | "">("");
  const [reasoning, setReasoning] = useState<string>("");
  const [fast, setFast] = useState<string>("");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [probeTarget, setProbeTarget] = useState<LlmProfile | null>(null);
  const [probeResult, setProbeResult] = useState<LlmProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const effectiveProfile = (profile || settings?.llm_profile) as LlmProfile | undefined;
  const effectiveReasoning =
    reasoning !== "" ? reasoning : (settings?.llm_role_reasoning ?? "");
  const effectiveFast = fast !== "" ? fast : (settings?.llm_role_fast ?? "");

  const saveMutation = useMutation({
    mutationFn: () =>
      updateSettings({
        llm_profile: effectiveProfile as LlmProfile,
        llm_role_reasoning: effectiveReasoning || null,
        llm_role_fast: effectiveFast || null,
      }),
    onSuccess: () => {
      setSaveSuccess(true);
      setSaveError(null);
      void queryClient.invalidateQueries({ queryKey: ["auth-settings"] });
      void queryClient.invalidateQueries({ queryKey: ["llm-profile"] });
      void queryClient.invalidateQueries({ queryKey: ["llm-readiness"] });
    },
    onError: (err) => {
      setSaveError(errorMessage(err));
      setSaveSuccess(false);
    },
  });

  const testMutation = useMutation({
    mutationFn: (target: LlmProfile) => testLlmConnection(target),
    onSuccess: (result) => {
      setProbeResult(result);
      setProbeError(null);
      setProbeTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["llm-readiness"] });
    },
    onError: (err) => {
      setProbeError(errorMessage(err));
      setProbeResult(null);
      setProbeTarget(null);
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaveError(null);
    setSaveSuccess(false);
    saveMutation.mutate();
  }

  function handleTest(target: LlmProfile) {
    setProbeTarget(target);
    setProbeError(null);
    setProbeResult(null);
    testMutation.mutate(target);
  }

  return (
    <section
      aria-label="LLM settings"
      data-testid="settings-llm"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          AI / LLM profile (admin)
        </h3>
        <p className="text-sm text-zinc-300">
          Choose which provider profile agents use. The default is{" "}
          <code className="font-mono text-xs text-zinc-200">local</code> (Ollama).
          API keys for Anthropic, OpenAI, and Azure are configured on the server
          via environment / secrets manager — never entered in this UI.
        </p>
        {effectiveProfile && effectiveProfile !== "local" && (
          <p
            role="status"
            data-testid="llm-egress-warning"
            className="rounded border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-xs text-status-warn"
          >
            External profile selected: prompts and tool context may leave this
            deployment. Selection is audit-logged.
          </p>
        )}
      </div>

      <div
        className="panel p-4 flex flex-col gap-3"
        data-testid="llm-readiness-panel"
      >
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Provider readiness
        </h3>
        <p className="text-xs text-zinc-400">
          Configured = server env has the required credentials. Test runs a
          bounded live probe (Ollama tags or provider models list) without
          showing secrets.
        </p>
        {readinessPending && (
          <p role="status" className="text-xs text-zinc-500">
            Loading readiness…
          </p>
        )}
        {readinessError && (
          <p role="alert" className="text-xs text-status-error">
            {errorMessage(readinessError)}
          </p>
        )}
        {readiness && (
          <>
            <p className="text-xs text-zinc-400">
              Active:{" "}
              <code className="font-mono text-zinc-200">{readiness.active_profile}</code>
              {" · "}
              Local model:{" "}
              <code className="font-mono text-zinc-200">{readiness.local_model}</code>
            </p>
            <ul className="flex flex-col gap-2" data-testid="llm-readiness-list">
              {readiness.profiles.map((row) => (
                <li
                  key={row.profile}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-carbon-800 px-3 py-2"
                >
                  <div className="flex flex-col gap-0.5">
                    <span className="font-mono text-xs text-zinc-100">
                      {row.profile}
                      {row.egress ? (
                        <span className="ml-2 text-[10px] uppercase text-status-warn">
                          egress
                        </span>
                      ) : null}
                    </span>
                    <span className={`text-[11px] ${readinessTone(row.status, row.configured)}`}>
                      {row.configured ? "configured" : "not configured"} · {row.status}
                      {row.model ? ` · ${row.model}` : ""}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="rounded border border-carbon-700 px-2 py-1 text-[11px] text-zinc-300 hover:border-carbon-600 hover:text-zinc-100 disabled:opacity-50"
                    disabled={testMutation.isPending}
                    onClick={() => handleTest(row.profile as LlmProfile)}
                    data-testid={`llm-test-${row.profile}`}
                  >
                    {probeTarget === row.profile && testMutation.isPending
                      ? "Testing…"
                      : "Test connection"}
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
        {probeError && (
          <p role="alert" className="text-xs text-status-error">
            {probeError}
          </p>
        )}
        {probeResult && (
          <div
            role="status"
            data-testid="llm-probe-result"
            className="rounded border border-carbon-700 bg-carbon-950/50 px-3 py-2 text-xs text-zinc-300"
          >
            <p>
              Probe <code className="font-mono text-zinc-100">{probeResult.profile}</code>
              :{" "}
              <span className={readinessTone(probeResult.status, probeResult.configured)}>
                {probeResult.status}
              </span>
              {probeResult.latency_ms != null
                ? ` · ${probeResult.latency_ms.toFixed(0)} ms`
                : ""}
            </p>
            {probeResult.detail ? (
              <p className="mt-1 text-zinc-500">{probeResult.detail}</p>
            ) : null}
            {probeResult.models.length > 0 ? (
              <p className="mt-1 font-mono text-[11px] text-zinc-500">
                models: {probeResult.models.join(", ")}
              </p>
            ) : null}
          </div>
        )}
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Subscription / local setup
        </h3>
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-zinc-300">
          <li>
            <strong className="text-zinc-100">local</strong> — run Ollama (
            <code className="font-mono text-[11px]">ollama pull llama3.1:8b</code>
            ), set <code className="font-mono text-[11px]">NETOPS_OLLAMA_BASE_URL</code>{" "}
            and <code className="font-mono text-[11px]">NETOPS_LLM_LOCAL_MODEL</code>.
          </li>
          <li>
            <strong className="text-zinc-100">anthropic</strong> — set{" "}
            <code className="font-mono text-[11px]">ANTHROPIC_API_KEY</code> on the
            API/worker, then select the profile here.
          </li>
          <li>
            <strong className="text-zinc-100">openai</strong> — set{" "}
            <code className="font-mono text-[11px]">OPENAI_API_KEY</code>.
          </li>
          <li>
            <strong className="text-zinc-100">azure</strong> — set{" "}
            <code className="font-mono text-[11px]">AZURE_OPENAI_API_KEY</code> +{" "}
            <code className="font-mono text-[11px]">AZURE_OPENAI_ENDPOINT</code>.
          </li>
        </ul>
      </div>

      {isPending && (
        <p role="status" className="text-xs text-zinc-500">
          Loading LLM settings…
        </p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">
          {errorMessage(loadError)}
        </p>
      )}

      {settings && (
        <form
          onSubmit={handleSubmit}
          className="panel p-4 flex flex-col gap-3"
          noValidate
        >
          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Profile
            <select
              value={effectiveProfile ?? ""}
              onChange={(e) => setProfile(e.target.value as LlmProfile)}
              className="input"
            >
              {KNOWN_PROFILES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Reasoning role override
            <select
              value={effectiveReasoning}
              onChange={(e) => setReasoning(e.target.value)}
              className="input"
            >
              <option value="">— use profile default —</option>
              {KNOWN_PROFILES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1 text-xs text-zinc-400">
            Fast role override
            <select
              value={effectiveFast}
              onChange={(e) => setFast(e.target.value)}
              className="input"
            >
              <option value="">— use profile default —</option>
              {KNOWN_PROFILES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>

          {saveError !== null && (
            <p role="alert" className="text-xs text-status-error">
              {saveError}
            </p>
          )}
          {saveSuccess && (
            <p className="text-xs text-status-ok">LLM settings saved.</p>
          )}

          <button type="submit" disabled={saveMutation.isPending} className="btn self-start">
            {saveMutation.isPending ? "Saving…" : "Save LLM settings"}
          </button>
        </form>
      )}
    </section>
  );
}

// ── Integrations matrix (admin, Path B / T2.1) ────────────────────────────────

export function SettingsIntegrationsSection() {
  const {
    data,
    isPending,
    error: loadError,
  } = useQuery({
    queryKey: ["integrations"],
    queryFn: listIntegrations,
  });

  return (
    <section
      aria-label="Integrations"
      data-testid="settings-integrations"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Vendor integrations
        </h3>
        <p className="text-sm text-zinc-300">
          Registered vendor plugins and the capabilities they declare. This is
          inventory only — live device reachability is discovery, not Settings.
        </p>
      </div>

      {isPending && (
        <p role="status" className="text-xs text-zinc-500">
          Loading integrations…
        </p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">
          {errorMessage(loadError)}
        </p>
      )}

      {data && data.vendors.length === 0 && (
        <div className="panel p-4 text-sm text-zinc-400" data-testid="integrations-empty">
          No vendor plugins are registered in this process.
        </div>
      )}

      {data && data.vendors.length > 0 && (
        <div className="panel overflow-x-auto" data-testid="integrations-table">
          <table className="w-full min-w-[36rem] text-left text-xs">
            <thead className="border-b border-carbon-800 text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-3 py-2 font-medium">Vendor</th>
                <th className="px-3 py-2 font-medium">Category</th>
                <th className="px-3 py-2 font-medium">Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {data.vendors.map((v) => (
                <tr
                  key={v.vendor_id}
                  className="border-b border-carbon-900/80 last:border-0"
                  data-testid={`integration-row-${v.vendor_id}`}
                >
                  <td className="px-3 py-2 align-top">
                    <div className="font-medium text-zinc-100">{v.display_name}</div>
                    <code className="font-mono text-[11px] text-zinc-500">
                      {v.vendor_id}
                    </code>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusPill variant="neutral">{v.category}</StatusPill>
                  </td>
                  <td className="px-3 py-2 align-top text-zinc-300">
                    {v.capabilities.length === 0 ? (
                      <span className="text-zinc-500">—</span>
                    ) : (
                      <ul className="flex flex-wrap gap-1">
                        {v.capabilities.map((cap) => (
                          <li key={cap}>
                            <code className="rounded border border-carbon-800 bg-carbon-950/40 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                              {cap}
                            </code>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-carbon-800 px-3 py-2 text-[11px] text-zinc-600">
            {data.vendors.length} vendor{data.vendors.length === 1 ? "" : "s"} registered
          </p>
        </div>
      )}
    </section>
  );
}

// ── Platform health + retention (admin, Path B / T2.2–T2.3) ───────────────────

function pad2(n: number): string {
  return n.toString().padStart(2, "0");
}

function utcSchedule(hour: number, minute: number): string {
  return `${pad2(hour)}:${pad2(minute)} UTC`;
}

export function SettingsPlatformSection() {
  const {
    data: health,
    isPending: healthPending,
    error: healthError,
    dataUpdatedAt: healthUpdatedAt,
    refetch: refetchHealth,
    isFetching: healthFetching,
  } = useQuery({
    queryKey: ["platform-health"],
    queryFn: getPlatformHealth,
  });

  const {
    data: config,
    isPending: configPending,
    error: configError,
  } = useQuery({
    queryKey: ["platform-config"],
    queryFn: getPlatformConfig,
  });

  const lastFetched =
    healthUpdatedAt > 0
      ? new Date(healthUpdatedAt).toLocaleTimeString()
      : null;

  return (
    <section
      aria-label="Platform health and retention"
      data-testid="settings-platform"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Platform health
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            {lastFetched && (
              <span className="text-[11px] text-zinc-500" data-testid="platform-health-fetched">
                Last fetched {lastFetched}
              </span>
            )}
            <button
              type="button"
              className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-300 hover:border-carbon-600"
              onClick={() => void refetchHealth()}
              disabled={healthFetching}
              data-testid="platform-health-refresh"
            >
              {healthFetching ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
        <p className="text-sm text-zinc-300">
          Dependency probes reuse the same checks as orchestrator readiness.
          Public <code className="font-mono text-[11px]">/health/ready</code> stays
          unauthenticated for K8s; this panel is admin-gated.
        </p>

        {healthPending && (
          <p role="status" className="text-xs text-zinc-500">
            Probing dependencies…
          </p>
        )}
        {healthError && (
          <p role="alert" className="text-xs text-status-error">
            {errorMessage(healthError)}
          </p>
        )}
        {health && (
          <div className="flex flex-col gap-3">
            <StatusPill
              variant={health.status === "ok" ? "ok" : "error"}
              data-testid="platform-health-overall"
            >
              {health.status === "ok" ? "all dependencies ok" : "degraded"}
            </StatusPill>
            <div
              className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3"
              data-testid="platform-health-deps"
            >
              {Object.entries(health.dependencies).map(([name, dep]) => (
                <div
                  key={name}
                  className="rounded border border-carbon-800 px-3 py-2"
                  data-testid={`platform-dep-${name}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-zinc-200">{name}</span>
                    <StatusPill variant={dep.status === "ok" ? "ok" : "error"}>
                      {dep.status}
                    </StatusPill>
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-500">
                    {dep.latency_ms.toFixed(0)} ms
                    {dep.error ? ` · ${dep.error}` : ""}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="panel p-4 flex flex-col gap-3" data-testid="platform-retention">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Retention & export (effective config)
        </h3>
        <p className="text-sm text-zinc-300">
          Read-only deploy configuration. Change via Helm/env, not this form.
        </p>
        {configPending && (
          <p role="status" className="text-xs text-zinc-500">
            Loading effective config…
          </p>
        )}
        {configError && (
          <p role="alert" className="text-xs text-status-error">
            {errorMessage(configError)}
          </p>
        )}
        {config && (
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div className="rounded border border-carbon-800 px-3 py-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Pcap retention
              </dt>
              <dd className="mt-0.5 text-zinc-200" data-testid="pcap-retention-days">
                {config.pcap_retention_days} day
                {config.pcap_retention_days === 1 ? "" : "s"} · purge schedule{" "}
                {utcSchedule(config.pcap_retention_hour, config.pcap_retention_minute)}
              </dd>
            </div>
            <div className="rounded border border-carbon-800 px-3 py-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Raw artifact retention
              </dt>
              <dd className="mt-0.5 text-zinc-200" data-testid="raw-artifact-retention-days">
                {config.raw_artifact_retention_days === 0
                  ? "disabled (keep forever)"
                  : `${config.raw_artifact_retention_days} days`}{" "}
                · schedule{" "}
                {utcSchedule(
                  config.raw_artifact_retention_hour,
                  config.raw_artifact_retention_minute,
                )}
              </dd>
            </div>
            <div className="rounded border border-carbon-800 px-3 py-2 sm:col-span-2">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">
                Audit → SIEM export
              </dt>
              <dd className="mt-0.5 flex flex-wrap items-center gap-2 text-zinc-200">
                <StatusPill
                  variant={config.audit_export_configured ? "ok" : "neutral"}
                  data-testid="audit-export-pill"
                >
                  {config.audit_export_configured
                    ? `export: ${config.audit_export_format}`
                    : "export disabled"}
                </StatusPill>
                <span className="text-xs text-zinc-500">
                  Host, URL, and bearer token are never shown here.
                </span>
              </dd>
            </div>
          </dl>
        )}
      </div>
    </section>
  );
}

// ── Page shell ────────────────────────────────────────────────────────────────

export function SettingsPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="settings-page">
      <PageHeader
        title="Settings"
        description="Appearance, account links, agents setup, credentials vault, and (for admins) AI profile, integrations, platform health, and user access."
      />
      <SettingsSectionNav />
      <Outlet />
    </div>
  );
}
