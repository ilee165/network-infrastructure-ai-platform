/**
 * SettingsPage (Auth & Account UI, F4): appearance + (admin) LLM profile select.
 *
 * Sections:
 *  - Appearance (any authed user): theme selector (light / dark / system)
 *    wired to the theme store (persisted to localStorage).
 *  - LLM (admin only, at nested /settings/llm via RoleRoute): profile select
 *    + reasoning/fast role map wired to GET/PATCH /auth/settings.
 *    Known profiles: local | anthropic | openai | azure.
 *    Provider API keys are NEVER shown, entered, or stored here.
 *
 * The Appearance section renders directly in SettingsPage. The LLM section
 * lives at the nested /settings/llm route (App.tsx wraps it with
 * RoleRoute("admin")), rendering through the <Outlet/> below.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";
import { Outlet } from "react-router-dom";
import { getSettings, updateSettings } from "../api/auth";
import { ApiError } from "../api/client";
import { PageHeader } from "../components/PageHeader";
import { useThemeStore } from "../stores/theme";
import type { Theme } from "../stores/theme";

// ── Known LLM profiles (must match KNOWN_PROFILES in the backend provider registry) ──

const KNOWN_PROFILES = ["local", "anthropic", "openai", "azure"] as const;
type LlmProfile = (typeof KNOWN_PROFILES)[number];

// ── Helpers ───────────────────────────────────────────────────────────────────

const GENERIC_ERROR = "Something went wrong. Please try again.";

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.problem.detail;
  }
  return GENERIC_ERROR;
}

// ── Appearance section ────────────────────────────────────────────────────────

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

function AppearanceSection() {
  const theme = useThemeStore((state) => state.theme);
  const setTheme = useThemeStore((state) => state.setTheme);

  return (
    <section aria-label="Appearance" className="panel p-4 flex flex-col gap-4">
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

// ── LLM settings section (admin only, mounted at /settings/llm) ───────────────

/**
 * Admin-only LLM profile + role map section.
 *
 * Loads the current settings from GET /auth/settings, lets the admin choose a
 * profile and optional reasoning/fast role overrides, then PATCHes on save.
 * Provider API keys are never shown, entered, or stored here — the backend has
 * no body field for them and this component has no such input.
 */
export function SettingsLlmSection() {
  const queryClient = useQueryClient();

  const { data: settings, isPending, error: loadError } = useQuery({
    queryKey: ["auth-settings"],
    queryFn: getSettings,
  });

  const [profile, setProfile] = useState<LlmProfile | "">("");
  const [reasoning, setReasoning] = useState<string>("");
  const [fast, setFast] = useState<string>("");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Sync local state from query result once loaded
  // (We use a controlled select initialised from the query data)
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
    },
    onError: (err) => {
      setSaveError(errorMessage(err));
      setSaveSuccess(false);
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaveError(null);
    setSaveSuccess(false);
    saveMutation.mutate();
  }

  return (
    <section
      aria-label="LLM settings"
      data-testid="settings-llm"
      className="panel p-4 flex flex-col gap-4"
    >
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        LLM profile (admin)
      </h3>

      {isPending && (
        <p role="status" className="text-xs text-zinc-500">Loading LLM settings…</p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">{errorMessage(loadError)}</p>
      )}

      {settings && (
        <form onSubmit={handleSubmit} className="flex flex-col gap-3" noValidate>
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

// ── Page ──────────────────────────────────────────────────────────────────────

export function SettingsPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="settings-page">
      <PageHeader
        title="Settings"
        description="Appearance and (for admins) the active LLM profile."
      />

      <AppearanceSection />

      {/* Admin-only LLM section renders here, gated by RoleRoute("admin") at the
          nested /settings/llm route in App.tsx. */}
      <Outlet />
    </div>
  );
}
