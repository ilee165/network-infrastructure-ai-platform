import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";

import {
  getLlmReadiness,
  getSettings,
  testLlmConnection,
  updateSettings,
  type LlmProbeResult,
} from "../../api/auth";
import { messageFor } from "../../components/ErrorBanner";

// ── Known LLM profiles (must match KNOWN_PROFILES in the backend registry) ──

const KNOWN_PROFILES = ["local", "anthropic", "openai", "azure"] as const;
type LlmProfile = (typeof KNOWN_PROFILES)[number];

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
      setSaveError(messageFor(err));
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
      setProbeError(messageFor(err));
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
            {messageFor(readinessError)}
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
          {messageFor(loadError)}
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
