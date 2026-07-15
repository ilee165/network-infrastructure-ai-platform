import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { getOidcStatus } from "../../api/auth";
import { messageFor } from "../../components/ErrorBanner";
import { StatusPill } from "../../components/StatusPill";

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
            {messageFor(oidcError)}
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
