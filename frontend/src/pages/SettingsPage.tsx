/**
 * SettingsPage (Auth & Account UI): appearance + (admin) LLM profile select.
 *
 * Placeholder shell introduced by the routing task (F2) so the ``/settings``
 * route resolves. The Appearance (theme) section is reachable by any
 * authenticated user and renders here directly. The LLM profile + role map
 * section is admin-only: it lives at the nested ``/settings/llm`` route, which
 * App wraps in ``RoleRoute("admin")`` (defense-in-depth over the backend
 * ``require_role``, which remains the source of truth), and renders through the
 * ``<Outlet/>`` below. Provider API keys are never shown, entered, or stored
 * here. Both sections' real controls are delivered by the settings task.
 */

import { Outlet } from "react-router-dom";
import { PageHeader } from "../components/PageHeader";

/**
 * Admin-only LLM profile + role map section, mounted at ``/settings/llm`` behind
 * ``RoleRoute("admin")``. Placeholder shell only; the settings task adds the
 * profile select + role map. Provider API keys are never shown or entered here.
 */
export function SettingsLlmSection() {
  return <div data-testid="settings-llm" />;
}

export function SettingsPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="settings-page">
      <PageHeader
        title="Settings"
        description="Appearance and (for admins) the active LLM profile."
      />
      {/* Admin-only LLM section renders here, gated by RoleRoute("admin") at the
          nested /settings/llm route in App.tsx. */}
      <Outlet />
    </div>
  );
}
