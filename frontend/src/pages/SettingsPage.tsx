/**
 * SettingsPage (Auth & Account UI): appearance + (admin) LLM profile select.
 *
 * Placeholder shell introduced by the routing task (F2) so the ``/settings``
 * route resolves. The Appearance (theme) section is reachable by any
 * authenticated user; the LLM profile + role map section is admin-only and is
 * gated by ``RoleRoute("admin")`` at its own nested route. Provider API keys are
 * never shown, entered, or stored here. Both sections are delivered by the
 * settings task.
 */

import { PageHeader } from "../components/PageHeader";

export function SettingsPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="settings-page">
      <PageHeader
        title="Settings"
        description="Appearance and (for admins) the active LLM profile."
      />
    </div>
  );
}
