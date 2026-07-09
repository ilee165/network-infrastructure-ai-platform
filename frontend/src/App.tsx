/**
 * Route table (Auth & Account UI, F2): the auth gate, the Layout shell, and the
 * pages.
 *
 * Structure:
 *  - Public, ungated: ``/login`` and ``/change-password``. ``/change-password``
 *    MUST stay reachable while ``must_change_password`` is set, so it lives
 *    outside ``ProtectedRoute`` (``ProtectedRoute`` itself redirects a flagged
 *    user *to* it).
 *  - Everything else sits under ``ProtectedRoute`` (auth + forced-change gate)
 *    and then the ``Layout`` shell. Sensitive surfaces are additionally wrapped
 *    in ``RoleRoute`` as defense-in-depth; the backend ``require_role`` remains
 *    the source of truth. ``/incidents`` uses ``RoleRoute("viewer")`` (matching
 *    the backend viewer+ RBAC on GET /docs). ``/packet`` and ``/changes`` use
 *    ``RoleRoute("engineer")``. Admin-only surfaces — ``/users`` and the LLM
 *    section of ``/settings`` (``/settings/llm``, ``/settings/access``) —
 *    use ``RoleRoute("admin")``. Credentials (``/settings/credentials``) use
 *    ``RoleRoute("engineer")``. Appearance, agents help, and account links stay
 *    reachable by any authenticated user.
 *
 * The existing M0 pages keep their paths; unknown paths redirect to the
 * dashboard.
 */

import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Layout } from "./components/Layout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { RoleRoute } from "./components/RoleRoute";
import { AdcPage } from "./pages/AdcPage";
import { ApplicationsPage } from "./pages/ApplicationsPage";
import { AuditPage } from "./pages/AuditPage";
import { ChangePasswordPage } from "./pages/ChangePasswordPage";
import { ChangesPage } from "./pages/ChangesPage";
import { ChatPage } from "./pages/ChatPage";
import { ConfigPage } from "./pages/ConfigPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DocumentsPage } from "./pages/DocumentsPage";
import { DevicesPage } from "./pages/DevicesPage";
import { IncidentReportsPage } from "./pages/IncidentReportsPage";
import { LoginPage } from "./pages/LoginPage";
import { PacketPage } from "./pages/PacketPage";
import { ProfilePage } from "./pages/ProfilePage";
import {
  SettingsAccessSection,
  SettingsAccountSection,
  SettingsAgentsSection,
  SettingsAppearanceSection,
  SettingsCredentialsSection,
  SettingsLlmSection,
  SettingsPage,
} from "./pages/SettingsPage";
import { TopologyPage } from "./pages/TopologyPage";
import { UsersPage } from "./pages/UsersPage";
import { VirtualizationPage } from "./pages/VirtualizationPage";

export function App() {
  // ErrorBoundary at the app level, per-route (audit UI_UX #1): a render
  // error anywhere in the tree previously produced a blank page. The
  // boundary's `resetKey` is the current pathname, so a tripped boundary
  // clears itself the moment navigation lands on a different route — a
  // crash on one page never wedges the rest of the app.
  const location = useLocation();
  return (
    <ErrorBoundary resetKey={location.pathname}>
      <Routes>
        {/* Public — reachable without auth. /change-password is also the forced
            first-login destination, so it must live outside the gate. */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />

        {/* Everything else: auth + forced-change gate, then the app shell. */}
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="devices" element={<DevicesPage />} />
            <Route path="adc" element={<AdcPage />} />
            <Route path="virtualization" element={<VirtualizationPage />} />
            <Route path="config" element={<ConfigPage />} />
            <Route path="documents" element={<DocumentsPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="applications" element={<ApplicationsPage />} />

            {/* /incidents: viewer+ (incident reports contain agent-generated
                network-failure evidence; defense-in-depth over the backend
                viewer+ RBAC on GET /docs — ADR-0019). */}
            <Route element={<RoleRoute minimum="viewer" />}>
              <Route path="incidents" element={<IncidentReportsPage />} />
            </Route>

            <Route path="chat" element={<ChatPage />} />

            {/* /packet: engineer+ (capture launch requires engineer+ RBAC) */}
            <Route element={<RoleRoute minimum="engineer" />}>
              <Route path="packet" element={<PacketPage />} />
            </Route>

            {/* /changes: the ChangeRequest approval queue is an engineer+
                capability (operator/viewer are not on the change surface;
                defense-in-depth over the backend RBAC). */}
            <Route element={<RoleRoute minimum="engineer" />}>
              <Route path="changes" element={<ChangesPage />} />
            </Route>

            <Route path="audit" element={<AuditPage />} />
            <Route path="profile" element={<ProfilePage />} />

            {/* /settings hub: Appearance / agents / account for any authed user;
                credentials engineer+; LLM + access admin-only. */}
            <Route path="settings" element={<SettingsPage />}>
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

            {/* Admin-only surfaces (defense-in-depth over the backend RBAC). */}
            <Route element={<RoleRoute minimum="admin" />}>
              <Route path="users" element={<UsersPage />} />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </ErrorBoundary>
  );
}
