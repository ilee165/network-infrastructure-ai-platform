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
 *    and then the ``Layout`` shell. Admin-only surfaces — ``/users`` and the LLM
 *    section of ``/settings`` (``/settings/llm``) — are additionally wrapped in
 *    ``RoleRoute("admin")`` as defense-in-depth; the backend ``require_role``
 *    remains the source of truth. The Appearance section of ``/settings`` stays
 *    reachable by any authenticated user.
 *
 * The existing M0 pages keep their paths; unknown paths redirect to the
 * dashboard.
 */

import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { RoleRoute } from "./components/RoleRoute";
import { AuditPage } from "./pages/AuditPage";
import { ChangePasswordPage } from "./pages/ChangePasswordPage";
import { ChangesPage } from "./pages/ChangesPage";
import { ChatPage } from "./pages/ChatPage";
import { ConfigPage } from "./pages/ConfigPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DocumentsPage } from "./pages/DocumentsPage";
import { DevicesPage } from "./pages/DevicesPage";
import { LoginPage } from "./pages/LoginPage";
import { ProfilePage } from "./pages/ProfilePage";
import { SettingsLlmSection, SettingsPage } from "./pages/SettingsPage";
import { TopologyPage } from "./pages/TopologyPage";
import { UsersPage } from "./pages/UsersPage";

export function App() {
  return (
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
          <Route path="config" element={<ConfigPage />} />
          <Route path="documents" element={<DocumentsPage />} />
          <Route path="topology" element={<TopologyPage />} />
          <Route path="chat" element={<ChatPage />} />
          <Route path="changes" element={<ChangesPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="profile" element={<ProfilePage />} />

          {/* /settings: Appearance is open to any authed user; the LLM section
              is admin-only (defense-in-depth over the backend RBAC). */}
          <Route path="settings" element={<SettingsPage />}>
            <Route element={<RoleRoute minimum="admin" />}>
              <Route path="llm" element={<SettingsLlmSection />} />
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
  );
}
