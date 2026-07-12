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
 *    section of ``/settings`` (``/settings/llm``, ``/settings/access``,
 *    ``/settings/integrations``, ``/settings/platform``) — use
 *    ``RoleRoute("admin")``. Credentials (``/settings/credentials``) use
 *    ``RoleRoute("engineer")``. Appearance, agents help, and account links stay
 *    reachable by any authenticated user.
 *
 * Wave 5 / perf #5: route-level ``React.lazy`` so cytoscape and other page
 * heavyweights are not shipped on ``/login``.
 */

import { lazy, Suspense, type ComponentType, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Layout } from "./components/Layout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { RoleRoute } from "./components/RoleRoute";

const LoginPage = lazy(() =>
  import("./pages/LoginPage").then((m) => ({ default: m.LoginPage })),
);
const ChangePasswordPage = lazy(() =>
  import("./pages/ChangePasswordPage").then((m) => ({ default: m.ChangePasswordPage })),
);
const DashboardPage = lazy(() =>
  import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })),
);
const DevicesPage = lazy(() =>
  import("./pages/DevicesPage").then((m) => ({ default: m.DevicesPage })),
);
const AdcPage = lazy(() =>
  import("./pages/AdcPage").then((m) => ({ default: m.AdcPage })),
);
const VirtualizationPage = lazy(() =>
  import("./pages/VirtualizationPage").then((m) => ({ default: m.VirtualizationPage })),
);
const ConfigPage = lazy(() =>
  import("./pages/ConfigPage").then((m) => ({ default: m.ConfigPage })),
);
const DocumentsPage = lazy(() =>
  import("./pages/DocumentsPage").then((m) => ({ default: m.DocumentsPage })),
);
const TopologyPage = lazy(() =>
  import("./pages/TopologyPage").then((m) => ({ default: m.TopologyPage })),
);
const ApplicationsPage = lazy(() =>
  import("./pages/ApplicationsPage").then((m) => ({ default: m.ApplicationsPage })),
);
const IncidentReportsPage = lazy(() =>
  import("./pages/IncidentReportsPage").then((m) => ({ default: m.IncidentReportsPage })),
);
const ChatPage = lazy(() =>
  import("./pages/ChatPage").then((m) => ({ default: m.ChatPage })),
);
const PacketPage = lazy(() =>
  import("./pages/PacketPage").then((m) => ({ default: m.PacketPage })),
);
const ChangesPage = lazy(() =>
  import("./pages/ChangesPage").then((m) => ({ default: m.ChangesPage })),
);
const AuditPage = lazy(() =>
  import("./pages/AuditPage").then((m) => ({ default: m.AuditPage })),
);
const ProfilePage = lazy(() =>
  import("./pages/ProfilePage").then((m) => ({ default: m.ProfilePage })),
);
const UsersPage = lazy(() =>
  import("./pages/UsersPage").then((m) => ({ default: m.UsersPage })),
);
const SettingsPage = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })),
);
const SettingsAppearanceSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsAppearanceSection })),
);
const SettingsAgentsSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsAgentsSection })),
);
const SettingsAccountSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsAccountSection })),
);
const SettingsCredentialsSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsCredentialsSection })),
);
const SettingsLlmSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsLlmSection })),
);
const SettingsAccessSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsAccessSection })),
);
const SettingsIntegrationsSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsIntegrationsSection })),
);
const SettingsPlatformSection = lazy(() =>
  import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPlatformSection })),
);

function RouteFallback() {
  return (
    <div
      data-testid="route-fallback"
      className="flex min-h-[12rem] items-center justify-center text-sm text-zinc-400"
      role="status"
    >
      Loading…
    </div>
  );
}

function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<RouteFallback />}>{children}</Suspense>;
}

/** Wrap a lazy page element for concise route tables. */
function page(Page: ComponentType) {
  return (
    <Lazy>
      <Page />
    </Lazy>
  );
}

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
        <Route path="/login" element={page(LoginPage)} />
        <Route path="/change-password" element={page(ChangePasswordPage)} />

        {/* Everything else: auth + forced-change gate, then the app shell. */}
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route index element={page(DashboardPage)} />
            <Route path="devices" element={page(DevicesPage)} />
            <Route path="adc" element={page(AdcPage)} />
            <Route path="virtualization" element={page(VirtualizationPage)} />
            <Route path="config" element={page(ConfigPage)} />
            <Route path="documents" element={page(DocumentsPage)} />
            <Route path="topology" element={page(TopologyPage)} />
            <Route path="applications" element={page(ApplicationsPage)} />

            {/* /incidents: viewer+ (incident reports contain agent-generated
                network-failure evidence; defense-in-depth over the backend
                viewer+ RBAC on GET /docs — ADR-0019). */}
            <Route element={<RoleRoute minimum="viewer" />}>
              <Route path="incidents" element={page(IncidentReportsPage)} />
            </Route>

            <Route path="chat" element={page(ChatPage)} />

            {/* /packet: engineer+ (capture launch requires engineer+ RBAC) */}
            <Route element={<RoleRoute minimum="engineer" />}>
              <Route path="packet" element={page(PacketPage)} />
            </Route>

            {/* /changes: the ChangeRequest approval queue is an engineer+
                capability (operator/viewer are not on the change surface;
                defense-in-depth over the backend RBAC). */}
            <Route element={<RoleRoute minimum="engineer" />}>
              <Route path="changes" element={page(ChangesPage)} />
            </Route>

            <Route path="audit" element={page(AuditPage)} />
            <Route path="profile" element={page(ProfilePage)} />

            {/* /settings hub: Appearance / agents / account for any authed user;
                credentials engineer+; LLM + access + integrations + platform
                admin-only. */}
            <Route path="settings" element={page(SettingsPage)}>
              <Route index element={page(SettingsAppearanceSection)} />
              <Route path="agents" element={page(SettingsAgentsSection)} />
              <Route path="account" element={page(SettingsAccountSection)} />
              <Route element={<RoleRoute minimum="engineer" />}>
                <Route path="credentials" element={page(SettingsCredentialsSection)} />
              </Route>
              <Route element={<RoleRoute minimum="admin" />}>
                <Route path="llm" element={page(SettingsLlmSection)} />
                <Route path="access" element={page(SettingsAccessSection)} />
                <Route path="integrations" element={page(SettingsIntegrationsSection)} />
                <Route path="platform" element={page(SettingsPlatformSection)} />
              </Route>
            </Route>

            {/* Admin-only surfaces (defense-in-depth over the backend RBAC). */}
            <Route element={<RoleRoute minimum="admin" />}>
              <Route path="users" element={page(UsersPage)} />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </ErrorBoundary>
  );
}
