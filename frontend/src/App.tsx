/**
 * Route table: wires the Layout shell (sidebar + header) to the six M0 pages.
 * Paths mirror the sidebar entries in components/Layout.tsx; unknown paths
 * redirect to the dashboard.
 */

import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuditPage } from "./pages/AuditPage";
import { ChangesPage } from "./pages/ChangesPage";
import { ChatPage } from "./pages/ChatPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DevicesPage } from "./pages/DevicesPage";
import { TopologyPage } from "./pages/TopologyPage";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="topology" element={<TopologyPage />} />
        <Route path="chat" element={<ChatPage />} />
        <Route path="changes" element={<ChangesPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
