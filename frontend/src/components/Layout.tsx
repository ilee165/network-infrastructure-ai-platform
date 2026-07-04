/**
 * Application shell: collapsible sidebar navigation + header with
 * environment / LLM-profile badges. Pages render through the router outlet.
 */

import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { ErrorBoundary } from "./ErrorBoundary";
import { Toaster } from "./Toaster";
import { logout } from "../api/auth";
import { useAuthStore } from "../stores/auth";
import { hasMinimumRole } from "../stores/roles";
import { useUiStore } from "../stores/ui";

/** DOM id the mobile hamburger toggle points `aria-controls` at. */
const SIDEBAR_ID = "app-sidebar";

interface NavItem {
  to: string;
  label: string;
  /** Two-letter glyph shown when the sidebar is collapsed. */
  abbr: string;
  end?: boolean;
  /** Shown only to admins (defense-in-depth; the backend RBAC is canonical). */
  adminOnly?: boolean;
  /** Shown only to engineer+ (defense-in-depth; the backend RBAC is canonical). */
  engineerOnly?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", abbr: "DB", end: true },
  { to: "/devices", label: "Devices", abbr: "DV" },
  { to: "/config", label: "Config", abbr: "CF" },
  { to: "/documents", label: "Documents", abbr: "DC" },
  { to: "/topology", label: "Topology", abbr: "TP" },
  { to: "/packet", label: "Packet", abbr: "PK", engineerOnly: true },
  { to: "/incidents", label: "Incidents", abbr: "IR" },
  { to: "/chat", label: "Chat", abbr: "CH" },
  { to: "/changes", label: "Changes", abbr: "CR", engineerOnly: true },
  { to: "/audit", label: "Audit", abbr: "AU" },
  { to: "/users", label: "Users", abbr: "US", adminOnly: true },
  { to: "/profile", label: "Profile", abbr: "PR" },
  { to: "/settings", label: "Settings", abbr: "ST" },
];

/** Map Vite's build mode onto the short env label used by the badge. */
function envLabel(): string {
  const mode = import.meta.env.MODE;
  if (mode === "development") {
    return "dev";
  }
  if (mode === "production") {
    return "prod";
  }
  return mode;
}

export function Layout() {
  const sidebarCollapsed = useUiStore((state) => state.sidebarCollapsed);
  const toggleSidebar = useUiStore((state) => state.toggleSidebar);
  const theme = useUiStore((state) => state.theme);
  const llmProfile = import.meta.env.VITE_LLM_PROFILE ?? "local";

  const user = useAuthStore((state) => state.user);
  const setAnon = useAuthStore((state) => state.setAnon);
  const navigate = useNavigate();
  const location = useLocation();

  const isAdmin = hasMinimumRole(user?.role, "admin");
  const isEngineer = hasMinimumRole(user?.role, "engineer");
  const navItems = NAV_ITEMS.filter(
    (item) =>
      (!item.adminOnly || isAdmin) && (!item.engineerOnly || isEngineer),
  );
  // Prefer the human-friendly name, fall back to the login username.
  const displayName = user?.display_name ?? user?.username ?? "";

  // Below `lg:` the sidebar renders as an overlay drawer instead of the fixed
  // column; this is transient, view-local state (unlike `sidebarCollapsed`,
  // which is a persisted preference in `ui.ts`) so it always starts closed.
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Escape closes the drawer from anywhere in the shell, matching the
  // backdrop-click affordance.
  useEffect(() => {
    if (!drawerOpen) {
      return;
    }
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") {
        setDrawerOpen(false);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [drawerOpen]);

  /**
   * Log out: revoke the server-side session + clear the refresh cookie, drop
   * the in-memory auth state, then route to /login. The server call is
   * best-effort — even if it fails we still clear local state and redirect so a
   * user is never stranded "logged in" in the SPA.
   */
  async function handleLogout(): Promise<void> {
    try {
      await logout();
    } catch {
      // Ignore — local sign-out + redirect proceed regardless.
    }
    setAnon();
    navigate("/login", { replace: true });
  }

  return (
    <div
      data-theme={theme}
      className="flex h-screen overflow-hidden bg-carbon-950 text-zinc-300"
    >
      {/* Below `lg:` the drawer is an overlay: a dimmed backdrop behind a
          fixed-position sidebar, both dismissable. At `lg:` and above neither
          renders as an overlay — the backdrop never mounts and the sidebar
          reverts to its normal static column via the `lg:` overrides below. */}
      {drawerOpen && (
        <div
          data-testid="drawer-backdrop"
          onClick={() => setDrawerOpen(false)}
          className="fixed inset-0 z-30 bg-black/50 transition-opacity duration-150 motion-reduce:transition-none lg:hidden"
        />
      )}

      <aside
        id={SIDEBAR_ID}
        className={`fixed inset-y-0 left-0 z-40 flex h-full ${sidebarCollapsed ? "w-14" : "w-56"} flex-col border-r border-carbon-700 bg-carbon-900 transition-transform duration-150 motion-reduce:transition-none ${drawerOpen ? "translate-x-0" : "-translate-x-full"} lg:static lg:z-auto lg:translate-x-0`}
      >
        <div className="flex h-12 items-center gap-2 border-b border-carbon-700 px-3">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded bg-accent/15 font-mono text-xs font-bold text-accent">
            NO
          </span>
          {!sidebarCollapsed && (
            <span className="font-mono text-xs uppercase tracking-widest text-zinc-400">
              netops
            </span>
          )}
        </div>
        <nav aria-label="Primary" className="flex flex-col gap-1 p-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              aria-label={item.label}
              title={item.label}
              onClick={() => setDrawerOpen(false)}
              className={({ isActive }) =>
                [
                  "flex items-center gap-3 rounded px-2.5 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-carbon-800 text-zinc-100"
                    : "text-zinc-500 hover:bg-carbon-850 hover:text-zinc-200",
                ].join(" ")
              }
            >
              <span className="w-5 shrink-0 text-center font-mono text-[10px] uppercase tracking-wider">
                {item.abbr}
              </span>
              {!sidebarCollapsed && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>
        <button
          type="button"
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="mt-auto border-t border-carbon-700 px-3 py-2 text-left font-mono text-xs text-zinc-500 transition-colors hover:text-zinc-200"
        >
          {sidebarCollapsed ? "»" : "« collapse"}
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-carbon-700 bg-carbon-900 px-4">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setDrawerOpen((open) => !open)}
              aria-expanded={drawerOpen}
              aria-controls={SIDEBAR_ID}
              aria-label={drawerOpen ? "Close navigation" : "Open navigation"}
              className="grid h-8 w-8 shrink-0 place-items-center rounded border border-carbon-700 text-zinc-400 transition-colors hover:border-carbon-600 hover:text-zinc-100 lg:hidden"
            >
              <span aria-hidden="true" className="font-mono text-sm leading-none">
                {drawerOpen ? "✕" : "☰"}
              </span>
            </button>
            <h1 className="truncate text-sm font-semibold text-zinc-100">NetOps Console</h1>
            <span className="hidden truncate text-xs text-zinc-500 sm:inline">
              AI Network Operations Platform
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span className="badge" data-testid="env-badge">
              env: {envLabel()}
            </span>
            <span className="badge" data-testid="llm-profile-badge">
              llm: {llmProfile}
            </span>
            {user && (
              <div
                data-testid="user-menu"
                className="flex items-center gap-3 border-l border-carbon-700 pl-3"
              >
                <span className="flex flex-col items-end leading-tight">
                  <span className="truncate text-xs font-medium text-zinc-200">{displayName}</span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                    {user.role}
                  </span>
                </span>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="rounded border border-carbon-700 px-2 py-1 text-xs text-zinc-400 transition-colors hover:border-carbon-600 hover:text-zinc-100"
                >
                  Log out
                </button>
              </div>
            )}
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto p-6">
          {/* Per-route boundary: a page crash must not unmount the shell
              (sidebar/header) — the app-level boundary in App.tsx is only the
              last resort for the shell itself failing. */}
          <ErrorBoundary resetKey={location.pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
      <Toaster />
    </div>
  );
}
