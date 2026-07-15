import { NavLink, Outlet } from "react-router-dom";

import { PageHeader } from "../../components/PageHeader";
import { useAuthStore } from "../../stores/auth";
import { hasMinimumRole, type Role } from "../../stores/roles";

interface SectionLink {
  to: string;
  label: string;
  end?: boolean;
  /** Shown only when the user meets this minimum role. */
  minRole?: Role;
}

/**
 * ADR-0009 security boundary: provider API keys are never displayed, entered,
 * or persisted by this settings shell. Secret material remains backend-only.
 */
const SECTION_LINKS: SectionLink[] = [
  { to: "/settings", label: "Appearance", end: true },
  { to: "/settings/agents", label: "Agents & Chat" },
  { to: "/settings/account", label: "My account" },
  { to: "/settings/credentials", label: "Credentials", minRole: "engineer" },
  { to: "/settings/llm", label: "AI / LLM", minRole: "admin" },
  { to: "/settings/access", label: "Users & access", minRole: "admin" },
  { to: "/settings/integrations", label: "Integrations", minRole: "admin" },
  { to: "/settings/platform", label: "Platform", minRole: "admin" },
];

function SettingsSectionNav() {
  const role = useAuthStore((s) => s.user?.role);
  const links = SECTION_LINKS.filter(
    (link) => !link.minRole || hasMinimumRole(role, link.minRole),
  );

  return (
    <nav
      aria-label="Settings sections"
      data-testid="settings-section-nav"
      className="flex flex-wrap gap-2 border-b border-carbon-800 pb-3"
    >
      {links.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          end={link.end}
          className={({ isActive }) =>
            [
              "rounded border px-3 py-1.5 text-xs font-medium transition-colors",
              isActive
                ? "border-accent bg-accent/10 text-accent"
                : "border-carbon-700 text-zinc-400 hover:border-carbon-600 hover:text-zinc-200",
            ].join(" ")
          }
        >
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}

export function SettingsPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="settings-page">
      <PageHeader
        title="Settings"
        description="Appearance, account links, agents setup, credentials vault, and (for admins) AI profile, integrations, platform health, and user access."
      />
      <SettingsSectionNav />
      <Outlet />
    </div>
  );
}
