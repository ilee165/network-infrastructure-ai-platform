import { Link } from "react-router-dom";

export function SettingsAccountSection() {
  return (
    <section
      aria-label="My account"
      data-testid="settings-account"
      className="panel p-4 flex flex-col gap-3"
    >
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        My account
      </h3>
      <p className="text-sm text-zinc-300">
        Profile editing, password change, and session management live on the
        Profile page so day-to-day account work stays one click away from the
        user menu.
      </p>
      <ul className="list-disc space-y-1 pl-5 text-sm text-zinc-400">
        <li>Display name and email</li>
        <li>Change password</li>
        <li>Active sessions (revoke one or all)</li>
      </ul>
      <Link to="/profile" className="btn self-start text-xs">
        Open Profile
      </Link>
    </section>
  );
}
