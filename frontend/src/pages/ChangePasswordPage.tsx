/**
 * ChangePasswordPage (Auth & Account UI): change-own-password flow.
 *
 * Public-by-route so the forced first-login change is reachable while
 * ``must_change_password`` is set (``ProtectedRoute`` pins flagged users here).
 * Placeholder shell introduced by the routing task (F2); the form + submit are
 * delivered by the password-change task.
 */

export function ChangePasswordPage() {
  return (
    <main className="flex h-screen items-center justify-center bg-carbon-950 px-4 text-zinc-300">
      <section
        data-testid="change-password-page"
        className="w-full max-w-sm rounded border border-carbon-700 bg-carbon-900 p-6"
      >
        <h1 className="text-lg font-semibold text-zinc-100">Change password</h1>
        <p className="mt-1 text-xs text-zinc-500">
          Set a new password to continue.
        </p>
      </section>
    </main>
  );
}
