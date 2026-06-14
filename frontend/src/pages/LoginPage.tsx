/**
 * LoginPage (Auth & Account UI): public credential entry.
 *
 * Placeholder shell introduced by the routing task (F2) so the public ``/login``
 * route resolves. The credential form, error handling, and redirect-on-success
 * are delivered by the login task; this stub renders the heading scaffold only.
 */

export function LoginPage() {
  return (
    <main className="flex h-screen items-center justify-center bg-carbon-950 px-4 text-zinc-300">
      <section
        data-testid="login-page"
        className="w-full max-w-sm rounded border border-carbon-700 bg-carbon-900 p-6"
      >
        <h1 className="text-lg font-semibold text-zinc-100">Sign in</h1>
        <p className="mt-1 text-xs text-zinc-500">NetOps Console</p>
      </section>
    </main>
  );
}
