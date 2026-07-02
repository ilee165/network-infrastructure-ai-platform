/**
 * ErrorBoundary (audit UI_UX #1): app-level React error boundary with a
 * per-route fallback.
 *
 * A render error anywhere in the tree previously produced a blank page —
 * React unmounts the whole subtree on an uncaught render error and there was
 * no boundary to catch it. This component renders a fallback UI instead and,
 * critically, resets itself whenever the route changes (via `resetKey`) so a
 * crash on one page does not permanently wedge the app: navigating to another
 * route re-mounts the boundary's children and gives that page a fresh
 * attempt to render.
 *
 * Usage: wrap the app once in `App.tsx` at a level that still has access to
 * the router (so navigation continues to work from the fallback), and pass
 * the current pathname (or any per-route key) as `resetKey`.
 */

import type { ErrorInfo, ReactNode } from "react";
import { Component } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Changing this value (e.g. the route pathname) resets a tripped boundary. */
  resetKey?: string;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/** Fallback UI shown when a child render throws. */
function ErrorFallback({ error }: { error: Error }) {
  return (
    <div
      data-testid="error-boundary-fallback"
      role="alert"
      className="flex flex-col items-center justify-center gap-2 py-24 text-center"
    >
      <p className="font-mono text-xs uppercase tracking-widest text-accent">Error</p>
      <h2 className="text-lg font-semibold text-zinc-100">Something went wrong</h2>
      <p className="max-w-sm text-sm text-zinc-500">
        This page hit an unexpected error and could not render. Try navigating to another page,
        or reload the app.
      </p>
      {error.message ? (
        <p className="max-w-md break-words font-mono text-xs text-zinc-600">{error.message}</p>
      ) : null}
    </div>
  );
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error("ErrorBoundary caught a render error:", error, info.componentStack);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps): void {
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render(): ReactNode {
    if (this.state.error) {
      return <ErrorFallback error={this.state.error} />;
    }
    return this.props.children;
  }
}
