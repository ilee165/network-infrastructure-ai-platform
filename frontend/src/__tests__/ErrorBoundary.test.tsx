/**
 * ErrorBoundary tests (audit UI_UX #1): app-level React error boundary with
 * a per-route fallback.
 *
 * Mirrors the App.tsx composition — ErrorBoundary wraps <Routes>, keyed off
 * the current pathname via useLocation — without pulling in the full auth
 * gate, so the test exercises the boundary/router contract directly:
 * a render-throw inside a route shows the fallback, and navigating to
 * another route resets the boundary and renders normally again.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { Link, MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { ErrorBoundary } from "../components/ErrorBoundary";

function Boom(): never {
  throw new Error("kaboom");
}

function Fine() {
  return <div data-testid="fine-page">All good</div>;
}

/**
 * Small stand-in for App.tsx's own ErrorBoundary + Routes composition. The
 * nav sits *outside* the boundary — same as the app shell's persistent chrome
 * sitting outside any single page's failure — so navigation stays clickable
 * even while a routed page has crashed the boundary underneath it.
 */
function TestApp() {
  const location = useLocation();
  return (
    <>
      <nav>
        <Link to="/boom">Boom</Link>
        <Link to="/fine">Fine</Link>
      </nav>
      <ErrorBoundary resetKey={location.pathname}>
        <Routes>
          <Route path="/boom" element={<Boom />} />
          <Route path="/fine" element={<Fine />} />
        </Routes>
      </ErrorBoundary>
    </>
  );
}

describe("ErrorBoundary", () => {
  it("renders children normally when nothing throws", () => {
    render(
      <MemoryRouter initialEntries={["/fine"]}>
        <TestApp />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("fine-page")).toBeInTheDocument();
    expect(screen.queryByTestId("error-boundary-fallback")).not.toBeInTheDocument();
  });

  it("shows the fallback UI when a routed page throws during render", () => {
    render(
      <MemoryRouter initialEntries={["/boom"]}>
        <TestApp />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("error-boundary-fallback")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong");
  });

  it("resets on navigation to another route so the app keeps working", () => {
    render(
      <MemoryRouter initialEntries={["/boom"]}>
        <TestApp />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("error-boundary-fallback")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("link", { name: "Fine" }));

    expect(screen.queryByTestId("error-boundary-fallback")).not.toBeInTheDocument();
    expect(screen.getByTestId("fine-page")).toBeInTheDocument();
  });

  it("shows the fallback even when a falsy value is thrown", () => {
    function BoomFalsy(): never {
      // A falsy throw is legal JS; the boundary must not treat the caught
      // value itself as the "no error" sentinel.
      throw null;
    }
    render(
      <MemoryRouter initialEntries={["/"]}>
        <ErrorBoundary>
          <BoomFalsy />
        </ErrorBoundary>
      </MemoryRouter>,
    );
    expect(screen.getByTestId("error-boundary-fallback")).toBeInTheDocument();
  });
});
