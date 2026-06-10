/**
 * Layout shell tests: every page in the route table is reachable from the
 * sidebar, the routed page renders through the outlet, and the header badges
 * are present. No network access — Layout itself fetches nothing.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Layout } from "../components/Layout";

/** Must stay in sync with NAV_ITEMS in components/Layout.tsx and App.tsx. */
const NAV_LABELS = ["Dashboard", "Devices", "Topology", "Chat", "Changes", "Audit"] as const;

function renderLayout() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div data-testid="outlet-page" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("Layout", () => {
  it("renders a navigation link for every page", () => {
    renderLayout();
    for (const label of NAV_LABELS) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("renders the routed page through the outlet", () => {
    renderLayout();
    expect(screen.getByTestId("outlet-page")).toBeInTheDocument();
  });

  it("shows environment and LLM-profile badges in the header", () => {
    renderLayout();
    expect(screen.getByTestId("env-badge")).toBeInTheDocument();
    // VITE_LLM_PROFILE is unset under vitest, so the badge falls back to "local".
    expect(screen.getByTestId("llm-profile-badge")).toHaveTextContent("llm: local");
  });
});
