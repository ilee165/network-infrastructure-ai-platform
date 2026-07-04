/**
 * StatusPill tests (audit UI_UX #3/#7): the single sanctioned pill
 * composition, plus the non-color glyph required by UI_UX #5.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusPill } from "../components/StatusPill";

describe("StatusPill", () => {
  it("renders the ok variant with the ok token classes", () => {
    render(
      <StatusPill variant="ok" data-testid="pill">
        active
      </StatusPill>,
    );
    const pill = screen.getByTestId("pill");
    expect(pill).toHaveClass("border-status-ok/40", "bg-status-ok/10", "text-status-ok");
    expect(pill).toHaveTextContent("active");
  });

  it("renders the warn variant with the warn token classes", () => {
    render(<StatusPill variant="warn">pending</StatusPill>);
    expect(screen.getByText("pending").closest("span")).toHaveClass(
      "border-status-warn/40",
      "bg-status-warn/10",
      "text-status-warn",
    );
  });

  it("renders the error variant with the error token classes", () => {
    render(<StatusPill variant="error">failed</StatusPill>);
    expect(screen.getByText("failed").closest("span")).toHaveClass(
      "border-status-error/40",
      "bg-status-error/10",
      "text-status-error",
    );
  });

  it("renders the neutral variant matching the ChangesPage draft composition", () => {
    render(<StatusPill variant="neutral">draft</StatusPill>);
    expect(screen.getByText("draft").closest("span")).toHaveClass(
      "border-carbon-600",
      "bg-carbon-800",
      "text-zinc-400",
    );
  });

  it("renders the info variant with the accent token classes", () => {
    render(<StatusPill variant="info">running</StatusPill>);
    expect(screen.getByText("running").closest("span")).toHaveClass(
      "border-accent/40",
      "bg-accent/10",
      "text-accent",
    );
  });

  it("renders a distinct aria-hidden glyph per variant so status is not color-only", () => {
    const { rerender } = render(
      <StatusPill variant="ok" data-testid="pill">
        active
      </StatusPill>,
    );
    const glyphFor = () => screen.getByTestId("pill").querySelector("[aria-hidden='true']");
    const okGlyph = glyphFor()?.textContent;

    rerender(
      <StatusPill variant="warn" data-testid="pill">
        pending
      </StatusPill>,
    );
    const warnGlyph = glyphFor()?.textContent;

    rerender(
      <StatusPill variant="error" data-testid="pill">
        failed
      </StatusPill>,
    );
    const errorGlyph = glyphFor()?.textContent;

    rerender(
      <StatusPill variant="neutral" data-testid="pill">
        draft
      </StatusPill>,
    );
    const neutralGlyph = glyphFor()?.textContent;

    rerender(
      <StatusPill variant="info" data-testid="pill">
        running
      </StatusPill>,
    );
    const infoGlyph = glyphFor()?.textContent;

    expect(okGlyph).toBeTruthy();
    const glyphs = new Set([okGlyph, warnGlyph, errorGlyph, neutralGlyph, infoGlyph]);
    expect(glyphs.size).toBe(5);
  });
});
