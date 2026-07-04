/**
 * Tests for the loading/motion primitives (audit UI_UX #4): Skeleton,
 * SkeletonRows, and Spinner — all must respect `prefers-reduced-motion`.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Skeleton, SkeletonRows, Spinner } from "../components/Skeleton";

describe("Skeleton", () => {
  it("renders a pulsing, motion-reduce-safe, aria-hidden block", () => {
    render(<Skeleton data-testid="block" />);
    const block = screen.getByTestId("block");
    expect(block).toHaveClass("animate-pulse", "motion-reduce:animate-none");
    expect(block).toHaveAttribute("aria-hidden", "true");
  });

  it("renders no accessible status by default (no label given)", () => {
    render(<Skeleton data-testid="block" />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("renders a visually-hidden role=status announcement when a label is given", () => {
    render(<Skeleton data-testid="block" label="Probing dependencies…" />);
    const status = screen.getByRole("status");
    expect(status).toHaveAccessibleName("Probing dependencies…");
    expect(status).toHaveClass("sr-only");
    // The pulsing visual stays aria-hidden regardless of the label.
    expect(screen.getByTestId("block")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("SkeletonRows", () => {
  it("renders the requested number of rows and columns", () => {
    render(
      <table>
        <tbody data-testid="body">
          <SkeletonRows rows={3} cols={4} />
        </tbody>
      </table>,
    );
    const body = screen.getByTestId("body");
    const rows = body.querySelectorAll("tr");
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row).toHaveClass("border-b", "border-carbon-800", "last:border-0");
      expect(row.querySelectorAll("td")).toHaveLength(4);
    }
  });

  it("renders no accessible status by default (no label given)", () => {
    render(
      <table>
        <tbody data-testid="body">
          <SkeletonRows rows={3} cols={4} />
        </tbody>
      </table>,
    );
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("renders a visually-hidden role=status announcement when a label is given, without adding a visible row", () => {
    render(
      <table>
        <tbody data-testid="body">
          <SkeletonRows rows={3} cols={4} label="Loading inventory…" />
        </tbody>
      </table>,
    );
    const status = screen.getByRole("status");
    expect(status).toHaveAccessibleName("Loading inventory…");
    expect(status.closest("tr")).toHaveClass("sr-only");

    // Still exactly 3 pulsing placeholder rows — the sr-only row is extra.
    const body = screen.getByTestId("body");
    const pulsingRows = Array.from(body.querySelectorAll("tr")).filter((row) =>
      row.querySelector(".animate-pulse"),
    );
    expect(pulsingRows).toHaveLength(3);
  });
});

describe("Spinner", () => {
  it("exposes role=status with a default 'Loading' label", () => {
    render(<Spinner />);
    expect(screen.getByRole("status")).toHaveAccessibleName("Loading");
  });

  it("accepts a custom aria-label", () => {
    render(<Spinner aria-label="Saving change" />);
    expect(screen.getByRole("status")).toHaveAccessibleName("Saving change");
  });

  it("respects prefers-reduced-motion with a static fallback glyph", () => {
    render(<Spinner />);
    const status = screen.getByRole("status");
    const spinningGlyph = status.querySelector(".animate-spin");
    expect(spinningGlyph).toHaveClass("motion-reduce:hidden");
    const staticGlyph = status.querySelector(".motion-reduce\\:flex");
    expect(staticGlyph).not.toBeNull();
    expect(staticGlyph).toHaveClass("hidden");
  });
});
