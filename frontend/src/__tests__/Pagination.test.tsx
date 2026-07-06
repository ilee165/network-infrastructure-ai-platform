/**
 * Pagination component tests: normal range rendering plus the self-healing
 * snap-back when a refetch shrinks `total` below a stale `offset` (a page
 * index past the end must never render an inverted range or strand the
 * caller on a nonexistent page).
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Pagination } from "../components/Pagination";

describe("Pagination", () => {
  it("renders the range and controls for a multi-page result", () => {
    const onChange = vi.fn();
    render(<Pagination offset={0} limit={100} total={150} onChange={onChange} label="vs" />);

    expect(screen.getByTestId("vs-pagination-range")).toHaveTextContent("Showing 1–100 of 150");
    expect(screen.getByTestId("vs-pagination-prev")).toBeDisabled();
    expect(screen.getByTestId("vs-pagination-next")).toBeEnabled();
    expect(onChange).not.toHaveBeenCalled();
  });

  it("renders nothing when the whole result fits on one page", () => {
    const onChange = vi.fn();
    render(<Pagination offset={0} limit={100} total={50} onChange={onChange} label="vs" />);

    expect(screen.queryByTestId("vs-pagination")).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
  });

  it("snaps a stale offset back to the last valid page when total shrinks", () => {
    const onChange = vi.fn();
    // User was on page 3 (offset 200) when a refetch returned total=150.
    render(<Pagination offset={200} limit={100} total={150} onChange={onChange} label="vs" />);

    // Never an inverted "Showing 201–150 of 150" — nothing renders while the
    // snap-back lands.
    expect(screen.queryByTestId("vs-pagination")).not.toBeInTheDocument();
    expect(onChange).toHaveBeenCalledWith(100); // last valid page for total=150
  });

  it("snaps back to the first page when total shrinks to a single page", () => {
    const onChange = vi.fn();
    render(<Pagination offset={100} limit={100} total={50} onChange={onChange} label="vs" />);

    expect(screen.queryByTestId("vs-pagination")).not.toBeInTheDocument();
    expect(onChange).toHaveBeenCalledWith(0);
  });

  it("snaps back to zero when the list empties under a stale offset", () => {
    const onChange = vi.fn();
    render(<Pagination offset={100} limit={100} total={0} onChange={onChange} label="vs" />);

    expect(screen.queryByTestId("vs-pagination")).not.toBeInTheDocument();
    expect(onChange).toHaveBeenCalledWith(0);
  });
});
